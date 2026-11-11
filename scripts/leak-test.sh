#!/bin/sh
# Privileged leak-protection test for a real Mac. It CHANGES THIS MAC'S NETWORKING while it runs (connects
# OpenWarp in "Traffic and DNS" mode with the kill switch, kills the daemon on purpose twice, stops and
# restarts the OpenWarp service, tries to send traffic around the tunnel) and puts the previous mode, kill
# switch and connection state back at the end.
#
# It is never run in CI and never by automation: it refuses unless all of these hold:
#   - not in CI (CI, GITHUB_ACTIONS unset);
#   - run as root, on macOS, by a person who set OPENWARP_LEAK_TEST=I-UNDERSTAND;
#   - the OpenWarp service (com.local.openwarp) is installed, running, and registered.
#
#   sudo OPENWARP_LEAK_TEST=I-UNDERSTAND scripts/leak-test.sh
#
# What it does, in five stages:
#   1. Positive controls, before connecting: TCP (IPv4, IPv6), DNS over UDP and TCP (to 1.1.1.1, to the
#      router), NTP over UDP and HTTPS, all bound to the physical interface (scripts/leak-probe.py), and a
#      long-running download started on the physical interface. A leak check whose control did not answer
#      is reported as SKIP: a block that also happens without OpenWarp proves nothing.
#   2. Connected with the kill switch: the same probes must fail, the download must stall, the routes, pf
#      anchor order and rules are checked, and two packet captures on the physical interface start
#      (anything unexpected sent out of it; anything with the tunnel's inner address).
#   3. The daemon is killed (kill -9) and launchd restarts it: the probes run continuously until it is
#      connected again, and the coverage of the outage is measured.
#   4. A crash without a restart: the service is stopped, a daemon is started by hand, connected and killed.
#      With no daemon at all traffic must stay blocked; `openwarp recover` must then restore pf, the routes
#      and the DNS servers to their state before the test. The service is started again.
#   5. A normal disconnect: the same restoration checks.
#
# It contacts Cloudflare (the connection itself, 1.1.1.1, www/speed/time.cloudflare.com) and your router's
# DNS, nothing else. Expect a few seconds without network during stages 3 and 4. If anything goes wrong,
# recover with
#   sudo openwarp recover            (removes the kill switch rules, restores routes and DNS)
#   sudo launchctl bootstrap system /Library/LaunchDaemons/com.local.openwarp.plist   (if the service is gone)
# Results: PASS/FAIL/SKIP per check on stdout; exit status 0 only if no check failed.
set -u

die() { echo "leak-test: $*" >&2; exit 2; }
[ -z "${CI:-}" ] && [ -z "${GITHUB_ACTIONS:-}" ] || die "refusing to run in CI: this test changes the machine's networking"
[ "$(uname -s)" = Darwin ] || die "macOS only"
[ "$(id -u)" = 0 ] || die "run with sudo"
[ "${OPENWARP_LEAK_TEST:-}" = I-UNDERSTAND ] || die "set OPENWARP_LEAK_TEST=I-UNDERSTAND to confirm (read the header first)"

HERE=$(cd "$(dirname "$0")" && pwd)
PROBE_PY="$HERE/leak-probe.py"
[ -f "$PROBE_PY" ] || die "missing $PROBE_PY"
probe() { /usr/bin/python3 -I "$PROBE_PY" "$@"; }
now() { /usr/bin/python3 -I -c 'import time; print("%.3f" % time.time())'; }

OW=${OPENWARP:-/usr/local/bin/openwarp}
HELPER=/Library/PrivilegedHelperTools/com.local.openwarp
PLIST=/Library/LaunchDaemons/com.local.openwarp.plist
STATE="/Library/Application Support/openwarp"
ANCHOR=com.apple/000.openwarp
LEGACY_ANCHOR=com.apple/openwarp
LOG=/var/log/openwarp.log
[ -x "$OW" ] || die "openwarp not found at $OW (set OPENWARP=...)"
[ -x "$HELPER" ] || die "the service binary $HELPER is missing"
launchctl print system/com.local.openwarp >/dev/null 2>&1 || die "the com.local.openwarp service is not installed"
json() { /usr/bin/python3 -I -c 'import json,sys
d=json.load(sys.stdin)
for k in sys.argv[1].split("."): d=(d or {}).get(k) if isinstance(d,dict) else None
print("" if d is None else d)' "$1"; }
"$OW" -j status | json registered | grep -q True || die "not registered"
[ "$("$OW" -j settings | json split_mode)" = include ] && die "split tunnelling is in Include mode, where the kill switch is not used"
# Another VPN that is up (the official Cloudflare WARP client included) changes routes and DNS itself, and the
# results would not say anything about OpenWarp.
WARP_CLI="/Applications/Cloudflare WARP.app/Contents/Resources/warp-cli"
if [ -x "$WARP_CLI" ] && "$WARP_CLI" --accept-tos status 2>/dev/null | grep -qi 'status update: *connect'; then
  die "the official Cloudflare WARP client is connected or connecting; disconnect it first"
fi
scutil --nc list 2>/dev/null | grep -q '^\* (Connected)' && die "another VPN is connected (scutil --nc list); disconnect it first"
TESTED=$("$OW" -j status | json version)

WORK=$(mktemp -d /tmp/openwarp-leak.XXXXXX) || die "mktemp failed"
pass=0; fail=0; skip=0
ok()      { pass=$((pass+1)); echo "PASS  $*"; }
bad()     { fail=$((fail+1)); echo "FAIL  $*"; }
skipped() { skip=$((skip+1)); echo "SKIP  $*"; }
info()    { echo "      $*"; }
check()  { name=$1; shift; if "$@" >/dev/null 2>&1; then ok "$name"; else bad "$name"; fi; }
refuse() { name=$1; shift; if "$@" >/dev/null 2>&1; then bad "$name"; else ok "$name"; fi; }
# control VAR NAME CMD...: a positive control (tried twice); sets VAR to 1 when it answered.
control() {
  var=$1; name=$2; shift 2
  if "$@" >/dev/null 2>&1 || { sleep 1; "$@" >/dev/null 2>&1; }; then
    eval "$var=1"; echo "CTRL  $name: answered"
  else
    eval "$var=0"; echo "CTRL  $name: no answer (its leak checks are skipped)"
  fi
}
# blocked CONTROL NAME CMD...: a leak check, meaningful only when its control answered before connecting.
blocked() {
  c=$1; name=$2; shift 2
  if [ "$c" != 1 ]; then skipped "$name (no answer before connecting either)"; return; fi
  if "$@" >/dev/null 2>&1; then bad "$name: an answer came back"; else ok "$name"; fi
}

# ---------- baseline ----------
PHYS=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')
case "$PHYS" in ""|utun*) die "no physical default route (disconnect OpenWarp first)";; esac
GW=$(route -n get default -ifscope "$PHYS" 2>/dev/null | awk '/gateway:/{print $2}')
dns_servers() {
  networksetup -listallnetworkservices | tail -n +2 | while IFS= read -r s; do
    printf '%s=%s\n' "$s" "$(networksetup -getdnsservers "$s" | tr '\n' ' ')"
  done
}
# Routes without the link-layer cache (L) and cloned (W) entries, which change on their own.
routes() { netstat -rn | awk 'NF >= 4 && $1 != "Destination" && $3 !~ /[LW]/ {print $1, $2, $3, $4}' | sort; }
pf_status() { pfctl -s info 2>/dev/null | awk '/^Status:/{print $2}'; }
anchor_has_rules() { pfctl -a "$1" -s rules 2>/dev/null | grep -q .; }
direct() { curl -sS --max-time 5 --interface "$PHYS" -o /dev/null https://1.1.1.1/cdn-cgi/trace; }
trace_warp() { curl -sS --max-time 10 https://www.cloudflare.com/cdn-cgi/trace | grep -Eq '^warp=(on|plus)$'; }
wait_status() { # wait_status <status> <seconds>
  i=0; while [ $i -lt "$2" ]; do [ "$("$OW" -j status 2>/dev/null | json status)" = "$1" ] && return 0; sleep 1; i=$((i+1)); done; return 1
}
daemon_up() { i=0; while [ $i -lt "$1" ]; do "$OW" -j status >/dev/null 2>&1 && return 0; sleep 1; i=$((i+1)); done; return 1; }

DNS_BEFORE=$(dns_servers)
routes >"$WORK/routes.before"
PF_BEFORE=$(pf_status)
OLD_MODE=$("$OW" -j settings | json mode)
OLD_KS=$("$OW" -j settings | json kill_switch)
OLD_STATUS=$("$OW" -j status | json status)
RESOLVERS=$(scutil --dns | awk '/nameserver\[/{print $3}' | sort -u | tr '\n' ' ')
echo "OpenWarp service version under test: ${TESTED:-unknown} ($HELPER)"
echo "physical interface: $PHYS, router: ${GW:-none}, resolvers: $RESOLVERS"
echo "pf before the test: $PF_BEFORE; previous mode: $OLD_MODE, kill switch: $OLD_KS, status: $OLD_STATUS"
echo "work directory (captures, logs): $WORK"

MANUAL=; HOLD=; TUNFLOW=; DUMP=; DUMP2=; WATCH=; RESTORED=
# restore puts the service, mode, kill switch and connection back as they were. It runs once: at the end, on
# Ctrl-C, a terminal that closes, or any unexpected exit after this point.
restore() {
  [ -n "$RESTORED" ] && return
  RESTORED=1
  for p in $HOLD $TUNFLOW $WATCH $DUMP $DUMP2; do kill "$p" 2>/dev/null; done
  if [ -n "$MANUAL" ] && kill -0 "$MANUAL" 2>/dev/null; then kill "$MANUAL"; sleep 2; fi
  if ! launchctl print system/com.local.openwarp >/dev/null 2>&1; then
    "$OW" recover >/dev/null 2>&1
    launchctl bootstrap system "$PLIST" 2>/dev/null
    daemon_up 20
  fi
  "$OW" disconnect >/dev/null 2>&1
  "$OW" mode "$OLD_MODE" >/dev/null 2>&1
  if [ "$OLD_KS" = True ]; then "$OW" killswitch on >/dev/null 2>&1; else "$OW" killswitch off >/dev/null 2>&1; fi
  [ "$OLD_STATUS" = Connected ] && "$OW" connect >/dev/null 2>&1
}
trap 'restore; echo "interrupted; settings restored"; exit 3' INT TERM HUP
trap 'restore' EXIT

# after_checks WHERE TAG: pf, routes and DNS are back to their state before the test.
TOKEN=
after_checks() {
  where=$1
  refuse "$where: no rules in $ANCHOR" anchor_has_rules "$ANCHOR"
  refuse "$where: no rules in the old anchor $LEGACY_ANCHOR" anchor_has_rules "$LEGACY_ANCHOR"
  refuse "$where: pf-token file removed" test -e "$STATE/pf-token"
  now_pf=$(pf_status)
  if [ "$now_pf" = "$PF_BEFORE" ]; then ok "$where: pf is $now_pf, as before the test"; else bad "$where: pf is $now_pf, was $PF_BEFORE"; fi
  if [ -n "$TOKEN" ]; then
    refuse "$where: OpenWarp's pf reference ($TOKEN) is released" sh -c "pfctl -s References 2>/dev/null | grep -qw '$TOKEN'"
  fi
  routes >"$WORK/routes.$2"
  if diff "$WORK/routes.before" "$WORK/routes.$2" >"$WORK/routes.$2.diff"; then
    ok "$where: the routing table is as before the test (no tunnel, reject, edge or split routes left)"
  else
    bad "$where: the routing table differs from before the test:"; sed 's/^/        /' "$WORK/routes.$2.diff" | head -20
  fi
  dns_after=$(dns_servers)
  if [ "$DNS_BEFORE" = "$dns_after" ]; then ok "$where: DNS servers as before the test"; else bad "$where: DNS servers differ: before [$DNS_BEFORE] now [$dns_after]"; fi
  check "$where: direct traffic works again" direct
}

# ---------- 1. positive controls ----------
echo "== 1. positive controls (disconnected; everything below goes out of $PHYS directly)"
"$OW" disconnect >/dev/null; sleep 1
T=$(probe resolve time.cloudflare.com); TIME4=${T% *}; TIME6=${T#* }
V6=2606:4700:4700::1111
control C_CURL  "HTTPS to 1.1.1.1 (curl --interface)" direct
control C_TCP4  "TCP to 1.1.1.1:443" probe tcp "$PHYS" 1.1.1.1 443
control C_TCP6  "TCP to [$V6]:443 (IPv6)" probe tcp "$PHYS" "$V6" 443
control C_DNS4U "DNS over UDP to 1.1.1.1" probe dns "$PHYS" 1.1.1.1 udp
control C_DNS4T "DNS over TCP to 1.1.1.1" probe dns "$PHYS" 1.1.1.1 tcp
control C_DNS6U "DNS over UDP to $V6 (IPv6)" probe dns "$PHYS" "$V6" udp
C_NTP4=0; C_NTP6=0
[ "$TIME4" != - ] && control C_NTP4 "NTP (UDP 123) to time.cloudflare.com ($TIME4)" probe ntp "$PHYS" "$TIME4"
[ "$TIME6" != - ] && control C_NTP6 "NTP (UDP 123) to time.cloudflare.com ($TIME6, IPv6)" probe ntp "$PHYS" "$TIME6"
C_GWU=0; C_GWT=0; GW_RESOLVER=0
if [ -n "$GW" ]; then
  control C_GWU "DNS over UDP to the router ($GW)" probe dns "$PHYS" "$GW" udp
  control C_GWT "DNS over TCP to the router ($GW)" probe dns "$PHYS" "$GW" tcp
  case " $RESOLVERS " in *" $GW "*) GW_RESOLVER=1;; esac
fi
# A download on the physical interface that is already running when the kill switch comes on.
curl -sS --interface "$PHYS" --limit-rate 200k --speed-time 3 --speed-limit 1 -o /dev/null \
  'https://speed.cloudflare.com/__down?bytes=900000000' 2>/dev/null &
HOLD=$!
sleep 3
if kill -0 "$HOLD" 2>/dev/null; then C_HOLD=1; echo "CTRL  download on $PHYS running"; else C_HOLD=0; echo "CTRL  download on $PHYS did not start (its check is skipped)"; fi

# ---------- 2. connected ----------
echo "== 2. connect with the kill switch (Traffic and DNS)"
"$OW" mode warp >/dev/null && "$OW" killswitch on >/dev/null && "$OW" connect >/dev/null
if wait_status Connected 90; then ok "connected"; else bad "connected (status: $("$OW" -j status | json status), error: $("$OW" -j status | json error))"; fi
"$OW" -j status >"$WORK/status.json"
IFACE=$(json interface <"$WORK/status.json")
INNER4=$(json interface_v4 <"$WORK/status.json"); INNER4=${INNER4%%/*}
INNER6=$(json interface_v6 <"$WORK/status.json"); INNER6=${INNER6%%/*}
info "tunnel $IFACE ($INNER4, ${INNER6:-no IPv6}); IPv6: $(json protection.ipv6 <"$WORK/status.json"); DNS: $(json protection.dns <"$WORK/status.json"); kill switch: $(json protection.kill_switch <"$WORK/status.json")"
check "the kill switch reports protecting" sh -c "[ \"\$('$OW' -j status | /usr/bin/python3 -I -c 'import json,sys; print(json.load(sys.stdin)[\"protection\"][\"kill_switch\"])')\" = protecting ]"
check "openwarp verify --cloudflare (the daemon's own checks; the ones below are independent)" "$OW" verify --cloudflare
check "Cloudflare reports warp=on" trace_warp
check "IPv4 default goes through $IFACE" sh -c "route -n get 1.1.1.1 | grep -q 'interface: $IFACE'"
check "IPv6 goes through $IFACE or is rejected" sh -c "r=\$(route -n get -inet6 $V6 2>&1); echo \"\$r\" | grep -Eq 'interface: $IFACE|REJECT|not in table'"
check "pf is enabled" sh -c "[ \"\$(pfctl -s info 2>/dev/null | awk '/^Status:/{print \$2}')\" = Enabled ]"
check "the kill switch rules are loaded in $ANCHOR" sh -c "pfctl -a $ANCHOR -s rules 2>/dev/null | grep -q 'block drop quick all'"
check "every kill switch pass rule is stateless" sh -c "! pfctl -a $ANCHOR -s rules 2>/dev/null | grep '^pass' | grep -qv 'no state'"
pfctl -a com.apple -s Anchors >"$WORK/anchors.txt" 2>&1
first=$(awk 'NF{print $1; exit}' "$WORK/anchors.txt")
if [ "$first" = "$ANCHOR" ]; then ok "pf evaluates $ANCHOR before the other com.apple anchors"; else bad "the first com.apple anchor is $first, not $ANCHOR"; sed 's/^/        /' "$WORK/anchors.txt"; fi
refuse "nothing is left in the old anchor $LEGACY_ANCHOR" anchor_has_rules "$LEGACY_ANCHOR"
TOKEN=$(cat "$STATE/pf-token" 2>/dev/null)
check "OpenWarp holds a pf reference (${TOKEN:-none})" sh -c "[ -n '$TOKEN' ] && pfctl -s References 2>/dev/null | grep -qw '$TOKEN'"

sleep 5   # the download's stall timeout is 3 s
if [ "$C_HOLD" = 1 ]; then
  refuse "a download started on $PHYS before connecting was cut (no pf state kept it open)" kill -0 "$HOLD"
else
  skipped "a download started before connecting was cut (it did not start)"
fi
kill "$HOLD" 2>/dev/null; HOLD=

blocked "$C_CURL"  "HTTPS bound to $PHYS is blocked" direct
blocked "$C_TCP4"  "TCP to 1.1.1.1:443 bound to $PHYS is blocked" probe tcp "$PHYS" 1.1.1.1 443
blocked "$C_TCP6"  "IPv6 TCP to [$V6]:443 bound to $PHYS is blocked" probe tcp "$PHYS" "$V6" 443
blocked "$C_DNS4U" "DNS over UDP to 1.1.1.1 bound to $PHYS is blocked" probe dns "$PHYS" 1.1.1.1 udp
blocked "$C_DNS4T" "DNS over TCP to 1.1.1.1 bound to $PHYS is blocked" probe dns "$PHYS" 1.1.1.1 tcp
blocked "$C_DNS6U" "IPv6 DNS over UDP to $V6 bound to $PHYS is blocked" probe dns "$PHYS" "$V6" udp
blocked "$C_NTP4"  "NTP (UDP 123) bound to $PHYS is blocked" probe ntp "$PHYS" "$TIME4"
blocked "$C_NTP6"  "IPv6 NTP (UDP 123) bound to $PHYS is blocked" probe ntp "$PHYS" "$TIME6"
if [ "$GW_RESOLVER" = 1 ]; then
  info "the router is one of the network's resolvers: DNS to it stays allowed for Local Domain Fallback (*.local, *.lan, ...)"
  skipped "DNS to the router is blocked (allowed by design while it is the network's resolver)"
else
  blocked "$C_GWU" "DNS over UDP to the router ($GW) is blocked" probe dns "$PHYS" "$GW" udp
  blocked "$C_GWT" "DNS over TCP to the router ($GW) is blocked" probe dns "$PHYS" "$GW" tcp
fi

# Packet captures on the physical interface, from here until after the restart in stage 3. pf drops blocked
# packets before the interface, so the captures show what actually left the Mac.
FILTER=$("$OW" -j settings | /usr/bin/python3 -I -c '
import json, sys
s = json.load(sys.stdin)
nets = [n for n in s.get("split_ips") or [] if "/" in n or ":" in n or n.count(".") == 3]
parts = ["(ip or ip6)"]
if nets:
    parts.append("not (" + " or ".join("dst net " + n for n in nets) + ")")
parts.append("not (udp and (dst net 162.159.0.0/16 or dst net 2606:4700::/32))")            # the edge (UDP)
parts.append("not (tcp and dst port 443 and (dst host 162.159.192.1 or dst host 2606:4700:d0::a29f:c001))")  # API fallback
parts.append("not (udp and (port 67 or port 68 or port 546 or port 547))")                   # DHCP
parts.append("not (icmp6 and ip6[40] >= 133 and ip6[40] <= 137)")                            # neighbour discovery
print(" and ".join(parts))')
tcpdump -i "$PHYS" -Q out -n -U -w "$WORK/unexpected.pcap" "$FILTER" >"$WORK/tcpdump.log" 2>&1 &
DUMP=$!
INNER_FILTER="src host $INNER4"
[ -n "$INNER6" ] && INNER_FILTER="$INNER_FILTER or src host $INNER6"
tcpdump -i "$PHYS" -Q out -n -U -w "$WORK/inner.pcap" "$INNER_FILTER" >"$WORK/tcpdump-inner.log" 2>&1 &
DUMP2=$!
sleep 2
if ! kill -0 "$DUMP" 2>/dev/null || ! kill -0 "$DUMP2" 2>/dev/null; then bad "tcpdump did not start (see $WORK/tcpdump*.log)"; fi

# ---------- 3. kill -9, launchd restarts the daemon ----------
echo "== 3. the daemon dies (kill -9); launchd restarts it"
# A download through the tunnel while it goes down: its packets carry the tunnel's inner address.
curl -sS --limit-rate 200k -o /dev/null 'https://speed.cloudflare.com/__down?bytes=900000000' 2>/dev/null &
TUNFLOW=$!
PROBES=""
[ "$C_TCP4" = 1 ] && PROBES="$PROBES tcp|1.1.1.1|443"
[ "$C_DNS4U" = 1 ] && PROBES="$PROBES dns|1.1.1.1|udp"
[ "$C_NTP4" = 1 ] && PROBES="$PROBES ntp|$TIME4"
[ "$C_TCP6" = 1 ] && PROBES="$PROBES tcp|$V6|443"
[ "$C_GWU" = 1 ] && [ "$GW_RESOLVER" = 0 ] && PROBES="$PROBES dns|$GW|udp"
sleep 2
LOGSIZE=$(wc -c <"$LOG" | tr -d ' ')
PID=$(pgrep -f "^$HELPER daemon" | head -1)
if [ -n "$PID" ] && [ -n "$PROBES" ]; then
  rm -f "$WORK/stop"
  # shellcheck disable=SC2086 # one argument per probe
  probe watch "$PHYS" "$WORK/stop" "$WORK/watch.log" $PROBES &
  WATCH=$!
  sleep 1
  T_KILL=$(now)
  kill -9 "$PID"
  # Until the process is gone it may still answer as Connected.
  i=0; while [ $i -lt 50 ] && kill -0 "$PID" 2>/dev/null; do sleep 0.1; i=$((i+1)); done
  if wait_status Connected 90; then T_UP=$(now); ok "reconnected after the restart"; else T_UP=$(now); bad "did not reconnect after the restart"; fi
  sleep 1
  touch "$WORK/stop"; wait "$WATCH"; WATCH=
  if summary=$(probe coverage "$WORK/watch.log" "$T_KILL" "$T_UP"); then
    ok "nothing got around the tunnel from the kill until it was back: $summary"
  else
    bad "outage coverage or leak: $summary"
  fi
  check "Cloudflare reports warp=on after the restart" trace_warp
  blocked "$C_TCP4" "traffic around the tunnel is still blocked after the restart" probe tcp "$PHYS" 1.1.1.1 443
  check "the restarted daemon restored the routes and DNS servers from its journal" \
    sh -c "tail -c +$((LOGSIZE+1)) '$LOG' | grep -q 'restored the routes and DNS servers left by a previous run'"
else
  bad "daemon process not found, or no positive control answered"
fi
kill "$TUNFLOW" 2>/dev/null; TUNFLOW=
kill -INT "$DUMP" "$DUMP2" 2>/dev/null; wait "$DUMP" 2>/dev/null; wait "$DUMP2" 2>/dev/null; DUMP=; DUMP2=
tcpdump -n -r "$WORK/unexpected.pcap" 2>/dev/null >"$WORK/unexpected.txt"
n=$(grep -c . "$WORK/unexpected.txt")
if [ "$n" = 0 ]; then ok "packet capture: nothing but the edge, DHCP/ND and the excluded ranges left $PHYS (stages 2 and 3)"
else bad "packet capture: $n unexpected packets left $PHYS (stages 2 and 3):"; head -10 "$WORK/unexpected.txt" | sed 's/^/        /'; fi
tcpdump -n -r "$WORK/inner.pcap" 2>/dev/null >"$WORK/inner.txt"
n=$(grep -c . "$WORK/inner.txt")
if [ "$n" = 0 ]; then ok "packet capture: no packet with the tunnel's inner address left $PHYS"
else bad "packet capture: $n packets with the tunnel's inner address left $PHYS:"; head -10 "$WORK/inner.txt" | sed 's/^/        /'; fi

# ---------- 4. a crash without a restart, then openwarp recover ----------
echo "== 4. a crash with no restart: the service is stopped, a daemon run by hand is killed, then 'openwarp recover'"
launchctl bootout system/com.local.openwarp 2>/dev/null
i=0; while [ $i -lt 15 ] && launchctl print system/com.local.openwarp >/dev/null 2>&1; do sleep 1; i=$((i+1)); done
"$HELPER" daemon >"$WORK/daemon.log" 2>&1 &
MANUAL=$!
if daemon_up 20 && "$OW" connect >/dev/null && wait_status Connected 90; then
  ok "a daemon started by hand connected"
  TOKEN=$(cat "$STATE/pf-token" 2>/dev/null)
  kill -9 "$MANUAL"; MANUAL=
  sleep 2
  check "the network journal survived the crash" test -s "$STATE/network-journal.json"
  check "with no daemon running, the kill switch rules are still loaded" anchor_has_rules "$ANCHOR"
  blocked "$C_TCP4" "with no daemon running, traffic around the tunnel is still blocked" probe tcp "$PHYS" 1.1.1.1 443
  if "$OW" recover >"$WORK/recover.log" 2>&1; then ok "openwarp recover"; else bad "openwarp recover failed:"; sed 's/^/        /' "$WORK/recover.log"; fi
  after_checks "after recover" recover
else
  bad "a daemon started by hand did not connect (see $WORK/daemon.log)"
  [ -n "$MANUAL" ] && kill "$MANUAL" 2>/dev/null; MANUAL=
  "$OW" recover >/dev/null 2>&1
fi
launchctl bootstrap system "$PLIST" 2>/dev/null
if daemon_up 30; then ok "the service is running again"; else bad "the service did not come back (run: sudo launchctl bootstrap system $PLIST)"; fi

# ---------- 5. a normal disconnect ----------
echo "== 5. connect again and disconnect normally"
"$OW" connect >/dev/null
if wait_status Connected 90; then ok "connected again"; else bad "did not connect again"; fi
TOKEN=$(cat "$STATE/pf-token" 2>/dev/null)
"$OW" disconnect >/dev/null
sleep 2
after_checks "after disconnecting" disconnect

restore
trap - INT TERM HUP EXIT
echo "== $pass passed, $fail failed, $skip skipped (service ${TESTED:-unknown}; settings restored: mode $OLD_MODE, kill switch $OLD_KS, status $OLD_STATUS)"
echo "Not covered here: sleep/wake, network changes, a restart of the Mac, other active interfaces, WireGuard, the"
echo "DoH/DoT/tunnel-only modes, Include split mode. Captures and logs: $WORK"
[ $fail = 0 ]
