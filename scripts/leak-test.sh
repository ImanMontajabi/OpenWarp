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
#      download started on the physical interface that must be receiving data. A leak check whose control
#      did not answer is reported as SKIP: a block that also happens without OpenWarp proves nothing.
#   2. Connected with the kill switch: the same probes must fail, the download must stop receiving, the
#      routes, pf anchor order and rules are checked, pf's evaluation order is tested with two temporary
#      test anchors of its own (one sorting after OpenWarp's, one before as the positive control; nothing
#      else in pf is touched), and two packet captures on the physical interface start (anything
#      unexpected sent out of it; anything with the tunnel's inner address).
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
# Every route change during the test is recorded (route -n monitor) for attribution.
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
# Background probes call python3 directly, not the function: then $! is the Python process itself. With the
# function, $! was a subshell, and killing it left the probe running after the test.
now() { /usr/bin/python3 -I -c 'import time; print("%.3f" % time.time())'; }
# calc EXPR: arithmetic on the timestamps above (the operands are numbers this script produced).
calc() { /usr/bin/python3 -I -c 'import sys; print("%.3f" % eval(sys.argv[1], {"__builtins__": {}, "max": max}))' "$1"; }

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
# json KEY: prints a field of the JSON on stdin; exit 1, silently, when stdin is empty or not JSON (the daemon
# is down or restarting).
json() { /usr/bin/python3 -I -c 'import json,sys
try:
    d=json.load(sys.stdin)
except ValueError:
    sys.exit(1)
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
STREAM_URL_PATH='/__down?bytes=50000000'   # speed.cloudflare.com answers 403 above 100 MB
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
# status_now: reads the daemon's status into LAST_STATUS; when the daemon does not answer (expected while it
# restarts), returns 1 and keeps the CLI's error in LAST_ERR.
LAST_STATUS=; LAST_ERR=; DOWN_POLLS=0
status_now() {
  out=$("$OW" -j status 2>"$WORK/cli.err")
  if st=$(printf '%s' "$out" | json status) && [ -n "$st" ]; then LAST_STATUS=$st; LAST_ERR=; return 0; fi
  LAST_STATUS="(no answer)"; LAST_ERR=$(tr '\n' ' ' <"$WORK/cli.err" | cut -c1-200); return 1
}
wait_status() { # wait_status <status> <seconds>: polls once a second; on timeout says what it last saw
  i=0; DOWN_POLLS=0
  while [ $i -lt "$2" ]; do
    if status_now; then [ "$LAST_STATUS" = "$1" ] && return 0; else DOWN_POLLS=$((DOWN_POLLS+1)); fi
    sleep 1; i=$((i+1))
  done
  info "no '$1' status within $2 s: last status $LAST_STATUS${LAST_ERR:+ (CLI: $LAST_ERR)}; $DOWN_POLLS polls got no answer"
  return 1
}
daemon_up() { i=0; while [ $i -lt "$1" ]; do "$OW" -j status >/dev/null 2>&1 && return 0; sleep 1; i=$((i+1)); done; return 1; }

DNS_BEFORE=$(dns_servers)
routes >"$WORK/routes.before"
# Every routing-socket message from here on (adds, deletes, changes, with the time), for attribution.
route -n monitor >"$WORK/route-monitor.log" 2>&1 &
RTMON=$!
# The destinations OpenWarp's route commands touch: the split-tunnel list and the tunnel's halves.
MANAGED="$("$OW" -j settings | /usr/bin/python3 -I -c 'import json,sys; print(" ".join(json.load(sys.stdin).get("split_ips") or []))') 0.0.0.0/1 128.0.0.0/1 ::/1 8000::/1"
PF_BEFORE=$(pf_status)
OLD_MODE=$("$OW" -j settings | json mode)
OLD_KS=$("$OW" -j settings | json kill_switch)
OLD_STATUS=$("$OW" -j status | json status)
RESOLVERS=$(scutil --dns | awk '/nameserver\[/{print $3}' | sort -u | tr '\n' ' ')
echo "OpenWarp service version under test: ${TESTED:-unknown} ($HELPER)"
echo "physical interface: $PHYS, router: ${GW:-none}, resolvers: $RESOLVERS"
echo "pf before the test: $PF_BEFORE; previous mode: $OLD_MODE, kill switch: $OLD_KS, status: $OLD_STATUS"
echo "work directory (captures, logs): $WORK"

MANUAL=; HOLD=; TUNFLOW=; DUMP=; DUMP2=; WATCH=; RESTORED=; TUNS=
TEST_AFTER=com.apple/zzz.openwarp-leaktest   # sorts after OpenWarp's anchor
TEST_BEFORE=com.apple/0.openwarp-leaktest    # sorts before it ("." < "0"): the positive control
# restore puts the service, mode, kill switch and connection back as they were. It runs once: at the end, on
# Ctrl-C, a terminal that closes, or any unexpected exit after this point.
restore() {
  [ -n "$RESTORED" ] && return
  RESTORED=1
  for p in $HOLD $TUNFLOW $WATCH $DUMP $DUMP2 $RTMON; do kill "$p" 2>/dev/null; done
  pfctl -q -a "$TEST_BEFORE" -F all 2>/dev/null; pfctl -q -a "$TEST_AFTER" -F all 2>/dev/null
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
  # The captures and logs belong to the person who ran the test (they hold only this Mac's own traffic).
  [ -n "${SUDO_UID:-}" ] && chown -R "$SUDO_UID" "$WORK" 2>/dev/null
}
trap 'restore; echo "interrupted; settings restored"; exit 3' INT TERM HUP
trap 'restore' EXIT

# route_checks WHERE TAG: the routing table is as before the test. A difference at a destination OpenWarp's
# route commands touch (MANAGED, an edge host route, a route on one of its tunnels, TUNS) always fails. Other differences
# are given 15 s, because macOS changes some routes by itself; one that is still there then fails too, and is
# reported as outside OpenWarp's destinations. route-monitor.log shows when each change happened.
route_checks() {
  where=$1; tag=$2; i=0
  while :; do
    routes >"$WORK/routes.$tag"
    # shellcheck disable=SC2086 # one argument per prefix
    if probe routes-diff "$WORK/routes.before" "$WORK/routes.$tag" "$(echo $TUNS | tr ' ' ',')" $MANAGED >"$WORK/routes.$tag.diff"; then
      if [ $i = 0 ]; then ok "$where: the routing table is as before the test (no tunnel, reject, edge or split routes left)"
      else ok "$where: the routing table is as before the test after ${i} s (transient changes outside OpenWarp's destinations:"; sed 's/^other /        /' "$WORK/routes.$tag.first.diff"; echo "      )"; fi
      return
    fi
    [ $i = 0 ] && cp "$WORK/routes.$tag.diff" "$WORK/routes.$tag.first.diff"
    if grep -q '^openwarp ' "$WORK/routes.$tag.diff" || [ $i -ge 15 ]; then break; fi
    sleep 1; i=$((i+1))
  done
  if grep -q '^openwarp ' "$WORK/routes.$tag.diff"; then
    bad "$where: routes at destinations OpenWarp manages differ from before the test (- missing, + added):"
  else
    bad "$where: the routing table still differs after 15 s, at destinations OpenWarp's route commands do not touch:"
  fi
  sed 's/^/        /' "$WORK/routes.$tag.diff" | head -20
  awk '{print $3}' "$WORK/routes.$tag.diff" | sort -u | while read -r d; do
    info "route-monitor.log: $(grep -c -F "$d" "$WORK/route-monitor.log" 2>/dev/null) lines mention $d"
  done
}

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
  route_checks "$where" "$2"
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
# A download on the physical interface that is already receiving data when the kill switch comes on.
/usr/bin/python3 -I "$PROBE_PY" stream "$PHYS" speed.cloudflare.com "$STREAM_URL_PATH" "$WORK/hold.log" &
HOLD=$!
sleep 4
t=$(now)
# shellcheck disable=SC2046 # "bytes status end" into $1 $2 $3
set -- $(probe bytes "$WORK/hold.log" "$(calc "$t - 2")" "$t")
if [ "${1:-0}" -ge 65536 ]; then
  C_HOLD=1; echo "CTRL  download on $PHYS receiving ($1 bytes in the last 2 s, HTTP $2)"
else
  C_HOLD=0; echo "CTRL  download on $PHYS not receiving (${1:-0} bytes in 2 s, HTTP ${2:-?}, ${3:-?}; its check is skipped)"
fi

# ---------- 2. connected ----------
echo "== 2. connect with the kill switch (Traffic and DNS)"
"$OW" mode warp >/dev/null && "$OW" killswitch on >/dev/null && "$OW" connect >/dev/null
if wait_status Connected 90; then ok "connected"; else bad "connected (error: $("$OW" -j status 2>/dev/null | json error))"; fi
T_CONN=$(now)
routes >"$WORK/routes.connected"
TUNS=$("$OW" -j status 2>/dev/null | json interface)   # every tunnel interface used during the test
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
# pfctl writes "No ALTQ support in kernel" and "ALTQ related functions disabled" to stderr: keep them out.
pfctl -a com.apple -s Anchors >"$WORK/anchors.txt" 2>"$WORK/anchors.err"
awk 'NF{a=$1; if (a !~ /^com\.apple\//) a="com.apple/" a; print a}' "$WORK/anchors.txt" >"$WORK/anchors.list"
info "com.apple anchors as pf lists them: $(tr '\n' ' ' <"$WORK/anchors.list")"
# An anchor listed before OpenWarp's matters only if it has rules: pf keeps empty anchors (an earlier run of
# this test leaves its test anchors behind, empty), and an empty one cannot end evaluation. The daemon's own
# audit (openwarp verify) applies the same rule.
EARLIER=$(awk -v a="$ANCHOR" '$0 == a {exit} {print}' "$WORK/anchors.list")
BUSY=; for a in $EARLIER; do anchor_has_rules "$a" && BUSY="$BUSY $a"; done
if ! grep -qxF "$ANCHOR" "$WORK/anchors.list"; then
  bad "$ANCHOR is not in pf's list of com.apple anchors"; sed 's/^/        /' "$WORK/anchors.txt"
elif [ -n "$BUSY" ]; then
  bad "com.apple anchors with rules are listed before $ANCHOR:$BUSY"; sed 's/^/        /' "$WORK/anchors.txt"
else
  ok "no com.apple anchor with rules is listed before $ANCHOR"
  [ -n "$EARLIER" ] && info "listed before it, without rules: $(printf '%s' "$EARLIER" | tr '\n' ' ')"
fi
# The listing alone does not prove the order pf evaluates them in; the test anchors below measure it.
if LC_ALL=C sort -c "$WORK/anchors.list" 2>/dev/null; then info "the listing is in byte order of the names"; else info "the listing is NOT in byte order of the names"; fi
# What pf evaluates before the com.apple anchors, and what could skip the filter altogether.
pfctl -s rules 2>/dev/null >"$WORK/main-rules.txt"
awk '/^anchor "com\.apple\/\*"/{exit} NF' "$WORK/main-rules.txt" >"$WORK/before-hook.txt"
# Only a rule that can end evaluation there ('pass ... quick', or a call to another anchor) can overtake the
# kill switch; later rules cannot, since all of OpenWarp's rules are 'quick'.
grep -E '^anchor |^pass.* quick' "$WORK/before-hook.txt" >"$WORK/before-hook.bad"
if [ -s "$WORK/before-hook.bad" ]; then
  bad "the main pf ruleset can end evaluation before anchor \"com.apple/*\":"; sed 's/^/        /' "$WORK/before-hook.bad"
else ok "nothing in the main pf ruleset can end evaluation before anchor \"com.apple/*\" ($(grep -c . "$WORK/before-hook.txt") rules before it)"; fi
: >"$WORK/nat-pass.txt"
{ pfctl -s nat 2>/dev/null; while read -r a; do pfctl -a "$a" -s nat 2>/dev/null; done <"$WORK/anchors.list"; } |
  grep -E '^(nat|rdr|binat)[^#]* pass ' >>"$WORK/nat-pass.txt"
if [ -s "$WORK/nat-pass.txt" ]; then
  bad "translation rules with 'pass' (their packets skip the filter rules, the kill switch included):"; sed 's/^/        /' "$WORK/nat-pass.txt"
else ok "no nat/rdr/binat rule with 'pass' (nothing skips the filter rules)"; fi
while read -r a; do
  [ "$a" = "$ANCHOR" ] && continue
  n=$(pfctl -a "$a" -s rules 2>/dev/null | grep -c .)
  q=$(pfctl -a "$a" -s rules 2>/dev/null | grep -c '^pass.* quick')
  info "other anchor $a: $n rules, $q 'pass quick' (evaluated after the kill switch, which ends evaluation for every packet)"
done <"$WORK/anchors.list"

# Evaluation order, measured: a 'pass quick' for one probe flow (TCP to 1.1.1.1:443 on $PHYS, stateless) in a
# temporary anchor of this test. After OpenWarp's anchor it must not get through; before it (the positive
# control) it must, or this check could not detect a precedence failure. Then it is removed again.
pass_probe_rules() {
  printf 'pass out quick on %s inet proto tcp from any to 1.1.1.1 port 443 no state\n' "$PHYS"
  printf 'pass in quick on %s inet proto tcp from 1.1.1.1 port 443 to any no state\n' "$PHYS"
}
# pf_counters ANCHOR NAME: saves pf's counters for the rules of a test anchor to $WORK/pf-counters.NAME.* and
# reports them. pf counts an evaluation of an anchor's first rule for every packet that enters the anchor,
# before any skip step, so FIRST_EVAL (that count, "-" if pfctl printed none) says whether pf evaluated the
# anchor at all; OUT_PKTS and IN_PKTS are the packets the probe's two rules passed.
pf_counters() {
  PFC_ANCHOR=$1; PFC_LIST="$WORK/pf-counters.$2.list"
  pfctl -a "$1" -vv -s rules >"$WORK/pf-counters.$2.txt" 2>/dev/null
  probe pf-counters "$WORK/pf-counters.$2.txt" >"$PFC_LIST"
  while read -r ev pk rule; do info "  pf counters in $PFC_ANCHOR: evaluated $ev, matched $pk packets: $rule"; done <"$PFC_LIST"
  # shellcheck disable=SC2046 # "evaluations packets" of the first and the second rule (this replaces $1 $2)
  set -- $(awk 'NR <= 2 {printf "%s %s ", $1, $2}' "$PFC_LIST")
  FIRST_EVAL=${1:--}; OUT_PKTS=${2:--}; IN_PKTS=${4:--}
}
if [ "$C_TCP4" = 1 ]; then
  if pass_probe_rules | pfctl -q -a "$TEST_AFTER" -f - 2>"$WORK/pf-test.err" && anchor_has_rules "$TEST_AFTER"; then
    refuse "a 'pass quick' in an anchor that sorts after the kill switch ($TEST_AFTER) does not get through" probe tcp "$PHYS" 1.1.1.1 443
    pf_counters "$TEST_AFTER" after
    # Every packet that enters OpenWarp's anchor ends there ('block drop quick all' comes last), so pf must
    # never get to an anchor evaluated after it.
    case $FIRST_EVAL in
      -) bad "could not read pf's counters for $TEST_AFTER (see $WORK/pf-counters.after.txt)";;
      0) ok "pf never evaluated $TEST_AFTER: the kill switch ended evaluation before it";;
      *) bad "pf evaluated $TEST_AFTER $FIRST_EVAL times although the kill switch ends evaluation for every packet: pf does not evaluate the com.apple anchors in the order they are listed";;
    esac
  else bad "could not load the test anchor $TEST_AFTER: $(cat "$WORK/pf-test.err")"; fi
  pfctl -q -a "$TEST_AFTER" -F all 2>/dev/null
  if pass_probe_rules | pfctl -q -a "$TEST_BEFORE" -f - 2>"$WORK/pf-test.err" && anchor_has_rules "$TEST_BEFORE"; then
    check "positive control: the same rule in an anchor that sorts before it ($TEST_BEFORE) gets through" probe tcp "$PHYS" 1.1.1.1 443
    pf_counters "$TEST_BEFORE" before
    case $FIRST_EVAL in
      -) bad "could not read pf's counters for $TEST_BEFORE (see $WORK/pf-counters.before.txt)";;
      0) bad "pf never evaluated $TEST_BEFORE although it is listed before $ANCHOR: pf does not evaluate the com.apple anchors in the order they are listed";;
      *) ok "pf evaluated $TEST_BEFORE ($FIRST_EVAL packets entered it) before the kill switch"
         # What the positive control's probe met there. Information only: the check above stays as it is.
         if [ "$OUT_PKTS" = 0 ]; then info "  the probe's SYN never matched the 'pass out' rule (it did not leave on $PHYS as expected)"
         elif [ "$IN_PKTS" = 0 ]; then info "  pf passed $OUT_PKTS packets out to 1.1.1.1:443 and no reply came in on $PHYS"
         else info "  pf passed $OUT_PKTS packets out and $IN_PKTS replies in: the probe failed for a reason outside pf's rule order"; fi;;
    esac
    check "openwarp verify reports the anchor that pf evaluates before the kill switch" \
      sh -c "'$OW' verify 2>&1 | grep -q '0.openwarp-leaktest'"
  else bad "could not load the test anchor $TEST_BEFORE: $(cat "$WORK/pf-test.err")"; fi
  pfctl -q -a "$TEST_BEFORE" -F all 2>/dev/null
  refuse "TCP to 1.1.1.1:443 bound to $PHYS is blocked again once the test anchor is empty" probe tcp "$PHYS" 1.1.1.1 443
  check "openwarp verify passes again" "$OW" verify
else
  skipped "pf evaluation order, measured (TCP to 1.1.1.1:443 did not answer before connecting)"
fi
refuse "nothing is left in the old anchor $LEGACY_ANCHOR" anchor_has_rules "$LEGACY_ANCHOR"
TOKEN=$(cat "$STATE/pf-token" 2>/dev/null)
check "OpenWarp holds a pf reference (${TOKEN:-none})" sh -c "[ -n '$TOKEN' ] && pfctl -s References 2>/dev/null | grep -qw '$TOKEN'"

if [ "$C_HOLD" = 1 ]; then
  wait_left=$(calc "max(0, $T_CONN + 8 - $(now))"); sleep "$wait_left"
  # shellcheck disable=SC2046 # "bytes status end" into $1 $2 $3
  set -- $(probe bytes "$WORK/hold.log" "$(calc "$T_CONN + 2")" "$(now)")
  before=$(probe bytes "$WORK/hold.log" 0 "$T_CONN" | awk '{print $1}')
  if [ "${1:-x}" = 0 ]; then ok "a download that was receiving on $PHYS before connecting got nothing more once connected ($before bytes before; stream: ${3:-running})"
  else bad "a download started on $PHYS before connecting still received ${1:-?} bytes after connecting (no pf state may keep it open)"; fi
else
  skipped "a download started before connecting was cut (it was not receiving before connecting)"
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
/usr/bin/python3 -I "$PROBE_PY" stream - speed.cloudflare.com "$STREAM_URL_PATH" "$WORK/tunflow.log" &
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
  /usr/bin/python3 -I "$PROBE_PY" watch "$PHYS" "$WORK/stop" "$WORK/watch.log" $PROBES &
  WATCH=$!
  sleep 1
  T_KILL=$(now)
  # shellcheck disable=SC2046 # "bytes status end" into $1 $2 $3
  set -- $(probe bytes "$WORK/tunflow.log" "$(calc "$T_KILL - 2")" "$T_KILL")
  if [ "${1:-0}" -gt 0 ]; then C_TUN=1; echo "CTRL  download through $IFACE receiving (${1} bytes in the 2 s before the kill)"
  else C_TUN=0; echo "CTRL  download through $IFACE not receiving (HTTP ${2:-?}, ${3:-?}): the inner-address capture is skipped"; fi
  kill -9 "$PID"
  # Until the process is gone it may still answer as Connected.
  i=0; while [ $i -lt 50 ] && kill -0 "$PID" 2>/dev/null; do sleep 0.1; i=$((i+1)); done
  if wait_status Connected 90; then T_UP=$(now); ok "reconnected after the restart"; else T_UP=$(now); bad "did not reconnect after the restart"; fi
  TUNS="$TUNS $("$OW" -j status 2>/dev/null | json interface)"
  info "the daemon did not answer for $DOWN_POLLS status polls during the restart (expected)"
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
if [ "$n" != 0 ]; then bad "packet capture: $n packets with the tunnel's inner address left $PHYS:"; head -10 "$WORK/inner.txt" | sed 's/^/        /'
elif [ "${C_TUN:-0}" = 1 ]; then ok "packet capture: no packet with the tunnel's inner address left $PHYS (a download was running through the tunnel when it went down)"
else skipped "packet capture of the tunnel's inner address (no download was running through the tunnel to exercise it)"; fi

# ---------- 4. a crash without a restart, then openwarp recover ----------
echo "== 4. a crash with no restart: the service is stopped, a daemon run by hand is killed, then 'openwarp recover'"
launchctl bootout system/com.local.openwarp 2>/dev/null
i=0; while [ $i -lt 15 ] && launchctl print system/com.local.openwarp >/dev/null 2>&1; do sleep 1; i=$((i+1)); done
"$HELPER" daemon >"$WORK/daemon.log" 2>&1 &
MANUAL=$!
if daemon_up 20 && "$OW" connect >/dev/null && wait_status Connected 90; then
  ok "a daemon started by hand connected"
  TUNS="$TUNS $("$OW" -j status 2>/dev/null | json interface)"
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
TUNS="$TUNS $("$OW" -j status 2>/dev/null | json interface)"
TOKEN=$(cat "$STATE/pf-token" 2>/dev/null)
"$OW" disconnect >/dev/null
sleep 2
after_checks "after disconnecting" disconnect

restore
trap - INT TERM HUP EXIT
echo "== $pass passed, $fail failed, $skip skipped (service ${TESTED:-unknown}; settings restored: mode $OLD_MODE, kill switch $OLD_KS, status $OLD_STATUS)"
echo "Route changes during the test: $WORK/route-monitor.log"
echo "Not covered here: sleep/wake, network changes, a restart of the Mac, other active interfaces, WireGuard, the"
echo "DoH/DoT/tunnel-only modes, Include split mode. Captures and logs: $WORK"
[ $fail = 0 ]
