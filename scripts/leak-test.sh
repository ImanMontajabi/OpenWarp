#!/bin/sh
# Privileged leak-protection test for a real Mac. It CHANGES THIS MAC'S NETWORKING while it runs (connects
# OpenWarp in "Traffic and DNS" mode with the kill switch, kills the daemon on purpose, tries to send traffic
# around the tunnel) and puts the previous mode, kill switch and connection state back at the end.
#
# It is never run in CI and never by automation: it refuses unless all of these hold:
#   - not in CI (CI, GITHUB_ACTIONS unset);
#   - run as root, on macOS, by a person who set OPENWARP_LEAK_TEST=I-UNDERSTAND;
#   - the OpenWarp service (com.local.openwarp) is installed, running, and registered.
#
#   sudo OPENWARP_LEAK_TEST=I-UNDERSTAND scripts/leak-test.sh
#
# It contacts Cloudflare (the connection itself, https://www.cloudflare.com/cdn-cgi/trace) and nothing else.
# Expect a few seconds without network while the daemon restarts. If anything goes wrong, recover with
#   sudo openwarp recover            (removes the kill switch rules, restores routes and DNS)
# Results: PASS/FAIL per check on stdout; exit status 0 only if every check passed.
set -u

die() { echo "leak-test: $*" >&2; exit 2; }
[ -z "${CI:-}" ] && [ -z "${GITHUB_ACTIONS:-}" ] || die "refusing to run in CI: this test changes the machine's networking"
[ "$(uname -s)" = Darwin ] || die "macOS only"
[ "$(id -u)" = 0 ] || die "run with sudo"
[ "${OPENWARP_LEAK_TEST:-}" = I-UNDERSTAND ] || die "set OPENWARP_LEAK_TEST=I-UNDERSTAND to confirm (read the header first)"

OW=${OPENWARP:-/usr/local/bin/openwarp}
[ -x "$OW" ] || die "openwarp not found at $OW (set OPENWARP=...)"
launchctl print system/com.local.openwarp >/dev/null 2>&1 || die "the com.local.openwarp service is not installed"
json() { /usr/bin/python3 -I -c 'import json,sys
d=json.load(sys.stdin)
for k in sys.argv[1].split("."): d=(d or {}).get(k) if isinstance(d,dict) else None
print("" if d is None else d)' "$1"; }
"$OW" -j status | json registered | grep -q True || die "not registered"

pass=0; fail=0
ok()  { pass=$((pass+1)); echo "PASS  $*"; }
bad() { fail=$((fail+1)); echo "FAIL  $*"; }
check() { name=$1; shift; if "$@" >/dev/null 2>&1; then ok "$name"; else bad "$name"; fi; }
refuse() { name=$1; shift; if "$@" >/dev/null 2>&1; then bad "$name"; else ok "$name"; fi; }

# The physical interface and the DNS servers before the test.
PHYS=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')
case "$PHYS" in ""|utun*) die "no physical default route (disconnect OpenWarp first)";; esac
DNS_BEFORE=$(for s in $(networksetup -listallnetworkservices | tail -n +2 | tr ' ' '_'); do
  printf '%s=%s\n' "$s" "$(networksetup -getdnsservers "$(echo "$s" | tr '_' ' ')" | tr '\n' ' ')"; done)
OLD_MODE=$("$OW" -j settings | json mode)
OLD_KS=$("$OW" -j settings | json kill_switch)
OLD_STATUS=$("$OW" -j status | json status)
echo "physical interface: $PHYS; previous mode: $OLD_MODE, kill switch: $OLD_KS, status: $OLD_STATUS"

restore() {
  "$OW" disconnect >/dev/null 2>&1
  "$OW" mode "$OLD_MODE" >/dev/null 2>&1
  if [ "$OLD_KS" = True ]; then "$OW" killswitch on >/dev/null 2>&1; else "$OW" killswitch off >/dev/null 2>&1; fi
  [ "$OLD_STATUS" = Connected ] && "$OW" connect >/dev/null 2>&1
}
trap 'restore; echo "interrupted; settings restored"; exit 3' INT TERM

wait_status() { # wait_status <status> <seconds>
  i=0; while [ $i -lt "$2" ]; do [ "$("$OW" -j status | json status)" = "$1" ] && return 0; sleep 1; i=$((i+1)); done; return 1
}
direct() { curl -sS --max-time 5 --interface "$PHYS" -o /dev/null https://1.1.1.1/cdn-cgi/trace; }
trace_warp() { curl -sS --max-time 10 https://www.cloudflare.com/cdn-cgi/trace | grep -Eq '^warp=(on|plus)$'; }

echo "== connect with the kill switch (Traffic and DNS, UDP)"
"$OW" disconnect >/dev/null
check "direct traffic works before the test" direct
"$OW" mode warp >/dev/null && "$OW" killswitch on >/dev/null && "$OW" connect >/dev/null
if wait_status Connected 90; then ok "connected"; else bad "connected (status: $("$OW" -j status | json status), error: $("$OW" -j status | json error))"; fi
check "openwarp verify --cloudflare" "$OW" verify --cloudflare
check "Cloudflare reports warp=on" trace_warp
IFACE=$("$OW" -j status | json interface)
check "IPv4 default goes through $IFACE" sh -c "route -n get 1.1.1.1 | grep -q 'interface: $IFACE'"
check "IPv6 goes through $IFACE or is rejected" sh -c "r=\$(route -n get -inet6 2606:4700:4700::1111 2>&1); echo \"\$r\" | grep -Eq 'interface: $IFACE|REJECT|not in table'"
refuse "traffic bound to $PHYS (around the tunnel) is blocked" direct
check "pf is enabled" sh -c "pfctl -s info 2>/dev/null | grep -q 'Status: Enabled'"
check "the kill switch rules are loaded" sh -c "pfctl -a com.apple/openwarp -s rules 2>/dev/null | grep -q 'block drop quick all'"
GW=$(route -n get default -ifscope "$PHYS" 2>/dev/null | awk '/gateway:/{print $2}')
if [ -n "$GW" ]; then
  refuse "DNS to the router ($GW) is blocked" dig +time=2 +tries=1 @"$GW" example.com
fi

echo "== the daemon dies (kill -9); launchd restarts it"
PID=$(pgrep -f '/Library/PrivilegedHelperTools/com.local.openwarp daemon' | head -1)
if [ -n "$PID" ]; then
  kill -9 "$PID"
  leaked=0; i=0
  while [ $i -lt 10 ]; do direct && leaked=1; i=$((i+1)); sleep 0.5; done
  if [ $leaked = 0 ]; then ok "no direct traffic while the daemon was down"; else bad "direct traffic got out while the daemon was down"; fi
  if wait_status Connected 90; then ok "reconnected after the restart"; else bad "did not reconnect after the restart"; fi
  check "Cloudflare reports warp=on after the restart" trace_warp
  refuse "traffic around the tunnel is still blocked" direct
else
  bad "daemon process not found"
fi

echo "== disconnect"
"$OW" disconnect >/dev/null
sleep 2
refuse "no kill switch rules after disconnecting" sh -c "pfctl -a com.apple/openwarp -s rules 2>/dev/null | grep -q block"
check "direct traffic works again" direct
refuse "no tunnel routes left" sh -c "netstat -rn | grep -Eq '^(0/1|128.0/1|::/1|8000::/1) .*utun'"
DNS_AFTER=$(for s in $(networksetup -listallnetworkservices | tail -n +2 | tr ' ' '_'); do
  printf '%s=%s\n' "$s" "$(networksetup -getdnsservers "$(echo "$s" | tr '_' ' ')" | tr '\n' ' ')"; done)
if [ "$DNS_BEFORE" = "$DNS_AFTER" ]; then ok "DNS servers restored"; else bad "DNS servers differ: before [$DNS_BEFORE] after [$DNS_AFTER]"; fi

restore
trap - INT TERM
echo "== $pass passed, $fail failed (settings restored: mode $OLD_MODE, kill switch $OLD_KS, status $OLD_STATUS)"
[ $fail = 0 ]
