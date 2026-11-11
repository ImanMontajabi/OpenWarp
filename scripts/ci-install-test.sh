#!/bin/sh
# End-to-end install test of a packaged DMG, for disposable CI runners only: it copies the app to
# /Applications, launches and quits it, installs the background service as root, checks that the daemon
# runs the right version from the root-owned helper path after the DMG is gone, survives a restart and an
# upgrade with its settings, and uninstalls it. It never registers with Cloudflare or connects, so routes
# and DNS are not touched.
#
#   scripts/ci-install-test.sh dist/OpenWarp-v0.1.0-macos-universal.dmg 0.1.0
#
# The version is the one the build reports (0.1.0, or 0.1.0+dev.1a2b3c4 for a development build).
set -eu
if [ "${GITHUB_ACTIONS:-}" != true ]; then
  echo "refusing to run outside GitHub Actions: this replaces /Applications/OpenWarp.app and the OpenWarp service" >&2
  exit 2
fi
DMG=$1; VERSION=$2
APP=/Applications/OpenWarp.app
CLI="$APP/Contents/Resources/openwarp"
step() { echo; echo "==> $*"; }
fail() { echo "::error::$*"; exit 1; }
# Quit like a user would (Apple Event); fall back to SIGTERM if the runner does not allow Apple Events.
quit_app() { osascript -e 'tell application "OpenWarp" to quit' 2>/dev/null || { echo "(quit via SIGTERM)"; pkill -TERM -x OpenWarp; }; }
json() { python3 -I -c 'import json,sys; d=json.load(sys.stdin); print(d.get(sys.argv[1]))' "$1"; }

step "Install from the DMG and eject it"
MNT=$(mktemp -d)
hdiutil attach -readonly -nobrowse -noautoopen -mountpoint "$MNT" "$DMG" >/dev/null
rm -rf "$APP"
ditto "$MNT/OpenWarp.app" "$APP"
hdiutil detach "$MNT" >/dev/null
rmdir "$MNT"
"$CLI" --version

step "Service status before installing (no root needed)"
"$CLI" -j service status | tee /tmp/st.json
[ "$(json installed </tmp/st.json)" = False ] || fail "a service is already installed"

step "Launch the app without the service, then quit it"
open "$APP"
sleep 8
pgrep -x OpenWarp >/dev/null || fail "OpenWarp is not running 8 s after launch"
quit_app
for _ in $(seq 1 10); do pgrep -x OpenWarp >/dev/null || break; sleep 1; done
pgrep -x OpenWarp >/dev/null && fail "OpenWarp did not quit"
ls ~/Library/Logs/DiagnosticReports/OpenWarp* 2>/dev/null && fail "OpenWarp crashed (see the report above)"

step "Install the service as root (what the app's Install button runs after the macOS prompt)"
sudo "$CLI" service install
ok=0
for _ in $(seq 1 20); do
  "$CLI" -j service status >/tmp/st.json 2>/dev/null || true
  if [ "$(json up_to_date </tmp/st.json)" = True ] && [ "$(json running </tmp/st.json)" = True ]; then ok=1; break; fi
  sleep 1
done
cat /tmp/st.json
[ "$ok" = 1 ] || fail "the service is not running and up to date"
[ "$(json version </tmp/st.json)" = "$VERSION" ] || fail "the daemon does not report $VERSION"
[ "$(json program </tmp/st.json)" = /Library/PrivilegedHelperTools/com.local.openwarp ] || fail "launchd runs the wrong binary"
ls -l /Library/PrivilegedHelperTools/com.local.openwarp /Library/LaunchDaemons/com.local.openwarp.plist /usr/local/bin/openwarp
[ "$(stat -f '%Su:%Sg %Lp' /Library/PrivilegedHelperTools/com.local.openwarp)" = "root:wheel 755" ] || fail "helper is not root:wheel 0755"
[ "$(readlink /usr/local/bin/openwarp)" = /Library/PrivilegedHelperTools/com.local.openwarp ] || fail "CLI link missing"

step "The daemon answers; change a setting (no connection)"
"$CLI" -j status | tee /tmp/status.json
[ "$(json status </tmp/status.json)" = Disconnected ] || fail "unexpected state"
"$CLI" mode proxy
[ "$("$CLI" -j settings | json mode)" = proxy ] || fail "setting not applied"

step "Restart the service: it comes back with its settings"
sudo launchctl kickstart -k system/com.local.openwarp
sleep 3
for _ in $(seq 1 10); do "$CLI" -j status >/dev/null 2>&1 && break; sleep 1; done
[ "$("$CLI" -j settings | json mode)" = proxy ] || fail "settings lost after restart"

step "Reinstall over the running service (the upgrade path): settings survive"
sudo "$CLI" service install
for _ in $(seq 1 10); do "$CLI" -j status >/dev/null 2>&1 && break; sleep 1; done
[ "$("$CLI" -j settings | json mode)" = proxy ] || fail "settings lost after reinstall"
[ "$("$CLI" -j service status | json up_to_date)" = True ] || fail "not up to date after reinstall"

step "Launch the app with the service running, then quit it"
open "$APP"
sleep 8
pgrep -x OpenWarp >/dev/null || fail "OpenWarp is not running"
quit_app
for _ in $(seq 1 10); do pgrep -x OpenWarp >/dev/null || break; sleep 1; done
pgrep -x OpenWarp >/dev/null && fail "OpenWarp did not quit"

step "Uninstall: the service is gone, settings are kept"
sudo "$CLI" service uninstall
"$CLI" -j service status | tee /tmp/st.json
[ "$(json installed </tmp/st.json)" = False ] || fail "still installed"
[ ! -e /Library/PrivilegedHelperTools/com.local.openwarp ] || fail "helper left behind"
sudo test -s "/Library/Application Support/openwarp/state.json" || fail "settings were deleted"
rm -rf "$APP"
echo; echo "Install test passed."
