#!/bin/sh
# Builds and tests the SwiftUI app locally, like the "macOS app" CI workflow.
#
#   scripts/test-app.sh          unit, contract and snapshot tests (no app window, safe to run any time)
#   scripts/test-app.sh ui       also the XCUITest UI tests. These launch the UITest build of OpenWarp and drive
#                                the mouse and keyboard, so keep your hands off them while it runs. The first run
#                                asks to allow UI automation. Your installed OpenWarp and its daemon are not used.
#   scripts/test-app.sh record   re-record the snapshot goldens (review the PNG diff before committing)
set -eu
cd "$(dirname "$0")/.."
command -v xcodegen >/dev/null || { echo "install XcodeGen first: brew install xcodegen" >&2; exit 1; }
xcodegen generate --quiet
DERIVED="${OPENWARP_DERIVED_DATA:-build/DerivedData}"
run() { xcodebuild -project OpenWarp.xcodeproj -destination 'platform=macOS' -derivedDataPath "$DERIVED" "$@"; }

case "${1:-}" in
  record)
    OPENWARP_RECORD_SNAPSHOTS=1 TEST_RUNNER_OPENWARP_RECORD_SNAPSHOTS=1 \
      run -scheme OpenWarp test -only-testing:OpenWarpTests/SnapshotTests
    git status --short ui/macos/Tests/__Snapshots__ ;;
  ui)
    run -scheme OpenWarp test
    run -scheme OpenWarpUITests test ;;
  "")
    run -scheme OpenWarp test ;;
  *)
    echo "usage: $0 [ui|record]" >&2; exit 2 ;;
esac
