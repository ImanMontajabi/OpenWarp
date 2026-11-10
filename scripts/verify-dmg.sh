#!/bin/sh
# Checks a packaged OpenWarp DMG without changing anything: mounts it read-only (hidden from Finder) and
# checks the layout, the app bundle (scripts/verify-app-bundle.sh), signatures, architectures, permissions
# and that nothing links against a developer machine's paths.
#
#   scripts/verify-dmg.sh dist/OpenWarp-v0.1.0-macos-universal.dmg 0.1.0 [arm64 x86_64]
set -eu
DMG=$1; VERSION=$2; shift 2
ARCHS=${*:-arm64 x86_64}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
fail=0
err() { echo "::error::$*"; fail=1; }

hdiutil verify -quiet "$DMG" || err "hdiutil verify failed"
format=$(hdiutil imageinfo "$DMG" | sed -n 's/^Format: //p')
[ "$format" = UDZO ] || err "image format is $format, expected UDZO (compressed, read-only)"

MNT=$(mktemp -d "${TMPDIR:-/tmp}/openwarp-verify.XXXXXX")
hdiutil attach -readonly -nobrowse -noautoopen -mountpoint "$MNT" "$DMG" >/dev/null
trap 'hdiutil detach "$MNT" -force >/dev/null 2>&1 || true; rmdir "$MNT" 2>/dev/null || true' EXIT

APP="$MNT/OpenWarp.app"
[ -d "$APP" ] || err "OpenWarp.app missing"
[ "$(readlink "$MNT/Applications")" = /Applications ] || err "Applications shortcut missing"
[ -s "$MNT/.background/background.tiff" ] || err "window background missing"
[ -s "$MNT/.DS_Store" ] || err "window layout (.DS_Store) missing"
[ -s "$MNT/.VolumeIcon.icns" ] || err "volume icon missing"

# The bundle: icon, Info.plist, version, licenses, architectures.
"$ROOT/scripts/verify-app-bundle.sh" "$APP" $ARCHS || fail=1
[ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$APP/Contents/Info.plist")" = "$VERSION" ] \
  || err "app version is not $VERSION"
CLI="$APP/Contents/Resources/openwarp"
cli_version=$("$CLI" --version 2>/dev/null || true)
[ "$cli_version" = "openwarp $VERSION" ] || err "bundled CLI reports '$cli_version', expected 'openwarp $VERSION'"
for arch in $ARCHS; do
  lipo -archs "$CLI" | tr ' ' '\n' | grep -qx "$arch" || err "bundled CLI lacks $arch"
done

# Executables are executable and nothing is writable by others.
[ -x "$APP/Contents/MacOS/OpenWarp" ] || err "app executable is not executable"
[ -x "$CLI" ] || err "bundled CLI is not executable"
if find "$APP" -perm -o+w | grep -q .; then err "world-writable files in the bundle"; fi

# Signatures: ad-hoc (no Developer ID). Verified, never described as anything else.
codesign --verify --strict "$CLI" || err "bundled CLI signature invalid"
codesign --verify --deep --strict "$APP" || err "app signature invalid"
sig=$(codesign -dv "$APP" 2>&1 | sed -n 's/^Signature=//p')
[ "$sig" = adhoc ] || err "expected an ad-hoc signature, found '$sig'"

# Runtime dependencies: only system libraries, no rpaths into a build machine.
for exe in "$APP/Contents/MacOS/OpenWarp" "$CLI"; do
  for arch in $ARCHS; do
    bad=$(otool -arch "$arch" -L "$exe" | tail -n +2 | awk '{print $1}' | grep -vE '^(/usr/lib/|/System/Library/)' || true)
    [ -z "$bad" ] || err "$(basename "$exe") ($arch) links outside the system: $bad"
    if otool -arch "$arch" -l "$exe" | grep -A2 LC_RPATH | grep -E 'path /(Users|Volumes|private|tmp)/' ; then
      err "$(basename "$exe") ($arch) has an rpath into a build machine"
    fi
  done
done

[ "$fail" = 0 ] && echo "$DMG: layout, bundle, signatures (ad-hoc), architectures ($ARCHS) and dependencies OK"
exit "$fail"
