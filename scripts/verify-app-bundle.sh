#!/bin/sh
# Checks a built OpenWarp.app: icon resources and Info.plist keys, version, executable architectures.
#   scripts/verify-app-bundle.sh build/OpenWarp.app [arm64 x86_64]
set -eu
APP="$1"; shift
fail=0
err() { echo "::error::$*"; fail=1; }
plist="$APP/Contents/Info.plist"
[ -f "$plist" ] || { echo "::error::no Info.plist in $APP"; exit 1; }
key() { /usr/libexec/PlistBuddy -c "Print :$1" "$plist" 2>/dev/null || true; }

[ "$(key CFBundleIconName)" = AppIcon ] || err "CFBundleIconName is not AppIcon"
[ "$(key CFBundleIconFile)" = AppIcon ] || err "CFBundleIconFile is not AppIcon"
[ -s "$APP/Contents/Resources/Assets.car" ] || err "Assets.car missing"
[ -s "$APP/Contents/Resources/AppIcon.icns" ] || err "AppIcon.icns (legacy fallback) missing"
# macOS reads the icon from Assets.car (CFBundleIconName); it must hold all ten macOS sizes, 16pt to 512pt@2x.
renditions=$(xcrun assetutil --info "$APP/Contents/Resources/Assets.car" 2>/dev/null | python3 -I -c '
import json, sys
print(" ".join(sorted({"%sx%s" % (r["PixelWidth"], r["Scale"]) for r in json.load(sys.stdin)[1:]
                       if r.get("Name") == "AppIcon" and r.get("PixelWidth")})))' || true)
for want in 16x1 32x2 32x1 64x2 128x1 256x2 256x1 512x2 512x1 1024x2; do
  case " $renditions " in *" $want "*) ;; *) err "Assets.car lacks the AppIcon rendition ${want%x*}px @${want#*x}x" ;; esac
done
cli=$(sed -n 's/^const Version = "\(.*\)"$/\1/p' "$(dirname "$0")/../internal/buildinfo/buildinfo.go")
[ "$(key CFBundleShortVersionString)" = "$cli" ] || err "app version $(key CFBundleShortVersionString) != CLI version $cli"
exe="$APP/Contents/MacOS/$(key CFBundleExecutable)"
for arch in "$@"; do
  lipo -archs "$exe" | tr ' ' '\n' | grep -qx "$arch" || err "executable lacks $arch"
done
[ "$fail" = 0 ] && echo "$APP: icon, Info.plist and architectures OK"
exit "$fail"
