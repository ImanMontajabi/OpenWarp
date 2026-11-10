#!/bin/sh
# Packages a built OpenWarp.app into a compressed, read-only DMG with an Applications shortcut and the
# OpenWarp window layout (dark background from assets/dmg, two large icons, an arrow between them).
#
#   scripts/make-dmg.sh build/OpenWarp.app dist/OpenWarp-v0.1.0-macos-universal.dmg
#
# Only built-in macOS tools (hdiutil, tiffutil, osascript, SetFile). The window layout is written by
# Finder through AppleScript, which needs a logged-in GUI session (CI runners have one; the first local
# run asks to let the terminal control Finder). OPENWARP_DMG_PLAIN=1 skips the layout and still produces
# a working DMG; release builds require the layout (scripts/verify-dmg.sh checks it).
set -eu
APP=$1
OUT=$2
[ -d "$APP/Contents/MacOS" ] || { echo "not an app bundle: $APP" >&2; exit 1; }
ROOT=$(cd "$(dirname "$0")/.." && pwd)
VERSION=$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$APP/Contents/Info.plist")
VOL="OpenWarp $VERSION"
mkdir -p "$(dirname "$OUT")"
rm -f "$OUT"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/openwarp-dmg.XXXXXX")
MNT=""
cleanup() {
  [ -n "$MNT" ] && hdiutil detach "$MNT" -force >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

# 1. Staging folder: the app (ditto keeps the signature and permissions), the Applications link and the
#    HiDPI background.
STAGE="$WORK/stage"
mkdir -p "$STAGE/.background"
ditto "$APP" "$STAGE/OpenWarp.app"
ln -s /Applications "$STAGE/Applications"
tiffutil -cathidpicheck "$ROOT/assets/dmg/background.png" "$ROOT/assets/dmg/background@2x.png" \
  -out "$STAGE/.background/background.tiff" >/dev/null 2>&1

# 2. A writable image to lay out.
SIZE_MB=$(( $(du -sm "$STAGE" | cut -f1) + 20 ))
hdiutil create -quiet -srcfolder "$STAGE" -volname "$VOL" -fs HFS+ -format UDRW -size "${SIZE_MB}m" "$WORK/rw.dmg"
MNT=$(hdiutil attach -readwrite -noverify -noautoopen "$WORK/rw.dmg" | sed -n 's|^/dev/[^[:space:]]*[[:space:]]*Apple_HFS[[:space:]]*||p')
[ -d "$MNT" ] || { echo "could not mount the writable image" >&2; exit 1; }
DISK=$(basename "$MNT")

# 3. Finder layout: icon view, no toolbar, the background, icons where the background's arrow expects them.
if [ "${OPENWARP_DMG_PLAIN:-}" != 1 ]; then
  layout_ok=0
  for attempt in 1 2 3; do
    if osascript - "$DISK" <<'APPLESCRIPT'
on run argv
  set diskName to item 1 of argv
  tell application "Finder"
    tell disk diskName
      open
      delay 1
      set current view of container window to icon view
      set toolbar visible of container window to false
      set statusbar visible of container window to false
      set the bounds of container window to {200, 120, 840, 548}
      set opts to the icon view options of container window
      set arrangement of opts to not arranged
      set icon size of opts to 112
      set text size of opts to 13
      set background picture of opts to file ".background:background.tiff"
      set position of item "OpenWarp.app" of container window to {170, 190}
      set position of item "Applications" of container window to {470, 190}
      update without registering applications
      delay 2
      close
    end tell
  end tell
end run
APPLESCRIPT
    then layout_ok=1; break; fi
    echo "Finder layout attempt $attempt failed; retrying" >&2
    sleep 3
  done
  [ "$layout_ok" = 1 ] || { echo "error: could not lay out the DMG window with Finder (OPENWARP_DMG_PLAIN=1 skips it)" >&2; exit 1; }
  # Finder writes .DS_Store asynchronously.
  for _ in 1 2 3 4 5 6 7 8 9 10; do [ -s "$MNT/.DS_Store" ] && break; sleep 1; done
  [ -s "$MNT/.DS_Store" ] || { echo "error: Finder did not save the window layout" >&2; exit 1; }
fi

# The volume icon goes in after the Finder layout (Finder dropped it on the CI runner when it was copied
# in with the staging folder).
cp "$APP/Contents/Resources/AppIcon.icns" "$MNT/.VolumeIcon.icns"
SetFile=$(xcrun -f SetFile 2>/dev/null || true)
if [ -n "$SetFile" ]; then "$SetFile" -a C "$MNT"; else echo "note: SetFile not found; the volume keeps the default icon"; fi
[ -s "$MNT/.VolumeIcon.icns" ] || { echo "error: volume icon missing" >&2; exit 1; }

chmod -Rf go-w "$MNT" 2>/dev/null || true
ls -la "$MNT"
sync
hdiutil detach "$MNT" -quiet || { sleep 2; hdiutil detach "$MNT" -force -quiet; }
MNT=""

# 4. Compressed, read-only image.
hdiutil convert -quiet "$WORK/rw.dmg" -format UDZO -imagekey zlib-level=9 -o "$OUT"
hdiutil verify -quiet "$OUT"
echo "$OUT ($(du -h "$OUT" | cut -f1 | tr -d ' '))"
