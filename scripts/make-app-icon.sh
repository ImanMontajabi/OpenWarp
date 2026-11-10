#!/bin/sh
# Regenerates ui/macos/Assets.xcassets/AppIcon.appiconset from the 1024x1024 master in assets/icon/.
# Downscaling only (sips, high-quality resampling); the master is never modified or upscaled.
set -eu
cd "$(dirname "$0")/.."
SRC="assets/icon/icon.PNG"
SET="ui/macos/Assets.xcassets/AppIcon.appiconset"

w=$(sips -g pixelWidth "$SRC" | awk '/pixelWidth/ {print $2}')
h=$(sips -g pixelHeight "$SRC" | awk '/pixelHeight/ {print $2}')
[ "$w" = 1024 ] && [ "$h" = 1024 ] || { echo "the master icon must be 1024x1024 (is ${w}x${h})" >&2; exit 1; }

mkdir -p "$SET"
cat > ui/macos/Assets.xcassets/Contents.json <<'JSON'
{
  "info" : { "author" : "xcode", "version" : 1 }
}
JSON

images=""
for pt in 16 32 128 256 512; do
  for scale in 1 2; do
    px=$((pt * scale))
    suffix=""; [ "$scale" = 1 ] || suffix="@2x"
    name="icon_${pt}x${pt}${suffix}.png"
    if [ "$px" = 1024 ]; then cp "$SRC" "$SET/$name"; else sips -s format png -z "$px" "$px" "$SRC" --out "$SET/$name" >/dev/null; fi
    images="$images    { \"filename\" : \"$name\", \"idiom\" : \"mac\", \"scale\" : \"${scale}x\", \"size\" : \"${pt}x${pt}\" },
"
  done
done
images=$(printf '%s' "$images" | sed '$ s/},$/}/')
cat > "$SET/Contents.json" <<JSON
{
  "images" : [
$images
  ],
  "info" : { "author" : "xcode", "version" : 1 }
}
JSON
echo "Wrote $SET"
