#!/bin/sh
# Builds build/openwarp (CLI + daemon) and build/OpenWarp.app (SwiftUI front end
# with the CLI embedded in Contents/Resources).
set -eu
cd "$(dirname "$0")"
mkdir -p build

echo "==> go test"
go test ./... >/dev/null

echo "==> openwarp (universal)"
GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o build/openwarp-arm64 ./cmd/openwarp
GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o build/openwarp-amd64 ./cmd/openwarp
lipo -create -output build/openwarp build/openwarp-arm64 build/openwarp-amd64
rm build/openwarp-arm64 build/openwarp-amd64

echo "==> OpenWarp.app"
APP=build/OpenWarp.app
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
swiftc -O -parse-as-library -target arm64-apple-macos14.0 ui/macos/*.swift -o build/OpenWarp-arm64
swiftc -O -parse-as-library -target x86_64-apple-macos14.0 ui/macos/*.swift -o build/OpenWarp-x86_64
lipo -create -output "$APP/Contents/MacOS/OpenWarp" build/OpenWarp-arm64 build/OpenWarp-x86_64
rm build/OpenWarp-arm64 build/OpenWarp-x86_64
cp build/openwarp "$APP/Contents/Resources/openwarp"
# Licenses of the third-party code in the embedded CLI (scripts/third-party-notices.sh).
cp LICENSE THIRD_PARTY_NOTICES.md "$APP/Contents/Resources/"
# App icon: compile the asset catalog (Assets.car + AppIcon.icns) from ui/macos/Assets.xcassets.
xcrun actool ui/macos/Assets.xcassets --compile "$APP/Contents/Resources" --platform macosx \
  --minimum-deployment-target 14.0 --app-icon AppIcon --output-partial-info-plist build/assets-info.plist >/dev/null
rm -f build/assets-info.plist
cat > "$APP/Contents/Info.plist" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key><string>OpenWarp</string>
  <key>CFBundleIdentifier</key><string>local.openwarp.app</string>
  <key>CFBundleName</key><string>OpenWarp</string>
  <key>CFBundleDisplayName</key><string>OpenWarp</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleIconFile</key><string>AppIcon</string>
  <key>CFBundleIconName</key><string>AppIcon</string>
  <key>CFBundleShortVersionString</key><string>0.1.0</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>LSMinimumSystemVersion</key><string>14.0</string>
  <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
EOF
# Ad-hoc signatures (no Developer ID): the embedded CLI first, then the app that seals it. A failure stops
# the build; macOS refuses to run unsigned arm64 code.
codesign --force -s - "$APP/Contents/Resources/openwarp"
codesign --force -s - "$APP"
codesign --verify --deep --strict "$APP"
echo "Built build/openwarp and $APP"
