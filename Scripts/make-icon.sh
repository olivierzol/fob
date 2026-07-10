#!/bin/bash
#
# Regenerates Resources/Assets.xcassets/AppIcon.appiconset from make-icon.swift.
# Run this only when changing the icon; build-app.sh compiles the committed
# asset catalog (via actool) into each build's Assets.car + AppIcon.icns.
#
set -euo pipefail
cd "$(dirname "$0")/.."

ICONSET="Resources/Assets.xcassets/AppIcon.appiconset"
MENUBAR="Resources/Assets.xcassets/MenuBarKey.imageset"
mkdir -p "$ICONSET" "$MENUBAR"

cat > Resources/Assets.xcassets/Contents.json <<'JSON'
{
  "info" : { "author" : "xcode", "version" : 1 }
}
JSON

# Monochrome template used for the menu-bar item (adapts to light/dark menu bar).
cat > "$MENUBAR/Contents.json" <<'JSON'
{
  "images" : [
    { "idiom" : "universal", "filename" : "menubar.png", "scale" : "1x" },
    { "idiom" : "universal", "filename" : "menubar@2x.png", "scale" : "2x" }
  ],
  "info" : { "author" : "xcode", "version" : 1 },
  "properties" : { "template-rendering-intent" : "template" }
}
JSON

cat > "$ICONSET/Contents.json" <<'JSON'
{
  "images" : [
    { "idiom" : "mac", "size" : "16x16",   "scale" : "1x", "filename" : "icon_16x16.png" },
    { "idiom" : "mac", "size" : "16x16",   "scale" : "2x", "filename" : "icon_16x16@2x.png" },
    { "idiom" : "mac", "size" : "32x32",   "scale" : "1x", "filename" : "icon_32x32.png" },
    { "idiom" : "mac", "size" : "32x32",   "scale" : "2x", "filename" : "icon_32x32@2x.png" },
    { "idiom" : "mac", "size" : "128x128", "scale" : "1x", "filename" : "icon_128x128.png" },
    { "idiom" : "mac", "size" : "128x128", "scale" : "2x", "filename" : "icon_128x128@2x.png" },
    { "idiom" : "mac", "size" : "256x256", "scale" : "1x", "filename" : "icon_256x256.png" },
    { "idiom" : "mac", "size" : "256x256", "scale" : "2x", "filename" : "icon_256x256@2x.png" },
    { "idiom" : "mac", "size" : "512x512", "scale" : "1x", "filename" : "icon_512x512.png" },
    { "idiom" : "mac", "size" : "512x512", "scale" : "2x", "filename" : "icon_512x512@2x.png" }
  ],
  "info" : { "author" : "xcode", "version" : 1 }
}
JSON

swift Scripts/make-icon.swift "$ICONSET" "$MENUBAR"
echo "wrote $ICONSET"
