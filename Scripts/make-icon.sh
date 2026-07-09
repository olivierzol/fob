#!/bin/bash
#
# Regenerates Resources/fob.icns from Scripts/make-icon.swift. Run this only when
# changing the icon; build-app.sh reuses the committed .icns otherwise.
#
set -euo pipefail
cd "$(dirname "$0")/.."

ICONSET="$(mktemp -d)/fob.iconset"
mkdir -p "$ICONSET" Resources
swift Scripts/make-icon.swift "$ICONSET"
iconutil -c icns "$ICONSET" -o Resources/fob.icns
rm -rf "$(dirname "$ICONSET")"
echo "wrote Resources/fob.icns"
