#!/bin/bash
#
# Builds fob.app (the menu-bar agent) and installs it to ~/Applications, plus the
# `fob` CLI to ~/.fob/bin. Zero third-party tooling — just swift + codesign.
#
#   ./Scripts/build-app.sh            build + install to ~/Applications
#   ./Scripts/build-app.sh --no-install   build ./fob.app only
#
set -euo pipefail

cd "$(dirname "$0")/.."

VERSION="0.3.0"
BUILD_NUMBER="3"
BUNDLE_ID="dev.fob.app"
APP="fob.app"
INSTALL_DIR="$HOME/Applications"
CLI_DIR="$HOME/.fob/bin"

install=1
[[ "${1:-}" == "--no-install" ]] && install=0

echo "==> Building release binaries"
swift build -c release
BIN_DIR="$(swift build -c release --show-bin-path)"

echo "==> Assembling $APP"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

cp "$BIN_DIR/FobApp" "$APP/Contents/MacOS/fob"       # the menu-bar app (CFBundleExecutable)
cp "$BIN_DIR/fob"    "$APP/Contents/MacOS/fob-cli"   # the CLI, bundled so it ships together

[[ -f Resources/fob.icns ]] || ./Scripts/make-icon.sh   # regenerate if missing
cp Resources/fob.icns "$APP/Contents/Resources/fob.icns" # used for the Dock/notification icon

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>          <string>$BUNDLE_ID</string>
    <key>CFBundleName</key>                <string>fob</string>
    <key>CFBundleDisplayName</key>         <string>fob</string>
    <key>CFBundleExecutable</key>          <string>fob</string>
    <key>CFBundleIconFile</key>            <string>fob</string>
    <key>CFBundlePackageType</key>         <string>APPL</string>
    <key>CFBundleShortVersionString</key>  <string>$VERSION</string>
    <key>CFBundleVersion</key>             <string>$BUILD_NUMBER</string>
    <key>LSMinimumSystemVersion</key>      <string>13.0</string>
    <key>LSUIElement</key>                 <true/>
    <key>NSHumanReadableCopyright</key>    <string>fob — Secure Enclave SSH keys gated by Touch ID</string>
</dict>
</plist>
PLIST

echo "==> Code signing (ad-hoc)"
# Ad-hoc signature is enough for local use. Sign the bundled CLI first, then the
# app, so --deep sees a consistent tree. For notarized distribution, swap the "-"
# identity for a Developer ID and add --options runtime.
codesign --force --sign - "$APP/Contents/MacOS/fob-cli"
codesign --force --deep --sign - "$APP"
codesign --verify --strict "$APP" && echo "    signature OK"

if [[ "$install" == "1" ]]; then
    echo "==> Installing to $INSTALL_DIR/$APP"
    mkdir -p "$INSTALL_DIR"
    rm -rf "$INSTALL_DIR/$APP"
    cp -R "$APP" "$INSTALL_DIR/$APP"

    echo "==> Installing CLI to $CLI_DIR/fob"
    mkdir -p "$CLI_DIR"
    ln -sf "$INSTALL_DIR/$APP/Contents/MacOS/fob-cli" "$CLI_DIR/fob"

    cat <<DONE

Installed.

  App:  $INSTALL_DIR/$APP
  CLI:  $CLI_DIR/fob  (add $CLI_DIR to your PATH if it isn't already)

Next:
  1. If you previously ran the CLI agent under launchd:  fob uninstall
  2. Open the app:                                        open "$INSTALL_DIR/$APP"
  3. In the menu-bar panel, turn on "Launch at login".
DONE
else
    echo "==> Built ./$APP (not installed)"
fi
