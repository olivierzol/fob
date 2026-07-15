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

VERSION="0.11.2"
BUILD_NUMBER="15"
BUNDLE_ID="dev.fob.app"
APP="fob.app"

# Code-signing identity. Default "-" is ad-hoc: fine for local dev, but
# UNUserNotificationCenter rejects ad-hoc apps, so notifications fall back to
# osascript and show no fob icon. Set FOB_SIGN_IDENTITY to a "Developer ID
# Application: …" name (or its SHA-1) for a notarizable, icon-capable build —
# Scripts/release.sh drives the full notarize + staple flow.
SIGN_IDENTITY="${FOB_SIGN_IDENTITY:--}"
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

# Compile the asset catalog into the bundle. A bare .icns via CFBundleIconFile is
# enough for Finder/Dock, but Notification Center and System Settings resolve icons
# through the asset catalog (Assets.car + CFBundleIconName) and show a blank icon
# without one. actool emits Assets.car + AppIcon.icns from Resources/Assets.xcassets.
[[ -d Resources/Assets.xcassets ]] || ./Scripts/make-icon.sh   # regenerate if missing
xcrun actool Resources/Assets.xcassets \
    --compile "$APP/Contents/Resources" \
    --app-icon AppIcon \
    --platform macosx \
    --minimum-deployment-target 13.0 \
    --output-partial-info-plist "$APP/Contents/Resources/.actool-partial.plist" >/dev/null
rm -f "$APP/Contents/Resources/.actool-partial.plist" # keys are hard-coded in Info.plist below

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>          <string>$BUNDLE_ID</string>
    <key>CFBundleName</key>                <string>fob</string>
    <key>CFBundleDisplayName</key>         <string>fob</string>
    <key>CFBundleExecutable</key>          <string>fob</string>
    <key>CFBundleIconFile</key>            <string>AppIcon</string>
    <key>CFBundleIconName</key>            <string>AppIcon</string>
    <key>CFBundlePackageType</key>         <string>APPL</string>
    <key>CFBundleShortVersionString</key>  <string>$VERSION</string>
    <key>CFBundleVersion</key>             <string>$BUILD_NUMBER</string>
    <key>LSMinimumSystemVersion</key>      <string>13.0</string>
    <key>LSUIElement</key>                 <true/>
    <key>NSHumanReadableCopyright</key>    <string>fob — Secure Enclave SSH keys gated by Touch ID</string>
</dict>
</plist>
PLIST

if [[ "$SIGN_IDENTITY" == "-" ]]; then
    echo "==> Code signing (ad-hoc — local only, no notification icon)"
    # Sign the bundled CLI first, then the app, so --deep sees a consistent tree.
    codesign --force --sign - "$APP/Contents/MacOS/fob-cli"
    codesign --force --deep --sign - "$APP"
else
    echo "==> Code signing ($SIGN_IDENTITY)"
    # Hardened runtime (--options runtime) and a secure timestamp are required for
    # notarization; the timestamp needs Apple's TSA, so set FOB_SIGN_TIMESTAMP=0 for
    # offline local signing (e.g. testing notifications with an Apple Development
    # cert). Sign the nested CLI first; signing the bundle then seals it, so no
    # --deep (Apple discourages --deep for distribution).
    ts="--timestamp"
    [[ "${FOB_SIGN_TIMESTAMP:-1}" == "0" ]] && ts="--timestamp=none"
    codesign --force --options runtime "$ts" --sign "$SIGN_IDENTITY" "$APP/Contents/MacOS/fob-cli"
    codesign --force --options runtime "$ts" --sign "$SIGN_IDENTITY" "$APP"

    # Optional: re-sign with a keychain-access-group entitlement so policies can live in
    # the code-identity-gated keychain (see Sources/FobKit/PolicyStore.swift). OFF by
    # default and EXPERIMENTAL: `keychain-access-groups` is only authorized for a signing
    # identity that has a matching provisioning profile / App Store or App Groups
    # entitlement. With a bare Apple Development or Developer ID cert, macOS treats the
    # entitlement as unauthorized and KILLS the app on launch (SIGKILL). Without the
    # entitlement the keychain probe simply fails and the policy store falls back to
    # files — safe, just not code-identity gated. Enable only once you have the profile
    # wired up, and verify the app still launches.
    if [[ "${FOB_KEYCHAIN_ENTITLEMENT:-0}" == "1" ]]; then
        TEAM="$(codesign -dvv "$APP" 2>&1 | awk -F= '/^TeamIdentifier=/{print $2}')"
        if [[ -n "$TEAM" && "$TEAM" != "not set" ]]; then
            echo "    [experimental] adding keychain-access-group entitlement ($TEAM.dev.fob.app)"
            ENT="$(mktemp)"
            cat > "$ENT" <<ENTITLEMENTS
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>keychain-access-groups</key>
    <array><string>$TEAM.dev.fob.app</string></array>
</dict>
</plist>
ENTITLEMENTS
            codesign --force --options runtime "$ts" --entitlements "$ENT" --sign "$SIGN_IDENTITY" "$APP/Contents/MacOS/fob-cli"
            codesign --force --options runtime "$ts" --entitlements "$ENT" --sign "$SIGN_IDENTITY" "$APP"
            rm -f "$ENT"
        fi
    fi
fi
codesign --verify --strict --verbose=2 "$APP" && echo "    signature OK"

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
