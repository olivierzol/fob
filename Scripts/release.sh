#!/bin/bash
#
# Signs, notarizes, and staples fob.app, then produces fob-<version>.zip ready to
# attach to a GitHub release and reference from the Homebrew cask.
#
# Runs locally with the Developer ID cert in your keychain; there is deliberately no
# CI release path (docs/RELEASING.md). Zero third-party tooling — swift, codesign,
# xcrun notarytool, ditto.
#
#   ./Scripts/release.sh
#
# Required environment:
#   FOB_SIGN_IDENTITY    "Developer ID Application: Name (TEAMID)" or its SHA-1.
#                        If unset, the sole Developer ID Application identity found
#                        in the keychain is used.
#
# Notarization credentials — App Store Connect API key (recommended in CI):
#   AC_API_KEY_PATH      path to the .p8 key file
#   AC_API_KEY_ID        key ID (e.g. ABC123DEF4)
#   AC_API_ISSUER_ID     issuer UUID
# …or a notarytool profile you saved once with `xcrun notarytool store-credentials`:
#   AC_KEYCHAIN_PROFILE  the profile name
#
set -euo pipefail
cd "$(dirname "$0")/.."

# Fall back to the one Developer ID Application identity in the keychain.
: "${FOB_SIGN_IDENTITY:=$(security find-identity -v -p codesigning \
    | awk -F'"' '/Developer ID Application/{print $2; exit}')}"
[[ -n "${FOB_SIGN_IDENTITY:-}" ]] || {
    echo "error: no Developer ID Application identity found; set FOB_SIGN_IDENTITY" >&2
    exit 1
}

# notarize.zip is only the temporary submission bundle — remove it on any exit so a
# failed run doesn't leave it behind (the release artifact is fob-<version>.zip).
# VERIFY_DIR holds the test extraction of the final zip.
VERIFY_DIR="$(mktemp -d)"
trap 'rm -f notarize.zip; rm -rf "$VERIFY_DIR"' EXIT

echo "==> Building + signing (identity: $FOB_SIGN_IDENTITY)"
FOB_SIGN_IDENTITY="$FOB_SIGN_IDENTITY" ./Scripts/build-app.sh --no-install

APP="fob.app"
VERSION="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$APP/Contents/Info.plist")"
ZIP="fob-$VERSION.zip"

# Archive without extended attributes. The build inherits com.apple.provenance (and
# possibly quarantine) xattrs from the terminal it runs in, and `ditto -c -k` stores
# xattrs as AppleDouble `._*` entries *inside* the bundle. Extractors that don't merge
# them back (plain `unzip`, some third-party unarchivers) leave them as real files,
# which breaks the code seal, so Gatekeeper refuses the app. Signatures and the
# stapled ticket are ordinary file contents, so stripping xattrs is safe.
archive() {
    xattr -cr "$1"
    ditto -c -k --keepParent --norsrc --noextattr --noqtn "$1" "$2"
}

echo "==> Zipping for notarization"
rm -f notarize.zip "$ZIP"
archive "$APP" notarize.zip

echo "==> Submitting to Apple notary service (may take a few minutes)"
if [[ -n "${AC_KEYCHAIN_PROFILE:-}" ]]; then
    xcrun notarytool submit notarize.zip --keychain-profile "$AC_KEYCHAIN_PROFILE" --wait
else
    : "${AC_API_KEY_PATH:?set AC_API_KEY_PATH (or AC_KEYCHAIN_PROFILE)}"
    : "${AC_API_KEY_ID:?set AC_API_KEY_ID}"
    : "${AC_API_ISSUER_ID:?set AC_API_ISSUER_ID}"
    xcrun notarytool submit notarize.zip \
        --key "$AC_API_KEY_PATH" --key-id "$AC_API_KEY_ID" --issuer "$AC_API_ISSUER_ID" --wait
fi

echo "==> Stapling notarization ticket"
xcrun stapler staple "$APP"
xcrun stapler validate "$APP"
# Gatekeeper sanity check (informational — don't fail the build on its exit code).
spctl --assess --type execute --verbose=4 "$APP" || true

echo "==> Packaging $ZIP"
rm -f notarize.zip
archive "$APP" "$ZIP"

# Verify the artifact the way users will extract it, not the tree we just zipped.
# Homebrew uses `ditto` (merges AppleDouble entries); a plain `unzip` does not, so
# extract with `unzip` and require the result to pass every Gatekeeper check.
echo "==> Verifying $ZIP after a plain unzip"
if unzip -Z1 "$ZIP" | grep -q '/\._'; then
    echo "error: $ZIP contains AppleDouble (._*) entries; the bundle would fail Gatekeeper after unzip" >&2
    exit 1
fi
/usr/bin/unzip -q "$ZIP" -d "$VERIFY_DIR"
codesign --verify --strict --deep --verbose=2 "$VERIFY_DIR/$APP"
xcrun stapler validate "$VERIFY_DIR/$APP"
spctl --assess --type execute --verbose=4 "$VERIFY_DIR/$APP"

SHA="$(shasum -a 256 "$ZIP" | awk '{print $1}')"
echo
echo "Built $ZIP"
echo "  version: $VERSION"
echo "  sha256:  $SHA"
echo "Next: attach it to the GitHub release and bump version + sha256 in the tap's Casks/fob.rb."
