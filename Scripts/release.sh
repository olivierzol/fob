#!/bin/bash
#
# Signs, notarizes, and staples fob.app, then produces fob-<version>.zip ready to
# attach to a GitHub release and reference from the Homebrew cask.
#
# Runs the same way locally (Developer ID cert in your keychain) or in CI (see
# .github/workflows/release.yml). Zero third-party tooling — swift, codesign,
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
trap 'rm -f notarize.zip' EXIT

echo "==> Building + signing (identity: $FOB_SIGN_IDENTITY)"
FOB_SIGN_IDENTITY="$FOB_SIGN_IDENTITY" ./Scripts/build-app.sh --no-install

APP="fob.app"
VERSION="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$APP/Contents/Info.plist")"
ZIP="fob-$VERSION.zip"

echo "==> Zipping for notarization"
rm -f notarize.zip "$ZIP"
ditto -c -k --keepParent "$APP" notarize.zip

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
ditto -c -k --keepParent "$APP" "$ZIP"

SHA="$(shasum -a 256 "$ZIP" | awk '{print $1}')"
echo
echo "Built $ZIP"
echo "  version: $VERSION"
echo "  sha256:  $SHA"

# Hand values to the GitHub Actions job (used to bump Casks/fob.rb).
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    {
        echo "version=$VERSION"
        echo "sha256=$SHA"
        echo "zip=$ZIP"
    } >> "$GITHUB_OUTPUT"
fi
