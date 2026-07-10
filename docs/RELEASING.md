# Releasing fob

fob ships as a **Developer ID–signed, notarized** `.app` distributed through a
Homebrew **cask**. Notarization is what makes `UNUserNotificationCenter` accept the
app on every user's Mac — so notification banners show the fob icon instead of
falling back to osascript (which always renders under "Script Editor").

Ad-hoc / unsigned builds still *run* (the agent, Touch ID, and SSH all work) — they
just get the icon-less osascript notification fallback. Signing only affects
distribution and the notification icon.

## One-time setup

### 1. Certificate & API key (from your Apple Developer account)

- **Developer ID Application certificate.** Create it in Xcode (Settings →
  Accounts → Manage Certificates → +) or the Developer portal, then export it
  from Keychain Access as a `.p12` (this bundles the private key). Note its name,
  e.g. `Developer ID Application: Your Name (TEAMID)`.
- **App Store Connect API key** for notarytool. In App Store Connect → Users and
  Access → Integrations → App Store Connect API, create a key with the
  **Developer** role. Download the `AuthKey_XXXX.p8` (once only) and note the
  **Key ID** and **Issuer ID**.

### 2. GitHub repository secrets

Add these under Settings → Secrets and variables → Actions:

| Secret | Value |
| --- | --- |
| `DEVELOPER_ID_CERT_P12` | `base64 -i cert.p12` (the whole file, base64) |
| `DEVELOPER_ID_CERT_PASSWORD` | the password you set when exporting the `.p12` |
| `KEYCHAIN_PASSWORD` | any string — for the throwaway CI keychain |
| `DEVELOPER_ID_IDENTITY` | *(optional)* the exact identity name; auto-detected if omitted |
| `AC_API_KEY_P8` | `base64 -i AuthKey_XXXX.p8` |
| `AC_API_KEY_ID` | the API Key ID |
| `AC_API_ISSUER_ID` | the API Issuer ID (UUID) |

`base64 -i file | pbcopy` copies a value straight to the clipboard.

### 3. Homebrew tap

Casks must live in a repo named `homebrew-*`. Create `OWNER/homebrew-fob` and copy
[`Casks/fob.rb`](../Casks/fob.rb) into it at `Casks/fob.rb`. Users then run:

```sh
brew install --cask OWNER/fob/fob
```

Replace `OWNER` in the cask (three places) with your GitHub account/org.

## Cutting a release

1. Bump `VERSION` / `BUILD_NUMBER` in `Scripts/build-app.sh`.
2. Tag and push:
   ```sh
   git tag v0.3.0
   git push origin v0.3.0
   ```
3. The `release` workflow builds, signs, notarizes, staples, and attaches
   `fob-<version>.zip` to a GitHub release. It prints the new `version` and
   `sha256` as a workflow notice.
4. Update `version` and `sha256` in your tap's `Casks/fob.rb` and commit.

## Building a signed release locally

With your Developer ID cert in the login keychain and notarytool credentials saved
once (`xcrun notarytool store-credentials fob-notary --key AuthKey_XXXX.p8
--key-id KEYID --issuer ISSUER`):

```sh
AC_KEYCHAIN_PROFILE=fob-notary ./Scripts/release.sh
```

This produces `fob-<version>.zip` and prints its SHA-256 — the same artifact CI
publishes.

## Local dev builds (no signing)

`./Scripts/build-app.sh` still defaults to ad-hoc signing for day-to-day work. To
get a real notification icon on *your own* machine without the full release flow,
sign with any code-signing identity your machine trusts:

```sh
FOB_SIGN_IDENTITY="Developer ID Application: Your Name (TEAMID)" ./Scripts/build-app.sh
```
