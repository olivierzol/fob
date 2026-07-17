# Releasing fob

fob ships as a **Developer ID–signed, notarized** `.app` distributed through a
Homebrew **cask**. Notarization is what makes `UNUserNotificationCenter` accept the
app on every user's Mac — so notification banners show the fob icon instead of
falling back to osascript (which always renders under "Script Editor").

Ad-hoc / unsigned builds still *run* (the agent, Touch ID, and SSH all work) — they
just get the icon-less osascript notification fallback. Signing only affects
distribution and the notification icon.

Releases are cut **locally, by hand** — built, signed, notarized, and published from
your Mac. There is intentionally **no CI release path**: the Developer ID signing
material never leaves the machine, and no build can be produced without you present
(keychain / Touch ID).

## One-time setup

### 1. Certificate & API key (from your Apple Developer account)

- **Developer ID Application certificate.** Create it in Xcode (Settings →
  Accounts → Manage Certificates → +) or the Developer portal, and keep it in your
  login keychain. Note its name, e.g. `Developer ID Application: Your Name (TEAMID)`.
- **App Store Connect API key** for notarytool. In App Store Connect → Users and
  Access → Integrations → App Store Connect API, create a key with the **Developer**
  role, download `AuthKey_XXXX.p8` (once only), and note the **Key ID** and
  **Issuer ID**. Save the notarytool credentials once as a profile:
  ```sh
  xcrun notarytool store-credentials fob-notary \
    --key AuthKey_XXXX.p8 --key-id KEYID --issuer ISSUER
  ```

### 2. Homebrew tap

Casks must live in a repo named `homebrew-*`. Create `olivierzol/homebrew-fob` and copy
[`Casks/fob.rb`](../Casks/fob.rb) into it at `Casks/fob.rb`. Users then run:

```sh
brew install --cask olivierzol/fob/fob
```

Replace `olivierzol` in the cask (three places) with your GitHub account/org.

## Cutting a release

Every step is local and needs you present (signed commit/tag, notarization, publish):

1. Bump `VERSION` / `BUILD_NUMBER` in `Scripts/build-app.sh`.
2. Commit + tag (signed) and push:
   ```sh
   git commit -am "Release v0.3.0"
   git tag -s v0.3.0 -m "fob v0.3.0"
   git push origin main v0.3.0
   ```
3. Build, sign, notarize, staple — produces `fob-<version>.zip` and prints its SHA-256.
   `release.sh` auto-detects the sole Developer ID Application identity in your keychain
   (or set `FOB_SIGN_IDENTITY` to pin it):
   ```sh
   AC_KEYCHAIN_PROFILE=fob-notary ./Scripts/release.sh
   ```
4. Publish the GitHub release with the notarized zip attached:
   ```sh
   gh release create v0.3.0 fob-0.3.0.zip --title "fob v0.3.0" --notes "…"
   ```
5. Bump `version` + `sha256` (from step 3) in your tap's `Casks/fob.rb` and push a
   commit. `brew upgrade --cask fob` then picks it up.

## Local dev builds (no signing)

`./Scripts/build-app.sh` still defaults to ad-hoc signing for day-to-day work. To
get a real notification icon on *your own* machine without the full release flow,
sign with any code-signing identity your machine trusts:

```sh
FOB_SIGN_IDENTITY="Developer ID Application: Your Name (TEAMID)" ./Scripts/build-app.sh
```
