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
   The script strips extended attributes before zipping (so the archive holds no
   AppleDouble `._*` entries) and then extracts the final zip with a plain `unzip` and
   re-runs `codesign --verify --strict --deep`, `stapler validate` and `spctl --assess`
   on the result. It fails if any of those fail — that is the copy users get.
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

If the Homebrew cask is installed on the same Mac, an ad-hoc build **refuses to
overwrite** `~/Applications/fob.app` (see "stale Gatekeeper cache" below). Test it in
place with `./Scripts/build-app.sh --no-install && open ./fob.app`, or pass `--force`
if you accept the consequences.

## Gatekeeper troubleshooting

A user (or you) sees **"Apple can't check *fob* for malicious software"** or
**"*fob* is damaged and can't be opened"** on launch. Work through these in order.

### 1. Is the installed bundle actually good?

```sh
APP=~/Applications/fob.app            # or /Applications/fob.app
spctl --assess --type execute -vv "$APP"     # want: accepted, source=Notarized Developer ID
xcrun stapler validate "$APP"                # want: The validate action worked!
codesign --verify --strict --deep -v "$APP"  # want: valid on disk / satisfies its Designated Requirement
```

- `a sealed resource is missing or invalid` + `file added: …/._Something` → the zip was
  extracted with a tool that keeps AppleDouble `._*` files (plain `unzip`, some
  third-party unarchivers). Re-extract with Archive Utility or `ditto -x -k`, or just
  `brew reinstall --cask fob`. `release.sh` now guards against shipping such a zip.
- `rejected … not notarized` / `stapler` fails → the release was not stapled; re-run
  `release.sh` and re-publish.

### 2. All three pass, but Gatekeeper still refuses the launch: stale scan cache

Gatekeeper's exec-time check (`syspolicyd`) caches its verdict **per bundle-directory
inode** in `/var/db/SystemPolicyConfiguration/ExecPolicy`. Homebrew deliberately keeps
the app's directory across upgrades and only swaps its contents, so the inode — and the
cached verdict — survives `brew upgrade`. If that directory ever held an **ad-hoc**
build (a dev `build-app.sh` install over the cask copy), the cached entry says
"unsigned, not notarized", the fresh notarized release inherits it, and macOS shows
"Apple can't check…" even though every command above passes. This is what
`build-app.sh`'s refusal prevents.

Read the verdict (root required; the path is redacted but team/id are not):

```sh
sudo log show --last 1h --info --style compact \
  --predicate 'process == "syspolicyd"' | grep -E 'evaluateScanResult|Prompt shown'
```

`GK evaluateScanResult: 3 … 4, 4` is a notarized Developer ID app passing.
`GK evaluateScanResult: 0 … (team: TEAMID), (id: (null)) … 0, 0` followed by
`Prompt shown (6, …)` is the stale-cache case. Optional confirmation:

```sh
sudo sqlite3 /var/db/SystemPolicyConfiguration/ExecPolicy \
  "select object_id, cdhash, team_identifier, policy_match from policy_scan_cache where bundle_id='dev.fob.app';"
```

A stale row has an empty `team_identifier`, `policy_match 0`, and a `cdhash` that
matches neither `codesign -dvvv "$APP" | grep ^CDHash` nor any shipped release.

**Fix:** give the bundle a new inode so Gatekeeper scans it fresh. Removing the whole
directory is exactly what Homebrew avoids, so expect to re-enable *Launch at login*
(and possibly re-grant notification permission) afterwards:

```sh
osascript -e 'quit app id "dev.fob.app"'
rm -rf ~/Applications/fob.app
brew reinstall --cask fob
open ~/Applications/fob.app
```

"Open Anyway" in System Settings → Privacy & Security also works, but leaves the stale
row in place for the next upgrade.
