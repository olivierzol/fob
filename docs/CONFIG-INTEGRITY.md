# Policy / config integrity — investigation and decision

**Question that started this:** can we use the Secure Enclave (or another mechanism)
to guarantee the integrity of fob's on-disk config — specifically the per-key
`.policy` files that hold pins and reuse windows — so they can't be corrupted or
tampered with?

**Short answer / current decision:** For *accidental* corruption, yes — handled (see
"Shipped"). For *malicious* tampering by code running as **you**, it is deliberately
**out of scope**, consistent with fob's [security model](../README.md#security-model).
The plumbing to add real protection later is in place but dormant.

## Why the Secure Enclave doesn't solve this

The enclave protects key **material** from extraction. It does **not** stop same-user
code from **asking the enclave to sign** — that's exactly how fob itself works, and
malware running as you can invoke it identically. So signing `.policy` files with a
no-presence enclave key gives no protection against the attacker we care about: they
can produce a valid signature too. (A presence-gated enclave signature would require a
Touch ID per policy change *and* still can't stop a rollback to an older validly-signed
policy, because preventing rollback needs protected/monotonic storage — see below.)

## What actually raises the bar (and the wall we hit)

The real primitive is **OS-enforced code identity**: a store only code *signed as fob*
can read/modify/delete, so other same-user code is locked out (not just other users).
Two ways to get it on macOS:

1. **Data-protection keychain + access group** (`keychain-access-groups`). Implemented
   as `KeychainPolicyStore` in `Sources/FobKit/PolicyStore.swift`. **This does not work
   for a non-sandboxed Developer ID app.** Access groups are an App Store / sandboxed
   mechanism; the entitlement is unauthorized for a bare Developer ID (or Apple
   Development) signature, and macOS **SIGKILLs the app on launch** (verified — exit
   137). There is no "Keychain Sharing" App-ID capability in the developer portal to
   enable it, either. Making it work would require **sandboxing the whole app** plus a
   provisioning profile — and fob needs to read `~/.ssh/known_hosts` / `~/.ssh/config`,
   bind a socket in `~/.fob`, and exec `ssh`/`ssh-copy-id`, all of which the sandbox
   restricts. Large, risky change for a narrow benefit. Not pursued.

2. **Legacy keychain ACL** (`SecAccess` / `SecTrustedApplication`). The idiomatic way
   for a *non-sandboxed* macOS app to gate a secret by code identity. Needs **no**
   entitlement, profile, portal, or sandbox — works today. Other code touching fob's
   items triggers a user "Allow/Deny" prompt, so *silent* tampering is blocked. Trade-
   offs: the APIs are deprecated (still functional), it's a consent-prompt model rather
   than a hard deny, and re-signing fob across versions can invalidate the ACL and cause
   a one-time re-consent. Not built yet — this is the realistic future route if we want
   live protection without the App Store apparatus.

The **downgrade/rollback** problem (malware deletes the policy → "no policy = open", or
restores an older signed policy) is only closed by a store other code can't write to —
i.e. mechanism 1 or 2. A plain signature/HMAC over a file cannot close it, because the
attacker keeps the old valid version or the signing key.

## Shipped (what protects config today)

- **Fail-closed on corruption (M-3).** `KeyStore.policyStatus` distinguishes *absent*
  (no policy — open by design) from *present-but-unreadable* (corrupt). The agent
  **refuses to sign** (`refused-policy`) on a corrupt policy instead of silently
  reverting to the open default. Covers accidental corruption safely.
- **`PolicyStore` abstraction.** Policy persistence is behind a protocol
  (`FilePolicyStore` today; `KeychainPolicyStore` as a dormant reference). A future
  legacy-ACL backend drops in behind the same protocol and probe/fallback, with no
  change to the agent, CLI, or app. Unit-tested with in-memory / throwing fakes.
- **UID isolation.** `~/.fob` is `0700` and the socket `0600`, so *other users* can't
  reach policies at all. The boundary fob does not cross is code running as **you**.

## If you want to make same-user tamper-resistance live later

- **Preferred for this app type:** implement a legacy-`SecAccess` backend conforming to
  `PolicyStore` (mechanism 2). No provisioning needed. Wire it into
  `KeyStore.selectPolicyStore` behind the existing availability probe.
- **Only if you ever sandbox the app:** the existing `KeychainPolicyStore` (mechanism 1)
  becomes viable — add the App Sandbox entitlement + a provisioning profile authorizing
  `keychain-access-groups`, embed `Contents/embedded.provisionprofile` before signing,
  and enable `FOB_KEYCHAIN_ENTITLEMENT=1` in `build-app.sh`. Verify the app launches
  (no SIGKILL) **and** that the bundled CLI run standalone via `~/.fob/bin/fob` also
  works and agrees with the app.

## Decision (2026-07-10)

Ship **Option 3**: accidental corruption handled (M-3); malicious same-user tampering
documented as out of scope (matches the threat model); abstraction kept ready. Revisit
with the legacy-ACL backend if/when there's demand.
