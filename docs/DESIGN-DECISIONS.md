# Design decisions

A short log of deliberate scope decisions for fob — especially things fob **won't**
do, and why. Recording the reasoning here keeps them from being silently re-explored.

Newest first.

---

## DD-0001 — fob does not manage macOS code-signing (Developer ID) keys

**Date:** 2026-07-18 · **Status:** Decided (won't do) · **Scope:** non-goal

### Context

fob's core primitive — a non-exportable, Touch-ID-gated **Secure Enclave** key — is a strong
defense against *key theft*, which is exactly how a lot of signed-malware gets signed: an
attacker steals a developer's signing key (an exportable file on disk or in CI) and signs at
will, with no presence check. fob already applies this primitive to a developer's SSH
**authentication** keys and git **commit-signing** keys.

The natural question: should fob extend to a developer's *third* signing key — the **Developer ID
Application** identity used to sign and notarize macOS releases? A stolen Developer ID key is the
classic "signed malware" vector.

### What we found

- **The mechanism exists and is Apple-sanctioned.** macOS supports non-exportable, presence-gated
  code-signing identities via CryptoTokenKit: `codesign -s <cert>` prompts for the token's secret
  once per invocation. This is proven in the wild with a YubiKey holding an RSA-2048 key
  ([Apple Developer forum 744992](https://developer.apple.com/forums/thread/744992)). The Secure
  Enclave is itself a CryptoTokenKit token, so an analogous SE-backed identity *should* prompt for
  Touch ID per signature.
- **But the substrate doesn't line up.** The Secure Enclave does **P-256 (ECDSA) only** and cannot
  hold an RSA key. Apple's Developer ID **leaf** certificates require an **RSA-2048** CSR. (The
  current [G6 WWDR intermediate is ECDSA P-384](https://developer.apple.com/support/certificates/),
  which proves Apple's CA *can* do ECDSA at the intermediate — but that is not the leaf you
  generate.)

### The deciding spike

We submitted a throwaway **P-256** CSR to Apple's Developer ID Application issuance (portal → G2
Sub-CA). Apple rejected it at validation:

> An attribute in the provided entity has invalid value.
> CSR algorithm/size incorrect. Expected: RSA(2048)

No certificate was issued (rejected pre-issuance), so no account slot was consumed.

### Decision

**fob will not manage code-signing identities.**

- A **Secure-Enclave-backed** Developer ID identity — the only version that would be genuinely
  *fob-shaped* (same non-exportable, Touch-ID-gated substrate as every other fob key) — is
  **impossible**, because Apple requires RSA-2048 and the SE can't produce RSA.
- The only buildable alternative is a **non-extractable keychain RSA key** (or an external
  hardware token). That never touches fob's Secure Enclave core and pulls in Apple's
  certificate-issuance/renewal lifecycle — a different domain that dilutes fob's narrow scope.
- Even a read-only **checkup nudge** ("your Developer ID key is extractable") is weak, because fob
  could offer **no fob-native remediation** — the fix would be a YubiKey or a keychain RSA key,
  neither of which is fob. A finding you can't fix inside fob is just nagging.

fob stays focused on **SSH authentication + git commit signing**, where it owns the full stack and
every finding has a real fob-native remedy.

### What would reopen this

Apple issuing **ECDSA / P-256 Developer ID leaf** certificates. If that ever ships, an SE-backed,
Touch-ID-gated release-signing identity becomes possible and would be a natural fob feature. Re-run
the P-256 CSR spike to check.

### Related

The *principle* still stands and fob already practices it: presence-required, non-exportable
signing is the right defense against stolen-key malware — and fob's own release flow is
deliberately manual/presence-gated (see [`RELEASING.md`](RELEASING.md)), so no fob build can be
signed unattended.
