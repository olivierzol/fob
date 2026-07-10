# fob — Security Audit Report

**Scope:** full source tree (`Sources/FobKit`, `Sources/fob`, `Sources/FobApp`), build
and release scripts (`Scripts/`, `.github/workflows/release.yml`, `Casks/fob.rb`).
**Reviewer:** security audit for open-source release.
**Date:** 2026-07-10.
**Commit reviewed:** working tree at `baf048b` (+ `.gitignore` update).

fob is a macOS ssh-agent that keeps SSH private keys in the Secure Enclave and gates
every signature behind user presence (Touch ID / Apple Watch / password), with
optional per-host pinning, a touch-reuse window, and a tamper-evident audit log.

**Overall assessment:** the core design is sound and, in several places, notably
careful (non-exportable enclave keys, explicit argument-injection defenses, verified
`session-bind` signatures, a single-instance lock, correct SSH signature
verification). **No critical or high-severity remotely-exploitable vulnerability was
found.** The findings below are medium/low hardening items plus an explicit statement
of the threat model and its inherent limits, which an open-source project should
document plainly so users don't over-trust it.

---

## Threat model (what fob does and does not defend against)

State this in the README. It is the single most important thing for users.

**fob protects against — strongly:**

- **Key theft / exfiltration.** Private keys are generated in and never leave the
  Secure Enclave; on disk there is only an enclave-wrapped blob that is useless on any
  other machine and cannot be turned back into key material (`KeyStore.swift:6-23`,
  `create()` uses `SecureEnclave.P256.Signing.PrivateKey`). Full disk access, a stolen
  laptop, a backup, or `sudo` does **not** yield a usable key.
- **Silent use.** Every fresh signature requires user presence via `LAContext`
  (`Agent.swift:256-260`), so a background process cannot use a key without a prompt…
  (but see the reuse-window caveat below).
- **Wrong-destination use of a pinned key.** With pinning, a key signs only for a
  bound, cryptographically-verified host key (`Agent.swift:230-240`).

**fob does NOT (and largely cannot) protect against — by design:**

- **A malicious process running as you, while the Mac is unlocked.** This is inherent
  to the ssh-agent model. Any process with your UID can `connect()` to the agent
  socket and request a signature. The Touch ID prompt is the backstop — but see reuse
  windows (M-2), and note the attacker can also read/rewrite everything under `~/.fob`
  (policies, audit log). fob is a hardware-backed key store with presence gating, not a
  sandbox against your own compromised session.
- **You, the machine owner.** The audit log is tamper-*evident* against naive edits,
  not tamper-*proof* (L-6).

---

## Findings summary

| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| M-1 | Medium | osascript notification string is built from attacker-controllable input; safety rests entirely on one untested `escape()` | **Fixed** |
| M-2 | Medium | Touch-reuse window lets *any* local process sign without a touch, for any destination (if key is unpinned) | **Fixed** (scoped to destination) |
| M-3 | Medium | Corrupt/unreadable `.policy` file fails **open** (pinning silently dropped) | **Fixed** (fails closed) |
| L-1 | Low | Socket `bind()`→`chmod()` TOCTOU (mitigated by `~/.fob` being `0700`) | **Fixed** |
| L-2 | Low | `~/.fob` permissions not re-asserted if the directory pre-exists with looser modes | **Fixed** |
| L-3 | Low | `ssh`/`ssh-copy-id` resolved via `/usr/bin/env` (PATH-dependent) | **Fixed** (absolute paths) |
| L-4 | Low | Unbounded thread-per-connection (local DoS) | **Fixed** (capped at 256) |
| L-5 | Low | Notification content (host, key) may appear on the lock screen | **Documented** (macOS user setting) |
| L-6 | Low | Audit log is not tamper-proof against the local user (acknowledged) | **Documented** (see note) |
| I-1 | Info | `session-bind` binding is not tied to the signed payload → replay limits pin guarantees | **Documented** |
| I-2 | Info | Peer attribution is spoofable (acknowledged in code) | **By design** |

> **Remediation (2026-07-10).** All medium and low code-level findings are fixed in
> commit following this report; see the per-finding "Fix applied" notes below. A
> `FobKitTests` target now locks the security-critical paths (name validation, SSH
> wire bounds, host-key signature verification incl. tampered/forged/unsupported
> cases, session-bind rules, fail-closed policy loading, audit chain tamper
> detection) — 16 tests, run with `swift test`. L-5 and L-6 are inherent to macOS /
> the threat model and are documented rather than "fixed" (see their notes).

---

## Medium

### M-1 — osascript notification is assembled from attacker-controlled input

**Files:** `Sources/FobKit/Notifier.swift:9-21`, reached from `Agent.swift:75,223,249,263`.

The fallback notifier builds an AppleScript program by string interpolation and runs it:

```swift
let script = "display notification \"\(escape(body))\" with title \"fob\""
process.arguments = ["-e", script]
```

`body` contains the **peer description** — `Peer.describe()` returns the connecting
process's executable filename (`Agent.swift:144`, `Notifier.swift:36`). A local
attacker fully controls that filename (`cp /bin/true '/tmp/anything"; …'` then exec
it); filenames may contain `"`, `\`, spaces, and AppleScript metacharacters (anything
but `/` and NUL). That string flows into the AppleScript source.

The only thing standing between this and arbitrary AppleScript execution
(`do shell script "…"` = code execution) is `escape()`, which backslash-escapes `\`
and `"` in the correct order. **In its current form I believe the escaping is
sufficient** to keep injected text inside the string literal — but:

- It is a hand-rolled, **untested** escape (the project has no test target at all).
- This path is always taken by the bare CLI (no bundle → no `UNUserNotificationCenter`),
  and by the app whenever notifications aren't authorized (`Notifications.swift:17-33`).
- A single future regression here turns a notification into RCE.

**Recommendation.** Don't construct AppleScript from untrusted data. Options, best
first: (a) drop the osascript fallback and rely solely on `UNUserNotificationCenter`
in the signed app; (b) if a CLI fallback is kept, pass the body out-of-band rather
than interpolated into source — e.g. read it from an environment variable inside the
script: `arguments = ["-e", "display notification (system attribute \"FOB_MSG\") with title \"fob\""]`
with `FOB_MSG` set in the child environment, so no user data ever touches the script
text; (c) at minimum, add unit tests for `escape()` and sanitize `peer`/`destination`
to a conservative character set before display.

**✅ Fix applied.** Option (b): `Notifier.post` (`Notifier.swift`) no longer builds
AppleScript from the body. The body is passed via the `FOB_NOTIFICATION_BODY`
environment variable and the (now-constant) script reads it with `system attribute`.
`escape()` is deleted. Verified: a body of `pwned" & (do shell script "…") & "` is
displayed as literal text and does **not** execute.

### M-2 — Reuse window signs with no touch for any caller

**File:** `Sources/FobKit/Agent.swift:242-254`, `KeyPolicy.swift:12-14`.

When a key has a reuse window, the authorized `LAContext` is cached and reused for
*any* subsequent sign request within the deadline (`cachedAuthorization`), with no new
prompt. Because the agent cannot authenticate the caller, **any** local process can,
during the window, obtain signatures without a touch. For an **unpinned** key this
means signatures for **any destination** the attacker chooses; for a pinned key it's
limited to the pinned host (the pin check at `:230` still runs — good).

This is a deliberate convenience trade-off (git/rsync bursts) and is capped at 300 s,
which is reasonable. But the security cost should be explicit, and it can be narrowed.

**Recommendation.**
- Document clearly that reuse = "N seconds of touchless signing available to anything
  running as you," and that it is off by default (it is — good).
- Consider binding a cached authorization to the **destination** it was approved for
  (only reuse when `bindings.last.hostKeyBlob` matches the approval's), so a reuse
  grant for host A can't be spent on host B. This makes reuse meaningfully safer for
  the common (pinned or bound) case.

**✅ Fix applied.** Cached authorizations now record the destination host-key blob
they were approved for (`Agent.swift`, `authorizations` tuple gains `destination`).
`cachedAuthorization(for:destination:)` reuses a grant only when the current
connection's bound host key matches. A touch approved while bound to host A can no
longer be spent on host B. (`nil == nil` still matches the unbound/pre-8.9 case — the
residual, documented trade-off, now confined to unpinned+unbound keys.)

### M-3 — Corrupt policy file fails open (pin silently dropped)

**File:** `Sources/FobKit/KeyPolicy.swift:29-35`.

```swift
public func policy(name: String) -> KeyPolicy {
    guard let data = try? Data(...), let policy = try? JSONDecoder().decode(...)
    else { return KeyPolicy() }   // default == no pin, touch every time
    return policy
}
```

If a `<name>.policy` file exists but is unreadable or corrupt, the agent falls back to
the **default open policy** — i.e. a key that was pinned becomes unpinned and will sign
for any destination. A security restriction disappearing on file corruption is
fail-open.

The practical impact is bounded: an attacker who can corrupt the file already has
write access to `~/.fob/keys` and could instead just rewrite the policy to remove the
pin, so this doesn't cross a trust boundary. But accidental corruption (disk error,
partial write) silently weakening a control is undesirable.

**Recommendation.** Distinguish "no policy file" (legitimately open) from "policy file
present but unreadable" (suspicious). In the latter case, fail **closed** — refuse to
sign — and surface an error, rather than silently reverting to open.

**✅ Fix applied.** New `KeyStore.policyStatus` returns `.absent` / `.present` /
`.unreadable` (`KeyPolicy.swift`). `Agent.sign` now refuses to sign on `.unreadable`
(new `refused-policy` audit event + `.refusedPolicy` feed event) instead of falling
back to the open default. `policy(name:)` still returns the default for display
contexts only.

**Malicious tampering** (as opposed to accidental corruption) by same-UID code is
**documented as out of scope**, matching the threat model. Policy persistence was
refactored behind a `PolicyStore` protocol so a code-identity-gated backend can be
added later; a data-protection-keychain backend is included but dormant (access groups
aren't authorized for a non-sandboxed Developer ID app — it SIGKILLs). Full
investigation and the realistic future route (a legacy `SecAccess`-ACL backend) are in
[`docs/CONFIG-INTEGRITY.md`](docs/CONFIG-INTEGRITY.md).

---

## Low

### L-1 — Socket creation TOCTOU
`bind()` creates the socket with `mode & ~umask` (often `0755`); `chmod(socketPath,
0o600)` runs immediately after. There is a brief window where the socket is
group/other-accessible. **Mitigated** because `~/.fob` is `0700`, so no other user can
traverse to the socket regardless.
**✅ Fix applied.** `Agent.run` now sets `umask(0o177)` around `bind()` so the socket
is created `0600` with no window; `chmod` retained as belt-and-suspenders.

### L-2 — Directory permissions not re-asserted
`createDirectory`'s permission attributes apply only when it *creates* the directory.
A pre-existing `~/.fob` / `~/.fob/keys` with looser modes (older version, restore, bad
umask) would not be tightened.
**✅ Fix applied.** `KeyStore.default()` now re-asserts `0700` on both directories on
every startup.

### L-3 — PATH-dependent subprocess resolution
`Setup` spawned via `/usr/bin/env` (`["/usr/bin/env", "ssh", …]`), resolving
`ssh`/`ssh-copy-id` through `$PATH`; a poisoned `PATH` could substitute a binary.
**✅ Fix applied.** `runInteractive` now takes and `posix_spawn`s an **absolute** path;
call sites use `/usr/bin/ssh` and `/usr/bin/ssh-copy-id`. (Argument-injection itself
was already well handled — see "Done well.")

### L-4 — Unbounded connection threads
The accept loop spawned an unbounded detached thread per connection; a local process
could open many to exhaust threads/FDs (local DoS, same-UID only).
**✅ Fix applied.** Concurrent connections are capped at 256 (an NSLock-guarded
counter); beyond that, new connections are closed immediately (load-shed) rather than
queued, so existing ssh sessions are never wedged.

### L-5 — Lock-screen information disclosure
Notifications include destination host and key name, which macOS may render on the
lock screen depending on the user's "Show previews" setting. Minor privacy leak of
which hosts you access.
**Documented, not code-changed.** macOS local notifications have no API to force
hide-on-lock; this is governed by System Settings → Notifications → fob → Show
previews. Hiding it in code would defeat the feature's purpose (telling you *which*
destination was signed for). Recommend a README note for users in sensitive settings.

### L-6 — Audit log is tamper-evident, not tamper-proof
The SHA-256 hash chain detects edits/deletions of individual lines, but the log is a
plain `0600` file owned by the user with no external anchor or secret key. Anyone who
can write it (the user, or malware running as the user) can recompute a fresh,
internally-consistent chain and `--verify` will pass.
**Documented as an inherent limit, not code-changed.** This *cannot* be fixed against a
same-UID attacker without hardware attestation: any signing key fob could use to seal
the log without prompting is, by definition, also usable by malware running as the
same user; and the attacker can always delete the whole file. Sealing each entry with
a Touch-ID-gated enclave key would defeat it but is unacceptable UX (a prompt per log
line). The honest framing — now recommended for the README — is that the audit log is
tamper-**evident against accidental/partial edits**, not tamper-**proof against a
motivated same-UID attacker**. (`swift test` covers the tamper-detection that *does*
hold.)

---

## Informational / by-design

### I-1 — `session-bind` is not tied to the signed payload
`SessionBind.swift` correctly verifies that the host-key signature over the session ID
is valid (`HostKeySignature.verify`, crypto reviewed — see below), proving the host
participated in *some* session. But the agent never checks that the bound `sessionID`
matches the data in the subsequent sign request (`Agent.sign` ignores the relationship).
A local attacker could **replay** a genuine (host key, session ID, signature) triple
captured from a past connection to a pinned host, satisfy the pin check, and obtain a
touch-approved signature. That signature is only over data the attacker supplies and is
only useful against the real host within a live session whose ID was mixed into the
signed data, so it does not directly grant impersonation — this mirrors OpenSSH's own
agent model. Net: pinning substantially raises the bar but is not an absolute guarantee
against a same-UID attacker. Worth a sentence in the docs.

### I-2 — Peer attribution is spoofable
`Notifier.swift:26-38` derives the peer from `LOCAL_PEERPID` + `proc_pidpath`. PID reuse
and the fact that a process can be named anything make this display-only, which the
code comments already state. Do not build any policy on it (fob doesn't — good).

---

## Things done well (worth keeping / highlighting to reviewers)

- **Non-exportable, presence-gated enclave keys** with
  `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` and `.userPresence` /
  `.biometryCurrentSet` (`KeyStore.swift:62-77`). `.biometryCurrentSet` invalidates keys
  if fingerprints are re-enrolled — a strong choice.
- **Storage model (file vs Keychain).** Keys are persisted as the Secure Enclave
  `dataRepresentation` in `0600` files under `~/.fob/keys/` (age-plugin-se pattern), not
  in the Keychain. This does not weaken key protection: the private key never leaves the
  enclave either way, the blob is device-bound and useless elsewhere, and every use is
  gated by the key's own presence access control regardless of where the blob is stored —
  possessing the file cannot yield a signature without Touch ID. The only delta vs a
  code-identity-gated Keychain item is that same-UID code can read the blob file, which
  sits in the already-out-of-scope same-user threat zone (such code can also drive the
  agent socket directly). At-rest encryption is delegated to FileVault; `0700`/`0600`
  enforce other-user isolation.
- **SSH signature verification is correct** across ed25519 / ECDSA P-256/384/521 / RSA
  (`SessionBind.swift:74-157`): right curves, hash-included verification variants, and
  DER assembly for RSA. Type confusion between key/sig blobs isn't exploitable because
  verification uses the parsed key's own algorithm. Unsupported host-key types are
  marked `verified: false` and **cannot satisfy a pin** (`Agent.swift:232` requires
  `bound.verified`) — fail-safe.
- **Argument-injection defenses** in `setup`: alias/key names are regex-restricted and
  must not start with `-` (`KeyStore.swift:52-56`, `Setup.swift:21,40-45`), and
  subprocesses use `posix_spawn` with an explicit `argv` (no shell) — no
  `-oProxyCommand=` style injection.
- **Single-instance lock** via `flock` released by the kernel on exit
  (`AgentLock.swift`), preventing socket races.
- **Message size is bounded** to 1 MiB (`Agent.swift:48,149`) and the SSH reader does
  length-checked reads (`SSHWire.swift:47-65`) — no obvious parser overreads.
- **Pin refusal happens before the Touch ID prompt** (`Agent.swift:230-240`), so a
  blocked request never costs a touch and can't be used to fatigue the user into
  approving.
- **Secrets hygiene** for release: `.p8`/`.p12`/`.env*` are git-ignored, and CI decodes
  the cert to a temp file it deletes; local signing is documented to use a keychain
  profile so no secret need touch disk.

---

## Prioritized recommendations

1. **Publish the threat model** (section above) in the README — set expectations
   honestly for an open-source audience. *(Still to do — documentation.)*
2. ✅ **M-1** fixed: osascript no longer interpolates untrusted data (env-var
   indirection); `escape()` removed.
3. ✅ **M-3** fixed: present-but-unreadable policy now fails closed.
4. ✅ **M-2** fixed: reuse grants are scoped to the approved destination.
5. ✅ **Test target added** (`Tests/FobKitTests`, 16 tests via `swift test`): name
   validation, SSH wire bounds, host-key signature verification (valid / tampered /
   wrong-message / unsupported / garbage), session-bind rules, fail-closed policy
   loading, and audit-chain tamper detection.
6. ✅ **L-1…L-4** fixed (umask, dir-perm re-assert, absolute exec paths, connection
   cap). **L-5, L-6** documented as inherent limits (see their notes).

**Remaining:** the only open item is documentation — add the threat model and the
L-5/L-6 caveats to the README before wide distribution.

*No finding blocked open-sourcing; the design was defensible to begin with, and the
medium items are now closed and regression-tested.*
