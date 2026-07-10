# fob

Your Mac as a key fob: SSH keys that live in the Secure Enclave, open only the doors they're badged for, and take one touch to use.

The private key is generated inside the Secure Enclave and never leaves it — there is no key file to steal, back up, or leak. What's stored on disk (`~/.fob/keys/`) is an encrypted blob only your machine's enclave can use. Every SSH authentication requires user presence (Touch ID, Apple Watch, or password — or strictly Touch ID with `--require-biometry`).

A `fob` CLI plus a menu-bar app (`fob.app`) that hosts the agent, zero third-party dependencies. Beyond basic Touch ID gating: destination-aware prompts (session-bind), per-host key pinning, opt-in touch reuse, a tamper-evident audit log, and native notifications with a live sign-request feed.

## Build

```sh
# CLI only:
swift build -c release          # binary at .build/release/fob

# Menu-bar app (also builds and bundles the CLI), installed to ~/Applications:
./Scripts/build-app.sh
```

The agent runs inside `fob.app`. `./Scripts/build-app.sh` builds and ad-hoc-signs the bundle, copies it to `~/Applications/fob.app`, and symlinks the CLI to `~/.fob/bin/fob`. Open the app and turn on **Launch at login**. Set `FOB_SIGN_IDENTITY` to sign with a real identity (an ad-hoc build works locally but can't show a notification icon and can't be distributed). For a notarized, Homebrew-distributable build, see [`docs/RELEASING.md`](docs/RELEASING.md).

## Usage

### Guided (recommended)

One command sets up a remote host end to end — creates the key, installs it on
the server with `ssh-copy-id` (you'll enter your password once), adds a `Host`
entry to `~/.ssh/config`, and verifies the connection with Touch ID:

```sh
fob setup myserver oliv@192.168.1.10
# or just `fob setup` and answer the prompts
```

After that, `ssh myserver` asks for Touch ID and connects.

Prefer to run every command yourself? `--manual` only creates and exports the
key, then prints the remaining steps (ssh-copy-id line, config block, test
command) for you to inspect and paste — it executes nothing and never touches
`~/.ssh/config`. Arguments are passed to subprocesses as an argv array (no
shell involved), and names/hosts/users may not start with `-`, so they can
never be smuggled in as ssh options.

### Manual

```sh
# 1. Create a key (P-256 — the only curve the Secure Enclave supports)
fob generate mykey

# 2. Add the printed public key to the server's ~/.ssh/authorized_keys (or GitHub)

# 3. Start the agent: open fob.app and turn on "Launch at login"
#    (build it first with ./Scripts/build-app.sh)

# 4. Point ssh at the agent — add to ~/.ssh/config:
#    Host *
#      IdentityAgent ~/.fob/agent.sock

# 5. Verify the Touch ID flow without a server:
fob test-sign mykey
```

Other commands: `list`, `pin`/`unpin`, `reuse`, `policy`, `audit`, `uninstall` (removes the legacy launchd agent). Most of these are also available from the menu-bar panel.

## Security model

Be clear-eyed about what a hardware-backed agent can and cannot do. fob is a
presence-gated key store, not a sandbox around your own logged-in session.

**Strongly protected:**

- **Key theft / exfiltration.** The private key is generated in the Secure Enclave and
  never leaves it. On disk there is only an enclave-wrapped blob that is useless on any
  other machine and can't be turned back into key material — full disk access, a stolen
  laptop, a Time Machine backup, or `sudo` yields nothing usable.
- **Memory scraping.** The enclave performs the signature; the key never enters the
  agent's (or any) process memory.
- **Silent use.** Every *fresh* signature needs user presence (Touch ID / Apple Watch /
  password), so nothing signs without a prompt — subject to the reuse window below.
- **Wrong-destination use.** A pinned key signs only for its verified, bound host
  (see [Per-host pinning](#per-host-pinning)).

**Not protected against — by design, and worth understanding:**

- **A malicious process running as you, while your Mac is unlocked.** This is inherent
  to *every* ssh-agent: anything with your user ID can connect to the agent socket and
  request a signature. The Touch ID prompt is the backstop for each fresh signature —
  but a **touch-reuse window** (off by default; opt-in, max 300 s) lets signatures
  happen with no prompt while it's open. Reuse is scoped to the destination it was
  approved for, so a grant for host A can't be spent on host B; still, treat reuse as
  "N seconds of touchless signing available to anything running as you." Such a process
  can also read or rewrite everything under `~/.fob` (policies, the audit log). The
  socket and `~/.fob` are `0600`/`0700`, so *other* users on the machine are kept out —
  the boundary fob cannot cross is code running as **you**.
- **A compromised host** piggybacking on a session you legitimately opened, and
  **agent-forwarding hijack** on a remote host — prefer `ProxyJump` over `ForwardAgent`.
- **You, the machine owner.** The audit log is tamper-*evident*, not tamper-*proof*
  (see [Audit log](#audit-log)).

Two honest nuances:

- **`session-bind` proves participation, not intent for a specific signature.** The
  binding proves a host holding that host key took part in *some* key exchange; fob does
  not tie it to the exact payload being signed (neither does OpenSSH's own agent). A
  local attacker could replay a captured binding for a pinned host to satisfy the pin
  check — but the resulting signature is only useful against the real host within a live
  session whose ID was mixed into the signed data. Pinning raises the bar substantially;
  it is not absolute against a determined same-user attacker.
- **Lock-screen previews.** Notifications name the destination and key; macOS may show
  that on the lock screen depending on **System Settings → Notifications → fob → Show
  previews**. Set it to "when unlocked" (or never) if which hosts you reach is sensitive.

**Where keys are stored.** fob keeps each key as its Secure Enclave `dataRepresentation`
— an enclave-wrapped, **device-bound blob** — in a `0600` file under `~/.fob/keys/` (the
[age-plugin-se](https://github.com/Foxboron/age-plugin-se) pattern), rather than in the
macOS Keychain. This does **not** weaken the core protection: the private key never
leaves the Secure Enclave in either model, the blob is useless on any other device, and
every use is gated by the key's own Touch ID / presence access control no matter where
the blob sits — reading the file cannot produce a signature without the prompt. The one
difference from Keychain storage is that a process running as *you* can read the blob
file; but it still can't sign without Touch ID, and same-user code can already reach the
agent socket regardless (this sits in the "malicious code running as you" zone above).
At-rest encryption is FileVault's job; `0700`/`0600` keep other users out. (Moving the
blob into a code-identity-gated Keychain item is possible but low-value, since the blob
isn't extractable — see [`docs/CONFIG-INTEGRITY.md`](docs/CONFIG-INTEGRITY.md) for why
that mechanism is dormant.)

A full third-party-style audit of this codebase, with these items resolved and a
regression test suite (`swift test`), is in [`SECURITY_CLAUDE_REPORT.md`](SECURITY_CLAUDE_REPORT.md).

## Destination awareness

The Touch ID prompt tells you **where** you're connecting, not just that something wants a signature:

> connect to **marvin (192.168.1.20)** — requested by ssh (pid 1234) with key "marvin"

This closes the classic ssh-agent **intent gap** (Touch ID proving *you are present* but not *which connection* you're approving). Modern ssh clients (OpenSSH 8.9+) send the agent a `session-bind@openssh.com` message carrying the destination's host key, the session ID, and the host key's signature over it. The agent **verifies that signature** (Ed25519, ECDSA, and RSA host keys), so a local process cannot claim a destination it didn't really do a key exchange with. The host key is resolved to a name you recognize via `known_hosts` and your ssh config aliases.

If a client omits the binding, the prompt says so — "connect to **an UNKNOWN destination**" — so silence is visible too. To refuse rather than just label, pin the key (next section).

## Per-host pinning

`setup` pins each key to its host automatically (opt out with `--no-pin`); do it by hand with `fob pin <key> <host>` (host keys are read from `~/.ssh/known_hosts`). A pinned key is refused — before any Touch ID prompt — for any other destination, for unverified bindings, and for clients that don't identify a destination at all. A stolen agent socket therefore can't use your pinned key against a different server even if you'd approve the touch. `unpin` reverses it; `policy` shows the state of every key.

Trade-off: a pinned key stops working with ssh clients older than OpenSSH 8.9 (they never send the binding).

## Touch reuse

`fob reuse <key> 30` lets one approval count for the next 30 seconds (max 300) for that key — one touch covers a `git pull`'s multiple connections or an rsync burst. The agent holds the authorization in memory and drops it at the deadline (or when the agent exits); reused signatures still go through pin checks and still produce notifications and audit entries (`signed-reused`). `reuse <key> off` restores touch-per-signature.

## Audit log

Every agent decision — `bind`, `signed`, `signed-reused`, `denied`, `refused-pin`, `refused-policy`, `unknown-key` — is appended to `~/.fob/audit.log` with timestamp, key, destination, and requesting process. Entries form a SHA-256 hash chain: each records the hash of the previous line, so editing or deleting a line breaks the chain for everything after it. `fob audit` shows recent entries; `audit --verify` checks the chain.

**Honest limitation — tamper-evident, not tamper-proof.** The log is a plain file you own, with no external anchor or secret key, so anyone who can write it (you, or malware running as you) can recompute a fresh, internally-consistent chain that `--verify` accepts, or simply delete the file. This *cannot* be fixed against a same-user attacker without hardware attestation: any key fob could use to seal the log without prompting is, by definition, also usable by that attacker, and a Touch-ID-gated seal would mean a prompt per log line. Treat `--verify` as detecting accidental or partial edits — not as proof against a motivated attacker who is already running as you.

## Menu-bar app

`fob.app` is a menu-bar-only app (no Dock icon) that hosts the agent in-process. From its panel you can:

- see agent status and a **live feed** of every decision (signed / denied / refused / bind) as it happens,
- manage keys — generate, set the touch-reuse window, pin to a host / unpin, delete,
- toggle **Launch at login** (via `SMAppService`), and reveal the audit log.

Because the app owns the socket, only one agent runs at a time: startup takes an exclusive lock on `~/.fob/agent.lock`, and the CLI `fob agent` command is disabled (it points you to the app). The CLI and app share the same `~/.fob` files, so `fob pin`/`reuse`/`generate` from the terminal take effect on the running app at the next signature.

Migrating from the phase-1/2 launchd agent: run `fob uninstall` to remove `dev.fob.agent`, then open `fob.app` and enable Launch at login.

## Notifications

The agent posts a macOS notification for every signature event, so key usage is never silent:

- 🔑 a signature was issued — including which process asked (e.g. `ssh (pid 1234)`) and for which destination (from the session binding)
- 🚫 a signature request was denied (Touch ID canceled or failed)
- ⛔️ a pinned key was blocked for the wrong destination
- ⚠️ something requested a signature with a key this agent doesn't hold

The requesting process is identified from the socket peer's PID. This is best-effort and spoofable in principle (PID reuse) — treat it as awareness, never proof. The app posts **native** notifications via `UNUserNotificationCenter` (allow notifications for "fob" if you don't see them); if that's unavailable — unsigned build or denied permission — it falls back automatically to the `osascript` notifier (which appears under "Script Editor").

## Notes

- Key type is `ecdsa-sha2-nistp256` only. No ed25519/RSA, no import/export — by design.
- `--require-biometry` binds the key to the currently enrolled fingerprints; enrolling a new fingerprint invalidates it. The default (`userPresence`) also allows Apple Watch and password, which covers clamshell mode.
- Deleting a `.key` file permanently destroys that key (nothing can recreate it).

## Acknowledgments

We first came across the idea of keeping SSH keys in the Secure Enclave through
[Secretive](https://github.com/maxgoedjen/secretive) by Max Goedjen (see its
[README](https://github.com/maxgoedjen/secretive/blob/main/README.md)). We liked the
concept — a menu-bar agent that never lets the key leave the enclave — and it's worth a
look if fob isn't what you're after.

We built fob rather than adopting it because we wanted to center a few different ideas:

- **Destination-aware authorization.** fob verifies the `session-bind@openssh.com`
  host-key signature and puts the *destination* in the Touch ID prompt ("connect to
  marvin (192.168.1.20)"), so you approve *where* you're connecting — not just *that*
  something wants a signature.
- **Per-host pinning.** A key can be refused — before any prompt — for every host but
  the one it's bound to, so a stolen agent socket can't redirect it elsewhere.
- **Opt-in, destination-scoped touch reuse**, a **tamper-evident audit log**, and a
  **CLI-first guided `fob setup`** that onboards a host end to end.
- **A tiny, zero-dependency codebase** you can read and audit in an afternoon.

## License

Copyright (C) 2026 Olivier Devaux.

fob is free software licensed under the **GNU Affero General Public License v3.0** (AGPL-3.0) — see [`LICENSE`](LICENSE). You may use, study, modify, and redistribute it, but any distributed or network-served derivative must also be released as open source under the same license.
