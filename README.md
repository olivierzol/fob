# fob

Your Mac as a key fob: SSH keys that live in the Secure Enclave, open only the doors they're badged for, and take one touch to use.

The private key is generated inside the Secure Enclave and never leaves it — there is no key file to steal, back up, or leak. What's stored on disk (`~/.fob/keys/`) is an encrypted blob only your machine's enclave can use. Every SSH authentication requires user presence (Touch ID, Apple Watch, or password — or strictly Touch ID with `--require-biometry`).

Minimal CLI + agent, zero third-party dependencies, no GUI. Beyond basic Touch ID gating: destination-aware prompts (session-bind), per-host key pinning, opt-in touch reuse, and a tamper-evident audit log.

## Build

```sh
swift build -c release
# binary at .build/release/fob
```

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

# 3. Start the agent at login
fob install

# 4. Point ssh at the agent — add to ~/.ssh/config:
#    Host *
#      IdentityAgent ~/.fob/agent.sock

# 5. Verify the Touch ID flow without a server:
fob test-sign mykey
```

Other commands: `list`, `pin`/`unpin`, `reuse`, `policy`, `audit`, `agent` (run in foreground), `uninstall`.

## What this defends against — and what it doesn't

Defends against: key file theft (no file exists), memory scraping of the agent (the enclave signs; the key never enters RAM), backup/sync leakage, and silent key use (a touch is required per signature).

Does **not** defend against: a compromised host piggybacking on a session you legitimately opened; and agent-forwarding hijack on a remote host (prefer `ProxyJump` over `ForwardAgent`).

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

Every agent decision — `bind`, `signed`, `denied`, `refused-pin`, `unknown-key` — is appended to `~/.fob/audit.log` with timestamp, key, destination, and requesting process. Entries form a SHA-256 hash chain: each records the hash of the previous line, so editing or deleting history breaks the chain for everything after it. `fob audit` shows recent entries; `audit --verify` checks the chain. Honest limitation: the *newest* entry can be altered undetectably until another lands on top of it — chain-head attestation (e.g. an enclave-signed head) would be the phase-3 fix.

## Notifications

The agent posts a macOS notification for every signature event, so key usage is never silent:

- 🔑 a signature was issued — including which process asked (e.g. `ssh (pid 1234)`) and for which destination (from the session binding)
- 🚫 a signature request was denied (Touch ID canceled or failed)
- ⚠️ something requested a signature with a key this agent doesn't hold

The requesting process is identified from the socket peer's PID. This is best-effort and spoofable in principle (PID reuse) — treat it as awareness, never proof. Notifications are posted via `osascript` (a bare CLI has no app bundle, which `UNUserNotificationCenter` requires); they appear under "Script Editor" in Notification Center settings, so allow notifications from Script Editor if you don't see them.

## Notes

- Key type is `ecdsa-sha2-nistp256` only. No ed25519/RSA, no import/export — by design.
- `--require-biometry` binds the key to the currently enrolled fingerprints; enrolling a new fingerprint invalidates it. The default (`userPresence`) also allows Apple Watch and password, which covers clamshell mode.
- Deleting a `.key` file permanently destroys that key (nothing can recreate it).
