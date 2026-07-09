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

The agent runs inside `fob.app`. `./Scripts/build-app.sh` builds and ad-hoc-signs the bundle, copies it to `~/Applications/fob.app`, and symlinks the CLI to `~/.fob/bin/fob`. Open the app and turn on **Launch at login**. (For notarized distribution, swap the ad-hoc identity in the script for a Developer ID and add `--options runtime`.)

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
