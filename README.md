<div align="center">

<img src="docs/logo.png" alt="fob" width="112" height="112">

# fob

**Your Mac as a key fob** — SSH keys that live in the Secure Enclave, open only the doors they're badged for, and take one touch to use.

[![License: AGPL v3](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)
&nbsp;![macOS 13+](https://img.shields.io/badge/macOS-13%2B-000?logo=apple)
&nbsp;![Swift 5.9](https://img.shields.io/badge/Swift-5.9-f05138?logo=swift&logoColor=white)
&nbsp;![Dependencies: none](https://img.shields.io/badge/dependencies-none-brightgreen)

</div>

The private key is generated **inside the Secure Enclave and never leaves it** — no key file to steal, back up, or leak. What's on disk is an encrypted blob only your Mac's enclave can use, and every use needs Touch ID (or Apple Watch / password). On top of that, fob adds destination-aware prompts, per-host pinning, touch reuse, a tamper-evident audit log, and a read-only checkup of your SSH setup — as a menu-bar app plus a `fob` CLI, with zero third-party dependencies.

## Features

- 🔐 **Keys in the Secure Enclave** — non-exportable; nothing usable on disk or in memory
- 👆 **One touch per use** — Touch ID, Apple Watch, or password
- 🎯 **Destination-aware prompts** — see *where* you're connecting, cryptographically verified
- 📌 **Per-host pinning** — a key refuses every host but the one it's bound to
- ⏱️ **Opt-in touch reuse** — one touch covers a `git` / `rsync` burst
- ✍️ **Touch-ID commit signing** — sign git commits with a Secure Enclave key; GitHub/GitLab show *Verified*
- 🚚 **Safe migration** — moves an existing SSH host to fob *alongside* the old key; no cutover, no lockout
- 🩺 **SSH checkup** — a read-only hygiene report of your `~/.ssh`: unencrypted or unused keys, risky config, and identity/signing footguns
- 📜 **Tamper-evident audit log** — hash-chained record of every decision
- 🖥️ **Menu-bar app + CLI** — live activity feed, guided setup, zero dependencies

## Install

### Homebrew (recommended)

```sh
brew install --cask olivierzol/fob/fob
```

Then open **fob** from the menu bar and turn on **Launch at login**.

### From source

```sh
./Scripts/build-app.sh      # builds fob.app → ~/Applications and symlinks the CLI
```

Ad-hoc-signed by default (fine for local use). Set `FOB_SIGN_IDENTITY` for a real signature; see [`docs/RELEASING.md`](docs/RELEASING.md) for notarized / Homebrew builds. CLI only: `swift build -c release`.

## Quick start

One command onboards a host end to end — creates the key, installs it with `ssh-copy-id`, adds a `~/.ssh/config` entry, verifies with Touch ID, and pins the key:

```sh
fob setup myserver you@host      # or just `fob setup` and answer the prompts
```

Then `ssh myserver` prompts for Touch ID and connects. Prefer to run each step yourself? `fob setup --manual` prints the commands and changes nothing.

<details>
<summary><strong>Manual setup</strong> (without the <code>setup</code> helper)</summary>

```sh
fob generate mykey                    # 1. create a Secure Enclave key (P-256)
# 2. add the printed public key to the server's authorized_keys (or GitHub)
# 3. open fob.app and enable "Launch at login"
# 4. point ssh at the agent — in ~/.ssh/config:
#      Host *
#        IdentityAgent ~/.fob/agent.sock
fob test-sign mykey                   # 5. verify the Touch ID flow, no server needed
```

</details>

## Already using SSH keys? Migrate

fob **can't import** an existing key — the Secure Enclave only generates keys on-device (P-256). That's the safety feature, not a limitation: migration means fob adds a **new key alongside your old one**, proves it works, and lets you retire the old one *when you choose*. Your current key keeps working the whole time — **no cutover, no lockout**.

For a host already in your `~/.ssh/config`, one command does it — it installs the fob key using your **current** key (so it's passwordless for hosts you can already reach), backs up and rewrites the config block (showing a diff first), verifies over Touch ID, and pins:

```sh
fob adopt myserver               # preview only: fob adopt myserver --dry-run
```

The old `IdentityFile` stays active as a fallback. Once you've confirmed fob works:

```sh
fob adopt myserver --retire      # comment the old key out of ~/.ssh/config
# then remove the old public key from the server's ~/.ssh/authorized_keys
```

**From the menu-bar app:** open the panel → **Migrate…**. It lists the hosts in your `~/.ssh/config` and walks each one through install → config diff → **Verify (Touch ID)** → pin → optional retire, with a timestamped `~/.ssh/config` backup at every write.

### Git hosts (GitHub, GitLab, …)

Git hosts have no shell, so instead of `ssh-copy-id` you add the key on the web. fob handles this: **Migrate…** lists your `github-*`/`gitlab-*` blocks (badged by provider), and **Set up a host…** has a **Git host** option for a brand-new one. The flow:

1. **Create key & open <provider>** — copies the pubkey and deep-links to the SSH-keys page; add it as an **Authentication Key**.
2. Config is rewritten to route the alias through fob (alongside your old key).
3. **Verify** runs `ssh -T` and confirms *"Authenticated as <you>"* over Touch ID.

`fob adopt <alias>` does the same from the CLI (prints the deep-link + key to add).

> **Signing is separate.** On GitHub a *signing* key is a distinct entry — add the same fob key **again** as a **Signing Key** (GitLab lets one key do both). Use **Sign commits with this key →** in the migrate flow, or a key's ••• → **Use for commit signing…** (see below).

## How it works

### 🎯 Destination-aware prompts

The Touch ID prompt tells you **where** you're connecting, not just that *something* wants a signature:

> connect to **marvin (192.168.1.20)** — requested by ssh (pid 1234) with key "marvin"

Modern ssh clients (OpenSSH 8.9+) send a `session-bind@openssh.com` message carrying the server's host key and a signature over the session ID. fob **verifies that signature** (Ed25519 / ECDSA / RSA) and resolves the host to a name from `known_hosts` and your ssh config — so a local process can't claim a destination it didn't actually connect to. A client that omits the binding shows as **"an UNKNOWN destination"**, so silence is visible too.

### 📌 Per-host pinning

`fob pin <key> <host>` (done automatically by `setup`) refuses a key — **before any Touch ID prompt** — for any other destination, unverified bindings, or clients that don't identify a host. A stolen agent socket therefore can't redirect a pinned key elsewhere. `unpin` reverses it; `policy` lists every key.

> **Trade-off:** pinned keys require OpenSSH ≥ 8.9 (older clients never send the binding).

### ⏱️ Touch reuse

`fob reuse <key> 30` lets one approval cover the next 30 s (max 300) — enough for a `git pull`'s many connections or an rsync burst. Reused signatures are still pin-checked, notified, and audited (`signed-reused`). `fob reuse <key> off` restores touch-per-signature.

### 📜 Audit log

Every decision (`signed`, `denied`, `refused-pin`, …) is appended to `~/.fob/audit.log` as a SHA-256 **hash chain** — editing or deleting any line breaks it. `fob audit` shows recent entries; `fob audit --verify` checks the chain. (Tamper-*evident*, not tamper-*proof* — see [Security model](#security-model).)

### 🖥️ Menu-bar app

`fob.app` (no Dock icon) hosts the agent in-process. Its panel shows status and a **live activity feed**, manages keys (generate / reuse / pin / delete), toggles Launch-at-login, and reveals the audit log. Only one agent runs at a time (an exclusive lock on `~/.fob/agent.lock`); the CLI and app share `~/.fob`, so `fob pin` / `reuse` / `generate` from the terminal take effect immediately.

### 🔔 Notifications

A native notification on every event, so key use is never silent:

| | |
|---|---|
| 🔑 | a signature was issued — with the requesting process and destination |
| 🚫 | a request was denied (Touch ID cancelled or failed) |
| ⛔️ | a pinned key was blocked for the wrong destination |
| ⚠️ | something asked for a key this agent doesn't hold |

Process attribution is best-effort (via the socket peer's PID) — treat it as awareness, not proof.

### ✍️ Commit signing

A fob key can also **sign git commits** — each `git commit` prompts Touch ID, and hosts
that verify SSH signatures (**GitHub, GitLab, Gitea/Forgejo, Codeberg, …**) show the commit
as **Verified**. It's standard SSH commit signing (`ssh-keygen -Y sign`), which fob's agent
serves from the Secure Enclave — so it also verifies **locally**, host-independently, via an
`allowed_signers` file. The same key can be **both** an *Authentication* key and a *Signing*
key on your host (they're separate entries).

```sh
fob sign-setup <key>     # prints the exact steps below for a key you've generated
```

It walks you through two things:

1. **Configure git** (`gpg.format ssh`, `user.signingkey <the fob pubkey>`,
   `gpg.ssh.program <fob wrapper>`, `commit.gpgsign true`). fob points git's signer at
   its agent through a tiny `gpg.ssh.program` wrapper (`~/.fob/bin/fob-sign`) rather than
   `SSH_AUTH_SOCK` — so **only git signing** reaches fob, and any other ssh agent you run
   (plus `git push` auth) is left untouched. Use `--global` for every repo, or `--local`
   (run inside a repo) if you switch between multiple git identities.
2. **Register the public key on your git host as a *signing* key** — e.g. GitHub or
   GitLab → Settings → SSH keys, added as a Signing Key (separate from an Authentication key).

fob tells a signing request apart from an SSH login by the SSHSIG envelope's **namespace**
(`git` for commits), shows a signing-specific prompt, and audits it as `signed-git`. You can
restrict which namespaces a key may sign — the signing-side analog of pinning:

```sh
fob namespaces <key> git     # this key may only sign git commits
fob namespaces <key> none    # disable signing entirely
fob namespaces <key> any     # default — any namespace
```

A touch per commit adds up, so pair it with `fob reuse <key> <seconds>` for rebases/bursts.

### 🩺 SSH checkup

A **read-only** pass over your SSH setup that reports hygiene problems and nudges toward
fob — it changes nothing, only shows findings (with a copy-paste fix for each):

```sh
fob checkup          # or the menu-bar panel → "SSH checkup"
```

It flags:

- **Unencrypted private keys** on disk — with different advice for a key that's still
  referenced (add a passphrase, or move it to fob) versus one nothing uses anymore (delete it).
- **Weak or world-readable keys** — DSA / short RSA, or key files other accounts can read.
- **Risky `~/.ssh/config` directives** — `StrictHostKeyChecking no`, `UserKnownHostsFile
  /dev/null`, `ForwardAgent yes`, `IdentitiesOnly no` (amplified when set under `Host *`).
- **Multi-account git footguns** — with per-directory `includeIf` identities but no
  `user.useConfigOnly` guard, a repo outside those directories silently commits as your
  default account (the classic "wrong email leaked into a commit" bug). The robust fix is
  written up in [`docs/MULTI-ACCOUNT-GIT.md`](docs/MULTI-ACCOUNT-GIT.md).
- **Signatures you can't verify locally** — a fob signing key that isn't yet in
  `~/.ssh/allowed_signers`, so `git verify-commit` can't check your own commits.
- **Keys loaded in your ssh-agent** — on-disk keys the running agent has loaded sign with
  *no* Touch ID prompt while they're loaded (fob's own keys are excluded).
- **Opportunities** — plain-key hosts and non-fob signing keys you could move to fob.

## Security model

fob is a **presence-gated key store, not a sandbox around your own logged-in session.**

**✅ Strongly protected**

- **Key theft** — the private key never leaves the enclave; the on-disk blob is device-bound and useless elsewhere (disk access, backups, `sudo` get nothing usable).
- **Memory scraping** — the enclave performs the signature; the key never enters process memory.
- **Silent use** — every *fresh* signature requires user presence.
- **Wrong destination** — a pinned key signs only for its verified, bound host.

**⚠️ Not protected against (by design)**

- **Code running as *you*, while your Mac is unlocked** — inherent to any ssh-agent: it can drive the agent socket (each sign still hits Touch ID, unless a reuse window is open) and read/rewrite `~/.fob`. Other *users* are kept out (`0700`/`0600`); the line fob can't cross is your own uid.
- **A compromised remote host** / agent-forwarding hijack — prefer `ProxyJump` over `ForwardAgent`.
- **You, the owner** — the audit log is tamper-evident, not tamper-proof.

<details>
<summary><strong>Deeper nuances</strong> — session-bind replay, lock-screen previews, and file-vs-Keychain storage</summary>

- **`session-bind` proves participation, not intent for a specific signature.** The binding proves a host holding that host key took part in *some* key exchange; fob does not tie it to the exact payload being signed (neither does OpenSSH's own agent). A local attacker could replay a captured binding for a pinned host to satisfy the pin check — but the resulting signature is only useful against the real host within a live session whose ID was mixed into the signed data. Pinning raises the bar substantially; it is not absolute against a determined same-user attacker.
- **Lock-screen previews.** Notifications name the destination and key; macOS may show that on the lock screen depending on **System Settings → Notifications → fob → Show previews**. Set it to "when unlocked" (or never) if which hosts you reach is sensitive.
- **Where keys are stored.** fob keeps each key as its Secure Enclave `dataRepresentation` — an enclave-wrapped, **device-bound blob** — in a `0600` file under `~/.fob/keys/` (the [age-plugin-se](https://github.com/Foxboron/age-plugin-se) pattern), rather than in the macOS Keychain. This does **not** weaken the core protection: the private key never leaves the enclave in either model, the blob is useless on any other device, and every use is gated by the key's own presence access control no matter where the blob sits — reading the file cannot produce a signature without the prompt. The one difference from Keychain storage is that a process running as *you* can read the blob file; but it still can't sign without Touch ID, and same-user code can already reach the agent socket regardless. At-rest encryption is FileVault's job; `0700`/`0600` keep other users out. (Moving the blob into a code-identity-gated Keychain item is possible but low-value, since the blob isn't extractable — see [`docs/CONFIG-INTEGRITY.md`](docs/CONFIG-INTEGRITY.md).)

</details>

A full third-party-style audit of this codebase (findings resolved) plus a regression test suite (`swift test`) is in [`SECURITY_CLAUDE_REPORT.md`](SECURITY_CLAUDE_REPORT.md).

## CLI reference

| Command | Description |
|---|---|
| `fob setup [alias] [user@host]` | Guided end-to-end host onboarding |
| `fob adopt <alias> [--dry-run] [--retire]` | Migrate an existing `~/.ssh/config` host to fob |
| `fob generate <name> [--require-biometry]` | Create a Secure Enclave key |
| `fob list` | Print public keys (authorized_keys format) |
| `fob delete <key> [--force]` | Permanently erase a key from the enclave |
| `fob pin <key> <host>` · `fob unpin <key>` | Restrict a key to a host / remove all pins |
| `fob reuse <key> <seconds\|off>` | Set the touch-reuse window (max 300 s) |
| `fob policy` | Show every key's pin + reuse state |
| `fob audit [--verify]` | Show recent decisions / verify the hash chain |
| `fob checkup` | Read-only `~/.ssh` hygiene report (keys, config, identity/signing) |
| `fob test-sign <key>` | Exercise the Touch ID flow, no server needed |

Most actions are also available from the menu-bar panel.

> **Notes:** keys are `ecdsa-sha2-nistp256` (the enclave's only curve); no import/export by design. `--require-biometry` binds a key to the currently enrolled fingerprints (re-enrolling invalidates it); the default also accepts Apple Watch / password. Deleting a key is permanent — nothing can recreate it.

## Acknowledgments

We first came across the idea of keeping SSH keys in the Secure Enclave through [Secretive](https://github.com/maxgoedjen/secretive) by Max Goedjen (see its [README](https://github.com/maxgoedjen/secretive/blob/main/README.md)). We liked the concept — a menu-bar agent that never lets the key leave the enclave — and it's worth a look if fob isn't what you're after.

We built fob rather than adopting it to center a few different ideas:

- **Destination-aware authorization** — the verified destination in the Touch ID prompt, not just *that* something wants a signature.
- **Per-host pinning** — a key refused, before any prompt, for every host but the one it's bound to.
- **Opt-in touch reuse**, a **tamper-evident audit log**, and a **CLI-first guided `fob setup`**.
- **A tiny, zero-dependency codebase** you can read and audit in an afternoon.

## License

Copyright © 2026 Olivier Devaux.

fob is free software under the **GNU Affero General Public License v3.0** ([AGPL-3.0](LICENSE)) — use, study, modify, and redistribute it freely, but any distributed or network-served derivative must also be open-sourced under the same license.
