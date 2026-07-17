# Multi-account git identity (without leaking the wrong one)

If you commit under more than one identity — say a work account and a personal one — the
default git setup has a sharp edge: **git falls back to a global default identity for any repo
that isn't explicitly covered**, so a clone in `/tmp`, `~/Downloads`, or a new project directory
silently commits (and signs) as the wrong account. fob's **SSH checkup** flags this; this guide
is the fix it points at.

## The footgun

A common multi-account setup uses `includeIf` to pick an identity by directory:

```ini
# ~/.gitconfig
[user]
    name  = You
    email = you@work.com          # ← global DEFAULT — used everywhere not covered below
[includeIf "gitdir:~/src/personal/"]
    path = ~/.gitconfig-personal   # personal identity, only under ~/src/personal
```

The problem is the global `[user]` block: **any repo outside `~/src/personal/`** — including
throwaway clones and brand-new directories — commits as `you@work.com`. Setting
`user.useConfigOnly = true` alone does **not** help while a global `user.email` is set (git
happily keeps using it).

## The robust setup

Two principles:

1. **No identity in the global config.** Move *every* identity into its own `includeIf` file.
2. **Turn on `user.useConfigOnly`.** With no global identity to fall back on, git *refuses to
   commit* in a directory that matches no include — an explicit error instead of a silent
   wrong-account commit.

```ini
# ~/.gitconfig  — no [user] name/email here on purpose
[user]
    useConfigOnly = true
[gpg "ssh"]
    allowedSignersFile = ~/.ssh/allowed_signers   # shared; fine to keep global

# Order matters: git uses the LAST matching include, so the broadest directory goes FIRST.
[includeIf "gitdir:~/src/"]
    path = ~/.gitconfig-work        # everything under ~/src …
[includeIf "gitdir:~/src/personal/"]
    path = ~/.gitconfig-personal    # … except ~/src/personal, which wins (listed after)
```

```ini
# ~/.gitconfig-work
[user]
    name  = You
    email = you@work.com
    signingkey = ~/.ssh/fob_work-signing.pub   # if you sign work commits with a fob key
[gpg]
    format = ssh
[gpg "ssh"]
    program = ~/.fob/bin/fob-sign
[commit]
    gpgsign = true
```

```ini
# ~/.gitconfig-personal  — same shape, personal values + its own fob signing key
[user]
    name  = You
    email = you@personal.dev
    signingkey = ~/.ssh/fob_personal-signing.pub
[gpg]
    format = ssh
[gpg "ssh"]
    program = ~/.fob/bin/fob-sign
[commit]
    gpgsign = true
```

### Why the ordering rule

git evaluates `includeIf` top-to-bottom and the **last** matching block wins. A repo in
`~/src/personal/foo` matches *both* includes above, so the personal one must come **after** the
work one to take effect. Rule of thumb: **the broadest directory goes first; the most specific
goes last.**

## How this interacts with fob

- **Commit signing** goes through fob's `gpg.ssh.program` wrapper (`~/.fob/bin/fob-sign`), set
  **per identity** so each account signs with its own fob key. Keep the wrapper *out* of the
  global config — a global `gpg.ssh.program` would try to route every account through one key.
- **`gpg.ssh.allowedSignersFile`** is a harmless shared pointer; keep it global so
  `git verify-commit` works in every repo. fob adds each signing key to `~/.ssh/allowed_signers`
  when you set signing up, and prunes the entry when you delete the key.
- **SSH auth** is independent of all this — it's driven by `~/.ssh/config`, not gitconfig.

## Verify it

```sh
git -C ~/src/anything     config user.email   # → you@work.com
git -C ~/src/personal/app config user.email   # → you@personal.dev

cd $(mktemp -d) && git init -q && git commit --allow-empty -m test
# → fatal: ... "user.useConfigOnly = true" ...  ← the guard working: no identity, so no
#   silent wrong-account commit. Run git in a directory that maps to an identity instead.
```

If a specific project lives outside your identity directories, give it a repo-local identity
(`git config user.email …` inside it) rather than reintroducing a global default.
