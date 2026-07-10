import CryptoKit
import FobKit
import Foundation
import LocalAuthentication

let usage = """
fob — Secure Enclave SSH keys gated by Touch ID

USAGE:
  fob generate <name> [--require-biometry]
      Create a new Secure Enclave key. By default any user-presence check
      (Touch ID, Apple Watch, or password) unlocks it; --require-biometry
      restricts it to the currently enrolled fingerprints only.

  fob setup [<alias>] [[user@]host] [--require-biometry] [--manual]
      Guided setup for one remote host: create the key, install it on the
      server (ssh-copy-id), add a Host entry to ~/.ssh/config, and verify.
      Prompts for anything not given on the command line.
      --manual only creates and exports the key, then prints the remaining
      commands for you to inspect and run yourself — nothing is executed
      and ~/.ssh/config is not touched.

  fob adopt <alias> [--require-biometry]
      Convert an existing ~/.ssh/config host to fob. Prints a dry-run plan
      (generates the enclave key locally but changes nothing on the server or
      in ~/.ssh/config); the install step reuses your current key, so it's
      passwordless for hosts you can already reach.

  fob list
      Print the public keys in authorized_keys format.

  fob pin <name> <host>
      Pin a key to a host: the agent will refuse to sign with this key for
      any other destination, or for clients that don't identify one. Host
      keys are taken from ~/.ssh/known_hosts (connect once first). Pinning
      the same key to another host adds to the allowed set.

  fob unpin <name>
      Remove all pins from a key.

  fob reuse <name> <seconds|off>
      After one approval, sign without re-prompting for up to <seconds>
      (max 300) — for git/rsync bursts. Every reused signature is still
      pin-checked, notified, and audited.

  fob sign-setup <name>
      Print how to use a key for Touch ID-gated git commit signing (SSH signing):
      the SSH_AUTH_SOCK export, the git config, and the public key to register on
      your git host (GitHub, GitLab, Gitea/Forgejo, …) as a Signing Key. A key can
      be both an Authentication and a Signing key. `git commit` then prompts Touch
      ID and the host shows "Verified".

  fob namespaces <name> <any|none|ns1,ns2,...>
      Restrict which SSHSIG namespaces a key may sign (git commit signing uses
      "git"). any = any namespace (default); none = signing disabled; a list =
      only those. Does not affect SSH authentication (see `pin`).

  fob policy
      Show the pinning, reuse, and signing policy of every key.

  fob audit [--verify]
      Show recent agent decisions (sign/deny/refuse/bind) from the
      tamper-evident audit log; --verify checks the log's hash chain.

  fob test-sign <name>
      Sign test data with a key (prompts for Touch ID) and verify it.

  fob install
      Print how to install the fob.app menu-bar agent.

  fob uninstall
      Remove the legacy launchd agent (dev.fob.agent), if present.

The agent runs inside fob.app (menu bar). Build and install it with:
  ./Scripts/build-app.sh
then open fob.app and enable "Launch at Login". Point ssh at it with:
  Host *
    IdentityAgent ~/.fob/agent.sock
"""

let installHelp = """
The fob agent now runs inside fob.app (menu bar), not the CLI.

To install it:
  ./Scripts/build-app.sh        # builds fob.app and copies it to ~/Applications
  open ~/Applications/fob.app    # then enable "Launch at Login" from the menu

If you previously ran the CLI agent under launchd, remove it first:
  fob uninstall
"""

func fail(_ message: String) -> Never {
    fflush(stdout) // keep buffered output ahead of the error line
    FileHandle.standardError.write(Data("error: \(message)\n".utf8))
    exit(1)
}

let arguments = Array(CommandLine.arguments.dropFirst())

do {
    let store = try KeyStore.default()
    switch arguments.first {
    case "generate":
        var rest = Array(arguments.dropFirst())
        let requireBiometry = rest.contains("--require-biometry")
        rest.removeAll { $0 == "--require-biometry" }
        guard let name = rest.first, rest.count == 1 else {
            fail("usage: fob generate <name> [--require-biometry]")
        }
        let key = try store.create(name: name, requireBiometry: requireBiometry)
        let line = SSHFormat.authorizedKeysLine(try key.publicKey(), comment: "fob:\(name)")
        print("Created Secure Enclave key '\(name)'.")
        print("")
        print(line)
        print("")
        print("Add the line above to the server's ~/.ssh/authorized_keys (or GitHub).")
        print("Protection: \(requireBiometry ? "Touch ID only (currently enrolled fingerprints)" : "user presence (Touch ID, Apple Watch, or password)")")

    case "setup":
        try Setup.run(store: store, arguments: Array(arguments.dropFirst()))

    case "adopt":
        try Setup.adopt(store: store, arguments: Array(arguments.dropFirst()))

    case "list":
        let keys = try store.all()
        if keys.isEmpty {
            print("No keys yet. Create one with: fob generate <name>")
        }
        for key in keys {
            print(SSHFormat.authorizedKeysLine(try key.publicKey(), comment: "fob:\(key.name)"))
        }

    case "pin":
        let rest = Array(arguments.dropFirst())
        guard rest.count == 2 else { fail("usage: fob pin <name> <host>") }
        let (name, host) = (rest[0], rest[1])
        let key = try store.find(name: name)
        let hostKeys = HostResolver.knownHostKeys(for: host)
        guard !hostKeys.isEmpty else {
            fail("no host keys for '\(host)' in ~/.ssh/known_hosts — connect once (ssh \(host)) and retry")
        }
        var policy = store.policy(name: key.name)
        let added = hostKeys.filter { !policy.pinnedHostKeys.contains($0) }
        policy.pinnedHostKeys.append(contentsOf: added)
        try store.savePolicy(policy, name: key.name)
        print("Pinned key '\(key.name)' to \(host) (\(added.count) new host key(s), \(policy.pinnedHostKeys.count) total).")
        print("The agent now refuses this key for any other destination — including")
        print("clients that don't identify their destination (older than OpenSSH 8.9).")

    case "unpin":
        guard let name = arguments.dropFirst().first, arguments.count == 2 else {
            fail("usage: fob unpin <name>")
        }
        let key = try store.find(name: name)
        var policy = store.policy(name: key.name)
        policy.pinnedHostKeys = []
        try store.savePolicy(policy, name: key.name)
        print("Removed all pins from key '\(key.name)'.")

    case "reuse":
        let rest = Array(arguments.dropFirst())
        guard rest.count == 2 else { fail("usage: fob reuse <name> <seconds|off>") }
        let key = try store.find(name: rest[0])
        var policy = store.policy(name: key.name)
        if rest[1] == "off" {
            policy.reuseSeconds = nil
            try store.savePolicy(policy, name: key.name)
            print("Key '\(key.name)' now requires a touch for every signature.")
        } else {
            guard let seconds = Double(rest[1]), seconds >= 1, seconds <= 300 else {
                fail("reuse window must be 1–300 seconds, or 'off'")
            }
            policy.reuseSeconds = seconds
            try store.savePolicy(policy, name: key.name)
            print("Key '\(key.name)': one approval now counts for \(Int(seconds))s of signatures.")
        }

    case "namespaces":
        let rest = Array(arguments.dropFirst())
        guard rest.count == 2 else { fail("usage: fob namespaces <name> <any|none|ns1,ns2,...>") }
        let key = try store.find(name: rest[0])
        var policy = store.policy(name: key.name)
        switch rest[1].lowercased() {
        case "any": policy.allowedNamespaces = nil
        case "none": policy.allowedNamespaces = []
        default:
            let list = rest[1].split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
            guard !list.isEmpty else { fail("usage: fob namespaces <name> <any|none|ns1,ns2,...>") }
            policy.allowedNamespaces = list
        }
        try store.savePolicy(policy, name: key.name)
        if let namespaces = policy.allowedNamespaces {
            print(namespaces.isEmpty
                ? "Key '\(key.name)' will refuse ALL signature requests."
                : "Key '\(key.name)' will sign only for: \(namespaces.joined(separator: ", ")).")
        } else {
            print("Key '\(key.name)' may sign for any namespace.")
        }

    case "sign-setup":
        guard let name = arguments.dropFirst().first, arguments.count == 2 else {
            fail("usage: fob sign-setup <name>")
        }
        let key = try store.find(name: name)
        let sshDir = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".ssh")
        try FileManager.default.createDirectory(at: sshDir, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        let pubURL = sshDir.appendingPathComponent("fob_\(name).pub")
        let pubLine = SSHFormat.authorizedKeysLine(try key.publicKey(), comment: "fob:\(name)")
        try Data((pubLine + "\n").utf8).write(to: pubURL, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: pubURL.path)
        print("Enable Touch ID-gated git commit signing with fob key '\(name)'.")
        print("Public key exported to \(pubURL.path).")
        print("")
        print("1. Point ssh-keygen's signer at fob's agent (add to your shell profile):")
        print("     export SSH_AUTH_SOCK=\(store.socketPath)")
        print("")
        print("2. Configure git to sign with this key:")
        print("     git config --global gpg.format ssh")
        print("     git config --global user.signingkey \(pubURL.path)")
        print("     git config --global commit.gpgsign true")
        print("     git config --global tag.gpgsign true")
        print("")
        print("3. Register the key on your git host as a SIGNING key (a separate entry from")
        print("   an Authentication key) — e.g. GitHub or GitLab → Settings → SSH keys:")
        print("     \(pubLine)")
        print("")
        print("4. (recommended) restrict this key to git signatures only:")
        print("     fob namespaces \(name) git")
        print("")
        print("Then `git commit` prompts Touch ID via fob, and your host (GitHub, GitLab,")
        print("Gitea/Forgejo, …) shows \"Verified\". It also verifies locally via allowed_signers.")

    case "policy":
        let keys = try store.all()
        if keys.isEmpty { print("No keys yet.") }
        for key in keys {
            let policy = store.policy(name: key.name)
            var parts: [String] = []
            if policy.pinnedHostKeys.isEmpty {
                parts.append("not pinned (any destination)")
            } else {
                let names = policy.pinnedHostKeys
                    .map { HostResolver.name(forHostKeyBlob: $0) ?? "unknown host key" }
                parts.append("pinned to \(Set(names).sorted().joined(separator: ", "))")
            }
            if let reuse = policy.reuseSeconds, reuse > 0 {
                parts.append("touch reuse \(Int(reuse))s")
            } else {
                parts.append("touch every time")
            }
            if let namespaces = policy.allowedNamespaces {
                parts.append(namespaces.isEmpty ? "signing disabled"
                                                : "signs only: \(namespaces.joined(separator: ", "))")
            }
            print("\(key.name): \(parts.joined(separator: "; "))")
        }

    case "audit":
        if arguments.dropFirst().first == "--verify" {
            let entries = AuditLog.entries(directory: store.directory)
            if let broken = AuditLog.firstBrokenLink(directory: store.directory) {
                fail("audit log TAMPERED: hash chain breaks at line \(broken) of \(entries.count)")
            }
            print("Audit log intact: \(entries.count) entries, hash chain verified.")
        } else {
            let entries = AuditLog.entries(directory: store.directory).suffix(20)
            if entries.isEmpty { print("No audit entries yet.") }
            for entry in entries {
                var line = "\(entry.ts)  \(entry.event)"
                if let key = entry.key { line += "  key=\(key)" }
                if let dest = entry.dest { line += "  dest=\(dest)" }
                if let peer = entry.peer { line += "  peer=\(peer)" }
                print(line)
            }
        }

    case "test-sign":
        guard let name = arguments.dropFirst().first else {
            fail("usage: fob test-sign <name>")
        }
        let key = try store.find(name: name)
        let context = LAContext()
        context.localizedReason = "test-sign with key \"\(name)\""
        let payload = Data("fob test payload".utf8)
        let signature = try key.privateKey(context: context).signature(for: payload)
        guard try key.publicKey().isValidSignature(signature, for: payload) else {
            fail("signature did not verify")
        }
        print("OK — signed with '\(name)' and verified.")

    case "agent":
        // The agent runs inside fob.app now. A single-instance lock already stops
        // two agents from racing on the socket; this refusal makes the intent
        // explicit and keeps a stray `fob agent` (e.g. an old launchd job) from
        // ever taking over.
        fail("`fob agent` is disabled — the agent runs inside fob.app.\n\n\(installHelp)")

    case "install":
        print(installHelp)

    case "uninstall":
        try Launchd.uninstall()
        print("Removed the legacy launchd agent (\(Launchd.label)), if it was present.")
        print("The agent now runs inside fob.app — open it and enable \"Launch at Login\".")

    default:
        print(usage)
    }
} catch {
    fail(error.localizedDescription)
}
