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

  fob adopt <alias> [--dry-run] [--retire] [--require-biometry]
      Convert an existing ~/.ssh/config host to fob. Installs the fob key on the
      server using your CURRENT key (passwordless), backs up + rewrites the config
      block (with a diff + confirm), verifies over Touch ID, and pins. The old key
      stays active as a fallback — no lockout. --dry-run prints the plan and changes
      nothing; --retire comments out the old key after you've verified fob works.

  fob list
      Print the public keys in authorized_keys format.

  fob delete <name> [--force]
      Permanently erase a key from the Secure Enclave (asks to confirm; --force
      skips). Remove its public key from any server/host that still trusts it.

  fob checkup
      Read-only SSH hygiene report: flags unencrypted / weak / loosely-permissioned
      on-disk keys, risky ~/.ssh/config directives, and hosts/signing that could move
      to fob. Changes nothing.

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
      the git config (routed to fob via a gpg.ssh.program wrapper, so SSH_AUTH_SOCK
      is untouched) and the public key to register on your git host (GitHub, GitLab,
      Gitea/Forgejo, …) as a Signing Key. A key can be both an Authentication and a
      Signing key. `git commit` then prompts Touch ID and the host shows "Verified".

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

/// `(type, bits)` from `ssh-keygen -l -f <key>`, or nil.
func sshKeygenTypeBits(_ path: String) -> (type: String, bits: Int?)? {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
    process.arguments = ["-l", "-f", path]
    let pipe = Pipe(); process.standardOutput = pipe; process.standardError = Pipe()
    guard (try? process.run()) != nil else { return nil }
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    guard process.terminationStatus == 0 else { return nil }
    let out = String(decoding: data, as: UTF8.self)
    let bits = out.split(separator: " ").first.flatMap { Int($0) }
    guard let o = out.lastIndex(of: "("), let c = out.lastIndex(of: ")"), o < c else { return nil }
    return (String(out[out.index(after: o)..<c]), bits)
}

/// Read-only SSH hygiene findings for `fob checkup` (keys + config + fob opportunities).
/// Full public keys the running ssh-agent has loaded (`ssh-add -L`); "" if the agent is
/// empty or unreachable (both exit non-zero, which we treat as "nothing to report").
func sshAddListPublicKeys() -> String {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-add")
    process.arguments = ["-L"]
    let pipe = Pipe(); process.standardOutput = pipe; process.standardError = Pipe()
    guard (try? process.run()) != nil else { return "" }
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    guard process.terminationStatus == 0 else { return "" }
    return String(decoding: data, as: UTF8.self)
}

func sshCheckupFindings(fobKeyBlobs: Set<String>, fobKeyNames: Set<String>) -> [SSHCheckup.Finding] {
    var findings: [SSHCheckup.Finding] = []
    let home = FileManager.default.homeDirectoryForCurrentUser
    let sshDir = home.appendingPathComponent(".ssh")
    let fm = FileManager.default

    let skip: Set<String> = ["config", "known_hosts", "authorized_keys", "agent.sock"]
    for name in ((try? fm.contentsOfDirectory(atPath: sshDir.path)) ?? []).sorted() {
        if name.hasSuffix(".pub") || name.hasPrefix("config.") || name.hasPrefix("known_hosts")
            || skip.contains(name) || name.hasPrefix(".") { continue }
        let path = sshDir.appendingPathComponent(name).path
        guard let contents = try? String(contentsOfFile: path, encoding: .utf8),
              let info = SSHCheckup.parsePrivateKey(contents) else { continue }
        if !info.isEncrypted {
            let cfg = (try? String(contentsOf: sshDir.appendingPathComponent("config"), encoding: .utf8)) ?? ""
            let gitSigning = GitConfig.parse((try? String(contentsOf: home.appendingPathComponent(".gitconfig"), encoding: .utf8)) ?? "").signingKey
            let referenced = SSHCheckup.isKeyReferenced(keyPath: path, configText: cfg, gitSigningKey: gitSigning)
            findings.append(SSHCheckup.unencryptedKeyFinding(name: name, path: path, referenced: referenced))
        }
        if let mode = (try? fm.attributesOfItem(atPath: path))?[.posixPermissions] as? Int,
           SSHCheckup.isPrivateKeyPermissive(mode: mode) {
            findings.append(.init(severity: .high, category: "Key", title: "“\(name)” is readable by other accounts",
                detail: "Mode \(String(mode, radix: 8)). Fix: chmod 600 \(path)", fix: .none))
        }
        if let (type, bits) = sshKeygenTypeBits(path) {
            let t = type.uppercased()
            if t.contains("DSA") || (t.contains("RSA") && (bits ?? 4096) < 3072) {
                findings.append(.init(severity: .medium, category: "Key",
                    title: "“\(name)” is a weak/deprecated key (\(type)\(bits.map { " \($0)" } ?? ""))",
                    detail: "Prefer Ed25519 or a fob Secure Enclave key.", fix: .none))
            }
        }
    }

    let config = (try? String(contentsOf: sshDir.appendingPathComponent("config"), encoding: .utf8)) ?? ""
    findings += SSHCheckup.scanConfig(config)

    let includeCount = GitConfig.parseIncludeEntries(gitIncludeRegexp()).count
    if let f = SSHCheckup.identityFinding(includeCount: includeCount,
                                          useConfigOnly: gitConfigGlobal("user.useConfigOnly") == "true",
                                          defaultEmail: gitConfigGlobal("user.email")) {
        findings.append(f)
    }

    for block in HostSetup.listHostBlocks(in: config) where !block.usesFob {
        findings.append(.init(severity: .opportunity, category: "Opportunity",
            title: "“\(block.alias)” still uses an on-disk key",
            detail: "Migrate it to a fob key:  fob adopt \(block.alias)", fix: .none))
    }
    let gitconfig = (try? String(contentsOf: home.appendingPathComponent(".gitconfig"), encoding: .utf8)) ?? ""
    let signing = GitConfig.parse(gitconfig)
    if (signing.signingKey != nil || signing.format != nil), !signing.usesFob {
        findings.append(.init(severity: .opportunity, category: "Opportunity",
            title: "Commit signing uses a non-fob key",
            detail: "Set up a fob signing key:  fob sign-setup <key>", fix: .none))
    }
    if signing.usesFob {
        let asFile = gitConfigGlobal("gpg.ssh.allowedSignersFile")
        var keyListed = false
        var keyLabel: String?
        if let sk = signing.signingKey {
            let pub = (try? String(contentsOfFile: (sk as NSString).expandingTildeInPath, encoding: .utf8)) ?? ""
            keyLabel = SSHCheckup.AllowedSigners.fobKeyName(fromPubLine: pub)
            if !asFile.isEmpty {
                let asText = (try? String(contentsOfFile: (asFile as NSString).expandingTildeInPath, encoding: .utf8)) ?? ""
                keyListed = SSHCheckup.AllowedSigners.contains(asText, pubLine: pub)
            }
        }
        if let f = SSHCheckup.signingVerificationFinding(
            usesFobSigning: true, allowedSignersConfigured: !asFile.isEmpty,
            keyListed: keyListed, keyLabel: keyLabel) {
            findings.append(f)
        }
    }

    // ssh-agent: on-disk keys loaded there sign without a Touch ID prompt (fob keys excluded).
    let agentBlobs = SSHCheckup.agentKeyBlobs(fromSSHAddL: sshAddListPublicKeys())
    if let f = SSHCheckup.agentLoadedKeysFinding(agentKeyBlobs: agentBlobs, fobKeyBlobs: fobKeyBlobs) {
        findings.append(f)
    }

    // allowed_signers entries fob wrote for keys that no longer exist.
    let signersURL = home.appendingPathComponent(".ssh/allowed_signers")
    let signersText = (try? String(contentsOf: signersURL, encoding: .utf8)) ?? ""
    let orphans = SSHCheckup.AllowedSigners.orphanedFobNames(signersText, liveNames: fobKeyNames)
    if let f = SSHCheckup.allowedSignersOrphanFinding(orphans: orphans) {
        findings.append(f)
    }

    return findings.sorted { $0.severity < $1.severity }
}

/// A single `git config --global <key>` value (trimmed; "" if unset/failure).
func gitConfigGlobal(_ key: String) -> String {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/git")
    process.arguments = ["config", "--global", key]
    let pipe = Pipe(); process.standardOutput = pipe; process.standardError = Pipe()
    guard (try? process.run()) != nil else { return "" }
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    return String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
}

/// Raw output of `git config --global --get-regexp '^includeif\.'` ("" on failure).
func gitIncludeRegexp() -> String {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/git")
    process.arguments = ["config", "--global", "--get-regexp", "^includeif\\."]
    let pipe = Pipe()
    process.standardOutput = pipe
    process.standardError = Pipe()
    guard (try? process.run()) != nil else { return "" }
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    return String(decoding: data, as: UTF8.self)
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

    case "checkup":
        // fob keys' base64 blobs, so the ssh-agent check can exclude them.
        let fobBlobs = Set(((try? store.all()) ?? []).compactMap { key -> String? in
            guard let line = try? SSHFormat.authorizedKeysLine(key.publicKey(), comment: "fob:\(key.name)") else { return nil }
            let parts = line.split(separator: " ")
            return parts.count >= 2 ? String(parts[1]) : nil
        })
        let fobNames = Set(((try? store.all()) ?? []).map(\.name))
        let findings = sshCheckupFindings(fobKeyBlobs: fobBlobs, fobKeyNames: fobNames)
        if findings.isEmpty {
            print("✅ SSH checkup: no issues found — your ~/.ssh looks healthy.")
        } else {
            let high = findings.filter { $0.severity == .high }.count
            let med = findings.filter { $0.severity == .medium }.count
            let low = findings.filter { $0.severity == .low }.count
            let opp = findings.filter { $0.severity == .opportunity }.count
            print("SSH checkup — \(high) high · \(med) medium · \(low) low · \(opp) to improve")
            print("(read-only; fob changed nothing)")
            for f in findings {
                print("")
                print("[\(f.severity.label)] \(f.title)")
                print("  \(f.detail)")
            }
        }

    case "delete":
        var rest = Array(arguments.dropFirst())
        let force = rest.contains("--force") || rest.contains("-y")
        rest.removeAll { $0.hasPrefix("-") }
        guard rest.count == 1, let name = rest.first else {
            fail("usage: fob delete <name> [--force]")
        }
        _ = try store.find(name: name) // 404s cleanly before we prompt
        if !force {
            print("Delete key '\(name)'? The Secure Enclave key is erased permanently and "
                + "cannot be recovered. [y/N]: ", terminator: "")
            let answer = readLine()?.trimmingCharacters(in: .whitespaces).lowercased() ?? ""
            guard answer == "y" || answer == "yes" else { print("Cancelled."); break }
        }
        try store.remove(name: name)
        print("Deleted '\(name)'. Remove its public key from any server/host that still trusts it.")

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
        let signer = try store.ensureSignWrapper()
        print("Enable Touch ID-gated git commit signing with fob key '\(name)'.")
        print("Public key exported to \(pubURL.path).")
        print("")
        print("1. Configure git to sign with this key. Use --global for every repo, or")
        print("   --local (run inside a repo) if you juggle multiple git identities:")
        print("     git config --global gpg.format ssh")
        print("     git config --global user.signingkey \(pubURL.path)")
        print("     git config --global gpg.ssh.program \(signer)")
        print("     git config --global commit.gpgsign true")
        print("     git config --global tag.gpgsign true")
        print("")
        print("   The gpg.ssh.program wrapper routes ONLY git signing to fob's agent, so")
        print("   SSH_AUTH_SOCK is untouched — other ssh agents and `git push` still work.")
        let includes = GitConfig.parseIncludeEntries(gitIncludeRegexp())
        if !includes.isEmpty {
            print("")
            print("   ⚠︎ You have multiple git identities (includeIf) — do NOT use --global; it")
            print("   would sign every account with this key. Write into the matching identity:")
            for inc in includes {
                let path = (inc.path as NSString).expandingTildeInPath
                print("     # \(inc.condition)")
                print("     git config --file \(path) gpg.format ssh")
                print("     git config --file \(path) user.signingkey \(pubURL.path)")
                print("     git config --file \(path) gpg.ssh.program \(signer)")
                print("     git config --file \(path) commit.gpgsign true")
            }
        }
        print("")
        print("2. Register the key on your git host as a SIGNING key (a separate entry from")
        print("   an Authentication key) — e.g. GitHub or GitLab → Settings → SSH keys:")
        print("     \(pubLine)")
        print("")
        print("3. (recommended) restrict this key to git signatures only:")
        print("     fob namespaces \(name) git")
        print("")
        let signEmail = gitConfigGlobal("user.email").trimmingCharacters(in: .whitespacesAndNewlines)
        let signerId = signEmail.isEmpty ? "<your-email>" : signEmail
        print("4. (local verification) so `git verify-commit` and `git log --show-signature`")
        print("   trust it, point git at an allow-list (safe to set globally) …")
        print("     git config --global gpg.ssh.allowedSignersFile ~/.ssh/allowed_signers")
        print("   … and add this key to that file:")
        print("     \(SSHCheckup.AllowedSigners.entry(email: signerId, pubLine: pubLine))")
        print("")
        print("Then `git commit` prompts Touch ID via fob, and your host (GitHub, GitLab,")
        print("Gitea/Forgejo, …) shows \"Verified\". It also verifies locally via allowed_signers.")

    case "rotate":
        // Signing-key rotation (v1): replace a key with a fresh enclave key, keeping its name.
        // Two steps so you can register the new key before the old is retired.
        var rest = Array(arguments.dropFirst())
        let doFinalize = rest.contains("--finalize")
        let requireBiometry = rest.contains("--require-biometry")
        rest.removeAll { $0.hasPrefix("-") }
        guard let name = rest.first, rest.count == 1 else {
            fail("usage: fob rotate <name> [--require-biometry]   then   fob rotate <name> --finalize")
        }
        _ = try store.find(name: name) // 404s cleanly if the key doesn't exist
        let sshDir = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".ssh")
        let signersURL = sshDir.appendingPathComponent("allowed_signers")
        let temp = "\(name).rotating"
        if !doFinalize {
            if (try? store.find(name: temp)) != nil { try store.remove(name: temp) } // clear an abandoned attempt
            let key = try store.create(name: temp, requireBiometry: requireBiometry)
            let pubLine = SSHFormat.authorizedKeysLine(try key.publicKey(), comment: "fob:\(name)")
            print("Rotation prepared for '\(name)'. On your git host, add this NEW key as a")
            print("Signing Key (a separate entry — keep the old one until you finalize):")
            print("     \(pubLine)")
            print("")
            print("Then swap to it with:  fob rotate \(name) --finalize")
        } else {
            guard (try? store.find(name: temp)) != nil else {
                fail("No rotation in progress for '\(name)'. Start one with: fob rotate \(name)")
            }
            let signersText = (try? String(contentsOf: signersURL, encoding: .utf8)) ?? ""
            let email = SSHCheckup.AllowedSigners.principal(signersText, fobKeyName: name)
                ?? gitConfigGlobal("user.email")
            try store.savePolicy(store.policy(name: name), name: temp) // carry pin/reuse/namespaces
            try store.rename(from: name, to: "\(name).retired")        // old aside (recoverable)
            try store.rename(from: temp, to: name)                     // new takes the name
            try store.remove(name: "\(name).retired")                  // destroy the old key
            let key = try store.find(name: name)
            let pubLine = SSHFormat.authorizedKeysLine(try key.publicKey(), comment: "fob:\(name)")
            let pubURL = sshDir.appendingPathComponent("fob_\(name).pub")
            try Data((pubLine + "\n").utf8).write(to: pubURL, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: pubURL.path)
            var text = signersText
            if let pruned = SSHCheckup.AllowedSigners.removing(text, fobKeyName: name) { text = pruned }
            if !email.isEmpty, let updated = SSHCheckup.AllowedSigners.appending(text, email: email, pubLine: pubLine) {
                text = updated
            }
            try? Data(text.utf8).write(to: signersURL, options: .atomic)
            try? FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: signersURL.path)
            print("Rotated '\(name)' to a fresh key (git config unchanged, allowed_signers updated).")
            print("Last step: remove the OLD signing key from your git host — it's now retired.")
        }

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
