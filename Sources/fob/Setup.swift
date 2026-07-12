import FobKit
import Foundation

/// Guided end-to-end setup for one remote host: create (or reuse) an enclave key,
/// export its public key, install it on the server, wire up ~/.ssh/config, verify.
enum Setup {
    /// `fob adopt <alias>` — convert an existing `~/.ssh/config` host to fob. By default it
    /// performs the migration: installs the fob key on the server using your EXISTING key
    /// (passwordless), previews + backs up + rewrites ~/.ssh/config, verifies over Touch ID,
    /// and pins. The old key stays active as a fallback until you `--retire` it. `--dry-run`
    /// prints the plan and changes nothing.
    static func adopt(store: KeyStore, arguments: [String]) throws {
        var rest = arguments
        let requireBiometry = rest.contains("--require-biometry")
        let dryRun = rest.contains("--dry-run")
        let retire = rest.contains("--retire")
        rest.removeAll { $0.hasPrefix("--") }
        guard rest.count == 1, let alias = rest.first, KeyStore.isValidName(alias) else {
            throw AdoptError.usage
        }

        let sshDir = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".ssh")
        let configURL = sshDir.appendingPathComponent("config")
        let configText = (try? String(contentsOf: configURL, encoding: .utf8)) ?? ""
        guard let parsed = HostSetup.parseHostBlock(alias: alias, in: configText) else {
            throw AdoptError.notConfigured(alias)
        }
        let host = parsed.hostName ?? alias
        let user = parsed.user ?? NSUserName()
        let port = parsed.port ?? 22
        let pubURL = sshDir.appendingPathComponent("fob_\(alias).pub")
        let old = parsed.identityFiles.first(where: { !$0.contains("/fob_") })
        let isGitProvider = ["github.com", "gitlab.com", "bitbucket.org", "ssh.github.com"].contains(host.lowercased())

        // `--retire`: just comment out the old IdentityFile (run after a verified migration).
        if retire {
            guard let newConfig = HostSetup.migratedConfig(configText, alias: alias,
                                                           fobPubPath: pubURL.path, socketPath: store.socketPath,
                                                           retireOld: true), newConfig != configText else {
                print("Nothing to retire — no active non-fob IdentityFile in `Host \(alias)`.")
                return
            }
            printDiff(configText, newConfig)
            guard confirm("Comment out the old key in ~/.ssh/config?") else { print("Cancelled."); return }
            let backup = try HostSetup.backupAndWriteConfig(newConfig, at: configURL)
            print("Retired. Backup: \(backup.lastPathComponent)")
            print("Now remove the old key from the server: edit ~/.ssh/authorized_keys on \(host).")
            return
        }

        if parsed.usesFobAgent {
            print("`\(alias)` already routes through fob (its IdentityAgent is ~/.fob/agent.sock).")
            print("Nothing to adopt. Manage its key with: fob pin/reuse/policy \(alias)")
            return
        }

        // Generate/reuse the enclave key and export the public key (safe, local-only).
        let key: StoredKey
        if let existing = try? store.find(name: alias) {
            key = existing
            print("Reusing existing fob key '\(alias)'.")
        } else {
            key = try store.create(name: alias, requireBiometry: requireBiometry)
            print("Created Secure Enclave key '\(alias)' (\(requireBiometry ? "Touch ID only" : "Touch ID, Apple Watch, or password")).")
        }
        let pubLine = SSHFormat.authorizedKeysLine(try key.publicKey(), comment: "fob:\(alias)")
        try Data((pubLine + "\n").utf8).write(to: pubURL, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: pubURL.path)
        print("Public key exported to \(pubURL.path).")

        let newConfig = HostSetup.migratedConfig(configText, alias: alias,
                                                 fobPubPath: pubURL.path, socketPath: store.socketPath)

        if dryRun {
            printDryRun(alias: alias, host: host, user: user, port: port, pubLine: pubLine,
                        pubPath: pubURL.path, socketPath: store.socketPath, old: old,
                        isGitProvider: isGitProvider, newConfig: newConfig, currentConfig: configText)
            return
        }

        // 1. Install the fob key on the server, authenticating with your current key.
        let portArg = port == 22 ? [] : ["-p", String(port)]
        if isGitProvider {
            print("")
            print("\(host) is a git host — add this key to your account (Settings → SSH keys):")
            print("     \(pubLine)")
            print("(then the config change below routes ssh through fob)")
        } else {
            guard hasControllingTerminal() else {
                print("No terminal for ssh-copy-id's prompts — run in a real terminal, or use --dry-run.")
                throw SetupError.copyFailed
            }
            print("")
            print("Installing the fob key on \(alias) using your current key…")
            let status = runInteractive("/usr/bin/ssh-copy-id", ["-f", "-i", pubURL.path] + portArg + [alias])
            guard status == 0 else {
                print("ssh-copy-id failed. Retry: ssh-copy-id -f -i \(pubURL.path) \(portArg.joined(separator: " ")) \(alias)")
                throw SetupError.copyFailed
            }
        }

        // 2. Rewrite ~/.ssh/config (preview + backup + confirm).
        if let newConfig, newConfig != configText {
            print("")
            printDiff(configText, newConfig)
            guard confirm("Apply this change to ~/.ssh/config?") else {
                print("Skipped — copy the lines above into `Host \(alias)` yourself.")
                return
            }
            let backup = try HostSetup.backupAndWriteConfig(newConfig, at: configURL)
            print("Applied. Backup: \(backup.lastPathComponent)")
        } else {
            print("~/.ssh/config already routes \(alias) through fob.")
        }

        // 3. Verify (servers only — a git host needs the key added first).
        if isGitProvider {
            print("")
            print("Test after adding the key to \(host):  ssh -T \(alias)")
        } else if confirm("Test the connection now? (Touch ID will prompt)") {
            let args = ["-o", "ConnectTimeout=10", "-o", "IdentitiesOnly=yes",
                        "-o", "IdentityAgent=\(store.socketPath)", "-i", pubURL.path]
                + portArg + ["\(user)@\(host)", "true"]
            if runInteractive("/usr/bin/ssh", args) == 0 {
                print("✅ fob works for \(alias). Your old key is still a fallback.")
            } else {
                print("Test failed — your old key still works and nothing was removed.")
                return
            }
        }

        // 4. Pin to this host (the connection just populated known_hosts).
        let hostKeys = HostResolver.knownHostKeys(for: host, port: port)
        if hostKeys.isEmpty {
            print("Not in known_hosts yet — pin later with: fob pin \(alias) \(host)")
        } else {
            var policy = store.policy(name: alias)
            policy.pinnedHostKeys.append(contentsOf: hostKeys.filter { !policy.pinnedHostKeys.contains($0) })
            try store.savePolicy(policy, name: alias)
            print("🔒 Pinned \(alias) to \(host) — undo with: fob unpin \(alias)")
        }

        // 5. Offer retire.
        if old != nil {
            print("")
            print("Once you're confident, retire the old key:")
            print("  fob adopt \(alias) --retire      # comment it out of ~/.ssh/config")
            print("  then remove it from the server's ~/.ssh/authorized_keys")
        }
    }

    /// Print the dry-run plan for `adopt` — nothing is executed.
    private static func printDryRun(alias: String, host: String, user: String, port: Int,
                                    pubLine: String, pubPath: String, socketPath: String,
                                    old: String?, isGitProvider: Bool,
                                    newConfig: String?, currentConfig: String) {
        print("")
        print("Dry run for `\(alias)` (\(user)@\(host)\(port == 22 ? "" : ":\(port)")) — nothing was changed.")
        print("Run without --dry-run to perform these steps (they use your EXISTING key):")
        print("")
        if isGitProvider {
            print("1. Add the fob public key to your \(host) account (Settings → SSH keys):")
            print("     \(pubLine)")
        } else {
            let portArg = port == 22 ? "" : " -p \(port)"
            print("1. Install the fob key on the server:")
            print("     ssh-copy-id -f -i \(pubPath)\(portArg) \(alias)")
        }
        print("")
        print("2. Rewrite `Host \(alias)` in ~/.ssh/config:")
        if let newConfig, newConfig != currentConfig {
            printDiff(currentConfig, newConfig)
        } else {
            print("   (already routes through fob)")
        }
        print("")
        print("3. Test:  ssh \(isGitProvider ? "-T " : "")\(alias)\(isGitProvider ? "" : " true")")
        print("4. Pin:   fob pin \(alias) \(host)")
        if old != nil {
            print("5. When confident: fob adopt \(alias) --retire, then remove the old key on the server.")
        }
    }

    /// Print a +/- unified diff of two config texts (only the changed region is interesting,
    /// but showing context keeps it readable).
    private static func printDiff(_ old: String, _ new: String) {
        for line in TextDiff.lines(old: old, new: new) {
            switch line.kind {
            case .added: print("   + \(line.text)")
            case .removed: print("   - \(line.text)")
            case .same: print("     \(line.text)")
            }
        }
    }

    static func run(store: KeyStore, arguments: [String]) throws {
        var rest = arguments
        let requireBiometry = rest.contains("--require-biometry")
        rest.removeAll { $0 == "--require-biometry" }
        let manual = rest.contains("--manual")
        rest.removeAll { $0 == "--manual" }
        let noPin = rest.contains("--no-pin")
        rest.removeAll { $0 == "--no-pin" }
        guard rest.count <= 2, rest.allSatisfy({ !$0.hasPrefix("-") }) else {
            throw SetupError.usage
        }

        // 1. Gather alias / host / user, prompting for whatever wasn't given.
        let alias = try rest.first ?? prompt("Alias for this host (used as key name and `ssh <alias>`)")
        guard KeyStore.isValidName(alias) else {
            throw KeyStoreError.invalidName(alias)
        }
        var user = NSUserName()
        var host: String
        if rest.count == 2 {
            host = rest[1]
        } else {
            host = try prompt("Hostname or IP", default: alias)
        }
        if host.contains("@") {
            let parts = host.split(separator: "@", maxSplits: 1)
            user = String(parts[0])
            host = String(parts[1])
        } else if rest.count < 2 {
            user = try prompt("Username on \(host)", default: user)
        }
        // Leading '-' would let a hostname or username be parsed as an ssh/ssh-copy-id
        // OPTION (e.g. "-oProxyCommand=...") — the classic ssh argument injection.
        guard !host.isEmpty, !host.contains(" "), !host.hasPrefix("-") else {
            throw SetupError.invalidHost(host)
        }
        guard !user.isEmpty, !user.contains(" "), !user.hasPrefix("-") else {
            throw SetupError.invalidUser(user)
        }

        // 2. Create the key, or reuse one that already has this name.
        let key: StoredKey
        if let existing = try? store.find(name: alias) {
            key = existing
            print("Reusing existing key '\(alias)'.")
        } else {
            key = try store.create(name: alias, requireBiometry: requireBiometry)
            print("Created Secure Enclave key '\(alias)' (\(requireBiometry ? "Touch ID only" : "Touch ID, Apple Watch, or password")).")
        }

        // 3. Export the public key where ssh and ssh-copy-id can see it.
        let sshDir = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".ssh")
        try FileManager.default.createDirectory(
            at: sshDir,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        let pubURL = sshDir.appendingPathComponent("fob_\(alias).pub")
        let pubLine = SSHFormat.authorizedKeysLine(try key.publicKey(), comment: "fob:\(alias)")
        try Data((pubLine + "\n").utf8).write(to: pubURL, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: pubURL.path)
        print("Public key exported to \(pubURL.path).")

        let destination = "\(user)@\(host)"
        let configBlock = HostSetup.configBlock(
            alias: alias, host: host, user: user,
            pubPath: pubURL.path, socketPath: store.socketPath)

        // --manual: stop here and print the remaining steps for the user to run
        // themselves. Nothing below this point is executed.
        if manual {
            print("")
            print("Manual mode — nothing else will be executed. Remaining steps:")
            print("")
            print("1. Install the public key on the server (asks for your password):")
            print("")
            print("     ssh-copy-id -f -i \(pubURL.path) \(destination)")
            print("")
            print("2. Add this to ~/.ssh/config:")
            print("")
            print(configBlock.split(separator: "\n").map { "     \($0)" }.joined(separator: "\n"))
            print("")
            var step = 3
            if !agentResponding(socketPath: store.socketPath) {
                print("\(step). Start the agent (it is not running) — open fob.app and turn on")
                print("   \"Launch at Login\" (run `fob install` for details):")
                print("")
                print("     open ~/Applications/fob.app")
                print("")
                step += 1
            }
            print("\(step). Test (Touch ID prompt will appear):")
            print("")
            print("     ssh \(alias) true")
            print("")
            print("\(step + 1). (recommended) Pin the key so it only works for this host:")
            print("")
            print("     fob pin \(alias) \(host)")
            return
        }

        // 4. The agent (fob.app) must be running before the verify step needs it.
        //    We can't launch it for the user here, so warn and continue — ssh-copy-id
        //    below uses password auth and doesn't need the agent.
        if !agentResponding(socketPath: store.socketPath) {
            print("Note: the fob agent isn't running. Open fob.app (menu bar) and enable")
            print("\"Launch at Login\" before the test step — see `fob install`. Continuing…")
        }

        // 5. Install the public key on the server. ssh-copy-id runs interactively so
        //    the user can answer the password / host-key prompts itself.
        print("")
        // ssh prompts for passwords on /dev/tty; without one it waits forever, invisibly.
        if !hasControllingTerminal() {
            print("No terminal available for ssh's password prompt — run this in a real")
            print("terminal (Terminal.app, iTerm, a cmux pane), or re-run with --manual")
            print("to get the commands to run yourself.")
            throw SetupError.copyFailed
        }
        print("Installing the key on \(destination) — you may be asked for your password.")
        let copyStatus = runInteractive("/usr/bin/ssh-copy-id", ["-f", "-i", pubURL.path, destination])
        guard copyStatus == 0 else {
            print("")
            print("ssh-copy-id failed. You can retry manually with:")
            print("  ssh-copy-id -f -i \(pubURL.path) \(destination)")
            throw SetupError.copyFailed
        }

        // 6. Offer the ~/.ssh/config block.
        let configURL = sshDir.appendingPathComponent("config")
        let existingConfig = (try? String(contentsOf: configURL, encoding: .utf8)) ?? ""
        var aliasConfigured = false
        if HostSetup.hostBlockExists(alias: alias, in: existingConfig) {
            print("")
            print("~/.ssh/config already has a `Host \(alias)` entry — leaving it untouched.")
            print("Make sure it contains:")
            print(configBlock)
            aliasConfigured = true // assume the user's existing block is intentional
        } else {
            print("")
            print(configBlock)
            if confirm("Add this entry to ~/.ssh/config?") {
                let separator = existingConfig.isEmpty || existingConfig.hasSuffix("\n\n")
                    ? "" : (existingConfig.hasSuffix("\n") ? "\n" : "\n\n")
                try Data((existingConfig + separator + configBlock + "\n").utf8)
                    .write(to: configURL, options: .atomic)
                try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: configURL.path)
                print("Added. You can now connect with: ssh \(alias)")
                aliasConfigured = true
            } else {
                print("Not added — copy the block above into ~/.ssh/config yourself.")
            }
        }

        // 7. Verify with a real connection (this is the Touch ID moment).
        guard confirm("Test the connection now? (Touch ID prompt will appear)") else {
            print("Done. Test later with: ssh \(aliasConfigured ? alias : destination)")
            return
        }
        let sshArgs = aliasConfigured
            ? ["-o", "ConnectTimeout=10", alias, "true"]
            : ["-o", "ConnectTimeout=10",
               "-o", "IdentityAgent=\(store.socketPath)",
               "-o", "IdentitiesOnly=yes",
               "-i", pubURL.path, destination, "true"]
        if runInteractive("/usr/bin/ssh", sshArgs) == 0 {
            print("")
            print("✅ \(destination) accepted the Secure Enclave key. You're all set\(aliasConfigured ? ": ssh \(alias)" : ".")")
        } else {
            throw SetupError.verifyFailed(destination)
        }

        // 8. Pin the key to this host: the connection just proved which host key it
        //    has (and put it in known_hosts), so record that this key is for it only.
        guard !noPin else { return }
        let hostKeys = HostResolver.knownHostKeys(for: host)
        if hostKeys.isEmpty {
            print("Could not find \(host) in ~/.ssh/known_hosts — key not pinned.")
            print("Pin it later with: fob pin \(alias) \(host)")
            return
        }
        var policy = store.policy(name: alias)
        policy.pinnedHostKeys.append(contentsOf: hostKeys.filter { !policy.pinnedHostKeys.contains($0) })
        try store.savePolicy(policy, name: alias)
        print("🔒 Key '\(alias)' pinned to \(host): the agent will refuse it for any other")
        print("destination. Undo with: fob unpin \(alias)")
    }

    // MARK: - Console helpers

    private static func prompt(_ question: String, default defaultValue: String? = nil) throws -> String {
        let suffix = defaultValue.map { " [\($0)]" } ?? ""
        print("\(question)\(suffix): ", terminator: "")
        fflush(stdout)
        guard let line = readLine() else { throw SetupError.notInteractive }
        let answer = line.trimmingCharacters(in: .whitespaces)
        if answer.isEmpty {
            if let defaultValue { return defaultValue }
            return try prompt(question)
        }
        return answer
    }

    private static func confirm(_ question: String) -> Bool {
        print("\(question) [Y/n]: ", terminator: "")
        fflush(stdout)
        guard let line = readLine() else { return false }
        let answer = line.trimmingCharacters(in: .whitespaces).lowercased()
        return answer.isEmpty || answer == "y" || answer == "yes"
    }

    // MARK: - Subprocesses

    /// Spawn a subprocess that stays in OUR process group. Foundation's Process puts
    /// children in a new group, so when ssh reads the password from /dev/tty the
    /// terminal suspends it (SIGTTIN) and the prompt never appears.
    ///
    /// `executable` is an ABSOLUTE path, run directly — no `/usr/bin/env` / PATH lookup,
    /// so a hijacked PATH can't substitute a malicious `ssh`.
    private static func runInteractive(_ executable: String, _ arguments: [String]) -> Int32 {
        fflush(stdout) // keep our output ordered ahead of the subprocess's
        var argv: [UnsafeMutablePointer<CChar>?] = ([executable] + arguments)
            .map { strdup($0) }
        argv.append(nil)
        defer { argv.forEach { free($0) } }

        var pid: pid_t = 0
        guard posix_spawn(&pid, executable, nil, nil, &argv, environ) == 0 else {
            return -1
        }
        var status: Int32 = 0
        while waitpid(pid, &status, 0) == -1 && errno == EINTR {}
        if (status & 0x7f) == 0 { return (status >> 8) & 0xff } // WEXITSTATUS
        return 128 + (status & 0x7f)                            // killed by signal
    }

    // MARK: - Checks

    /// True if /dev/tty is usable — i.e. ssh will be able to show its password prompt.
    private static func hasControllingTerminal() -> Bool {
        let fd = open("/dev/tty", O_RDWR)
        guard fd >= 0 else { return false }
        close(fd)
        return true
    }

    /// True if something accepts connections on the agent socket (a stale socket file doesn't).
    private static func agentResponding(socketPath: String) -> Bool {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return false }
        defer { close(fd) }
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let maxPath = MemoryLayout.size(ofValue: addr.sun_path) - 1
        let pathBytes = Array(socketPath.utf8)
        guard pathBytes.count <= maxPath else { return false }
        withUnsafeMutableBytes(of: &addr.sun_path) { $0.copyBytes(from: pathBytes) }
        return withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        } == 0
    }

}

enum SetupError: LocalizedError {
    case usage
    case invalidHost(String)
    case invalidUser(String)
    case notInteractive
    case copyFailed
    case verifyFailed(String)

    var errorDescription: String? {
        switch self {
        case .usage:
            return "usage: fob setup [<alias>] [[user@]host] [--require-biometry] [--manual]"
        case .invalidHost(let host):
            return "invalid hostname '\(host)'"
        case .invalidUser(let user):
            return "invalid username '\(user)'"
        case .notInteractive:
            return "setup needs an interactive terminal (or pass <alias> and [user@]host as arguments)"
        case .copyFailed:
            return "could not install the public key on the server"
        case .verifyFailed(let destination):
            return "test connection to \(destination) failed — check the server's authorized_keys and sshd config"
        }
    }
}

enum AdoptError: LocalizedError {
    case usage
    case notConfigured(String)

    var errorDescription: String? {
        switch self {
        case .usage:
            return "usage: fob adopt <alias> [--dry-run] [--retire] [--require-biometry]"
        case .notConfigured(let alias):
            return "no `Host \(alias)` entry in ~/.ssh/config — for a brand-new host use: fob setup \(alias)"
        }
    }
}
