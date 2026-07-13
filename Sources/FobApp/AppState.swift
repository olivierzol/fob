import AppKit
import Combine
import FobKit
import Foundation
import ServiceManagement

/// A key as the UI needs it: name plus its resolved pinning / reuse policy.
struct KeyInfo: Identifiable {
    let name: String
    let pinnedNames: [String] // resolved destination names; empty == any destination
    let reuseSeconds: Int     // 0 == touch every time
    var id: String { name }
    var isPinned: Bool { !pinnedNames.isEmpty }
}

/// The app's single source of truth: owns the in-process agent, mirrors its live
/// events into a feed for the UI, and exposes key-management actions that write the
/// same `~/.fob` files the CLI reads.
@MainActor
final class AppState: ObservableObject {
    @Published private(set) var status: String = "starting…"
    @Published private(set) var listening = false
    @Published private(set) var keys: [KeyInfo] = []
    @Published private(set) var feed: [AgentEvent] = []
    @Published private(set) var launchAtLogin = false
    /// Non-nil when the agent could not start (e.g. another agent holds the lock).
    @Published private(set) var fatalError: String?
    /// Transient error from the most recent key action, shown then cleared.
    @Published var actionError: String?
    /// The key the "Commit signing" window is set up for (set before opening it).
    @Published var signingSetupKey: String?
    /// Optional git host the signing window was opened for (from the git-host migrate
    /// flow), so it can deep-link to that provider's SSH-keys page. nil = generic entry.
    @Published var signingSetupHost: String?
    /// The alias the "Migrate a server" window is set up for (set before opening it).
    @Published var migrateAlias: String?

    private let store: KeyStore?
    private var agent: Agent?
    private static let feedLimit = 40

    var socketPath: String { store?.socketPath ?? "~/.fob/agent.sock" }

    init() {
        store = try? KeyStore.default()
        if store == nil {
            fatalError = "could not open ~/.fob"
            status = "error"
        }
        Notifications.requestAuthorization()
        refreshKeys()
        refreshLoginItem()
        startAgent()
    }

    // MARK: - Agent lifecycle

    private func startAgent() {
        guard let store else { return }
        let agent = Agent(store: store)
        agent.onEvent = { [weak self] event in
            DispatchQueue.main.async { self?.handle(event) }
        }
        agent.notify = { message in
            Notifications.post(message) // called off the main thread; Notifications is thread-safe
        }
        self.agent = agent
        Thread.detachNewThread { [weak self] in
            do {
                try agent.run() // never returns on success
            } catch {
                let message = error.localizedDescription
                DispatchQueue.main.async {
                    self?.fatalError = message
                    self?.status = "not running"
                }
            }
        }
    }

    private func handle(_ event: AgentEvent) {
        if event.kind == .listening {
            listening = true
            status = "listening"
            return
        }
        feed.insert(event, at: 0)
        if feed.count > Self.feedLimit { feed.removeLast(feed.count - Self.feedLimit) }
        // Pin/reuse never change under a sign event, so no key refresh is needed here.
    }

    // MARK: - Keys

    func refreshKeys() {
        guard let store else { keys = []; return }
        let all = (try? store.all()) ?? []
        keys = all.map { key in
            let policy = store.policy(name: key.name)
            let names = policy.pinnedHostKeys.map {
                HostResolver.name(forHostKeyBlob: $0) ?? "unknown host key"
            }
            return KeyInfo(name: key.name,
                           pinnedNames: Array(Set(names)).sorted(),
                           reuseSeconds: Int(policy.reuseSeconds ?? 0))
        }
    }

    /// The most recently generated key's public line, so the panel can show a copyable
    /// key + "what next" instead of leaving a freshly generated key as a dead end.
    struct GeneratedKey: Equatable { let name: String; let pubLine: String }
    @Published var lastGenerated: GeneratedKey?

    func generate(name: String, requireBiometry: Bool) {
        guard let store else { actionError = "store unavailable"; return }
        do {
            let key = try store.create(name: name, requireBiometry: requireBiometry)
            lastGenerated = GeneratedKey(
                name: name,
                pubLine: SSHFormat.authorizedKeysLine(try key.publicKey(), comment: "fob:\(name)"))
            actionError = nil
        } catch {
            actionError = error.localizedDescription
        }
        refreshKeys()
    }

    func delete(name: String) {
        run { store in try store.remove(name: name) }
    }

    /// Confirm-then-delete via an AppKit alert. A SwiftUI `confirmationDialog` fired
    /// from a `Menu` inside the `MenuBarExtra` panel never appears — presenting it
    /// makes the panel resign key and dismiss, canceling the dialog with it. An
    /// `NSAlert` runs its own modal that doesn't depend on the panel staying open.
    func requestDelete(name: String) {
        // Defer so the menu finishes dismissing before the modal opens.
        DispatchQueue.main.async {
            let alert = NSAlert()
            alert.messageText = "Delete key “\(name)”?"
            alert.informativeText =
                "The Secure Enclave key is erased permanently and cannot be recovered."
            alert.alertStyle = .critical
            alert.addButton(withTitle: "Delete")
            alert.addButton(withTitle: "Cancel")
            NSApp.activate(ignoringOtherApps: true)
            if alert.runModal() == .alertFirstButtonReturn {
                self.delete(name: name)
            }
        }
    }

    // MARK: - Host onboarding (the "Set up a host" window)

    struct HostSetupResult {
        let alias: String
        let user: String
        let host: String
        let port: Int
        let pubPath: String
        let copyCommand: String   // ssh-copy-id line to run on the server
        let configAdded: Bool     // did we add a ~/.ssh/config block?
        let alreadyConfigured: Bool
        let hostKnown: Bool       // host already in known_hosts → can pin now
        var destination: String { "\(user)@\(host)" }
    }

    enum HostSetupOutcome {
        case success(HostSetupResult)
        case failure(String)
    }

    /// Creates (or reuses) the key, exports its public key, and writes a `~/.ssh/config`
    /// block — everything except the one step that needs your server password
    /// (`ssh-copy-id`) and the interactive first connection, which you do yourself.
    func addHost(alias rawAlias: String, host rawHost: String, user rawUser: String,
                 port: Int, requireBiometry: Bool) -> HostSetupOutcome {
        let alias = rawAlias.trimmingCharacters(in: .whitespaces)
        let host = rawHost.trimmingCharacters(in: .whitespaces)
        let user = rawUser.trimmingCharacters(in: .whitespaces)
        guard KeyStore.isValidName(alias) else {
            return .failure("Invalid alias — use letters, digits, '.', '_', '-' (not starting with '-').")
        }
        guard HostSetup.isValidHostToken(host) else { return .failure("Invalid hostname.") }
        guard HostSetup.isValidHostToken(user) else { return .failure("Invalid username.") }
        guard (1...65535).contains(port) else { return .failure("Port must be 1–65535.") }
        guard let store else { return .failure("Key store unavailable.") }
        do {
            let key: StoredKey
            if let existing = try? store.find(name: alias) {
                key = existing
            } else {
                key = try store.create(name: alias, requireBiometry: requireBiometry)
            }

            let sshDir = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".ssh")
            try FileManager.default.createDirectory(at: sshDir, withIntermediateDirectories: true,
                                                    attributes: [.posixPermissions: 0o700])
            let pubURL = sshDir.appendingPathComponent("fob_\(alias).pub")
            let pubLine = SSHFormat.authorizedKeysLine(try key.publicKey(), comment: "fob:\(alias)")
            try Data((pubLine + "\n").utf8).write(to: pubURL, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: pubURL.path)

            let configURL = sshDir.appendingPathComponent("config")
            let existing = (try? String(contentsOf: configURL, encoding: .utf8)) ?? ""
            let already = HostSetup.hostBlockExists(alias: alias, in: existing)
            var configAdded = false
            if !already {
                let block = HostSetup.configBlock(alias: alias, host: host, user: user, port: port,
                                                  pubPath: pubURL.path, socketPath: store.socketPath)
                let separator = existing.isEmpty ? "" : (existing.hasSuffix("\n") ? "\n" : "\n\n")
                try Data((existing + separator + block + "\n").utf8).write(to: configURL, options: .atomic)
                try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: configURL.path)
                configAdded = true
            }
            refreshKeys()
            var copy = ["ssh-copy-id", "-f", "-i", pubURL.path]
            if port != 22 { copy += ["-p", String(port)] }
            copy.append("\(user)@\(host)")
            return .success(HostSetupResult(
                alias: alias, user: user, host: host, port: port, pubPath: pubURL.path,
                copyCommand: copy.joined(separator: " "),
                configAdded: configAdded, alreadyConfigured: already,
                hostKnown: !HostResolver.knownHostKeys(for: host, port: port).isEmpty))
        } catch {
            return .failure(error.localizedDescription)
        }
    }

    /// Pin a key to its host after the first connection has populated known_hosts.
    /// Returns nil on success, or an error message.
    func pinHost(alias: String, host: String, port: Int) -> String? {
        guard let store else { return "Key store unavailable." }
        let hostKeys = HostResolver.knownHostKeys(for: host, port: port)
        guard !hostKeys.isEmpty else {
            return "“\(host)” isn't in ~/.ssh/known_hosts yet — connect once (ssh \(alias)) first, then pin."
        }
        do {
            var policy = store.policy(name: alias)
            policy.pinnedHostKeys.append(contentsOf: hostKeys.filter { !policy.pinnedHostKeys.contains($0) })
            try store.savePolicy(policy, name: alias)
            refreshKeys()
            return nil
        } catch {
            return error.localizedDescription
        }
    }

    // MARK: - Server migration (the "Migrate" windows)

    /// An existing `~/.ssh/config` server, as a migration candidate.
    struct MigrationCandidate: Identifiable {
        let alias: String
        let host: String
        let user: String
        let port: Int
        let usesFob: Bool
        let oldIdentityFiles: [String]
        let isGitHost: Bool
        let provider: HostSetup.GitProvider
        let settingsURL: URL?
        var id: String { alias }
        var destination: String { port == 22 ? "\(user)@\(host)" : "\(user)@\(host):\(port)" }
    }

    enum GitKeyResult { case ok(pubLine: String); case error(String) }

    enum InstallOutcome {
        case installed        // fob key appended to the server's authorized_keys
        case alreadyPresent   // it was already there
        // headless install couldn't run — do it in a terminal. `detail` is the sanitized
        // ssh output (why it failed), empty if there was none.
        case needsManual(command: String, detail: String)
        case failed(String)   // a real error (bad alias / key store)
    }

    /// Result of a ~/.ssh/config write: the backup filename on success, else a message.
    enum ConfigWriteResult {
        case ok(backup: String)
        case error(String)
    }

    private var sshConfigURL: URL {
        FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".ssh/config")
    }
    private func fobPubURL(_ alias: String) -> URL {
        FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".ssh/fob_\(alias).pub")
    }

    /// Every literal `Host` block in ~/.ssh/config, as migration candidates.
    func discoverServers() -> [MigrationCandidate] {
        let text = (try? String(contentsOf: sshConfigURL, encoding: .utf8)) ?? ""
        return HostSetup.listHostBlocks(in: text).map { block in
            let host = block.parsed.hostName ?? block.alias
            let declaredUser = block.parsed.user
            let isGit = HostSetup.isGitHost(hostName: host, user: declaredUser)
            // Git hosts log in as `git`; only fall back to the local username for servers.
            let user = declaredUser ?? (isGit ? "git" : NSUserName())
            return MigrationCandidate(
                alias: block.alias,
                host: host,
                user: user,
                port: block.parsed.port ?? 22,
                usesFob: block.usesFob,
                oldIdentityFiles: block.parsed.identityFiles.filter { !$0.contains("/fob_") },
                isGitHost: isGit,
                provider: isGit ? HostSetup.gitProvider(forHost: host) : .other,
                settingsURL: isGit ? HostSetup.sshKeySettingsURL(forHost: host) : nil)
        }
    }

    /// The candidate for a single alias (re-read fresh from config).
    func migrationCandidate(alias: String) -> MigrationCandidate? {
        discoverServers().first { $0.alias == alias }
    }

    /// Whether git commit signing is already configured (informational in the migrate view).
    func gitSigningInfo() -> GitConfig.SigningInfo {
        let url = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".gitconfig")
        return GitConfig.parse((try? String(contentsOf: url, encoding: .utf8)) ?? "")
    }

    /// Create (or reuse) the fob key, export its public key, and install it on the server
    /// using the host's CURRENT key (headless, passwordless). Runs BEFORE the config is
    /// rewritten, so `ssh <alias>` still authenticates with the old key. `.failure` is a
    /// real error (bad alias / key store); an unreachable/passphrase-locked host resolves
    /// to `.success(.needsManual)` with a copy-paste fallback.
    func createAndInstall(_ c: MigrationCandidate, requireBiometry: Bool) async -> InstallOutcome {
        guard let store else { return .failed("Key store unavailable.") }
        guard KeyStore.isValidName(c.alias) else { return .failed("Invalid alias “\(c.alias)”.") }
        let pubLine: String
        do {
            let key: StoredKey
            if let existing = try? store.find(name: c.alias) { key = existing }
            else { key = try store.create(name: c.alias, requireBiometry: requireBiometry) }
            pubLine = SSHFormat.authorizedKeysLine(try key.publicKey(), comment: "fob:\(c.alias)")
            let pubURL = fobPubURL(c.alias)
            try FileManager.default.createDirectory(at: pubURL.deletingLastPathComponent(),
                                                    withIntermediateDirectories: true,
                                                    attributes: [.posixPermissions: 0o700])
            try Data((pubLine + "\n").utf8).write(to: pubURL, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: pubURL.path)
            refreshKeys()
        } catch {
            return .failed(error.localizedDescription)
        }
        let fallback = HostSetup.fallbackCopyCommand(alias: c.alias, fobPubPath: fobPubURL(c.alias).path, port: c.port)
        guard let args = HostSetup.installArguments(alias: c.alias) else {
            return .needsManual(command: fallback, detail: "")
        }
        let (status, output) = await runProcess("/usr/bin/ssh", args, stdin: pubLine + "\n")
        if status == 0 && output.contains("fob-installed") { return .installed }
        if status == 0 && output.contains("fob-present") { return .alreadyPresent }
        return .needsManual(command: fallback, detail: HostSetup.sanitizeForDisplay(output))
    }

    /// The `old → new` ~/.ssh/config text for the diff preview, or nil if there's no
    /// literal block (or it's already fully migrated).
    func configDiff(alias: String) -> (old: String, new: String)? {
        guard let store else { return nil }
        let old = (try? String(contentsOf: sshConfigURL, encoding: .utf8)) ?? ""
        guard let new = HostSetup.migratedConfig(old, alias: alias,
                                                 fobPubPath: fobPubURL(alias).path,
                                                 socketPath: store.socketPath),
              new != old else { return nil }
        return (old, new)
    }

    /// Back up ~/.ssh/config and write the migrated version. Returns the backup filename
    /// on success (for undo guidance), or an error message.
    func applyConfigMigration(alias: String) -> ConfigWriteResult {
        guard let store else { return .error("Key store unavailable.") }
        let old = (try? String(contentsOf: sshConfigURL, encoding: .utf8)) ?? ""
        guard let new = HostSetup.migratedConfig(old, alias: alias,
                                                 fobPubPath: fobPubURL(alias).path,
                                                 socketPath: store.socketPath) else {
            return .error("No “Host \(alias)” block found in ~/.ssh/config.")
        }
        do {
            let backup = try HostSetup.backupAndWriteConfig(new, at: sshConfigURL)
            return .ok(backup: backup.lastPathComponent)
        } catch {
            return .error(error.localizedDescription)
        }
    }

    /// Prove fob works for this host by connecting with ONLY the fob identity (not the
    /// old-key fallback), so a green check means fob specifically succeeded. Touch ID
    /// prompts. Returns nil on success, else an error message.
    func verifyMigration(_ c: MigrationCandidate) async -> String? {
        guard let store else { return "Key store unavailable." }
        var args = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
                    "-o", "StrictHostKeyChecking=accept-new",
                    "-o", "IdentitiesOnly=yes",
                    "-o", "IdentityAgent=\(store.socketPath)",
                    "-i", fobPubURL(c.alias).path]
        if c.port != 22 { args += ["-p", String(c.port)] }
        args += ["\(c.user)@\(c.host)", "true"]
        let (status, output) = await runProcess("/usr/bin/ssh", args)
        guard status == 0 else {
            let tail = output.trimmingCharacters(in: .whitespacesAndNewlines)
            return "Test connection failed — your existing key still works, nothing was removed."
                + (tail.isEmpty ? "" : "\n\(tail)")
        }
        return nil
    }

    /// Greenfield git host: create the fob key and write a NEW `Host <alias>` block routed
    /// through fob (User git). Returns nil on success or an error message. The caller then
    /// runs the same add-to-account → verify flow as an existing git host.
    func addGitHost(alias rawAlias: String, hostName: String, requireBiometry: Bool) -> String? {
        let alias = rawAlias.trimmingCharacters(in: .whitespaces)
        guard KeyStore.isValidName(alias) else {
            return "Invalid alias — letters, digits, '.', '_', '-' (not starting with '-')."
        }
        guard HostSetup.isValidHostToken(hostName) else { return "Invalid host name." }
        guard let store else { return "Key store unavailable." }
        do {
            if (try? store.find(name: alias)) == nil {
                _ = try store.create(name: alias, requireBiometry: requireBiometry)
            }
            let pubURL = fobPubURL(alias)
            let key = try store.find(name: alias)
            let pubLine = SSHFormat.authorizedKeysLine(try key.publicKey(), comment: "fob:\(alias)")
            try FileManager.default.createDirectory(at: pubURL.deletingLastPathComponent(),
                                                    withIntermediateDirectories: true,
                                                    attributes: [.posixPermissions: 0o700])
            try Data((pubLine + "\n").utf8).write(to: pubURL, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: pubURL.path)

            let existing = (try? String(contentsOf: sshConfigURL, encoding: .utf8)) ?? ""
            if !HostSetup.hostBlockExists(alias: alias, in: existing) {
                let block = HostSetup.configBlock(alias: alias, host: hostName, user: "git",
                                                  pubPath: pubURL.path, socketPath: store.socketPath)
                let separator = existing.isEmpty ? "" : (existing.hasSuffix("\n") ? "\n" : "\n\n")
                try Data((existing + separator + block + "\n").utf8).write(to: sshConfigURL, options: .atomic)
                try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: sshConfigURL.path)
            }
            refreshKeys()
            return nil
        } catch {
            return error.localizedDescription
        }
    }

    /// Git hosts have no shell — the key is added on the web, not via ssh-copy-id. Create/
    /// reuse the fob key and export its public line to paste into the account's SSH keys.
    func prepareGitKey(_ c: MigrationCandidate, requireBiometry: Bool) -> GitKeyResult {
        guard let store else { return .error("Key store unavailable.") }
        guard KeyStore.isValidName(c.alias) else { return .error("Invalid alias “\(c.alias)”.") }
        do {
            let key: StoredKey
            if let existing = try? store.find(name: c.alias) { key = existing }
            else { key = try store.create(name: c.alias, requireBiometry: requireBiometry) }
            let pubLine = SSHFormat.authorizedKeysLine(try key.publicKey(), comment: "fob:\(c.alias)")
            let pubURL = fobPubURL(c.alias)
            try FileManager.default.createDirectory(at: pubURL.deletingLastPathComponent(),
                                                    withIntermediateDirectories: true,
                                                    attributes: [.posixPermissions: 0o700])
            try Data((pubLine + "\n").utf8).write(to: pubURL, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: pubURL.path)
            refreshKeys()
            return .ok(pubLine: pubLine)
        } catch {
            return .error(error.localizedDescription)
        }
    }

    /// Prove the fob key works on a git host with `ssh -T` (no remote command). Success is
    /// read from the greeting, not the exit code (`ssh -T git@github.com` exits non-zero
    /// even when it works). Connects with ONLY the fob identity so a pass means fob.
    func verifyGitHost(_ c: MigrationCandidate) async -> (ok: Bool, message: String) {
        guard let store else { return (false, "Key store unavailable.") }
        var args = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
                    "-o", "StrictHostKeyChecking=accept-new",
                    "-o", "IdentitiesOnly=yes",
                    "-o", "IdentityAgent=\(store.socketPath)",
                    "-i", fobPubURL(c.alias).path, "-T"]
        if c.port != 22 { args += ["-p", String(c.port)] }
        args += ["\(c.user)@\(c.host)"]
        let (_, output) = await runProcess("/usr/bin/ssh", args)
        let greeting = HostSetup.parseSSHGreeting(output)
        if greeting.authenticated {
            let who = greeting.user.map { " as “\($0)”" } ?? ""
            return (true, "Authenticated\(who) with fob — Touch ID now gates \(c.host).")
        }
        let tail = HostSetup.sanitizeForDisplay(output)
        if output.lowercased().contains("permission denied") {
            return (false, "Not authenticated yet — add this key to \(c.provider.displayName) as an Authentication Key first."
                + (tail.isEmpty ? "" : "\n\(tail)"))
        }
        return (false, "Couldn't verify." + (tail.isEmpty ? "" : "\n\(tail)"))
    }

    /// Open a URL (the provider's SSH-keys settings page) in the default browser.
    func openSettings(_ url: URL) {
        NSWorkspace.shared.open(url)
    }

    /// Comment out the old `IdentityFile` in the block (the explicit, optional retire step),
    /// after the user has confirmed fob works. Returns the backup filename or an error.
    func retireOldKey(alias: String) -> ConfigWriteResult {
        guard let store else { return .error("Key store unavailable.") }
        let old = (try? String(contentsOf: sshConfigURL, encoding: .utf8)) ?? ""
        guard let new = HostSetup.migratedConfig(old, alias: alias,
                                                 fobPubPath: fobPubURL(alias).path,
                                                 socketPath: store.socketPath, retireOld: true) else {
            return .error("No “Host \(alias)” block found in ~/.ssh/config.")
        }
        do {
            let backup = try HostSetup.backupAndWriteConfig(new, at: sshConfigURL)
            return .ok(backup: backup.lastPathComponent)
        } catch {
            return .error(error.localizedDescription)
        }
    }

    /// Run a subprocess off the main actor, feeding `stdin` if given, capturing merged
    /// stdout+stderr. `/usr/bin/ssh` bounds itself via BatchMode + ConnectTimeout.
    private func runProcess(_ launchPath: String, _ args: [String], stdin: String? = nil) async -> (status: Int32, output: String) {
        await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                let process = Process()
                process.executableURL = URL(fileURLWithPath: launchPath)
                process.arguments = args
                let outPipe = Pipe()
                process.standardOutput = outPipe
                process.standardError = outPipe
                var inPipe: Pipe?
                if stdin != nil { let p = Pipe(); process.standardInput = p; inPipe = p }
                do {
                    try process.run()
                    if let stdin, let inPipe {
                        inPipe.fileHandleForWriting.write(Data(stdin.utf8))
                        try? inPipe.fileHandleForWriting.close()
                    }
                    let data = outPipe.fileHandleForReading.readDataToEndOfFile()
                    process.waitUntilExit()
                    continuation.resume(returning: (process.terminationStatus, String(decoding: data, as: UTF8.self)))
                } catch {
                    continuation.resume(returning: (-1, error.localizedDescription))
                }
            }
        }
    }

    // MARK: - Commit signing (the "Commit signing" window)

    struct SigningInfo {
        let name: String
        let pubLine: String            // add to the git host as a Signing Key
        let pubPath: String
        let signerProgram: String      // ~/.fob/bin/fob-sign (git's gpg.ssh.program)
        let gitOnly: Bool              // policy currently restricts signing to "git"

        /// The git config commands for a scope ("--global" or "--local"). The view
        /// builds these so it can switch scope without re-reading the key. Uses a
        /// `gpg.ssh.program` wrapper so only git signing reaches fob — SSH_AUTH_SOCK
        /// (and any other ssh agent the user runs) is left completely alone.
        func gitConfigCommands(global: Bool) -> [String] {
            let scope = global ? "--global" : "--local"
            return [
                "git config \(scope) gpg.format ssh",
                "git config \(scope) user.signingkey \(pubPath)",
                "git config \(scope) gpg.ssh.program \(signerProgram)",
                "git config \(scope) commit.gpgsign true",
                "git config \(scope) tag.gpgsign true",
            ]
        }
    }

    /// Exports the key's public key and gathers everything the signing window shows.
    /// Returns nil if the key or store is unavailable.
    func signingInfo(for name: String) -> SigningInfo? {
        guard let store, let key = try? store.find(name: name) else { return nil }
        let sshDir = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".ssh")
        try? FileManager.default.createDirectory(at: sshDir, withIntermediateDirectories: true,
                                                 attributes: [.posixPermissions: 0o700])
        let pubURL = sshDir.appendingPathComponent("fob_\(name).pub")
        guard let pubLine = try? SSHFormat.authorizedKeysLine(key.publicKey(), comment: "fob:\(name)") else {
            return nil
        }
        try? Data((pubLine + "\n").utf8).write(to: pubURL, options: .atomic)
        try? FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: pubURL.path)
        let signer = (try? store.ensureSignWrapper()) ?? store.signWrapperPath
        return SigningInfo(
            name: name, pubLine: pubLine, pubPath: pubURL.path,
            signerProgram: signer,
            gitOnly: store.policy(name: name).allowedNamespaces == ["git"])
    }

    /// Restrict a key to git-commit signatures only (["git"]), or clear the restriction.
    func setGitSigningOnly(_ on: Bool, name: String) {
        run { store in
            var policy = store.policy(name: name)
            policy.allowedNamespaces = on ? ["git"] : nil
            try store.savePolicy(policy, name: name)
        }
    }

    /// Run the `git config --global` signing setup for the user. nil = success.
    func configureGitSigning(pubPath: String, signerProgram: String) -> String? {
        for args in [["config", "--global", "gpg.format", "ssh"],
                     ["config", "--global", "user.signingkey", pubPath],
                     ["config", "--global", "gpg.ssh.program", signerProgram],
                     ["config", "--global", "commit.gpgsign", "true"],
                     ["config", "--global", "tag.gpgsign", "true"]] {
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/git")
            process.arguments = args
            do {
                try process.run(); process.waitUntilExit()
                guard process.terminationStatus == 0 else { return "`git \(args.joined(separator: " "))` failed" }
            } catch {
                return error.localizedDescription
            }
        }
        return nil
    }

    func unpin(name: String) {
        run { store in
            var policy = store.policy(name: name)
            policy.pinnedHostKeys = []
            try store.savePolicy(policy, name: name)
        }
    }

    /// Prompt for a host and pin, via an AppKit alert with a text field. Same reason
    /// as `requestDelete`: a SwiftUI `.sheet` presented from the `MenuBarExtra` panel
    /// is unreliable — submitting it dismisses the panel and leaves the sheet stuck.
    func requestPin(name: String) {
        DispatchQueue.main.async {
            let alert = NSAlert()
            alert.messageText = "Pin “\(name)” to a host"
            alert.informativeText =
                "The agent will refuse this key for any other destination. "
                + "The host must be in ~/.ssh/known_hosts (connect once first)."
            alert.addButton(withTitle: "Pin")
            alert.addButton(withTitle: "Cancel")
            let field = NSTextField(frame: NSRect(x: 0, y: 0, width: 240, height: 24))
            field.placeholderString = "hostname or alias"
            alert.accessoryView = field
            alert.window.initialFirstResponder = field
            NSApp.activate(ignoringOtherApps: true)
            guard alert.runModal() == .alertFirstButtonReturn else { return }
            let host = field.stringValue.trimmingCharacters(in: .whitespaces)
            guard !host.isEmpty else { return }
            self.pin(name: name, toHost: host)
            // Surface a pin failure right here — in full, and where the user is
            // looking — instead of as a truncated line atop the panel.
            if let err = self.actionError {
                let fail = NSAlert()
                fail.messageText = "Couldn’t pin “\(name)”"
                fail.informativeText = err
                fail.alertStyle = .warning
                fail.runModal()
                self.actionError = nil // shown here; don't also echo it in the header
            }
        }
    }

    func pin(name: String, toHost host: String) {
        run { store in
            let hostKeys = HostResolver.knownHostKeys(for: host)
            guard !hostKeys.isEmpty else {
                throw ActionError.message(
                    "No host key for “\(host)” in ~/.ssh/known_hosts yet.\n\n"
                    + "Pinning binds this key to the host’s public key, so the host "
                    + "must be known first. Connect to it once — e.g. `ssh \(host)` "
                    + "and accept the prompt — or run `fob setup \(host)`. Then pin again.")
            }
            var policy = store.policy(name: name)
            policy.pinnedHostKeys.append(contentsOf: hostKeys.filter { !policy.pinnedHostKeys.contains($0) })
            try store.savePolicy(policy, name: name)
        }
    }

    func setReuse(name: String, seconds: Int) {
        run { store in
            var policy = store.policy(name: name)
            policy.reuseSeconds = seconds > 0 ? Double(min(seconds, 300)) : nil
            try store.savePolicy(policy, name: name)
        }
    }

    /// Run a store mutation, surface any error, and refresh the key list.
    private func run(_ body: (KeyStore) throws -> Void) {
        guard let store else { actionError = "store unavailable"; return }
        do {
            try body(store)
            actionError = nil
        } catch {
            actionError = error.localizedDescription
        }
        refreshKeys()
    }

    // MARK: - Launch at login

    func refreshLoginItem() {
        launchAtLogin = SMAppService.mainApp.status == .enabled
    }

    func setLaunchAtLogin(_ enabled: Bool) {
        do {
            if enabled {
                try SMAppService.mainApp.register()
            } else {
                try SMAppService.mainApp.unregister()
            }
        } catch {
            actionError = "launch at login: \(error.localizedDescription)"
        }
        refreshLoginItem()
    }

    // MARK: - Audit

    func revealAuditLog() {
        guard let store else { return }
        let url = AuditLog.logURL(directory: store.directory)
        NSWorkspace.shared.activateFileViewerSelecting([url])
    }
}

enum ActionError: LocalizedError {
    case message(String)
    var errorDescription: String? { if case .message(let m) = self { return m } else { return nil } }
}
