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
    /// Bumped after any ~/.ssh/config write so open lists (e.g. Migrate) refresh live.
    @Published var configRevision = 0

    // MARK: - Config window routing
    // The single "fob" window shows one of these tabs; two flows (signing, migrate-a-host)
    // are reached from other flows/the popover, so they render as a pushed detail over the
    // current tab rather than as tabs of their own.
    enum ConfigTab: Hashable { case newKey, keys, migrate, checkup, audit, settings }
    enum ConfigDetail: Equatable { case signing, migrateHost }
    @Published var configTab: ConfigTab = .newKey
    @Published var configDetail: ConfigDetail?

    /// Set the config window's route, then the caller opens the window. Detail routes reuse
    /// the existing `signingSetupKey`/`migrateAlias` fields as their parameters (set those
    /// first). Passing a tab clears any active detail.
    func openConfig(tab: ConfigTab, detail: ConfigDetail? = nil) {
        configTab = tab
        configDetail = detail
    }

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
            // Prefer the alias matching the key name so a key pinned to a shared HostName
            // (github-ousson / github-feedly both → github.com) shows its own alias.
            let names = policy.pinnedHostKeys.map {
                HostResolver.name(forHostKeyBlob: $0, preferredAlias: key.name) ?? "unknown host key"
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
        // Only tidy the key's config/pub if the enclave key was actually erased — a failed
        // remove must not leave the key alive while stripping its ~/.ssh/config entry.
        if actionError == nil { cleanupAfterDelete(name) }
    }

    /// After erasing the enclave key, clear what fob wrote for it: the exported public key
    /// and — if this alias had a fob-created `~/.ssh/config` block — that block (backed up
    /// first). Otherwise the dead entry lingers and re-appears in Migrate (the confusion
    /// this fixes). A migrated host with a live old key is left untouched by removeFobHostBlock.
    private func cleanupAfterDelete(_ name: String) {
        let ssh = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".ssh")
        try? FileManager.default.removeItem(at: ssh.appendingPathComponent("fob_\(name).pub"))
        let cfg = (try? String(contentsOf: sshConfigURL, encoding: .utf8)) ?? ""
        if let new = HostSetup.removeFobHostBlock(cfg, alias: name), new != cfg {
            _ = try? HostSetup.backupAndWriteConfig(new, at: sshConfigURL)
            configRevision += 1
        }
    }

    /// Remove a single fob `Host <alias>` block from ~/.ssh/config (backup first) — used by
    /// the Keys page to prune a redundant SSH auth alias on a signing-only key. Returns an
    /// error string, or nil on success (also nil-safe: a migrated host with a live old key
    /// isn't removable and returns a message rather than touching it). Bumps configRevision.
    func removeSSHHostAlias(_ alias: String) -> String? {
        let cfg = (try? String(contentsOf: sshConfigURL, encoding: .utf8)) ?? ""
        guard let new = HostSetup.removeFobHostBlock(cfg, alias: alias), new != cfg else {
            return "Couldn’t remove “\(alias)” — it isn’t a plain fob host block."
        }
        do {
            _ = try HostSetup.backupAndWriteConfig(new, at: sshConfigURL)
            configRevision += 1
            return nil
        } catch {
            return error.localizedDescription
        }
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
                "The Secure Enclave key is erased permanently and cannot be recovered. "
                + "fob also removes its exported public key and its ~/.ssh/config entry (backed up first)."
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
            if configAdded { configRevision += 1 }
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

    /// What a key is actually used for, so the Keys page can tailor its row (e.g. hide
    /// "Sign commits…" for a key that already signs, or "Pin" for a signing-only key).
    struct KeyUsage: Equatable {
        let signsCommits: Bool     // it's the git signing key (global or any includeIf identity)
        let authHosts: [String]    // ~/.ssh/config aliases whose IdentityFile is this fob key
        let authGitHosts: [String] // subset of authHosts that are git services (GitHub/GitLab/…)
        var isSigningOnly: Bool { signsCommits && authHosts.isEmpty }
        var isUnused: Bool { !signsCommits && authHosts.isEmpty }
        /// Commit signing is a git concept — offer it for git-service keys or a bare key, not
        /// for a plain server-login key where it's meaningless.
        var canOfferSigning: Bool { !signsCommits && (isUnused || !authGitHosts.isEmpty) }
    }

    func keyUsage(name: String) -> KeyUsage {
        let inputs = usageInputs()
        return usage(for: name, inputs: inputs)
    }

    /// Usage for every key in one shot — shares the git/ssh reads across all keys so the
    /// Keys tab doesn't spawn a subprocess storm (the source of the tab-open lag).
    func keyUsages() -> [String: KeyUsage] {
        let inputs = usageInputs()
        var out: [String: KeyUsage] = [:]
        for key in keys { out[key.name] = usage(for: key.name, inputs: inputs) }
        return out
    }

    /// The shared, key-independent reads: the set of configured signing-key basenames
    /// (global + every includeIf identity) and the parsed ssh `Host` blocks. Computed once.
    private struct UsageInputs { let signingBases: Set<String>; let blocks: [HostSetup.HostBlock] }
    private func usageInputs() -> UsageInputs {
        func base(_ p: String) -> String {
            (p.trimmingCharacters(in: .whitespacesAndNewlines) as NSString).lastPathComponent
        }
        var signing = Set<String>()
        let g = base(runGitSync(["config", "--global", "user.signingkey"]))
        if !g.isEmpty { signing.insert(g) }
        for inc in GitConfig.parseIncludeEntries(runGitSync(["config", "--global", "--get-regexp", "^includeif\\."])) {
            let b = base(runGitSync(["config", "--file", (inc.path as NSString).expandingTildeInPath, "user.signingkey"]))
            if !b.isEmpty { signing.insert(b) }
        }
        let cfg = (try? String(contentsOf: sshConfigURL, encoding: .utf8)) ?? ""
        return UsageInputs(signingBases: signing, blocks: HostSetup.listHostBlocks(in: cfg))
    }

    private func usage(for name: String, inputs: UsageInputs) -> KeyUsage {
        let pubBase = "fob_\(name).pub"
        let mine = inputs.blocks.filter {
            $0.parsed.identityFiles.contains { ($0 as NSString).lastPathComponent == pubBase }
        }
        let gitHosts = mine
            .filter { HostSetup.isGitHost(hostName: $0.parsed.hostName ?? $0.alias, user: $0.parsed.user) }
            .map(\.alias)
        return KeyUsage(signsCommits: inputs.signingBases.contains(pubBase),
                        authHosts: Array(Set(mine.map(\.alias))).sorted(),
                        authGitHosts: Array(Set(gitHosts)).sorted())
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
            configRevision += 1
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
            configRevision += 1
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
            configRevision += 1
            return .ok(backup: backup.lastPathComponent)
        } catch {
            return .error(error.localizedDescription)
        }
    }

    // MARK: - SSH checkup (read-only hygiene report)

    struct CheckupReport {
        let findings: [SSHCheckup.Finding]
        var high: Int { findings.filter { $0.severity == .high }.count }
        var medium: Int { findings.filter { $0.severity == .medium }.count }
        var low: Int { findings.filter { $0.severity == .low }.count }
        var opportunities: Int { findings.filter { $0.severity == .opportunity }.count }
        var isClean: Bool { findings.allSatisfy { $0.severity == .opportunity } }
    }

    /// Scan ~/.ssh read-only and return findings, most severe first. Reads private-key
    /// files (encryption, permissions, type/bits), lints ~/.ssh/config, and surfaces
    /// migrate/signing opportunities from the existing discovery. Never writes anything.
    func runCheckup() async -> CheckupReport {
        var findings: [SSHCheckup.Finding] = []
        let sshDir = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".ssh")
        let fm = FileManager.default

        // 1. On-disk private keys.
        let skipExact: Set<String> = ["config", "known_hosts", "authorized_keys", "agent.sock"]
        let entries = (try? fm.contentsOfDirectory(atPath: sshDir.path)) ?? []
        for name in entries.sorted() {
            if name.hasSuffix(".pub") || name.hasPrefix("config.") || name.hasPrefix("known_hosts")
                || skipExact.contains(name) || name.hasPrefix(".") { continue }
            let url = sshDir.appendingPathComponent(name)
            var isDir: ObjCBool = false
            guard fm.fileExists(atPath: url.path, isDirectory: &isDir), !isDir.boolValue,
                  let contents = try? String(contentsOf: url, encoding: .utf8),
                  let info = SSHCheckup.parsePrivateKey(contents) else { continue }

            if !info.isEncrypted {
                let cfg = (try? String(contentsOf: sshConfigURL, encoding: .utf8)) ?? ""
                let referenced = SSHCheckup.isKeyReferenced(
                    keyPath: url.path, configText: cfg, gitSigningKey: gitSigningInfo().signingKey)
                findings.append(SSHCheckup.unencryptedKeyFinding(name: name, path: url.path, referenced: referenced))
            }
            if let mode = (try? fm.attributesOfItem(atPath: url.path))?[.posixPermissions] as? Int,
               SSHCheckup.isPrivateKeyPermissive(mode: mode) {
                findings.append(.init(severity: .high, category: "Key",
                    title: "“\(name)” is readable by other accounts",
                    detail: "Mode \(String(mode, radix: 8)) — private keys must be owner-only. ssh will often refuse it too.",
                    fix: .command("chmod 600 \(url.path)")))
            }
            if let (type, bits) = await sshKeyTypeBits(url), isWeakKey(type: type, bits: bits) {
                findings.append(.init(severity: .medium, category: "Key",
                    title: "“\(name)” is a weak/deprecated key (\(type)\(bits.map { " \($0)" } ?? ""))",
                    detail: "Prefer Ed25519 (or a fob Secure Enclave key). DSA is disabled by modern OpenSSH; RSA under 3072 bits is weak.",
                    fix: .none))
            }
        }

        // 2. Risky ~/.ssh/config directives.
        let config = (try? String(contentsOf: sshDir.appendingPathComponent("config"), encoding: .utf8)) ?? ""
        findings += SSHCheckup.scanConfig(config)

        // 2b. Multi-account git-identity footgun.
        let identities = discoverGitIdentities()
        let useConfigOnly = runGitSync(["config", "--global", "user.useConfigOnly"])
            .trimmingCharacters(in: .whitespacesAndNewlines) == "true"
        let defaultEmail = runGitSync(["config", "--global", "user.email"])
            .trimmingCharacters(in: .whitespacesAndNewlines)
        if let f = SSHCheckup.identityFinding(includeCount: identities.count,
                                              useConfigOnly: useConfigOnly, defaultEmail: defaultEmail) {
            findings.append(f)
        }

        // 3. Opportunities — hosts/signing not yet on fob (reuse existing discovery).
        for c in discoverServers() where !c.usesFob {
            let kind = c.isGitHost ? "git host" : "server"
            findings.append(.init(severity: .opportunity, category: "Opportunity",
                title: "“\(c.alias)” still uses an on-disk key",
                detail: "This \(kind) authenticates with a plain key. Migrate it to a Touch ID-gated fob key.",
                fix: .migrate(alias: c.alias)))
        }
        let signing = gitSigningInfo()
        if (signing.signingKey != nil || signing.format != nil), !signing.usesFob {
            findings.append(.init(severity: .opportunity, category: "Opportunity",
                title: "Commit signing uses a non-fob key",
                detail: "Your git signing key isn't a fob key. Move it so commit signatures are Touch ID-gated.",
                fix: .signing))
        }

        // 3b. fob signing set up, but can it be verified locally?
        if signing.usesFob {
            let asFile = runGitSync(["config", "--global", "gpg.ssh.allowedSignersFile"])
                .trimmingCharacters(in: .whitespacesAndNewlines)
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

        // 4. ssh-agent: on-disk keys loaded there sign with no Touch ID prompt (fob keys excluded).
        let fobBlobs = Set(((try? store?.all()) ?? []).compactMap { key -> String? in
            guard let pub = try? key.publicKey() else { return nil }
            let parts = SSHFormat.authorizedKeysLine(pub, comment: "fob:\(key.name)").split(separator: " ")
            return parts.count >= 2 ? String(parts[1]) : nil
        })
        let (agentStatus, agentOut) = await runProcess("/usr/bin/ssh-add", ["-L"])
        let agentBlobs = agentStatus == 0 ? SSHCheckup.agentKeyBlobs(fromSSHAddL: agentOut) : []
        if let f = SSHCheckup.agentLoadedKeysFinding(agentKeyBlobs: agentBlobs, fobKeyBlobs: fobBlobs) {
            findings.append(f)
        }

        return CheckupReport(findings: findings.sorted { $0.severity < $1.severity })
    }

    /// `(type, bits)` from `ssh-keygen -l -f <key>` — reads the public half, no passphrase.
    private func sshKeyTypeBits(_ url: URL) async -> (type: String, bits: Int?)? {
        let (status, out) = await runProcess("/usr/bin/ssh-keygen", ["-l", "-f", url.path])
        guard status == 0 else { return nil }
        // "256 SHA256:… comment (ED25519)"
        let bits = out.split(separator: " ").first.flatMap { Int($0) }
        guard let open = out.lastIndex(of: "("), let close = out.lastIndex(of: ")"), open < close else {
            return nil
        }
        return (String(out[out.index(after: open)..<close]), bits)
    }

    private func isWeakKey(type: String, bits: Int?) -> Bool {
        let t = type.uppercased()
        if t.contains("DSA") { return true }               // ssh-dss / DSA — deprecated
        if t.contains("RSA"), let bits, bits < 3072 { return true }
        return false
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

    /// A git identity fob can write signing config into: a `~/.gitconfig` include
    /// (from an `includeIf` block — the multi-account case), the global config, or the
    /// current repo (copy-only — the window has no repo context).
    enum SigningScope: Hashable {
        case repository            // git config --local (shown as commands to run in the repo)
        case identity(GitIdentity) // git config --file <include path>
        case global                // git config --global

        /// git-config location flag(s) — the args between `git config` and the key/value.
        var flag: [String] {
            switch self {
            case .repository: return ["--local"]
            case .identity(let id): return ["--file", id.path]
            case .global: return ["--global"]
            }
        }
    }

    /// A per-identity include discovered in `~/.gitconfig` (via an `includeIf` block).
    struct GitIdentity: Identifiable, Hashable {
        let path: String            // expanded absolute path to the include file
        let conditionLabel: String  // e.g. "gitdir:~/src/perso/"
        let email: String?          // that file's user.email, for a friendly label
        var id: String { path }
    }

    struct SigningInfo {
        let name: String
        let pubLine: String            // add to the git host as a Signing Key
        let pubPath: String
        let signerProgram: String      // ~/.fob/bin/fob-sign (git's gpg.ssh.program)
        let gitOnly: Bool              // policy currently restricts signing to "git"

        /// The git config commands for a scope. The view builds these so it can switch
        /// scope without re-reading the key. Uses a `gpg.ssh.program` wrapper so only git
        /// signing reaches fob — SSH_AUTH_SOCK (and any other ssh agent) is left alone.
        func gitConfigCommands(scope: SigningScope) -> [String] {
            let flag = scope.flag.joined(separator: " ")
            return [
                "git config \(flag) gpg.format ssh",
                "git config \(flag) user.signingkey \(pubPath)",
                "git config \(flag) gpg.ssh.program \(signerProgram)",
                "git config \(flag) commit.gpgsign true",
                "git config \(flag) tag.gpgsign true",
                "git config --global gpg.ssh.allowedSignersFile ~/.ssh/allowed_signers",
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


    /// Write the signing config to `scope` (global, or a specific include file for a
    /// multi-account identity). nil = success. `.repository` is not applied here — the
    /// window has no repo context, so those are shown as copy commands.
    func configureGitSigning(pubPath: String, signerProgram: String, pubLine: String, scope: SigningScope) -> String? {
        let signersPath = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".ssh/allowed_signers").path
        // Signing itself is scoped (so multi-account setups don't clobber each other);
        // the allow-list pointer is a harmless shared path, set globally so verification
        // works in every repo, not just this identity's directories.
        let writes: [[String]] = [
            scope.flag + ["gpg.format", "ssh"],
            scope.flag + ["user.signingkey", pubPath],
            scope.flag + ["gpg.ssh.program", signerProgram],
            scope.flag + ["commit.gpgsign", "true"],
            scope.flag + ["tag.gpgsign", "true"],
            ["--global", "gpg.ssh.allowedSignersFile", signersPath],
        ]
        for kv in writes {
            let args = ["config"] + kv
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
        // Add the key to allowed_signers so `git verify-commit` works locally.
        if let email = signingEmail(for: scope) { addAllowedSigner(email: email, pubLine: pubLine) }
        return nil
    }

    /// The committer email a signature under `scope` will carry — the include identity's
    /// email, else the global user.email.
    private func signingEmail(for scope: SigningScope) -> String? {
        if case .identity(let id) = scope, let e = id.email { return e }
        let e = runGitSync(["config", "--global", "user.email"]).trimmingCharacters(in: .whitespacesAndNewlines)
        return e.isEmpty ? nil : e
    }

    /// Append an entry to ~/.ssh/allowed_signers (idempotent) so signed commits verify locally.
    private func addAllowedSigner(email: String, pubLine: String) {
        let url = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".ssh/allowed_signers")
        let text = (try? String(contentsOf: url, encoding: .utf8)) ?? ""
        guard let updated = SSHCheckup.AllowedSigners.appending(text, email: email, pubLine: pubLine) else { return }
        try? Data(updated.utf8).write(to: url, options: .atomic)
        try? FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: url.path)
    }

    /// Whether `scope` already signs with this key (so the window can say "already set"
    /// instead of implying action). True when its user.signingkey is this pubkey and
    /// commit.gpgsign is on.
    func signingConfigured(pubPath: String, scope: SigningScope) -> Bool {
        let key = runGitSync(["config"] + scope.flag + ["user.signingkey"])
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let sign = runGitSync(["config"] + scope.flag + ["commit.gpgsign"])
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return key == pubPath && sign == "true"
    }

    /// The per-identity `includeIf` files in ~/.gitconfig, so the signing window can offer
    /// each git identity as a target instead of only clobbering `--global`.
    func discoverGitIdentities() -> [GitIdentity] {
        let output = runGitSync(["config", "--global", "--get-regexp", "^includeif\\."])
        return GitConfig.parseIncludeEntries(output).map { entry in
            let path = (entry.path as NSString).expandingTildeInPath
            let email = runGitSync(["config", "--file", path, "user.email"])
                .trimmingCharacters(in: .whitespacesAndNewlines)
            return GitIdentity(path: path, conditionLabel: entry.condition,
                               email: email.isEmpty ? nil : email)
        }
    }

    /// Run git synchronously and return stdout (empty on failure). Only used for fast,
    /// local `git config` reads from the main actor.
    private func runGitSync(_ args: [String]) -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/git")
        process.arguments = args
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = Pipe()
        do {
            try process.run()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            return String(decoding: data, as: UTF8.self)
        } catch {
            return ""
        }
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

    /// Map a `~/.ssh/config` alias (e.g. "github-ousson") to its real HostName + Port for
    /// a known_hosts lookup. known_hosts is keyed by hostname (github.com), not the alias.
    /// Returns the token unchanged if it isn't a config alias.
    private func resolveKnownHost(_ token: String) -> (host: String, port: Int?) {
        let config = (try? String(contentsOf: sshConfigURL, encoding: .utf8)) ?? ""
        if let parsed = HostSetup.parseHostBlock(alias: token, in: config), let hostName = parsed.hostName {
            return (hostName, parsed.port)
        }
        return (token, nil)
    }

    func pin(name: String, toHost host: String) {
        let (resolved, port) = resolveKnownHost(host)
        run { store in
            let hostKeys = HostResolver.knownHostKeys(for: resolved, port: port)
            guard !hostKeys.isEmpty else {
                throw ActionError.message(
                    "No host key for “\(resolved)” in ~/.ssh/known_hosts yet.\n\n"
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

    /// Audit entries, newest first, for the in-app Audit page ([] if the store is unavailable).
    func auditEntries() -> [AuditLog.Entry] {
        guard let store else { return [] }
        return AuditLog.entries(directory: store.directory).reversed()
    }

    /// 1-based line of the first broken hash-chain link, or nil if the chain verifies.
    func auditFirstBrokenLink() -> Int? {
        guard let store else { return nil }
        return AuditLog.firstBrokenLink(directory: store.directory)
    }
}

enum ActionError: LocalizedError {
    case message(String)
    var errorDescription: String? { if case .message(let m) = self { return m } else { return nil } }
}
