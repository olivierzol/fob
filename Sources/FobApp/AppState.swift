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

    func generate(name: String, requireBiometry: Bool) {
        run { store in _ = try store.create(name: name, requireBiometry: requireBiometry) }
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
