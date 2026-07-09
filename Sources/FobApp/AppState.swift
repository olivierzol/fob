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

    func unpin(name: String) {
        run { store in
            var policy = store.policy(name: name)
            policy.pinnedHostKeys = []
            try store.savePolicy(policy, name: name)
        }
    }

    func pin(name: String, toHost host: String) {
        run { store in
            let hostKeys = HostResolver.knownHostKeys(for: host)
            guard !hostKeys.isEmpty else {
                throw ActionError.message(
                    "no host keys for '\(host)' in ~/.ssh/known_hosts — connect once first")
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
