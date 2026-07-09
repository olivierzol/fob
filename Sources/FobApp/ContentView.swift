import AppKit
import FobKit
import SwiftUI

struct ContentView: View {
    @EnvironmentObject var state: AppState

    @State private var newKeyName = ""
    @State private var newKeyBiometry = false
    @State private var pinTarget: String?      // key name awaiting a host to pin to
    @State private var pinHost = ""
    @State private var deleteTarget: String?   // key name awaiting delete confirmation

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            header
            Divider()
            keysSection
            Divider()
            newKeySection
            Divider()
            activitySection
            Divider()
            footer
        }
        .padding(14)
        .frame(width: 360)
        .sheet(item: Binding(get: { pinTarget.map(Identified.init) },
                             set: { pinTarget = $0?.value })) { item in
            pinSheet(keyName: item.value)
        }
        .confirmationDialog("Delete key?", isPresented: Binding(
            get: { deleteTarget != nil }, set: { if !$0 { deleteTarget = nil } })) {
            if let name = deleteTarget {
                Button("Delete '\(name)'", role: .destructive) {
                    state.delete(name: name); deleteTarget = nil
                }
            }
            Button("Cancel", role: .cancel) { deleteTarget = nil }
        } message: {
            Text("The Secure Enclave key is erased permanently and cannot be recovered.")
        }
    }

    // MARK: - Header

    private var header: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 8) {
                Image(systemName: "key.fill").foregroundStyle(.tint)
                Text("fob").font(.headline)
                Spacer()
                Circle()
                    .fill(state.listening ? Color.green : Color.orange)
                    .frame(width: 8, height: 8)
                Text(state.status).font(.caption).foregroundStyle(.secondary)
            }
            Text(state.socketPath).font(.caption2).foregroundStyle(.tertiary)
            if let fatal = state.fatalError {
                Label(fatal, systemImage: "exclamationmark.triangle.fill")
                    .font(.caption).foregroundStyle(.red).padding(.top, 2)
            }
            if let err = state.actionError {
                Text(err).font(.caption).foregroundStyle(.red).padding(.top, 2)
            }
        }
    }

    // MARK: - Keys

    private var keysSection: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("KEYS").font(.caption2).bold().foregroundStyle(.secondary)
            if state.keys.isEmpty {
                Text("No keys yet — create one below.").font(.caption).foregroundStyle(.secondary)
            }
            ForEach(state.keys) { key in
                keyRow(key)
            }
        }
    }

    private func keyRow(_ key: KeyInfo) -> some View {
        HStack(alignment: .top) {
            VStack(alignment: .leading, spacing: 2) {
                Text(key.name).font(.system(.body, design: .rounded)).bold()
                Text(pinDescription(key)).font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            Menu {
                Section("Touch reuse") {
                    reuseButton(key, seconds: 0, label: "Every time")
                    reuseButton(key, seconds: 30, label: "30 seconds")
                    reuseButton(key, seconds: 60, label: "1 minute")
                    reuseButton(key, seconds: 300, label: "5 minutes")
                }
                Divider()
                if key.isPinned {
                    Button("Unpin (allow any destination)") { state.unpin(name: key.name) }
                }
                Button("Pin to host…") { pinHost = ""; pinTarget = key.name }
                Divider()
                Button("Delete…", role: .destructive) { deleteTarget = key.name }
            } label: {
                Image(systemName: "ellipsis.circle")
            }
            .menuStyle(.borderlessButton)
            .fixedSize()
        }
        .padding(.vertical, 2)
    }

    private func reuseButton(_ key: KeyInfo, seconds: Int, label: String) -> some View {
        Button {
            state.setReuse(name: key.name, seconds: seconds)
        } label: {
            Label(label, systemImage: key.reuseSeconds == seconds ? "checkmark" : "")
        }
    }

    private func pinDescription(_ key: KeyInfo) -> String {
        var parts: [String] = []
        parts.append(key.isPinned ? "pinned to \(key.pinnedNames.joined(separator: ", "))"
                                  : "any destination")
        parts.append(key.reuseSeconds > 0 ? "reuse \(key.reuseSeconds)s" : "touch every time")
        return parts.joined(separator: " · ")
    }

    // MARK: - New key

    private var newKeySection: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("NEW KEY").font(.caption2).bold().foregroundStyle(.secondary)
            HStack {
                TextField("key name", text: $newKeyName)
                    .textFieldStyle(.roundedBorder)
                Button("Generate") {
                    let name = newKeyName.trimmingCharacters(in: .whitespaces)
                    guard !name.isEmpty else { return }
                    state.generate(name: name, requireBiometry: newKeyBiometry)
                    newKeyName = ""
                }
                .disabled(newKeyName.trimmingCharacters(in: .whitespaces).isEmpty)
            }
            Toggle("Touch ID only (currently enrolled fingerprints)", isOn: $newKeyBiometry)
                .font(.caption).toggleStyle(.checkbox)
        }
    }

    // MARK: - Activity

    private var activitySection: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("RECENT ACTIVITY").font(.caption2).bold().foregroundStyle(.secondary)
            if state.feed.isEmpty {
                Text("Nothing yet.").font(.caption).foregroundStyle(.secondary)
            } else {
                ScrollView {
                    VStack(alignment: .leading, spacing: 6) {
                        ForEach(Array(state.feed.enumerated()), id: \.offset) { _, event in
                            eventRow(event)
                        }
                    }
                }
                .frame(maxHeight: 160)
            }
        }
    }

    private func eventRow(_ event: AgentEvent) -> some View {
        HStack(alignment: .top, spacing: 6) {
            Image(systemName: icon(event.kind)).foregroundStyle(color(event.kind))
                .frame(width: 16)
            VStack(alignment: .leading, spacing: 1) {
                Text(event.message).font(.caption).lineLimit(3)
                Text(Self.timeFormatter.string(from: event.date))
                    .font(.caption2).foregroundStyle(.tertiary)
            }
        }
    }

    // MARK: - Footer

    private var footer: some View {
        VStack(alignment: .leading, spacing: 8) {
            Toggle("Launch at login", isOn: Binding(
                get: { state.launchAtLogin },
                set: { state.setLaunchAtLogin($0) }))
                .toggleStyle(.switch).font(.caption)
            HStack {
                Button("Reveal audit log") { state.revealAuditLog() }
                Spacer()
                Button("Quit fob") { NSApplication.shared.terminate(nil) }
            }
            .font(.caption)
        }
    }

    // MARK: - Pin sheet

    private func pinSheet(keyName: String) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Pin '\(keyName)' to a host").font(.headline)
            Text("The agent will refuse this key for any other destination. The host must be in ~/.ssh/known_hosts (connect once first).")
                .font(.caption).foregroundStyle(.secondary)
            TextField("hostname or alias", text: $pinHost)
                .textFieldStyle(.roundedBorder)
            HStack {
                Spacer()
                Button("Cancel") { pinTarget = nil }
                Button("Pin") {
                    let host = pinHost.trimmingCharacters(in: .whitespaces)
                    guard !host.isEmpty else { return }
                    state.pin(name: keyName, toHost: host)
                    pinTarget = nil
                }.keyboardShortcut(.defaultAction)
            }
        }
        .padding(16)
        .frame(width: 320)
    }

    // MARK: - Helpers

    private static let timeFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss"
        return f
    }()

    private func icon(_ kind: AgentEvent.Kind) -> String {
        switch kind {
        case .signed, .signedReused: return "checkmark.seal.fill"
        case .denied: return "xmark.seal.fill"
        case .refusedPin: return "hand.raised.fill"
        case .unknownKey: return "questionmark.circle.fill"
        case .bind: return "link"
        case .bindRejected: return "exclamationmark.triangle.fill"
        case .listening: return "dot.radiowaves.left.and.right"
        }
    }

    private func color(_ kind: AgentEvent.Kind) -> Color {
        switch kind {
        case .signed, .signedReused: return .green
        case .denied: return .orange
        case .refusedPin, .bindRejected: return .red
        case .unknownKey: return .yellow
        case .bind, .listening: return .secondary
        }
    }
}

/// Wraps a String so it can drive a `.sheet(item:)`.
private struct Identified: Identifiable {
    let value: String
    var id: String { value }
}
