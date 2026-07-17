import AppKit
import FobKit
import SwiftUI

/// The Keys page: full per-key management (the roomy counterpart to the popover's ••• menu).
/// Each row is tailored to what the key is actually for — a signing-only key doesn't offer
/// "Sign commits…" or "Pin" (it does no SSH auth); an auth key offers pin + a signing hop.
/// Actions reuse AppState, so they take effect immediately and mirror what the CLI writes.
struct KeysView: View {
    @EnvironmentObject var state: AppState

    @State private var usage: [String: AppState.KeyUsage] = [:]
    @State private var pruneError: String?

    private static let reuseChoices: [(Int, String)] =
        [(0, "Touch every time"), (30, "Reuse 30s"), (60, "Reuse 1m"), (300, "Reuse 5m")]

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 10) {
                FobKeyGlyph(size: 28)
                Text("Keys").font(.title2.weight(.semibold))
                Spacer()
                Button("New key…") { state.openConfig(tab: .newKey) }
            }

            if let pruneError {
                Label(pruneError, systemImage: "exclamationmark.triangle.fill")
                    .font(.caption).foregroundStyle(.red).fixedSize(horizontal: false, vertical: true)
            }

            if state.keys.isEmpty {
                Text("No keys yet. Create one from the **New key** tab.")
                    .font(.callout).foregroundStyle(.secondary).padding(.vertical, 20)
            } else {
                ScrollView {
                    VStack(spacing: 8) {
                        ForEach(state.keys) { key in row(key) }
                    }
                }
                .frame(minHeight: 220, maxHeight: 440)
            }
        }
        .padding(22)
        .frame(maxWidth: .infinity, alignment: .leading)
        .onAppear(perform: loadUsage)
        .onChange(of: state.configRevision) { _ in loadUsage() }
        .onChange(of: state.keys.count) { _ in loadUsage() }
    }

    private func loadUsage() {
        Task { usage = await state.keyUsages() }
    }

    private func row(_ key: KeyInfo) -> some View {
        let use = usage[key.name]
        return VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                Text(key.name).font(.callout.weight(.semibold))
                ForEach(roleBadges(use), id: \.self) { badge($0) }
            }
            Text(meta(key, use)).font(.caption).foregroundStyle(.secondary)

            HStack(spacing: 8) {
                // Pin is SSH-auth only — hide it for a signing-only key (but always allow
                // Unpin if something is pinned).
                if key.isPinned {
                    Button("Unpin") { state.unpin(name: key.name) }
                } else if !(use?.isSigningOnly ?? false) {
                    Button("Pin…") { state.requestPin(name: key.name) }
                }

                Menu(reuseLabel(key.reuseSeconds)) {
                    ForEach(Self.reuseChoices, id: \.0) { seconds, label in
                        Button {
                            state.setReuse(name: key.name, seconds: seconds)
                        } label: {
                            if key.reuseSeconds == seconds { Label(label, systemImage: "checkmark") }
                            else { Text(label) }
                        }
                    }
                }
                .frame(width: 150)

                // Signing is a git concept: manage it if already signing; offer it for a
                // git-service or bare key; omit it for a plain server-login key.
                if use?.signsCommits ?? false {
                    Button("Signing setup…") { openSigning(key.name) }
                        .help("Review or change this key's commit-signing configuration.")
                    Button("Rotate…") { openRotate(key.name) }
                        .help("Replace this signing key with a fresh Secure Enclave key and retire this one.")
                } else if use?.canOfferSigning ?? true {
                    Button("Sign commits…") { openSigning(key.name) }
                }

                Spacer()
                Button(role: .destructive) { state.requestDelete(name: key.name) } label: {
                    Text("Delete").foregroundStyle(Theme.red)
                }
            }
            .font(.caption)

            // A signing key that also carries an SSH host alias — offer to prune it, since a
            // signing key doesn't need one (signing goes through the fob-sign wrapper). Opt-in,
            // because a key CAN be genuinely dual-purpose (e.g. GitLab allows one for both).
            if let use, use.signsCommits, !use.authHosts.isEmpty {
                ForEach(use.authHosts, id: \.self) { alias in
                    HStack(spacing: 6) {
                        Image(systemName: "info.circle").foregroundStyle(.secondary)
                        Text("Also an SSH alias “\(alias)” — a signing key usually doesn't need one.")
                            .foregroundStyle(.secondary)
                        Button("Remove alias") { prune(alias) }
                    }
                    .font(.caption2)
                }
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 8).fill(Color.secondary.opacity(0.08)))
    }

    private func openSigning(_ name: String) {
        state.signingSetupKey = name
        state.signingSetupHost = nil
        state.configDetail = .signing
    }

    private func openRotate(_ name: String) {
        state.rotateKey = name
        state.configDetail = .rotate
    }

    private func prune(_ alias: String) {
        pruneError = state.removeSSHHostAlias(alias)
        loadUsage()
    }

    /// Short role tags shown next to the key name.
    private func roleBadges(_ use: AppState.KeyUsage?) -> [String] {
        guard let use else { return [] }
        var tags: [String] = []
        if use.signsCommits { tags.append("Signing") }
        if !use.authHosts.isEmpty { tags.append("Auth") }
        if use.isUnused { tags.append("Unused") }
        return tags
    }

    private func badge(_ text: String) -> some View {
        Text(text.uppercased())
            .font(.system(size: 9, weight: .bold)).tracking(0.4)
            .padding(.horizontal, 5).padding(.vertical, 1.5)
            .background(RoundedRectangle(cornerRadius: 4).fill(badgeColor(text).opacity(0.16)))
            .foregroundStyle(badgeColor(text))
    }

    private func badgeColor(_ text: String) -> Color {
        switch text {
        case "Signing": return Theme.accent
        case "Auth": return Theme.green
        default: return .secondary
        }
    }

    /// Second line: what the key is used for, then its pin/reuse state.
    private func meta(_ key: KeyInfo, _ use: AppState.KeyUsage?) -> String {
        var parts: [String] = []
        if let use {
            if !use.authHosts.isEmpty { parts.append("auth: \(use.authHosts.joined(separator: ", "))") }
            if use.signsCommits { parts.append("commit signing") }
            if use.isUnused { parts.append("not yet used") }
        }
        parts.append(key.pinnedNames.isEmpty ? "any destination" : "pinned → \(key.pinnedNames.joined(separator: ", "))")
        parts.append(reuseLabel(key.reuseSeconds).lowercased())
        return parts.joined(separator: " · ")
    }

    private func reuseLabel(_ seconds: Int) -> String {
        switch seconds {
        case 0: return "Touch every time"
        case 60: return "Reuse 1m"
        case 300: return "Reuse 5m"
        default: return "Reuse \(seconds)s"
        }
    }
}
