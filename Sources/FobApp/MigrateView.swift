import FobKit
import SwiftUI

/// The "Migrate to fob" page: lists the servers already in ~/.ssh/config and starts a
/// per-host migration. Servers are the focus; commit signing is surfaced only as a
/// pointer to the ••• → "Use for commit signing…" flow.
struct MigrateView: View {
    @EnvironmentObject var state: AppState

    @State private var servers: [AppState.MigrationCandidate] = []
    @State private var signing: GitConfig.SigningInfo?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 10) {
                FobKeyGlyph(size: 28)
                Text("Migrate to fob").font(.title2.weight(.semibold))
            }

            Text("fob adds a new Secure Enclave key **alongside** each existing key, proves it works, then lets you retire the old one. Your current keys keep working the whole time — no lockout.")
                .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)

            if servers.isEmpty {
                Text("No `Host` entries found in ~/.ssh/config. Add one with “Set up a host”, then come back here.")
                    .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            } else {
                Text("SERVERS IN ~/.ssh/config").font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary).tracking(0.6)
                VStack(spacing: 0) {
                    ForEach(Array(servers.enumerated()), id: \.element.id) { index, s in
                        serverRow(s)
                        if index < servers.count - 1 { Divider() }
                    }
                }
                .background(RoundedRectangle(cornerRadius: 8).fill(Color.secondary.opacity(0.08)))
            }

            if let signing { signingLine(signing) }

            HStack {
                Button("Refresh") { load() }
                Spacer()
            }
        }
        .padding(22)
        .frame(maxWidth: .infinity, alignment: .leading)
        .onAppear(perform: load)
        .onChange(of: state.configRevision) { _ in load() }
    }

    private func load() {
        servers = state.discoverServers()
        signing = state.gitSigningInfo()
    }

    private func serverRow(_ s: AppState.MigrationCandidate) -> some View {
        HStack(spacing: 10) {
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(s.alias).font(.callout.weight(.semibold))
                    if s.isGitHost {
                        Text(s.provider.displayName.uppercased())
                            .font(.system(size: 9, weight: .semibold)).tracking(0.4)
                            .padding(.horizontal, 5).padding(.vertical, 1.5)
                            .background(RoundedRectangle(cornerRadius: 4).fill(Color.accentColor.opacity(0.15)))
                            .foregroundStyle(Color.accentColor)
                    }
                }
                Text(s.destination).font(.system(.caption, design: .monospaced)).foregroundStyle(.secondary)
            }
            Spacer()
            if s.usesFob && !s.oldIdentityFiles.isEmpty {
                // Migrated but the old key is still active — let them come back to retire it.
                HStack(spacing: 8) {
                    Label("Using fob", systemImage: "checkmark.seal.fill").font(.caption).foregroundStyle(.green)
                    Button("Retire old key…") { openMigrate(s.alias) }
                }
            } else if s.usesFob {
                Label("Using fob", systemImage: "checkmark.seal.fill")
                    .font(.caption).foregroundStyle(.green)
            } else {
                Button("Migrate…") { openMigrate(s.alias) }
            }
        }
        .padding(.horizontal, 12).padding(.vertical, 8)
    }

    private func openMigrate(_ alias: String) {
        state.migrateAlias = alias
        state.configDetail = .migrateHost
    }

    @ViewBuilder
    private func signingLine(_ info: GitConfig.SigningInfo) -> some View {
        Divider()
        Group {
            if info.usesFob {
                Label("Commit signing already uses a fob key.", systemImage: "signature")
            } else if info.signingKey != nil || info.format != nil {
                Label("Commit signing uses a non-fob key — move it via a key's ••• → “Use for commit signing…”.", systemImage: "signature")
            } else {
                Label("To sign commits with fob, use a key's ••• → “Use for commit signing…”.", systemImage: "signature")
            }
        }
        .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
    }
}
