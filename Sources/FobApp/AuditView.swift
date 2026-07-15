import AppKit
import FobKit
import SwiftUI

/// The Audit page: the hash-chained decision log, newest first, with a chain-integrity
/// badge. Read-only — the log itself is append-only and tamper-evident; this just shows it
/// and re-verifies the chain on demand.
struct AuditView: View {
    @EnvironmentObject var state: AppState

    @State private var entries: [AuditLog.Entry] = []
    @State private var brokenAt: Int?
    @State private var loaded = false

    private static let parser = ISO8601DateFormatter()
    private static let display: DateFormatter = {
        let f = DateFormatter(); f.dateFormat = "MMM d · h:mm:ss a"; return f
    }()

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 10) {
                FobKeyGlyph(size: 28)
                Text("Audit log").font(.title2.weight(.semibold))
                Spacer()
                chainBadge
            }
            Text("Every signature and decision is appended to a SHA-256 **hash chain** — editing or deleting any line breaks it. Tamper-evident, newest first.")
                .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)

            if entries.isEmpty {
                Text(loaded ? "No audit entries yet — nothing has used a key." : "Loading…")
                    .font(.callout).foregroundStyle(.secondary).padding(.vertical, 20)
            } else {
                ScrollView {
                    VStack(spacing: 6) {
                        ForEach(Array(entries.enumerated()), id: \.offset) { _, e in row(e) }
                    }
                }
                .frame(minHeight: 260, maxHeight: 460)
            }

            HStack {
                Button("Verify chain") { load() }
                Spacer()
                Button("Reveal in Finder") { state.revealAuditLog() }
            }
        }
        .padding(22)
        .frame(maxWidth: .infinity, alignment: .leading)
        .onAppear { if !loaded { load() } }
    }

    private var chainBadge: some View {
        Group {
            if let brokenAt {
                Label("chain broken at line \(brokenAt)", systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(Theme.red)
            } else if !entries.isEmpty {
                Label("chain intact", systemImage: "checkmark.seal.fill").foregroundStyle(Theme.green)
            }
        }
        .font(.caption.weight(.semibold))
    }

    private func load() {
        entries = state.auditEntries()
        brokenAt = state.auditFirstBrokenLink()
        loaded = true
    }

    private func row(_ e: AuditLog.Entry) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Text(eventLabel(e.event))
                .font(.system(size: 9, weight: .bold)).tracking(0.4)
                .padding(.horizontal, 5).padding(.vertical, 2)
                .background(RoundedRectangle(cornerRadius: 4).fill(color(e.event).opacity(0.16)))
                .foregroundStyle(color(e.event))
                .frame(width: 96, alignment: .leading)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    if let key = e.key { Text(key).font(.callout.weight(.semibold)) }
                    if let dest = e.dest, !dest.isEmpty {
                        Text("→ \(dest)").font(.caption).foregroundStyle(.secondary)
                    }
                }
                Text(timestamp(e.ts)).font(.system(.caption2, design: .monospaced)).foregroundStyle(.secondary)
                if let peer = e.peer, !peer.isEmpty {
                    Text(peer).font(.system(.caption2, design: .monospaced)).foregroundStyle(.tertiary)
                        .lineLimit(1).truncationMode(.middle)
                }
            }
            Spacer(minLength: 0)
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 8).fill(Color.secondary.opacity(0.08)))
    }

    private func timestamp(_ ts: String) -> String {
        guard let date = Self.parser.date(from: ts) else { return ts }
        return Self.display.string(from: date)
    }

    /// Short, human label for a raw event token (e.g. "signed-reused" → "REUSED").
    private func eventLabel(_ event: String) -> String {
        switch event {
        case "signed": return "SIGNED"
        case "signed-reused": return "REUSED"
        case "signed-git": return "SIGNED GIT"
        case "denied": return "DENIED"
        case "refused-pin": return "REFUSED PIN"
        case "refused-policy": return "REFUSED"
        case "refused-namespace": return "REFUSED NS"
        case "bind-rejected": return "BIND REJECT"
        case "unknown-key": return "UNKNOWN KEY"
        default: return event.uppercased()
        }
    }

    private func color(_ event: String) -> Color {
        if event.hasPrefix("signed") { return Theme.green }
        if event == "denied" { return .orange }
        if event.hasPrefix("refused") || event == "bind-rejected" { return Theme.red }
        if event == "unknown-key" { return .yellow }
        return .secondary
    }
}
