import AppKit
import FobKit
import SwiftUI

/// The "SSH checkup" page (a Configure-window tab): a read-only scan of ~/.ssh (keys, config) plus
/// migrate/signing opportunities, shown as severity-ranked findings. Every fix is opt-in
/// — it either opens an existing fob flow or copies a command; the checkup never edits
/// anything itself.
struct CheckupView: View {
    @EnvironmentObject var state: AppState

    @State private var report: AppState.CheckupReport?
    @State private var running = false
    @State private var copied: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 10) {
                FobKeyGlyph(size: 28)
                Text("SSH checkup").font(.title2.weight(.semibold))
                Spacer()
                Button(running ? "Scanning…" : "Re-run") { run() }.disabled(running)
            }
            Text("A read-only look at your `~/.ssh` — keys, config, and what could move to fob. fob doesn't change anything here.")
                .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)

            if let report {
                summary(report)
                if report.findings.isEmpty {
                    Label("No issues found — your SSH setup looks healthy.", systemImage: "checkmark.seal.fill")
                        .font(.callout).foregroundStyle(.green).padding(.vertical, 6)
                } else {
                    ScrollView {
                        VStack(spacing: 8) {
                            ForEach(report.findings) { finding in row(finding) }
                        }
                    }
                    .frame(minHeight: 240, maxHeight: 480)
                }
            } else {
                HStack { Spacer(); ProgressView(); Spacer() }.padding(.vertical, 20)
            }

        }
        .padding(22)
        .frame(maxWidth: .infinity, alignment: .leading)
        .onAppear { if report == nil { run() } }
    }

    private func run() {
        running = true
        Task {
            let r = await state.runCheckup()
            report = r
            running = false
        }
    }

    private func summary(_ r: AppState.CheckupReport) -> some View {
        HStack(spacing: 8) {
            if r.high > 0 { pill("\(r.high) high", Theme.red) }
            if r.medium > 0 { pill("\(r.medium) medium", .orange) }
            if r.low > 0 { pill("\(r.low) low", .secondary) }
            if r.opportunities > 0 { pill("\(r.opportunities) to improve", Theme.accent) }
            if r.findings.isEmpty { pill("all clear", Theme.green) }
        }
    }

    private func pill(_ text: String, _ color: Color) -> some View {
        Text(text).font(.system(size: 11, weight: .semibold))
            .padding(.horizontal, 8).padding(.vertical, 3)
            .background(RoundedRectangle(cornerRadius: 6).fill(color.opacity(0.16)))
            .foregroundStyle(color)
    }

    private func row(_ f: SSHCheckup.Finding) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Text(f.severity.label)
                .font(.system(size: 9, weight: .bold)).tracking(0.4)
                .padding(.horizontal, 5).padding(.vertical, 2)
                .background(RoundedRectangle(cornerRadius: 4).fill(color(f.severity).opacity(0.16)))
                .foregroundStyle(color(f.severity))
                .frame(width: 58, alignment: .leading)
            VStack(alignment: .leading, spacing: 3) {
                Text(f.title).font(.callout.weight(.semibold)).fixedSize(horizontal: false, vertical: true)
                Text(f.detail).font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                action(f)
            }
            Spacer(minLength: 0)
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 8).fill(Color.secondary.opacity(0.08)))
    }

    @ViewBuilder
    private func action(_ f: SSHCheckup.Finding) -> some View {
        switch f.fix {
        case .migrate(let alias):
            Button("Migrate \(alias)…") {
                state.migrateAlias = alias
                state.configDetail = .migrateHost
            }.font(.caption).padding(.top, 2)
        case .signing:
            Text("Fix: a key's ••• → “Use for commit signing…”.")
                .font(.caption).foregroundStyle(.tertiary)
        case .command(let cmd):
            HStack(spacing: 8) {
                Text(cmd).font(.system(.caption2, design: .monospaced)).textSelection(.enabled)
                    .padding(6).background(RoundedRectangle(cornerRadius: 5).fill(Color.secondary.opacity(0.12)))
                Button(copied == cmd ? "Copied" : "Copy") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(cmd, forType: .string)
                    copied = cmd
                }.font(.caption)
            }.padding(.top, 2)
        case .revealFile(let path):
            Button("Reveal in Finder") {
                NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)])
            }.font(.caption).padding(.top, 2)
        case .none:
            EmptyView()
        }
    }

    private func color(_ s: SSHCheckup.Severity) -> Color {
        switch s {
        case .high: return Theme.red
        case .medium: return .orange
        case .low: return .secondary
        case .opportunity: return Theme.accent
        case .ok: return Theme.green
        }
    }
}
