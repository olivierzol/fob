import AppKit
import FobKit
import SwiftUI

/// The per-host migration flow (opened from MigrateView). Staged, and safe by design:
/// install the fob key on the server (using your existing key) → preview + back up +
/// apply the ~/.ssh/config edit → verify fob works with Touch ID → pin, and only then
/// optionally retire the old key. The old key stays active until Retire, so there's no
/// lockout at any step.
struct MigrateHostView: View {
    static let windowID = "fob-migrate-host"

    @EnvironmentObject var state: AppState
    @Environment(\.dismiss) private var dismiss
    @Environment(\.openWindow) private var openWindow

    @State private var candidate: AppState.MigrationCandidate?
    @State private var alreadyMigrated = false
    @State private var biometry = true
    @State private var busy = false

    // Progressive stage results.
    @State private var install: InstallUI?
    @State private var applied: Status?
    @State private var verified: Status?
    @State private var pinned = false
    @State private var pinNote: String?
    @State private var retired: Status?

    // Git-host flow state.
    @State private var gitPub: String?          // exported public line, once prepared
    @State private var gitPrepError: String?
    @State private var addedToAccount = false

    private enum InstallUI {
        case done(String)              // green summary
        case manual(command: String, detail: String) // fallback command + why headless failed
        case error(String)
    }
    private struct Status { let ok: Bool; let text: String }

    private var alias: String { state.migrateAlias ?? "" }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 10) {
                FobKeyGlyph(size: 28)
                Text("Migrate “\(alias)” to fob").font(.title2.weight(.semibold))
            }
            if let candidate { content(candidate) }
            else { Text("This host is no longer in ~/.ssh/config.").foregroundStyle(.secondary) }
        }
        .padding(22)
        .frame(width: 520)
        .onAppear(perform: load)
        .onChange(of: state.migrateAlias) { _ in load() }
    }

    private func load() {
        candidate = state.migrationCandidate(alias: alias)
        alreadyMigrated = candidate?.usesFob ?? false
        install = nil; applied = nil; verified = nil
        pinned = state.keys.first { $0.name == alias }?.isPinned ?? false
        pinNote = nil; retired = nil; busy = false
        gitPub = nil; gitPrepError = nil; addedToAccount = false
    }

    @ViewBuilder
    private func content(_ c: AppState.MigrationCandidate) -> some View {
        if c.isGitHost {
            gitHostContent(c)
        } else if alreadyMigrated {
            migratedContent(c)
        } else {
            freshContent(c)
        }
        HStack {
            Spacer()
            Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
        }
    }

    // MARK: Git host flow (add key on the web → config → verify via ssh -T → pin/retire/sign)

    @ViewBuilder
    private func gitHostContent(_ c: AppState.MigrationCandidate) -> some View {
        Text("Adds a fob key to \(c.provider.displayName) **alongside** your existing key. You add the public key on the web (git hosts have no shell), then fob signs every use with Touch ID.")
            .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)

        // Step 1 — put the key on the account
        step(1, "Add the key to \(c.provider.displayName)") {
            if gitPub == nil {
                Toggle("Touch ID only (currently enrolled fingerprints)", isOn: $biometry)
                    .toggleStyle(.checkbox).font(.callout)
                Button(busy ? "Preparing…" : "Create key & open \(c.provider.displayName)") { prepareGit(c) }
                    .disabled(busy).buttonStyle(.borderedProminent)
                if let gitPrepError {
                    Label(gitPrepError, systemImage: "exclamationmark.triangle.fill")
                        .font(.caption).foregroundStyle(.red).fixedSize(horizontal: false, vertical: true)
                }
            } else {
                Text("Paste this as an **Authentication Key** (Key type: Authentication):")
                    .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                copyBox(gitPub!)
                if c.settingsURL != nil {
                    Text("⚠︎ Make sure your browser is signed into the right \(c.provider.displayName) account.")
                        .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
                HStack {
                    if let url = c.settingsURL {
                        Button("Open \(c.provider.displayName) SSH keys") { state.openSettings(url) }
                    }
                    Button(addedToAccount ? "Added ✓" : "I added it") { addedToAccount = true }
                        .disabled(addedToAccount)
                }
            }
        }

        // Step 2 — config (fob alongside old key; skipped if already routed)
        if addedToAccount {
            step(2, "Update ~/.ssh/config") {
                if state.configDiff(alias: alias) != nil && applied?.ok != true {
                    diffPreview()
                    Button("Back up & apply") { runApply() }.buttonStyle(.borderedProminent).disabled(busy)
                } else if applied?.ok == true {
                    Label(applied!.text, systemImage: "checkmark.circle.fill").font(.callout).foregroundStyle(.green)
                } else {
                    Text("Already routed through fob — nothing to change.").font(.caption).foregroundStyle(.secondary)
                }
                if let applied, !applied.ok {
                    Label(applied.text, systemImage: "exclamationmark.triangle.fill")
                        .font(.caption).foregroundStyle(.red).fixedSize(horizontal: false, vertical: true)
                }
            }
        }

        // Step 3 — verify with ssh -T
        if addedToAccount && (applied?.ok == true || state.configDiff(alias: alias) == nil) {
            step(3, "Verify fob works (Touch ID)") {
                Button(busy ? "Connecting…" : "Verify \(alias)") { runVerifyGit(c) }
                    .disabled(busy).buttonStyle(.borderedProminent)
                if let verified {
                    Label(verified.text, systemImage: verified.ok ? "checkmark.seal.fill" : "exclamationmark.triangle.fill")
                        .font(.caption).foregroundStyle(verified.ok ? .green : .red)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }

        // Step 4 — pin + retire + sign hop
        if verified?.ok == true {
            step(4, "Lock it down") {
                HStack(spacing: 10) {
                    Button(pinned ? "Pinned ✓" : "Pin \(alias) → \(c.host)") { runPin(c) }.disabled(pinned)
                    if let pinNote {
                        Text(pinNote).font(.caption).foregroundStyle(pinned ? .green : .orange)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                if !c.oldIdentityFiles.isEmpty {
                    HStack(spacing: 10) {
                        Button(retired?.ok == true ? "Retired ✓" : "Retire old key") { runRetire() }
                            .disabled(retired?.ok == true || busy)
                        if let retired {
                            Text(retired.text).font(.caption)
                                .foregroundStyle(retired.ok ? .green : .red).fixedSize(horizontal: false, vertical: true)
                        }
                    }
                }
                Divider().padding(.vertical, 2)
                Text("Signing is a **separate** key entry on \(c.provider.displayName) — this sets it up (add the same key again as a Signing Key).")
                    .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                Button("Sign commits with this key →") {
                    state.signingSetupKey = alias
                    state.signingSetupHost = c.host
                    NSApp.activate(ignoringOtherApps: true)
                    openWindow(id: SigningSetupView.windowID)
                }
            }
        }
    }

    private func prepareGit(_ c: AppState.MigrationCandidate) {
        busy = true
        switch state.prepareGitKey(c, requireBiometry: biometry) {
        case .ok(let pub):
            gitPub = pub; gitPrepError = nil
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(pub, forType: .string)
            if let url = c.settingsURL { state.openSettings(url) }
        case .error(let msg):
            gitPrepError = msg
        }
        busy = false
    }

    private func runVerifyGit(_ c: AppState.MigrationCandidate) {
        busy = true
        Task {
            let result = await state.verifyGitHost(c)
            verified = Status(ok: result.ok, text: result.message)
            busy = false
        }
    }

    /// Re-entry view for a host already routed through fob — jump straight to verify
    /// (optional reassurance) and retire, which is easy to miss on the first pass.
    @ViewBuilder
    private func migratedContent(_ c: AppState.MigrationCandidate) -> some View {
        Label("“\(alias)” already routes through fob. Your old key stays a working fallback until you retire it — do that whenever you're ready.",
              systemImage: "checkmark.seal.fill")
            .font(.callout).foregroundStyle(.green).fixedSize(horizontal: false, vertical: true)
        verifyStep(c, 1, optional: true)
        lockdownStep(c, 2)
    }

    @ViewBuilder
    private func freshContent(_ c: AppState.MigrationCandidate) -> some View {
        Text("Adds a fob key **alongside** your existing key on `\(c.destination)`. Your current key keeps working until you choose to retire it below.")
            .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)

        // Step 1 — install on the server
        step(1, "Install the fob key on the server") {
            if install == nil {
                Toggle("Touch ID only (currently enrolled fingerprints)", isOn: $biometry)
                    .toggleStyle(.checkbox).font(.callout)
            }
            switch install {
            case nil, .error:
                if case .error(let msg) = install {
                    Label(msg, systemImage: "exclamationmark.triangle.fill")
                        .font(.caption).foregroundStyle(.red).fixedSize(horizontal: false, vertical: true)
                }
                Button(busy ? "Installing…" : "Migrate \(alias)") { runInstall(c) }
                    .disabled(busy).buttonStyle(.borderedProminent)
            case .done(let msg):
                Label(msg, systemImage: "checkmark.circle.fill").font(.callout).foregroundStyle(.green)
            case .manual(let cmd, let detail):
                Text(HostSetup.installFailureHint(detail))
                    .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                copyBox(cmd)
                if !detail.isEmpty {
                    DisclosureGroup("Why it failed") {
                        Text(detail)
                            .font(.system(.caption2, design: .monospaced))
                            .foregroundStyle(.secondary).textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(8)
                            .background(RoundedRectangle(cornerRadius: 6).fill(Color.secondary.opacity(0.1)))
                    }
                    .font(.caption)
                }
                HStack {
                    Button("Open in Terminal") { openInTerminal(cmd) }
                    Button(busy ? "Checking…" : "Retry headless") { runInstall(c) }.disabled(busy)
                    Button("I ran it — continue") { install = .done("Installed manually.") }
                }
            }
        }

        // Step 2 — config edit (diff + backup + apply)
        if canShowApply {
            step(2, "Update ~/.ssh/config") {
                if let (_, _) = state.configDiff(alias: alias), applied?.ok != true {
                    diffPreview()
                    Button("Back up & apply") { runApply() }.buttonStyle(.borderedProminent).disabled(busy)
                } else if applied?.ok == true {
                    Label(applied!.text, systemImage: "checkmark.circle.fill").font(.callout).foregroundStyle(.green)
                } else {
                    Text("Already routed through fob — nothing to change.").font(.caption).foregroundStyle(.secondary)
                }
                if let applied, !applied.ok {
                    Label(applied.text, systemImage: "exclamationmark.triangle.fill")
                        .font(.caption).foregroundStyle(.red).fixedSize(horizontal: false, vertical: true)
                }
            }
        }

        // Step 3 — verify
        if canShowVerify { verifyStep(c, 3, optional: false) }

        // Step 4 — pin + retire (only after a green verify)
        if verified?.ok == true { lockdownStep(c, 4) }
    }

    @ViewBuilder
    private func verifyStep(_ c: AppState.MigrationCandidate, _ n: Int, optional: Bool) -> some View {
        step(n, optional ? "Re-verify fob works (optional)" : "Verify fob works (Touch ID)") {
            Button(busy ? "Connecting…" : "Verify \(alias)") { runVerify(c) }
                .disabled(busy).buttonStyle(.borderedProminent)
            if let verified {
                Label(verified.text, systemImage: verified.ok ? "checkmark.seal.fill" : "exclamationmark.triangle.fill")
                    .font(.caption).foregroundStyle(verified.ok ? .green : .red)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    @ViewBuilder
    private func lockdownStep(_ c: AppState.MigrationCandidate, _ n: Int) -> some View {
        step(n, "Lock it down") {
            HStack(spacing: 10) {
                Button(pinned ? "Pinned ✓" : "Pin \(alias) → \(c.host)") { runPin(c) }.disabled(pinned)
                if let pinNote {
                    Text(pinNote).font(.caption).foregroundStyle(pinned ? .green : .orange)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            if !c.oldIdentityFiles.isEmpty {
                Divider().padding(.vertical, 2)
                Text("Comment out the old key in ~/.ssh/config now that fob is verified. It stays on the server's authorized_keys until you remove it there.")
                    .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                HStack(spacing: 10) {
                    Button(retired?.ok == true ? "Retired ✓" : "Retire old key") { runRetire() }
                        .disabled(retired?.ok == true || busy)
                    if let retired {
                        Text(retired.text).font(.caption)
                            .foregroundStyle(retired.ok ? .green : .red).fixedSize(horizontal: false, vertical: true)
                    }
                }
            } else {
                Text("No local old key left to retire. If one is still on the server's authorized_keys, remove it there.")
                    .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    // MARK: Stage gating

    private var installedOK: Bool {
        if case .done = install { return true }
        return false
    }
    private var canShowApply: Bool { installedOK }
    private var canShowVerify: Bool {
        installedOK && (applied?.ok == true || state.configDiff(alias: alias) == nil)
    }

    // MARK: Actions

    private func runInstall(_ c: AppState.MigrationCandidate) {
        busy = true
        Task {
            let outcome = await state.createAndInstall(c, requireBiometry: biometry)
            switch outcome {
            case .installed: install = .done("fob key installed on \(c.host).")
            case .alreadyPresent: install = .done("fob key already on \(c.host).")
            case .needsManual(let cmd, let detail): install = .manual(command: cmd, detail: detail)
            case .failed(let msg): install = .error(msg)
            }
            busy = false
        }
    }

    private func runApply() {
        busy = true
        switch state.applyConfigMigration(alias: alias) {
        case .ok(let backup): applied = Status(ok: true, text: "Applied · backup \(backup)")
        case .error(let msg): applied = Status(ok: false, text: msg)
        }
        busy = false
    }

    private func runVerify(_ c: AppState.MigrationCandidate) {
        busy = true
        Task {
            if let msg = await state.verifyMigration(c) {
                verified = Status(ok: false, text: msg)
            } else {
                verified = Status(ok: true, text: "fob works for \(c.destination). Your old key is still a fallback.")
            }
            busy = false
        }
    }

    private func runPin(_ c: AppState.MigrationCandidate) {
        if let msg = state.pinHost(alias: c.alias, host: c.host, port: c.port) {
            pinNote = msg; pinned = false
        } else {
            pinned = true; pinNote = "Pinned — \(c.alias) will refuse any other host."
        }
    }

    private func runRetire() {
        switch state.retireOldKey(alias: alias) {
        case .ok(let backup): retired = Status(ok: true, text: "Old key commented out · backup \(backup)")
        case .error(let msg): retired = Status(ok: false, text: msg)
        }
    }

    // MARK: Diff preview

    @ViewBuilder
    private func diffPreview() -> some View {
        if let (old, new) = state.configDiff(alias: alias) {
            let lines = TextDiff.lines(old: old, new: new)
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    ForEach(Array(lines.enumerated()), id: \.offset) { _, line in
                        diffRow(line)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .frame(maxHeight: 180)
            .padding(8)
            .background(RoundedRectangle(cornerRadius: 6).fill(Color.secondary.opacity(0.1)))
        }
    }

    private func diffRow(_ line: TextDiff.Line) -> some View {
        let (prefix, color): (String, Color) = {
            switch line.kind {
            case .added: return ("+", .green)
            case .removed: return ("-", .red)
            case .same: return (" ", .secondary)
            }
        }()
        return Text("\(prefix) \(line.text)")
            .font(.system(.caption2, design: .monospaced))
            .foregroundStyle(line.kind == .same ? Color.secondary : color)
            .frame(maxWidth: .infinity, alignment: .leading)
            .textSelection(.enabled)
    }

    // MARK: Building blocks

    @ViewBuilder
    private func step<Content: View>(_ n: Int, _ title: String, @ViewBuilder _ content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("\(n). \(title)").font(.callout.weight(.semibold))
            content()
        }
    }

    private func copyBox(_ text: String) -> some View {
        HStack(spacing: 8) {
            Text(text).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                .padding(8).frame(maxWidth: .infinity, alignment: .leading)
                .background(RoundedRectangle(cornerRadius: 6).fill(Color.secondary.opacity(0.12)))
            Button("Copy") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(text, forType: .string)
            }
        }
    }

    /// Open Terminal.app running `command`. The command is fob-built from validated
    /// tokens (alias/path), so there's no untrusted interpolation.
    private func openInTerminal(_ command: String) {
        let escaped = command.replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
        let script = "tell application \"Terminal\" to do script \"\(escaped)\""
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        process.arguments = ["-e", script]
        try? process.run()
    }
}
