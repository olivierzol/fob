import AppKit
import FobKit
import SwiftUI

/// The "Rotate" page (a pushed detail from the Keys tab). Replaces a key with a fresh Secure
/// Enclave key and retires the old one, keeping the same name so every reference keeps working
/// (ssh-config `IdentityFile` / gitconfig `user.signingkey` = fob_<name>.pub, now the new key).
/// Role-aware: a signing key just re-registers; an auth key (server or git host) installs the
/// new key alongside the old, verifies it, then swaps. Safe by design — the old enclave key is
/// destroyed only after the new one is proven and in place.
struct RotateKeyView: View {
    @EnvironmentObject var state: AppState

    private enum Role { case signing, server, git }

    @State private var candidate: AppState.MigrationCandidate?
    @State private var biometry = true
    @State private var prep: AppState.RotationPrep?
    @State private var install: InstallUI?
    @State private var addedOnWeb = false
    @State private var verified: Bool?
    @State private var verifyNote: String?
    @State private var busy = false
    @State private var error: String?
    @State private var done = false
    @State private var copied = false

    private enum InstallUI { case done(String); case manual(command: String, detail: String) }

    private var name: String { state.rotateKey ?? "" }
    private var role: Role {
        guard let c = candidate else { return .signing }
        return c.isGitHost ? .git : .server
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 10) {
                FobKeyGlyph(size: 28)
                Text("Rotate — \(name)").font(.title2.weight(.semibold))
            }
            if done { doneView }
            else if prep == nil { startView }
            else {
                switch role {
                case .signing: signingFlow
                case .server: serverFlow
                case .git: gitFlow
                }
            }
            if let error {
                Label(error, systemImage: "exclamationmark.triangle.fill")
                    .font(.caption).foregroundStyle(.red).fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(22)
        .frame(maxWidth: .infinity, alignment: .leading)
        .onAppear { candidate = state.migrationCandidate(alias: name) }
        .onDisappear { if prep != nil && !done { state.cancelRotation(name: name) } } // drop an abandoned temp key
    }

    // MARK: Step 1 — create the replacement key

    private var startView: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(.init(startBlurb))
                .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            Toggle("Touch ID only (currently enrolled fingerprints)", isOn: $biometry)
                .toggleStyle(.checkbox).font(.callout)
            HStack {
                Spacer()
                Button(busy ? "Creating…" : "Create replacement key") { create() }
                    .keyboardShortcut(.defaultAction).buttonStyle(.borderedProminent).disabled(busy)
            }
        }
    }

    private var startBlurb: String {
        let base = "Creates a **new** Secure Enclave key to take over for “\(name)”, then retires this one. It's added alongside the old key (no lockout) and keeps the name “\(name)”, so your config needs no changes."
        switch role {
        case .signing: return base + " You'll register the new key on your git host as a Signing Key."
        case .server:  return base + " fob installs the new key on the server using your current key."
        case .git:     return base + " You'll add the new key to your git host as an Authentication Key."
        }
    }

    // MARK: Signing flow (register → swap)

    private var signingFlow: some View {
        VStack(alignment: .leading, spacing: 14) {
            step(1, "Register the new key as a Signing Key",
                 "Add this on your git host as a **Signing Key** (a new entry — keep the old one for now):")
            copyBox(prep!.pubLine)
            step(2, "Swap to the new key", "Retires the old key; signing points at the new one. Verifies locally once it's in allowed_signers; your host shows *Verified* once you've registered it.")
            finalizeButton
        }
    }

    // MARK: Server flow (install via old key → verify → swap)

    private var serverFlow: some View {
        VStack(alignment: .leading, spacing: 14) {
            step(1, "Install the new key on the server") {
                switch install {
                case nil:
                    Button(busy ? "Installing…" : "Install (using your current key)") { runInstall() }
                        .disabled(busy).buttonStyle(.borderedProminent)
                case .done(let msg):
                    Label(msg, systemImage: "checkmark.circle.fill").font(.callout).foregroundStyle(.green)
                case .manual(let cmd, let detail):
                    Text(.init(HostSetup.installFailureHint(detail)))
                        .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                    copyBox(cmd)
                    HStack {
                        Button("I ran it — continue") { install = .done("Installed manually.") }
                        Button(busy ? "Retrying…" : "Retry") { runInstall() }.disabled(busy)
                    }
                }
            }
            if installedOK {
                verifyStep
                if verified == true { swapStep }
            }
        }
    }

    // MARK: Git-host flow (register on web → verify → swap)

    private var gitFlow: some View {
        VStack(alignment: .leading, spacing: 14) {
            step(1, "Add the new key to \(candidate?.provider.displayName ?? "your git host")") {
                Text("Add this as an **Authentication Key** (a new entry — keep the old one for now):")
                    .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                copyBox(prep!.pubLine)
                HStack {
                    if let url = candidate?.settingsURL {
                        Button("Open \(candidate?.provider.displayName ?? "provider") SSH keys") { state.openSettings(url) }
                    }
                    Button(addedOnWeb ? "Added ✓" : "I added it") { addedOnWeb = true }.disabled(addedOnWeb)
                }
            }
            if addedOnWeb {
                verifyStep
                if verified == true { swapStep }
            }
        }
    }

    private var verifyStep: some View {
        step(2, "Verify the new key (Touch ID)") {
            Button(busy ? "Connecting…" : (verified == true ? "Re-verify" : "Verify new key")) { runVerify() }
                .disabled(busy).buttonStyle(.borderedProminent)
            if let verifyNote {
                Label(verifyNote, systemImage: verified == true ? "checkmark.seal.fill" : "exclamationmark.triangle.fill")
                    .font(.caption).foregroundStyle(verified == true ? .green : .red)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private var swapStep: some View {
        step(3, "Swap to the new key", "Retires the old key. Its config entry is unchanged — it just points at the new key now.") {
            finalizeButton
        }
    }

    private var finalizeButton: some View {
        HStack {
            Spacer()
            Button(busy ? "Rotating…" : "Swap & retire old key") { finalize() }
                .keyboardShortcut(.defaultAction).buttonStyle(.borderedProminent).disabled(busy)
        }
    }

    // MARK: Done

    private var doneView: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label("“\(name)” rotated to a fresh key", systemImage: "checkmark.seal.fill")
                .foregroundStyle(.green).font(.headline)
            Text(.init(doneBlurb))
                .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            HStack {
                Spacer()
                Button("Done") { state.configDetail = nil }.keyboardShortcut(.defaultAction).buttonStyle(.borderedProminent)
            }
        }
    }

    private var doneBlurb: String {
        let base = "The new Secure Enclave key is in place under the same name; the old one is destroyed and your config is unchanged."
        switch role {
        case .signing: return base + " **Last step:** remove the old signing key from your git host."
        case .server:  return base + " **Last step:** remove the old key from the server's `~/.ssh/authorized_keys`."
        case .git:     return base + " **Last step:** remove the old key from your git host's SSH keys."
        }
    }

    // MARK: Actions

    private var installedOK: Bool { if case .done = install { return true }; return false }

    private func create() {
        busy = true
        switch state.prepareRotation(name: name, requireBiometry: biometry) {
        case .ready(let p): prep = p; error = nil
        case .failed(let msg): error = msg
        }
        busy = false
    }

    private func runInstall() {
        guard let c = candidate, let prep else { return }
        busy = true
        Task {
            switch await state.installRotationKeyOnServer(c, tempPubLine: prep.pubLine) {
            case .installed: install = .done("New key installed on \(c.host).")
            case .alreadyPresent: install = .done("New key already on \(c.host).")
            case .needsManual(let cmd, let detail): install = .manual(command: cmd, detail: detail)
            case .failed(let msg): error = msg
            }
            busy = false
        }
    }

    private func runVerify() {
        guard let c = candidate else { return }
        busy = true
        Task {
            let r = await state.verifyRotationKey(c)
            verified = r.ok; verifyNote = r.message
            busy = false
        }
    }

    private func finalize() {
        busy = true
        if let msg = state.finalizeRotation(name: name) { error = msg }
        else { done = true; error = nil }
        busy = false
    }

    // MARK: Building blocks

    private func step(_ n: Int, _ title: String, _ detail: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text("\(n). \(title)").font(.callout.weight(.semibold))
            Text(.init(detail)).font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        }
    }

    @ViewBuilder
    private func step<Content: View>(_ n: Int, _ title: String, _ detail: String? = nil,
                                     @ViewBuilder _ content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            VStack(alignment: .leading, spacing: 2) {
                Text("\(n). \(title)").font(.callout.weight(.semibold))
                if let detail {
                    Text(.init(detail)).font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
            }
            content()
        }
    }

    private func copyBox(_ text: String) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Text(text).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(8)
                .background(RoundedRectangle(cornerRadius: 6).fill(Color.secondary.opacity(0.12)))
            Button(copied ? "Copied" : "Copy") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(text, forType: .string)
                copied = true
            }
        }
    }
}
