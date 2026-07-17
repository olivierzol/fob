import AppKit
import FobKit
import SwiftUI

/// The "Rotate" page (a pushed detail from the Keys tab). Replaces a commit-signing key with a
/// fresh Secure Enclave key and retires the old one, keeping the same name so gitconfig's
/// `user.signingkey = ~/.ssh/fob_<name>.pub` keeps working. Safe by design: the new key is
/// created and registered alongside the old one, and the old enclave key is destroyed only
/// after the new one is in place.
struct RotateKeyView: View {
    @EnvironmentObject var state: AppState

    @State private var biometry = true
    @State private var prep: AppState.RotationPrep?
    @State private var busy = false
    @State private var error: String?
    @State private var done = false
    @State private var copied = false

    private var name: String { state.rotateKey ?? "" }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 10) {
                FobKeyGlyph(size: 28)
                Text("Rotate — \(name)").font(.title2.weight(.semibold))
            }
            if done { doneView }
            else if let prep { registerView(prep) }
            else { startView }
            if let error {
                Label(error, systemImage: "exclamationmark.triangle.fill")
                    .font(.caption).foregroundStyle(.red).fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(22)
        .frame(maxWidth: .infinity, alignment: .leading)
        .onDisappear { if prep != nil && !done { state.cancelRotation(name: name) } } // drop an abandoned temp key
    }

    // Step 1 — create the replacement key.
    private var startView: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Creates a **new** Secure Enclave key to take over commit signing for “\(name)”, then retires this one. The new key is registered alongside the old, so nothing breaks mid-way — and it keeps the name “\(name)”, so your git config needs no changes.")
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

    // Step 2 — register the new key, then finalize.
    private func registerView(_ prep: AppState.RotationPrep) -> some View {
        VStack(alignment: .leading, spacing: 14) {
            step(1, "Register the new key on your git host as a Signing Key",
                 "Add this as a **Signing Key** (a new entry — keep the old one for now):")
            copyBox(prep.pubLine)
            step(2, "Swap to the new key", "Retires the old key and points signing at the new one. Local signing keeps working; your host shows *Verified* once the new key is registered.")
            HStack {
                Spacer()
                Button(busy ? "Rotating…" : "I registered it — rotate now") { finalize() }
                    .keyboardShortcut(.defaultAction).buttonStyle(.borderedProminent).disabled(busy)
            }
        }
    }

    private var doneView: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label("“\(name)” rotated to a fresh key", systemImage: "checkmark.seal.fill")
                .foregroundStyle(.green).font(.headline)
            Text("Signing now uses the new Secure Enclave key; the old one is destroyed. Its allowed_signers entry was updated, and your git config is unchanged.")
                .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            Text("**Last step:** remove the **old** signing key from your git host (it's now dead). The new key is already registered.")
                .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            HStack {
                Spacer()
                Button("Done") { state.configDetail = nil }.keyboardShortcut(.defaultAction).buttonStyle(.borderedProminent)
            }
        }
    }

    private func create() {
        busy = true
        switch state.prepareSigningRotation(name: name, requireBiometry: biometry) {
        case .ready(let p): prep = p; error = nil
        case .failed(let msg): error = msg
        }
        busy = false
    }

    private func finalize() {
        busy = true
        if let msg = state.finalizeSigningRotation(name: name) { error = msg }
        else { done = true; error = nil }
        busy = false
    }

    private func step(_ n: Int, _ title: String, _ detail: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text("\(n). \(title)").font(.callout.weight(.semibold))
            Text(.init(detail)).font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
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
