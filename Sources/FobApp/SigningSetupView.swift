import AppKit
import FobKit
import SwiftUI

/// The "Commit signing" window (opened from a key's ••• menu). Sets a fob key up for
/// Touch ID-gated git commit signing: shows the public key to register on your git
/// host and the git config (per-repo or global, with a one-click apply for global).
/// Signing is routed to fob via a `gpg.ssh.program` wrapper, so it never touches
/// SSH_AUTH_SOCK — other ssh agents and `git push` auth are unaffected. The one thing
/// it does directly is the namespace restriction — fob's own policy.
struct SigningSetupView: View {
    static let windowID = "fob-signing-setup"

    @EnvironmentObject var state: AppState
    @Environment(\.dismiss) private var dismiss

    private enum Scope { case repository, global }

    @State private var info: AppState.SigningInfo?
    @State private var gitOnly = false
    @State private var scope: Scope = .repository
    @State private var copied: String?
    @State private var gitConfigured = false
    @State private var gitError: String?

    private var keyName: String { state.signingSetupKey ?? "" }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 10) {
                FobKeyGlyph(size: 28)
                Text("Commit signing — \(keyName)").font(.title2.weight(.semibold))
            }
            if let info { content(info) } else { Text("Key unavailable.").foregroundStyle(.secondary) }
        }
        .padding(22)
        .frame(width: 500)
        .onAppear { load() }
        .onChange(of: state.signingSetupKey) { _ in load() }
    }

    private func load() {
        info = state.signingInfo(for: keyName)
        gitOnly = info?.gitOnly ?? false
        gitConfigured = false; gitError = nil; copied = nil
    }

    @ViewBuilder
    private func content(_ info: AppState.SigningInfo) -> some View {
        Text("Sign git commits with “\(keyName)” — Touch ID on each commit, and your host (GitHub, GitLab, …) shows *Verified*.")
            .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)

        Toggle(isOn: Binding(get: { gitOnly }, set: { gitOnly = $0; state.setGitSigningOnly($0, name: keyName) })) {
            Text("Restrict this key to git commits only").font(.callout)
        }
        .toggleStyle(.checkbox)

        step(1, "Register the public key on your git host as a Signing Key",
             "e.g. GitHub / GitLab → Settings → SSH keys (a separate entry from an Authentication key):")
        copyBox(info.pubLine, id: "pub")

        step(2, "Configure git to sign with this key", nil)
        Picker("Scope", selection: $scope) {
            Text("This repo").tag(Scope.repository)
            Text("All repos (global)").tag(Scope.global)
        }
        .pickerStyle(.segmented).labelsHidden().frame(width: 260)
        Text(scope == .repository
             ? "Recommended if you switch between git identities — run these **inside** the repo you want to sign. Doesn't touch your other repos."
             : "⚠️ Sets signing for **every** repo on this Mac. If you use multiple git accounts, use “This repo” instead.")
            .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        copyBox(info.gitConfigCommands(global: scope == .global).joined(separator: "\n"), id: "git")
        if scope == .global {
            HStack(spacing: 10) {
                Button(gitConfigured ? "Configured ✓" : "Configure git for me") {
                    if let err = state.configureGitSigning(pubPath: info.pubPath, signerProgram: info.signerProgram) { gitError = err; gitConfigured = false }
                    else { gitConfigured = true; gitError = nil }
                }
                .disabled(gitConfigured)
                if let gitError {
                    Text(gitError).font(.caption).foregroundStyle(.red).fixedSize(horizontal: false, vertical: true)
                } else if gitConfigured {
                    Text("git config --global set").font(.caption).foregroundStyle(.green)
                }
            }
        } else {
            Text("Copy and run these in the repo (the app can't target a repo for you).")
                .font(.caption).foregroundStyle(.tertiary)
        }

        Text("fob signs commits through a `gpg.ssh.program` wrapper, so it **won't** change `SSH_AUTH_SOCK` — your other ssh agents and `git push` auth are untouched.")
            .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        Text("Tip: a touch per commit adds up — pair with a reuse window (the key's ••• → Touch reuse) for rebases.")
            .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)

        HStack {
            Spacer()
            Button("Done") { dismiss() }.keyboardShortcut(.defaultAction).buttonStyle(.borderedProminent)
        }
    }

    private func step(_ n: Int, _ title: String, _ detail: String?) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text("\(n). \(title)").font(.callout.weight(.semibold))
            if let detail {
                Text(detail).font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private func copyBox(_ text: String, id: String) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Text(text).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                .padding(8).frame(maxWidth: .infinity, alignment: .leading)
                .background(RoundedRectangle(cornerRadius: 6).fill(Color.secondary.opacity(0.12)))
            Button(copied == id ? "Copied" : "Copy") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(text, forType: .string)
                copied = id
            }
        }
    }
}
