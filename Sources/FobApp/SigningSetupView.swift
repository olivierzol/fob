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

    @State private var info: AppState.SigningInfo?
    @State private var gitOnly = false
    @State private var identities: [AppState.GitIdentity] = []
    @State private var scope: AppState.SigningScope = .repository
    @State private var copied: String?
    @State private var gitConfigured = false
    @State private var gitError: String?
    @State private var alreadyConfigured = false

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
        identities = state.discoverGitIdentities()
        // Multi-account: default to the first identity (writing --global would clobber
        // their setup). Single-account: default to per-repo (safe, universal).
        scope = identities.first.map { .identity($0) } ?? .repository
        gitConfigured = false; gitError = nil; copied = nil
        refreshConfigured()
    }

    /// Is the selected scope already signing with this key? (Answers "is it already set?")
    private func refreshConfigured() {
        alreadyConfigured = info.map { state.signingConfigured(pubPath: $0.pubPath, scope: scope) } ?? false
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
             "Key type: **Signing Key** — a separate entry from an Authentication key (GitHub keeps the two apart; on GitLab one key can be marked for both).")
        copyBox(info.pubLine, id: "pub")
        if let host = state.signingSetupHost, let url = HostSetup.sshKeySettingsURL(forHost: host) {
            Button("Open \(HostSetup.gitProvider(forHost: host).displayName) SSH keys") { state.openSettings(url) }
                .font(.callout)
        }

        step(2, "Configure git to sign with this key", nil)
        Picker("Where", selection: $scope) {
            ForEach(identities) { id in
                Text(identityLabel(id)).tag(AppState.SigningScope.identity(id))
            }
            Text("This repo only").tag(AppState.SigningScope.repository)
            Text(identities.isEmpty ? "All repos (global)" : "All repos (global) ⚠︎")
                .tag(AppState.SigningScope.global)
        }
        .pickerStyle(.menu).labelsHidden().frame(maxWidth: 320, alignment: .leading)
        .onChange(of: scope) { _ in gitConfigured = false; gitError = nil; refreshConfigured() }
        Text(.init(scopeCaption)).font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        if alreadyConfigured && !gitConfigured {
            Label("Already signing with this key here — nothing to do.", systemImage: "checkmark.seal.fill")
                .font(.caption).foregroundStyle(.green)
        }
        copyBox(info.gitConfigCommands(scope: scope).joined(separator: "\n"), id: "git")
        if scope == .repository {
            Text("Copy and run these inside the repo (the app can't target a repo for you).")
                .font(.caption).foregroundStyle(.tertiary)
        } else {
            HStack(spacing: 10) {
                Button(configureButtonTitle) {
                    if let err = state.configureGitSigning(pubPath: info.pubPath, signerProgram: info.signerProgram, scope: scope) {
                        gitError = err; gitConfigured = false
                    } else { gitConfigured = true; gitError = nil }
                }
                .disabled(gitConfigured)
                if let gitError {
                    Text(gitError).font(.caption).foregroundStyle(.red).fixedSize(horizontal: false, vertical: true)
                } else if gitConfigured {
                    Text("written ✓").font(.caption).foregroundStyle(.green)
                }
            }
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

    private var configureButtonTitle: String {
        if gitConfigured { return "Configured ✓" }
        return alreadyConfigured ? "Re-apply" : "Configure git for me"
    }

    private func identityLabel(_ id: AppState.GitIdentity) -> String {
        let who = id.email ?? id.conditionLabel
        return "\(who) — \((id.path as NSString).abbreviatingWithTildeInPath)"
    }

    private var scopeCaption: String {
        switch scope {
        case .identity(let id):
            return "Signs commits in \(id.conditionLabel) repos, via \((id.path as NSString).abbreviatingWithTildeInPath). Your other git identities are untouched."
        case .repository:
            return "Run these **inside** the repo you want to sign. Doesn't touch anything else."
        case .global:
            return identities.isEmpty
                ? "Sets signing for every repo on this Mac."
                : "⚠️ Every repo on this Mac — this overrides your per-identity setup and would sign other accounts with this key. Prefer an identity above."
        }
    }

    private func step(_ n: Int, _ title: String, _ detail: String?) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text("\(n). \(title)").font(.callout.weight(.semibold))
            if let detail {
                Text(.init(detail)).font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
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
