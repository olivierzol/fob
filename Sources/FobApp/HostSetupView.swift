import AppKit
import FobKit
import SwiftUI

/// The "Set up a host" window: generate a key, write the `~/.ssh/config` entry, and hand
/// the user the one command to run on the server. It deliberately does NOT run
/// `ssh-copy-id` itself — ssh reads the server password from a TTY the app doesn't have.
struct HostSetupView: View {
    static let windowID = "fob-host-setup"

    @EnvironmentObject var state: AppState
    @Environment(\.dismiss) private var dismiss
    @Environment(\.openWindow) private var openWindow

    private enum Mode: Hashable { case server, git, sign, bare }

    @State private var mode: Mode = .server
    @State private var alias = ""
    @State private var host = ""
    @State private var user = NSUserName()
    @State private var portText = "22"
    @State private var touchIDOnly = true
    @State private var error: String?
    @State private var result: AppState.HostSetupResult?
    @State private var pinMessage: String?
    @State private var pinned = false
    @State private var copied = false

    // Git-host mode.
    @State private var provider: HostSetup.GitProvider = .github
    @State private var gitAlias = ""
    @State private var customHost = ""

    // Sign / bare modes.
    @State private var keyName = ""
    @State private var bareResult: AppState.GeneratedKey?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 10) {
                FobKeyGlyph(size: 28)
                Text(headerTitle).font(.title2.weight(.semibold))
            }
            if let bareResult { bareResultView(bareResult) }
            else if let result { resultView(result) }
            else { formView }
        }
        .padding(22)
        .frame(width: 460)
    }

    // MARK: Form

    private var formView: some View {
        VStack(alignment: .leading, spacing: 14) {
            Picker("Kind", selection: $mode) {
                Text("Server").tag(Mode.server)
                Text("Git host").tag(Mode.git)
                Text("Sign commits").tag(Mode.sign)
                Text("Just a key").tag(Mode.bare)
            }
            .pickerStyle(.segmented).labelsHidden()

            switch mode {
            case .server: serverForm
            case .git: gitForm
            case .sign: signForm
            case .bare: bareForm
            }

            if let error {
                Label(error, systemImage: "exclamationmark.triangle.fill")
                    .font(.callout).foregroundStyle(.red).fixedSize(horizontal: false, vertical: true)
            }

            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button(mode == .server || mode == .git ? "Set up" : "Create") { setUp() }
                    .keyboardShortcut(.defaultAction).buttonStyle(.borderedProminent)
                    .disabled(!formValid)
            }
        }
    }

    private var serverForm: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Creates a Secure Enclave key and a `~/.ssh/config` entry. You'll run one command on the server to install the public key.")
                .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)

            Grid(alignment: .leading, horizontalSpacing: 10, verticalSpacing: 10) {
                field("Alias", "myserver", $alias)
                field("Host", "hostname or IP", $host)
                field("User", "username", $user)
                GridRow {
                    Text("Port").foregroundStyle(.secondary).gridColumnAlignment(.trailing)
                    HStack {
                        TextField("22", text: $portText).textFieldStyle(.roundedBorder).frame(width: 80)
                        Text("SSH port (default 22)").font(.caption).foregroundStyle(.secondary)
                    }
                }
            }

            Toggle("Touch ID only (currently enrolled fingerprints)", isOn: $touchIDOnly)
                .toggleStyle(.checkbox).font(.callout)
        }
    }

    private var gitForm: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Creates a Secure Enclave key and a `~/.ssh/config` entry for a git host. You'll add the public key to your account on the web (git hosts have no shell).")
                .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)

            Grid(alignment: .leading, horizontalSpacing: 10, verticalSpacing: 10) {
                GridRow {
                    Text("Provider").foregroundStyle(.secondary).gridColumnAlignment(.trailing)
                    Picker("Provider", selection: $provider) {
                        Text("GitHub").tag(HostSetup.GitProvider.github)
                        Text("GitLab").tag(HostSetup.GitProvider.gitlab)
                        Text("Bitbucket").tag(HostSetup.GitProvider.bitbucket)
                        Text("Codeberg").tag(HostSetup.GitProvider.codeberg)
                        Text("Other…").tag(HostSetup.GitProvider.other)
                    }
                    .labelsHidden().frame(maxWidth: 200, alignment: .leading)
                }
                if provider == .other {
                    field("Host", "git.example.com", $customHost)
                }
                field("Alias", "github-work", $gitAlias)
            }

            Text("The alias keeps multiple accounts separate (e.g. `github-work` vs `github-personal`) and is the key's name.")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)

            Toggle("Touch ID only (currently enrolled fingerprints)", isOn: $touchIDOnly)
                .toggleStyle(.checkbox).font(.callout)
        }
    }

    private var signForm: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("A dedicated Secure Enclave key for signing git commits. Next you'll register it on your git host as a **Signing Key** and configure git — Touch ID on each commit, no on-disk key to steal.")
                .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            Grid(alignment: .leading, horizontalSpacing: 10, verticalSpacing: 10) {
                field("Key name", "commit-signing", $keyName)
            }
            Toggle("Touch ID only (currently enrolled fingerprints)", isOn: $touchIDOnly)
                .toggleStyle(.checkbox).font(.callout)
        }
    }

    private var bareForm: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Just creates the Secure Enclave key. You'll add its public key wherever you need it (a server, a git host, or commit signing). Advanced — the guided options above wire it up for you.")
                .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            Grid(alignment: .leading, horizontalSpacing: 10, verticalSpacing: 10) {
                field("Key name", "mykey", $keyName)
            }
            Toggle("Touch ID only (currently enrolled fingerprints)", isOn: $touchIDOnly)
                .toggleStyle(.checkbox).font(.callout)
        }
    }

    private var headerTitle: String {
        if result != nil { return "Almost done" }
        if bareResult != nil { return "Key created" }
        return "New key"
    }

    private func bareResultView(_ gen: AppState.GeneratedKey) -> some View {
        VStack(alignment: .leading, spacing: 14) {
            Label("Key “\(gen.name)” created", systemImage: "checkmark.seal.fill")
                .foregroundStyle(.green).font(.headline)
            Text("Add this public key wherever you'll use it — a server's `authorized_keys`, or a git host (as an Authentication or a Signing key):")
                .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            commandBox(gen.pubLine)
            HStack {
                Spacer()
                Button("Done") { dismiss() }.keyboardShortcut(.defaultAction).buttonStyle(.borderedProminent)
            }
        }
    }

    private func providerHost() -> String {
        switch provider {
        case .github: return "github.com"
        case .gitlab: return "gitlab.com"
        case .bitbucket: return "bitbucket.org"
        case .codeberg: return "codeberg.org"
        case .other: return customHost.trimmingCharacters(in: .whitespaces)
        }
    }

    private func field(_ label: String, _ placeholder: String, _ text: Binding<String>) -> some View {
        GridRow {
            Text(label).foregroundStyle(.secondary).gridColumnAlignment(.trailing)
            TextField(placeholder, text: text).textFieldStyle(.roundedBorder)
        }
    }

    private var formValid: Bool {
        switch mode {
        case .git:
            let hostOK = provider != .other || !customHost.trimmingCharacters(in: .whitespaces).isEmpty
            return hostOK && !gitAlias.trimmingCharacters(in: .whitespaces).isEmpty
        case .sign, .bare:
            return !keyName.trimmingCharacters(in: .whitespaces).isEmpty
        case .server:
            return [alias, host, user].allSatisfy { !$0.trimmingCharacters(in: .whitespaces).isEmpty }
        }
    }

    /// Create/reuse the key for the sign/bare modes; returns the trimmed name on success.
    private func createKeyForName() -> String? {
        let name = keyName.trimmingCharacters(in: .whitespaces)
        guard KeyStore.isValidName(name) else {
            error = "Invalid key name — letters, digits, '.', '_', '-' (not starting with '-')."
            return nil
        }
        state.generate(name: name, requireBiometry: touchIDOnly)
        if let err = state.actionError { error = err; return nil }
        error = nil
        return name
    }

    private func setUp() {
        switch mode {
        case .git: setUpGit(); return
        case .sign:
            guard let name = createKeyForName() else { return }
            state.signingSetupKey = name
            state.signingSetupHost = nil
            dismiss()
            NSApp.activate(ignoringOtherApps: true)
            openWindow(id: SigningSetupView.windowID)
            return
        case .bare:
            if createKeyForName() != nil { bareResult = state.lastGenerated }
            return
        case .server:
            break
        }
        let trimmedPort = portText.trimmingCharacters(in: .whitespaces)
        guard let port = Int(trimmedPort.isEmpty ? "22" : trimmedPort) else {
            error = "Port must be a number (1–65535)."; return
        }
        switch state.addHost(alias: alias, host: host, user: user, port: port, requireBiometry: touchIDOnly) {
        case .success(let r): result = r; error = nil
        case .failure(let message): error = message
        }
    }

    /// Create the key + git `Host` block, then hand off to the per-host git flow
    /// (add-to-account → verify → pin/sign) in MigrateHostView.
    private func setUpGit() {
        let a = gitAlias.trimmingCharacters(in: .whitespaces)
        if let err = state.addGitHost(alias: a, hostName: providerHost(), requireBiometry: touchIDOnly) {
            error = err; return
        }
        error = nil
        state.migrateAlias = a
        dismiss()
        NSApp.activate(ignoringOtherApps: true)
        openWindow(id: MigrateHostView.windowID)
    }

    // MARK: Result

    private func resultView(_ r: AppState.HostSetupResult) -> some View {
        VStack(alignment: .leading, spacing: 14) {
            Label("Key “\(r.alias)” is ready\(r.configAdded ? " · added to ~/.ssh/config" : r.alreadyConfigured ? " · ~/.ssh/config already had it" : "")",
                  systemImage: "checkmark.seal.fill")
                .foregroundStyle(.green).font(.headline)

            step(1, "Install the key on the server", "Run this in Terminal and enter your server password:")
            commandBox(r.copyCommand)

            step(2, "Connect", "Touch ID will prompt:")
            codeLine("ssh \(r.alias)")

            step(3, "Pin the key to this host", "After your first connection, so \(r.alias) only works for \(r.host):")
            HStack(spacing: 10) {
                Button(pinned ? "Pinned ✓" : "Pin \(r.alias) → \(r.host)") { pin(r) }.disabled(pinned)
                if let pinMessage {
                    Text(pinMessage).font(.caption)
                        .foregroundStyle(pinned ? .green : .orange)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }

            HStack {
                Spacer()
                Button("Done") { dismiss() }.keyboardShortcut(.defaultAction).buttonStyle(.borderedProminent)
            }
        }
    }

    private func pin(_ r: AppState.HostSetupResult) {
        if let message = state.pinHost(alias: r.alias, host: r.host, port: r.port) {
            pinMessage = message; pinned = false
        } else {
            pinned = true; pinMessage = "Pinned — \(r.alias) will refuse any other host."
        }
    }

    // MARK: Small building blocks

    private func step(_ n: Int, _ title: String, _ detail: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text("\(n). \(title)").font(.callout.weight(.semibold))
            Text(detail).font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        }
    }

    private func commandBox(_ text: String) -> some View {
        HStack(spacing: 8) {
            Text(text).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                .padding(8).frame(maxWidth: .infinity, alignment: .leading)
                .background(RoundedRectangle(cornerRadius: 6).fill(Color.secondary.opacity(0.12)))
            Button(copied ? "Copied" : "Copy") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(text, forType: .string)
                copied = true
            }
        }
    }

    private func codeLine(_ text: String) -> some View {
        Text(text).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
            .padding(8).frame(maxWidth: .infinity, alignment: .leading)
            .background(RoundedRectangle(cornerRadius: 6).fill(Color.secondary.opacity(0.12)))
    }
}
