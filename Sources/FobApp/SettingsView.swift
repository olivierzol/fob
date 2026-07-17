import AppKit
import FobKit
import SwiftUI

/// The Settings page: app-level preferences that used to live in the popover footer.
struct SettingsView: View {
    @EnvironmentObject var state: AppState
    @State private var checking = false

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 10) {
                FobKeyGlyph(size: 28)
                Text("Settings").font(.title2.weight(.semibold))
                Spacer()
                if let v = state.appVersion {
                    Text("v\(v)").font(.caption).foregroundStyle(.secondary)
                }
            }

            Toggle(isOn: Binding(get: { state.launchAtLogin },
                                 set: { state.setLaunchAtLogin($0) })) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Launch fob at login").font(.callout)
                    Text("Keep the agent running so `ssh` always reaches fob. Recommended.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            .toggleStyle(.checkbox)

            VStack(alignment: .leading, spacing: 4) {
                Toggle(isOn: Binding(get: { state.checkForUpdates },
                                     set: { state.checkForUpdates = $0 })) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Check for updates automatically").font(.callout)
                        Text("Once a day, fob checks GitHub's public releases for a newer version. No data about you is sent.")
                            .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                    }
                }
                .toggleStyle(.checkbox)
                HStack(spacing: 8) {
                    Button(checking ? "Checking…" : "Check now") {
                        checking = true
                        Task { await state.checkForUpdatesNow(force: true); checking = false }
                    }
                    .disabled(checking)
                    if let u = state.updateAvailable {
                        Text("v\(u.version) available").font(.caption).foregroundStyle(Theme.accent)
                    } else if !checking {
                        Text("Up to date.").font(.caption).foregroundStyle(.secondary)
                    }
                }
                .padding(.leading, 20)
            }

            Divider()

            VStack(alignment: .leading, spacing: 4) {
                Text("AGENT SOCKET").font(.caption.weight(.semibold)).foregroundStyle(.secondary).tracking(0.6)
                Text(state.socketPath)
                    .font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                    .foregroundStyle(.secondary)
                Text("Point ssh at this in `~/.ssh/config` with `IdentityAgent`.")
                    .font(.caption).foregroundStyle(.tertiary)
            }

            Spacer(minLength: 0)
        }
        .padding(22)
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}
