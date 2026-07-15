import AppKit
import FobKit
import SwiftUI

/// The Settings page: app-level preferences that used to live in the popover footer.
struct SettingsView: View {
    @EnvironmentObject var state: AppState

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 10) {
                FobKeyGlyph(size: 28)
                Text("Settings").font(.title2.weight(.semibold))
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
