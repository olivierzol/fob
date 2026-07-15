import FobKit
import SwiftUI

/// The single "fob" window. A segmented tab bar picks one of the top-level pages
/// (New key · Migrate · SSH checkup · Audit · Settings); Commit-signing and Migrate-a-host
/// aren't tabs — they're entered from other flows/the popover, so they render as a pushed
/// *detail* over the current tab with a Back button. Every former separate window is now a
/// page here, so nothing spawns extra windows.
struct ConfigWindow: View {
    static let windowID = "fob-config"

    @EnvironmentObject var state: AppState

    private var tabBinding: Binding<AppState.ConfigTab> {
        Binding(get: { state.configTab }, set: { state.configTab = $0 })
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            content
        }
        .frame(width: 560)
    }

    @ViewBuilder
    private var header: some View {
        if state.configDetail != nil {
            HStack(spacing: 6) {
                Button { state.configDetail = nil } label: {
                    Label(backTitle, systemImage: "chevron.left").font(.callout.weight(.medium))
                }
                .buttonStyle(.plain).foregroundStyle(Color.accentColor)
                Spacer()
            }
            .padding(.horizontal, 16).padding(.vertical, 10)
        } else {
            Picker("", selection: tabBinding) {
                Text("New key").tag(AppState.ConfigTab.newKey)
                Text("Keys").tag(AppState.ConfigTab.keys)
                Text("Migrate").tag(AppState.ConfigTab.migrate)
                Text("Checkup").tag(AppState.ConfigTab.checkup)
                Text("Audit").tag(AppState.ConfigTab.audit)
                Text("Settings").tag(AppState.ConfigTab.settings)
            }
            .pickerStyle(.segmented).labelsHidden()
            .padding(.horizontal, 16).padding(.vertical, 10)
        }
    }

    private var backTitle: String {
        switch state.configTab {
        case .keys: return "Keys"
        case .migrate: return "Migrate"
        case .checkup: return "Checkup"
        default: return "New key"
        }
    }

    @ViewBuilder
    private var content: some View {
        if let detail = state.configDetail {
            switch detail {
            case .signing: SigningSetupView()
            case .migrateHost: MigrateHostView()
            }
        } else {
            switch state.configTab {
            case .newKey: HostSetupView()
            case .keys: KeysView()
            case .migrate: MigrateView()
            case .checkup: CheckupView()
            case .audit: AuditView()
            case .settings: SettingsView()
            }
        }
    }
}
