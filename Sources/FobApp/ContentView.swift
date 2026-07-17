import AppKit
import FobKit
import SwiftUI

// MARK: - Theme tokens (ported from the Claude Design prototype)

/// Colors that flip with the system appearance. Values are the prototype's light/dark
/// token maps verbatim, so the panel reads the same in both modes.
struct Theme {
    let text, sub: Color
    let div, div2: Color
    let fieldBg, fieldBorder: Color
    let dotBg, chev: Color
    let footBg, footBorder: Color
    let menuBg, menuBorder, hoverBg: Color

    static let accent = Color(.sRGB, red: 0.039, green: 0.518, blue: 1.0)   // #0a84ff
    static let green = Color(.sRGB, red: 0.188, green: 0.820, blue: 0.345)  // #30d158
    static let red = Color(.sRGB, red: 1.0, green: 0.271, blue: 0.227)      // #ff453a

    static func current(_ scheme: ColorScheme) -> Theme { scheme == .dark ? dark : light }

    static let light = Theme(
        text: c(29, 29, 31), sub: c(134, 134, 139),
        div: c(0, 0, 0, 0.08), div2: c(0, 0, 0, 0.05),
        fieldBg: c(255, 255, 255, 0.7), fieldBorder: c(0, 0, 0, 0.15),
        dotBg: c(0, 0, 0, 0.05), chev: c(199, 199, 204),
        footBg: c(255, 255, 255, 0.6), footBorder: c(0, 0, 0, 0.12),
        menuBg: c(247, 247, 249, 0.98), menuBorder: c(0, 0, 0, 0.08), hoverBg: c(120, 120, 130, 0.14))

    static let dark = Theme(
        text: c(245, 245, 247), sub: c(152, 152, 157),
        div: c(255, 255, 255, 0.1), div2: c(255, 255, 255, 0.06),
        fieldBg: c(255, 255, 255, 0.06), fieldBorder: c(255, 255, 255, 0.14),
        dotBg: c(255, 255, 255, 0.08), chev: c(106, 106, 112),
        footBg: c(255, 255, 255, 0.06), footBorder: c(255, 255, 255, 0.12),
        menuBg: c(46, 46, 50, 0.98), menuBorder: c(255, 255, 255, 0.1), hoverBg: c(255, 255, 255, 0.09))

    private static func c(_ r: Double, _ g: Double, _ b: Double, _ a: Double = 1) -> Color {
        Color(.sRGB, red: r / 255, green: g / 255, blue: b / 255, opacity: a)
    }
}

/// Anchors the ••• buttons so the floating dropdown can position itself over the panel.
private struct MenuAnchorKey: PreferenceKey {
    static var defaultValue: [String: Anchor<CGRect>] = [:]
    static func reduce(value: inout [String: Anchor<CGRect>], nextValue: () -> [String: Anchor<CGRect>]) {
        value.merge(nextValue()) { $1 }
    }
}

// MARK: - Panel

struct ContentView: View {
    @EnvironmentObject var state: AppState
    @Environment(\.colorScheme) private var scheme
    @Environment(\.openWindow) private var openWindow

    @State private var openMenuKey: String?
    @State private var menuUsage: AppState.KeyUsage?
    @State private var updateCopied = false

    private var t: Theme { Theme.current(scheme) }
    private let width: CGFloat = 360

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            divider
            if state.updateAvailable != nil { updateBanner; divider }
            keysSection
            divider
            newKeySection
            divider
            activitySection
            divider
            footer
        }
        .frame(width: width)
        .overlayPreferenceValue(MenuAnchorKey.self) { anchors in
            dropdownOverlay(anchors)
        }
    }

    private var divider: some View {
        Rectangle().fill(t.div).frame(height: 0.5)
    }

    private func sectionLabel(_ text: String) -> some View {
        Text(text)
            .font(.system(size: 10.5, weight: .semibold))
            .tracking(0.6)
            .foregroundStyle(t.sub)
    }

    // MARK: Header

    private var header: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 9) {
                FobKeyGlyph(size: 23)
                Text("fob").font(.system(size: 14, weight: .semibold)).foregroundStyle(t.text)
                Spacer()
                PulsingDot(color: state.listening ? Theme.green : .orange)
                Text(state.status).font(.system(size: 12)).foregroundStyle(t.text)
            }
            .padding(.horizontal, 14).padding(.top, 13).padding(.bottom, 8)

            Text(state.socketPath)
                .font(.system(size: 11, design: .monospaced))
                .foregroundStyle(t.sub)
                .padding(.horizontal, 14).padding(.bottom, 10)

            if let fatal = state.fatalError {
                inlineError(fatal, systemImage: "exclamationmark.triangle.fill")
            }
            if let err = state.actionError {
                inlineError(err, systemImage: nil)
            }
        }
    }

    private var updateBanner: some View {
        HStack(spacing: 9) {
            Image(systemName: "arrow.up.circle.fill").foregroundStyle(Theme.accent)
            VStack(alignment: .leading, spacing: 1) {
                Text("Update available").font(.system(size: 12, weight: .semibold)).foregroundStyle(t.text)
                if let u = state.updateAvailable {
                    Text("\(state.appVersion.map { "v\($0) → " } ?? "")v\(u.version)")
                        .font(.system(size: 11)).foregroundStyle(t.sub)
                }
            }
            Spacer()
            Button("Notes") { if let u = state.updateAvailable { NSWorkspace.shared.open(u.url) } }
                .buttonStyle(.plain).font(.system(size: 11, weight: .medium)).foregroundStyle(Theme.accent)
            Button(updateCopied ? "Copied" : "Copy `brew upgrade`") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString("brew upgrade --cask fob", forType: .string)
                updateCopied = true
            }
            .buttonStyle(.plain).font(.system(size: 11, weight: .medium)).foregroundStyle(Theme.accent)
        }
        .padding(.horizontal, 14).padding(.vertical, 10)
        .background(Theme.accent.opacity(0.08))
    }

    private func inlineError(_ message: String, systemImage: String?) -> some View {
        HStack(alignment: .top, spacing: 5) {
            if let systemImage { Image(systemName: systemImage) }
            Text(message).fixedSize(horizontal: false, vertical: true)
        }
        .font(.system(size: 11)).foregroundStyle(Theme.red)
        .padding(.horizontal, 14).padding(.bottom, 10)
    }

    // MARK: Keys

    private var keysSection: some View {
        VStack(alignment: .leading, spacing: 0) {
            sectionLabel("KEYS").padding(.horizontal, 14).padding(.top, 12).padding(.bottom, 4)
            if state.keys.isEmpty { emptyState }
            ForEach(state.keys) { key in
                keyRow(key)
                Rectangle().fill(t.div2).frame(height: 0.5).padding(.horizontal, 14)
            }
        }
    }

    private var emptyState: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Welcome to fob")
                .font(.system(size: 13, weight: .semibold)).foregroundStyle(t.text)
            Text("fob keeps SSH keys in the Secure Enclave, unlocked by Touch ID. Already using SSH keys? Migrate a server — fob adds a new key alongside the old one and proves it works before you retire anything.")
                .font(.system(size: 11.5)).foregroundStyle(t.sub).fixedSize(horizontal: false, vertical: true)
            Button {
                openConfigWindow(.migrate)
            } label: {
                Text("Migrate an existing server…")
                    .font(.system(size: 12.5, weight: .semibold)).foregroundStyle(.white)
                    .padding(.horizontal, 14).frame(height: 28)
                    .background(RoundedRectangle(cornerRadius: 7).fill(Theme.accent))
            }
            .buttonStyle(.plain)
            Text("…or **Configure… → New key** to create one from scratch.")
                .font(.system(size: 11)).foregroundStyle(t.sub)
        }
        .padding(.horizontal, 14).padding(.top, 2).padding(.bottom, 10)
    }

    private func keyRow(_ key: KeyInfo) -> some View {
        HStack(spacing: 10) {
            VStack(alignment: .leading, spacing: 2) {
                Text(key.name).font(.system(size: 13, weight: .semibold)).foregroundStyle(t.text)
                Text(meta(key)).font(.system(size: 11.5)).foregroundStyle(t.sub)
            }
            Spacer(minLength: 0)
            Button { toggleMenu(key.name) } label: {
                HStack(spacing: 2) {
                    ZStack {
                        Circle().fill(t.dotBg).frame(width: 24, height: 24)
                        HStack(spacing: 2) {
                            ForEach(0..<3) { _ in Circle().fill(t.sub).frame(width: 2.5, height: 2.5) }
                        }
                    }
                    Text("⌄").font(.system(size: 11)).foregroundStyle(t.chev)
                }
            }
            .buttonStyle(.plain)
            .anchorPreference(key: MenuAnchorKey.self, value: .bounds) { [key.name: $0] }
        }
        .padding(.horizontal, 14).padding(.vertical, 8)
    }

    // MARK: New key / actions

    private var newKeySection: some View {
        HStack(spacing: 18) {
            linkButton("slider.horizontal.3", "Configure…") { openConfigWindow(.newKey) }
            Spacer()
        }
        .padding(.horizontal, 14).padding(.vertical, 12)
    }

    /// Set the config window's route and bring it up (all popover flows funnel through here).
    private func openConfigWindow(_ tab: AppState.ConfigTab, detail: AppState.ConfigDetail? = nil) {
        state.openConfig(tab: tab, detail: detail)
        NSApp.activate(ignoringOtherApps: true)
        openWindow(id: ConfigWindow.windowID)
    }

    /// Open the signing page in the config window for this key (from the ••• menu).
    private func openSigning(_ name: String) {
        state.signingSetupKey = name
        state.signingSetupHost = nil
        openConfigWindow(.newKey, detail: .signing)
    }

    private func linkButton(_ icon: String, _ title: String, _ action: @escaping () -> Void) -> some View {
        Button {
            NSApp.activate(ignoringOtherApps: true)
            action()
        } label: {
            HStack(spacing: 5) {
                Image(systemName: icon)
                Text(title)
            }
            .font(.system(size: 12)).foregroundStyle(Theme.accent)
        }
        .buttonStyle(.plain)
    }

    // MARK: Activity

    private var activitySection: some View {
        VStack(alignment: .leading, spacing: 0) {
            sectionLabel("RECENT ACTIVITY").padding(.horizontal, 14).padding(.top, 12).padding(.bottom, 6)
            if state.feed.isEmpty {
                Text("Nothing yet.").font(.system(size: 11)).foregroundStyle(t.sub)
                    .padding(.horizontal, 14).padding(.bottom, 12)
            } else {
                // The last three events, each with room to read — no cramped scroller.
                VStack(alignment: .leading, spacing: 9) {
                    ForEach(Array(state.feed.prefix(3).enumerated()), id: \.offset) { _, event in
                        eventRow(event)
                    }
                }
                .padding(.horizontal, 14).padding(.top, 2).padding(.bottom, 12)
            }
        }
    }

    private func eventRow(_ event: AgentEvent) -> some View {
        let line = activity(event)
        return HStack(alignment: .top, spacing: 9) {
            Text(Self.time.string(from: event.date))
                .font(.system(size: 10.5, design: .monospaced)).foregroundStyle(t.sub)
                .frame(width: 56, alignment: .leading)
            Circle().fill(color(event.kind)).frame(width: 6, height: 6).padding(.top, 4)
            (Text(line.name).fontWeight(.semibold) + Text(line.rest))
                .font(.system(size: 11.5)).foregroundStyle(t.text)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    // MARK: Footer

    private var footer: some View {
        HStack {
            Spacer()
            footerButton("Quit fob") { NSApplication.shared.terminate(nil) }
        }
        .padding(.horizontal, 12).padding(.vertical, 9)
    }

    private func footerButton(_ title: String, _ action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Text(title).font(.system(size: 12, weight: .medium)).foregroundStyle(t.text)
                .padding(.horizontal, 12).frame(height: 28)
                .background(RoundedRectangle(cornerRadius: 7).fill(t.footBg))
                .overlay(RoundedRectangle(cornerRadius: 7).strokeBorder(t.footBorder, lineWidth: 0.5))
        }
        .buttonStyle(.plain)
    }

    // MARK: Dropdown

    private func toggleMenu(_ name: String) {
        let opening = openMenuKey != name
        openMenuKey = opening ? name : nil
        // Compute usage (off the main actor) only for the key whose menu is opening, so the
        // dropdown can scope the signing item without blocking the UI. The signing row fills
        // in a moment after the menu appears.
        menuUsage = nil
        if opening { Task { if openMenuKey == name { menuUsage = await state.keyUsage(name: name) } } }
    }

    @ViewBuilder
    private func dropdownOverlay(_ anchors: [String: Anchor<CGRect>]) -> some View {
        if let name = openMenuKey, let anchor = anchors[name],
           let key = state.keys.first(where: { $0.name == name }) {
            GeometryReader { proxy in
                let rect = proxy[anchor]
                ZStack(alignment: .topLeading) {
                    Color.clear.contentShape(Rectangle())
                        .onTapGesture { openMenuKey = nil }
                    dropdown(for: key)
                        .frame(width: 212)
                        .offset(x: max(8, rect.maxX - 212), y: rect.maxY + 4)
                }
            }
        }
    }

    private func dropdown(for key: KeyInfo) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text("TOUCH REUSE")
                .font(.system(size: 10.5, weight: .semibold)).tracking(0.5).foregroundStyle(t.sub)
                .padding(.horizontal, 10).padding(.vertical, 5)
            reuseItem(key, seconds: 0, "Every time")
            reuseItem(key, seconds: 30, "30 seconds")
            reuseItem(key, seconds: 60, "1 minute")
            reuseItem(key, seconds: 300, "5 minutes")
            Rectangle().fill(t.div).frame(height: 0.5).padding(.horizontal, 8).padding(.vertical, 5)
            if key.isPinned {
                menuItem("Unpin (any destination)", color: t.text) { state.unpin(name: key.name) }
            }
            if !(menuUsage?.isSigningOnly ?? false) {
                menuItem("Pin to host…", color: t.text) { state.requestPin(name: key.name) }
            }
            if menuUsage?.signsCommits ?? false {
                menuItem("Signing setup…", color: t.text) { openSigning(key.name) }
            } else if menuUsage?.canOfferSigning ?? true {
                menuItem("Use for commit signing…", color: t.text) { openSigning(key.name) }
            }
            menuItem("Delete…", color: Theme.red) { state.requestDelete(name: key.name) }
        }
        .padding(6)
        .background(RoundedRectangle(cornerRadius: 11).fill(t.menuBg))
        .overlay(RoundedRectangle(cornerRadius: 11).strokeBorder(t.menuBorder, lineWidth: 0.5))
        .shadow(color: .black.opacity(0.35), radius: 22, y: 16)
    }

    private func reuseItem(_ key: KeyInfo, seconds: Int, _ label: String) -> some View {
        let selected = key.reuseSeconds == seconds
        return MenuRow(hoverBg: t.hoverBg) {
            state.setReuse(name: key.name, seconds: seconds); openMenuKey = nil
        } content: {
            HStack(spacing: 7) {
                Text(selected ? "✓" : "").frame(width: 11, alignment: .leading)
                    .font(.system(size: 11)).foregroundStyle(Theme.accent)
                Text(label).font(.system(size: 12.5, weight: selected ? .semibold : .regular))
                    .foregroundStyle(selected ? Theme.accent : t.text)
                Spacer(minLength: 0)
            }
        }
    }

    private func menuItem(_ label: String, color: Color, _ action: @escaping () -> Void) -> some View {
        MenuRow(hoverBg: t.hoverBg) { action(); openMenuKey = nil } content: {
            HStack { Text(label).font(.system(size: 12.5)).foregroundStyle(color); Spacer(minLength: 0) }
        }
    }

    // MARK: Helpers

    private func meta(_ key: KeyInfo) -> String {
        let dest = key.isPinned ? "pinned to \(key.pinnedNames.joined(separator: ", "))" : "any destination"
        return "\(dest) · \(reuseText(key.reuseSeconds))"
    }

    private func reuseText(_ s: Int) -> String {
        switch s {
        case 0: return "touch every time"
        case 30: return "reuse 30s"
        case 60: return "reuse 1m"
        case 300: return "reuse 5m"
        default: return "reuse \(s)s"
        }
    }

    /// A "**key** · <command> <dest> · <auth>" line matching the design (the design
    /// bolds the leading name). Built from the event's structured fields rather than
    /// the verbose notification text.
    private func activity(_ e: AgentEvent) -> (name: String, rest: String) {
        let dest = destDisplay(e.destination, key: e.key)
        let action = [peerCmd(e.peer), dest].compactMap { $0 }.joined(separator: " ")
        let act = action.isEmpty ? "" : " · \(action)"
        switch e.kind {
        case .signed:        return (e.key ?? "key", "\(act) · Touch ID")
        case .signedReused:  return (e.key ?? "key", "\(act) · reused")
        case .denied:        return (e.key ?? "key", "\(act) · denied")
        case .refusedPin:    return (e.key ?? "key", "\(act) · blocked (wrong host)")
        case .refusedPolicy: return (e.key ?? "key", "\(act) · blocked (policy)")
        case .refusedNamespace: return (e.key ?? "key", "\(act) · blocked (namespace)")
        case .unknownKey:    return (peerCmd(e.peer) ?? "unknown", (dest.map { " · \($0)" } ?? "") + " · unknown key")
        case .bind:          return (dest ?? "host", " · bound")
        case .bindRejected:  return (peerCmd(e.peer) ?? "client", " · bind rejected")
        case .listening:     return ("agent", " · listening")
        }
    }

    /// Requesting process without the pid: "ssh (pid 70860)" → "ssh".
    private func peerCmd(_ p: String?) -> String? {
        p?.components(separatedBy: " (pid").first
    }

    /// The destination to show. "bender (192.168.1.10)" → the IP when the alias equals
    /// the key (so we don't print "bender · ssh bender"), otherwise the alias.
    private func destDisplay(_ d: String?, key: String?) -> String? {
        guard let d else { return nil }
        let parts = d.components(separatedBy: " (")
        let alias = parts.first ?? d
        if parts.count > 1 {
            let ip = parts[1].replacingOccurrences(of: ")", with: "")
            return alias == key ? ip : alias
        }
        return alias
    }

    private static let time: DateFormatter = {
        let f = DateFormatter(); f.dateFormat = "h:mm a"; return f
    }()

    private func color(_ kind: AgentEvent.Kind) -> Color {
        switch kind {
        case .signed, .signedReused: return Theme.green
        case .denied: return .orange
        case .refusedPin, .refusedPolicy, .refusedNamespace, .bindRejected: return Theme.red
        case .unknownKey: return .yellow
        case .bind: return Theme.accent
        case .listening: return t.sub
        }
    }
}

/// A dropdown row with a hover highlight and a tap action.
private struct MenuRow<Content: View>: View {
    let hoverBg: Color
    let action: () -> Void
    @ViewBuilder let content: Content
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            content.padding(.horizontal, 10).padding(.vertical, 6)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(RoundedRectangle(cornerRadius: 6).fill(hovering ? hoverBg : .clear))
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .onHover { hovering = $0 }
    }
}

/// The green "listening" status dot with a gentle pulse.
private struct PulsingDot: View {
    let color: Color
    @State private var on = false

    var body: some View {
        Circle().fill(color).frame(width: 7, height: 7)
            .opacity(on ? 0.4 : 1).scaleEffect(on ? 0.82 : 1)
            .animation(.easeInOut(duration: 1.2).repeatForever(autoreverses: true), value: on)
            .onAppear { on = true }
    }
}
