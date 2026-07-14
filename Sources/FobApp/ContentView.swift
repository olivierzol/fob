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

    @State private var newKeyName = ""
    @State private var newKeyBiometry = true
    @State private var openMenuKey: String?

    private var t: Theme { Theme.current(scheme) }
    private let width: CGFloat = 360

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            divider
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
                NSApp.activate(ignoringOtherApps: true)
                openWindow(id: MigrateView.windowID)
            } label: {
                Text("Migrate an existing server…")
                    .font(.system(size: 12.5, weight: .semibold)).foregroundStyle(.white)
                    .padding(.horizontal, 14).frame(height: 28)
                    .background(RoundedRectangle(cornerRadius: 7).fill(Theme.accent))
            }
            .buttonStyle(.plain)
            Text("…or create your first key below.")
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

    // MARK: New key

    private var newKeySection: some View {
        VStack(alignment: .leading, spacing: 0) {
            sectionLabel("NEW KEY").padding(.horizontal, 14).padding(.top, 12).padding(.bottom, 6)
            HStack(spacing: 8) {
                TextField("key name", text: $newKeyName)
                    .textFieldStyle(.plain)
                    .font(.system(size: 12.5)).foregroundStyle(t.text)
                    .padding(.horizontal, 10).frame(height: 28)
                    .background(RoundedRectangle(cornerRadius: 7).fill(t.fieldBg))
                    .overlay(RoundedRectangle(cornerRadius: 7).strokeBorder(t.fieldBorder, lineWidth: 0.5))
                    .onSubmit(generate)
                Button(action: generate) {
                    Text("Generate")
                        .font(.system(size: 12.5, weight: .semibold)).foregroundStyle(.white)
                        .padding(.horizontal, 14).frame(height: 28)
                        .background(RoundedRectangle(cornerRadius: 7).fill(Theme.accent))
                }
                .buttonStyle(.plain)
                .disabled(newKeyName.trimmingCharacters(in: .whitespaces).isEmpty)
                .opacity(newKeyName.trimmingCharacters(in: .whitespaces).isEmpty ? 0.5 : 1)
            }
            .padding(.horizontal, 14)

            Button { newKeyBiometry.toggle() } label: {
                HStack(spacing: 7) {
                    ZStack {
                        RoundedRectangle(cornerRadius: 4)
                            .fill(newKeyBiometry ? Theme.accent : .clear)
                        RoundedRectangle(cornerRadius: 4)
                            .strokeBorder(newKeyBiometry ? Theme.accent : t.sub.opacity(0.5), lineWidth: 1.5)
                        if newKeyBiometry {
                            Image(systemName: "checkmark").font(.system(size: 8, weight: .bold)).foregroundStyle(.white)
                        }
                    }
                    .frame(width: 15, height: 15)
                    Text("Touch ID only").font(.system(size: 12)).foregroundStyle(t.text)
                }
            }
            .buttonStyle(.plain)
            .padding(.horizontal, 14).padding(.top, 10).padding(.bottom, 8)

            if let gen = state.lastGenerated { generatedBox(gen) }

            HStack(spacing: 16) {
                linkButton("sparkles", "Set up a host…") {
                    openWindow(id: HostSetupView.windowID)
                }
                linkButton("arrow.right.arrow.left", "Migrate…") {
                    openWindow(id: MigrateView.windowID)
                }
            }
            .padding(.horizontal, 14).padding(.bottom, 12)
        }
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

    private func generatedBox(_ gen: AppState.GeneratedKey) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("“\(gen.name)” created. Add this public key where you'll use it — a server's authorized_keys, or GitHub/GitLab:")
                .font(.system(size: 11)).foregroundStyle(t.sub).fixedSize(horizontal: false, vertical: true)
            HStack(spacing: 8) {
                Text(gen.pubLine)
                    .font(.system(size: 10, design: .monospaced)).foregroundStyle(t.text)
                    .lineLimit(2).truncationMode(.middle)
                    .padding(8).frame(maxWidth: .infinity, alignment: .leading)
                    .background(RoundedRectangle(cornerRadius: 6).fill(t.fieldBg))
                Button {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(gen.pubLine, forType: .string)
                } label: {
                    Text("Copy").font(.system(size: 11, weight: .semibold)).foregroundStyle(Theme.accent)
                }
                .buttonStyle(.plain)
            }
            HStack(spacing: 14) {
                Text("Use for:").font(.system(size: 11)).foregroundStyle(t.sub)
                linkButton("sparkles", "a host…") { openWindow(id: HostSetupView.windowID) }
                linkButton("signature", "commit signing…") {
                    state.signingSetupKey = gen.name
                    state.signingSetupHost = nil
                    openWindow(id: SigningSetupView.windowID)
                }
            }
        }
        .padding(.horizontal, 14).padding(.bottom, 8)
    }

    private func generate() {
        let name = newKeyName.trimmingCharacters(in: .whitespaces)
        guard !name.isEmpty else { return }
        state.generate(name: name, requireBiometry: newKeyBiometry)
        newKeyName = ""
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
        VStack(spacing: 0) {
            HStack {
                Text("Launch at login").font(.system(size: 12)).foregroundStyle(t.text)
                Spacer()
                Toggle("", isOn: Binding(get: { state.launchAtLogin },
                                         set: { state.setLaunchAtLogin($0) }))
                    .labelsHidden().toggleStyle(.switch).tint(Theme.green)
            }
            .padding(.horizontal, 14).padding(.vertical, 11)
            divider
            HStack {
                footerButton("SSH checkup") {
                    NSApp.activate(ignoringOtherApps: true)
                    openWindow(id: CheckupView.windowID)
                }
                footerButton("Reveal audit log") { state.revealAuditLog() }
                Spacer()
                footerButton("Quit fob") { NSApplication.shared.terminate(nil) }
            }
            .padding(.horizontal, 12).padding(.vertical, 9)
        }
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
        openMenuKey = (openMenuKey == name) ? nil : name
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
            menuItem("Pin to host…", color: t.text) { state.requestPin(name: key.name) }
            menuItem("Use for commit signing…", color: t.text) {
                state.signingSetupKey = key.name
                state.signingSetupHost = nil
                NSApp.activate(ignoringOtherApps: true)
                openWindow(id: SigningSetupView.windowID)
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
