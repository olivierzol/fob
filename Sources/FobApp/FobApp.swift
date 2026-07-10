import AppKit
import SwiftUI
import UserNotifications

@main
struct FobApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @StateObject private var state = AppState()

    var body: some Scene {
        MenuBarExtra("fob", image: "MenuBarKey") {
            ContentView().environmentObject(state)
        }
        .menuBarExtraStyle(.window)

        Window("Set up a host", id: HostSetupView.windowID) {
            HostSetupView().environmentObject(state)
        }
        .windowResizability(.contentSize)
    }
}

/// Keeps the app out of the Dock and shows notification banners even while the
/// menu-bar panel is the active window.
final class AppDelegate: NSObject, NSApplicationDelegate, UNUserNotificationCenterDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory) // belt-and-suspenders alongside LSUIElement
        // An LSUIElement app has no Dock tile, so NSApplication never loads its icon
        // image — and Notification Center renders the running app's icon, showing a
        // blank glyph. Set it explicitly from the bundled asset catalog.
        if let icon = NSImage(named: "AppIcon") {
            NSApp.applicationIconImage = icon
        }
        if Bundle.main.bundleIdentifier != nil {
            UNUserNotificationCenter.current().delegate = self
        }
    }

    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
    ) {
        completionHandler([.banner, .sound])
    }
}
