import FobKit
import Foundation
import UserNotifications

/// Native notifications with a graceful fallback.
///
/// `UNUserNotificationCenter` needs a signed app bundle and the user's permission.
/// When either is missing (unsigned build, denied permission, or the framework
/// refuses to load outside a bundle), we fall back to the osascript notifier that
/// the CLI has always used — so a sign event is never silent.
enum Notifications {
    /// Ask once, early. Harmless if it fails; `post` degrades on its own.
    static func requestAuthorization() {
        center?.requestAuthorization(options: [.alert, .sound]) { _, _ in }
    }

    static func post(_ body: String) {
        guard let center else { Notifier.post(body); return }
        center.getNotificationSettings { settings in
            switch settings.authorizationStatus {
            case .authorized, .provisional, .ephemeral:
                let content = UNMutableNotificationContent()
                content.title = "fob"
                content.body = body
                let request = UNNotificationRequest(
                    identifier: UUID().uuidString, content: content, trigger: nil)
                center.add(request) { error in
                    if error != nil { Notifier.post(body) } // last-resort fallback
                }
            default:
                Notifier.post(body)
            }
        }
    }

    /// `UNUserNotificationCenter.current()` traps if there is no bundle identifier
    /// (e.g. the raw executable run outside fob.app). Guard so we can fall back.
    private static var center: UNUserNotificationCenter? {
        Bundle.main.bundleIdentifier == nil ? nil : .current()
    }
}
