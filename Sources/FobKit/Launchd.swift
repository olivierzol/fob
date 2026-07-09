import Foundation

/// Legacy launchd job management. Phases 1–2 ran the agent as a launchd-launched
/// CLI (`fob agent`, label `dev.fob.agent`). The agent now lives in fob.app and
/// registers itself for login via SMAppService, so only teardown of the old job
/// remains here — the app does not use launchd.
public enum Launchd {
    public static let label = "dev.fob.agent"

    static var plistURL: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/LaunchAgents/\(label).plist")
    }

    public static func uninstall() throws {
        _ = runLaunchctl(["bootout", "gui/\(getuid())/\(label)"])
        try? FileManager.default.removeItem(at: plistURL)
    }

    private static func runLaunchctl(_ arguments: [String]) -> Int32 {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = arguments
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
        } catch {
            return -1
        }
        process.waitUntilExit()
        return process.terminationStatus
    }
}
