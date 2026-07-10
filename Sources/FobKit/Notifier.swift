import Foundation

/// Posts macOS notifications from the agent.
///
/// A bare CLI binary has no app bundle, so UNUserNotificationCenter is unavailable;
/// osascript is the dependency-free fallback until the phase-2 menu-bar app exists.
public enum Notifier {
    public static func post(_ body: String) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        // The body carries attacker-influenced text (a connecting process's name).
        // NEVER interpolate it into the AppleScript source, or a crafted process name
        // could inject `do shell script …` and run code. Instead pass it through the
        // environment and have the script read it with `system attribute`, so the
        // script text is a fixed constant and the body is only ever data.
        var environment = ProcessInfo.processInfo.environment
        environment["FOB_NOTIFICATION_BODY"] = body
        process.environment = environment
        process.arguments = [
            "-e",
            "display notification (system attribute \"FOB_NOTIFICATION_BODY\") with title \"fob\"",
        ]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try? process.run() // fire and forget — notifications must never block or break signing
    }
}

/// Best-effort identification of the process on the other end of the agent socket.
/// PID reuse makes this spoofable in principle — display/awareness only, never policy.
enum Peer {
    static func describe(fd: Int32) -> String {
        var pid: pid_t = 0
        var size = socklen_t(MemoryLayout<pid_t>.size)
        guard getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &pid, &size) == 0, pid > 0 else {
            return "unknown process"
        }
        var buffer = [CChar](repeating: 0, count: 4096)
        let length = proc_pidpath(pid, &buffer, UInt32(buffer.count))
        guard length > 0 else { return "pid \(pid)" }
        let name = URL(fileURLWithPath: String(cString: buffer)).lastPathComponent
        return "\(name) (pid \(pid))"
    }
}
