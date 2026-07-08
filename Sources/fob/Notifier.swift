import Foundation

/// Posts macOS notifications from the agent.
///
/// A bare CLI binary has no app bundle, so UNUserNotificationCenter is unavailable;
/// osascript is the dependency-free fallback until the phase-2 menu-bar app exists.
enum Notifier {
    static func post(_ body: String) {
        let script = "display notification \"\(escape(body))\" with title \"fob\""
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        process.arguments = ["-e", script]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try? process.run() // fire and forget — notifications must never block or break signing
    }

    private static func escape(_ text: String) -> String {
        text.replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
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
