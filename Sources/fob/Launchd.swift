import Foundation

enum Launchd {
    static let label = "dev.fob.agent"

    static var plistURL: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/LaunchAgents/\(label).plist")
    }

    static func install(store: KeyStore) throws {
        guard let sourceExecutable = Bundle.main.executablePath else {
            throw LaunchdError.executablePathUnknown
        }
        // Copy the binary into ~/.fob/bin so the agent keeps working if the
        // build directory moves or is cleaned. Re-running install updates it.
        let binDir = store.directory.appendingPathComponent("bin")
        try FileManager.default.createDirectory(
            at: binDir,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        let executable = binDir.appendingPathComponent("fob").path
        if FileManager.default.fileExists(atPath: executable) {
            try FileManager.default.removeItem(atPath: executable)
        }
        try FileManager.default.copyItem(atPath: sourceExecutable, toPath: executable)
        let logPath = store.directory.appendingPathComponent("agent.log").path
        let plist = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>Label</key>
            <string>\(label)</string>
            <key>ProgramArguments</key>
            <array>
                <string>\(executable)</string>
                <string>agent</string>
            </array>
            <key>RunAtLoad</key>
            <true/>
            <key>KeepAlive</key>
            <true/>
            <key>StandardErrorPath</key>
            <string>\(logPath)</string>
        </dict>
        </plist>
        """
        try FileManager.default.createDirectory(
            at: plistURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try Data(plist.utf8).write(to: plistURL, options: .atomic)

        let domain = "gui/\(getuid())"
        _ = runLaunchctl(["bootout", "\(domain)/\(label)"]) // ignore failure: not loaded yet
        let bootstrap = runLaunchctl(["bootstrap", domain, plistURL.path])
        guard bootstrap == 0 else { throw LaunchdError.bootstrapFailed(bootstrap) }
    }

    static func uninstall() throws {
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

enum LaunchdError: LocalizedError {
    case executablePathUnknown
    case bootstrapFailed(Int32)

    var errorDescription: String? {
        switch self {
        case .executablePathUnknown:
            return "could not determine the path of this executable"
        case .bootstrapFailed(let code):
            return "launchctl bootstrap failed with status \(code)"
        }
    }
}
