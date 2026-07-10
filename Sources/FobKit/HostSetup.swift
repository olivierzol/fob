import Foundation

/// Shared pieces of host onboarding, used by both the CLI `fob setup` and the app's
/// "Set up a host" window so what gets written to `~/.ssh/config` can't drift.
public enum HostSetup {
    /// The `~/.ssh/config` Host block fob writes for a key. A non-default `port` adds a
    /// `Port` line (omitted for 22 to keep the entry clean).
    public static func configBlock(alias: String, host: String, user: String,
                                   port: Int = 22, pubPath: String, socketPath: String) -> String {
        var lines = ["# added by fob", "Host \(alias)", "  HostName \(host)", "  User \(user)"]
        if port != 22 { lines.append("  Port \(port)") }
        lines += ["  IdentityAgent \(socketPath)", "  IdentityFile \(pubPath)", "  IdentitiesOnly yes"]
        return lines.joined(separator: "\n")
    }

    /// Whether `~/.ssh/config` already declares a `Host <alias>` entry.
    public static func hostBlockExists(alias: String, in config: String) -> Bool {
        for line in config.split(separator: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard trimmed.lowercased().hasPrefix("host ") else { continue }
            let patterns = trimmed.dropFirst("host ".count)
                .split(separator: " ", omittingEmptySubsequences: true)
            if patterns.contains(where: { $0 == Substring(alias) }) { return true }
        }
        return false
    }

    /// A hostname/username safe to interpolate into ssh arguments and config: non-empty,
    /// no spaces, and no leading '-' (so it can never be parsed as an ssh option).
    public static func isValidHostToken(_ s: String) -> Bool {
        !s.isEmpty && !s.contains(" ") && !s.hasPrefix("-")
    }
}
