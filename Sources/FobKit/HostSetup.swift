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

    /// What we read out of an existing `~/.ssh/config` Host block, for `fob adopt`.
    public struct ParsedHost: Equatable {
        public var hostName: String?
        public var user: String?
        public var port: Int?
        public var identityFiles: [String]
        public var usesFobAgent: Bool // IdentityAgent already points at ~/.fob/agent.sock
    }

    /// Reads the `Host <alias>` block from ssh-config text, if the alias appears as a
    /// literal pattern (never via a wildcard/`Match` block — we won't touch those).
    /// Returns nil when there's no such block.
    public static func parseHostBlock(alias: String, in config: String) -> ParsedHost? {
        var inBlock = false, found = false
        var host = ParsedHost(hostName: nil, user: nil, port: nil, identityFiles: [], usesFobAgent: false)
        for raw in config.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }
            let lower = line.lowercased()
            if lower == "host" || lower.hasPrefix("host ") || lower == "match" || lower.hasPrefix("match ") {
                if inBlock { break } // reached the next section — our block ended
                if lower.hasPrefix("host ") {
                    let patterns = line.dropFirst(5).split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
                    if patterns.contains(alias) { inBlock = true; found = true }
                }
                continue
            }
            guard inBlock else { continue }
            // key / value separated by whitespace or '='
            guard let sep = line.firstIndex(where: { $0 == " " || $0 == "\t" || $0 == "=" }) else { continue }
            let key = line[..<sep].lowercased()
            let value = line[line.index(after: sep)...]
                .trimmingCharacters(in: CharacterSet(charactersIn: " \t=\""))
            switch key {
            case "hostname": host.hostName = value
            case "user": host.user = value
            case "port": host.port = Int(value)
            case "identityfile": host.identityFiles.append(value)
            case "identityagent": if value.contains("/.fob/") { host.usesFobAgent = true }
            default: break
            }
        }
        return found ? host : nil
    }
}
