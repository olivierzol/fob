import Foundation

/// Minimal read-only parse of `~/.gitconfig` for the migration discovery view. We only
/// need to tell the user whether commit signing is already configured and, if so, whether
/// it's already a fob key — everything here is informational (servers are the priority).
public enum GitConfig {
    public struct SigningInfo: Equatable {
        public let format: String?      // gpg.format (e.g. "ssh")
        public let signingKey: String?  // user.signingkey
        public let usesFob: Bool        // signingkey points at a fob key/socket

        public init(format: String?, signingKey: String?, usesFob: Bool) {
            self.format = format
            self.signingKey = signingKey
            self.usesFob = usesFob
        }
    }

    /// Parse the `[gpg] format` and `[user] signingkey` values out of gitconfig text.
    /// Tolerates subsection headers (`[gpg "ssh"]`) — only the bare `[gpg]`/`[user]`
    /// sections carry the keys we read.
    public static func parse(_ gitconfig: String) -> SigningInfo {
        var section = ""
        var format: String?
        var signingKey: String?
        for raw in gitconfig.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("[") && line.contains("]") {
                let header = line.dropFirst().prefix(while: { $0 != "]" })
                // Section name is the first token before any quoted subsection.
                section = header.split(whereSeparator: { $0 == " " || $0 == "\t" })
                    .first.map(String.init)?.lowercased() ?? ""
                continue
            }
            guard let eq = line.firstIndex(of: "=") else { continue }
            let key = line[..<eq].trimmingCharacters(in: .whitespaces).lowercased()
            let value = line[line.index(after: eq)...].trimmingCharacters(in: .whitespaces)
            if section == "gpg" && key == "format" { format = value }
            if section == "user" && key == "signingkey" { signingKey = value }
        }
        let key = signingKey ?? ""
        let usesFob = key.contains("/fob_") || key.contains("/.fob/")
        return SigningInfo(format: format, signingKey: signingKey, usesFob: usesFob)
    }
}
