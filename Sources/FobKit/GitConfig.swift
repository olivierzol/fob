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

    /// A conditional include in `~/.gitconfig` — a per-identity config file selected by a
    /// condition (e.g. `gitdir:~/src/perso/` → `~/.gitconfig-perso`). This is how people
    /// keep multiple git identities apart, and where per-identity signing config belongs.
    public struct IncludeEntry: Equatable {
        public let condition: String  // e.g. "gitdir:~/src/perso/", "gitdir/i:~/work/"
        public let path: String       // e.g. "~/.gitconfig-perso" (tilde not expanded)
        public init(condition: String, path: String) {
            self.condition = condition
            self.path = path
        }
    }

    /// Parse the output of `git config --global --get-regexp '^includeif\.'`. Each line is
    /// `includeif.<condition>.path <path>` (git lowercases the section/key but preserves the
    /// quoted condition's case). Returns one entry per include.
    public static func parseIncludeEntries(_ regexpOutput: String) -> [IncludeEntry] {
        var entries: [IncludeEntry] = []
        for raw in regexpOutput.split(separator: "\n", omittingEmptySubsequences: true) {
            let line = String(raw)
            guard let space = line.firstIndex(of: " ") else { continue }
            let key = String(line[..<space])
            let path = String(line[line.index(after: space)...]).trimmingCharacters(in: .whitespaces)
            let lower = key.lowercased()
            guard lower.hasPrefix("includeif."), lower.hasSuffix(".path"), !path.isEmpty else { continue }
            let start = key.index(key.startIndex, offsetBy: "includeif.".count)
            let end = key.index(key.endIndex, offsetBy: -".path".count)
            guard start < end else { continue }
            entries.append(IncludeEntry(condition: String(key[start..<end]), path: path))
        }
        return entries
    }
}
