import Foundation

/// A minimal line diff (LCS) used to preview exactly what a migration will change in
/// `~/.ssh/config` before it's written — so the user confirms a diff, never a black box.
public enum TextDiff {
    public enum Kind: Equatable { case same, added, removed }

    public struct Line: Equatable {
        public let kind: Kind
        public let text: String
        public init(_ kind: Kind, _ text: String) {
            self.kind = kind
            self.text = text
        }
    }

    /// Line-by-line diff of `old` → `new` via a longest-common-subsequence walk.
    public static func lines(old: String, new: String) -> [Line] {
        let a = old.components(separatedBy: "\n")
        let b = new.components(separatedBy: "\n")
        let n = a.count, m = b.count

        // dp[i][j] = LCS length of a[i...] and b[j...].
        var dp = Array(repeating: Array(repeating: 0, count: m + 1), count: n + 1)
        if n > 0 && m > 0 {
            for i in stride(from: n - 1, through: 0, by: -1) {
                for j in stride(from: m - 1, through: 0, by: -1) {
                    dp[i][j] = a[i] == b[j] ? dp[i + 1][j + 1] + 1 : max(dp[i + 1][j], dp[i][j + 1])
                }
            }
        }

        var out: [Line] = []
        var i = 0, j = 0
        while i < n && j < m {
            if a[i] == b[j] { out.append(Line(.same, a[i])); i += 1; j += 1 }
            else if dp[i + 1][j] >= dp[i][j + 1] { out.append(Line(.removed, a[i])); i += 1 }
            else { out.append(Line(.added, b[j])); j += 1 }
        }
        while i < n { out.append(Line(.removed, a[i])); i += 1 }
        while j < m { out.append(Line(.added, b[j])); j += 1 }
        return out
    }
}
