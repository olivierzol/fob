import Foundation

/// Pure version comparison for the in-app "update available" nudge. The network fetch (the
/// GitHub releases API) lives in the app layer; this just decides whether a fetched tag is
/// newer than the running version.
public enum UpdateCheck {
    /// True if `latest` is a strictly newer dotted version than `current`. Tolerates a leading
    /// `v` and differing component counts (missing = 0). Non-numeric suffixes (e.g. a
    /// `-beta`) are treated as their leading number, so pre-releases don't spuriously trigger.
    public static func isNewer(_ latest: String, than current: String) -> Bool {
        func parts(_ s: String) -> [Int] {
            s.trimmingCharacters(in: CharacterSet(charactersIn: "vV "))
                .split(separator: ".")
                .map { Int($0.prefix { $0.isNumber }) ?? 0 }
        }
        let a = parts(latest), b = parts(current)
        for i in 0..<max(a.count, b.count) {
            let x = i < a.count ? a[i] : 0
            let y = i < b.count ? b[i] : 0
            if x != y { return x > y }
        }
        return false
    }
}
