import Foundation

/// What a fob key is actually used for, so the UI can tailor a key's row (e.g. hide
/// "Sign commits…" for a key that already signs, or "Pin" for a signing-only key). The
/// impure git/ssh reads that feed this live in the app/CLI layer; the resolution is pure.
public struct KeyUsage: Equatable {
    public let signsCommits: Bool     // it's the git signing key (global or any includeIf identity)
    public let authHosts: [String]    // ~/.ssh/config aliases whose IdentityFile is this fob key
    public let authGitHosts: [String] // subset of authHosts that are git services (GitHub/GitLab/…)

    public init(signsCommits: Bool, authHosts: [String], authGitHosts: [String]) {
        self.signsCommits = signsCommits
        self.authHosts = authHosts
        self.authGitHosts = authGitHosts
    }

    public var isSigningOnly: Bool { signsCommits && authHosts.isEmpty }
    public var isUnused: Bool { !signsCommits && authHosts.isEmpty }
    /// Commit signing is a git concept — offer it for git-service keys or a bare key, not for
    /// a plain server-login key where it's meaningless.
    public var canOfferSigning: Bool { !signsCommits && (isUnused || !authGitHosts.isEmpty) }
}

public enum KeyUsageResolver {
    /// Resolve a fob key's usage from the configured signing-key basenames (global + every
    /// includeIf identity's `user.signingkey`) and the parsed ssh `Host` blocks. Pure.
    public static func resolve(name: String, signingBases: Set<String>,
                               blocks: [HostSetup.HostBlock]) -> KeyUsage {
        let pubBase = "fob_\(name).pub"
        let mine = blocks.filter {
            $0.parsed.identityFiles.contains { ($0 as NSString).lastPathComponent == pubBase }
        }
        let gitHosts = mine
            .filter { HostSetup.isGitHost(hostName: $0.parsed.hostName ?? $0.alias, user: $0.parsed.user) }
            .map(\.alias)
        return KeyUsage(signsCommits: signingBases.contains(pubBase),
                        authHosts: Array(Set(mine.map(\.alias))).sorted(),
                        authGitHosts: Array(Set(gitHosts)).sorted())
    }
}
