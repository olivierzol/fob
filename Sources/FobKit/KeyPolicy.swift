import CryptoKit
import Foundation

/// Per-key signing policy, stored next to the key blob as <name>.policy (JSON).
/// Absent file = default policy (no pinning, touch required every time).
public struct KeyPolicy: Codable {
    /// Host-key blobs this key may sign for. Empty = any destination.
    /// Non-empty = the agent refuses unbound connections and any destination
    /// whose (verified) host key is not in this list.
    public var pinnedHostKeys: [Data] = []

    /// Seconds a successful Touch ID may be reused without re-prompting (max 300).
    /// nil/0 = touch required for every signature. Applies to Touch ID only.
    public var reuseSeconds: Double?

    /// SSHSIG namespaces this key may sign for (`ssh-keygen -Y sign` / git commit
    /// signing). `nil` = any namespace allowed (the default, mirroring "no pin");
    /// a list = only those namespaces (e.g. ["git"]); `[]` = signing disabled.
    /// Does not affect SSH authentication, which is governed by `pinnedHostKeys`.
    public var allowedNamespaces: [String]?

    /// Set once the user has *explicitly* chosen this key's namespace restriction (ticked or
    /// unticked "only sign git commits"). It stops the signing page from re-hardening a key
    /// whose restriction the user deliberately cleared — `nil` allowedNamespaces alone can't
    /// tell "never decided" from "chose unrestricted". Optional (nil = never chosen) so old
    /// `.policy` JSON that predates this field still decodes (synthesized Codable requires a
    /// key for non-optional properties even when they have a default).
    public var namespaceChoiceMade: Bool?

    public var isDefault: Bool {
        pinnedHostKeys.isEmpty && (reuseSeconds ?? 0) <= 0
            && allowedNamespaces == nil && namespaceChoiceMade != true
    }

    /// Whether an SSHSIG signature for `namespace` is permitted by this policy.
    public func allowsSignature(namespace: String) -> Bool {
        guard let allowedNamespaces else { return true } // nil = any
        return allowedNamespaces.contains(namespace)
    }

    /// Whether the signing page should auto-harden this key to git-only: only when it's a
    /// dedicated signing key (no SSH-auth role), currently unrestricted, and the user hasn't
    /// made an explicit namespace choice yet. Never overrides a deliberate user decision.
    public func shouldAutoHardenSigning(isSigningOnly: Bool) -> Bool {
        isSigningOnly && allowedNamespaces == nil && namespaceChoiceMade != true
    }

    public init(pinnedHostKeys: [Data] = [], reuseSeconds: Double? = nil,
                allowedNamespaces: [String]? = nil, namespaceChoiceMade: Bool? = nil) {
        self.pinnedHostKeys = pinnedHostKeys
        self.reuseSeconds = reuseSeconds
        self.allowedNamespaces = allowedNamespaces
        self.namespaceChoiceMade = namespaceChoiceMade
    }
}

/// Result of loading a key's policy file, so the agent can tell "no policy, open by
/// design" apart from "policy present but unreadable" and fail closed on the latter.
public enum PolicyStatus {
    case absent               // no file → default (open) policy, as intended
    case present(KeyPolicy)   // parsed cleanly
    case unreadable           // file exists but couldn't be read/decoded → fail closed
}

extension KeyStore {
    /// Distinguishes absent (open by design) from present-but-corrupt/unreadable (must
    /// fail closed): a security control silently vanishing on corruption is a fail-open
    /// bug, so the agent refuses to sign when a policy is `.unreadable`. Delegates to
    /// the active `PolicyStore` (keychain when available, files otherwise).
    public func policyStatus(name: String) -> PolicyStatus {
        do {
            if let policy = try policyStore.load(name: name) { return .present(policy) }
            return .absent
        } catch {
            return .unreadable
        }
    }

    /// Convenience for display contexts (CLI/UI): an unreadable policy shows as the
    /// default. Signing decisions MUST use `policyStatus` so corruption fails closed.
    public func policy(name: String) -> KeyPolicy {
        if case .present(let policy) = policyStatus(name: name) { return policy }
        return KeyPolicy()
    }

    public func savePolicy(_ policy: KeyPolicy, name: String) throws {
        // A default (open) policy is represented by the absence of a record.
        if policy.isDefault {
            try policyStore.remove(name: name)
        } else {
            try policyStore.save(policy, name: name)
        }
    }
}

extension HostResolver {
    /// All host-key blobs recorded for `host` in ~/.ssh/known_hosts. Pass `port` when
    /// it's known (matches the exact `[host]:port` form ssh stores for non-default
    /// ports, including inside hashed `|1|…` entries); pass nil to match the host on
    /// **any** port — the right default for pinning, since a server's host key is the
    /// same whichever port you reach it on.
    public static func knownHostKeys(for host: String, port: Int? = nil) -> [Data] {
        let url = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".ssh/known_hosts")
        guard let contents = try? String(contentsOf: url, encoding: .utf8) else { return [] }
        return hostKeys(inKnownHosts: contents, host: host, port: port)
    }

    /// Pure matcher over known_hosts contents (testable without touching the filesystem).
    static func hostKeys(inKnownHosts contents: String, host: String, port: Int?) -> [Data] {
        var blobs: [Data] = []
        for line in contents.split(separator: "\n") {
            let fields = line.split(separator: " ", omittingEmptySubsequences: true)
            // skip @cert-authority / @revoked lines: not directly presented host keys
            guard fields.count >= 3, fields[0].hasPrefix("@") == false else { continue }
            let matches = fields[0].split(separator: ",").contains { patternSub in
                let pattern = String(patternSub)
                if pattern.hasPrefix("|1|") {
                    // Hashed: the hash covers the exact string ssh used, incl. the port.
                    if let port, port != 22 { return hashedPatternMatches(pattern, host: "[\(host)]:\(port)") }
                    return hashedPatternMatches(pattern, host: host)
                }
                if let port {
                    return port == 22 ? (pattern == host || pattern == "[\(host)]:22")
                                      : pattern == "[\(host)]:\(port)"
                }
                // Port unknown → match the host on any port.
                return pattern == host || pattern.hasPrefix("[\(host)]:")
            }
            guard matches, let blob = Data(base64Encoded: String(fields[2])) else { continue }
            if !blobs.contains(blob) { blobs.append(blob) }
        }
        return blobs
    }

    /// HashKnownHosts format: |1|base64(salt)|base64(HMAC-SHA1(salt, hostname))
    private static func hashedPatternMatches(_ pattern: String, host: String) -> Bool {
        let parts = pattern.split(separator: "|")
        guard parts.count == 3,
              let salt = Data(base64Encoded: String(parts[1])),
              let expected = Data(base64Encoded: String(parts[2])) else { return false }
        let mac = HMAC<Insecure.SHA1>.authenticationCode(
            for: Data(host.utf8), using: SymmetricKey(data: salt))
        return Data(mac) == expected
    }
}
