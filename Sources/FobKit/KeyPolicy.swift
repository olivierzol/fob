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

    public var isDefault: Bool { pinnedHostKeys.isEmpty && (reuseSeconds ?? 0) <= 0 }

    public init(pinnedHostKeys: [Data] = [], reuseSeconds: Double? = nil) {
        self.pinnedHostKeys = pinnedHostKeys
        self.reuseSeconds = reuseSeconds
    }
}

extension KeyStore {
    private func policyURL(name: String) -> URL {
        keysDirectory.appendingPathComponent("\(name).policy")
    }

    /// Never throws: an unreadable/corrupt policy degrades to the default (open) policy.
    public func policy(name: String) -> KeyPolicy {
        guard let data = try? Data(contentsOf: policyURL(name: name)),
              let policy = try? JSONDecoder().decode(KeyPolicy.self, from: data)
        else { return KeyPolicy() }
        return policy
    }

    public func savePolicy(_ policy: KeyPolicy, name: String) throws {
        let url = policyURL(name: name)
        if policy.isDefault {
            try? FileManager.default.removeItem(at: url)
            return
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        try (try encoder.encode(policy)).write(to: url, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }
}

extension HostResolver {
    /// All host-key blobs recorded for `host` in ~/.ssh/known_hosts.
    /// Matches plain entries, `[host]:port` entries, and hashed (`|1|…`) entries.
    public static func knownHostKeys(for host: String) -> [Data] {
        let url = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".ssh/known_hosts")
        guard let contents = try? String(contentsOf: url, encoding: .utf8) else { return [] }
        var blobs: [Data] = []
        for line in contents.split(separator: "\n") {
            let fields = line.split(separator: " ", omittingEmptySubsequences: true)
            // skip @cert-authority / @revoked lines: not directly presented host keys
            guard fields.count >= 3, fields[0].hasPrefix("@") == false else { continue }
            let matches = fields[0].split(separator: ",").contains { pattern in
                if pattern.hasPrefix("|1|") { return hashedPatternMatches(String(pattern), host: host) }
                return pattern == Substring(host) || pattern == Substring("[\(host)]:22")
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
