import Foundation
import Security

/// Where a key's signing policy (pins, reuse window) is persisted.
///
/// Two backends, chosen at startup by `KeyStore`:
///
/// - `KeychainPolicyStore` — the data-protection keychain, gated by fob's code-signing
///   identity via a keychain access group. Other code running as the *same user* (a
///   different app, malware) cannot read, modify, or delete these items, so it cannot
///   silently weaken or drop a pin — the OS enforces this by *who signed the code*, not
///   just by UID. Requires the signed build + the `keychain-access-groups` entitlement.
///
/// - `FilePolicyStore` — JSON files under `~/.fob/keys` (`0600`). UID-gated only. Used
///   as a fallback for unsigned/dev builds where the entitlement isn't present, so the
///   agent always works even when the stronger backend is unavailable.
///
/// `load` returns `nil` for "no record" (open by design) and **throws** on a backend or
/// decode error — callers MUST fail closed on a throw (see `KeyStore.policyStatus`).
public protocol PolicyStore {
    func load(name: String) throws -> KeyPolicy?
    func save(_ policy: KeyPolicy, name: String) throws
    func remove(name: String) throws
}

public enum PolicyStoreError: Error {
    case keychain(OSStatus)
    case decode
}

/// JSON-file backend (the historical layout). Only as strong as the filesystem: any
/// process with your UID can read/rewrite these, so it cannot defend a pin against
/// same-user malware — that's what `KeychainPolicyStore` is for.
public struct FilePolicyStore: PolicyStore {
    let keysDirectory: URL

    public init(keysDirectory: URL) { self.keysDirectory = keysDirectory }

    private func url(_ name: String) -> URL {
        keysDirectory.appendingPathComponent("\(name).policy")
    }

    public func load(name: String) throws -> KeyPolicy? {
        let fileURL = url(name)
        guard FileManager.default.fileExists(atPath: fileURL.path) else { return nil }
        let data = try Data(contentsOf: fileURL)                     // throws → fail closed
        return try JSONDecoder().decode(KeyPolicy.self, from: data)  // throws → fail closed
    }

    public func save(_ policy: KeyPolicy, name: String) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        try encoder.encode(policy).write(to: url(name), options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url(name).path)
    }

    public func remove(name: String) throws {
        let fileURL = url(name)
        if FileManager.default.fileExists(atPath: fileURL.path) {
            try FileManager.default.removeItem(at: fileURL)
        }
    }
}

/// Code-identity-gated backend. Stores each policy as a generic-password item in the
/// data-protection keychain, in fob's own access group. Because access is enforced by
/// the entitlement (hence by code signature), a same-user process that isn't signed as
/// fob cannot read, forge, or delete these — closing the "malware silently unpins a
/// key" and "malware deletes the policy to downgrade to open" gaps that a plain file
/// cannot. Only available in the signed build; `isAvailable()` probes for it.
public struct KeychainPolicyStore: PolicyStore {
    private let service = "dev.fob.policy"
    private let accessGroup: String?

    public init() { accessGroup = Self.discoverAccessGroup() }

    /// Our access group is whatever the `keychain-access-groups` entitlement grants
    /// (team-prefixed). Reading it at runtime avoids hard-coding the team id and works
    /// for any signing identity. nil in unsigned/unentitled builds.
    private static func discoverAccessGroup() -> String? {
        guard let task = SecTaskCreateFromSelf(nil),
              let value = SecTaskCopyValueForEntitlement(task, "keychain-access-groups" as CFString, nil),
              let groups = value as? [String] else { return nil }
        return groups.first
    }

    private func baseQuery(_ account: String) -> [CFString: Any] {
        var query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecUseDataProtectionKeychain: true,
            kSecAttrService: service,
            kSecAttrAccount: account,
        ]
        if let accessGroup { query[kSecAttrAccessGroup] = accessGroup }
        return query
    }

    public func load(name: String) throws -> KeyPolicy? {
        var query = baseQuery(name)
        query[kSecReturnData] = true
        query[kSecMatchLimit] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else {
            throw PolicyStoreError.keychain(status)
        }
        guard let policy = try? JSONDecoder().decode(KeyPolicy.self, from: data) else {
            throw PolicyStoreError.decode
        }
        return policy
    }

    public func save(_ policy: KeyPolicy, name: String) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(policy)
        let update = SecItemUpdate(baseQuery(name) as CFDictionary,
                                   [kSecValueData: data] as CFDictionary)
        if update == errSecSuccess { return }
        guard update == errSecItemNotFound else { throw PolicyStoreError.keychain(update) }
        var add = baseQuery(name)
        add[kSecValueData] = data
        add[kSecAttrAccessible] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let addStatus = SecItemAdd(add as CFDictionary, nil)
        guard addStatus == errSecSuccess else { throw PolicyStoreError.keychain(addStatus) }
    }

    public func remove(name: String) throws {
        let status = SecItemDelete(baseQuery(name) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw PolicyStoreError.keychain(status)
        }
    }

    /// True if this build can actually use the protected keychain (entitlement present
    /// and functional). Probes with a sentinel round-trip and returns false on any
    /// failure, so callers fall back to files rather than break.
    public static func isAvailable() -> Bool {
        let store = KeychainPolicyStore()
        let probe = "__fob_probe__"
        defer { try? store.remove(name: probe) }
        do {
            try store.save(KeyPolicy(), name: probe)
            return try store.load(name: probe) != nil
        } catch {
            return false
        }
    }

    /// Copy meaningful (non-default) file policies into the keychain, once, without
    /// clobbering an existing keychain record. Returns false if a policy that exists as
    /// a file could not be carried over — the caller then stays on the file store
    /// rather than risk silently losing a pin.
    func migrate(from file: FilePolicyStore, keys: [String]) -> Bool {
        for name in keys {
            let filePolicy: KeyPolicy?
            do { filePolicy = try file.load(name: name) } catch { return false }
            guard let policy = filePolicy, !policy.isDefault else { continue }
            do {
                if try load(name: name) == nil { try save(policy, name: name) }
            } catch {
                return false
            }
        }
        return true
    }
}
