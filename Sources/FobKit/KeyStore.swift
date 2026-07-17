import CryptoKit
import Foundation
import LocalAuthentication
import Security

/// A Secure Enclave key persisted as its encrypted `dataRepresentation` blob on disk.
/// The blob is only usable by the Secure Enclave of this machine; it is not key material.
public struct StoredKey {
    public let name: String
    let dataRepresentation: Data

    public func privateKey(context: LAContext? = nil) throws -> SecureEnclave.P256.Signing.PrivateKey {
        try SecureEnclave.P256.Signing.PrivateKey(
            dataRepresentation: dataRepresentation,
            authenticationContext: context
        )
    }

    /// Public key access never prompts for authentication.
    public func publicKey() throws -> P256.Signing.PublicKey {
        try privateKey().publicKey
    }
}

public struct KeyStore {
    public let directory: URL
    /// Where signing policies live. Injectable for tests; `default()` picks the
    /// code-identity-gated keychain when the signed build allows it, else files.
    let policyStore: PolicyStore

    public init(directory: URL, policyStore: PolicyStore? = nil) {
        self.directory = directory
        self.policyStore = policyStore
            ?? FilePolicyStore(keysDirectory: directory.appendingPathComponent("keys"))
    }

    public static func `default`() throws -> KeyStore {
        let dir = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".fob")
        try FileManager.default.createDirectory(
            at: dir,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        let keysDir = dir.appendingPathComponent("keys")
        try FileManager.default.createDirectory(
            at: keysDir,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        // createDirectory only applies permissions when it creates the directory, so a
        // pre-existing ~/.fob (from an older build, a restore, or a bad umask) could be
        // world-readable. Re-assert 0700 on every startup — these hold key blobs,
        // policies, and the audit log.
        try? FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: dir.path)
        try? FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: keysDir.path)
        return KeyStore(directory: dir, policyStore: selectPolicyStore(keysDirectory: keysDir))
    }

    /// Prefer the keychain (code-identity gated) when the signed build supports it,
    /// migrating any existing file policies into it first. If the keychain is
    /// unavailable — or a file policy can't be migrated (so we'd risk dropping a pin) —
    /// stay on the file store. Always yields a working store.
    private static func selectPolicyStore(keysDirectory: URL) -> PolicyStore {
        let file = FilePolicyStore(keysDirectory: keysDirectory)
        guard KeychainPolicyStore.isAvailable() else {
            diagnostic("policy store: files (keychain unavailable — dev/unsigned build)")
            return file
        }
        let keychain = KeychainPolicyStore()
        guard keychain.migrate(from: file, keys: keyNames(in: keysDirectory)) else {
            diagnostic("policy store: files (keychain migration incomplete)")
            return file
        }
        diagnostic("policy store: keychain (code-identity gated)")
        return keychain
    }

    /// Key names present on disk (basename of each `<name>.key`), used to migrate their
    /// policies. Reads only filenames, never the enclave blobs.
    private static func keyNames(in keysDirectory: URL) -> [String] {
        let files = (try? FileManager.default.contentsOfDirectory(
            at: keysDirectory, includingPropertiesForKeys: nil)) ?? []
        return files.filter { $0.pathExtension == "key" }
            .map { $0.deletingPathExtension().lastPathComponent }
    }

    private static func diagnostic(_ message: String) {
        FileHandle.standardError.write(Data("[fob] \(message)\n".utf8))
    }

    public var keysDirectory: URL { directory.appendingPathComponent("keys") }
    public var socketPath: String { directory.appendingPathComponent("agent.sock").path }

    /// Path to the git-signing wrapper (`~/.fob/bin/fob-sign`). Set as git's
    /// `gpg.ssh.program` so *only* commit signing reaches fob's agent — SSH_AUTH_SOCK
    /// stays untouched, so other ssh agents and `git push` auth are unaffected.
    public var signWrapperPath: String {
        directory.appendingPathComponent("bin/fob-sign").path
    }

    /// Create (or refresh) the git-signing wrapper and return its path. The wrapper
    /// sets SSH_AUTH_SOCK to fob's socket only for the `ssh-keygen -Y sign` invocation
    /// that git runs, leaving the user's global agent selection alone.
    @discardableResult
    public func ensureSignWrapper() throws -> String {
        let bin = directory.appendingPathComponent("bin")
        try FileManager.default.createDirectory(
            at: bin, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        let wrapper = bin.appendingPathComponent("fob-sign")
        let script = """
        #!/bin/sh
        # fob: route only git's SSH signing to fob's agent, without touching SSH_AUTH_SOCK
        # (so your other ssh agents and `git push` auth are unaffected). Set as git's
        # gpg.ssh.program. Managed by fob — regenerated on setup.
        exec env SSH_AUTH_SOCK="\(socketPath)" /usr/bin/ssh-keygen "$@"

        """
        try script.data(using: .utf8)!.write(to: wrapper)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o755], ofItemAtPath: wrapper.path)
        return wrapper.path
    }

    /// Valid key/alias name: letters, digits, '.', '_', '-', and never a leading '-'.
    /// These names become CLI arguments (`ssh <alias>`, `-i <file>`) and filenames, so
    /// they must never be parseable as an option nor contain path/shell metacharacters.
    public static func isValidName(_ name: String) -> Bool {
        name.range(of: "^[A-Za-z0-9._][A-Za-z0-9._-]*$", options: .regularExpression) != nil
    }

    public func create(name: String, requireBiometry: Bool) throws -> StoredKey {
        guard SecureEnclave.isAvailable else {
            throw KeyStoreError.secureEnclaveUnavailable
        }
        guard Self.isValidName(name) else {
            throw KeyStoreError.invalidName(name)
        }
        let keyURL = keysDirectory.appendingPathComponent("\(name).key")
        guard !FileManager.default.fileExists(atPath: keyURL.path) else {
            throw KeyStoreError.keyExists(name)
        }

        let flags: SecAccessControlCreateFlags = requireBiometry
            ? [.privateKeyUsage, .biometryCurrentSet]
            : [.privateKeyUsage, .userPresence]
        var acError: Unmanaged<CFError>?
        guard let accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            flags,
            &acError
        ) else {
            let message = acError.map { String(describing: $0.takeRetainedValue()) } ?? "unknown"
            throw KeyStoreError.accessControl(message)
        }

        let privateKey = try SecureEnclave.P256.Signing.PrivateKey(accessControl: accessControl)
        try privateKey.dataRepresentation.write(to: keyURL, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: keyURL.path)

        let key = StoredKey(name: name, dataRepresentation: privateKey.dataRepresentation)
        let pubLine = SSHFormat.authorizedKeysLine(privateKey.publicKey, comment: "fob:\(name)")
        try Data((pubLine + "\n").utf8).write(to: keysDirectory.appendingPathComponent("\(name).pub"))
        return key
    }

    public func all() throws -> [StoredKey] {
        let files = try FileManager.default.contentsOfDirectory(
            at: keysDirectory,
            includingPropertiesForKeys: nil
        )
        return try files
            .filter { $0.pathExtension == "key" }
            .sorted { $0.lastPathComponent < $1.lastPathComponent }
            .map { url in
                StoredKey(
                    name: url.deletingPathExtension().lastPathComponent,
                    dataRepresentation: try Data(contentsOf: url)
                )
            }
    }

    public func find(name: String) throws -> StoredKey {
        guard let key = try all().first(where: { $0.name == name }) else {
            throw KeyStoreError.notFound(name)
        }
        return key
    }

    /// Delete a key and everything the store keeps beside it (public key + policy).
    /// The Secure Enclave private key is unrecoverable afterwards. The exported
    /// ~/.ssh/fob_<name>.pub (written by `setup`) is left alone — it lives in the
    /// user's ssh directory, not the store.
    public func remove(name: String) throws {
        _ = try find(name: name) // 404s cleanly if the key doesn't exist
        for ext in ["key", "pub", "policy"] {
            let url = keysDirectory.appendingPathComponent("\(name).\(ext)")
            if FileManager.default.fileExists(atPath: url.path) {
                try FileManager.default.removeItem(at: url)
            }
        }
        try? policyStore.remove(name: name) // also clear a keychain-backed policy
    }

    /// Rename a key in place: move its enclave blob, migrate its policy, and refresh the
    /// in-store public-key line's `fob:<name>` comment. Used by rotation to swap a freshly
    /// created key into the retired key's name so every reference (gitconfig `user.signingkey
    /// = ~/.ssh/fob_<name>.pub`, ssh-config `IdentityFile`) keeps working unchanged. The
    /// enclave key is unaffected — only its stored name changes. Throws if `from` is missing
    /// or `to` already exists. The exported ~/.ssh/fob_<name>.pub is the caller's to refresh.
    public func rename(from: String, to: String) throws {
        guard Self.isValidName(to) else { throw KeyStoreError.invalidName(to) }
        _ = try find(name: from) // 404s cleanly if the source is missing
        let fm = FileManager.default
        let toKey = keysDirectory.appendingPathComponent("\(to).key")
        guard !fm.fileExists(atPath: toKey.path) else { throw KeyStoreError.keyExists(to) }
        // Move the Secure Enclave blob.
        try fm.moveItem(at: keysDirectory.appendingPathComponent("\(from).key"), to: toKey)
        // Migrate the policy through the store (handles both file- and keychain-backed).
        if let policy = try? policyStore.load(name: from) {
            try policyStore.save(policy, name: to)
            try policyStore.remove(name: from)
        }
        // Rewrite the in-store public-key line with the new name's comment; drop the old.
        let moved = try find(name: to)
        let pubLine = SSHFormat.authorizedKeysLine(try moved.publicKey(), comment: "fob:\(to)")
        try Data((pubLine + "\n").utf8).write(
            to: keysDirectory.appendingPathComponent("\(to).pub"), options: .atomic)
        try? fm.removeItem(at: keysDirectory.appendingPathComponent("\(from).pub"))
    }
}

public enum KeyStoreError: LocalizedError {
    case secureEnclaveUnavailable
    case accessControl(String)
    case keyExists(String)
    case notFound(String)
    case invalidName(String)

    public var errorDescription: String? {
        switch self {
        case .secureEnclaveUnavailable:
            return "Secure Enclave is not available on this machine"
        case .accessControl(let message):
            return "failed to create access control: \(message)"
        case .keyExists(let name):
            return "a key named '\(name)' already exists"
        case .notFound(let name):
            return "no key named '\(name)'"
        case .invalidName(let name):
            return "invalid key name '\(name)' (letters, digits, '.', '_', '-'; must not start with '-')"
        }
    }
}
