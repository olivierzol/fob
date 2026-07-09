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
        return KeyStore(directory: dir)
    }

    public var keysDirectory: URL { directory.appendingPathComponent("keys") }
    public var socketPath: String { directory.appendingPathComponent("agent.sock").path }

    public func create(name: String, requireBiometry: Bool) throws -> StoredKey {
        guard SecureEnclave.isAvailable else {
            throw KeyStoreError.secureEnclaveUnavailable
        }
        // No leading '-': these names end up as CLI arguments (ssh <alias>, -i <file>)
        // and must never be parseable as an option.
        guard name.range(of: "^[A-Za-z0-9._][A-Za-z0-9._-]*$", options: .regularExpression) != nil else {
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
