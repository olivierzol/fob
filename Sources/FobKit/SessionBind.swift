import CryptoKit
import Foundation
import Security

/// The `session-bind@openssh.com` agent extension (OpenSSH PROTOCOL.agent).
///
/// Before requesting signatures, modern ssh clients bind their agent connection
/// to the destination: they send the server's host key, the session ID, and the
/// host key's KEX signature over that session ID. Verifying the signature proves
/// a server holding that host key really participated in the session — a local
/// process cannot claim a destination it didn't actually connect to.
struct SessionBinding {
    let hostKeyBlob: Data
    let sessionID: Data
    let isForwarding: Bool
    /// false when the host key type is one we cannot verify (binding is then advisory)
    let verified: Bool

    /// "alias (hostname)" via known_hosts + ssh config, or a key fingerprint.
    var destination: String {
        let name = HostResolver.name(forHostKeyBlob: hostKeyBlob) ?? fingerprint
        return verified ? name : "\(name) (unverified)"
    }

    private var fingerprint: String {
        "host key SHA256:\(Data(SHA256.hash(data: hostKeyBlob)).base64EncodedString().trimmingCharacters(in: CharacterSet(charactersIn: "=")))"
    }

    /// Parses the extension payload (after the extension-name string).
    /// Returns nil if the payload is malformed or the signature fails to verify.
    static func parse(_ reader: inout SSHReader) -> SessionBinding? {
        guard let hostKey = try? reader.readString(),
              let sessionID = try? reader.readString(),
              let signature = try? reader.readString(),
              let forwarding = try? reader.readByte() else { return nil }
        switch HostKeySignature.verify(hostKeyBlob: hostKey, signatureBlob: signature, message: sessionID) {
        case .valid:
            return SessionBinding(hostKeyBlob: hostKey, sessionID: sessionID,
                                  isForwarding: forwarding != 0, verified: true)
        case .invalid:
            return nil
        case .unsupportedKeyType:
            return SessionBinding(hostKeyBlob: hostKey, sessionID: sessionID,
                                  isForwarding: forwarding != 0, verified: false)
        }
    }

    /// OpenSSH binding rules: re-binding an identical destination is fine; adding a
    /// new one is only allowed while every existing binding was made for forwarding.
    static func add(_ new: SessionBinding, to bindings: inout [SessionBinding]) -> Bool {
        if bindings.contains(where: {
            $0.hostKeyBlob == new.hostKeyBlob && $0.sessionID == new.sessionID
        }) { return true }
        guard bindings.allSatisfy(\.isForwarding) else { return false }
        bindings.append(new)
        return true
    }

    /// Human description of a connection's binding chain for prompts/notifications.
    static func describe(_ bindings: [SessionBinding]) -> String {
        guard !bindings.isEmpty else { return "an UNKNOWN destination" }
        return bindings.map(\.destination).joined(separator: " → ")
    }
}

/// Verifies an SSH signature blob against a host public-key blob.
enum HostKeySignature {
    enum Result {
        case valid
        case invalid
        case unsupportedKeyType
    }

    static func verify(hostKeyBlob: Data, signatureBlob: Data, message: Data) -> Result {
        do {
            var keyReader = SSHReader(hostKeyBlob)
            let keyType = String(decoding: try keyReader.readString(), as: UTF8.self)
            var sigReader = SSHReader(signatureBlob)
            let sigType = String(decoding: try sigReader.readString(), as: UTF8.self)
            let signature = try sigReader.readString()

            switch keyType {
            case "ssh-ed25519":
                let raw = try keyReader.readString()
                let key = try Curve25519.Signing.PublicKey(rawRepresentation: raw)
                return key.isValidSignature(signature, for: message) ? .valid : .invalid

            case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
                _ = try keyReader.readString() // curve name, implied by the type
                let point = try keyReader.readString()
                let rawSig = try ecdsaRawSignature(signature, componentSize: keyType.hasSuffix("256") ? 32 : keyType.hasSuffix("384") ? 48 : 66)
                switch keyType {
                case "ecdsa-sha2-nistp256":
                    let key = try P256.Signing.PublicKey(x963Representation: point)
                    return key.isValidSignature(try P256.Signing.ECDSASignature(rawRepresentation: rawSig), for: message) ? .valid : .invalid
                case "ecdsa-sha2-nistp384":
                    let key = try P384.Signing.PublicKey(x963Representation: point)
                    return key.isValidSignature(try P384.Signing.ECDSASignature(rawRepresentation: rawSig), for: message) ? .valid : .invalid
                default:
                    let key = try P521.Signing.PublicKey(x963Representation: point)
                    return key.isValidSignature(try P521.Signing.ECDSASignature(rawRepresentation: rawSig), for: message) ? .valid : .invalid
                }

            case "ssh-rsa":
                let e = try keyReader.readString()
                let n = try keyReader.readString()
                let algorithm: SecKeyAlgorithm
                switch sigType {
                case "rsa-sha2-256": algorithm = .rsaSignatureMessagePKCS1v15SHA256
                case "rsa-sha2-512": algorithm = .rsaSignatureMessagePKCS1v15SHA512
                case "ssh-rsa":      algorithm = .rsaSignatureMessagePKCS1v15SHA1
                default: return .invalid
                }
                guard let key = rsaPublicKey(e: e, n: n) else { return .unsupportedKeyType }
                return SecKeyVerifySignature(key, algorithm, message as CFData, signature as CFData, nil)
                    ? .valid : .invalid

            default:
                return .unsupportedKeyType // e.g. sk-* security-key host keys, ssh-dss
            }
        } catch {
            return .invalid
        }
    }

    /// SSH ECDSA signatures carry (mpint r, mpint s); CryptoKit wants fixed-size r||s.
    private static func ecdsaRawSignature(_ blob: Data, componentSize: Int) throws -> Data {
        var reader = SSHReader(blob)
        func fixed(_ mpint: Data) throws -> Data {
            let stripped = mpint.drop(while: { $0 == 0 })
            guard stripped.count <= componentSize else { throw SSHWireError.truncated }
            return Data(repeating: 0, count: componentSize - stripped.count) + stripped
        }
        return try fixed(reader.readString()) + fixed(reader.readString())
    }

    /// Builds a SecKey from SSH mpints via PKCS#1 DER: SEQUENCE { INTEGER n, INTEGER e }.
    /// SSH mpints and DER integers share the same minimal big-endian encoding.
    private static func rsaPublicKey(e: Data, n: Data) -> SecKey? {
        func derInteger(_ bytes: Data) -> Data {
            let content = bytes.isEmpty ? Data([0]) : bytes
            return Data([0x02]) + derLength(content.count) + content
        }
        func derLength(_ length: Int) -> Data {
            if length < 0x80 { return Data([UInt8(length)]) }
            var bytes = withUnsafeBytes(of: UInt32(length).bigEndian) { Data($0) }
            bytes = bytes.drop(while: { $0 == 0 })
            return Data([0x80 | UInt8(bytes.count)]) + bytes
        }
        let body = derInteger(n) + derInteger(e)
        let der = Data([0x30]) + derLength(body.count) + body
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: kSecAttrKeyClassPublic,
        ]
        return SecKeyCreateWithData(der as CFData, attributes as CFDictionary, nil)
    }
}

/// Maps a host-key blob back to a human-readable name using ~/.ssh/known_hosts,
/// then upgrades it to the user's ssh-config alias when one points at that host.
public enum HostResolver {
    public static func name(forHostKeyBlob blob: Data) -> String? {
        guard let hostname = knownHostsName(forHostKeyBlob: blob) else { return nil }
        if let alias = configAlias(forHostName: hostname), alias != hostname {
            return "\(alias) (\(hostname))"
        }
        return hostname
    }

    private static func knownHostsName(forHostKeyBlob blob: Data) -> String? {
        let url = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".ssh/known_hosts")
        guard let contents = try? String(contentsOf: url, encoding: .utf8) else { return nil }
        for line in contents.split(separator: "\n") {
            var fields = line.split(separator: " ", omittingEmptySubsequences: true)
            if fields.first?.hasPrefix("@") == true { fields.removeFirst() } // @cert-authority etc.
            guard fields.count >= 3,
                  let candidate = Data(base64Encoded: String(fields[2])),
                  candidate == blob else { continue }
            // First non-hashed host entry; hashed entries can't be reversed to a name.
            guard let host = fields[0].split(separator: ",").first(where: { !$0.hasPrefix("|") })
            else { continue }
            return String(host).replacingOccurrences(of: "[", with: "")
                .replacingOccurrences(of: "]", with: "") // keep [host]:port readable
        }
        return nil
    }

    private static func configAlias(forHostName hostname: String) -> String? {
        let url = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".ssh/config")
        guard let contents = try? String(contentsOf: url, encoding: .utf8) else { return nil }
        var currentAliases: [String] = []
        for rawLine in contents.split(separator: "\n") {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            let lowered = line.lowercased()
            if lowered.hasPrefix("host ") {
                currentAliases = line.dropFirst("host ".count)
                    .split(separator: " ").map(String.init)
                    .filter { !$0.contains("*") && !$0.contains("?") }
            } else if lowered.hasPrefix("hostname ") || lowered.hasPrefix("hostname\t") {
                let value = line.dropFirst("hostname".count).trimmingCharacters(in: .whitespaces)
                if value == hostname, let alias = currentAliases.first {
                    return alias
                }
            }
        }
        return nil
    }
}
