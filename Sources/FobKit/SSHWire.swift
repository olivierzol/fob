import CryptoKit
import Foundation

/// Minimal SSH wire-format encoding/decoding (RFC 4251 primitives),
/// just enough for the agent protocol and ecdsa-sha2-nistp256 blobs.

struct SSHWriter {
    private(set) var data = Data()

    mutating func writeByte(_ value: UInt8) {
        data.append(value)
    }

    mutating func writeUInt32(_ value: UInt32) {
        withUnsafeBytes(of: value.bigEndian) { data.append(contentsOf: $0) }
    }

    mutating func writeString(_ value: Data) {
        writeUInt32(UInt32(value.count))
        data.append(value)
    }

    mutating func writeString(_ value: String) {
        writeString(Data(value.utf8))
    }

    /// Encodes a positive integer given as raw big-endian bytes.
    mutating func writeMPInt(_ raw: Data) {
        var bytes = Data(raw.drop(while: { $0 == 0 }))
        if let first = bytes.first, first & 0x80 != 0 {
            bytes.insert(0, at: 0)
        }
        writeString(bytes)
    }
}

struct SSHReader {
    private let bytes: [UInt8]
    private var offset = 0

    init(_ data: Data) {
        self.bytes = [UInt8](data)
    }

    var isAtEnd: Bool { offset >= bytes.count }

    mutating func readByte() throws -> UInt8 {
        guard offset < bytes.count else { throw SSHWireError.truncated }
        defer { offset += 1 }
        return bytes[offset]
    }

    mutating func readUInt32() throws -> UInt32 {
        guard offset + 4 <= bytes.count else { throw SSHWireError.truncated }
        let value = bytes[offset..<offset + 4].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        offset += 4
        return value
    }

    mutating func readString() throws -> Data {
        let length = Int(try readUInt32())
        guard offset + length <= bytes.count else { throw SSHWireError.truncated }
        defer { offset += length }
        return Data(bytes[offset..<offset + length])
    }
}

enum SSHWireError: LocalizedError {
    case truncated

    var errorDescription: String? {
        switch self {
        case .truncated: return "truncated SSH wire message"
        }
    }
}

public enum SSHFormat {
    static let keyType = "ecdsa-sha2-nistp256"

    /// SSH public key blob: string type, string curve, string EC point (uncompressed).
    static func publicKeyBlob(_ publicKey: P256.Signing.PublicKey) -> Data {
        var writer = SSHWriter()
        writer.writeString(keyType)
        writer.writeString("nistp256")
        writer.writeString(publicKey.x963Representation)
        return writer.data
    }

    /// Line suitable for authorized_keys / GitHub.
    public static func authorizedKeysLine(_ publicKey: P256.Signing.PublicKey, comment: String) -> String {
        "\(keyType) \(publicKeyBlob(publicKey).base64EncodedString()) \(comment)"
    }

    /// SSH signature blob: string type, string (mpint r, mpint s).
    static func signatureBlob(_ signature: P256.Signing.ECDSASignature) -> Data {
        let raw = signature.rawRepresentation // r (32 bytes) || s (32 bytes)
        var inner = SSHWriter()
        inner.writeMPInt(Data(raw.prefix(32)))
        inner.writeMPInt(Data(raw.suffix(32)))
        var writer = SSHWriter()
        writer.writeString(keyType)
        writer.writeString(inner.data)
        return writer.data
    }
}

/// The SSHSIG signing envelope (`ssh-keygen -Y sign`, which is how git signs commits).
/// The blob handed to the agent is the signed-data structure from PROTOCOL.sshsig:
///
///     "SSHSIG"  string namespace  string reserved
///     string hash_algorithm  string H(message)
///
/// The magic + namespace exist to keep an SSHSIG signature from being usable in another
/// protocol (domain separation). We therefore parse it *strictly*: a blob that carries
/// the magic but doesn't conform is treated as malformed and refused — never signed under
/// a misleading "git commit" label, and never allowed to fall through to the SSH-auth path.
enum SSHSIG {
    static let magic = Data("SSHSIG".utf8)

    struct Parsed: Equatable {
        let namespace: String
        let hashAlgorithm: String // "sha256" or "sha512"
    }

    /// The result of inspecting a to-be-signed blob.
    enum Classification: Equatable {
        case notSSHSIG          // no magic → an ordinary SSH authentication payload
        case malformed          // magic present but the envelope is invalid → refuse
        case valid(Parsed)      // a well-formed SSHSIG envelope → sign, gated by namespace
    }

    /// Digest sizes per hash algorithm (SHA-256 → 32 bytes, SHA-512 → 64).
    private static let digestSize = ["sha256": 32, "sha512": 64]

    /// Strictly classify `data`. Requires, after the magic: a non-empty valid-UTF-8
    /// namespace, a `reserved` string, `hash_algorithm ∈ {sha256, sha512}`, an `H(message)`
    /// whose length matches that algorithm, and no trailing bytes.
    static func classify(_ data: Data) -> Classification {
        guard data.count >= magic.count, data.prefix(magic.count) == magic else { return .notSSHSIG }
        var reader = SSHReader(Data(data.dropFirst(magic.count)))
        do {
            let namespaceData = try reader.readString()
            guard !namespaceData.isEmpty,
                  let namespace = String(bytes: namespaceData, encoding: .utf8) else { return .malformed }
            _ = try reader.readString() // reserved (any value, typically empty)
            let algoData = try reader.readString()
            guard let algo = String(bytes: algoData, encoding: .utf8),
                  let wantDigest = digestSize[algo] else { return .malformed }
            let digest = try reader.readString()
            guard digest.count == wantDigest else { return .malformed }
            guard reader.isAtEnd else { return .malformed } // reject trailing bytes
            return .valid(Parsed(namespace: namespace, hashAlgorithm: algo))
        } catch {
            return .malformed
        }
    }
}
