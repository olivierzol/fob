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
/// The blob handed to the agent starts with the literal magic "SSHSIG" followed by a
/// namespace string ("git" for commits) — letting the agent tell a *signature*
/// operation apart from an SSH *authentication* and label / gate it accordingly.
enum SSHSIG {
    static let magic = Data("SSHSIG".utf8)

    /// The namespace of an SSHSIG blob, or nil if `data` isn't one (e.g. it's an
    /// ordinary SSH authentication payload, which never starts with this magic).
    static func namespace(of data: Data) -> String? {
        guard data.count > magic.count, data.prefix(magic.count) == magic else { return nil }
        var reader = SSHReader(Data(data.dropFirst(magic.count)))
        guard let namespace = try? reader.readString() else { return nil }
        return String(decoding: namespace, as: UTF8.self)
    }
}
