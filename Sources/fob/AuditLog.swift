import CryptoKit
import Foundation

/// Append-only, tamper-evident record of every agent decision.
///
/// One JSON object per line in ~/.fob/audit.log. Each entry carries
/// `prev`: the SHA-256 of the previous line's exact bytes ("genesis" for the
/// first). Editing or deleting any line breaks the chain for every line after
/// it, which `fob audit --verify` detects.
final class AuditLog {
    struct Entry: Codable {
        let ts: String
        let event: String
        let key: String?
        let dest: String?
        let peer: String?
        let prev: String
    }

    private let url: URL
    private let queue = DispatchQueue(label: "dev.fob.audit")
    private var lastHash: String

    init(directory: URL) {
        url = Self.logURL(directory: directory)
        lastHash = Self.chainHead(url: url)
    }

    static func logURL(directory: URL) -> URL {
        directory.appendingPathComponent("audit.log")
    }

    func record(_ event: String, key: String? = nil, destination: String? = nil, peer: String? = nil) {
        let timestamp = ISO8601DateFormatter().string(from: Date())
        queue.async { [self] in
            let entry = Entry(ts: timestamp, event: event, key: key,
                              dest: destination, peer: peer, prev: lastHash)
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys]
            guard let line = try? encoder.encode(entry) else { return }
            guard let handle = fileHandleForAppend() else { return }
            defer { try? handle.close() }
            try? handle.write(contentsOf: line + Data("\n".utf8))
            lastHash = Self.hash(line)
        }
    }

    private func fileHandleForAppend() -> FileHandle? {
        if !FileManager.default.fileExists(atPath: url.path) {
            FileManager.default.createFile(atPath: url.path, contents: nil,
                                           attributes: [.posixPermissions: 0o600])
        }
        guard let handle = try? FileHandle(forWritingTo: url) else { return nil }
        try? handle.seekToEnd()
        return handle
    }

    // MARK: - Reading & verification (also used by the CLI)

    static func entries(directory: URL) -> [Entry] {
        rawLines(directory: directory).compactMap {
            try? JSONDecoder().decode(Entry.self, from: $0)
        }
    }

    /// Walks the hash chain. Returns the 1-based line number of the first broken
    /// link, or nil if the whole log is intact.
    static func firstBrokenLink(directory: URL) -> Int? {
        var expected = "genesis"
        for (index, line) in rawLines(directory: directory).enumerated() {
            guard let entry = try? JSONDecoder().decode(Entry.self, from: line),
                  entry.prev == expected else { return index + 1 }
            expected = hash(line)
        }
        return nil
    }

    /// Lines as exact bytes (the log is JSON, so UTF-8 round-trips faithfully).
    private static func rawLines(directory: URL) -> [Data] {
        guard let data = try? Data(contentsOf: logURL(directory: directory)) else { return [] }
        return String(decoding: data, as: UTF8.self)
            .split(separator: "\n")
            .map { Data($0.utf8) }
    }

    private static func chainHead(url: URL) -> String {
        guard let data = try? Data(contentsOf: url) else { return "genesis" }
        guard let last = String(decoding: data, as: UTF8.self).split(separator: "\n").last
        else { return "genesis" }
        return hash(Data(last.utf8))
    }

    private static func hash(_ line: Data) -> String {
        SHA256.hash(data: line).map { String(format: "%02x", $0) }.joined()
    }
}
