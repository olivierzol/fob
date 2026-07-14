import Foundation

/// Read-only SSH hygiene checks. The pure detection lives here (encryption detection,
/// risky-directive scanning, permission rules) so it's testable; file enumeration and
/// subprocess calls (`ssh-keygen -l`, stat) live in the app/CLI layer that builds the
/// full report. Nothing here writes anything.
public enum SSHCheckup {
    public enum Severity: Int, Comparable {
        case high = 0, medium = 1, low = 2, opportunity = 3, ok = 4
        public static func < (a: Severity, b: Severity) -> Bool { a.rawValue < b.rawValue }
        public var label: String {
            switch self {
            case .high: return "HIGH"
            case .medium: return "MEDIUM"
            case .low: return "LOW"
            case .opportunity: return "IMPROVE"
            case .ok: return "OK"
            }
        }
    }

    /// What the UI/CLI can offer for a finding (all opt-in; the checkup never acts itself).
    public enum FixHint: Equatable {
        case migrate(alias: String) // open the Migrate flow for this host
        case signing               // open the commit-signing flow
        case command(String)       // copy-paste guidance (a config line / chmod)
        case revealFile(String)    // reveal a key file in Finder
        case none
    }

    public struct Finding: Equatable, Identifiable {
        public let severity: Severity
        public let category: String   // "Key" · "Config" · "Opportunity"
        public let title: String
        public let detail: String
        public let fix: FixHint
        public var id: String { "\(category)|\(title)" }
        public init(severity: Severity, category: String, title: String, detail: String, fix: FixHint) {
            self.severity = severity
            self.category = category
            self.title = title
            self.detail = detail
            self.fix = fix
        }
    }

    // MARK: - Private-key encryption detection

    public struct PrivateKeyInfo: Equatable {
        public let isEncrypted: Bool
        public init(isEncrypted: Bool) { self.isEncrypted = isEncrypted }
    }

    /// Determine whether a private-key file is passphrase-encrypted. Returns nil if the
    /// contents aren't a private key at all. When the format is a private key but can't be
    /// parsed, errs on the side of `isEncrypted: true` (no false "unencrypted!" alarm).
    public static func parsePrivateKey(_ contents: String) -> PrivateKeyInfo? {
        if contents.contains("BEGIN OPENSSH PRIVATE KEY") {
            guard let b64 = base64Body(contents,
                                       begin: "-----BEGIN OPENSSH PRIVATE KEY-----",
                                       end: "-----END OPENSSH PRIVATE KEY-----"),
                  let data = Data(base64Encoded: b64) else {
                return PrivateKeyInfo(isEncrypted: true)
            }
            // Layout: "openssh-key-v1\0" magic, then uint32 len + ciphername. "none" == plain.
            let bytes = [UInt8](data)
            let magic = [UInt8]("openssh-key-v1\u{0}".utf8) // 15 bytes
            let i = magic.count
            guard bytes.count > i + 4, Array(bytes.prefix(i)) == magic else {
                return PrivateKeyInfo(isEncrypted: true)
            }
            let len = Int(bytes[i]) << 24 | Int(bytes[i + 1]) << 16 | Int(bytes[i + 2]) << 8 | Int(bytes[i + 3])
            guard len >= 0, bytes.count >= i + 4 + len else { return PrivateKeyInfo(isEncrypted: true) }
            let cipher = String(decoding: bytes[(i + 4)..<(i + 4 + len)], as: UTF8.self)
            return PrivateKeyInfo(isEncrypted: cipher != "none")
        }
        if contents.contains("PRIVATE KEY-----") {
            // Legacy PEM / PKCS#8: encrypted markers are "ENCRYPTED" (PKCS#8) or
            // "Proc-Type: 4,ENCRYPTED" / "DEK-Info:" (traditional).
            let enc = contents.contains("ENCRYPTED") || contents.contains("DEK-Info:")
            return PrivateKeyInfo(isEncrypted: enc)
        }
        return nil
    }

    private static func base64Body(_ contents: String, begin: String, end: String) -> String? {
        guard let b = contents.range(of: begin), let e = contents.range(of: end),
              b.upperBound <= e.lowerBound else { return nil }
        return contents[b.upperBound..<e.lowerBound].split(whereSeparator: \.isNewline).joined()
    }

    // MARK: - File permissions

    /// A private key readable by group or other (`mode & 0o077 != 0`) — ssh itself refuses
    /// these, and it means another local account could read the key.
    public static func isPrivateKeyPermissive(mode: Int) -> Bool { mode & 0o077 != 0 }

    // MARK: - Risky ~/.ssh/config directives

    /// Scan config text for dangerous directives, tracking which `Host`/`Match` block each
    /// falls under (a global `Host *` amplifies the severity).
    public static func scanConfig(_ text: String) -> [Finding] {
        var findings: [Finding] = []
        var scope = "(global)"
        var wildcard = true   // directives before any Host apply everywhere
        for raw in text.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }
            let lower = line.lowercased()
            if lower == "host" || lower.hasPrefix("host ") {
                let patterns = line.dropFirst(4).split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
                scope = "Host " + patterns.joined(separator: " ")
                wildcard = patterns.contains("*")
                continue
            }
            if lower == "match" || lower.hasPrefix("match ") {
                scope = line; wildcard = true; continue
            }
            guard let sep = line.firstIndex(where: { $0 == " " || $0 == "\t" || $0 == "=" }) else { continue }
            let key = line[..<sep].lowercased()
            let value = line[line.index(after: sep)...].trimmingCharacters(in: CharacterSet(charactersIn: " \t=\"")).lowercased()
            switch key {
            case "stricthostkeychecking" where value == "no":
                findings.append(.init(severity: .high, category: "Config",
                    title: "StrictHostKeyChecking no · \(scope)",
                    detail: "Accepts any host key without checking — no protection against a man-in-the-middle. Use “accept-new” or “ask”.",
                    fix: .command("StrictHostKeyChecking accept-new")))
            case "userknownhostsfile" where value.contains("/dev/null"):
                findings.append(.init(severity: .high, category: "Config",
                    title: "UserKnownHostsFile /dev/null · \(scope)",
                    detail: "Throws away host-key memory, so a changed (possibly attacker) host key is never noticed.",
                    fix: .none))
            case "forwardagent" where value == "yes":
                findings.append(.init(severity: wildcard ? .high : .medium, category: "Config",
                    title: "ForwardAgent yes · \(scope)",
                    detail: wildcard
                        ? "Forwards your agent to EVERY host — a malicious or compromised server can use your keys. Scope it to specific trusted hosts, or drop it for ProxyJump."
                        : "That host can use your loaded keys while you're connected. Prefer ProxyJump unless you fully trust it.",
                    fix: .none))
            case "identitiesonly" where value == "no":
                findings.append(.init(severity: .low, category: "Config",
                    title: "IdentitiesOnly no · \(scope)",
                    detail: "Offers every loaded key to the host, revealing which keys you hold. Set “IdentitiesOnly yes” with an explicit IdentityFile.",
                    fix: .command("IdentitiesOnly yes")))
            default:
                break
            }
        }
        return findings
    }
}
