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

    // MARK: - Unencrypted on-disk key

    /// Is `keyPath` still referenced by an active `IdentityFile` in ssh config, or by the
    /// git signing key? Matched by exact filename (so `id_ed25519` ≠ `id_ed25519_perso`).
    public static func isKeyReferenced(keyPath: String, configText: String, gitSigningKey: String?) -> Bool {
        // Compare by filename, ignoring a `.pub` suffix so a private key matches its
        // public-key reference (a signing key or IdentityFile is usually the `.pub`).
        func norm(_ p: String) -> String {
            let b = (p as NSString).lastPathComponent
            return b.hasSuffix(".pub") ? String(b.dropLast(4)) : b
        }
        let base = norm(keyPath)
        if let s = gitSigningKey, norm(s) == base { return true }
        for raw in configText.split(separator: "\n") {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }
            guard line.lowercased().hasPrefix("identityfile") else { continue }
            let value = line.dropFirst("identityfile".count)
                .trimmingCharacters(in: CharacterSet(charactersIn: " \t=\""))
            if norm(value) == base { return true }
        }
        return false
    }

    /// Finding for an unencrypted on-disk private key. If nothing references it, steer the
    /// user to delete it (they've likely migrated off it); otherwise, to protect it.
    public static func unencryptedKeyFinding(name: String, path: String, referenced: Bool) -> Finding {
        if referenced {
            return Finding(severity: .high, category: "Key", title: "“\(name)” has no passphrase",
                detail: "This private key is stored unencrypted — anyone who reads the file (a backup, a stolen laptop, malware running as you) gets a working key. Add a passphrase, or move the hosts that use it to a fob key (Secure Enclave keys can't be copied off the machine).",
                fix: .command("ssh-keygen -p -f \(path)"))
        }
        return Finding(severity: .high, category: "Key", title: "“\(name)” is unencrypted and unused",
            detail: "This private key is stored unencrypted and no ~/.ssh/config host or your git signing config references it — you've likely migrated off it to fob. Delete it, and remove it from any account/server that still trusts it.",
            fix: .command("rm \(path) \(path).pub"))
    }

    // MARK: - allowed_signers (local commit-signature verification)

    /// Build/inspect `~/.ssh/allowed_signers` entries. Format: `<principals> [options]
    /// <keytype> <base64> [comment]`. fob writes `<email> namespaces="git" <pubLine>`.
    public enum AllowedSigners {
        /// "<keytype> <base64>" from a public-key line, for presence checks.
        public static func keyFields(_ pubLine: String) -> String? {
            let parts = pubLine.split(separator: " ")
            guard parts.count >= 2 else { return nil }
            return "\(parts[0]) \(parts[1])"
        }

        /// The fob key name from a public-key line's `fob:<name>` comment, if present —
        /// so findings can name which key git signs with.
        public static func fobKeyName(fromPubLine pubLine: String) -> String? {
            guard let comment = pubLine.split(separator: " ").dropFirst(2).first,
                  comment.hasPrefix("fob:") else { return nil }
            return String(comment.dropFirst(4))
        }

        public static func contains(_ fileText: String, pubLine: String) -> Bool {
            guard let kf = keyFields(pubLine) else { return false }
            return fileText.contains(kf)
        }

        public static func entry(email: String, pubLine: String) -> String {
            "\(email) namespaces=\"git\" \(pubLine)"
        }

        /// Append an entry for this key/email if not already present; nil = already there.
        public static func appending(_ fileText: String, email: String, pubLine: String) -> String? {
            guard !contains(fileText, pubLine: pubLine) else { return nil }
            let sep = fileText.isEmpty || fileText.hasSuffix("\n") ? "" : "\n"
            return fileText + sep + entry(email: email, pubLine: pubLine) + "\n"
        }
    }

    /// Flag when fob-signed commits can't be verified LOCALLY (GitHub's Verified is
    /// separate). Either the allowed_signers file isn't configured, or the key isn't in it.
    public static func signingVerificationFinding(usesFobSigning: Bool,
                                                  allowedSignersConfigured: Bool,
                                                  keyListed: Bool,
                                                  keyLabel: String? = nil) -> Finding? {
        guard usesFobSigning else { return nil }
        // "your fob key “name”" when we know which key git signs with, else a bare phrase.
        let named = keyLabel.map { "your fob key “\($0)”" } ?? "your fob signing key"
        if !allowedSignersConfigured {
            return Finding(severity: .medium, category: "Config",
                title: "Signed commits aren't verifiable locally",
                detail: "You sign commits with \(named), but git's gpg.ssh.allowedSignersFile isn't set — `git log --show-signature` / `git verify-commit` can't check your own signatures (your git host still shows Verified). Point git at an allowed_signers file.",
                fix: .command("git config --global gpg.ssh.allowedSignersFile ~/.ssh/allowed_signers"))
        }
        if !keyListed {
            let title = keyLabel.map { "Signing key “\($0)” isn’t in allowed_signers" }
                ?? "Your signing key isn’t in allowed_signers"
            return Finding(severity: .medium, category: "Config",
                title: title,
                detail: "\(named.prefix(1).uppercased() + named.dropFirst()) isn't listed in allowed_signers, so `git verify-commit` shows your commits unverified locally. Open that key's ••• → “Use for commit signing…” — fob adds it for you.",
                fix: .none)
        }
        return nil
    }

    // MARK: - ssh-agent (keys usable without a presence prompt)

    /// The base64 key-blob fields (`ssh-ed25519 <BLOB> …` → `<BLOB>`) from `ssh-add -L`
    /// output, one per loaded identity. The blob uniquely identifies a public key across
    /// agents, so it can be compared against fob's keys regardless of comment/socket.
    public static func agentKeyBlobs(fromSSHAddL output: String) -> [String] {
        output.split(whereSeparator: \.isNewline).compactMap { line in
            let parts = line.split(separator: " ")
            guard parts.count >= 2, parts[0].hasPrefix("ssh-") || parts[0].hasPrefix("ecdsa-") || parts[0].hasPrefix("sk-") else { return nil }
            return String(parts[1])
        }
    }

    /// Flag on-disk keys sitting in the running ssh-agent: they sign with **no Touch ID
    /// prompt** for as long as they're loaded — the opposite of fob's per-use presence gate.
    /// fob's own keys (matched by blob) are excluded, so pointing `SSH_AUTH_SOCK` at fob
    /// produces no finding. nil = nothing loaded but fob keys (or the agent was unreachable).
    public static func agentLoadedKeysFinding(agentKeyBlobs: [String], fobKeyBlobs: Set<String>) -> Finding? {
        let foreign = agentKeyBlobs.filter { !fobKeyBlobs.contains($0) }
        guard !foreign.isEmpty else { return nil }
        let n = foreign.count
        return Finding(severity: .medium, category: "Agent",
            title: "\(n) key\(n == 1 ? "" : "s") loaded in your ssh-agent sign without Touch ID",
            detail: "Your ssh-agent has \(n) non-fob \(n == 1 ? "key" : "keys") loaded — while loaded, \(n == 1 ? "it signs" : "they sign") for any request with no presence prompt, which is exactly what fob avoids. Inspect with `ssh-add -l`; drop one with `ssh-add -d <keyfile>`, or clear the agent with `ssh-add -D`. On macOS a key can reload from the login Keychain (so it returns after `ssh-add -D`, even if its file is gone) — delete it in Keychain Access → login (search “ssh”) to remove it for good. Better still: migrate those hosts to fob so signing is Touch ID-gated.",
            fix: .command("ssh-add -l"))
    }

    // MARK: - File permissions

    /// A private key readable by group or other (`mode & 0o077 != 0`) — ssh itself refuses
    /// these, and it means another local account could read the key.
    public static func isPrivateKeyPermissive(mode: Int) -> Bool { mode & 0o077 != 0 }

    // MARK: - Git identity footgun (multi-account default leak)

    /// With multiple `includeIf` git identities but `user.useConfigOnly` unset, any repo
    /// outside those directories silently commits/signs as the global default identity —
    /// the class of bug that leaks the wrong account's email into a repo. nil = safe (no
    /// includes, or the guard is already on).
    public static func identityFinding(includeCount: Int, useConfigOnly: Bool,
                                       defaultEmail: String?) -> Finding? {
        guard includeCount > 0 else { return nil }
        let hasGlobalEmail = defaultEmail?.isEmpty == false
        // If there's no global user.email, useConfigOnly alone is the fix (git errors when
        // it can't find one). If a global email IS set, useConfigOnly won't help — git will
        // keep using that email; the identity has to be relocated into an includeIf.
        if !hasGlobalEmail {
            guard !useConfigOnly else { return nil }
            return Finding(severity: .medium, category: "Config",
                title: "Repos outside your includeIf directories have no identity guard",
                detail: "You keep \(includeCount) per-directory git \(includeCount == 1 ? "identity" : "identities"). Set user.useConfigOnly so git refuses to invent an identity for a repo outside them, instead of guessing one from your system.",
                fix: .command("git config --global user.useConfigOnly true"))
        }
        return Finding(severity: .medium, category: "Config",
            title: "Repos outside your includeIf directories commit as \(defaultEmail!)",
            detail: "Git uses your global default identity (\(defaultEmail!)) for any repo outside your \(includeCount) includeIf \(includeCount == 1 ? "directory" : "directories") — a clone in /tmp or ~/Downloads would commit (and sign) as the wrong account. Fix in two steps: move your default identity into its own includeIf (e.g. gitdir:~/work/), THEN set user.useConfigOnly=true — so a repo matching no include has no identity and git errors instead of defaulting. (Setting useConfigOnly alone won't help while a global user.email is set.)",
            fix: .command("git config --global user.useConfigOnly true"))
    }

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
