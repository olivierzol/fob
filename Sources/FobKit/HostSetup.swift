import Foundation

/// Shared pieces of host onboarding, used by both the CLI `fob setup` and the app's
/// "Set up a host" window so what gets written to `~/.ssh/config` can't drift.
public enum HostSetup {
    /// The `~/.ssh/config` Host block fob writes for a key. A non-default `port` adds a
    /// `Port` line (omitted for 22 to keep the entry clean).
    public static func configBlock(alias: String, host: String, user: String,
                                   port: Int = 22, pubPath: String, socketPath: String) -> String {
        var lines = ["# added by fob", "Host \(alias)", "  HostName \(host)", "  User \(user)"]
        if port != 22 { lines.append("  Port \(port)") }
        lines += ["  IdentityAgent \(socketPath)", "  IdentityFile \(pubPath)", "  IdentitiesOnly yes"]
        return lines.joined(separator: "\n")
    }

    /// Whether `~/.ssh/config` already declares a `Host <alias>` entry.
    public static func hostBlockExists(alias: String, in config: String) -> Bool {
        for line in config.split(separator: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard trimmed.lowercased().hasPrefix("host ") else { continue }
            let patterns = trimmed.dropFirst("host ".count)
                .split(separator: " ", omittingEmptySubsequences: true)
            if patterns.contains(where: { $0 == Substring(alias) }) { return true }
        }
        return false
    }

    /// A hostname/username safe to interpolate into ssh arguments and config: non-empty,
    /// no spaces, and no leading '-' (so it can never be parsed as an ssh option).
    public static func isValidHostToken(_ s: String) -> Bool {
        !s.isEmpty && !s.contains(" ") && !s.hasPrefix("-")
    }

    /// POSIX single-quote a string so a shell treats it as one literal argument, safe to
    /// interpolate into a command line that will actually be executed (e.g. Terminal).
    public static func shellQuote(_ s: String) -> String {
        "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    /// What we read out of an existing `~/.ssh/config` Host block, for `fob adopt`.
    public struct ParsedHost: Equatable {
        public var hostName: String?
        public var user: String?
        public var port: Int?
        public var identityFiles: [String]
        public var usesFobAgent: Bool // IdentityAgent already points at ~/.fob/agent.sock

        public init(hostName: String?, user: String?, port: Int?,
                    identityFiles: [String], usesFobAgent: Bool) {
            self.hostName = hostName
            self.user = user
            self.port = port
            self.identityFiles = identityFiles
            self.usesFobAgent = usesFobAgent
        }
    }

    /// One migratable host discovered in `~/.ssh/config`.
    public struct HostBlock: Equatable {
        public let alias: String
        public let parsed: ParsedHost
        public init(alias: String, parsed: ParsedHost) {
            self.alias = alias
            self.parsed = parsed
        }
        public var usesFob: Bool { parsed.usesFobAgent }
    }

    /// Reads the `Host <alias>` block from ssh-config text, if the alias appears as a
    /// literal pattern (never via a wildcard/`Match` block — we won't touch those).
    /// Returns nil when there's no such block.
    public static func parseHostBlock(alias: String, in config: String) -> ParsedHost? {
        var inBlock = false, found = false
        var host = ParsedHost(hostName: nil, user: nil, port: nil, identityFiles: [], usesFobAgent: false)
        for raw in config.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }
            let lower = line.lowercased()
            if lower == "host" || lower.hasPrefix("host ") || lower == "match" || lower.hasPrefix("match ") {
                if inBlock { break } // reached the next section — our block ended
                if lower.hasPrefix("host ") {
                    let patterns = line.dropFirst(5).split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
                    if patterns.contains(alias) { inBlock = true; found = true }
                }
                continue
            }
            guard inBlock else { continue }
            // key / value separated by whitespace or '='
            guard let sep = line.firstIndex(where: { $0 == " " || $0 == "\t" || $0 == "=" }) else { continue }
            let key = line[..<sep].lowercased()
            let value = line[line.index(after: sep)...]
                .trimmingCharacters(in: CharacterSet(charactersIn: " \t=\""))
            switch key {
            case "hostname": host.hostName = value
            case "user": host.user = value
            case "port": host.port = Int(value)
            case "identityfile": host.identityFiles.append(value)
            case "identityagent": if value.contains("/.fob/") { host.usesFobAgent = true }
            default: break
            }
        }
        return found ? host : nil
    }

    // MARK: - Migration (fob adopt / the app's migrate flow)

    /// Enumerate every *literal* `Host <alias>` block in the config (skipping wildcard
    /// and `Match` blocks, same rule as `parseHostBlock`). A `Host a b` line yields one
    /// entry per literal token. Used to build the migration candidate list.
    public static func listHostBlocks(in config: String) -> [HostBlock] {
        var out: [HostBlock] = []
        var seen = Set<String>()
        for raw in config.split(separator: "\n") {
            let line = raw.trimmingCharacters(in: .whitespaces)
            guard line.lowercased().hasPrefix("host ") else { continue }
            let tokens = line.split(whereSeparator: { $0 == " " || $0 == "\t" }).dropFirst().map(String.init)
            for token in tokens {
                // Skip ssh pattern tokens — we only touch a plain, literal alias.
                if token.contains("*") || token.contains("?") || token.hasPrefix("!") { continue }
                if seen.contains(token) { continue }
                seen.insert(token)
                if let parsed = parseHostBlock(alias: token, in: config) {
                    out.append(HostBlock(alias: token, parsed: parsed))
                }
            }
        }
        return out
    }

    /// True if an `IdentityFile`/`IdentityAgent` value belongs to fob.
    private static func isFobIdentity(_ value: String) -> Bool {
        value.contains("/fob_") || value.contains("/.fob/")
    }

    /// The risky transform: edit the existing `Host <alias>` block in place to route it
    /// through fob. Adds `IdentityAgent`/`IdentityFile`/`IdentitiesOnly yes` (only the
    /// ones missing) and comments out any non-fob `IdentityAgent`. The old `IdentityFile`
    /// is left ACTIVE (fob is preferred, the old key is the fallback — no lockout) unless
    /// `retireOld` is true, in which case it is commented out.
    ///
    /// Returns nil if there's no literal `Host <alias>` block. Idempotent: returns the
    /// input unchanged when there's nothing left to do. Never touches other blocks,
    /// `HostName`/`User`/`Port`, or `Match`/wildcard sections.
    public static func migratedConfig(_ config: String, alias: String,
                                      fobPubPath: String, socketPath: String,
                                      retireOld: Bool = false) -> String? {
        // components/joined round-trips exactly, so untouched bytes are preserved.
        var lines = config.components(separatedBy: "\n")

        func isSectionStart(_ raw: String) -> Bool {
            let l = raw.trimmingCharacters(in: .whitespaces).lowercased()
            return l == "host" || l.hasPrefix("host ") || l == "match" || l.hasPrefix("match ")
        }
        func keyValue(_ raw: String) -> (key: String, value: String)? {
            let t = raw.trimmingCharacters(in: .whitespaces)
            if t.isEmpty || t.hasPrefix("#") { return nil }
            guard let sep = t.firstIndex(where: { $0 == " " || $0 == "\t" || $0 == "=" }) else { return nil }
            let key = t[..<sep].lowercased()
            let value = t[t.index(after: sep)...].trimmingCharacters(in: CharacterSet(charactersIn: " \t=\""))
            return (key, value)
        }

        // 1. Locate the literal block for `alias`.
        var start: Int?
        for (i, raw) in lines.enumerated() {
            let line = raw.trimmingCharacters(in: .whitespaces)
            guard line.lowercased().hasPrefix("host ") else { continue }
            let tokens = line.split(whereSeparator: { $0 == " " || $0 == "\t" }).dropFirst().map(String.init)
            if tokens.contains(alias) { start = i; break }
        }
        guard let blockStart = start else { return nil }

        // 2. Block end = next Host/Match, else EOF.
        var end = lines.count
        var k = blockStart + 1
        while k < lines.count {
            if isSectionStart(lines[k]) { end = k; break }
            k += 1
        }

        // 3. Indent from the first indented directive; default two spaces.
        var indent = "  "
        for i in (blockStart + 1)..<end {
            let trimmed = lines[i].trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty || trimmed.hasPrefix("#") { continue }
            let leading = String(lines[i].prefix(while: { $0 == " " || $0 == "\t" }))
            if !leading.isEmpty { indent = leading }
            break
        }

        // 4. Scan the body.
        var hasFobAgent = false, hasFobIdentityFile = false, hasIdentitiesOnly = false
        var nonFobAgentIdxs: [Int] = [], nonFobIdentityFileIdxs: [Int] = []
        var keychainDirectiveIdxs: [Int] = []   // UseKeychain/AddKeysToAgent — see below
        var lastDirectiveIdx = blockStart
        var firstIdentityFileIdx: Int?   // insert fob BEFORE this, so fob is preferred
        for i in (blockStart + 1)..<end {
            guard let (key, value) = keyValue(lines[i]) else { continue }
            lastDirectiveIdx = i
            switch key {
            case "identityagent":
                if isFobIdentity(value) || value == socketPath { hasFobAgent = true }
                else { nonFobAgentIdxs.append(i) }
            case "identityfile":
                if firstIdentityFileIdx == nil { firstIdentityFileIdx = i }
                if value == fobPubPath || isFobIdentity(value) { hasFobIdentityFile = true }
                else { nonFobIdentityFileIdxs.append(i) }
            case "identitiesonly":
                if value.lowercased() == "yes" { hasIdentitiesOnly = true }
            case "usekeychain", "addkeystoagent":
                // These cache the block's on-disk key in the macOS Keychain/agent, so it
                // signs with no Touch ID. Pointless (and counterproductive) once the old
                // key is retired and fob serves this host via IdentityAgent — retiring
                // without removing them lets the Keychain keep re-loading the old key.
                if value.lowercased() == "yes" { keychainDirectiveIdxs.append(i) }
            default: break
            }
        }

        // 5. Idempotency: nothing to add and (not retiring, or nothing left to retire).
        if hasFobAgent && hasFobIdentityFile && hasIdentitiesOnly
            && (!retireOld || (nonFobIdentityFileIdxs.isEmpty && keychainDirectiveIdxs.isEmpty)) {
            return config
        }

        // 6. Comment out lines in place (no index shift).
        func commentOut(_ i: Int, suffix: String = "") {
            let leading = String(lines[i].prefix(while: { $0 == " " || $0 == "\t" }))
            lines[i] = leading + "# " + lines[i].dropFirst(leading.count) + suffix
        }
        for i in nonFobAgentIdxs { commentOut(i) }
        if retireOld {
            for i in nonFobIdentityFileIdxs {
                commentOut(i, suffix: "   # disabled by fob after verified migration")
            }
            for i in keychainDirectiveIdxs {
                commentOut(i, suffix: "   # disabled by fob (old key retired)")
            }
        }

        // 7. Insert the missing fob directives. Place them BEFORE the first existing
        //    IdentityFile so ssh offers fob first (Touch ID), falling back to the old key
        //    only if fob is unavailable. With no IdentityFile in the block, append them.
        var toInsert: [String] = []
        if !hasFobAgent { toInsert.append(indent + "IdentityAgent " + socketPath) }
        if !hasFobIdentityFile { toInsert.append(indent + "IdentityFile " + fobPubPath) }
        if !hasIdentitiesOnly { toInsert.append(indent + "IdentitiesOnly yes") }
        if !toInsert.isEmpty {
            lines.insert(contentsOf: toInsert, at: firstIdentityFileIdx ?? (lastDirectiveIdx + 1))
        }

        var result = lines.joined(separator: "\n")
        // Normalize: an edited file should end in exactly one newline.
        if !result.isEmpty && !result.hasSuffix("\n") { result += "\n" }
        return result
    }

    /// Shell run on the server (over the user's CURRENT key) to append the fob public
    /// key to `authorized_keys`, idempotently. The pub line is piped on stdin. Prints
    /// `fob-installed` or `fob-present` on success.
    public static let remoteAppendScript =
        #"umask 077; mkdir -p ~/.ssh; k="$(cat)"; touch ~/.ssh/authorized_keys; "#
        + #"if grep -qxF "$k" ~/.ssh/authorized_keys; then echo fob-present; "#
        + #"else printf '%s\n' "$k" >> ~/.ssh/authorized_keys && echo fob-installed; fi"#

    /// ssh argv (for `/usr/bin/ssh`) to install the fob key headless, authenticating with
    /// the host's existing key. Returns nil for an unsafe alias (leading '-' etc.) so it
    /// can never be parsed as an ssh option. Pass the fob pub line on the child's stdin.
    public static func installArguments(alias: String) -> [String]? {
        guard isValidHostToken(alias) else { return nil }
        return ["-o", "BatchMode=yes",
                "-o", "ConnectTimeout=10",
                "-o", "StrictHostKeyChecking=accept-new",
                alias, remoteAppendScript]
    }

    /// The manual fallback shown when the headless install can't run (passphrase-locked
    /// old key, unreachable host, …). ssh-copy-id gets a real TTY for the prompt.
    public static func fallbackCopyCommand(alias: String, fobPubPath: String, port: Int) -> String {
        // -f is required: fob keys have no private file on disk (it's in the enclave),
        // and without -f ssh-copy-id tries to derive from a private key it can't find.
        // alias/path are SINGLE-QUOTED: this command is both copy-pasted and run in a real
        // shell (the app's "Open in Terminal"), so metacharacters in an alias read from
        // ~/.ssh/config must be inert, not interpreted.
        var parts = ["ssh-copy-id", "-f", "-i", shellQuote(fobPubPath)]
        if port != 22 { parts += ["-p", String(port)] }
        parts.append(shellQuote(alias))
        return parts.joined(separator: " ")
    }

    // MARK: - Git hosts (GitHub/GitLab/… — no shell, key added via the web)

    public enum GitProvider: Equatable {
        case github, gitlab, bitbucket, codeberg, other
        public var displayName: String {
            switch self {
            case .github: return "GitHub"
            case .gitlab: return "GitLab"
            case .bitbucket: return "Bitbucket"
            case .codeberg: return "Codeberg"
            case .other: return "your git host"
            }
        }
    }

    /// Classify a HostName by provider (substring match also covers enterprise hosts
    /// like github.mycorp.com / gitlab.internal).
    public static func gitProvider(forHost host: String) -> GitProvider {
        let h = host.lowercased()
        if h.contains("github") { return .github }
        if h.contains("gitlab") { return .gitlab }
        if h.contains("bitbucket") { return .bitbucket }
        if h.contains("codeberg") || h.contains("gitea") || h.contains("forgejo") { return .codeberg }
        return .other
    }

    /// A `Host` block is a git host if it logs in as `git` or its HostName is a known
    /// provider — either way there's no shell and the key is registered on the web.
    public static func isGitHost(hostName: String, user: String?) -> Bool {
        if (user ?? "").lowercased() == "git" { return true }
        return gitProvider(forHost: hostName) != .other
    }

    /// Deep link to the provider's "add SSH key" page (nil for unknown self-hosted).
    /// Normalizes ssh aliases (ssh.github.com, gist.github.com) to the public web host,
    /// while leaving an enterprise host (github.mycorp.com) as-is.
    public static func sshKeySettingsURL(forHost host: String) -> URL? {
        let h = host.lowercased()
        func web(_ known: String) -> String { (h == known || h.hasSuffix(".\(known)")) ? known : host }
        switch gitProvider(forHost: host) {
        case .github:    return URL(string: "https://\(web("github.com"))/settings/ssh/new")
        case .gitlab:    return URL(string: "https://\(web("gitlab.com"))/-/user_settings/ssh_keys")
        case .bitbucket: return URL(string: "https://bitbucket.org/account/settings/ssh-keys/")
        case .codeberg:  return URL(string: "https://\(web("codeberg.org"))/user/settings/keys")
        case .other:     return nil
        }
    }

    /// Parse an `ssh -T` greeting. `ssh -T git@github.com` exits NON-zero even on success,
    /// so we detect success by the greeting text, not the exit code, and pull out the
    /// authenticated username when the provider includes it.
    public static func parseSSHGreeting(_ output: String) -> (authenticated: Bool, user: String?) {
        let lower = output.lowercased()
        let authed = lower.contains("successfully authenticated")
            || lower.contains("does not provide shell access")
            || lower.contains("welcome to gitlab")
            || lower.contains("logged in as")
            || lower.contains("authenticated via ssh")
        guard authed else { return (false, nil) }
        let user =
            firstCapture(in: output, pattern: #"Hi ([^!]+)!"#)                 // GitHub
            ?? firstCapture(in: output, pattern: #"Welcome to GitLab, @([^!]+)!"#) // GitLab
            ?? firstCapture(in: output, pattern: #"logged in as ([^.\s]+)"#)   // Bitbucket
        return (true, user?.trimmingCharacters(in: .whitespaces))
    }

    private static func firstCapture(in text: String, pattern: String) -> String? {
        guard let re = try? NSRegularExpression(pattern: pattern) else { return nil }
        let range = NSRange(text.startIndex..., in: text)
        guard let m = re.firstMatch(in: text, range: range), m.numberOfRanges > 1,
              let r = Range(m.range(at: 1), in: text) else { return nil }
        return String(text[r])
    }

    /// Turn a failed headless-install ssh error into a plain-language reason + what to do.
    /// The headless install runs with `BatchMode=yes`, so a passphrase-protected key (not
    /// loaded in ssh-agent) can't be unlocked and the server reports "Permission denied".
    public static func installFailureHint(_ output: String) -> String {
        let o = output.lowercased()
        if o.contains("does not provide shell access") || o.contains("welcome to gitlab") {
            return "That's a git host — its key is added on the web, not with ssh-copy-id. "
                + "Use “Set up a host → Git host” instead."
        }
        if o.contains("permission denied") {
            return "Your existing key couldn't be used automatically — most likely it needs a "
                + "passphrase (and isn't loaded in ssh-agent), which the non-interactive install "
                + "can't enter. Run it in a terminal (you'll be asked for the passphrase), or "
                + "`ssh-add` the key and Retry headless:"
        }
        if o.contains("could not resolve") || o.contains("no route to host")
            || o.contains("timed out") || o.contains("connection refused") {
            return "The host couldn't be reached from here — check your network, then run it in a terminal:"
        }
        if o.contains("host key verification failed") {
            return "The host key didn't match ~/.ssh/known_hosts. Resolve that, then run it in a terminal:"
        }
        return "Couldn't install headlessly (the host may be unreachable, or your key needs a "
            + "passphrase). Run this in a terminal — it uses your existing key, no fob needed yet:"
    }

    /// Make untrusted subprocess output (an ssh/server error) safe to show in the UI:
    /// drop control characters and escape sequences, keep only the last few lines, and
    /// cap the length. It's only ever rendered as text, never executed — this just keeps
    /// a hostile server from spamming the UI with control bytes or huge output.
    public static func sanitizeForDisplay(_ s: String, maxLines: Int = 6, maxChars: Int = 600) -> String {
        let scalars = s.unicodeScalars.filter {
            $0 == "\n" || $0 == "\t" || ($0.value >= 0x20 && $0.value != 0x7f)
        }
        var text = String(String.UnicodeScalarView(scalars))
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let lines = text.split(separator: "\n", omittingEmptySubsequences: false)
        if lines.count > maxLines { text = lines.suffix(maxLines).joined(separator: "\n") }
        if text.count > maxChars { text = "…" + text.suffix(maxChars) }
        return text
    }

    /// Backup name for `~/.ssh/config`, e.g. `config.fob-backup-20260711-094512`.
    public static func backupName(now: Date) -> String {
        let fmt = DateFormatter()
        fmt.locale = Locale(identifier: "en_US_POSIX")
        fmt.timeZone = .current
        fmt.dateFormat = "yyyyMMdd-HHmmss"
        return "config.fob-backup-\(fmt.string(from: now))"
    }

    /// Copy the current `~/.ssh/config` to a timestamped 0600 backup, then atomically
    /// write `newText` (also 0600). Returns the backup URL (or the intended path when the
    /// config didn't exist yet). The backup is the undo path if a migration misbehaves.
    @discardableResult
    public static func backupAndWriteConfig(_ newText: String, at configURL: URL,
                                            now: Date = Date()) throws -> URL {
        let fm = FileManager.default
        let backupURL = configURL.deletingLastPathComponent().appendingPathComponent(backupName(now: now))
        if fm.fileExists(atPath: configURL.path) {
            if fm.fileExists(atPath: backupURL.path) { try fm.removeItem(at: backupURL) }
            try fm.copyItem(at: configURL, to: backupURL)
            try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: backupURL.path)
        }
        try Data(newText.utf8).write(to: configURL, options: .atomic)
        try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: configURL.path)
        return backupURL
    }

    /// Remove a fob-created `Host <alias>` block entirely — used when its key is deleted, so
    /// a dead entry pointing at a now-missing key doesn't linger (and re-appear in Migrate).
    /// Only removes when the block is a single-alias block that routes through fob AND has no
    /// active non-fob `IdentityFile` (a migrated host with a live old key is left untouched).
    /// Also drops an immediately preceding `# added by fob` comment and trailing blank lines.
    /// Returns nil when there's nothing safe to remove.
    public static func removeFobHostBlock(_ config: String, alias: String) -> String? {
        guard let parsed = parseHostBlock(alias: alias, in: config), parsed.usesFobAgent,
              parsed.identityFiles.allSatisfy({ isFobIdentity($0) }) else { return nil }
        var lines = config.components(separatedBy: "\n")
        func isSectionStart(_ raw: String) -> Bool {
            let l = raw.trimmingCharacters(in: .whitespaces).lowercased()
            return l == "host" || l.hasPrefix("host ") || l == "match" || l.hasPrefix("match ")
        }
        // The literal `Host <alias>` line — only a single-alias block is safe to remove
        // wholesale (a `Host a b` line also serves other aliases).
        var start: Int?
        for (i, raw) in lines.enumerated() {
            let line = raw.trimmingCharacters(in: .whitespaces)
            guard line.lowercased().hasPrefix("host ") else { continue }
            let tokens = line.split(whereSeparator: { $0 == " " || $0 == "\t" }).dropFirst().map(String.init)
            if tokens == [alias] { start = i; break }
        }
        guard var blockStart = start else { return nil }
        var end = blockStart + 1
        while end < lines.count { if isSectionStart(lines[end]) { break }; end += 1 }
        // Absorb an immediately preceding fob-written marker ("# added by fob[ setup]") only —
        // never an unrelated user comment sitting above the block.
        if blockStart > 0,
           lines[blockStart - 1].trimmingCharacters(in: .whitespaces).hasPrefix("# added by fob") {
            blockStart -= 1
        }
        // Absorb trailing blank lines that separated this block from the next.
        while end < lines.count, lines[end].trimmingCharacters(in: .whitespaces).isEmpty { end += 1 }
        lines.removeSubrange(blockStart..<end)
        var result = lines.joined(separator: "\n")
        if !result.isEmpty && !result.hasSuffix("\n") { result += "\n" }
        return result
    }
}
