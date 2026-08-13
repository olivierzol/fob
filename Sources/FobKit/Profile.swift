import Foundation

/// A portable description of a fob setup, for moving to a new Mac.
///
/// Secure Enclave keys are **non-exportable by hardware design** — the on-disk blob is wrapped by
/// one machine's enclave and is inert anywhere else — so a profile deliberately carries **no key
/// material**. What it does carry is everything *around* the keys, all of which is public or
/// reconstructible: key names, their policies, the `~/.ssh/config` host mappings, and the
/// commit-signing setup. On the new Mac, `fob import-profile` recreates that shape with **fresh**
/// keys, which then have to be registered on the servers and git hosts (the import prints a
/// checklist, including each retired key's fingerprint so the old entries can be removed).
///
/// Not secret, but not nothing: a profile maps your key names, hosts, users and signing identities.
/// It's written `0600` and shouldn't be posted or synced casually.
public struct Profile: Codable, Equatable {
    /// Bumped when the schema changes incompatibly; `validate` refuses anything newer.
    public static let currentVersion = 1

    public var version: Int
    public var exportedAt: String          // ISO-8601, informational only
    public var keys: [Key]
    public var hosts: [Host]
    public var signing: Signing?

    public struct Key: Codable, Equatable {
        public var name: String
        /// Always written, even when open/default — absence in the store means "default", which a
        /// manifest must state explicitly rather than silently skip.
        public var policy: KeyPolicy
        /// `SHA256:…` of the key being left behind, so the import checklist can say which entry to
        /// remove from each host. Never any private material.
        public var oldFingerprint: String?
        public var signsCommits: Bool
        /// Principal from `~/.ssh/allowed_signers`, so the new key can be re-listed under it.
        public var signingEmail: String?

        public init(name: String, policy: KeyPolicy, oldFingerprint: String? = nil,
                    signsCommits: Bool = false, signingEmail: String? = nil) {
            self.name = name
            self.policy = policy
            self.oldFingerprint = oldFingerprint
            self.signsCommits = signsCommits
            self.signingEmail = signingEmail
        }
    }

    /// One `~/.ssh/config` host that routes through fob. Only the four directives fob understands
    /// are carried (`HostName`/`User`/`Port`/`IdentityFile`); anything else the block contained is
    /// recorded by *name* in `droppedDirectives` so the import can warn instead of silently losing
    /// it. Raw block text is deliberately not copied — it can hold `ProxyCommand` lines with
    /// internal hostnames or tokens, and this file travels between machines.
    public struct Host: Codable, Equatable {
        public var alias: String
        public var hostName: String
        public var user: String
        public var port: Int
        public var keyName: String
        public var isGitHost: Bool
        public var droppedDirectives: [String]

        public init(alias: String, hostName: String, user: String, port: Int = 22,
                    keyName: String, isGitHost: Bool, droppedDirectives: [String] = []) {
            self.alias = alias
            self.hostName = hostName
            self.user = user
            self.port = port
            self.keyName = keyName
            self.isGitHost = isGitHost
            self.droppedDirectives = droppedDirectives
        }
    }

    public struct Signing: Codable, Equatable {
        /// Path as configured in git (`~`-relative where possible; the importer re-expands it).
        public var allowedSignersFile: String?
        public init(allowedSignersFile: String? = nil) { self.allowedSignersFile = allowedSignersFile }
    }

    public init(version: Int = Profile.currentVersion, exportedAt: String,
                keys: [Key], hosts: [Host], signing: Signing? = nil) {
        self.version = version
        self.exportedAt = exportedAt
        self.keys = keys
        self.hosts = hosts
        self.signing = signing
    }
}

// MARK: - Validation

extension Profile {
    /// Why a profile can't be imported. A manifest is **untrusted input** — it's hand-editable and
    /// travels between machines — and `HostSetup.configBlock` interpolates its values verbatim into
    /// `~/.ssh/config`, so a newline in a hostname would inject arbitrary ssh directives and a
    /// leading `-` would later be read as an ssh option. Everything is re-validated here.
    public enum Issue: Equatable, CustomStringConvertible {
        case unsupportedVersion(Int)
        case invalidKeyName(String)
        case invalidHostField(alias: String, field: String, value: String)
        case unknownKeyReference(alias: String, keyName: String)
        case duplicateKeyName(String)
        case duplicateAlias(String)

        public var description: String {
            switch self {
            case .unsupportedVersion(let v):
                return "profile version \(v) is newer than this fob understands (\(Profile.currentVersion)) — upgrade fob"
            case .invalidKeyName(let name):
                return "invalid key name '\(name)'"
            case .invalidHostField(let alias, let field, let value):
                return "host '\(alias)' has an unsafe \(field) value '\(value)'"
            case .unknownKeyReference(let alias, let keyName):
                return "host '\(alias)' references key '\(keyName)', which isn't in the profile"
            case .duplicateKeyName(let name): return "key '\(name)' appears more than once"
            case .duplicateAlias(let alias): return "host '\(alias)' appears more than once"
            }
        }
    }

    /// Every problem found, empty when the profile is safe to import.
    public func validate() -> [Issue] {
        var issues: [Issue] = []
        if version > Profile.currentVersion { issues.append(.unsupportedVersion(version)) }

        var seenKeys = Set<String>()
        for key in keys {
            guard KeyStore.isValidName(key.name) else {
                issues.append(.invalidKeyName(key.name)); continue
            }
            if !seenKeys.insert(key.name).inserted { issues.append(.duplicateKeyName(key.name)) }
        }

        var seenAliases = Set<String>()
        for host in hosts {
            if !HostSetup.isValidHostToken(host.alias) {
                issues.append(.invalidHostField(alias: host.alias, field: "alias", value: host.alias))
            }
            if !HostSetup.isValidHostToken(host.hostName) {
                issues.append(.invalidHostField(alias: host.alias, field: "HostName", value: host.hostName))
            }
            if !HostSetup.isValidHostToken(host.user) {
                issues.append(.invalidHostField(alias: host.alias, field: "User", value: host.user))
            }
            if host.port < 1 || host.port > 65535 {
                issues.append(.invalidHostField(alias: host.alias, field: "Port", value: String(host.port)))
            }
            if !seenAliases.insert(host.alias).inserted { issues.append(.duplicateAlias(host.alias)) }
            if !keys.contains(where: { $0.name == host.keyName }) {
                issues.append(.unknownKeyReference(alias: host.alias, keyName: host.keyName))
            }
        }
        return issues
    }
}

// MARK: - Import planning

extension Profile {
    /// What importing would do to one key or host. Computed up front so the whole plan can be shown
    /// and confirmed before anything is created or written.
    public struct Plan: Equatable {
        public var keysToCreate: [Key]
        public var keysSkipped: [String]        // a key of that name already exists here
        public var hostsToAdd: [Host]
        public var hostsSkipped: [(alias: String, reason: String)]

        public var isEmpty: Bool { keysToCreate.isEmpty && hostsToAdd.isEmpty }

        public static func == (a: Plan, b: Plan) -> Bool {
            a.keysToCreate == b.keysToCreate && a.keysSkipped == b.keysSkipped
                && a.hostsToAdd == b.hostsToAdd
                && a.hostsSkipped.map(\.alias) == b.hostsSkipped.map(\.alias)
        }
    }

    /// Decide what to import. Never partially applies: existing keys and conflicting hosts are
    /// skipped with a reason rather than overwritten, so a re-run is safe.
    public func plan(existingKeys: Set<String>, existingConfig: String) -> Plan {
        var keysToCreate: [Key] = []
        var keysSkipped: [String] = []
        for key in keys {
            if existingKeys.contains(key.name) { keysSkipped.append(key.name) }
            else { keysToCreate.append(key) }
        }

        var hostsToAdd: [Host] = []
        var hostsSkipped: [(alias: String, reason: String)] = []
        for host in hosts {
            // Sibling check first: a shared `Host a b` line also satisfies hostBlockExists, and the
            // sibling reason is the more useful one to show. Same rule the migrate/adopt flows
            // enforce — editing such a block silently rewrites the siblings' auth too (CWE-706).
            let siblings = HostSetup.hostLineSiblings(ofAlias: host.alias, in: existingConfig)
            if !siblings.isEmpty {
                hostsSkipped.append((host.alias,
                    "shares a Host line with \(siblings.joined(separator: ", "))"))
                continue
            }
            if HostSetup.hostBlockExists(alias: host.alias, in: existingConfig) {
                hostsSkipped.append((host.alias, "a Host block already exists in ~/.ssh/config"))
                continue
            }
            hostsToAdd.append(host)
        }
        return Plan(keysToCreate: keysToCreate, keysSkipped: keysSkipped,
                    hostsToAdd: hostsToAdd, hostsSkipped: hostsSkipped)
    }

    /// The complete new `~/.ssh/config` text with every planned host appended. Built in one pass and
    /// written once — appending host-by-host would make `backupAndWriteConfig` overwrite its own
    /// pristine backup with an already-modified copy (its name is per-second).
    ///
    /// `pubPath` and `socketPath` are supplied by the caller from the *new* machine's home
    /// directory; paths in the profile are never reused.
    public static func configText(applying hosts: [Host], to config: String,
                                  socketPath: String,
                                  pubPath: (String) -> String) -> String {
        guard !hosts.isEmpty else { return config }
        var text = config
        for host in hosts {
            let block = HostSetup.configBlock(alias: host.alias, host: host.hostName,
                                              user: host.user, port: host.port,
                                              pubPath: pubPath(host.keyName), socketPath: socketPath)
            let separator = text.isEmpty ? "" : (text.hasSuffix("\n") ? "\n" : "\n\n")
            text += separator + block + "\n"
        }
        return text
    }
}
