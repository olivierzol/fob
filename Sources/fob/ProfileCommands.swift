import FobKit
import Foundation

/// `fob export-profile` / `fob import-profile` — move a fob setup to a new Mac.
///
/// Secure Enclave keys can't leave the machine that created them, so this moves everything *around*
/// them (names, policies, host mappings, signing) and recreates that shape with **fresh** keys on
/// the new Mac. The import ends with a checklist of where to register each new public key.
enum ProfileCommands {
    private static var sshDir: URL {
        FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".ssh")
    }
    private static var configURL: URL { sshDir.appendingPathComponent("config") }
    private static var signersURL: URL { sshDir.appendingPathComponent("allowed_signers") }
    private static func pubURL(_ name: String) -> URL {
        sshDir.appendingPathComponent("fob_\(name).pub")
    }

    /// `SHA256:…` for an authorized_keys-style line, matching what `ssh-keygen -l` prints.
    private static func fingerprint(ofPubLine line: String) -> String? {
        let fields = line.split(separator: " ")
        guard fields.count >= 2, let blob = Data(base64Encoded: String(fields[1])) else { return nil }
        return HostResolver.fingerprint(ofHostKey: blob)
    }

    // MARK: - Export

    static func export(store: KeyStore, arguments: [String]) throws {
        var rest = arguments
        var output = FileManager.default.currentDirectoryPath + "/fob-profile.json"
        if let i = rest.firstIndex(of: "--output"), i + 1 < rest.count {
            output = rest[i + 1]
            rest.removeSubrange(i...(i + 1))
        }

        let configText = (try? String(contentsOf: configURL, encoding: .utf8)) ?? ""
        let signersText = (try? String(contentsOf: signersURL, encoding: .utf8)) ?? ""
        let blocks = HostSetup.listHostBlocks(in: configText)

        // Keys, with their policies read fail-closed: `displayPolicy` would silently report an
        // unreadable policy as "open", which would export away the key's pins.
        var keys: [Profile.Key] = []
        for stored in try store.all() {
            let policy: KeyPolicy
            switch store.policyStatus(name: stored.name) {
            case .present(let p): policy = p
            case .absent: policy = KeyPolicy()
            case .unreadable:
                fail("policy for '\(stored.name)' is unreadable — fix or remove "
                    + "~/.fob/keys/\(stored.name).policy before exporting, so its pins aren't lost")
            }
            let inStorePub = (try? String(contentsOfFile: store.keysDirectory
                .appendingPathComponent("\(stored.name).pub").path, encoding: .utf8)) ?? ""
            keys.append(Profile.Key(
                name: stored.name,
                policy: policy,
                oldFingerprint: fingerprint(ofPubLine: inStorePub),
                signsCommits: SSHCheckup.AllowedSigners.principal(signersText, fobKeyName: stored.name) != nil,
                signingEmail: SSHCheckup.AllowedSigners.principal(signersText, fobKeyName: stored.name)))
        }

        // Host mappings: only blocks whose IdentityFile is a fob key we actually hold.
        let known = Set(keys.map(\.name))
        var hosts: [Profile.Host] = []
        for block in blocks {
            guard let keyName = block.parsed.identityFiles.compactMap({ path -> String? in
                let base = (path as NSString).lastPathComponent
                guard base.hasPrefix("fob_"), base.hasSuffix(".pub") else { return nil }
                return String(base.dropFirst(4).dropLast(4))
            }).first(where: { known.contains($0) }) else { continue }
            let host = block.parsed.hostName ?? block.alias
            hosts.append(Profile.Host(
                alias: block.alias, hostName: host,
                user: block.parsed.user ?? NSUserName(), port: block.parsed.port ?? 22,
                keyName: keyName,
                isGitHost: HostSetup.isGitHost(hostName: host, user: block.parsed.user),
                droppedDirectives: Profile.droppedDirectives(forAlias: block.alias, in: configText)))
        }

        let profile = Profile(
            exportedAt: ISO8601DateFormatter().string(from: Date()),
            keys: keys, hosts: hosts,
            signing: Profile.Signing(
                allowedSignersFile: gitConfigGlobal("gpg.ssh.allowedSignersFile").isEmpty
                    ? nil : gitConfigGlobal("gpg.ssh.allowedSignersFile")))

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let url = URL(fileURLWithPath: (output as NSString).expandingTildeInPath)
        try encoder.encode(profile).write(to: url, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)

        print("Wrote \(url.path) (0600) — \(keys.count) key(s), \(hosts.count) host(s).")
        let dropped = hosts.filter { !$0.droppedDirectives.isEmpty }
        if !dropped.isEmpty {
            print("")
            print("Not carried (fob only recreates HostName/User/Port/IdentityFile):")
            for host in dropped {
                print("  \(host.alias): \(host.droppedDirectives.joined(separator: ", "))")
            }
        }
        print("")
        print("This file contains NO key material — enclave keys can't leave this Mac. It does map")
        print("your key names, hosts and signing identities, so keep it 0600 and don't post it.")
        print("On the new Mac:  fob import-profile \(url.lastPathComponent)")
    }

    // MARK: - Import

    static func importProfile(store: KeyStore, arguments: [String]) throws {
        var rest = arguments
        let dryRun = rest.contains("--dry-run")
        let forceBiometry = rest.contains("--require-biometry")
        rest.removeAll { $0.hasPrefix("--") }
        guard let path = rest.first, rest.count == 1 else {
            fail("usage: fob import-profile <profile.json> [--dry-run] [--require-biometry]")
        }

        let url = URL(fileURLWithPath: (path as NSString).expandingTildeInPath)
        guard let data = try? Data(contentsOf: url) else { fail("can't read \(url.path)") }
        guard let profile = try? JSONDecoder().decode(Profile.self, from: data) else {
            fail("\(url.lastPathComponent) isn't a valid fob profile")
        }

        // A profile is untrusted input — refuse anything unsafe before it can reach ~/.ssh/config.
        let issues = profile.validate()
        guard issues.isEmpty else {
            for issue in issues { print("error: \(issue)") }
            fail("profile rejected (\(issues.count) problem(s))")
        }

        let configText = (try? String(contentsOf: configURL, encoding: .utf8)) ?? ""
        let existing = Set((try? store.all())?.map(\.name) ?? [])
        let plan = profile.plan(existingKeys: existing, existingConfig: configText)

        print("From \(url.lastPathComponent) (exported \(profile.exportedAt)):")
        for key in plan.keysToCreate {
            let level = (key.policy.requireBiometry ?? forceBiometry)
                ? "Touch ID only" : "Touch ID, Apple Watch, or password"
            print("  + key '\(key.name)' (\(level))")
        }
        for name in plan.keysSkipped { print("  · key '\(name)' already exists — skipped") }
        for host in plan.hostsToAdd { print("  + host '\(host.alias)' → \(host.user)@\(host.hostName)") }
        for skipped in plan.hostsSkipped { print("  · host '\(skipped.alias)' skipped: \(skipped.reason)") }
        for host in profile.hosts where !host.droppedDirectives.isEmpty {
            print("  ! '\(host.alias)' had directives fob doesn't carry: \(host.droppedDirectives.joined(separator: ", "))")
        }

        guard !plan.isEmpty else { print("\nNothing to import."); return }

        let newConfig = Profile.configText(applying: plan.hostsToAdd, to: configText,
                                           socketPath: store.socketPath,
                                           pubPath: { pubURL($0).path })
        if newConfig != configText {
            print("")
            Setup.printDiff(configText, newConfig)
        }

        if dryRun {
            print("\nDry run — nothing was created or written.")
            return
        }
        guard Setup.confirm("Create these keys and apply the config change?") else {
            print("Cancelled."); return
        }

        // 1. Keys + policies. Each key's own protection level is restored; unknown (exported before
        //    fob recorded it) falls back to --require-biometry, else any-user-presence.
        var created: [Profile.Key] = []
        for key in plan.keysToCreate {
            let biometry = key.policy.requireBiometry ?? forceBiometry
            do {
                _ = try store.create(name: key.name, requireBiometry: biometry)
            } catch {
                print("error: couldn't create '\(key.name)': \(error.localizedDescription)")
                continue
            }
            var policy = key.policy
            policy.requireBiometry = biometry
            try store.savePolicy(policy, name: key.name)
            let pubLine = SSHFormat.authorizedKeysLine(try store.find(name: key.name).publicKey(),
                                                       comment: "fob:\(key.name)")
            try Data((pubLine + "\n").utf8).write(to: pubURL(key.name), options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600],
                                                  ofItemAtPath: pubURL(key.name).path)
            created.append(key)
        }

        // 2. One config write — a per-host loop would let the per-second backup overwrite itself.
        if newConfig != configText {
            let backup = try HostSetup.backupAndWriteConfig(newConfig, at: configURL)
            print("Applied ~/.ssh/config. Backup: \(backup.lastPathComponent)")
        }

        // 3. Signing: regenerate the wrapper locally and list the NEW public keys under the
        //    principals carried over.
        var signersText = (try? String(contentsOf: signersURL, encoding: .utf8)) ?? ""
        var addedSigners = false
        for key in created where key.signsCommits {
            guard let email = key.signingEmail,
                  let pubLine = try? String(contentsOf: pubURL(key.name), encoding: .utf8)
                      .trimmingCharacters(in: .whitespacesAndNewlines),
                  let updated = SSHCheckup.AllowedSigners.appending(signersText, email: email,
                                                                    pubLine: pubLine) else { continue }
            signersText = updated
            addedSigners = true
        }
        if addedSigners {
            try Data(signersText.utf8).write(to: signersURL, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o644],
                                                  ofItemAtPath: signersURL.path)
            _ = try? store.ensureSignWrapper()
            print("Updated ~/.ssh/allowed_signers with the new signing key(s).")
        }

        printChecklist(profile: profile, created: created)
    }

    /// What the user still has to do by hand: the new keys are different keys, so every server and
    /// git host has to trust them (and stop trusting the old ones).
    private static func printChecklist(profile: Profile, created: [Profile.Key]) {
        guard !created.isEmpty else { return }
        print("")
        print("═══ Register the new keys ═══")
        print("These are NEW keys — the old ones stayed on the other Mac and can't be moved.")

        for key in created {
            let pubLine = (try? String(contentsOf: pubURL(key.name), encoding: .utf8))?
                .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            print("")
            print("• \(key.name)")
            print("    \(pubLine)")

            for host in profile.hosts where host.keyName == key.name {
                if host.isGitHost {
                    let provider = HostSetup.gitProvider(forHost: host.hostName)
                    // Only ever a canonical provider URL; never synthesised from the manifest.
                    if let url = HostSetup.sshKeySettingsURL(forHost: host.hostName) {
                        print("    \(host.alias): add as an Authentication Key → \(url.absoluteString)")
                    } else {
                        print("    \(host.alias): add as an Authentication Key on \(provider.displayName) (\(host.hostName))")
                    }
                } else {
                    print("    \(host.alias): \(HostSetup.fallbackCopyCommand(alias: host.alias, fobPubPath: pubURL(key.name).path, port: host.port))")
                }
            }
            if key.signsCommits {
                print("    also add it as a Signing Key (a separate entry on GitHub)")
            }
            if let old = key.oldFingerprint {
                print("    then remove the old key (\(old)) from those hosts")
            }
        }
        print("")
        print("Verify a git host with:  ssh -T <alias>")
    }
}
