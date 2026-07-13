import XCTest

@testable import FobKit

/// Golden + safety tests for the server-migration core in HostSetup, plus GitConfig /
/// TextDiff. The config rewrite edits the user's ~/.ssh/config, so it's held to exact,
/// byte-level expectations.
final class MigrationTests: XCTestCase {
    private let pub = "/Users/me/.ssh/fob_web.pub"
    private let sock = "/Users/me/.fob/agent.sock"

    private func migrate(_ config: String, alias: String = "web", retireOld: Bool = false) -> String? {
        HostSetup.migratedConfig(config, alias: alias, fobPubPath: pub, socketPath: sock, retireOld: retireOld)
    }

    // 1. Old IdentityFile stays active; the three fob lines are added, fob PREFERRED
    //    (listed before the old key so ssh tries fob first, old as fallback).
    func testAddsFobLinesKeepsOldIdentity() {
        let config = "Host web\n  HostName web.example\n  IdentityFile ~/.ssh/id_ed25519\n"
        let out = migrate(config)!
        XCTAssertTrue(out.contains("  IdentityFile ~/.ssh/id_ed25519\n"), "old key must stay active")
        XCTAssertTrue(out.contains("  IdentityAgent \(sock)"))
        XCTAssertTrue(out.contains("  IdentityFile \(pub)"))
        XCTAssertTrue(out.contains("  IdentitiesOnly yes"))
        let fobAt = out.range(of: "IdentityFile \(pub)")!.lowerBound
        let oldAt = out.range(of: "IdentityFile ~/.ssh/id_ed25519")!.lowerBound
        XCTAssertTrue(fobAt < oldAt, "fob key must be listed before the old key so it's preferred")
        let agentAt = out.range(of: "IdentityAgent \(sock)")!.lowerBound
        XCTAssertTrue(agentAt < oldAt, "fob agent must precede the old key")
    }

    // 2. Idempotent.
    func testIdempotent() {
        let config = "Host web\n  HostName web.example\n  IdentityFile ~/.ssh/id_ed25519\n"
        let once = migrate(config)!
        let twice = migrate(once)!
        XCTAssertEqual(once, twice)
    }

    // 3. Custom Port preserved, no new Port line.
    func testPreservesPort() {
        let config = "Host web\n  HostName web.example\n  Port 2222\n  IdentityFile ~/.ssh/id\n"
        let out = migrate(config)!
        XCTAssertTrue(out.contains("  Port 2222\n"))
        XCTAssertEqual(out.components(separatedBy: "Port 2222").count - 1, 1)
    }

    // 4. Unrelated blocks/comments preserved exactly.
    func testUnrelatedBlocksUntouched() {
        let config = """
        # my ssh config
        Host other
          HostName other.example
          IdentityFile ~/.ssh/other

        Host web
          HostName web.example
          IdentityFile ~/.ssh/id

        Host third
          HostName third.example
        """
        let out = migrate(config)!
        XCTAssertTrue(out.contains("# my ssh config\nHost other\n  HostName other.example\n  IdentityFile ~/.ssh/other\n"))
        XCTAssertTrue(out.contains("Host third\n  HostName third.example"))
        XCTAssertFalse(out.contains("other.example\n  IdentityAgent"), "other block must not get fob lines")
    }

    // 5. Host with no IdentityFile → only fob lines added, nothing commented.
    func testNoIdentityFile() {
        let config = "Host web\n  HostName web.example\n"
        let out = migrate(config)!
        XCTAssertTrue(out.contains("  IdentityAgent \(sock)"))
        XCTAssertTrue(out.contains("  IdentityFile \(pub)"))
        XCTAssertTrue(out.contains("  IdentitiesOnly yes"))
        XCTAssertFalse(out.contains("# "), "nothing to comment out")
    }

    // 6. Partial migration: only the missing directive is added.
    func testPartialMigrationAddsMissingOnly() {
        let config = "Host web\n  HostName web.example\n  IdentityAgent \(sock)\n  IdentityFile \(pub)\n"
        let out = migrate(config)!
        XCTAssertEqual(out.components(separatedBy: "IdentityAgent").count - 1, 1)
        XCTAssertEqual(out.components(separatedBy: "IdentityFile \(pub)").count - 1, 1)
        XCTAssertTrue(out.contains("  IdentitiesOnly yes"))
    }

    // 7. '=' separator on the old IdentityFile is recognized (and retired correctly).
    func testEqualsSeparatorRetire() {
        let config = "Host web\n  HostName web.example\n  IdentityFile=~/.ssh/id\n"
        let out = migrate(config, retireOld: true)!
        XCTAssertTrue(out.contains("# IdentityFile=~/.ssh/id"), "old key should be commented under retire")
        XCTAssertTrue(out.contains("disabled by fob"))
    }

    // 8. Multi-token Host line edits only the matched block.
    func testMultiTokenHost() {
        let config = "Host web web-old\n  HostName web.example\n  IdentityFile ~/.ssh/id\n\nHost api\n  HostName api.example\n"
        let out = migrate(config, alias: "web-old")!
        XCTAssertTrue(out.contains("Host web web-old\n"))
        XCTAssertTrue(out.contains("  IdentityAgent \(sock)"))
        XCTAssertFalse(out.contains("api.example\n  IdentityAgent"))
    }

    // 9. Non-fob IdentityAgent is commented out and the fob one added.
    func testCommentsForeignIdentityAgent() {
        let config = "Host web\n  HostName web.example\n  IdentityAgent /other/agent.sock\n"
        let out = migrate(config)!
        XCTAssertTrue(out.contains("# IdentityAgent /other/agent.sock"))
        XCTAssertTrue(out.contains("  IdentityAgent \(sock)"))
    }

    // 10. Tab indentation preserved.
    func testTabIndent() {
        let config = "Host web\n\tHostName web.example\n\tIdentityFile ~/.ssh/id\n"
        let out = migrate(config)!
        XCTAssertTrue(out.contains("\tIdentityAgent \(sock)"), "should reuse the block's tab indent")
    }

    // 11. No trailing newline → output is normalized to end with one.
    func testNoTrailingNewlineNormalized() {
        let config = "Host web\n  HostName web.example\n  IdentityFile ~/.ssh/id"
        let out = migrate(config)!
        XCTAssertTrue(out.hasSuffix("\n"))
    }

    // 12. retireOld on an already-migrated-but-not-retired block comments the old key
    //     and is itself idempotent.
    func testRetireThenIdempotent() {
        let config = "Host web\n  HostName web.example\n  IdentityFile ~/.ssh/id\n"
        let migrated = migrate(config)!                     // fob added, old still active
        XCTAssertTrue(migrated.contains("  IdentityFile ~/.ssh/id\n"))
        let retired = migrate(migrated, retireOld: true)!   // now comment the old
        XCTAssertTrue(retired.contains("# IdentityFile ~/.ssh/id"))
        XCTAssertEqual(migrate(retired, retireOld: true)!, retired, "retire is idempotent")
    }

    // 13. Alias only under Host * / Match → nil (never touched).
    func testWildcardAndMatchNotMigrated() {
        XCTAssertNil(migrate("Host *\n  IdentityFile ~/.ssh/id\n"))
        XCTAssertNil(HostSetup.migratedConfig("Match host web\n  IdentityFile ~/.ssh/id\n",
                                              alias: "web", fobPubPath: pub, socketPath: sock))
    }

    // Missing alias entirely → nil.
    func testMissingAliasReturnsNil() {
        XCTAssertNil(migrate("Host other\n  HostName other.example\n"))
    }

    // MARK: - listHostBlocks

    func testListHostBlocksSkipsWildcardAndMarksFob() {
        let config = """
        Host *
          ForwardAgent no

        Host web
          HostName web.example
          IdentityFile ~/.ssh/id

        Host prod
          HostName prod.example
          IdentityAgent \(sock)
        """
        let blocks = HostSetup.listHostBlocks(in: config)
        XCTAssertEqual(blocks.map(\.alias), ["web", "prod"])
        XCTAssertFalse(blocks[0].usesFob)
        XCTAssertTrue(blocks[1].usesFob)
    }

    // MARK: - installArguments (injection safety)

    func testInstallArgumentsRejectsUnsafeAlias() {
        XCTAssertNil(HostSetup.installArguments(alias: "-oProxyCommand=evil"))
        XCTAssertNil(HostSetup.installArguments(alias: "has space"))
    }

    func testInstallArgumentsShape() {
        let args = HostSetup.installArguments(alias: "web")!
        XCTAssertEqual(args.last, HostSetup.remoteAppendScript)
        XCTAssertTrue(args.contains("BatchMode=yes"))
        XCTAssertTrue(args.contains("StrictHostKeyChecking=accept-new"))
        XCTAssertEqual(args[args.count - 2], "web")
    }

    func testFallbackCommandPort() {
        XCTAssertEqual(HostSetup.fallbackCopyCommand(alias: "web", fobPubPath: pub, port: 22),
                       "ssh-copy-id -f -i \(pub) web")
        XCTAssertTrue(HostSetup.fallbackCopyCommand(alias: "web", fobPubPath: pub, port: 2222)
            .contains("-p 2222"))
    }

    // MARK: - HostResolver alias disambiguation (multi-account same-host)

    func testConfigAliasPrefersKeyNameWhenSameHost() {
        let config = """
        Host github-feedly
          HostName github.com
          User git
        Host github-ousson
          HostName github.com
          User git
        """
        // Without a hint, first block wins (ssh's own default).
        XCTAssertEqual(HostResolver.configAlias(inConfig: config, forHostName: "github.com", preferredAlias: nil),
                       "github-feedly")
        // With the signing key's name, the matching alias wins.
        XCTAssertEqual(HostResolver.configAlias(inConfig: config, forHostName: "github.com", preferredAlias: "github-ousson"),
                       "github-ousson")
        // A preferred alias that isn't a match falls back to first.
        XCTAssertEqual(HostResolver.configAlias(inConfig: config, forHostName: "github.com", preferredAlias: "nope"),
                       "github-feedly")
    }

    func testConfigAliasNoMatch() {
        XCTAssertNil(HostResolver.configAlias(inConfig: "Host x\n  HostName a.com\n",
                                              forHostName: "b.com", preferredAlias: "x"))
    }

    // MARK: - git hosts

    func testIsGitHost() {
        XCTAssertTrue(HostSetup.isGitHost(hostName: "github.com", user: "git"))
        XCTAssertTrue(HostSetup.isGitHost(hostName: "gitlab.com", user: nil))
        XCTAssertTrue(HostSetup.isGitHost(hostName: "github.mycorp.com", user: "git"))
        XCTAssertFalse(HostSetup.isGitHost(hostName: "192.168.1.10", user: "oliv"))
        XCTAssertFalse(HostSetup.isGitHost(hostName: "server.example.com", user: "deploy"))
    }

    func testGitProviderAndURL() {
        XCTAssertEqual(HostSetup.gitProvider(forHost: "ssh.github.com"), .github)
        XCTAssertEqual(HostSetup.gitProvider(forHost: "gitlab.com"), .gitlab)
        XCTAssertEqual(HostSetup.gitProvider(forHost: "server.example.com"), .other)
        // ssh alias normalizes to the public web host…
        XCTAssertEqual(HostSetup.sshKeySettingsURL(forHost: "ssh.github.com")?.absoluteString,
                       "https://github.com/settings/ssh/new")
        // …enterprise keeps its own host…
        XCTAssertEqual(HostSetup.sshKeySettingsURL(forHost: "github.mycorp.com")?.absoluteString,
                       "https://github.mycorp.com/settings/ssh/new")
        XCTAssertEqual(HostSetup.sshKeySettingsURL(forHost: "gitlab.com")?.absoluteString,
                       "https://gitlab.com/-/user_settings/ssh_keys")
        // …unknown self-hosted has no reliable URL.
        XCTAssertNil(HostSetup.sshKeySettingsURL(forHost: "git.example.com"))
    }

    func testParseSSHGreeting() {
        let gh = HostSetup.parseSSHGreeting("Hi ousson! You've successfully authenticated, but GitHub does not provide shell access.")
        XCTAssertTrue(gh.authenticated)
        XCTAssertEqual(gh.user, "ousson")

        let gl = HostSetup.parseSSHGreeting("Welcome to GitLab, @oliv!")
        XCTAssertTrue(gl.authenticated)
        XCTAssertEqual(gl.user, "oliv")

        let bb = HostSetup.parseSSHGreeting("authenticated via ssh key.\nYou can use git to connect to Bitbucket. Shell access is disabled.\nlogged in as oliv.")
        XCTAssertTrue(bb.authenticated)
        XCTAssertEqual(bb.user, "oliv")

        let denied = HostSetup.parseSSHGreeting("git@github.com: Permission denied (publickey).")
        XCTAssertFalse(denied.authenticated)
        XCTAssertNil(denied.user)
    }

    func testInstallHintDetectsGitHost() {
        let hint = HostSetup.installFailureHint("Hi ousson! You've successfully authenticated, but GitHub does not provide shell access.")
        XCTAssertTrue(hint.lowercased().contains("git host"))
    }

    // MARK: - installFailureHint

    func testHintPermissionDeniedMentionsPassphrase() {
        let hint = HostSetup.installFailureHint("oliv@192.168.64.64: Permission denied (publickey,password).")
        XCTAssertTrue(hint.lowercased().contains("passphrase"))
    }

    func testHintUnreachable() {
        XCTAssertTrue(HostSetup.installFailureHint("ssh: connect to host x port 22: Operation timed out")
            .lowercased().contains("reach"))
    }

    // MARK: - sanitizeForDisplay

    func testSanitizeStripsControlChars() {
        let dirty = "Permission denied\u{1b}[0m\u{7f}\u{00}\nnext line"
        let clean = HostSetup.sanitizeForDisplay(dirty)
        XCTAssertFalse(clean.unicodeScalars.contains { $0.value == 0x1b || $0.value == 0x7f || $0.value == 0 })
        XCTAssertTrue(clean.contains("Permission denied"))
        XCTAssertTrue(clean.contains("next line"))
    }

    func testSanitizeCapsLinesAndLength() {
        let many = (1...20).map { "line \($0)" }.joined(separator: "\n")
        let clean = HostSetup.sanitizeForDisplay(many, maxLines: 3)
        XCTAssertEqual(clean.split(separator: "\n").count, 3)
        XCTAssertTrue(clean.contains("line 20"))
        XCTAssertFalse(clean.contains("line 1\n"))
    }

    // MARK: - backupName

    func testBackupNameFormat() {
        var comps = DateComponents()
        comps.year = 2026; comps.month = 7; comps.day = 11
        comps.hour = 9; comps.minute = 45; comps.second = 12
        let date = Calendar.current.date(from: comps)!
        XCTAssertEqual(HostSetup.backupName(now: date), "config.fob-backup-20260711-094512")
    }

    // MARK: - GitConfig

    func testGitConfigParse() {
        let gc = """
        [user]
            name = Me
            email = me@example.com
            signingkey = /Users/me/.ssh/fob_signing.pub
        [gpg]
            format = ssh
        """
        let info = GitConfig.parse(gc)
        XCTAssertEqual(info.format, "ssh")
        XCTAssertEqual(info.signingKey, "/Users/me/.ssh/fob_signing.pub")
        XCTAssertTrue(info.usesFob)
    }

    func testGitConfigNonFobSigningKey() {
        let info = GitConfig.parse("[user]\n  signingkey = ~/.ssh/id_ed25519.pub\n[gpg]\n  format = ssh\n")
        XCTAssertFalse(info.usesFob)
        XCTAssertEqual(info.signingKey, "~/.ssh/id_ed25519.pub")
    }

    func testGitConfigEmpty() {
        let info = GitConfig.parse("[core]\n  editor = vim\n")
        XCTAssertNil(info.format)
        XCTAssertNil(info.signingKey)
        XCTAssertFalse(info.usesFob)
    }

    // MARK: - TextDiff

    func testTextDiffAddedLines() {
        let old = "a\nb\nc"
        let new = "a\nX\nb\nc"
        let diff = TextDiff.lines(old: old, new: new)
        XCTAssertEqual(diff, [
            .init(.same, "a"),
            .init(.added, "X"),
            .init(.same, "b"),
            .init(.same, "c"),
        ])
    }

    func testTextDiffRemovedLine() {
        let diff = TextDiff.lines(old: "a\nb\nc", new: "a\nc")
        XCTAssertEqual(diff, [.init(.same, "a"), .init(.removed, "b"), .init(.same, "c")])
    }
}
