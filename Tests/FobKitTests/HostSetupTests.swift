import XCTest

@testable import FobKit

final class HostSetupTests: XCTestCase {
    func testIsValidHostTokenRejectsOptionAndWhitespaceInjection() {
        // Valid tokens.
        XCTAssertTrue(HostSetup.isValidHostToken("example.com"))
        XCTAssertTrue(HostSetup.isValidHostToken("git"))
        XCTAssertTrue(HostSetup.isValidHostToken("192.168.1.10"))
        XCTAssertTrue(HostSetup.isValidHostToken("user_1"))
        // Leading dash → would be parsed as an ssh option.
        XCTAssertFalse(HostSetup.isValidHostToken("-oProxyCommand=evil"))
        XCTAssertFalse(HostSetup.isValidHostToken("-"))
        // Whitespace/control — space, tab, newline (not just the literal space).
        XCTAssertFalse(HostSetup.isValidHostToken("a b"))
        XCTAssertFalse(HostSetup.isValidHostToken("a\tb"))
        XCTAssertFalse(HostSetup.isValidHostToken("a\nProxyCommand x"))
        XCTAssertFalse(HostSetup.isValidHostToken("a\r"))
        XCTAssertFalse(HostSetup.isValidHostToken(""))
    }

    func testConfigBlockOmitsDefaultPort() {
        let block = HostSetup.configBlock(alias: "web", host: "h.example", user: "u",
                                          pubPath: "/p.pub", socketPath: "/s.sock")
        XCTAssertTrue(block.contains("Host web"))
        XCTAssertTrue(block.contains("HostName h.example"))
        XCTAssertTrue(block.contains("IdentityFile /p.pub"))
        XCTAssertTrue(block.contains("IdentitiesOnly yes"))
        XCTAssertFalse(block.contains("Port"), "port 22 should not add a Port line")
    }

    func testConfigBlockIncludesCustomPort() {
        let block = HostSetup.configBlock(alias: "web", host: "h", user: "u", port: 2222,
                                          pubPath: "/p", socketPath: "/s")
        XCTAssertTrue(block.contains("\n  Port 2222\n"))
    }

    func testHostBlockExists() {
        let config = "Host prod alias2\n  HostName x\n\nHost other\n  HostName y\n"
        XCTAssertTrue(HostSetup.hostBlockExists(alias: "prod", in: config))
        XCTAssertTrue(HostSetup.hostBlockExists(alias: "alias2", in: config))
        XCTAssertFalse(HostSetup.hostBlockExists(alias: "missing", in: config))
    }

    // Regression: a host on a non-default port is stored as [host]:port, and a
    // port-less pin lookup must still find it (the host key is port-independent).
    func testKnownHostsCustomPortMatching() {
        let kh = """
        192.168.1.9 ssh-ed25519 QUFB
        [192.168.64.64]:1221 ssh-ed25519 QkJC
        [192.168.64.64]:1221 ecdsa-sha2-nistp256 Q0ND
        """
        func blobs(_ host: String, _ port: Int?) -> [Data] {
            HostResolver.hostKeys(inKnownHosts: kh, host: host, port: port)
        }
        // Port unknown → matches the host on its actual port (both key types).
        XCTAssertEqual(blobs("192.168.64.64", nil).count, 2)
        // Exact port matches.
        XCTAssertEqual(blobs("192.168.64.64", 1221).count, 2)
        // Wrong / default port does not match a non-default-port host.
        XCTAssertTrue(blobs("192.168.64.64", 22).isEmpty)
        // A plain (port-22) host still matches with nil and with 22.
        XCTAssertEqual(blobs("192.168.1.9", nil).count, 1)
        XCTAssertEqual(blobs("192.168.1.9", 22).count, 1)
    }

    func testHostKeyFingerprintFormat() {
        // Known SHA-256 of the ASCII bytes "abc" → base64, no padding, "SHA256:" prefix.
        let fp = HostResolver.fingerprint(ofHostKey: Data("abc".utf8))
        XCTAssertEqual(fp, "SHA256:ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0")
    }

    func testParseHostBlock() {
        let cfg = """
        Host web
          HostName example.com
          User deploy
          Port 2222
          IdentityFile ~/.ssh/id_ed25519

        Host other
          HostName x.example
        """
        let p = HostSetup.parseHostBlock(alias: "web", in: cfg)
        XCTAssertEqual(p?.hostName, "example.com")
        XCTAssertEqual(p?.user, "deploy")
        XCTAssertEqual(p?.port, 2222)
        XCTAssertEqual(p?.identityFiles, ["~/.ssh/id_ed25519"])
        XCTAssertEqual(p?.usesFobAgent, false)
        XCTAssertNil(HostSetup.parseHostBlock(alias: "missing", in: cfg), "unknown alias → nil")
        // Block ends at the next Host — don't leak `other`'s HostName into `web`.
        XCTAssertNotEqual(p?.hostName, "x.example")
    }

    func testParseHostBlockIgnoresWildcardAndDetectsFob() {
        let cfg = """
        Host *
          IdentityAgent ~/.fob/agent.sock
        Host prod
          HostName p.example
          IdentityAgent ~/.fob/agent.sock
        """
        // 'foo' is only covered by the wildcard block → not an adoptable literal host.
        XCTAssertNil(HostSetup.parseHostBlock(alias: "foo", in: cfg))
        let p = HostSetup.parseHostBlock(alias: "prod", in: cfg)
        XCTAssertEqual(p?.hostName, "p.example")
        XCTAssertEqual(p?.usesFobAgent, true)
    }

    func testSshKeySettingsURLCanonicalOnly() {
        // Canonical origins (exact or true subdomain) → link to the hardcoded apex.
        XCTAssertEqual(HostSetup.sshKeySettingsURL(forHost: "github.com")?.absoluteString,
                       "https://github.com/settings/ssh/new")
        XCTAssertEqual(HostSetup.sshKeySettingsURL(forHost: "ssh.github.com")?.absoluteString,
                       "https://github.com/settings/ssh/new")
        XCTAssertEqual(HostSetup.sshKeySettingsURL(forHost: "gitlab.com")?.absoluteString,
                       "https://gitlab.com/-/user_settings/ssh_keys")
        // Phishing look-alikes → nil (userinfo bypass and suffixed impostor).
        XCTAssertNil(HostSetup.sshKeySettingsURL(forHost: "github.com@evil.example"))
        XCTAssertNil(HostSetup.sshKeySettingsURL(forHost: "github.com.evil.example"))
        // Enterprise / self-hosted → nil (no unreliable path guess, no branded link).
        XCTAssertNil(HostSetup.sshKeySettingsURL(forHost: "github.mycorp.com"))
        XCTAssertNil(HostSetup.sshKeySettingsURL(forHost: "gitea.mycorp.com"))
    }

    func testValidHostToken() {
        XCTAssertTrue(HostSetup.isValidHostToken("example.com"))
        XCTAssertTrue(HostSetup.isValidHostToken("10.0.0.1"))
        XCTAssertFalse(HostSetup.isValidHostToken("-oProxyCommand=x")) // would be an ssh option
        XCTAssertFalse(HostSetup.isValidHostToken("has space"))
        XCTAssertFalse(HostSetup.isValidHostToken(""))
    }
}
