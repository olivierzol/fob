import XCTest

@testable import FobKit

final class KnownHostsTests: XCTestCase {
    private func hosts(_ text: String) -> [String] {
        SSHCheckup.parseKnownHosts(text).hosts.map(\.host)
    }

    func testPlaintextHostsAndDedup() {
        let kh = """
        github.com ssh-ed25519 AAAAC3Nza...
        example.com ssh-rsa AAAAB3Nza...
        github.com ecdsa-sha2-nistp256 AAAAE2Vj...
        """
        // github.com appears twice (two key types) → one entry.
        XCTAssertEqual(hosts(kh), ["github.com", "example.com"])
    }

    func testCommaListAndIPs() {
        let kh = "server.local,192.168.1.20 ssh-ed25519 AAAAC3Nza..."
        XCTAssertEqual(hosts(kh), ["server.local", "192.168.1.20"])
    }

    func testBracketHostPort() {
        let kh = "[bastion.example.com]:2222 ssh-ed25519 AAAAC3Nza..."
        let parsed = SSHCheckup.parseKnownHosts(kh).hosts
        XCTAssertEqual(parsed.first?.host, "bastion.example.com")
        XCTAssertEqual(parsed.first?.port, 2222)
    }

    func testHashedCountedNotReturned() {
        let kh = """
        |1|abc123=|def456= ssh-ed25519 AAAAC3Nza...
        plain.example.com ssh-ed25519 AAAAC3Nza...
        """
        let r = SSHCheckup.parseKnownHosts(kh)
        XCTAssertEqual(r.hashedCount, 1)
        XCTAssertEqual(r.hosts.map(\.host), ["plain.example.com"])
    }

    func testSkipsMarkersCommentsWildcardsAndLocalhost() {
        let kh = """
        # a comment
        @cert-authority *.example.com ssh-ed25519 AAAAC3Nza...
        @revoked old.example.com ssh-ed25519 AAAAC3Nza...
        *.wild.net ssh-ed25519 AAAAC3Nza...
        localhost ssh-ed25519 AAAAC3Nza...
        127.0.0.1 ssh-ed25519 AAAAC3Nza...
        keep.example.com ssh-ed25519 AAAAC3Nza...
        """
        XCTAssertEqual(hosts(kh), ["keep.example.com"])
    }

    func testEmpty() {
        XCTAssertTrue(hosts("").isEmpty)
        XCTAssertEqual(SSHCheckup.parseKnownHosts("").hashedCount, 0)
    }

    func testUnconfiguredExcludesConfiguredAliasAndHostName() {
        let kh = """
        newbox.example.net ssh-ed25519 AAAAC3Nza...
        10.0.0.5 ssh-ed25519 AAAAC3Nza...
        github.com ssh-ed25519 AAAAC3Nza...
        """
        // config: an alias "gh" → HostName github.com, and a host whose HostName is the IP.
        let cfg = """
        Host gh
          HostName github.com
          IdentityAgent ~/.fob/agent.sock
        Host inbox
          HostName 10.0.0.5
        """
        let flagged = SSHCheckup.unconfiguredKnownHosts(knownHosts: kh, sshConfig: cfg).map(\.host)
        // github.com (matched by HostName) and 10.0.0.5 (matched by HostName) are excluded;
        // only the never-configured host remains.
        XCTAssertEqual(flagged, ["newbox.example.net"])
    }

    func testUnconfiguredEmptyWhenAllConfigured() {
        let kh = "onlybox.example.com ssh-ed25519 AAAAC3Nza..."
        let cfg = "Host onlybox.example.com\n  HostName onlybox.example.com\n"
        XCTAssertTrue(SSHCheckup.unconfiguredKnownHosts(knownHosts: kh, sshConfig: cfg).isEmpty)
    }
}
