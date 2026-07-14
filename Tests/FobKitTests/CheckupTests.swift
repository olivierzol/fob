import XCTest

@testable import FobKit

final class CheckupTests: XCTestCase {
    // MARK: - parsePrivateKey

    func testUnencryptedOpenSSHKey() {
        // A real unencrypted ed25519 OpenSSH key (cipher "none").
        let key = """
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
        QyNTUxOQAAACBHUJVXfxRBGgZA5pBGADoQ0LZkfunGi73KqPuYYni2vAAAAKDv0aXt79Gl
        7QAAAAtzc2gtZWQyNTUxOQAAACBHUJVXfxRBGgZA5pBGADoQ0LZkfunGi73KqPuYYni2v
        AAAAEBnZ2h0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
        -----END OPENSSH PRIVATE KEY-----
        """
        // The body above is illustrative; construct a valid one programmatically instead.
        let real = Self.makeOpenSSHKey(cipher: "none")
        XCTAssertEqual(SSHCheckup.parsePrivateKey(real)?.isEncrypted, false)
        _ = key
    }

    func testEncryptedOpenSSHKey() {
        let enc = Self.makeOpenSSHKey(cipher: "aes256-ctr")
        XCTAssertEqual(SSHCheckup.parsePrivateKey(enc)?.isEncrypted, true)
    }

    func testLegacyPEMEncrypted() {
        let pem = """
        -----BEGIN RSA PRIVATE KEY-----
        Proc-Type: 4,ENCRYPTED
        DEK-Info: AES-128-CBC,0123456789ABCDEF

        AAAA
        -----END RSA PRIVATE KEY-----
        """
        XCTAssertEqual(SSHCheckup.parsePrivateKey(pem)?.isEncrypted, true)
    }

    func testLegacyPEMPlain() {
        let pem = "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n"
        XCTAssertEqual(SSHCheckup.parsePrivateKey(pem)?.isEncrypted, false)
    }

    func testNotAPrivateKey() {
        XCTAssertNil(SSHCheckup.parsePrivateKey("ssh-ed25519 AAAA... comment"))
        XCTAssertNil(SSHCheckup.parsePrivateKey("just some text"))
    }

    /// Build a minimal valid OpenSSH-format private key blob with the given cipher name,
    /// so encryption detection is tested against the real binary layout.
    private static func makeOpenSSHKey(cipher: String) -> String {
        var blob = [UInt8]("openssh-key-v1\u{0}".utf8)
        let name = [UInt8](cipher.utf8)
        blob += [UInt8((name.count >> 24) & 0xff), UInt8((name.count >> 16) & 0xff),
                 UInt8((name.count >> 8) & 0xff), UInt8(name.count & 0xff)]
        blob += name
        blob += [0, 0, 0, 4, 110, 111, 110, 101] // a trailing field, ignored by the parser
        let b64 = Data(blob).base64EncodedString()
        return "-----BEGIN OPENSSH PRIVATE KEY-----\n\(b64)\n-----END OPENSSH PRIVATE KEY-----\n"
    }

    // MARK: - permissions

    func testPermissive() {
        XCTAssertFalse(SSHCheckup.isPrivateKeyPermissive(mode: 0o600))
        XCTAssertFalse(SSHCheckup.isPrivateKeyPermissive(mode: 0o400))
        XCTAssertTrue(SSHCheckup.isPrivateKeyPermissive(mode: 0o644))
        XCTAssertTrue(SSHCheckup.isPrivateKeyPermissive(mode: 0o640))
        XCTAssertTrue(SSHCheckup.isPrivateKeyPermissive(mode: 0o660))
    }

    // MARK: - scanConfig

    func testScanFlagsRiskyDirectives() {
        let config = """
        Host prod
          HostName prod.example
          StrictHostKeyChecking no
          ForwardAgent yes

        Host *
          ForwardAgent yes
          IdentitiesOnly no
        """
        let f = SSHCheckup.scanConfig(config)
        // StrictHostKeyChecking no under Host prod → high
        XCTAssertTrue(f.contains { $0.title.contains("StrictHostKeyChecking no") && $0.severity == .high })
        // ForwardAgent under a specific host = medium; under Host * = high
        XCTAssertTrue(f.contains { $0.title.contains("ForwardAgent yes · Host prod") && $0.severity == .medium })
        XCTAssertTrue(f.contains { $0.title.contains("ForwardAgent yes · Host *") && $0.severity == .high })
        XCTAssertTrue(f.contains { $0.title.contains("IdentitiesOnly no") && $0.severity == .low })
    }

    func testCleanConfigNoFindings() {
        let config = """
        Host web
          HostName web.example
          User me
          IdentityAgent ~/.fob/agent.sock
          IdentitiesOnly yes
          StrictHostKeyChecking accept-new
        """
        XCTAssertTrue(SSHCheckup.scanConfig(config).isEmpty)
    }

    func testUserKnownHostsDevNull() {
        let f = SSHCheckup.scanConfig("Host x\n  UserKnownHostsFile /dev/null\n")
        XCTAssertTrue(f.contains { $0.title.contains("/dev/null") && $0.severity == .high })
    }
}
