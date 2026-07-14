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

    // MARK: - isKeyReferenced / unencryptedKeyFinding

    func testIsKeyReferenced() {
        let config = """
        Host a
          IdentityFile ~/.ssh/id_ed25519_perso_ousson
        Host b
          # IdentityFile ~/.ssh/id_ed25519
          IdentityFile ~/.ssh/fob_b.pub
        """
        // id_ed25519 is only in a COMMENTED line → not referenced (and not confused with
        // the substring match against id_ed25519_perso_ousson).
        XCTAssertFalse(SSHCheckup.isKeyReferenced(keyPath: "/Users/me/.ssh/id_ed25519", configText: config, gitSigningKey: nil))
        // the perso key IS active
        XCTAssertTrue(SSHCheckup.isKeyReferenced(keyPath: "/Users/me/.ssh/id_ed25519_perso_ousson", configText: config, gitSigningKey: nil))
        // referenced via git signing key
        XCTAssertTrue(SSHCheckup.isKeyReferenced(keyPath: "/Users/me/.ssh/id_ed25519", configText: "", gitSigningKey: "/Users/me/.ssh/id_ed25519.pub"))
    }

    func testUnencryptedKeyFindingWording() {
        XCTAssertTrue(SSHCheckup.unencryptedKeyFinding(name: "k", path: "/p", referenced: true).fix == .command("ssh-keygen -p -f /p"))
        let unused = SSHCheckup.unencryptedKeyFinding(name: "k", path: "/p", referenced: false)
        XCTAssertTrue(unused.title.contains("unused"))
        XCTAssertEqual(unused.fix, .command("rm /p /p.pub"))
    }

    // MARK: - identityFinding

    func testIdentityFinding() {
        // global email set → flag (useConfigOnly alone insufficient), even if useConfigOnly on
        let f = SSHCheckup.identityFinding(includeCount: 2, useConfigOnly: false, defaultEmail: "me@work.com")
        XCTAssertNotNil(f)
        XCTAssertTrue(f?.title.contains("me@work.com") == true)
        XCTAssertTrue(f?.detail.contains("two steps") == true || f?.detail.contains("relocate") == true || f?.detail.contains("includeIf") == true)
        // no global email + guard off → bare useConfigOnly is the fix
        let g = SSHCheckup.identityFinding(includeCount: 2, useConfigOnly: false, defaultEmail: "")
        XCTAssertEqual(g?.fix, .command("git config --global user.useConfigOnly true"))
        // no global email + guard on → nil
        XCTAssertNil(SSHCheckup.identityFinding(includeCount: 2, useConfigOnly: true, defaultEmail: ""))
        // no includes → nil
        XCTAssertNil(SSHCheckup.identityFinding(includeCount: 0, useConfigOnly: false, defaultEmail: "me@work.com"))
    }

    func testAllowedSigners() {
        let pub = "ecdsa-sha2-nistp256 AAAABBBCCC fob:x"
        XCTAssertEqual(SSHCheckup.AllowedSigners.keyFields(pub), "ecdsa-sha2-nistp256 AAAABBBCCC")
        XCTAssertEqual(SSHCheckup.AllowedSigners.entry(email: "me@x.com", pubLine: pub),
                       "me@x.com namespaces=\"git\" ecdsa-sha2-nistp256 AAAABBBCCC fob:x")
        XCTAssertFalse(SSHCheckup.AllowedSigners.contains("", pubLine: pub))
        let added = SSHCheckup.AllowedSigners.appending("", email: "me@x.com", pubLine: pub)
        XCTAssertNotNil(added)
        XCTAssertTrue(SSHCheckup.AllowedSigners.contains(added!, pubLine: pub))
        XCTAssertNil(SSHCheckup.AllowedSigners.appending(added!, email: "me@x.com", pubLine: pub)) // idempotent
    }

    func testSigningVerificationFinding() {
        XCTAssertNil(SSHCheckup.signingVerificationFinding(usesFobSigning: false, allowedSignersConfigured: false, keyListed: false))
        XCTAssertTrue(SSHCheckup.signingVerificationFinding(usesFobSigning: true, allowedSignersConfigured: false, keyListed: false)?.title.contains("verifiable") == true)
        XCTAssertTrue(SSHCheckup.signingVerificationFinding(usesFobSigning: true, allowedSignersConfigured: true, keyListed: false)?.title.contains("allowed_signers") == true)
        XCTAssertNil(SSHCheckup.signingVerificationFinding(usesFobSigning: true, allowedSignersConfigured: true, keyListed: true))
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
