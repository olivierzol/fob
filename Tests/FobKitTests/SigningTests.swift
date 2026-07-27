import Foundation
import XCTest

@testable import FobKit

final class SigningTests: XCTestCase {
    // MARK: SSHSIG detection

    /// Build a well-formed SSHSIG signed-data envelope (per PROTOCOL.sshsig).
    private func sshsigBlob(namespace: String, reserved: Data = Data(),
                            hashAlgorithm: String = "sha256", digestLen: Int = 32,
                            trailing: Data = Data()) -> Data {
        var body = SSHWriter()
        body.writeString(namespace)
        body.writeString(reserved)
        body.writeString(hashAlgorithm)
        body.writeString(Data(repeating: 0xAB, count: digestLen))
        return SSHSIG.magic + body.data + trailing
    }

    func testValidSSHSIGClassified() {
        let blob = sshsigBlob(namespace: "git")
        XCTAssertEqual(SSHSIG.classify(blob), .valid(.init(namespace: "git", hashAlgorithm: "sha256")))
        XCTAssertEqual(SSHSIG.classify(sshsigBlob(namespace: "file", hashAlgorithm: "sha512", digestLen: 64)),
                       .valid(.init(namespace: "file", hashAlgorithm: "sha512")))
    }

    func testNonSSHSIGClassified() {
        // An ordinary SSH auth payload (session id + fields) never starts with the magic.
        var auth = SSHWriter()
        auth.writeString("session-id-bytes")
        XCTAssertEqual(SSHSIG.classify(auth.data), .notSSHSIG)
        XCTAssertEqual(SSHSIG.classify(Data([0x00, 0x01, 0x02])), .notSSHSIG)
    }

    func testMalformedSSHSIGRejected() {
        // Magic + namespace only (the pre-fix parser accepted this) — now malformed.
        var nsOnly = SSHWriter(); nsOnly.writeString("git")
        XCTAssertEqual(SSHSIG.classify(SSHSIG.magic + nsOnly.data), .malformed)
        // Magic alone.
        XCTAssertEqual(SSHSIG.classify(Data("SSHSIG".utf8)), .malformed)
        // Trailing bytes after a complete envelope.
        XCTAssertEqual(SSHSIG.classify(sshsigBlob(namespace: "git", trailing: Data([0xFF]))), .malformed)
        // Empty namespace.
        XCTAssertEqual(SSHSIG.classify(sshsigBlob(namespace: "")), .malformed)
        // Unsupported hash algorithm.
        XCTAssertEqual(SSHSIG.classify(sshsigBlob(namespace: "git", hashAlgorithm: "md5")), .malformed)
        // Digest length that doesn't match the algorithm (sha256 wants 32).
        XCTAssertEqual(SSHSIG.classify(sshsigBlob(namespace: "git", digestLen: 16)), .malformed)
        // Invalid UTF-8 namespace.
        var badNS = SSHWriter()
        badNS.writeString(Data([0xFF, 0xFE]))
        badNS.writeString(Data()); badNS.writeString("sha256"); badNS.writeString(Data(repeating: 0, count: 32))
        XCTAssertEqual(SSHSIG.classify(SSHSIG.magic + badNS.data), .malformed)
    }

    func testSanitizeNamespaceStripsControlChars() {
        XCTAssertEqual(Agent.sanitizeNamespace("git\nrm -rf"), "gitrm -rf")
        XCTAssertEqual(Agent.sanitizeNamespace("git"), "git")
        XCTAssertEqual(Agent.sanitizeNamespace(String(repeating: "x", count: 200)).count, 64)
    }

    // MARK: Namespace policy

    func testAllowsSignatureNamespaces() {
        XCTAssertTrue(KeyPolicy().allowsSignature(namespace: "git"), "nil = any namespace")
        XCTAssertTrue(KeyPolicy().allowsSignature(namespace: "file"))

        let gitOnly = KeyPolicy(allowedNamespaces: ["git"])
        XCTAssertTrue(gitOnly.allowsSignature(namespace: "git"))
        XCTAssertFalse(gitOnly.allowsSignature(namespace: "file"))

        let disabled = KeyPolicy(allowedNamespaces: [])
        XCTAssertFalse(disabled.allowsSignature(namespace: "git"), "[] = signing disabled")
    }

    func testNamespaceRestrictionCountsAsNonDefault() {
        XCTAssertTrue(KeyPolicy().isDefault)
        XCTAssertFalse(KeyPolicy(allowedNamespaces: ["git"]).isDefault)
        XCTAssertFalse(KeyPolicy(allowedNamespaces: []).isDefault)
    }

    func testPolicyRoundTripsNamespaces() throws {
        let policy = KeyPolicy(pinnedHostKeys: [], reuseSeconds: 30, allowedNamespaces: ["git", "file"])
        let data = try JSONEncoder().encode(policy)
        let decoded = try JSONDecoder().decode(KeyPolicy.self, from: data)
        XCTAssertEqual(decoded.allowedNamespaces, ["git", "file"])
        XCTAssertEqual(decoded.reuseSeconds, 30)
    }
}
