import Foundation
import XCTest

@testable import FobKit

final class SigningTests: XCTestCase {
    // MARK: SSHSIG detection

    func testSSHSIGNamespaceParsed() {
        var body = SSHWriter()
        body.writeString("git") // the namespace, as an SSH string
        let blob = SSHSIG.magic + body.data
        XCTAssertEqual(SSHSIG.namespace(of: blob), "git")
    }

    func testNonSSHSIGReturnsNil() {
        // An ordinary SSH auth payload (session id + fields) never starts with the magic.
        var auth = SSHWriter()
        auth.writeString("session-id-bytes")
        XCTAssertNil(SSHSIG.namespace(of: auth.data))
        XCTAssertNil(SSHSIG.namespace(of: Data([0x00, 0x01, 0x02])))
        XCTAssertNil(SSHSIG.namespace(of: Data("SSHSIG".utf8))) // magic but no namespace
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
