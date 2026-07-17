import CryptoKit
import Foundation
import XCTest

@testable import FobKit

/// Security-critical unit tests. These lock down the paths a same-UID attacker or a
/// malformed peer could try to abuse: name validation, SSH wire parsing, host-key
/// signature verification (the trust root for pinning), session-bind rules, the
/// fail-closed policy loader, and the audit hash chain.
final class SecurityTests: XCTestCase {

    // MARK: - Key/alias name validation (argument-injection defense)

    func testValidNamesAccepted() {
        for name in ["bender", "prod-web", "host_1", "a.b.c", "A9", "_local"] {
            XCTAssertTrue(KeyStore.isValidName(name), "\(name) should be valid")
        }
    }

    func testDangerousNamesRejected() {
        for name in [
            "-rf",                 // leading dash → parsed as an ssh option
            "-oProxyCommand=x",    // the classic ssh argument injection
            "",                    // empty
            "a b",                 // space
            "../etc",              // path traversal
            "a/b",                 // slash
            "name;rm -rf",         // shell metachars
            "quote\"",             // quote
            "$(whoami)",           // command substitution text
        ] {
            XCTAssertFalse(KeyStore.isValidName(name), "\(name) must be rejected")
        }
    }

    // MARK: - SSH wire reader bounds (no over-read on malformed input)

    func testReaderRejectsTruncatedLength() {
        var reader = SSHReader(Data([0x00, 0x00])) // fewer than 4 bytes for a uint32
        XCTAssertThrowsError(try reader.readUInt32())
    }

    func testReaderRejectsStringLongerThanBuffer() {
        // Declares a 16-byte string but supplies only 2 bytes of body.
        var reader = SSHReader(Data([0x00, 0x00, 0x00, 0x10, 0x41, 0x42]))
        XCTAssertThrowsError(try reader.readString())
    }

    func testReaderRoundTrip() throws {
        var writer = SSHWriter()
        writer.writeString("hello")
        writer.writeUInt32(0xDEAD_BEEF)
        writer.writeByte(0x2A)
        var reader = SSHReader(writer.data)
        XCTAssertEqual(String(decoding: try reader.readString(), as: UTF8.self), "hello")
        XCTAssertEqual(try reader.readUInt32(), 0xDEAD_BEEF)
        XCTAssertEqual(try reader.readByte(), 0x2A)
        XCTAssertTrue(reader.isAtEnd)
    }

    // MARK: - Host-key signature verification (the pinning trust root)

    func testEd25519ValidSignatureVerifies() {
        let priv = Curve25519.Signing.PrivateKey()
        let message = Data("session-id-bytes".utf8)
        let signature = try! priv.signature(for: message)

        var key = SSHWriter(); key.writeString("ssh-ed25519"); key.writeString(priv.publicKey.rawRepresentation)
        var sig = SSHWriter(); sig.writeString("ssh-ed25519"); sig.writeString(signature)

        assertResult(.valid, HostKeySignature.verify(hostKeyBlob: key.data, signatureBlob: sig.data, message: message))
    }

    func testEd25519TamperedSignatureRejected() {
        let priv = Curve25519.Signing.PrivateKey()
        let message = Data("session-id-bytes".utf8)
        var signature = [UInt8](try! priv.signature(for: message))
        signature[0] ^= 0xFF // flip a bit

        var key = SSHWriter(); key.writeString("ssh-ed25519"); key.writeString(priv.publicKey.rawRepresentation)
        var sig = SSHWriter(); sig.writeString("ssh-ed25519"); sig.writeString(Data(signature))

        assertResult(.invalid, HostKeySignature.verify(hostKeyBlob: key.data, signatureBlob: sig.data, message: message))
    }

    func testEd25519WrongMessageRejected() {
        let priv = Curve25519.Signing.PrivateKey()
        let signature = try! priv.signature(for: Data("real".utf8))

        var key = SSHWriter(); key.writeString("ssh-ed25519"); key.writeString(priv.publicKey.rawRepresentation)
        var sig = SSHWriter(); sig.writeString("ssh-ed25519"); sig.writeString(signature)

        // A local attacker replaying a signature can't make it verify over other data.
        assertResult(.invalid, HostKeySignature.verify(hostKeyBlob: key.data, signatureBlob: sig.data, message: Data("forged".utf8)))
    }

    func testEcdsaP256ValidSignatureVerifies() {
        let priv = P256.Signing.PrivateKey()
        let message = Data("session-id-bytes".utf8)
        let signature = try! priv.signature(for: message)

        // publicKeyBlob/signatureBlob are the exact SSH encodings the agent produces.
        let hostKeyBlob = SSHFormat.publicKeyBlob(priv.publicKey)
        let signatureBlob = SSHFormat.signatureBlob(signature)

        assertResult(.valid, HostKeySignature.verify(hostKeyBlob: hostKeyBlob, signatureBlob: signatureBlob, message: message))
    }

    func testUnsupportedKeyTypeReportedNotAcceptedAsValid() {
        var key = SSHWriter(); key.writeString("ssh-dss"); key.writeString(Data([1, 2, 3]))
        var sig = SSHWriter(); sig.writeString("ssh-dss"); sig.writeString(Data([4, 5, 6]))
        // Must be .unsupportedKeyType (advisory), never .valid — a pinned key requires
        // `verified == true`, so unsupported types can never satisfy a pin.
        assertResult(.unsupportedKeyType, HostKeySignature.verify(hostKeyBlob: key.data, signatureBlob: sig.data, message: Data()))
    }

    func testGarbageBlobRejected() {
        assertResult(.invalid, HostKeySignature.verify(hostKeyBlob: Data([0xFF, 0xFF]), signatureBlob: Data([0xFF]), message: Data()))
    }

    // MARK: - session-bind add / re-bind rules

    func testRebindIdenticalDestinationAllowed() {
        var bindings: [SessionBinding] = []
        let b = SessionBinding(hostKeyBlob: Data([1]), sessionID: Data([9]), isForwarding: false, verified: true)
        XCTAssertTrue(SessionBinding.add(b, to: &bindings))
        XCTAssertTrue(SessionBinding.add(b, to: &bindings)) // identical re-bind is fine
        XCTAssertEqual(bindings.count, 1, "identical re-bind must not duplicate")
    }

    func testAddNewDestinationRefusedUnlessAllForwarding() {
        var bindings: [SessionBinding] = []
        let first = SessionBinding(hostKeyBlob: Data([1]), sessionID: Data([9]), isForwarding: false, verified: true)
        XCTAssertTrue(SessionBinding.add(first, to: &bindings))
        let second = SessionBinding(hostKeyBlob: Data([2]), sessionID: Data([8]), isForwarding: false, verified: true)
        // Existing binding is not for forwarding → adding a different destination is refused.
        XCTAssertFalse(SessionBinding.add(second, to: &bindings))
        XCTAssertEqual(bindings.count, 1)
    }

    func testAddNewDestinationAllowedWhenAllForwarding() {
        var bindings: [SessionBinding] = []
        let first = SessionBinding(hostKeyBlob: Data([1]), sessionID: Data([9]), isForwarding: true, verified: true)
        XCTAssertTrue(SessionBinding.add(first, to: &bindings))
        let second = SessionBinding(hostKeyBlob: Data([2]), sessionID: Data([8]), isForwarding: true, verified: true)
        XCTAssertTrue(SessionBinding.add(second, to: &bindings))
        XCTAssertEqual(bindings.count, 2)
    }

    // MARK: - Policy loader fails closed on corruption (M-3)

    func testPolicyStatusAbsentPresentUnreadable() throws {
        let store = try makeTempStore()
        let name = "k"

        // Absent → open by design.
        assertPolicy(.absent, store.policyStatus(name: name))

        // Present → parsed.
        try store.savePolicy(KeyPolicy(pinnedHostKeys: [Data([1, 2, 3])]), name: name)
        if case .present(let p) = store.policyStatus(name: name) {
            XCTAssertEqual(p.pinnedHostKeys, [Data([1, 2, 3])])
        } else {
            XCTFail("expected .present")
        }

        // Corrupt → .unreadable (must NOT fall back to open), and policy() shows default.
        let policyURL = store.keysDirectory.appendingPathComponent("\(name).policy")
        try Data("this is not json".utf8).write(to: policyURL)
        assertPolicy(.unreadable, store.policyStatus(name: name))
        XCTAssertTrue(store.policy(name: name).pinnedHostKeys.isEmpty, "display fallback is default")
    }

    // MARK: - Audit hash chain tamper-evidence

    func testAuditChainIntactThenBroken() throws {
        let store = try makeTempStore()
        let audit = AuditLog(directory: store.directory)
        audit.record("signed", key: "k", destination: "bender", peer: "ssh")
        audit.record("denied", key: "k", destination: "bender", peer: "ssh")
        audit.record("bind", destination: "bender", peer: "ssh")

        waitForAuditEntries(3, in: store.directory)
        XCTAssertNil(AuditLog.firstBrokenLink(directory: store.directory), "fresh chain must verify")

        // Tamper: edit a byte in the middle of the log and confirm the chain breaks.
        let logURL = AuditLog.logURL(directory: store.directory)
        var bytes = [UInt8](try Data(contentsOf: logURL))
        bytes[bytes.count / 2] = bytes[bytes.count / 2] == 0x20 ? 0x21 : 0x20
        try Data(bytes).write(to: logURL)
        XCTAssertNotNil(AuditLog.firstBrokenLink(directory: store.directory), "tampering must be detected")
    }

    // MARK: - Helpers

    private func assertResult(_ expected: HostKeySignature.Result, _ actual: HostKeySignature.Result,
                              file: StaticString = #filePath, line: UInt = #line) {
        switch (expected, actual) {
        case (.valid, .valid), (.invalid, .invalid), (.unsupportedKeyType, .unsupportedKeyType):
            break
        default:
            XCTFail("expected \(expected), got \(actual)", file: file, line: line)
        }
    }

    private func assertPolicy(_ expected: PolicyStatus, _ actual: PolicyStatus,
                              file: StaticString = #filePath, line: UInt = #line) {
        switch (expected, actual) {
        case (.absent, .absent), (.present, .present), (.unreadable, .unreadable):
            break
        default:
            XCTFail("expected \(expected), got \(actual)", file: file, line: line)
        }
    }

    func testRenamePreservesKeyAndPolicy() throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, "Secure Enclave required")
        let store = try makeTempStore()
        let orig = try store.create(name: "rot", requireBiometry: false)
        try store.savePolicy(KeyPolicy(reuseSeconds: 30, namespaceChoiceMade: true), name: "rot")
        let origPub = try orig.publicKey().rawRepresentation

        try store.rename(from: "rot", to: "rot2")
        XCTAssertThrowsError(try store.find(name: "rot"))                    // old name gone
        let moved = try store.find(name: "rot2")
        XCTAssertEqual(try moved.publicKey().rawRepresentation, origPub)     // same enclave key
        XCTAssertEqual(store.policy(name: "rot2").reuseSeconds, 30)          // policy carried over
        XCTAssertEqual(store.policy(name: "rot2").namespaceChoiceMade, true)

        XCTAssertThrowsError(try store.rename(from: "absent", to: "x"))      // source missing
        _ = try store.create(name: "other", requireBiometry: false)
        XCTAssertThrowsError(try store.rename(from: "rot2", to: "other"))    // target exists
    }

    private func makeTempStore() throws -> KeyStore {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("fobtest-\(UUID().uuidString)")
        let store = KeyStore(directory: dir)
        try FileManager.default.createDirectory(at: store.keysDirectory, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: dir) }
        return store
    }

    private func waitForAuditEntries(_ count: Int, in directory: URL) {
        for _ in 0..<200 { // audit writes are async on a serial queue
            if AuditLog.entries(directory: directory).count >= count { return }
            usleep(10_000)
        }
        XCTFail("timed out waiting for \(count) audit entries")
    }
}
