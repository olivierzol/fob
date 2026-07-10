import Foundation
import XCTest

@testable import FobKit

/// A PolicyStore backed by a dictionary — lets us test KeyStore's delegation and the
/// fail-closed semantics without touching the real keychain or filesystem.
final class InMemoryPolicyStore: PolicyStore {
    var storage: [String: KeyPolicy] = [:]
    func load(name: String) throws -> KeyPolicy? { storage[name] }
    func save(_ policy: KeyPolicy, name: String) throws { storage[name] = policy }
    func remove(name: String) throws { storage[name] = nil }
}

/// Simulates a backend error (e.g. a corrupt keychain item) on every read.
struct ThrowingPolicyStore: PolicyStore {
    func load(name: String) throws -> KeyPolicy? { throw PolicyStoreError.decode }
    func save(_ policy: KeyPolicy, name: String) throws {}
    func remove(name: String) throws {}
}

final class PolicyStoreTests: XCTestCase {

    // MARK: - FilePolicyStore

    func testFileStoreRoundTrip() throws {
        let store = FilePolicyStore(keysDirectory: try makeTempKeysDir())
        XCTAssertNil(try store.load(name: "k"), "no file → nil (open by design)")

        try store.save(KeyPolicy(pinnedHostKeys: [Data([1, 2, 3])], reuseSeconds: 30), name: "k")
        let loaded = try store.load(name: "k")
        XCTAssertEqual(loaded?.pinnedHostKeys, [Data([1, 2, 3])])
        XCTAssertEqual(loaded?.reuseSeconds, 30)

        try store.remove(name: "k")
        XCTAssertNil(try store.load(name: "k"))
    }

    func testFileStoreCorruptFileThrows() throws {
        let dir = try makeTempKeysDir()
        let store = FilePolicyStore(keysDirectory: dir)
        try Data("not valid json".utf8).write(to: dir.appendingPathComponent("k.policy"))
        // A present-but-corrupt file must throw (KeyStore maps this to .unreadable →
        // the agent fails closed), never silently read as the open default.
        XCTAssertThrowsError(try store.load(name: "k"))
    }

    // MARK: - KeyStore delegation & fail-closed

    func testPolicyStatusFailsClosedWhenStoreThrows() {
        let store = KeyStore(directory: URL(fileURLWithPath: "/tmp/unused"),
                             policyStore: ThrowingPolicyStore())
        guard case .unreadable = store.policyStatus(name: "k") else {
            return XCTFail("a throwing store must surface as .unreadable (fail closed)")
        }
        // Display convenience still degrades to the open default.
        XCTAssertTrue(store.policy(name: "k").pinnedHostKeys.isEmpty)
    }

    func testSavePolicyStoresAndDefaultRemoves() throws {
        let memory = InMemoryPolicyStore()
        let store = KeyStore(directory: URL(fileURLWithPath: "/tmp/unused"), policyStore: memory)

        try store.savePolicy(KeyPolicy(pinnedHostKeys: [Data([9])]), name: "k")
        guard case .present(let p) = store.policyStatus(name: "k"), p.pinnedHostKeys == [Data([9])] else {
            return XCTFail("expected the pinned policy to be present")
        }

        // Saving a default (open) policy is represented as the absence of a record.
        try store.savePolicy(KeyPolicy(), name: "k")
        guard case .absent = store.policyStatus(name: "k") else {
            return XCTFail("default policy should clear the record → .absent")
        }
        XCTAssertNil(memory.storage["k"])
    }

    // MARK: - Keychain availability probe is safe on any build

    func testKeychainAvailabilityProbeDoesNotCrash() {
        // On an unsigned/dev test binary this returns false (no entitlement); the point
        // is that probing never throws or crashes, so selection always yields a store.
        _ = KeychainPolicyStore.isAvailable()
    }

    // MARK: - Helpers

    private func makeTempKeysDir() throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("fobpolicy-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: dir) }
        return dir
    }
}
