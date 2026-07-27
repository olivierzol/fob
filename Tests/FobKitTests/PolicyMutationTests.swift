import Foundation
import XCTest

@testable import FobKit

/// A PolicyStore whose `load`/`save` can be made to throw, to prove that policy-mutating
/// paths fail closed (never overwrite an unreadable record with the open default) and that
/// `rename` is transactional (CG-02).
private struct FaultyPolicyStore: PolicyStore {
    var loadError: Error?
    var saveError: Error?
    var loadResult: KeyPolicy? = KeyPolicy()

    func load(name: String) throws -> KeyPolicy? {
        if let loadError { throw loadError }
        return loadResult
    }
    func save(_ policy: KeyPolicy, name: String) throws {
        if let saveError { throw saveError }
    }
    func remove(name: String) throws {}
}

final class PolicyMutationTests: XCTestCase {
    private func tempStore(_ ps: PolicyStore) throws -> (KeyStore, URL) {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("fob-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: dir.appendingPathComponent("keys"), withIntermediateDirectories: true)
        return (KeyStore(directory: dir, policyStore: ps), dir)
    }

    // loadPolicyForMutation must THROW when the policy is unreadable (so a mutation can't
    // rebuild it on the open default), while displayPolicy still shows the default.
    func testMutationLoadFailsClosedButDisplayDefaults() throws {
        let (store, dir) = try tempStore(FaultyPolicyStore(loadError: PolicyStoreError.decode))
        defer { try? FileManager.default.removeItem(at: dir) }

        XCTAssertThrowsError(try store.loadPolicyForMutation(name: "k")) { error in
            guard case KeyStoreError.policyUnreadable = error else {
                return XCTFail("expected .policyUnreadable, got \(error)")
            }
        }
        XCTAssertTrue(store.displayPolicy(name: "k").isDefault, "display still falls back to open default")
    }

    // absent (no record) is the open default — a mutation may proceed from it.
    func testMutationLoadTreatsAbsentAsDefault() throws {
        let (store, dir) = try tempStore(FaultyPolicyStore(loadResult: nil))
        defer { try? FileManager.default.removeItem(at: dir) }
        XCTAssertTrue(try store.loadPolicyForMutation(name: "k").isDefault)
    }

    // rename fails closed on an unreadable policy: it throws BEFORE moving the key blob,
    // so the key keeps its old name (never renamed without its policy).
    func testRenameFailsClosedOnUnreadablePolicy() throws {
        let (store, dir) = try tempStore(FaultyPolicyStore(loadError: PolicyStoreError.decode))
        defer { try? FileManager.default.removeItem(at: dir) }
        let keys = dir.appendingPathComponent("keys")
        try Data("blob".utf8).write(to: keys.appendingPathComponent("from.key"))

        XCTAssertThrowsError(try store.rename(from: "from", to: "to"))
        XCTAssertTrue(FileManager.default.fileExists(atPath: keys.appendingPathComponent("from.key").path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: keys.appendingPathComponent("to.key").path))
    }

    // rename rolls back the key-blob move if the policy save fails midway — the key stays
    // under its original name, not stranded under the new name with no policy.
    func testRenameRollsBackWhenPolicySaveFails() throws {
        let (store, dir) = try tempStore(FaultyPolicyStore(saveError: PolicyStoreError.decode))
        defer { try? FileManager.default.removeItem(at: dir) }
        let keys = dir.appendingPathComponent("keys")
        try Data("blob".utf8).write(to: keys.appendingPathComponent("from.key"))

        XCTAssertThrowsError(try store.rename(from: "from", to: "to"))
        XCTAssertTrue(FileManager.default.fileExists(atPath: keys.appendingPathComponent("from.key").path),
                      "blob rolled back to original name")
        XCTAssertFalse(FileManager.default.fileExists(atPath: keys.appendingPathComponent("to.key").path))
    }
}
