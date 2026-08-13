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

    // MARK: - requireBiometry (protection level)

    /// A Touch-ID-only key must produce a *persisted* record: the enclave's access control can't be
    /// read back from the blob, so if `isDefault` ignored this flag `savePolicy` would delete the
    /// record and the setting would be lost (and a migration would silently downgrade the key).
    func testRequireBiometryIsNotDefaultAndSurvivesSave() throws {
        XCTAssertTrue(KeyPolicy().isDefault)
        XCTAssertTrue(KeyPolicy(requireBiometry: false).isDefault, "user-presence is the default")
        XCTAssertFalse(KeyPolicy(requireBiometry: true).isDefault)

        let memory = InMemoryPolicyStore()
        let store = KeyStore(directory: try makeTempKeysDir().deletingLastPathComponent(),
                             policyStore: memory)
        try store.savePolicy(KeyPolicy(requireBiometry: true), name: "k")
        XCTAssertEqual(try store.loadPolicyForMutation(name: "k").requireBiometry, true)
    }

    /// Old `.policy` JSON predates the field, so it must still decode (nil = unknown).
    func testRequireBiometryDecodesFromLegacyJSON() throws {
        let legacy = Data(#"{"pinnedHostKeys":[],"reuseSeconds":30}"#.utf8)
        let policy = try JSONDecoder().decode(KeyPolicy.self, from: legacy)
        XCTAssertNil(policy.requireBiometry, "unknown, not false")
        XCTAssertEqual(policy.reuseSeconds, 30)
    }

    /// Rotation carries the retired key's pins/reuse but must keep the *replacement's* protection
    /// level — the user re-chooses it when creating the new key.
    func testCarryPolicyKeepsDestinationProtectionLevel() throws {
        let memory = InMemoryPolicyStore()
        let store = KeyStore(directory: try makeTempKeysDir().deletingLastPathComponent(),
                             policyStore: memory)
        try store.savePolicy(KeyPolicy(pinnedHostKeys: [Data([9])], reuseSeconds: 30,
                                       requireBiometry: true), name: "old")
        try store.savePolicy(KeyPolicy(requireBiometry: false), name: "new")

        try store.carryPolicy(from: "old", to: "new")

        let carried = try store.loadPolicyForMutation(name: "new")
        XCTAssertEqual(carried.pinnedHostKeys, [Data([9])], "pins carried")
        XCTAssertEqual(carried.reuseSeconds, 30, "reuse carried")
        XCTAssertNotEqual(carried.requireBiometry, true, "destination's own level kept, not the old key's")
    }

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
        XCTAssertTrue(store.displayPolicy(name: "k").pinnedHostKeys.isEmpty)
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

    // MARK: - KeyPolicy: namespaceChoiceMade marker (auto-harden)

    func testPolicyDecodesOldJSONWithoutMarker() throws {
        // A .policy written before the marker existed must still decode (marker defaults false).
        let old = #"{"pinnedHostKeys":[],"allowedNamespaces":["git"]}"#
        let policy = try JSONDecoder().decode(KeyPolicy.self, from: Data(old.utf8))
        XCTAssertEqual(policy.allowedNamespaces, ["git"])
        XCTAssertNotEqual(policy.namespaceChoiceMade, true)  // absent → treated as "not chosen"
    }

    func testIsDefaultAccountsForMarker() {
        // An otherwise-empty policy that records a deliberate choice must NOT be "default"
        // (else savePolicy would delete it and the choice would be forgotten → re-harden).
        var p = KeyPolicy()
        XCTAssertTrue(p.isDefault)
        p.namespaceChoiceMade = true
        XCTAssertFalse(p.isDefault)
    }

    func testShouldAutoHardenSigning() {
        // Signing-only + unrestricted + no explicit choice → harden.
        XCTAssertTrue(KeyPolicy().shouldAutoHardenSigning(isSigningOnly: true))
        // Not signing-only (has an auth role) → never.
        XCTAssertFalse(KeyPolicy().shouldAutoHardenSigning(isSigningOnly: false))
        // Already restricted → nothing to do.
        XCTAssertFalse(KeyPolicy(allowedNamespaces: ["git"]).shouldAutoHardenSigning(isSigningOnly: true))
        // User made a choice (e.g. deliberately unrestricted) → don't override.
        XCTAssertFalse(KeyPolicy(namespaceChoiceMade: true).shouldAutoHardenSigning(isSigningOnly: true))
    }

    func testMarkerSurvivesSaveLoadAndClearedPolicyPersists() throws {
        let store = KeyStore(directory: URL(fileURLWithPath: "/tmp/unused"),
                             policyStore: InMemoryPolicyStore())
        // User unticks git-only on a signing-only key: allowedNamespaces nil BUT choice made.
        try store.savePolicy(KeyPolicy(namespaceChoiceMade: true), name: "k")
        // It must persist (not be dropped as "default") so it isn't re-hardened later.
        XCTAssertEqual(store.displayPolicy(name: "k").namespaceChoiceMade, true)
        XCTAssertFalse(store.displayPolicy(name: "k").shouldAutoHardenSigning(isSigningOnly: true))
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
