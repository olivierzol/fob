import XCTest

@testable import FobKit

final class UpdateCheckTests: XCTestCase {
    func testIsNewer() {
        XCTAssertTrue(UpdateCheck.isNewer("v0.15.0", than: "0.14.0"))
        XCTAssertTrue(UpdateCheck.isNewer("0.14.1", than: "0.14.0"))
        XCTAssertTrue(UpdateCheck.isNewer("v1.0.0", than: "v0.14.0"))
        XCTAssertTrue(UpdateCheck.isNewer("0.14.0", than: "0.13.9"))
        XCTAssertFalse(UpdateCheck.isNewer("v0.14.0", than: "v0.14.0"))       // equal
        XCTAssertFalse(UpdateCheck.isNewer("v0.13.1", than: "0.14.0"))        // older
        XCTAssertFalse(UpdateCheck.isNewer("0.14", than: "0.14.0"))           // 0.14 == 0.14.0
        XCTAssertFalse(UpdateCheck.isNewer("0.14.0", than: "0.14"))           // symmetric
        // Pre-release suffix treated as its leading number (no spurious update).
        XCTAssertFalse(UpdateCheck.isNewer("v0.14.0-beta", than: "v0.14.0"))
    }
}
