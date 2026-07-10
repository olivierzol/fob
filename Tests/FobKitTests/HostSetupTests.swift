import XCTest

@testable import FobKit

final class HostSetupTests: XCTestCase {
    func testConfigBlockOmitsDefaultPort() {
        let block = HostSetup.configBlock(alias: "web", host: "h.example", user: "u",
                                          pubPath: "/p.pub", socketPath: "/s.sock")
        XCTAssertTrue(block.contains("Host web"))
        XCTAssertTrue(block.contains("HostName h.example"))
        XCTAssertTrue(block.contains("IdentityFile /p.pub"))
        XCTAssertTrue(block.contains("IdentitiesOnly yes"))
        XCTAssertFalse(block.contains("Port"), "port 22 should not add a Port line")
    }

    func testConfigBlockIncludesCustomPort() {
        let block = HostSetup.configBlock(alias: "web", host: "h", user: "u", port: 2222,
                                          pubPath: "/p", socketPath: "/s")
        XCTAssertTrue(block.contains("\n  Port 2222\n"))
    }

    func testHostBlockExists() {
        let config = "Host prod alias2\n  HostName x\n\nHost other\n  HostName y\n"
        XCTAssertTrue(HostSetup.hostBlockExists(alias: "prod", in: config))
        XCTAssertTrue(HostSetup.hostBlockExists(alias: "alias2", in: config))
        XCTAssertFalse(HostSetup.hostBlockExists(alias: "missing", in: config))
    }

    // Regression: a host on a non-default port is stored as [host]:port, and a
    // port-less pin lookup must still find it (the host key is port-independent).
    func testKnownHostsCustomPortMatching() {
        let kh = """
        192.168.1.9 ssh-ed25519 QUFB
        [192.168.64.64]:1221 ssh-ed25519 QkJC
        [192.168.64.64]:1221 ecdsa-sha2-nistp256 Q0ND
        """
        func blobs(_ host: String, _ port: Int?) -> [Data] {
            HostResolver.hostKeys(inKnownHosts: kh, host: host, port: port)
        }
        // Port unknown → matches the host on its actual port (both key types).
        XCTAssertEqual(blobs("192.168.64.64", nil).count, 2)
        // Exact port matches.
        XCTAssertEqual(blobs("192.168.64.64", 1221).count, 2)
        // Wrong / default port does not match a non-default-port host.
        XCTAssertTrue(blobs("192.168.64.64", 22).isEmpty)
        // A plain (port-22) host still matches with nil and with 22.
        XCTAssertEqual(blobs("192.168.1.9", nil).count, 1)
        XCTAssertEqual(blobs("192.168.1.9", 22).count, 1)
    }

    func testValidHostToken() {
        XCTAssertTrue(HostSetup.isValidHostToken("example.com"))
        XCTAssertTrue(HostSetup.isValidHostToken("10.0.0.1"))
        XCTAssertFalse(HostSetup.isValidHostToken("-oProxyCommand=x")) // would be an ssh option
        XCTAssertFalse(HostSetup.isValidHostToken("has space"))
        XCTAssertFalse(HostSetup.isValidHostToken(""))
    }
}
