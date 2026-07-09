// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "fob",
    platforms: [.macOS(.v13)],
    targets: [
        .target(name: "FobKit", path: "Sources/FobKit"),
        .executableTarget(name: "fob", dependencies: ["FobKit"], path: "Sources/fob"),
        .executableTarget(name: "FobApp", dependencies: ["FobKit"], path: "Sources/FobApp"),
    ]
)
