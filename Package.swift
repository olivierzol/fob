// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "fob",
    platforms: [.macOS(.v13)],
    targets: [
        .executableTarget(name: "fob", path: "Sources/fob")
    ]
)
