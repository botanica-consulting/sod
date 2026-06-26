// swift-tools-version: 6.0
import PackageDescription

// Development builds opt into the no-Touch-ID mock backend with `SE_SSH_MOCK=1 swift build`.
// A normal build (and any release build) leaves the mock physically uncompiled.
let mock = Context.environment["SE_SSH_MOCK"] != nil
let mockSettings: [SwiftSetting] = mock ? [.define("SE_SSH_MOCK")] : []

let package = Package(
    name: "sod",
    platforms: [.macOS(.v13)],
    products: [
        // The single shipped binary: `sod <subcommand>`.
        .executable(name: "sod", targets: ["sod"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser", from: "1.3.0"),
    ],
    targets: [
        // Pure SSH wire-format library — no SE/Security/CryptoKit. CI-able core.
        .target(name: "SSHWire"),

        // Secure Enclave key backend + handle-file format, behind the KeyBackend seam.
        .target(name: "SEKeyStore", swiftSettings: mockSettings),

        // Fat library: keygen/agent/add command implementations as testable code.
        .target(
            name: "SodKit",
            dependencies: [
                "SSHWire", "SEKeyStore",
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ],
            swiftSettings: mockSettings
        ),

        // Thin executable: @main + subcommand dispatch only.
        .executableTarget(
            name: "sod",
            dependencies: [
                "SodKit",
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ],
            swiftSettings: mockSettings
        ),

        // Self-contained test runner. CLT has no XCTest and `swift test` can't
        // bootstrap a harness without Xcode, so tests are a plain executable with
        // no framework deps. Run: `SE_SSH_MOCK=1 swift run sod-tests`.
        // Built WITH the mock so it can exercise the agent handlers without a real SE.
        .executableTarget(
            name: "sod-tests",
            dependencies: ["SodKit", "SEKeyStore", "SSHWire"],
            path: "Tests/SodTests",
            swiftSettings: mockSettings
        ),
    ]
)
