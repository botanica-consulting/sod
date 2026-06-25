// swift-tools-version: 6.0
import PackageDescription

// Development builds opt into the no-Touch-ID mock backend with `SE_SSH_MOCK=1 swift build`.
// A normal build (and any release build) leaves the mock physically uncompiled.
let mock = Context.environment["SE_SSH_MOCK"] != nil
let mockSettings: [SwiftSetting] = mock ? [.define("SE_SSH_MOCK")] : []

let package = Package(
    name: "se-ssh",
    platforms: [.macOS(.v13)],
    targets: [
        // Pure SSH wire-format library — no SE/Security/CryptoKit. CI-able core.
        .target(name: "SSHWire"),

        // Secure Enclave key backend + handle-file format, behind the KeyBackend seam.
        .target(name: "SEKeyStore", swiftSettings: mockSettings),

        // keygen CLI.
        .executableTarget(
            name: "se-ssh-keygen",
            dependencies: ["SSHWire", "SEKeyStore"],
            swiftSettings: mockSettings
        ),

        // agent CLI (ssh-agent protocol over a unix socket).
        .executableTarget(
            name: "se-ssh-agent",
            dependencies: ["SSHWire", "SEKeyStore"],
            swiftSettings: mockSettings
        ),

        // se-ssh-add — DISPOSABLE client that loads keys without ssh-add's PIN prompt.
        // Backend-agnostic (just talks the agent protocol); no mock flag needed.
        .executableTarget(name: "se-ssh-add", dependencies: ["SSHWire"]),

        // M0 throwaway feasibility spike — never shipped.
        .executableTarget(name: "spike", path: "Sources/spike"),

        // Self-contained test runner. CLT has no XCTest and `swift test` can't
        // bootstrap a harness without Xcode, so tests are a plain executable with
        // no framework deps. Run: `swift run wire-tests` (works in CI too).
        .executableTarget(name: "wire-tests", dependencies: ["SSHWire"], path: "Tests/SSHWireTests"),
    ]
)
