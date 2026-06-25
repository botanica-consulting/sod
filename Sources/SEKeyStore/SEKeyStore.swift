import Foundation

/// Errors from a key backend, with human-readable messages for CLI stderr.
public enum KeyBackendError: Error, CustomStringConvertible {
    case unavailable(String)
    case create(String)
    case load(String)
    case sign(String)

    public var description: String {
        switch self {
        case .unavailable(let m): return "secure enclave unavailable: \(m)"
        case .create(let m): return "key creation failed: \(m)"
        case .load(let m): return "key load failed: \(m)"
        case .sign(let m): return "signing failed: \(m)"
        }
    }
}

/// The seam between the wire/agent code and the actual key material. The real
/// conformer talks to the Secure Enclave (Touch ID on `sign`); the mock uses a
/// plain in-process P-256 key (no SE, no Touch ID) for development and tests.
public protocol KeyBackend {
    /// 1 = Secure Enclave, 2 = mock. Stored in the handle file so an agent only
    /// serves handles its own backend can use.
    var kind: UInt8 { get }
    var isMock: Bool { get }

    /// Create a new key. Returns the opaque handle to persist + the public key
    /// (x9.63, 65-byte `0x04‖X‖Y`). Never prompts.
    func createKey() throws -> (handle: Data, publicKeyX963: Data)

    /// Public key (x9.63) for a stored handle. Never prompts.
    func publicKey(forHandle handle: Data) throws -> Data

    /// Sign `data`, returning raw 64-byte `r‖s`. The real backend triggers Touch ID.
    func sign(handle: Data, data: Data) throws -> Data
}

/// On-disk handle file format: `MAGIC(16) || kind(1) || handle`.
/// The handle is the backend's opaque blob (SE `dataRepresentation`, or — for the
/// mock — the plain key bytes). Contains no usable secret for the SE backend.
public enum HandleFile {
    public static let magic = Array("SE-SSH-HANDLE-v1".utf8)   // 16 bytes
    public static let kindSecureEnclave: UInt8 = 1
    public static let kindMock: UInt8 = 2

    public static func encode(kind: UInt8, handle: Data) -> Data {
        Data(magic) + Data([kind]) + handle
    }

    public static func isHandleFile(_ data: Data) -> Bool {
        let b = [UInt8](data)
        return b.count >= magic.count && Array(b.prefix(magic.count)) == magic
    }

    public static func decode(_ data: Data) -> (kind: UInt8, handle: Data)? {
        let b = [UInt8](data)
        guard b.count > magic.count, Array(b.prefix(magic.count)) == magic else { return nil }
        return (b[magic.count], Data(b[(magic.count + 1)...]))
    }
}

/// Expand a leading `~` against the real home directory (in-process, defensively).
public func expandTilde(_ path: String) -> String {
    if path == "~" { return NSHomeDirectory() }
    if path.hasPrefix("~/") { return NSHomeDirectory() + String(path.dropFirst(1)) }
    return path
}

/// Build-time backend selection. The mock is compiled in ONLY when SE_SSH_MOCK is
/// defined (gated on an env var in Package.swift), so a normal build cannot use it.
public enum Backends {
    public static func active() -> KeyBackend {
        #if SE_SSH_MOCK
        return MockP256Backend()
        #else
        return SecureEnclaveBackend()
        #endif
    }

    public static var isMock: Bool {
        #if SE_SSH_MOCK
        return true
        #else
        return false
        #endif
    }
}
