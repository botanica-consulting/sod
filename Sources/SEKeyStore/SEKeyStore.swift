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

/// On-disk handle file format: `MAGIC || kind(1) || handle`.
/// The handle is the backend's opaque blob (SE `dataRepresentation`, or — for the
/// mock — the plain key bytes). Contains no usable secret for the SE backend.
public enum HandleFile {
    /// Current magic, written by `encode`. Handles created before the `sod` rename
    /// used `SE-SSH-HANDLE-v1`; those are still accepted on read (see `legacyMagics`).
    public static let magic = Array("SOD-HANDLE-v1".utf8)
    static let legacyMagics: [[UInt8]] = [Array("SE-SSH-HANDLE-v1".utf8)]
    public static let kindSecureEnclave: UInt8 = 1
    public static let kindMock: UInt8 = 2

    public static func encode(kind: UInt8, handle: Data) -> Data {
        Data(magic) + Data([kind]) + handle
    }

    /// If `bytes` begins with a known magic AND has at least one more byte (the kind),
    /// return the magic length; else nil. Keeps `isHandleFile` and `decode` in agreement.
    private static func magicLength(_ bytes: [UInt8]) -> Int? {
        for m in [magic] + legacyMagics where bytes.count > m.count && Array(bytes.prefix(m.count)) == m {
            return m.count
        }
        return nil
    }

    public static func isHandleFile(_ data: Data) -> Bool {
        magicLength([UInt8](data)) != nil
    }

    public static func decode(_ data: Data) -> (kind: UInt8, handle: Data)? {
        let b = [UInt8](data)
        guard let mlen = magicLength(b) else { return nil }
        return (b[mlen], Data(b[(mlen + 1)...]))
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

    /// Single source of truth for the dev-build warning printed by the CLIs.
    public static let mockWarning =
        "WARNING built with SE_SSH_MOCK — uses a plain in-process P-256 key, NOT the Secure Enclave (development only)"
}
