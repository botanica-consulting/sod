#if SE_SSH_MOCK
import Foundation
import CryptoKit

/// DEVELOPMENT ONLY. A plain in-process P-256 key — same raw `r‖s` signature shape
/// as the SE backend, but **no Secure Enclave and no Touch ID**, so the whole
/// keygen/agent/SSH flow can be developed and tested without a fingerprint.
///
/// The handle file stores the actual private key bytes, so this is NOT secure.
/// It is compiled in ONLY when SE_SSH_MOCK is defined and is therefore physically
/// absent from any normal/release build.
public struct MockP256Backend: KeyBackend {
    public init() {}
    public var kind: UInt8 { HandleFile.kindMock }
    public var isMock: Bool { true }

    public func createKey() throws -> (handle: Data, publicKeyX963: Data) {
        let k = P256.Signing.PrivateKey()
        return (k.rawRepresentation, k.publicKey.x963Representation)
    }

    public func publicKey(forHandle handle: Data) throws -> Data {
        do { return try P256.Signing.PrivateKey(rawRepresentation: handle).publicKey.x963Representation } catch {
            throw KeyBackendError.load("\(error)")
        }
    }

    public func sign(handle: Data, data: Data, reason: String) throws -> Data {
        _ = reason  // no prompt in the mock
        do {
            return try P256.Signing.PrivateKey(rawRepresentation: handle).signature(for: data).rawRepresentation
        } catch { throw KeyBackendError.sign("\(error)") }
    }
}
#endif
