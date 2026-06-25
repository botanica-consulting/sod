import Foundation
import CryptoKit
import LocalAuthentication
import Security

/// Real backend: keys live in the Secure Enclave; `sign` triggers Touch ID.
/// The handle is the CryptoKit `dataRepresentation` (SEP-wrapped, device-bound,
/// reloadable across processes — no keychain access group, no entitlements).
public struct SecureEnclaveBackend: KeyBackend {
    public init() {}
    public var kind: UInt8 { HandleFile.kindSecureEnclave }
    public var isMock: Bool { false }

    private func accessControl() throws -> SecAccessControl {
        var err: Unmanaged<CFError>?
        // .privateKeyUsage is required alongside the presence flag or signing fails.
        // .userPresence = Touch ID with passcode fallback, durable across re-enrollment.
        guard let ac = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .userPresence],
            &err
        ) else {
            throw KeyBackendError.create("SecAccessControlCreateWithFlags: \(String(describing: err?.takeRetainedValue()))")
        }
        return ac
    }

    public func createKey() throws -> (handle: Data, publicKeyX963: Data) {
        guard SecureEnclave.isAvailable else {
            throw KeyBackendError.unavailable("SecureEnclave.isAvailable == false")
        }
        do {
            let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: try accessControl())
            return (key.dataRepresentation, key.publicKey.x963Representation)
        } catch let e as KeyBackendError {
            throw e
        } catch {
            throw KeyBackendError.create("\(error)")
        }
    }

    public func publicKey(forHandle handle: Data) throws -> Data {
        do {
            let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: handle)
            return key.publicKey.x963Representation
        } catch {
            throw KeyBackendError.load("\(error)")
        }
    }

    public func sign(handle: Data, data: Data) throws -> Data {
        do {
            let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: handle)
            return try key.signature(for: data).rawRepresentation   // Touch ID fires here
        } catch {
            throw KeyBackendError.sign("\(error)")
        }
    }
}
