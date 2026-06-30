import CryptoKit
import Dispatch
import Foundation
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
        guard
            let ac = SecAccessControlCreateWithFlags(
                nil,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                [.privateKeyUsage, .userPresence],
                &err
            )
        else {
            throw KeyBackendError.create(
                "SecAccessControlCreateWithFlags: \(String(describing: err?.takeRetainedValue()))")
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

    public func sign(handle: Data, data: Data, reason: String) throws -> Data {
        do {
            // Authenticate once with our own prompt text, then hand the already-authenticated
            // context to the signing operation so it doesn't prompt a second time. A fresh
            // context per call (and no reuse duration) keeps Touch ID on *every* signature. The
            // key still carries .userPresence, so this can only reuse a satisfied prompt — never
            // bypass presence.
            let context = LAContext()
            try authenticatePresence(context, reason: reason)
            let key = try SecureEnclave.P256.Signing.PrivateKey(
                dataRepresentation: handle, authenticationContext: context)
            return try key.signature(for: data).rawRepresentation
        } catch let e as KeyBackendError {
            throw e
        } catch {
            throw KeyBackendError.sign("\(error)")
        }
    }

    /// Block until Touch ID (passcode fallback) authorizes key-signing for `context`, showing
    /// `reason`. Throws on cancel/failure so a refused prompt never yields a signature.
    private func authenticatePresence(_ context: LAContext, reason: String) throws {
        let ac = try accessControl()
        let sem = DispatchSemaphore(value: 0)
        let box = AuthResultBox()
        context.evaluateAccessControl(ac, operation: .useKeySign, localizedReason: reason) { _, error in
            box.error = error
            sem.signal()
        }
        sem.wait()  // happens-after the reply, so the read below sees the stored error
        if let error = box.error { throw error }
    }
}

/// One-shot carrier for the auth reply across the (Sendable) `evaluateAccessControl` callback.
/// Safe because the `DispatchSemaphore` orders the write (in the callback) before the read.
private final class AuthResultBox: @unchecked Sendable {
    var error: Error?
}
