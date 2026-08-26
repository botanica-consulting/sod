import CryptoKit
import Foundation

/// The OpenSSH fingerprint of a public-key blob: `SHA256:` + unpadded base64 of the digest —
/// byte-for-byte what `ssh-keygen -l` prints. Shared by `sd ssh-keygen` and `sd ssh-add -l`.
public func sshKeyFingerprint(_ blob: Data) -> String {
    "SHA256:" + Data(SHA256.hash(data: blob)).base64EncodedString().replacingOccurrences(of: "=", with: "")
}
