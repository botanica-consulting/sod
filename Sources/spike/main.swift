// M0 feasibility spike (throwaway). Answers the load-bearing question:
// can an AD-HOC-signed CLI create a presence-gated Secure Enclave key and
// sign behind a real Touch ID prompt, with the blob reloadable across processes?
//
// Subcommands (run as separate process invocations to prove cross-process reload):
//   gen-noacl <blob>   0a: create no-ACL SE key, persist blob               (no prompt)
//   sign-noacl <blob>  0a: reload blob in a 2nd process, sign               (no prompt)
//   inproc-acl         0b: create .userPresence key + sign in one process   (TOUCH ID)
//   gen-acl <blob>     0c: create .userPresence key, persist blob           (no prompt)
//   sign-acl <blob>    0c: reload .userPresence key in a 2nd process, sign  (TOUCH ID)

import Foundation
import CryptoKit
import LocalAuthentication
import Security

func elog(_ msg: String) {
    FileHandle.standardError.write(Data((msg + "\n").utf8))
}

func makeAccessControl() throws -> SecAccessControl {
    var err: Unmanaged<CFError>?
    guard let ac = SecAccessControlCreateWithFlags(
        nil,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        [.privateKeyUsage, .userPresence],   // .privateKeyUsage is required or signing fails opaquely
        &err
    ) else {
        throw NSError(domain: "spike", code: 1, userInfo: [
            NSLocalizedDescriptionKey: "SecAccessControlCreateWithFlags failed: \(err!.takeRetainedValue())"
        ])
    }
    return ac
}

let args = CommandLine.arguments
let cmd = args.count >= 2 ? args[1] : ""
let blobPath = args.count >= 3 ? args[2] : "/tmp/se-spike.blob"
let message = Data("hello secure enclave".utf8)

guard SecureEnclave.isAvailable else {
    elog("SPIKE FAILED: SecureEnclave.isAvailable == false")
    exit(1)
}

do {
    switch cmd {
    case "gen-noacl":
        let key = try SecureEnclave.P256.Signing.PrivateKey()
        try key.dataRepresentation.write(to: URL(fileURLWithPath: blobPath))
        elog("0a OK: created no-ACL SE key; pub=\(key.publicKey.x963Representation.count)B blob=\(key.dataRepresentation.count)B -> \(blobPath)")

    case "sign-noacl":
        let blob = try Data(contentsOf: URL(fileURLWithPath: blobPath))
        let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob)
        let sig = try key.signature(for: message)
        elog("0a OK: reloaded blob in 2nd process & signed (no prompt); valid=\(key.publicKey.isValidSignature(sig, for: message)) sig=\(sig.rawRepresentation.count)B")

    case "inproc-acl":
        let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: try makeAccessControl())
        elog("0b: created .userPresence key (no prompt at create). Signing now — TOUCH ID SHOULD PROMPT...")
        let sig = try key.signature(for: message)
        elog("0b OK: signed behind Touch ID; valid=\(key.publicKey.isValidSignature(sig, for: message))")

    case "gen-acl":
        let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: try makeAccessControl())
        try key.dataRepresentation.write(to: URL(fileURLWithPath: blobPath))
        elog("0c: created .userPresence key (no prompt at create) -> \(blobPath)")

    case "sign-acl":
        let blob = try Data(contentsOf: URL(fileURLWithPath: blobPath))
        let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob)
        elog("0c: reloaded .userPresence key in a separate process. Signing now — TOUCH ID SHOULD PROMPT...")
        let sig = try key.signature(for: message)
        elog("0c OK: cold-reload signed behind Touch ID; valid=\(key.publicKey.isValidSignature(sig, for: message))")

    default:
        elog("usage: spike <gen-noacl|sign-noacl|inproc-acl|gen-acl|sign-acl> [blobpath]")
        exit(2)
    }
} catch {
    elog("SPIKE FAILED [\(cmd)]: \(error)")
    exit(1)
}
