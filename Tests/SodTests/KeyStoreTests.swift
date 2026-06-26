#if SE_SSH_MOCK
import Foundation
import SEKeyStore
import SSHWire

/// HandleFile codec + HandleScanner. Mock-gated: uses MockP256Backend, no SE/Touch ID.
func runKeyStoreSuite(_ h: Harness) {
    // HandleFile encode/decode round-trip for both kinds.
    for kind in [HandleFile.kindSecureEnclave, HandleFile.kindMock] {
        let handle = Data((0..<40).map { UInt8($0 & 0xff) })
        let file = HandleFile.encode(kind: kind, handle: handle)
        h.ok(HandleFile.isHandleFile(file), "isHandleFile accepts encoded (kind \(kind))")
        if let dec = HandleFile.decode(file) {
            h.eq(dec.kind, kind, "decoded kind (kind \(kind))")
            h.eqData(dec.handle, handle, "decoded handle (kind \(kind))")
        } else {
            h.fail("decode returned nil (kind \(kind))")
        }
    }

    // Reject foreign / magic-only / a real pubkey line.
    h.ok(!HandleFile.isHandleFile(Data("not a handle".utf8)), "isHandleFile rejects foreign")
    h.ok(!HandleFile.isHandleFile(Data(HandleFile.magic)), "isHandleFile rejects magic-only (no kind byte)")
    h.ok(HandleFile.decode(Data("ssh-ed25519 AAAAC3Nza...".utf8)) == nil, "decode rejects a real pubkey line")

    // Legacy magic (pre-rename SE-SSH-HANDLE-v1) is still accepted on read.
    let legacy = Data(Array("SE-SSH-HANDLE-v1".utf8)) + Data([HandleFile.kindSecureEnclave]) + Data([1, 2, 3, 4])
    h.ok(HandleFile.isHandleFile(legacy), "isHandleFile accepts legacy magic")
    if let dec = HandleFile.decode(legacy) {
        h.eq(dec.kind, HandleFile.kindSecureEnclave, "legacy decoded kind")
        h.eqData(dec.handle, Data([1, 2, 3, 4]), "legacy decoded handle")
    } else {
        h.fail("legacy decode returned nil")
    }

    // HandleScanner: write a mock key + .pub, resolve by file and by directory.
    let dir = h.tempDir()
    let mock = MockP256Backend()
    let created = try! mock.createKey()
    let keyPath = dir + "/id"
    try! HandleFile.encode(kind: mock.kind, handle: created.handle).write(to: URL(fileURLWithPath: keyPath))
    let line = SSHWire.ecdsaP256PublicKeyLine(x963: created.publicKeyX963, comment: "alice@host") + "\n"
    try! Data(line.utf8).write(to: URL(fileURLWithPath: keyPath + ".pub"))

    let byFile = HandleScanner.resolve(provider: keyPath, kind: mock.kind)
    h.eq(byFile.count, 1, "resolve file -> 1 handle")
    h.eq(byFile.first?.comment ?? "", "alice@host", "comment from .pub 3rd field")
    h.eq(HandleScanner.resolve(provider: dir, kind: mock.kind).count, 1, "resolve dir -> 1 handle")
    // Kind mismatch -> nothing (an SE agent must not serve mock handles, and vice-versa).
    h.eq(
        HandleScanner.resolve(provider: keyPath, kind: HandleFile.kindSecureEnclave).count, 0,
        "resolve filters by kind")
}
#endif
