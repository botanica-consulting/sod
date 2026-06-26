#if SE_SSH_MOCK
import CryptoKit
import Foundation
import SEKeyStore
import SodKit
import SSHWire

/// Drives the agent's request handler directly with the mock backend — covers
/// add/identities/sign/remove/remove-all without a socket, sshd, or Touch ID.
func runAgentSuite(_ h: Harness) {
    let dir = h.tempDir()
    let backend = MockP256Backend()
    let created = try! backend.createKey()
    let keyPath = dir + "/id"
    try! HandleFile.encode(kind: backend.kind, handle: created.handle).write(to: URL(fileURLWithPath: keyPath))
    let pubLine = SSHWire.ecdsaP256PublicKeyLine(x963: created.publicKeyX963, comment: "k@test") + "\n"
    try! Data(pubLine.utf8).write(to: URL(fileURLWithPath: keyPath + ".pub"))
    let expectedBlob = SSHWire.ecdsaP256PublicKeyBlob(x963: created.publicKeyX963)

    let state = AgentState(backend: backend)

    // Empty agent: identities answer with zero keys.
    do {
        let (t, p) = try SSHWire.splitFramed(
            handleRequest(type: SSHWire.Agent.requestIdentities, payload: Data(), state: state))
        h.eq(t, SSHWire.Agent.identitiesAnswer, "identities answer type (empty)")
        var r = ByteReader(p)
        h.eq(try r.readUInt32(), 0, "no identities before load")
    } catch { h.fail("empty-identities threw \(error)") }

    // add-smartcard: success on a real handle, failure on a bogus path.
    h.eqFramed(
        handleRequest(
            type: SSHWire.Agent.addSmartcardKey,
            payload: SSHWire.string(keyPath) + SSHWire.string(""), state: state),
        type: SSHWire.Agent.success, "add-smartcard loads a handle")
    h.eqFramed(
        handleRequest(
            type: SSHWire.Agent.addSmartcardKey,
            payload: SSHWire.string(dir + "/nope") + SSHWire.string(""), state: state),
        type: SSHWire.Agent.failure, "add-smartcard rejects non-handle")

    // request-identities: our one key, blob + comment match.
    do {
        let (t, p) = try SSHWire.splitFramed(
            handleRequest(type: SSHWire.Agent.requestIdentities, payload: Data(), state: state))
        h.eq(t, SSHWire.Agent.identitiesAnswer, "identities answer type")
        var r = ByteReader(p)
        h.eq(try r.readUInt32(), 1, "identities count == 1")
        h.eqData(try r.readString(), expectedBlob, "identity blob matches mock key")
        h.eq(String(decoding: try r.readString(), as: UTF8.self), "k@test", "identity comment from .pub")
    } catch { h.fail("identities threw \(error)") }

    // sign: the response verifies against the mock public key (mock signs, no Touch ID).
    let msg = Data("ssh signing payload".utf8)
    let signReq = SSHWire.string(expectedBlob) + SSHWire.string(msg) + SSHWire.uint32(0)
    do {
        let (st, sp) = try SSHWire.splitFramed(
            handleRequest(type: SSHWire.Agent.signRequest, payload: signReq, state: state))
        h.eq(st, SSHWire.Agent.signResponse, "sign response type")
        var rr = ByteReader(sp)
        let (rRaw, sRaw) = try SSHWire.parseEcdsaP256SignatureBlob(try rr.readString())
        let pub = try P256.Signing.PublicKey(x963Representation: created.publicKeyX963)
        let sig = try P256.Signing.ECDSASignature(rawRepresentation: h.leftPad32(rRaw) + h.leftPad32(sRaw))
        h.ok(pub.isValidSignature(sig, for: msg), "agent signature verifies against mock pubkey")
    } catch { h.fail("sign threw \(error)") }

    // sign with an unknown key blob -> FAILURE.
    let bad = SSHWire.string(Data([0, 1, 2])) + SSHWire.string(msg) + SSHWire.uint32(0)
    h.eqFramed(
        handleRequest(type: SSHWire.Agent.signRequest, payload: bad, state: state),
        type: SSHWire.Agent.failure, "sign unknown key -> failure")

    // remove-smartcard: success, then already-removed -> failure.
    h.eqFramed(
        handleRequest(
            type: SSHWire.Agent.removeSmartcardKey,
            payload: SSHWire.string(keyPath) + SSHWire.string(""), state: state),
        type: SSHWire.Agent.success, "remove-smartcard unloads")
    h.eqFramed(
        handleRequest(
            type: SSHWire.Agent.removeSmartcardKey,
            payload: SSHWire.string(keyPath) + SSHWire.string(""), state: state),
        type: SSHWire.Agent.failure, "remove of unloaded -> failure")

    // remove-all (-D): load again, clear, confirm zero identities.
    state.add(keyPath)
    h.eqFramed(
        handleRequest(type: SSHWire.Agent.removeAllIdentities, payload: Data(), state: state),
        type: SSHWire.Agent.success, "remove-all succeeds")
    do {
        let (_, p) = try SSHWire.splitFramed(
            handleRequest(type: SSHWire.Agent.requestIdentities, payload: Data(), state: state))
        var r = ByteReader(p)
        h.eq(try r.readUInt32(), 0, "no identities after remove-all")
    } catch { h.fail("identities-after-removeall threw \(error)") }
}
#endif
