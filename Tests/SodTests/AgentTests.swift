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

    // ---- agent forwarding (session-bind is_forwarding) ----
    // A session-bind extension body with the given forwarding flag (host key + ids are dummies).
    func bind(_ forwarding: UInt8) -> Data {
        SSHWire.string("session-bind@openssh.com") + SSHWire.string(Data([0xab]))  // hostkey
            + SSHWire.string(Data([0x01])) + SSHWire.string(Data([0x02]))  // session id, signature
            + Data([forwarding])
    }
    let goodSign = SSHWire.string(expectedBlob) + SSHWire.string(msg) + SSHWire.uint32(0)

    // Default policy refuses forwarding. A non-forwarded connection (bind fwd=0) behaves normally.
    let refusing = AgentState(backend: backend)
    refusing.add(keyPath)
    let local = AgentConnection()
    h.eqFramed(
        handleRequest(type: SSHWire.Agent.extensionRequest, payload: bind(0), state: refusing, conn: local),
        type: SSHWire.Agent.success, "session-bind (local) acks")
    h.eqFramed(
        handleRequest(type: SSHWire.Agent.signRequest, payload: goodSign, state: refusing, conn: local),
        type: SSHWire.Agent.signResponse, "local (fwd=0) connection signs")

    // A forwarded connection (bind fwd=1) refuses to sign / add, and lists no identities.
    let fwd = AgentConnection()
    h.eqFramed(
        handleRequest(type: SSHWire.Agent.extensionRequest, payload: bind(1), state: refusing, conn: fwd),
        type: SSHWire.Agent.success, "session-bind (forwarded) acks")
    h.eqFramed(
        handleRequest(type: SSHWire.Agent.signRequest, payload: goodSign, state: refusing, conn: fwd),
        type: SSHWire.Agent.failure, "forwarded connection refuses to sign")
    h.eqFramed(
        handleRequest(
            type: SSHWire.Agent.addSmartcardKey,
            payload: SSHWire.string(keyPath) + SSHWire.string(""), state: refusing, conn: fwd),
        type: SSHWire.Agent.failure, "forwarded connection refuses add")
    do {
        let (t, p) = try SSHWire.splitFramed(
            handleRequest(type: SSHWire.Agent.requestIdentities, payload: Data(), state: refusing, conn: fwd))
        h.eq(t, SSHWire.Agent.identitiesAnswer, "forwarded identities answer type")
        var r = ByteReader(p)
        h.eq(try r.readUInt32(), 0, "forwarded connection presents no identities")
    } catch { h.fail("forwarded-identities threw \(error)") }

    // Downgrade defense: the real forwarded flow is bind(fwd=1) THEN bind(fwd=0) (the remote's
    // own user-auth, or a malicious remote injecting it). The forwarding latch must hold, so the
    // sign is still refused.
    let downgrade = AgentConnection()
    _ = handleRequest(type: SSHWire.Agent.extensionRequest, payload: bind(1), state: refusing, conn: downgrade)
    _ = handleRequest(type: SSHWire.Agent.extensionRequest, payload: bind(0), state: refusing, conn: downgrade)
    h.eqFramed(
        handleRequest(type: SSHWire.Agent.signRequest, payload: goodSign, state: refusing, conn: downgrade),
        type: SSHWire.Agent.failure, "forwarding latch: bind(1) then bind(0) still refuses to sign")

    // Opt-in: with forwarding allowed, the same forwarded connection signs.
    let allowing = AgentState(backend: backend, refuseForwarding: false)
    allowing.add(keyPath)
    let fwdAllowed = AgentConnection()
    h.eqFramed(
        handleRequest(type: SSHWire.Agent.extensionRequest, payload: bind(1), state: allowing, conn: fwdAllowed),
        type: SSHWire.Agent.success, "session-bind (forwarded, allowed) acks")
    h.eqFramed(
        handleRequest(type: SSHWire.Agent.signRequest, payload: goodSign, state: allowing, conn: fwdAllowed),
        type: SSHWire.Agent.signResponse, "allowed forwarding signs")
}
#endif
