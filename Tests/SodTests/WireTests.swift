import CryptoKit  // test-only: produce real ECDSA vectors; SSHWire itself imports none of this
import Foundation
import SSHWire

// Vector captured 2026-06-25 from `ssh-keygen -t ecdsa -b 256 -C vector@m0`.
private let realPubBlobB64 =
    "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLrfTOpAMyG7gBdNExBavhwNXAx/Sd1W4A1lreztfwY37vHS7yZuOQXeXsDl8GRtUSk4jCPPdjUqd3fND4IxzGk="

extension Harness {
    /// The pure SSHWire suite (no Secure Enclave / Touch ID); always runs.
    func runWireSuite() {
        runPrimitives()
        runByteReader()
        do { try runPubKey() } catch { fail("pubkey section threw \(error)") }
        do { try runSignature() } catch { fail("signature section threw \(error)") }
        do { try runFraming() } catch { fail("framing section threw \(error)") }
        runParseRequests()
    }

    func runPrimitives() {
        eqData(SSHWire.uint32(0x0102_0304), Data([1, 2, 3, 4]), "uint32 big-endian")
        eqData(SSHWire.uint32(0), Data([0, 0, 0, 0]), "uint32 zero")
        eqData(SSHWire.uint32(.max), Data([0xff, 0xff, 0xff, 0xff]), "uint32 max")

        eqData(SSHWire.string(Data([0xaa, 0xbb])), Data([0, 0, 0, 2, 0xaa, 0xbb]), "string bytes")
        eqData(SSHWire.string("abc"), Data([0, 0, 0, 3, 0x61, 0x62, 0x63]), "string utf8")
        eqData(SSHWire.string(Data()), Data([0, 0, 0, 0]), "string empty")

        // mpint — the classic ECDSA-over-ssh-agent bug (RFC 4251 §5).
        eqData(SSHWire.mpint(Data([])), Data([0, 0, 0, 0]), "mpint zero")
        eqData(SSHWire.mpint(Data([0x00, 0x00])), Data([0, 0, 0, 0]), "mpint all-zero")
        eqData(SSHWire.mpint(Data([0x80])), Data([0, 0, 0, 2, 0x00, 0x80]), "mpint high-bit pad")
        eqData(SSHWire.mpint(Data([0x7f])), Data([0, 0, 0, 1, 0x7f]), "mpint no pad")
        eqData(SSHWire.mpint(Data([0x01, 0x02, 0x03, 0x04])), Data([0, 0, 0, 4, 1, 2, 3, 4]), "mpint plain")
        eqData(SSHWire.mpint(Data([0x00, 0x80, 0x01])), Data([0, 0, 0, 3, 0x00, 0x80, 0x01]), "mpint strip-then-pad")
        eqData(SSHWire.mpint(Data([0x00, 0x7f, 0x01])), Data([0, 0, 0, 2, 0x7f, 0x01]), "mpint strip-no-pad")
    }

    func runByteReader() {
        do {
            var r = ByteReader(SSHWire.uint32(42) + SSHWire.string("hi"))
            eq(try r.readUInt32(), 42, "reader uint32")
            eq(String(decoding: try r.readString(), as: UTF8.self), "hi", "reader string")
            ok(r.isAtEnd, "reader at end")
        } catch { fail("byte reader round-trip threw \(error)") }

        throwsErr("reader truncated uint32") {
            var r = ByteReader(Data([0, 0, 0])); _ = try r.readUInt32()
        }
        throwsErr("reader truncated string") {
            var r = ByteReader(Data([0, 0, 0, 5, 1, 2])); _ = try r.readString()
        }
    }

    func runPubKey() throws {
        let blob = Data(base64Encoded: realPubBlobB64)!
        let (curve, q) = try SSHWire.parseEcdsaP256PublicKeyBlob(blob)
        eq(curve, "nistp256", "pub curve")
        eq(q.count, 65, "pub Q length")
        eq(q.first, 0x04, "pub Q uncompressed marker")
        eqData(SSHWire.ecdsaP256PublicKeyBlob(x963: q), blob, "pub blob rebuild matches ssh-keygen")
        eq(
            SSHWire.ecdsaP256PublicKeyLine(x963: q, comment: "vector@m0"),
            "ecdsa-sha2-nistp256 \(realPubBlobB64) vector@m0", "pub line matches ssh-keygen")
        eq(
            SSHWire.ecdsaP256PublicKeyLine(x963: q, comment: ""),
            "ecdsa-sha2-nistp256 \(realPubBlobB64)", "pub line no comment")
    }

    func leftPad32(_ mpintContent: Data) -> Data {
        var b = [UInt8](mpintContent)
        while b.count > 32, b.first == 0x00 { b.removeFirst() }  // drop mpint sign pad
        while b.count < 32 { b.insert(0x00, at: 0) }  // left-pad to fixed width
        return Data(b)
    }

    func runSignature() throws {
        let key = P256.Signing.PrivateKey()  // plain P-256: same raw r‖s as the SE key, no Touch ID
        for i in 0..<64 {  // exercise high-bit / short r,s cases
            let msg = Data("message number \(i) for ecdsa sig encoding".utf8)
            let sig = try key.signature(for: msg)
            eq(sig.rawRepresentation.count, 64, "raw sig 64B (iter \(i))")

            let sblob = try SSHWire.ecdsaP256SignatureBlob(rawRS: sig.rawRepresentation)
            var outer = ByteReader(sblob)
            eq(String(decoding: try outer.readString(), as: UTF8.self), "ecdsa-sha2-nistp256", "sig type (iter \(i))")

            let (r, s) = try SSHWire.parseEcdsaP256SignatureBlob(sblob)
            let recon = try P256.Signing.ECDSASignature(rawRepresentation: leftPad32(r) + leftPad32(s))
            ok(key.publicKey.isValidSignature(recon, for: msg), "sig encode round-trips & verifies (iter \(i))")
        }
        throwsErr("sig rejects wrong length") {
            _ = try SSHWire.ecdsaP256SignatureBlob(rawRS: Data(repeating: 0, count: 63))
        }
    }

    func runFraming() throws {
        let ids = [
            SSHWire.AgentIdentity(keyBlob: Data([1, 2, 3]), comment: "alpha"),
            SSHWire.AgentIdentity(keyBlob: Data([9, 8]), comment: "beta"),
        ]
        let (t12, p12) = try SSHWire.splitFramed(SSHWire.identitiesAnswer(ids))
        eq(t12, UInt8(12), "identities answer type")
        var r = ByteReader(p12)
        eq(try r.readUInt32(), 2, "identities count")
        eqData(try r.readString(), Data([1, 2, 3]), "identity 0 blob")
        eq(String(decoding: try r.readString(), as: UTF8.self), "alpha", "identity 0 comment")
        eqData(try r.readString(), Data([9, 8]), "identity 1 blob")
        eq(String(decoding: try r.readString(), as: UTF8.self), "beta", "identity 1 comment")
        ok(r.isAtEnd, "identities fully consumed")

        let (t14, p14) = try SSHWire.splitFramed(SSHWire.signResponse(signatureBlob: Data([0xde, 0xad])))
        eq(t14, UInt8(14), "sign response type")
        var r14 = ByteReader(p14)
        eqData(try r14.readString(), Data([0xde, 0xad]), "sign response payload")

        let (t5, p5) = try SSHWire.splitFramed(SSHWire.failure())
        eq(t5, UInt8(5), "failure type")
        ok(p5.isEmpty, "failure empty payload")

        let (t6, p6) = try SSHWire.splitFramed(SSHWire.success())
        eq(t6, UInt8(6), "success type")
        ok(p6.isEmpty, "success empty payload")
    }

    func runParseRequests() {
        eq(SSHWire.parseRequest(type: 11, payload: Data()), .requestIdentities, "parse request-identities")
        eq(SSHWire.parseRequest(type: 9, payload: Data()), .removeAllIdentities, "parse remove-all (-D)")

        let signReq = SSHWire.string(Data([0xaa])) + SSHWire.string(Data([0xbb, 0xcc])) + SSHWire.uint32(0)
        eq(
            SSHWire.parseRequest(type: 13, payload: signReq),
            .signRequest(keyBlob: Data([0xaa]), data: Data([0xbb, 0xcc]), flags: 0), "parse sign-request")

        eq(SSHWire.parseRequest(type: 99, payload: Data()), .unsupported(type: 99), "parse unknown -> unsupported")
        eq(
            SSHWire.parseRequest(type: 13, payload: Data([0, 0, 0, 5, 1, 2])),
            .unsupported(type: 13), "parse malformed sign -> unsupported")

        // smartcard messages (ssh-add -s / -e); provider reinterpreted as an SE handle path,
        // PIN field parsed-and-discarded
        let add = SSHWire.string("/path/to/key") + SSHWire.string("")
        eq(
            SSHWire.parseRequest(type: 20, payload: add),
            .addSmartcardKey(provider: "/path/to/key"), "parse add-smartcard (-s)")
        // pin + trailing constraints are parsed and ignored
        let addc = SSHWire.string("/p") + SSHWire.string("pin") + Data([0, 0, 0, 0])
        eq(
            SSHWire.parseRequest(type: 26, payload: addc),
            .addSmartcardKey(provider: "/p"), "parse add-smartcard-constrained")
        let rem = SSHWire.string("/path/to/key") + SSHWire.string("")
        eq(
            SSHWire.parseRequest(type: 21, payload: rem),
            .removeSmartcardKey(provider: "/path/to/key"), "parse remove-smartcard (-e)")
    }
}
