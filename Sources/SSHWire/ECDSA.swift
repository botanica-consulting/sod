import Foundation

extension SSHWire {
    public static let ecdsaP256KeyType = "ecdsa-sha2-nistp256"
    public static let ecdsaP256CurveName = "nistp256"

    /// Public-key blob (RFC 5656 §3.1):
    /// `string(keytype) || string(curve) || string(Q)`, Q = 65-byte x9.63 `0x04‖X‖Y`.
    public static func ecdsaP256PublicKeyBlob(x963 q: Data) -> Data {
        string(ecdsaP256KeyType) + string(ecdsaP256CurveName) + string(q)
    }

    /// OpenSSH `.pub` / authorized_keys line: `ecdsa-sha2-nistp256 <base64-blob> [comment]`.
    public static func ecdsaP256PublicKeyLine(x963 q: Data, comment: String) -> String {
        let blob = ecdsaP256PublicKeyBlob(x963: q)
        let base = "\(ecdsaP256KeyType) \(blob.base64EncodedString())"
        return comment.isEmpty ? base : "\(base) \(comment)"
    }

    /// Signature blob (RFC 5656 §3.1.2) from raw 64-byte `r‖s`:
    /// `string(keytype) || string( mpint r || mpint s )`.
    public static func ecdsaP256SignatureBlob(rawRS: Data) throws -> Data {
        guard rawRS.count == 64 else {
            throw WireError.malformed("expected 64-byte raw r||s, got \(rawRS.count)")
        }
        let r = Data(rawRS.prefix(32))
        let s = Data(rawRS.suffix(32))
        let inner = mpint(r) + mpint(s)
        return string(ecdsaP256KeyType) + string(inner)
    }

    /// Parse a public-key blob to `(curve, Q)`. (Used by tests; the agent matches
    /// key blobs by byte-equality and does not need to parse.)
    public static func parseEcdsaP256PublicKeyBlob(_ blob: Data) throws -> (curve: String, q: Data) {
        var r = ByteReader(blob)
        let keyType = try r.readString()
        guard String(decoding: keyType, as: UTF8.self) == ecdsaP256KeyType else {
            throw WireError.malformed("not an ecdsa-sha2-nistp256 public key")
        }
        let curve = try r.readString()
        let q = try r.readString()
        return (String(decoding: curve, as: UTF8.self), q)
    }

    /// Parse a signature blob to the raw `(r, s)` mpint contents. (Tests.)
    public static func parseEcdsaP256SignatureBlob(_ blob: Data) throws -> (r: Data, s: Data) {
        var outer = ByteReader(blob)
        let keyType = try outer.readString()
        guard String(decoding: keyType, as: UTF8.self) == ecdsaP256KeyType else {
            throw WireError.malformed("not an ecdsa-sha2-nistp256 signature")
        }
        let inner = try outer.readString()
        var ir = ByteReader(inner)
        let r = try ir.readString()
        let s = try ir.readString()
        return (r, s)
    }
}
