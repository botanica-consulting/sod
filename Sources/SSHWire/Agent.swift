import Foundation

extension SSHWire {
    /// ssh-agent protocol message numbers (RFC 9987 / OpenSSH PROTOCOL.agent).
    public enum Agent {
        public static let failure: UInt8 = 5
        public static let success: UInt8 = 6
        public static let removeAllIdentities: UInt8 = 9          // ssh-add -D
        public static let requestIdentities: UInt8 = 11
        public static let identitiesAnswer: UInt8 = 12
        public static let signRequest: UInt8 = 13
        public static let signResponse: UInt8 = 14
        public static let addSmartcardKey: UInt8 = 20             // ssh-add -s
        public static let removeSmartcardKey: UInt8 = 21          // ssh-add -e
        public static let addSmartcardKeyConstrained: UInt8 = 26  // ssh-add -s with constraints
    }

    /// One entry in an IDENTITIES_ANSWER.
    public struct AgentIdentity: Equatable {
        public let keyBlob: Data
        public let comment: String
        public init(keyBlob: Data, comment: String) {
            self.keyBlob = keyBlob
            self.comment = comment
        }
    }

    /// A parsed client request.
    public enum Request: Equatable {
        case requestIdentities
        case removeAllIdentities                                  // ssh-add -D
        case signRequest(keyBlob: Data, data: Data, flags: UInt32)
        // We repurpose the smartcard messages: `provider` is an SE handle file or a
        // directory of handles, not a PKCS#11 library. `ssh-add -s` / `ssh-add -e`.
        // The wire PIN field is parsed but dropped (the SE gates on Touch ID).
        case addSmartcardKey(provider: String)
        case removeSmartcardKey(provider: String)
        case unsupported(type: UInt8)
    }

    /// Max ssh-agent message size we accept (bounds allocation against a hostile length prefix).
    public static let maxAgentMessage = 256 * 1024

    // MARK: - Framing

    /// Frame a message: `uint32(len) || type || payload`, where `len = 1 + payload.count`.
    public static func frame(type: UInt8, payload: Data = Data()) -> Data {
        uint32(UInt32(1 + payload.count)) + Data([type]) + payload
    }

    /// Split a fully-framed message into `(type, payload)`.
    public static func splitFramed(_ framed: Data) throws -> (type: UInt8, payload: Data) {
        var r = ByteReader(framed)
        let len = Int(try r.readUInt32())
        guard len >= 1 else { throw WireError.malformed("zero-length message") }
        let body = try r.readBytes(len)
        guard let type = body.first else { throw WireError.malformed("empty message body") }
        return (type, Data(body.dropFirst()))
    }

    // MARK: - Responses

    public static func identitiesAnswer(_ ids: [AgentIdentity]) -> Data {
        var payload = uint32(UInt32(ids.count))
        for id in ids {
            payload += string(id.keyBlob)
            payload += string(id.comment)
        }
        return frame(type: Agent.identitiesAnswer, payload: payload)
    }

    public static func signResponse(signatureBlob: Data) -> Data {
        frame(type: Agent.signResponse, payload: string(signatureBlob))
    }

    public static func failure() -> Data {
        frame(type: Agent.failure)
    }

    public static func success() -> Data {
        frame(type: Agent.success)
    }

    // MARK: - Requests

    /// Parse a request from its type byte and (frame-stripped) payload.
    /// Malformed requests degrade to `.unsupported` (→ caller answers FAILURE).
    public static func parseRequest(type: UInt8, payload: Data) -> Request {
        switch type {
        case Agent.requestIdentities:
            return .requestIdentities

        case Agent.removeAllIdentities:
            return .removeAllIdentities

        case Agent.signRequest:
            var r = ByteReader(payload)
            guard let keyBlob = try? r.readString(),
                  let data = try? r.readString(),
                  let flags = try? r.readUInt32() else {
                return .unsupported(type: type)
            }
            return .signRequest(keyBlob: keyBlob, data: data, flags: flags)

        case Agent.addSmartcardKey, Agent.addSmartcardKeyConstrained, Agent.removeSmartcardKey:
            // provider path, then a PIN we read only to stay wire-aligned and discard;
            // the constrained variant's trailing constraints are ignored.
            var r = ByteReader(payload)
            guard let prov = try? r.readString(), (try? r.readString()) != nil else {
                return .unsupported(type: type)
            }
            let provider = String(decoding: prov, as: UTF8.self)
            return type == Agent.removeSmartcardKey
                ? .removeSmartcardKey(provider: provider)
                : .addSmartcardKey(provider: provider)

        default:
            return .unsupported(type: type)
        }
    }
}
