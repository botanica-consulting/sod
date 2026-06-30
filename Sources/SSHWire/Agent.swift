import Foundation

extension SSHWire {
    /// ssh-agent protocol message numbers (OpenSSH `PROTOCOL.agent`; the IETF
    /// `draft-ietf-sshm-ssh-agent` Standards-Track draft — the protocol is not an RFC).
    public enum Agent {
        public static let failure: UInt8 = 5
        public static let success: UInt8 = 6
        public static let removeAllIdentities: UInt8 = 9  // ssh-add -D
        public static let requestIdentities: UInt8 = 11
        public static let identitiesAnswer: UInt8 = 12
        public static let signRequest: UInt8 = 13
        public static let signResponse: UInt8 = 14
        public static let addSmartcardKey: UInt8 = 20  // ssh-add -s
        public static let removeSmartcardKey: UInt8 = 21  // ssh-add -e
        public static let addSmartcardKeyConstrained: UInt8 = 26  // ssh-add -s with constraints
        public static let extensionRequest: UInt8 = 27  // SSH_AGENTC_EXTENSION

        /// Extension name `ssh` sends (≥ 8.9) to bind a connection to its session/host key and to
        /// flag whether the agent is being *forwarded* to a remote host.
        public static let sessionBindExtension = "session-bind@openssh.com"
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
        case removeAllIdentities  // ssh-add -D
        case signRequest(keyBlob: Data, data: Data, flags: UInt32)
        // We repurpose the smartcard messages: `provider` is an SE handle file or a
        // directory of handles, not a PKCS#11 library. `ssh-add -s` / `ssh-add -e`.
        // The wire PIN field is parsed but dropped (the SE gates on Touch ID).
        case addSmartcardKey(provider: String)
        case removeSmartcardKey(provider: String)
        // session-bind@openssh.com (SSH_AGENTC_EXTENSION): ssh tells us the session's host key and
        // whether this agent connection is being *forwarded* to a remote host. We record the
        // forwarding flag per connection so a SIGN_REQUEST on a forwarded connection can be refused.
        case sessionBind(hostKey: Data, isForwarding: Bool)
        case unsupported(type: UInt8)
    }

    /// What a SIGN_REQUEST's to-be-signed blob represents — enough to describe it in a Touch ID
    /// prompt. Derived purely from the bytes the client handed us, so it needs nothing else.
    public enum SignedPayload: Equatable {
        case sshsig(namespace: String)  // ssh-keygen -Y sign (git, file, app-defined) — SSHSIG blob
        case sshUserAuth  // a public-key SSH login (SSH2_MSG_USERAUTH_REQUEST)
        case other
    }

    /// SSH2_MSG_USERAUTH_REQUEST, the byte that follows the session id in a userauth signature.
    private static let userAuthRequest: UInt8 = 50

    /// Classify a SIGN_REQUEST payload. SSHSIG blobs begin with the literal magic "SSHSIG"
    /// followed by a namespace string; a userauth blob is `string session-id || byte 50 || …`.
    public static func classifySignedData(_ data: Data) -> SignedPayload {
        let magic = Data("SSHSIG".utf8)
        if data.starts(with: magic) {
            var r = ByteReader(Data(data.dropFirst(magic.count)))
            let ns = (try? r.readString()).map { String(decoding: $0, as: UTF8.self) } ?? ""
            return .sshsig(namespace: ns)
        }
        var r = ByteReader(data)
        if (try? r.readString()) != nil, (try? r.readBytes(1))?.first == userAuthRequest {
            return .sshUserAuth
        }
        return .other
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
                let flags = try? r.readUInt32()
            else {
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

        case Agent.extensionRequest:
            // string ext-name, then ext-specific data. We only care about session-bind; any other
            // extension (or a short/garbled body) degrades to unsupported → FAILURE.
            var r = ByteReader(payload)
            guard let nameData = try? r.readString(),
                String(decoding: nameData, as: UTF8.self) == Agent.sessionBindExtension
            else {
                return .unsupported(type: type)
            }
            // session-bind body: string hostkey, string session-id, string signature, bool is_forwarding.
            guard let hostKey = try? r.readString(),
                (try? r.readString()) != nil,  // session id — unused
                (try? r.readString()) != nil,  // signature — unused (ssh already verified the host)
                let fwd = (try? r.readBytes(1))?.first
            else {
                return .unsupported(type: type)
            }
            return .sessionBind(hostKey: hostKey, isForwarding: fwd != 0)

        default:
            return .unsupported(type: type)
        }
    }
}
