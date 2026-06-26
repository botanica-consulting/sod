import ArgumentParser
import CryptoKit   // SHA256 for the `-l` fingerprint only
import Foundation
import SEKeyStore
import SSHWire
#if canImport(Darwin)
import Darwin
#endif

private let tool = "sod ssh-add"
private let maxMessage = SSHWire.maxAgentMessage

private func elog(_ s: String) { FileHandle.standardError.write(Data("\(tool): \(s)\n".utf8)) }
private func errExit(_ s: String) -> Never { elog(s); exit(1) }

private func absolute(_ p: String) -> String {
    let e = expandTilde(p)
    return (e as NSString).isAbsolutePath ? e : FileManager.default.currentDirectoryPath + "/" + e
}

private func transact(socket path: String, _ request: Data) -> (type: UInt8, payload: Data) {
    let fd = connectUnix(path)
    guard fd >= 0 else {
        errExit("cannot connect to agent at \(path) — is it running? " +
                "(run: eval \"$(sod ssh-agent)\", or set SSH_AUTH_SOCK / pass -a)")
    }
    defer { close(fd) }
    guard writeAll(fd, request) else { errExit("write to agent failed") }
    guard let lenData = readExactly(fd, 4) else { errExit("no response from agent") }
    var r = ByteReader(lenData)
    guard let len = try? r.readUInt32(), len >= 1, Int(len) <= maxMessage,
          let body = readExactly(fd, Int(len)) else { errExit("malformed response from agent") }
    guard let type = body.first else { errExit("empty response from agent") }
    return (type, Data(body.dropFirst()))
}

private func sshFingerprint(_ blob: Data) -> String {
    "SHA256:" + Data(SHA256.hash(data: blob)).base64EncodedString().replacingOccurrences(of: "=", with: "")
}

private func resolveSocket(_ explicit: String?) -> String {
    if let e = explicit { return expandTilde(e) }
    if let s = ProcessInfo.processInfo.environment["SSH_AUTH_SOCK"], !s.isEmpty { return s }
    return expandTilde("~/.ssh/sod-agent.sock")
}

private func listIdentities(_ sock: String, full: Bool) {
    let (t, payload) = transact(socket: sock, SSHWire.frame(type: SSHWire.Agent.requestIdentities))
    guard t == SSHWire.Agent.identitiesAnswer else { errExit("unexpected agent reply (type \(t))") }
    var r = ByteReader(payload)
    guard let n = try? r.readUInt32() else { errExit("malformed identities answer") }
    if n == 0 { print("The agent has no identities."); return }
    for _ in 0 ..< n {
        guard let blob = try? r.readString(), let c = try? r.readString() else { errExit("malformed identity") }
        let comment = String(decoding: c, as: UTF8.self)
        if full { print("ecdsa-sha2-nistp256 \(blob.base64EncodedString()) \(comment)") }
        else { print("256 \(sshFingerprint(blob)) \(comment) (ECDSA)") }
    }
}

private func sendProvider(_ sock: String, type: UInt8, provider: String) -> Bool {
    let (t, _) = transact(socket: sock,
                          SSHWire.frame(type: type, payload: SSHWire.string(absolute(provider)) + SSHWire.string("")))
    return t == SSHWire.Agent.success
}

public struct Add: ParsableCommand {
    public static let configuration = CommandConfiguration(
        commandName: "ssh-add",
        abstract: "Load, unload, or list Secure-Enclave keys in the agent.",
        discussion: """
        With no arguments, loads the default key ~/.ssh/id_sod. Unlike stock
        `ssh-add -s`, this talks to the agent with an empty PIN, so it never prompts.
        """
    )

    @Option(name: .customShort("a"), help: ArgumentHelp("Agent socket (default $SSH_AUTH_SOCK, else ~/.ssh/sod-agent.sock).", valueName: "socket"))
    var socket: String?

    @Flag(name: .customShort("d"), help: "Unload the given key(s) instead of loading.")
    var delete = false

    @Flag(name: .customShort("e"), help: "Unload the given key(s) (alias of -d).")
    var deleteAlias = false

    @Flag(name: .customShort("D"), help: "Unload all keys.")
    var deleteAll = false

    @Flag(name: .customShort("l"), help: "List fingerprints of loaded keys.")
    var list = false

    @Flag(name: .customShort("L"), help: "List public keys of loaded keys.")
    var listFull = false

    @Argument(help: "Handle file(s) to load or unload (default ~/.ssh/id_sod).")
    var keyfiles: [String] = []

    public init() {}

    public func run() throws {
        let sock = resolveSocket(socket)

        if list { listIdentities(sock, full: false); return }
        if listFull { listIdentities(sock, full: true); return }
        if deleteAll {
            let (t, _) = transact(socket: sock, SSHWire.frame(type: SSHWire.Agent.removeAllIdentities))
            guard t == SSHWire.Agent.success else { errExit("agent did not remove identities (type \(t))") }
            print("All identities removed.")
            return
        }

        let removing = delete || deleteAlias
        let paths = keyfiles.isEmpty ? ["~/.ssh/id_sod"] : keyfiles

        if removing {
            for p in paths where !sendProvider(sock, type: SSHWire.Agent.removeSmartcardKey, provider: p) {
                errExit("could not unload \(p)")
            }
            for p in paths { print("Identity removed: \(absolute(p))") }
        } else {
            for p in paths where !sendProvider(sock, type: SSHWire.Agent.addSmartcardKey, provider: p) {
                errExit("could not add \(p) — not a sod handle, or the agent rejected it")
            }
            for p in paths { print("Identity added: \(absolute(p))") }
        }
    }
}
