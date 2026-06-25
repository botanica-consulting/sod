// =============================================================================
// se-ssh-add — DISPOSABLE convenience wrapper.  DELETE ME once it's not needed.
// =============================================================================
//
// WHY THIS EXISTS
//   se-ssh-agent loads Secure-Enclave keys via the ssh-agent "smartcard" messages
//   (ADD_SMARTCARD_KEY / REMOVE_SMARTCARD_KEY), which stock `ssh-add -s` / `-e`
//   send. That works — BUT `ssh-add -s` ALWAYS reads a PKCS#11 PIN on the *client*
//   side (OpenSSH ssh-add.c, update_card(): `if (add) read_passphrase("Enter
//   passphrase for PKCS#11:")`) before it ever contacts the agent, and there is no
//   ssh-add flag to skip it. For us that PIN is meaningless — the private key lives
//   in the Secure Enclave and signing is gated by Touch ID, not a PIN — so the
//   prompt is pure friction.
//
//   This tool speaks the same agent protocol directly and sends an EMPTY pin, so it
//   never prompts. It is otherwise a faithful subset of ssh-add:
//       se-ssh-add <handle>      ~  ssh-add -s <handle>   (load — no PIN prompt)
//       se-ssh-add -d <handle>   ~  ssh-add -e <handle>   (unload)
//       se-ssh-add -l | -L       ~  ssh-add -l | -L       (list)
//
// WHEN TO DELETE THIS FILE (and its target in Package.swift)
//   This is a workaround, not core functionality. Trash it the moment any of these
//   is true — the agent itself needs no change:
//     • stock `ssh-add -s` gains a way to skip the PIN (a flag, or it stops asking
//       when the token reports no PIN); or
//     • you standardize on PRELOADING keys at agent start instead of adding at
//       runtime:  `se-ssh-agent ~/keys/id`  or  `eval "$(se-ssh-agent -E ~/keys/id)"`
//       (no ssh-add in the loop  ⇒  no PIN); or
//     • upstream OpenSSH changes the smartcard-add PIN behavior.
//   Nothing else depends on se-ssh-add: the agent still works with stock
//   `ssh-add -s` (you just answer the PIN prompt) and with preloading.
// =============================================================================

import Foundation
import SSHWire
import CryptoKit   // SHA256 for the `-l` fingerprint only
#if canImport(Darwin)
import Darwin
#endif

private let tool = "se-ssh-add"
private let maxMessage = SSHWire.maxAgentMessage

private func elog(_ s: String) { FileHandle.standardError.write(Data("\(tool): \(s)\n".utf8)) }
private func errExit(_ s: String) -> Never { elog(s); exit(1) }

private func expandTilde(_ p: String) -> String {
    if p == "~" { return NSHomeDirectory() }
    if p.hasPrefix("~/") { return NSHomeDirectory() + String(p.dropFirst(1)) }
    return p
}
private func absolute(_ p: String) -> String {
    let e = expandTilde(p)
    return (e as NSString).isAbsolutePath ? e : FileManager.default.currentDirectoryPath + "/" + e
}

// MARK: - tiny unix-socket client

private func connectUnix(_ path: String) -> Int32 {
    let bytes = Array(path.utf8)
    let maxLen = MemoryLayout.size(ofValue: sockaddr_un().sun_path)
    guard bytes.count < maxLen else { return -1 }
    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    guard fd >= 0 else { return -1 }
    var addr = sockaddr_un()
    addr.sun_family = sa_family_t(AF_UNIX)
    addr.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
    withUnsafeMutablePointer(to: &addr.sun_path) {
        $0.withMemoryRebound(to: CChar.self, capacity: maxLen) { dst in
            for (i, b) in bytes.enumerated() { dst[i] = CChar(bitPattern: b) }
            dst[bytes.count] = 0
        }
    }
    let len = socklen_t(MemoryLayout<sockaddr_un>.size)
    let r = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, len) } }
    if r != 0 { close(fd); return -1 }
    return fd
}

private func readExactly(_ fd: Int32, _ n: Int) -> Data? {
    guard n > 0 else { return Data() }
    var buf = [UInt8](repeating: 0, count: n); var got = 0
    while got < n {
        let r = buf.withUnsafeMutableBytes { read(fd, $0.baseAddress!.advanced(by: got), n - got) }
        if r <= 0 { return nil }
        got += r
    }
    return Data(buf)
}
private func writeAll(_ fd: Int32, _ data: Data) -> Bool {
    let b = [UInt8](data); var off = 0
    while off < b.count {
        let w = b.withUnsafeBytes { write(fd, $0.baseAddress!.advanced(by: off), b.count - off) }
        if w <= 0 { return false }
        off += w
    }
    return true
}

private func transact(socket path: String, _ request: Data) -> (type: UInt8, payload: Data) {
    let fd = connectUnix(path)
    guard fd >= 0 else {
        errExit("cannot connect to agent at \(path) — is se-ssh-agent running? (set SSH_AUTH_SOCK or pass -a)")
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

// MARK: - actions

private func sshFingerprint(_ blob: Data) -> String {
    "SHA256:" + Data(SHA256.hash(data: blob)).base64EncodedString().replacingOccurrences(of: "=", with: "")
}

private func resolveSocket(_ explicit: String?) -> String {
    if let e = explicit { return expandTilde(e) }
    if let s = ProcessInfo.processInfo.environment["SSH_AUTH_SOCK"], !s.isEmpty { return s }
    return expandTilde("~/.ssh/se-agent.sock")
}

private func list(_ sock: String, full: Bool) {
    let (t, payload) = transact(socket: sock, SSHWire.frame(type: SSHWire.Agent.requestIdentities))
    guard t == SSHWire.Agent.identitiesAnswer else { errExit("unexpected agent reply (type \(t))") }
    var r = ByteReader(payload)
    guard let n = try? r.readUInt32() else { errExit("malformed identities answer") }
    if n == 0 { print("The agent has no identities."); exit(0) }
    for _ in 0 ..< n {
        guard let blob = try? r.readString(), let c = try? r.readString() else { errExit("malformed identity") }
        let comment = String(decoding: c, as: UTF8.self)
        if full { print("ecdsa-sha2-nistp256 \(blob.base64EncodedString()) \(comment)") }
        else    { print("256 \(sshFingerprint(blob)) \(comment) (ECDSA)") }
    }
}

private func send(_ sock: String, type: UInt8, provider: String) -> Bool {
    let (t, _) = transact(socket: sock,
                          SSHWire.frame(type: type, payload: SSHWire.string(absolute(provider)) + SSHWire.string("")))
    return t == SSHWire.Agent.success
}

private func usage() {
    print("""
    usage: \(tool) [-a socket] <keyfile> ...    load SE handle(s) into se-ssh-agent
           \(tool) [-a socket] -d <keyfile> ... unload them
           \(tool) [-a socket] -l | -L          list loaded keys (fingerprints | full)

    Like `ssh-add -s/-e/-l/-L`, but talks to se-ssh-agent with an empty PIN, so it
    never prompts. DISPOSABLE — see the header of Sources/\(tool)/main.swift: delete
    it if stock `ssh-add -s` ever stops demanding a PKCS#11 PIN, or if you preload
    keys at agent start instead.
    """)
}

private func main() {
    var sock: String?
    var mode = "add"           // add | remove | list-l | list-L
    var paths: [String] = []

    let argv = CommandLine.arguments
    var i = 1
    while i < argv.count {
        switch argv[i] {
        case "-a": i += 1; guard i < argv.count else { errExit("-a requires a path") }; sock = argv[i]
        case "-d", "-e": mode = "remove"
        case "-l": mode = "list-l"
        case "-L": mode = "list-L"
        case "-h", "--help": usage(); exit(0)
        default:
            if argv[i].hasPrefix("-") { errExit("unknown argument '\(argv[i])'") }
            paths.append(argv[i])
        }
        i += 1
    }

    let s = resolveSocket(sock)
    switch mode {
    case "list-l": list(s, full: false)
    case "list-L": list(s, full: true)
    case "remove":
        guard !paths.isEmpty else { errExit("specify the keyfile(s) to remove") }
        for p in paths where !send(s, type: SSHWire.Agent.removeSmartcardKey, provider: p) {
            errExit("could not remove \(p)")
        }
        for p in paths { print("Identity removed: \(p)") }
    default: // add
        guard !paths.isEmpty else { errExit("specify keyfile(s) to load (or -l/-L to list, -d to remove)") }
        for p in paths where !send(s, type: SSHWire.Agent.addSmartcardKey, provider: p) {
            errExit("could not add \(p) — not an se-ssh handle, or the agent rejected it")
        }
        for p in paths { print("Identity added: \(p)") }
    }
}

main()
