import Foundation
import SSHWire
import SEKeyStore
#if canImport(Darwin)
import Darwin
#endif

private let tool = "se-ssh-agent"
private let maxMessage = SSHWire.maxAgentMessage   // bound allocations against a hostile length prefix

private func elog(_ msg: String) { FileHandle.standardError.write(Data("\(tool): \(msg)\n".utf8)) }
private func errExit(_ msg: String) -> Never { elog(msg); exit(1) }

// Stored as a C string so the (async-signal-safe) handler can unlink without Swift runtime calls.
nonisolated(unsafe) private var gSockPathC: UnsafeMutablePointer<CChar>?

private func installSignalHandlers(socketPath: String) {
    signal(SIGPIPE, SIG_IGN)   // don't die when a client disconnects mid-write
    gSockPathC = strdup(socketPath)
    let cleanup: @convention(c) (Int32) -> Void = { _ in
        if let p = gSockPathC { unlink(p) }
        _exit(0)
    }
    signal(SIGINT, cleanup)
    signal(SIGTERM, cleanup)
}

/// In-memory agent state: the set of loaded "providers" (each a Secure-Enclave
/// handle file or a directory of handles). Populated at startup from CLI args and
/// at runtime via `ssh-add -s` (add) / `ssh-add -e` (remove). Mutated only from the
/// serial accept loop, so no locking is needed.
final class AgentState {
    let backend: KeyBackend
    private var providers: [String] = []

    init(backend: KeyBackend) { self.backend = backend }

    private func absolute(_ path: String) -> String {
        (path as NSString).isAbsolutePath ? path
            : FileManager.default.currentDirectoryPath + "/" + path
    }

    /// Add a provider; returns false if it yields no usable handle for this backend.
    @discardableResult
    func add(_ path: String) -> Bool {
        let abs = absolute(path)
        guard !HandleScanner.resolve(provider: abs, kind: backend.kind).isEmpty else { return false }
        if !providers.contains(abs) { providers.append(abs) }
        return true
    }

    func remove(_ path: String) -> Bool {
        let abs = absolute(path)
        guard let i = providers.firstIndex(of: abs) else { return false }
        providers.remove(at: i)
        return true
    }

    /// Re-resolve all providers to their current handles (stateless per request).
    func handles() -> [DiscoveredHandle] {
        providers.flatMap { HandleScanner.resolve(provider: $0, kind: backend.kind) }
    }
}

private func handleRequest(type: UInt8, payload: Data, state: AgentState) -> Data {
    switch SSHWire.parseRequest(type: type, payload: payload) {
    case .requestIdentities:
        // No biometrics: reconstructing a key and reading its public key never prompts.
        var ids: [SSHWire.AgentIdentity] = []
        for h in state.handles() {
            guard let x963 = try? state.backend.publicKey(forHandle: h.handle) else { continue }
            ids.append(SSHWire.AgentIdentity(keyBlob: SSHWire.ecdsaP256PublicKeyBlob(x963: x963), comment: h.comment))
        }
        return SSHWire.identitiesAnswer(ids)

    case .signRequest(let keyBlob, let data, _):   // flags ignored (RSA-only)
        for h in state.handles() {
            guard let x963 = try? state.backend.publicKey(forHandle: h.handle),
                  SSHWire.ecdsaP256PublicKeyBlob(x963: x963) == keyBlob else { continue }
            do {
                let raw = try state.backend.sign(handle: h.handle, data: data)   // Touch ID (real backend)
                return SSHWire.signResponse(signatureBlob: try SSHWire.ecdsaP256SignatureBlob(rawRS: raw))
            } catch {
                elog("sign failed: \(error)")
                return SSHWire.failure()
            }
        }
        elog("sign: no loaded key matches the requested public key")
        return SSHWire.failure()

    case .addSmartcardKey(let provider):           // ssh-add -s <provider>
        if state.add(provider) { elog("loaded \(provider)"); return SSHWire.success() }
        elog("no se-ssh handle at \(provider)"); return SSHWire.failure()

    case .removeSmartcardKey(let provider):        // ssh-add -e <provider>
        if state.remove(provider) { elog("unloaded \(provider)"); return SSHWire.success() }
        return SSHWire.failure()

    case .unsupported:
        return SSHWire.failure()
    }
}

private func serve(_ fd: Int32, state: AgentState) {
    while true {
        guard let lenData = readExactly(fd, 4) else { return }
        var r = ByteReader(lenData)
        guard let len = try? r.readUInt32(), len >= 1, Int(len) <= maxMessage else { return }
        guard let body = readExactly(fd, Int(len)) else { return }
        if !writeAll(fd, handleRequest(type: body.first!, payload: Data(body.dropFirst()), state: state)) { return }
    }
}

// MARK: - `-E` env emitter + lazy daemon

private func executablePath() -> String {
    var size: UInt32 = 0
    _ = _NSGetExecutablePath(nil, &size)
    var buf = [CChar](repeating: 0, count: Int(size) + 1)
    guard _NSGetExecutablePath(&buf, &size) == 0 else { return CommandLine.arguments[0] }
    return String(cString: buf)
}

private func detectShell() -> String {
    (((ProcessInfo.processInfo.environment["SHELL"]) ?? "/bin/sh") as NSString).lastPathComponent
}

private func emitEnv(socketPath: String, shell: String) {
    switch shell {
    case "csh", "tcsh": print("setenv SSH_AUTH_SOCK \(socketPath);")
    case "fish":        print("set -gx SSH_AUTH_SOCK \(socketPath);")
    default:            print("SSH_AUTH_SOCK=\(socketPath); export SSH_AUTH_SOCK;")
    }
}

private func spawnDaemon(socketPath: String, providers: [String]) {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: executablePath())
    p.arguments = ["--daemon", "-a", socketPath] + providers
    p.standardInput = FileHandle.nullDevice
    p.standardOutput = FileHandle.nullDevice
    p.standardError = FileHandle.nullDevice
    do { try p.run() } catch { errExit("could not start daemon: \(error)") }
    // Do not wait — the child setsid()s and keeps running; we emit env and exit.
}

/// Detach from the controlling terminal, log to <dir>/se-agent.log. Keeps the
/// macOS GUI/audit session (only the POSIX session changes), so Touch ID works.
private func daemonize(logDir: String) {
    setsid()
    let devnull = open("/dev/null", O_RDWR)
    if devnull >= 0 { dup2(devnull, 0) }
    let logfd = open(logDir + "/se-agent.log", O_WRONLY | O_CREAT | O_APPEND, 0o600)
    if logfd >= 0 { dup2(logfd, 1); dup2(logfd, 2) }
    else if devnull >= 0 { dup2(devnull, 1); dup2(devnull, 2) }
    if devnull > 2 { close(devnull) }
    if logfd > 2 { close(logfd) }
}

private func printUsage() {
    print("""
    usage: \(tool) [provider ...] [-a <socket>] [-E [-s sh|csh|fish]]

    A Secure-Enclave ssh-agent. It holds nothing until you load a key:
      ssh-add -s <keyfile>     load an SE handle into the running agent
      ssh-add -e <keyfile>     unload it
      ssh-add -l / -L          list loaded keys
    You may also preload handle files or directories by passing them as arguments.

      -a   socket path (default ~/.ssh/se-agent.sock)
      -E   ensure an agent is running, then print shell to set SSH_AUTH_SOCK:
             eval "$(\(tool) -E)"
      -s   force -E output dialect: sh | csh | fish (default: detect from $SHELL)

    Typical:  eval "$(\(tool) -E)"  &&  ssh-add -s ~/keys/id  &&  ssh -i ~/keys/id host
    """)
}

private func run() {
    var socketPath = expandTilde("~/.ssh/se-agent.sock")
    var providers: [String] = []
    var envMode = false
    var daemonMode = false
    var shell: String?

    let argv = CommandLine.arguments
    var i = 1
    while i < argv.count {
        let a = argv[i]
        switch a {
        case "-a":
            i += 1; guard i < argv.count else { errExit("-a requires a path") }
            socketPath = expandTilde(argv[i])
        case "-E", "--env":
            envMode = true
        case "-s":
            i += 1; guard i < argv.count else { errExit("-s requires sh|csh|fish") }
            shell = argv[i]
        case "--daemon":
            daemonMode = true
        case "-h", "--help":
            printUsage(); exit(0)
        default:
            if a.hasPrefix("-") { errExit("unknown argument '\(a)'") }
            providers.append(expandTilde(a))
        }
        i += 1
    }

    // -E: lazily ensure a daemon is up, then print env (stdout = eval-clean).
    if envMode {
        if Backends.isMock { elog(Backends.mockWarning) }
        if !isSocketLive(socketPath) {
            spawnDaemon(socketPath: socketPath, providers: providers)
            var tries = 0
            while !isSocketLive(socketPath), tries < 300 { usleep(10_000); tries += 1 }   // up to ~3s
            guard isSocketLive(socketPath) else { errExit("daemon did not come up at \(socketPath)") }
            elog("started agent on \(socketPath)")
        } else {
            elog("reusing agent already on \(socketPath)")
            if !providers.isEmpty {
                elog("note: agent already running — preloaded key args ignored; load with se-ssh-add / ssh-add -s")
            }
        }
        emitEnv(socketPath: socketPath, shell: shell ?? detectShell())
        exit(0)
    }

    if Backends.isMock { elog(Backends.mockWarning) }

    let logDir = (socketPath as NSString).deletingLastPathComponent
    if daemonMode { daemonize(logDir: logDir.isEmpty ? "." : logDir) }

    let backend = Backends.active()
    let state = AgentState(backend: backend)
    for p in providers where !state.add(p) { elog("warning: no se-ssh handle at \(p)") }

    let server = UnixSocketServer(path: socketPath)
    do { try server.bindAndListen() } catch { errExit("\(error)") }
    installSignalHandlers(socketPath: socketPath)

    elog("listening on \(socketPath)  backend: \(backend.isMock ? "MOCK (no Touch ID)" : "Secure Enclave (Touch ID on sign)")")
    elog("load a key:  SSH_AUTH_SOCK=\(socketPath) ssh-add -s <keyfile>")
    server.acceptLoop { serve($0, state: state) }
}

run()
