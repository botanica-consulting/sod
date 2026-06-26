import ArgumentParser
import Foundation
import SEKeyStore
import SSHWire

#if canImport(Darwin)
import Darwin
#endif

private let tool = "sod ssh-agent"
private let maxMessage = SSHWire.maxAgentMessage  // bound allocations against a hostile length prefix

private func elog(_ msg: String) { FileHandle.standardError.write(Data("\(tool): \(msg)\n".utf8)) }
private func errExit(_ msg: String) -> Never { elog(msg); exit(1) }

// Stored as C strings so the (async-signal-safe) handler can unlink without Swift runtime calls.
nonisolated(unsafe) private var gSockPathC: UnsafeMutablePointer<CChar>?
nonisolated(unsafe) private var gPidPathC: UnsafeMutablePointer<CChar>?

private func installSignalHandlers(socketPath: String, pidPath: String) {
    signal(SIGPIPE, SIG_IGN)  // don't die when a client disconnects mid-write
    gSockPathC = strdup(socketPath)
    gPidPathC = strdup(pidPath)
    let cleanup: @convention(c) (Int32) -> Void = { _ in
        if let p = gSockPathC { unlink(p) }
        if let p = gPidPathC { unlink(p) }
        _exit(0)
    }
    signal(SIGINT, cleanup)
    signal(SIGTERM, cleanup)
}

// MARK: - In-memory agent state (public so tests can drive it without a socket)

/// The set of loaded "providers" (each a Secure-Enclave handle file or a directory
/// of handles). Populated at startup from CLI args and at runtime via `ssh-add -s`
/// (add) / `-e` (remove) / `-D` (remove all). Mutated only from the serial accept
/// loop, so no locking is needed.
public final class AgentState {
    public let backend: KeyBackend
    private var providers: [String] = []

    public init(backend: KeyBackend) { self.backend = backend }

    private func absolute(_ path: String) -> String {
        (path as NSString).isAbsolutePath
            ? path
            : FileManager.default.currentDirectoryPath + "/" + path
    }

    /// Add a provider; returns false if it yields no usable handle for this backend.
    @discardableResult
    public func add(_ path: String) -> Bool {
        let abs = absolute(path)
        guard !HandleScanner.resolve(provider: abs, kind: backend.kind).isEmpty else { return false }
        if !providers.contains(abs) { providers.append(abs) }
        return true
    }

    @discardableResult
    public func remove(_ path: String) -> Bool {
        let abs = absolute(path)
        guard let i = providers.firstIndex(of: abs) else { return false }
        providers.remove(at: i)
        return true
    }

    public func removeAll() { providers.removeAll() }

    /// Re-resolve all providers to their current handles (stateless per request).
    public func handles() -> [DiscoveredHandle] {
        providers.flatMap { HandleScanner.resolve(provider: $0, kind: backend.kind) }
    }
}

/// Handle one agent request and produce the framed response. Public so tests can
/// exercise identities/sign/add/remove with the mock backend (no socket, no Touch ID).
public func handleRequest(type: UInt8, payload: Data, state: AgentState) -> Data {
    switch SSHWire.parseRequest(type: type, payload: payload) {
    case .requestIdentities:
        // No biometrics: reconstructing a key and reading its public key never prompts.
        var ids: [SSHWire.AgentIdentity] = []
        for h in state.handles() {
            guard let x963 = try? state.backend.publicKey(forHandle: h.handle) else { continue }
            ids.append(SSHWire.AgentIdentity(keyBlob: SSHWire.ecdsaP256PublicKeyBlob(x963: x963), comment: h.comment))
        }
        return SSHWire.identitiesAnswer(ids)

    case .signRequest(let keyBlob, let data, _):  // flags ignored (RSA-only)
        for h in state.handles() {
            guard let x963 = try? state.backend.publicKey(forHandle: h.handle),
                SSHWire.ecdsaP256PublicKeyBlob(x963: x963) == keyBlob
            else { continue }
            do {
                let raw = try state.backend.sign(handle: h.handle, data: data)  // Touch ID (real backend)
                return SSHWire.signResponse(signatureBlob: try SSHWire.ecdsaP256SignatureBlob(rawRS: raw))
            } catch {
                elog("sign failed: \(error)")
                return SSHWire.failure()
            }
        }
        elog("sign: no loaded key matches the requested public key")
        return SSHWire.failure()

    case .addSmartcardKey(let provider):  // ssh-add -s <provider>
        if state.add(provider) { elog("loaded \(provider)"); return SSHWire.success() }
        elog("no sod handle at \(provider)"); return SSHWire.failure()

    case .removeSmartcardKey(let provider):  // ssh-add -e <provider>
        if state.remove(provider) { elog("unloaded \(provider)"); return SSHWire.success() }
        return SSHWire.failure()

    case .removeAllIdentities:  // ssh-add -D
        state.removeAll(); elog("unloaded all keys"); return SSHWire.success()

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

// MARK: - daemon / env / kill helpers

private func detectDialect() -> String {
    let shell = (((ProcessInfo.processInfo.environment["SHELL"]) ?? "/bin/sh") as NSString).lastPathComponent
    switch shell {
    case "csh", "tcsh": return "csh"
    case "fish": return "fish"
    default: return "sh"
    }
}

private func emitEnv(socketPath: String, dialect: String) {
    switch dialect {
    case "csh": print("setenv SSH_AUTH_SOCK \(socketPath);")
    case "fish": print("set -gx SSH_AUTH_SOCK \(socketPath);")
    default: print("SSH_AUTH_SOCK=\(socketPath); export SSH_AUTH_SOCK;")
    }
}

private func spawnDaemon(socketPath: String, providers: [String]) {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: executablePath())
    // Re-enter via the subcommand: `sod ssh-agent --daemon -a <sock> [providers...]`.
    p.arguments = ["ssh-agent", "--daemon", "-a", socketPath] + providers
    p.standardInput = FileHandle.nullDevice
    p.standardOutput = FileHandle.nullDevice
    p.standardError = FileHandle.nullDevice
    do { try p.run() } catch { errExit("could not start daemon: \(error)") }
    // Do not wait — the child setsid()s and keeps running; we emit env and exit.
}

/// Detach from the controlling terminal, log to <dir>/sod-agent.log. Keeps the
/// macOS GUI/audit session (only the POSIX session changes), so Touch ID works.
private func daemonize(logDir: String) {
    setsid()
    let devnull = open("/dev/null", O_RDWR)
    if devnull >= 0 { dup2(devnull, 0) }
    let logfd = open(logDir + "/sod-agent.log", O_WRONLY | O_CREAT | O_APPEND, 0o600)
    if logfd >= 0 { dup2(logfd, 1); dup2(logfd, 2) } else if devnull >= 0 { dup2(devnull, 1); dup2(devnull, 2) }
    if devnull > 2 { close(devnull) }
    if logfd > 2 { close(logfd) }
}

private func writePidFile(_ path: String) {
    FileManager.default.createFile(
        atPath: path, contents: Data(String(getpid()).utf8),
        attributes: [.posixPermissions: NSNumber(value: 0o600)])
}

private func killAgent(socketPath: String) -> Never {
    let pidPath = socketPath + ".pid"
    guard let data = FileManager.default.contents(atPath: pidPath),
        let text = String(data: data, encoding: .utf8),
        let pid = pid_t(text.trimmingCharacters(in: .whitespacesAndNewlines))
    else {
        errExit("no agent pidfile at \(pidPath) — is an agent running on \(socketPath)?")
    }
    if kill(pid, SIGTERM) == 0 {
        elog("killed agent (pid \(pid)) on \(socketPath)")
        exit(0)
    }
    errExit("could not kill agent pid \(pid): \(errnoString())")
}

// MARK: - run modes

private func runListen(socketPath: String, providers: [String], detach: Bool) -> Never {
    if Backends.isMock { elog(Backends.mockWarning) }
    let logDir = (socketPath as NSString).deletingLastPathComponent
    if detach { daemonize(logDir: logDir.isEmpty ? "." : logDir) }

    let backend = Backends.active()
    let state = AgentState(backend: backend)
    for p in providers where !state.add(p) { elog("warning: no sod handle at \(p)") }

    let server = UnixSocketServer(path: socketPath)
    do { try server.bindAndListen() } catch { errExit("\(error)") }
    let pidPath = socketPath + ".pid"
    writePidFile(pidPath)
    installSignalHandlers(socketPath: socketPath, pidPath: pidPath)

    elog(
        "listening on \(socketPath)  backend: \(backend.isMock ? "MOCK (no Touch ID)" : "Secure Enclave (Touch ID on sign)")"
    )
    elog("load a key:  sod ssh-add <keyfile>")
    server.acceptLoop { serve($0, state: state) }
    exit(0)
}

private func ensureAndEmit(socketPath: String, providers: [String], dialect: String) -> Never {
    if Backends.isMock { elog(Backends.mockWarning) }
    if !isSocketLive(socketPath) {
        spawnDaemon(socketPath: socketPath, providers: providers)
        var tries = 0
        while !isSocketLive(socketPath), tries < 300 { usleep(10_000); tries += 1 }  // up to ~3s
        guard isSocketLive(socketPath) else { errExit("agent did not come up at \(socketPath)") }
        elog("started agent on \(socketPath)")
    } else {
        elog("reusing agent already on \(socketPath)")
        if !providers.isEmpty {
            elog("note: agent already running — preload args ignored; load with sod ssh-add")
        }
    }
    emitEnv(socketPath: socketPath, dialect: dialect)
    exit(0)
}

// MARK: - command

public struct Agent: ParsableCommand {
    public static let configuration = CommandConfiguration(
        commandName: "ssh-agent",
        abstract: "Run the Secure-Enclave ssh-agent and print the environment to use it.",
        discussion: """
            With no options, ensures an agent is running on the socket (reusing one if
            present) and prints shell commands that set SSH_AUTH_SOCK:

                eval "$(sod ssh-agent)"

            Then load a key with `sod ssh-add` and use `ssh` as usual; Touch ID is
            requested on each signature. Handle files or directories given as arguments
            are preloaded when the agent starts.
            """
    )

    @Option(
        name: .customShort("a"),
        help: ArgumentHelp("Agent socket path (default ~/.ssh/sod-agent.sock).", valueName: "socket"))
    var socket: String?

    @Flag(name: .customShort("s"), help: "Force Bourne-shell (sh) output for the env.")
    var sh = false

    @Flag(name: .customShort("c"), help: "Force C-shell (csh) output for the env.")
    var csh = false

    @Flag(name: .customShort("d"), help: "Foreground: bind and serve, do not fork (debugging / LaunchAgent).")
    var foreground = false

    @Flag(name: .customShort("k"), help: "Kill the agent running on the socket.")
    var kill = false

    @Flag(name: .customShort("E"), help: "Ensure an agent is running and print its env (the default).")
    var ensure = false

    @Flag(name: .long, help: ArgumentHelp(visibility: .private))  // internal: invoked by the lazy-spawn path
    var daemon = false

    @Argument(help: "Handle files or directories to preload.")
    var providers: [String] = []

    public init() {}

    public func run() throws {
        let sock = expandTilde(socket ?? "~/.ssh/sod-agent.sock")
        let provs = providers.map { expandTilde($0) }

        if kill { killAgent(socketPath: sock) }  // Never
        if daemon { runListen(socketPath: sock, providers: provs, detach: true) }  // Never
        if foreground { runListen(socketPath: sock, providers: provs, detach: false) }  // Never

        let dialect = csh ? "csh" : (sh ? "sh" : detectDialect())
        ensureAndEmit(socketPath: sock, providers: provs, dialect: dialect)  // Never
    }
}
