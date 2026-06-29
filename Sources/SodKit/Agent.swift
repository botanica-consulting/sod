import ArgumentParser
import Foundation
import SEKeyStore
import SSHWire

#if canImport(Darwin)
import Darwin
#endif

private let tool = "sd ssh-agent"
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
    /// When true (the default), refuse to act as a *forwarded* agent — a remote host can neither
    /// use nor enumerate the Secure-Enclave key. Cleared by `sd ssh-agent --allow-agent-forwarding`.
    public let refuseForwarding: Bool
    private var providers: [String] = []

    public init(backend: KeyBackend, refuseForwarding: Bool = true) {
        self.backend = backend
        self.refuseForwarding = refuseForwarding
    }

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

    /// Retain a provider path unconditionally — no existence check — so it is re-resolved
    /// on every request. Used to always offer the canonical key ~/.ssh/id_sod: it shows up
    /// in the agent as soon as the file exists, and can still be dropped at runtime with
    /// `ssh-add -d`/`-D` (until the agent restarts and offers it again).
    public func alwaysOffer(_ path: String) {
        let abs = absolute(path)
        if !providers.contains(abs) { providers.append(abs) }
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

/// Per-connection state for one agent socket connection. The accept loop is serial and each
/// connection runs its own `serve` loop, so this needs no locking. `session-bind@openssh.com`
/// populates `forwarding`/`boundHostKey`; the requests that follow on the connection consult it.
public final class AgentConnection {
    public var forwarding = false
    public var boundHostKey: Data?
    public init() {}
}

/// Handle one agent request and produce the framed response. Public so tests can
/// exercise identities/sign/add/remove with the mock backend (no socket, no Touch ID).
/// `conn` carries per-connection session-bind state; it defaults to a fresh (non-forwarded)
/// connection so existing call sites and one-shot tests are unaffected.
public func handleRequest(
    type: UInt8, payload: Data, state: AgentState, conn: AgentConnection = AgentConnection()
) -> Data {
    let request = SSHWire.parseRequest(type: type, payload: payload)

    // ssh binds the connection before authenticating: record the host key and whether this
    // connection is being *forwarded* to a remote host, then ack. Everything after consults it.
    if case .sessionBind(let hostKey, let isForwarding) = request {
        conn.forwarding = isForwarding
        conn.boundHostKey = hostKey
        if isForwarding {
            elog("session bound as FORWARDED — agent is being forwarded to a remote host")
        }
        return SSHWire.success()
    }

    // Refuse to act as a forwarded agent unless explicitly allowed. `-A` produces a forwarded
    // connection (bound is_forwarding=1 by the relaying ssh); `-J`/ProxyJump and direct
    // connections authenticate locally (is_forwarding=0) and are unaffected. Present an *empty*
    // agent for identity listing — no public-key/comment leak, no confusing downstream errors —
    // and fail every other operation so a remote can neither sign with nor manage the SE key.
    if conn.forwarding && state.refuseForwarding {
        if case .requestIdentities = request {
            elog("forwarded agent: presenting no identities (agent forwarding disabled)")
            return SSHWire.identitiesAnswer([])
        }
        elog(
            "forwarded agent: refused (agent forwarding disabled; run the agent with "
                + "--allow-agent-forwarding to permit)")
        return SSHWire.failure()
    }

    switch request {
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

    case .sessionBind:
        return SSHWire.success()  // unreachable: handled above before the forwarding gate

    case .unsupported:
        return SSHWire.failure()
    }
}

private func serve(_ fd: Int32, state: AgentState) {
    let conn = AgentConnection()  // session-bind state lives for this one connection
    while true {
        guard let lenData = readExactly(fd, 4) else { return }
        var r = ByteReader(lenData)
        guard let len = try? r.readUInt32(), len >= 1, Int(len) <= maxMessage else { return }
        guard let body = readExactly(fd, Int(len)) else { return }
        if !writeAll(fd, handleRequest(type: body.first!, payload: Data(body.dropFirst()), state: state, conn: conn)) {
            return
        }
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

private func spawnDaemon(socketPath: String, providers: [String], allowForwarding: Bool) {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: executablePath())
    // Re-enter via the subcommand: `sd ssh-agent --daemon -a <sock> [--allow-agent-forwarding] [providers...]`.
    p.arguments =
        ["ssh-agent", "--daemon", "-a", socketPath]
        + (allowForwarding ? ["--allow-agent-forwarding"] : []) + providers
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

private func runListen(socketPath: String, providers: [String], detach: Bool, allowForwarding: Bool) -> Never {
    if Backends.isMock { elog(Backends.mockWarning) }
    let logDir = (socketPath as NSString).deletingLastPathComponent
    if detach { daemonize(logDir: logDir.isEmpty ? "." : logDir) }

    let backend = Backends.active()
    let state = AgentState(backend: backend, refuseForwarding: !allowForwarding)
    if allowForwarding { elog("agent forwarding ALLOWED (--allow-agent-forwarding)") }
    for p in providers where !state.add(p) { elog("warning: no sod handle at \(p)") }
    // The default key is canonical: always serve ~/.ssh/id_sod, resolved per request so it
    // appears as soon as it exists. Drop it for the session with `sd ssh-add -d`/`-D`.
    state.alwaysOffer(expandTilde("~/.ssh/id_sod"))

    let server = UnixSocketServer(path: socketPath)
    do { try server.bindAndListen() } catch { errExit("\(error)") }
    let pidPath = socketPath + ".pid"
    writePidFile(pidPath)
    installSignalHandlers(socketPath: socketPath, pidPath: pidPath)

    elog(
        "listening on \(socketPath)  backend: \(backend.isMock ? "MOCK (no Touch ID)" : "Secure Enclave (Touch ID on sign)")"
    )
    elog("serving ~/.ssh/id_sod automatically; load more with:  sd ssh-add <keyfile>")
    server.acceptLoop { serve($0, state: state) }
    exit(0)
}

private func ensureAndEmit(
    socketPath: String, providers: [String], dialect: String, allowForwarding: Bool
) -> Never {
    if Backends.isMock { elog(Backends.mockWarning) }
    if !isSocketLive(socketPath) {
        spawnDaemon(socketPath: socketPath, providers: providers, allowForwarding: allowForwarding)
        var tries = 0
        while !isSocketLive(socketPath), tries < 300 { usleep(10_000); tries += 1 }  // up to ~3s
        guard isSocketLive(socketPath) else { errExit("agent did not come up at \(socketPath)") }
        elog("started agent on \(socketPath)")
    } else {
        elog("reusing agent already on \(socketPath)")
        if !providers.isEmpty {
            elog("note: agent already running — preload args ignored; load with sd ssh-add")
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

                eval "$(sd ssh-agent)"

            The default key ~/.ssh/id_sod is served automatically (no `sd ssh-add` needed);
            drop it with `sd ssh-add -d`/`-D`. Use `ssh` as usual; Touch ID is requested on
            each signature. Extra handle files or directories given as arguments are also
            loaded when the agent starts.
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

    @Flag(
        name: .long,
        help: """
            Permit agent forwarding (ssh -A). Off by default: the agent refuses to sign for or \
            list keys over a forwarded connection, so a remote host can't use this Secure-Enclave \
            key. ProxyJump (-J) and direct connections are unaffected either way.
            """)
    var allowAgentForwarding = false

    @Flag(name: .long, help: ArgumentHelp(visibility: .private))  // internal: invoked by the lazy-spawn path
    var daemon = false

    @Argument(help: "Handle files or directories to preload.")
    var providers: [String] = []

    public init() {}

    public func run() throws {
        let sock = expandTilde(socket ?? "~/.ssh/sod-agent.sock")
        let provs = providers.map { expandTilde($0) }

        let allowFwd = allowAgentForwarding
        if kill { killAgent(socketPath: sock) }  // Never
        if daemon { runListen(socketPath: sock, providers: provs, detach: true, allowForwarding: allowFwd) }  // Never
        if foreground {
            runListen(socketPath: sock, providers: provs, detach: false, allowForwarding: allowFwd)  // Never
        }

        let dialect = csh ? "csh" : (sh ? "sh" : detectDialect())
        ensureAndEmit(socketPath: sock, providers: provs, dialect: dialect, allowForwarding: allowFwd)  // Never
    }
}
