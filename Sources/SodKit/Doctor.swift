import ArgumentParser
import CryptoKit  // SecureEnclave.isAvailable
import Foundation
import SEKeyStore
import SSHWire

#if canImport(Darwin)
import Darwin
#endif

/// The running binary's version string. The generated `Build` enum lives in the `sd`
/// executable target, which SodKit can't import, so the entry point injects it here.
public enum SodRuntime {
    // Set exactly once by the executable's entry point before argument parsing begins,
    // then only read — so the unchecked global is safe.
    public nonisolated(unsafe) static var version = "unknown"
}

/// `sd doctor` — a read-only health check of the whole setup. It inspects but never
/// changes anything (consistent with `sd install`, which only prints instructions),
/// prints a check-list with actionable hints, and exits non-zero if anything failed.
public struct Doctor: ParsableCommand {
    public static let configuration = CommandConfiguration(
        commandName: "doctor",
        abstract: "Check that your sod setup is healthy.",
        discussion: """
            Read-only diagnostics: verifies the Secure Enclave, the default key
            ~/.ssh/id_sod, the login agent (installed + loaded), the live socket and the
            key loaded in it, and whether SSH_AUTH_SOCK is set in this shell and exported
            from your shell startup file. It changes nothing; it only prints what to fix.
            Exits non-zero if any check fails.
            """
    )

    public init() {}

    public func run() throws {
        var r = Report()
        let fm = FileManager.default

        // Shared state: resolve the key, the installed plist, and the agent socket once.
        let keyPath = expandTilde("~/.ssh/id_sod")
        let pubPath = keyPath + ".pub"
        let plistPath = LaunchAgentManager.plistPath()
        let plistInstalled = fm.fileExists(atPath: plistPath)
        let plistInfo: (binary: String, socket: String?)? =
            plistInstalled
            ? (try? String(contentsOfFile: plistPath, encoding: .utf8)).flatMap(parsePlistProgram) : nil
        // Probe the sod agent's own socket (the plist's -a, else the default) regardless
        // of whatever SSH_AUTH_SOCK happens to point at in this shell.
        let sock = expandTilde(plistInfo?.socket ?? "~/.ssh/sod-agent.sock")
        let envSock = ProcessInfo.processInfo.environment["SSH_AUTH_SOCK"].flatMap { $0.isEmpty ? nil : $0 }

        r.header("sd doctor — Secure-Enclave SSH health check")

        // 1. Secure Enclave / backend.
        if Backends.isMock {
            r.warn(
                "Backend: development mock (SE_SSH_MOCK)",
                "signs with a plain in-process P-256 key — NOT the Secure Enclave, no Touch ID",
                hint: "rebuild without SE_SSH_MOCK for real protection")
        } else if SecureEnclave.isAvailable {
            r.pass("Secure Enclave available", "keys are device-bound; Touch ID gates every signature")
        } else {
            r.fail(
                "Secure Enclave NOT available", "this Mac has no usable Secure Enclave",
                hint: "needs Apple Silicon or an Intel Mac with a T2 chip")
        }

        // 2. Default key (~/.ssh/id_sod): exists, is a sod handle, has a .pub, sane perms,
        //    and its kind matches this build's backend.
        if !fm.fileExists(atPath: keyPath) {
            r.fail("Default key  ~/.ssh/id_sod", "not found", hint: "create it:  sd ssh-keygen")
        } else if let data = fm.contents(atPath: keyPath) {
            if !HandleFile.isHandleFile(data) {
                r.fail(
                    "Default key  ~/.ssh/id_sod", "exists but is not a sod handle file",
                    hint: "regenerate:  sd ssh-keygen")
            } else {
                var issues: [String] = []
                var hint: String?
                if let dec = HandleFile.decode(data) {
                    let active = Backends.active().kind
                    if dec.kind != active {
                        issues.append(
                            "handle is a \(kindName(dec.kind)) key but this build's backend is "
                                + "\(kindName(active)) — the agent will refuse it")
                    }
                }
                if !fm.fileExists(atPath: pubPath) {
                    issues.append("missing ~/.ssh/id_sod.pub")
                    hint = "regenerate the .pub:  sd ssh-keygen -y -f ~/.ssh/id_sod"
                }
                if let mode = fileMode(keyPath), mode & 0o077 != 0 {
                    issues.append("permissions are \(String(mode, radix: 8)) (expected 600)")
                    hint = hint ?? "tighten it:  chmod 600 ~/.ssh/id_sod"
                }
                if issues.isEmpty {
                    r.pass("Default key  ~/.ssh/id_sod", "valid \(kindName(Backends.active().kind)) handle (+ .pub)")
                } else {
                    r.warn("Default key  ~/.ssh/id_sod", issues.joined(separator: "; "), hint: hint)
                }
            }
        } else {
            r.fail("Default key  ~/.ssh/id_sod", "could not read the file")
        }

        // 3. Login agent (LaunchAgent) installed — and its plist still points at a real
        //    binary (catches drift, e.g. a stale plist left over from a renamed binary).
        if !plistInstalled {
            r.fail("Login agent installed", "no LaunchAgent plist", hint: "install it:  sd install")
        } else if let info = plistInfo {
            if fm.fileExists(atPath: info.binary) {
                r.pass("Login agent installed", tildeSocket(plistPath))
            } else {
                r.warn(
                    "Login agent installed", "plist points at a missing binary: \(info.binary)",
                    hint: "re-run:  sd install")
            }
        } else {
            r.warn("Login agent installed", "could not parse \(tildeSocket(plistPath))", hint: "re-run:  sd install")
        }

        // 4. Login agent loaded into launchd.
        if plistInstalled {
            if LaunchAgentManager.isLoaded() {
                r.pass("Login agent loaded", "launchd is running it (starts at login)")
            } else {
                r.fail("Login agent loaded", "not loaded into launchd", hint: "reload it:  sd install")
            }
        }

        // 5. Agent socket live.
        let live = isSocketLive(sock)
        if live {
            r.pass("Agent socket live", tildeSocket(sock))
        } else {
            r.fail(
                "Agent socket live", "nothing is listening at \(tildeSocket(sock))",
                hint: plistInstalled
                    ? "reload it:  sd install" : "start it:  sd install   (or: eval \"$(sd ssh-agent)\")")
        }

        // 6. Keys loaded in the agent — and specifically the default key.
        if live {
            if let ids = agentIdentities(sock: sock) {
                if ids.isEmpty {
                    r.warn(
                        "Keys loaded in agent", "the agent has no identities",
                        hint: fm.fileExists(atPath: keyPath)
                            ? "id_sod was dropped this session — restart the agent, or re-add:  sd ssh-add"
                            : "the agent auto-serves id_sod once it exists — create it:  sd ssh-keygen")
                } else if idSodLoaded(pubPath: pubPath, ids: ids) {
                    r.pass("Keys loaded in agent", "\(count(ids.count, "identity", "identities")) (incl. id_sod)")
                } else {
                    r.warn(
                        "Keys loaded in agent",
                        "\(count(ids.count, "identity", "identities")), but id_sod is not among them",
                        hint: "load it:  sd ssh-add")
                }
            } else {
                r.warn("Keys loaded in agent", "the agent did not answer a list request")
            }
        }

        // 7. SSH_AUTH_SOCK in the current shell.
        let shellPath = ProcessInfo.processInfo.environment["SHELL"] ?? "/bin/sh"
        let snip = shellSnippet(shellPath: shellPath, socketPath: sock)
        if let e = envSock {
            if expandTilde(e) == sock {
                r.pass("SSH_AUTH_SOCK in this shell", "points at the sod agent")
            } else {
                r.warn(
                    "SSH_AUTH_SOCK in this shell", "set to \(e) — a different agent is active here",
                    hint: "to use sod in this shell:  export SSH_AUTH_SOCK=\(displaySocket(sock))")
            }
        } else {
            r.warn(
                "SSH_AUTH_SOCK in this shell", "not set",
                hint:
                    "open a new shell after adding the startup line below, or run:  export SSH_AUTH_SOCK=\(displaySocket(sock))"
            )
        }

        // 8. Shell startup file wires SSH_AUTH_SOCK at login (for the current shell).
        let rcPath = expandTilde(snip.rcFile)
        let rcContents = (try? String(contentsOfFile: rcPath, encoding: .utf8)) ?? ""
        if rcConfigured(contents: rcContents, socketPath: sock) {
            r.pass("Startup file (\(snip.shell))", "\(snip.rcFile) exports SSH_AUTH_SOCK to the sod agent")
        } else {
            r.warn(
                "Startup file (\(snip.shell))", "\(snip.rcFile) doesn't point SSH_AUTH_SOCK at the sod agent",
                hint: "add to \(snip.rcFile):  \(snip.line)")
        }

        // 9. The binary itself: where it runs from, its version, and whether `sd` is on PATH.
        let exe = executablePath()
        r.pass("sd binary", "\(exe)  (version \(SodRuntime.version))")
        if let onPath = firstOnPath("sd") {
            if onPath != exe {
                r.warn("sd on PATH", "PATH resolves `sd` to \(onPath), not the running binary")
            }
        } else {
            r.warn(
                "sd on PATH", "`sd` is not on your PATH",
                hint:
                    "install it (adds /usr/local/bin/sd):  brew install botanica-consulting/tap/sod  — or: make install"
            )
        }

        r.summary()
        if r.failCount > 0 { throw ExitCode.failure }
    }
}

// MARK: - pure helpers (unit-tested in Tests/SodTests)

/// Pull the program binary and the `-a` socket out of a generated LaunchAgent plist
/// (the format is fixed by `LaunchAgentManager.plist`). A small string scan — no XML
/// dependency. Returns nil if the ProgramArguments array can't be found.
public func parsePlistProgram(_ plist: String) -> (binary: String, socket: String?)? {
    guard let argsKey = plist.range(of: "<key>ProgramArguments</key>") else { return nil }
    let after = plist[argsKey.upperBound...]
    guard let arrStart = after.range(of: "<array>"),
        let arrEnd = after.range(of: "</array>", range: arrStart.upperBound..<after.endIndex)
    else { return nil }
    var rest = after[arrStart.upperBound..<arrEnd.lowerBound]
    var items: [String] = []
    while let s = rest.range(of: "<string>"),
        let e = rest.range(of: "</string>", range: s.upperBound..<rest.endIndex)
    {
        items.append(String(rest[s.upperBound..<e.lowerBound]))
        rest = rest[e.upperBound...]
    }
    guard let bin = items.first else { return nil }
    var socket: String?
    if let i = items.firstIndex(of: "-a"), i + 1 < items.count { socket = items[i + 1] }
    return (bin, socket)
}

/// Whether `contents` (a shell startup file) already exports SSH_AUTH_SOCK pointing at
/// `socketPath`. Tolerant of `$HOME`/`~` forms and quotes; skips comment lines.
public func rcConfigured(contents: String, socketPath: String) -> Bool {
    let home = NSHomeDirectory()
    var forms = [socketPath]
    if socketPath.hasPrefix(home + "/") {
        let tail = String(socketPath.dropFirst(home.count))  // includes leading "/"
        forms.append("$HOME" + tail)
        forms.append("~" + tail)
    }
    for raw in contents.split(whereSeparator: { $0 == "\n" || $0 == "\r" }) {
        let line = raw.trimmingCharacters(in: .whitespaces)
        if line.hasPrefix("#") || !line.contains("SSH_AUTH_SOCK") { continue }
        if forms.contains(where: line.contains) { return true }
    }
    return false
}

// MARK: - private helpers

/// Output sink: prints a colorized (when stdout is a TTY) check-list and tallies results.
private struct Report {
    private let color: Bool
    private(set) var okCount = 0, warnCount = 0, failCount = 0

    init() { color = isatty(1) != 0 }

    private func paint(_ s: String, _ code: String) -> String { color ? "\u{1B}[\(code)m\(s)\u{1B}[0m" : s }

    func header(_ title: String) { print("\n\(paint(title, "1"))\n") }

    private mutating func emit(_ sym: String, _ code: String, _ label: String, _ detail: String?, _ hint: String?) {
        print("  \(paint(sym, code)) \(label)")
        if let d = detail { print("      \(d)") }
        if let h = hint { print("      \(paint("→ " + h, "2"))") }
    }

    mutating func pass(_ label: String, _ detail: String? = nil) { emit("✓", "32", label, detail, nil); okCount += 1 }
    mutating func warn(_ label: String, _ detail: String? = nil, hint: String? = nil) {
        emit("!", "33", label, detail, hint)
        warnCount += 1
    }
    mutating func fail(_ label: String, _ detail: String? = nil, hint: String? = nil) {
        emit("✗", "31", label, detail, hint)
        failCount += 1
    }

    mutating func summary() {
        var parts = ["\(okCount) ok"]
        if warnCount > 0 { parts.append("\(warnCount) warning\(warnCount == 1 ? "" : "s")") }
        if failCount > 0 { parts.append("\(failCount) problem\(failCount == 1 ? "" : "s")") }
        let line = parts.joined(separator: ", ")
        print("")
        if failCount > 0 {
            print(paint("✗ \(line)", "31"))
        } else if warnCount > 0 {
            print(paint("! \(line) — usable, with caveats above", "33"))
        } else {
            print(paint("✓ \(line) — your sod setup looks healthy", "32"))
        }
    }
}

private func kindName(_ k: UInt8) -> String {
    switch k {
    case HandleFile.kindSecureEnclave: return "Secure Enclave"
    case HandleFile.kindMock: return "mock"
    default: return "unknown (\(k))"
    }
}

private func count(_ n: Int, _ one: String, _ many: String) -> String { "\(n) \(n == 1 ? one : many)" }

private func fileMode(_ path: String) -> mode_t? {
    var st = stat()
    guard stat(path, &st) == 0 else { return nil }
    return st.st_mode & 0o777
}

private func firstOnPath(_ name: String) -> String? {
    guard let path = ProcessInfo.processInfo.environment["PATH"] else { return nil }
    for dir in path.split(separator: ":") {
        let p = String(dir) + "/" + name
        if FileManager.default.isExecutableFile(atPath: p) { return p }
    }
    return nil
}

/// Ask the agent for its loaded identities (request 11 → answer 12). Returns the key
/// blobs + comments, or nil if the agent couldn't be reached / gave a bad reply.
private func agentIdentities(sock: String) -> [(blob: Data, comment: String)]? {
    let fd = connectUnix(sock)
    guard fd >= 0 else { return nil }
    defer { close(fd) }
    guard writeAll(fd, SSHWire.frame(type: SSHWire.Agent.requestIdentities)),
        let lenData = readExactly(fd, 4)
    else { return nil }
    var lr = ByteReader(lenData)
    guard let len = try? lr.readUInt32(), len >= 1, Int(len) <= SSHWire.maxAgentMessage,
        let body = readExactly(fd, Int(len)), let type = body.first, type == SSHWire.Agent.identitiesAnswer
    else { return nil }
    var r = ByteReader(Data(body.dropFirst()))
    guard let n = try? r.readUInt32() else { return nil }
    var out: [(blob: Data, comment: String)] = []
    for _ in 0..<n {
        guard let blob = try? r.readString(), let c = try? r.readString() else { return nil }
        out.append((blob, String(decoding: c, as: UTF8.self)))
    }
    return out
}

/// Whether the default key's public blob (`~/.ssh/id_sod.pub`) is among the loaded ids.
private func idSodLoaded(pubPath: String, ids: [(blob: Data, comment: String)]) -> Bool {
    guard let pub = try? String(contentsOfFile: pubPath, encoding: .utf8) else { return false }
    let fields = pub.split(separator: " ")
    guard fields.count >= 2, let blob = Data(base64Encoded: String(fields[1])) else { return false }
    return ids.contains { $0.blob == blob }
}
