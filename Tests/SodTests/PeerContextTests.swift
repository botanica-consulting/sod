import Foundation
import SSHWire
import SodKit

/// Peer-derived prompt context — pure, so it runs without a Secure Enclave or mock.
func runPeerContextSuite(_ h: Harness) {
    // ---- ssh destination from argv ----
    h.eq(sshDestination(argv: ["ssh", "user@host"]), "host", "user@host -> host")
    h.eq(sshDestination(argv: ["ssh", "host"]), "host", "bare host")
    h.eq(sshDestination(argv: ["ssh", "-p", "2222", "-i", "/k", "user@host"]), "host", "value options skipped")
    h.eq(
        sshDestination(argv: [
            "ssh", "-vT", "-o", "SendEnv=GIT_PROTOCOL", "git@github.com", "git-upload-pack", "'o/r.git'",
        ]),
        "github.com", "git's ssh invocation -> github.com, command args ignored")
    h.eq(sshDestination(argv: ["ssh", "-J", "jump", "target"]), "target", "-J consumes its jump host")
    h.eq(sshDestination(argv: ["ssh", "-p2222", "host"]), "host", "attached option value")
    h.eq(sshDestination(argv: ["ssh", "-4A", "host"]), "host", "flag cluster without values")
    h.eq(sshDestination(argv: ["ssh", "-l", "root", "host"]), "host", "-l user consumed")
    h.eq(sshDestination(argv: ["ssh", "ssh://user@host:2200/"]), "host", "ssh:// URL form")
    h.eq(sshDestination(argv: ["ssh", "ssh://[fe80::1]:22"]), "fe80::1", "ssh:// IPv6 literal")
    h.eq(sshDestination(argv: ["ssh", "--", "-weird"]), "-weird", "-- ends options")
    h.eq(sshDestination(argv: ["ssh", "-p", "22"]), nil, "no destination -> nil")
    h.eq(sshDestination(argv: []), nil, "empty argv -> nil")

    // ---- repo name from a working directory ----
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("sod-peer-\(getpid())", isDirectory: true)
    let repo = root.appendingPathComponent("my-repo", isDirectory: true)
    let deep = repo.appendingPathComponent("Sources/Deep", isDirectory: true)
    let worktree = root.appendingPathComponent("wt", isDirectory: true)
    let plain = root.appendingPathComponent("plain", isDirectory: true)
    do {
        try FileManager.default.createDirectory(at: deep, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(
            at: repo.appendingPathComponent(".git"), withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: worktree, withIntermediateDirectories: true)
        try "gitdir: /elsewhere".write(to: worktree.appendingPathComponent(".git"), atomically: true, encoding: .utf8)
        try FileManager.default.createDirectory(at: plain, withIntermediateDirectories: true)
    } catch { h.fail("fixture setup failed: \(error)"); return }
    defer { try? FileManager.default.removeItem(at: root) }

    h.eq(gitRepoName(cwd: deep.path), "my-repo", "walks up from a subdirectory")
    h.eq(gitRepoName(cwd: repo.path), "my-repo", "repo root itself")
    h.eq(gitRepoName(cwd: worktree.path), "wt", ".git file (worktree) counts")
    h.eq(gitRepoName(cwd: plain.path), nil, "no .git above -> nil (fixture dir has none)")

    // ---- bounded decoding of kernel buffers (hostile inputs) ----
    h.eq(PeerContext.decodeCString([0x41, 0x42, 0x43, 0, 0x44], limit: 5), "ABC", "stops at first NUL")
    h.eq(
        PeerContext.decodeCString([0x41, 0x42, 0x43], limit: 3), "ABC",
        "unterminated buffer -> bounded prefix, no overrun")
    h.eq(PeerContext.decodeCString([0x41, 0x42, 0x43], limit: 2), "AB", "limit shorter than buffer is honoured")
    h.eq(PeerContext.decodeCString([0x41, 0x42], limit: 100), "AB", "limit longer than buffer is clamped to the array")
    h.eq(PeerContext.decodeCString([0, 0x41], limit: 2), nil, "leading NUL -> nil")
    h.eq(PeerContext.decodeCString([], limit: 10), nil, "empty -> nil")
    h.eq(PeerContext.decodeCString([0x41], limit: -1), nil, "negative limit -> nil")
    h.eq(
        PeerContext.decodeCString([0xff, 0xfe, 0x41], limit: 3), "\u{FFFD}\u{FFFD}A",
        "invalid UTF-8 replaced, not trapped")

    func procArgs(argc: Int32, _ items: [String], env: [String] = ["HOME=/x"]) -> [UInt8] {
        var out = withUnsafeBytes(of: argc.littleEndian) { Array($0) }
        for s in items { out += Array(s.utf8) + [0] }
        out += [0, 0, 0]  // the padding the kernel leaves after the exec path
        for s in env { out += Array(s.utf8) + [0] }
        return out
    }
    h.eq(
        PeerContext.parseProcArgs(procArgs(argc: 2, ["/usr/bin/ssh", "ssh", "host"])), ["ssh", "host"],
        "well-formed image")
    h.eq(
        PeerContext.parseProcArgs(procArgs(argc: 5, ["/usr/bin/ssh", "ssh", "host"])), ["ssh", "host", "HOME=/x"],
        "argc overclaims -> bounded by what's present (environment may leak into the tail, never past the buffer)")
    h.eq(
        PeerContext.parseProcArgs(procArgs(argc: 1, ["/usr/bin/ssh", "ssh", "host"])), ["ssh"],
        "argc underclaims -> truncated")
    h.eq(PeerContext.parseProcArgs(procArgs(argc: 0, ["/usr/bin/ssh", "ssh"])), [], "argc 0 -> nothing")
    h.eq(PeerContext.parseProcArgs(procArgs(argc: -1, ["/usr/bin/ssh", "ssh"])), [], "negative argc -> nothing")
    h.eq(PeerContext.parseProcArgs(procArgs(argc: Int32.max, ["/usr/bin/ssh", "ssh"])), [], "absurd argc -> refused")
    h.eq(
        PeerContext.parseProcArgs(procArgs(argc: Int32(PeerContext.maxArgc + 1), ["/usr/bin/ssh", "ssh"])), [],
        "argc above cap -> refused")
    h.eq(PeerContext.parseProcArgs([]), [], "empty image -> nothing")
    h.eq(PeerContext.parseProcArgs([2, 0, 0, 0]), [], "argc only, no strings -> nothing")
    h.eq(PeerContext.parseProcArgs([2, 0, 0]), [], "truncated argc -> nothing")
    h.eq(
        PeerContext.parseProcArgs([2, 0, 0, 0, 0x41, 0x42]), [],
        "exec path only, unterminated -> nothing (dropped as argv[0])")
    h.ok(PeerContext.maxProcArgsBytes == 1 << 20, "ARG_MAX cap is 1 MiB")

    // ---- repo walk is bounded and path-validated ----
    h.eq(gitRepoName(cwd: "relative/path"), nil, "relative cwd rejected")
    h.eq(gitRepoName(cwd: String(repeating: "/a", count: 600)), nil, "over-long cwd rejected")
    h.eq(gitRepoName(cwd: deep.path, maxDepth: 1), nil, "depth cap stops the walk before the repo root")
    h.eq(gitRepoName(cwd: deep.path, maxDepth: 3), "my-repo", "within the cap the repo is found")

    // ---- the live kernel path: a socketpair makes this process its own peer, and a loopback
    // TCP connection to ourselves gives that peer an established socket to report ----
    var fds: [Int32] = [0, 0]
    let loop = LoopbackTCP()
    defer { loop?.tearDown() }
    if socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0 {
        defer { close(fds[0]); close(fds[1]) }
        if let me = PeerContext.capture(fd: fds[0]) {
            h.eq(me.pid, getpid(), "socketpair peer is ourselves")
            h.ok(
                me.executable?.hasSuffix("sod-tests") == true,
                "executable resolved via proc_pidpath: \(me.executable ?? "nil")")
            let want = URL(fileURLWithPath: FileManager.default.currentDirectoryPath).resolvingSymlinksInPath().path
            h.eq(
                me.cwd.map { URL(fileURLWithPath: $0).resolvingSymlinksInPath().path }, want,
                "cwd resolved via proc_pidinfo")
            h.ok(
                !me.argv.isEmpty && me.argv[0].hasSuffix("sod-tests"),
                "argv resolved via KERN_PROCARGS2: \(me.argv.first ?? "nil")")
            if let loop {
                h.ok(
                    me.remotes.contains(RemoteEndpoint(address: "127.0.0.1", port: loop.port)),
                    "established TCP connection reported via proc_pidfdinfo: \(me.remotes)")
            } else {
                h.fail("loopback TCP fixture failed")
            }
        } else {
            h.fail("PeerContext.capture returned nil for a same-uid socketpair peer (size/uid checks too strict?)")
        }
    } else {
        h.fail("socketpair failed")
    }

    // ---- sanitizer ----
    h.ok(isSafePromptName("github.com"), "hostname safe")
    h.ok(isSafePromptName("my-repo_2"), "repo name safe")
    h.ok(!isSafePromptName("repo approved by IT"), "spaces rejected")
    h.ok(!isSafePromptName("sod\u{2014}ok"), "non-ASCII rejected")
    h.ok(!isSafePromptName(String(repeating: "a", count: 49)), "over-long rejected")
    h.ok(!isSafePromptName(""), "empty rejected")

    // ---- the reason line, with and without context ----
    let gitSig = Data("SSHSIG".utf8) + SSHWire.string("git") + SSHWire.string("")
    let userauth = SSHWire.string(Data(repeating: 0xab, count: 32)) + Data([50]) + SSHWire.string("alon")
    let inRepo = PeerContext(
        pid: 1, executable: "/usr/bin/ssh-keygen", cwd: deep.path, argv: ["ssh-keygen", "-Y", "sign"])
    let toHost = PeerContext(pid: 1, executable: "/usr/bin/ssh", cwd: "/", argv: ["ssh", "-T", "git@github.com"])
    let unsafe = PeerContext(pid: 1, executable: nil, cwd: "/", argv: ["ssh", "evil host"])

    h.eq(
        signReason(for: gitSig, peer: inRepo), "sign a git commit or tag in my-repo with your sod key",
        "git + repo context")
    h.eq(signReason(for: gitSig, peer: nil), "sign a git commit or tag with your sod key", "git, no peer -> generic")
    h.eq(
        signReason(for: gitSig, peer: toHost), "sign a git commit or tag with your sod key",
        "git, cwd outside any repo -> generic")
    h.eq(
        signReason(for: userauth, peer: toHost), "log in to github.com over SSH with your sod key",
        "userauth + host context")
    h.eq(signReason(for: userauth, peer: nil), "log in over SSH with your sod key", "userauth, no peer -> generic")
    h.eq(signReason(for: userauth, peer: unsafe), "log in over SSH with your sod key", "unsafe host name -> generic")
    h.eq(signReason(for: Data([1, 2, 3]), peer: toHost), "sign with your sod key", "unknown payload ignores context")

    // ---- the shared fingerprint helper (sd ssh-keygen / sd ssh-add -l) ----
    // github.com's published ED25519 host key; the expected line is `ssh-keygen -lf` on it.
    let ghEd25519 = Data(base64Encoded: "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl")!
    h.eq(
        sshKeyFingerprint(ghEd25519), "SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU",
        "fingerprint matches ssh-keygen -l")

    // ---- the peer's TCP connection names the address ----
    let gh4 = RemoteEndpoint(address: "140.82.121.4", port: 22)
    let gh6 = RemoteEndpoint(address: "2606:50c0:8000::153", port: 22)
    h.eq(sshRemote(remotes: [gh4]), gh4, "exactly one connection -> that one")
    h.eq(sshRemote(remotes: []), nil, "no connection (ProxyJump destination) -> nil")
    h.eq(sshRemote(remotes: [gh4, gh6]), nil, "several connections -> ambiguous, nil")
    h.eq(gh4.promptText, "140.82.121.4", "default port omitted")
    h.eq(RemoteEndpoint(address: "140.82.121.4", port: 2222).promptText, "140.82.121.4:2222", "other port shown")
    h.eq(gh6.promptText, "2606:50c0:8000::153", "IPv6 bare on port 22")
    h.eq(
        RemoteEndpoint(address: "2606:50c0:8000::153", port: 2222).promptText, "[2606:50c0:8000::153]:2222",
        "IPv6 bracketed with a port")
    h.ok(isSafePromptAddress("[2606:50c0:8000::153]:2222"), "rendered address passes the sanitizer")
    h.ok(!isSafePromptAddress("140.82.121.4 (trusted)"), "anything but an address is refused")

    let toHostAt = PeerContext(
        pid: 1, executable: "/usr/bin/ssh", cwd: "/", argv: ["ssh", "-T", "git@github.com"], remotes: [gh4])
    let noName = PeerContext(pid: 1, executable: "/usr/bin/ssh", cwd: "/", argv: [], remotes: [gh4])
    let literal = PeerContext(
        pid: 1, executable: "/usr/bin/ssh", cwd: "/", argv: ["ssh", "140.82.121.4"], remotes: [gh4])
    let jumped = PeerContext(
        pid: 1, executable: "/usr/bin/ssh", cwd: "/", argv: ["ssh", "-J", "jump", "inner"], remotes: [])
    h.eq(
        signReason(for: userauth, peer: toHostAt), "log in to github.com (140.82.121.4) over SSH with your sod key",
        "name + address")
    h.eq(
        signReason(for: userauth, peer: noName), "log in to 140.82.121.4 over SSH with your sod key",
        "address alone still says where")
    h.eq(
        signReason(for: userauth, peer: literal), "log in to 140.82.121.4 over SSH with your sod key",
        "a literal-IP host is not repeated")
    h.eq(
        signReason(for: userauth, peer: jumped), "log in to inner over SSH with your sod key",
        "no connection of its own (ProxyJump) -> name only")
    h.eq(
        signReason(for: gitSig, peer: toHostAt), "sign a git commit or tag with your sod key",
        "git signing ignores connections")
}

/// A TCP connection from this process to itself over loopback — listener, client and the
/// accepted server side — so the process holds ESTABLISHED sockets for `PeerContext.capture`
/// to find. `port` is the listener's, i.e. the remote port the client side reports.
private final class LoopbackTCP {
    private(set) var port: UInt16 = 0
    private var fds: [Int32] = []

    init?() {
        let len = socklen_t(MemoryLayout<sockaddr_in>.size)
        var addr = sockaddr_in()
        addr.sin_len = UInt8(len)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        addr.sin_port = 0  // kernel picks

        let lfd = socket(AF_INET, SOCK_STREAM, 0)
        guard lfd >= 0 else { return nil }
        fds.append(lfd)
        let bound = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(lfd, $0, len) }
        }
        guard bound == 0, listen(lfd, 1) == 0 else { tearDown(); return nil }
        var gotLen = len
        let named = withUnsafeMutablePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(lfd, $0, &gotLen) }
        }
        guard named == 0 else { tearDown(); return nil }
        port = UInt16(bigEndian: addr.sin_port)

        let cfd = socket(AF_INET, SOCK_STREAM, 0)
        guard cfd >= 0 else { tearDown(); return nil }
        fds.append(cfd)
        let connected = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(cfd, $0, len) }
        }
        guard connected == 0 else { tearDown(); return nil }
        let afd = accept(lfd, nil, nil)
        guard afd >= 0 else { tearDown(); return nil }
        fds.append(afd)
    }

    func tearDown() {
        for fd in fds { close(fd) }
        fds = []
    }
}
