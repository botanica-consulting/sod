import Darwin
import Foundation

/// Who is on the other end of an agent socket connection, learned from the kernel at accept
/// time: the peer's pid, executable, working directory and argument vector. Used only to make
/// the Touch ID reason more specific ("… in <repo>", "… to <host>").
///
/// Everything here is *advisory*. cwd and argv are under the peer's control, and any process
/// running as the same user can chdir into a repo or fake its argv, so this context guards
/// against a mistimed tap on the wrong request — it is not, and must not be read as, a
/// security control. Nothing in the signing decision depends on it.
///
/// Because the inputs are peer-influenced, every kernel-supplied buffer is decoded by explicit
/// length — never by scanning for a NUL terminator — and every count the kernel reports
/// (`argc`, buffer sizes, struct fill) is range-checked before use.
public struct PeerContext: Sendable {
    public let pid: pid_t
    public let executable: String?
    public let cwd: String?
    public let argv: [String]

    public init(pid: pid_t, executable: String?, cwd: String?, argv: [String]) {
        self.pid = pid
        self.executable = executable
        self.cwd = cwd
        self.argv = argv
    }

    /// Identify the peer of a connected unix-domain socket. Returns nil if the kernel won't say
    /// (not a unix socket, peer already gone) or if the peer is not running as this user —
    /// callers then fall back to the generic prompt.
    public static func capture(fd: Int32) -> PeerContext? {
        var pid: pid_t = 0
        var len = socklen_t(MemoryLayout<pid_t>.size)
        guard getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &pid, &len) == 0,
            len == socklen_t(MemoryLayout<pid_t>.size), pid > 0
        else { return nil }
        // Only describe peers that are us. The socket mode should already guarantee this; the
        // check keeps a root-owned or misconfigured connection from having its context echoed.
        guard ownerUID(of: pid) == getuid() else { return nil }
        return PeerContext(
            pid: pid, executable: executablePath(of: pid), cwd: workingDirectory(of: pid), argv: arguments(of: pid))
    }

    // MARK: kernel queries

    private static func ownerUID(of pid: pid_t) -> uid_t? {
        var info = proc_bsdinfo()
        let want = Int32(MemoryLayout<proc_bsdinfo>.size)
        guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, want) == want else { return nil }
        return info.pbi_uid
    }

    private static func executablePath(of pid: pid_t) -> String? {
        var buf = [UInt8](repeating: 0, count: 4 * Int(MAXPATHLEN))  // PROC_PIDPATHINFO_MAXSIZE
        let n = proc_pidpath(pid, &buf, UInt32(buf.count))
        // proc_pidpath returns the byte count it wrote; trust nothing beyond it.
        guard n > 0, Int(n) <= buf.count else { return nil }
        return decodeCString(buf, limit: Int(n))
    }

    private static func workingDirectory(of pid: pid_t) -> String? {
        var info = proc_vnodepathinfo()
        let want = Int32(MemoryLayout<proc_vnodepathinfo>.size)
        // A short fill means the struct is partly garbage; insist on the whole thing.
        guard proc_pidinfo(pid, PROC_PIDVNODEPATHINFO, 0, &info, want) == want else { return nil }
        // vip_path is a fixed MAXPATHLEN array; copy it out and decode within that bound.
        let bytes = withUnsafeBytes(of: &info.pvi_cdir.vip_path) { Array($0) }
        return decodeCString(bytes, limit: Int(MAXPATHLEN))
    }

    private static func arguments(of pid: pid_t) -> [String] {
        var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
        var size = 0
        guard sysctl(&mib, 3, nil, &size, nil, 0) == 0, size > 4, size <= maxProcArgsBytes else { return [] }
        var raw = [UInt8](repeating: 0, count: size)
        guard sysctl(&mib, 3, &raw, &size, nil, 0) == 0, size > 4, size <= raw.count else { return [] }
        return parseProcArgs(Array(raw.prefix(size)))
    }

    // MARK: bounded decoders (pure; unit-tested with hostile inputs)

    /// The kernel caps a process's argument+environment block at ARG_MAX (1 MiB on macOS);
    /// anything larger is not a real process image and is refused.
    public static let maxProcArgsBytes = 1 << 20
    /// More arguments than this is not a plausible `ssh`/`ssh-keygen` invocation.
    public static let maxArgc = 4096

    /// Decode a C string from `bytes`, reading at most `limit` bytes and stopping at the first
    /// NUL. Never scans past `limit` or past the array, so an unterminated buffer yields the
    /// bounded prefix instead of a read overrun. nil for an empty result.
    public static func decodeCString(_ bytes: [UInt8], limit: Int) -> String? {
        let end = min(max(limit, 0), bytes.count)
        var slice = bytes[0..<end]
        if let nul = slice.firstIndex(of: 0) { slice = bytes[0..<nul] }
        guard !slice.isEmpty else { return nil }
        return String(decoding: slice, as: UTF8.self)
    }

    /// Parse a `KERN_PROCARGS2` image: `int32 argc`, the exec path, NUL padding, then `argc`
    /// NUL-terminated argv strings, then the environment (ignored). `argc` is peer-controlled
    /// in the sense that any process picks its own, so it is range-checked and used only as a
    /// cap — the strings actually present bound the result, never the claimed count.
    public static func parseProcArgs(_ raw: [UInt8]) -> [String] {
        guard raw.count > 4 else { return [] }
        let argc = Int(raw.withUnsafeBytes { $0.loadUnaligned(as: Int32.self) })
        guard argc > 0, argc <= maxArgc else { return [] }
        let strings = raw[4...].split(separator: 0, omittingEmptySubsequences: true)
            .map { String(decoding: $0, as: UTF8.self) }
        // strings[0] is the exec path; argv follows.
        return Array(strings.dropFirst().prefix(argc))
    }
}

// MARK: - pure helpers (unit-tested without a socket)

/// The destination host of an `ssh` invocation, from its argv: the first non-option argument,
/// with `user@`, an `ssh://` scheme and a `:port` stripped. nil if there is none. Understands
/// which single-letter options consume a value so `-p 2222`/`-o Foo=bar`/`-i key` are skipped
/// and `-vT`-style flag clusters don't swallow the host.
public func sshDestination(argv: [String]) -> String? {
    // ssh(1) options that take an argument. Anything else starting with "-" is a bare flag.
    let takesValue: Set<Character> = [
        "B", "b", "c", "D", "E", "e", "F", "I", "i", "J", "L", "l", "m", "O", "o", "p", "P", "Q", "R", "S", "W", "w",
    ]
    var it = argv.dropFirst().makeIterator()
    while let tok = it.next() {
        if tok == "--" { return it.next().flatMap(hostPart) }
        guard tok.hasPrefix("-"), tok.count > 1 else { return hostPart(tok) }
        // A flag cluster ("-vT", "-p", "-p2222"). If a value-taking option ends the cluster, the
        // value is the next token; if it sits mid-cluster the rest of the token is its value.
        let cluster = tok.dropFirst()
        if let last = cluster.last, takesValue.contains(last),
            cluster.count == 1 || !cluster.dropLast().contains(where: takesValue.contains)
        {
            _ = it.next()
        }
    }
    return nil
}

private func hostPart(_ dest: String) -> String? {
    var s = Substring(dest)
    if s.lowercased().hasPrefix("ssh://") {
        s = s.dropFirst("ssh://".count)
        if let slash = s.firstIndex(of: "/") { s = s[..<slash] }
        if let at = s.lastIndex(of: "@") { s = s[s.index(after: at)...] }
        if s.hasPrefix("[") {  // [v6::addr]:port
            if let close = s.firstIndex(of: "]") { s = s[s.index(after: s.startIndex)..<close] }
        } else if let colon = s.lastIndex(of: ":") {
            s = s[..<colon]
        }
    } else if let at = s.lastIndex(of: "@") {
        s = s[s.index(after: at)...]
    }
    return s.isEmpty ? nil : String(s)
}

/// The name of the git repository containing `cwd`: walk upward until a `.git` entry (a
/// directory, or the file a worktree carries) and return that directory's basename. nil if
/// none is found before the filesystem root, or within `maxDepth` components — the path is
/// peer-chosen, so the walk is bounded rather than trusting it to be short.
public func gitRepoName(cwd: String, maxDepth: Int = 64) -> String? {
    guard cwd.hasPrefix("/"), cwd.utf8.count <= Int(MAXPATHLEN) else { return nil }
    var dir = URL(fileURLWithPath: cwd).standardizedFileURL
    let fm = FileManager.default
    for _ in 0..<maxDepth {
        if fm.fileExists(atPath: dir.appendingPathComponent(".git").path) {
            let name = dir.lastPathComponent
            return (name.isEmpty || name == "/") ? nil : name
        }
        let parent = dir.deletingLastPathComponent()
        if parent.path == dir.path { return nil }
        dir = parent
    }
    return nil
}

/// A peer-supplied name is echoed into the Touch ID sheet only if it is short and made of
/// unambiguous characters — so a crafted directory name or hostname can't inject text that
/// reads as part of the system prompt.
public func isSafePromptName(_ s: String) -> Bool {
    !s.isEmpty && s.count <= 48 && s.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || "._-".contains($0)) }
}
