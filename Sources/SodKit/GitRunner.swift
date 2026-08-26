import Foundation

/// Hardened wrapper over the git binary. It NEVER goes through a shell: it execs
/// `/usr/bin/git` directly with an argv array (Foundation `Process`), so argument values
/// cannot inject commands — the same discipline GitHub's own CLI uses (cli/safeexec + argv
/// arrays). Config *keys* are always hardcoded literals at the call sites; only *values*
/// vary, and callers validate them before they reach here.
enum GitRunner {
    /// Absolute path — never resolved via `$PATH`, so a `git` shadowing us earlier on PATH
    /// (or in the current directory) cannot be run.
    static let binary = URL(fileURLWithPath: "/usr/bin/git")

    struct Result {
        let status: Int32
        let stdout: String
        let stderr: String
        var ok: Bool { status == 0 }
    }

    /// Env vars that redirect where git reads/writes config, which repo it targets, or how
    /// it makes SSH connections. Scrubbed so the process working directory is the only
    /// authority over which repo we touch. (`HOME` is intentionally kept.)
    private static let scrubbedEnv = [
        "GIT_CONFIG", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_CONFIG_COUNT",
        "GIT_DIR", "GIT_WORK_TREE", "GIT_SSH_COMMAND",
    ]

    static func isInstalled() -> Bool { FileManager.default.isExecutableFile(atPath: binary.path) }

    /// Run `git <args>` with no shell. `repo`, when given, sets the working directory (so
    /// `--local` config and `rev-parse` act on that repo). Captures stdout/stderr; never throws.
    static func run(_ args: [String], in repo: URL? = nil) -> Result {
        let p = Process()
        p.executableURL = binary
        p.arguments = args
        if let repo { p.currentDirectoryURL = repo }

        var env = ProcessInfo.processInfo.environment
        for k in scrubbedEnv { env.removeValue(forKey: k) }
        env["GIT_TERMINAL_PROMPT"] = "0"  // never block waiting on a credential prompt
        env["LC_ALL"] = "C"  // stable, parseable messages
        p.environment = env

        let outPipe = Pipe(), errPipe = Pipe()
        p.standardOutput = outPipe
        p.standardError = errPipe
        p.standardInput = FileHandle.nullDevice
        do {
            try p.run()
        } catch {
            return Result(status: -1, stdout: "", stderr: "could not exec \(binary.path): \(error)")
        }
        // Read stdout then stderr, then wait. Safe against pipe-buffer deadlock here because
        // every git command we run (config get/set, rev-parse, remote get-url) produces only
        // a few bytes — far below the ~64 KB pipe buffer. Don't reuse this helper for commands
        // with large output without draining the pipes concurrently.
        let outData = outPipe.fileHandleForReading.readDataToEndOfFile()
        let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return Result(
            status: p.terminationStatus,
            stdout: String(decoding: outData, as: UTF8.self),
            stderr: String(decoding: errData, as: UTF8.self))
    }

    /// `git config --local --get <key>` — reads the REPO-LOCAL value only (not the merged /
    /// global value). Returns nil when the key is unset (git exits 1).
    static func configGet(_ key: String, in repo: URL? = nil) -> String? {
        let r = run(["config", "--local", "--get", key], in: repo)
        guard r.ok else { return nil }
        let v = r.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        return v.isEmpty ? nil : v
    }

    /// `git config --get <key>` — reads the MERGED / effective value (local → global → system).
    /// Used to decide whether the user already has an identity (e.g. a global `user.email`) that
    /// we must respect rather than shadow with a repo-local one. Returns nil when unset.
    static func configGetMerged(_ key: String, in repo: URL? = nil) -> String? {
        let r = run(["config", "--get", key], in: repo)
        guard r.ok else { return nil }
        let v = r.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        return v.isEmpty ? nil : v
    }

    /// `git config --local <key> <value>` — writes to the current repo's `.git/config`.
    @discardableResult
    static func configSet(_ key: String, _ value: String, in repo: URL? = nil) -> Bool {
        run(["config", "--local", key, value], in: repo).ok
    }

    /// `git config --local --unset <key>` — removes the repo-local value. Git exits 5 when the
    /// key wasn't set locally; we treat that as success (the desired end-state — key absent — is
    /// already met), so only a real failure returns false.
    @discardableResult
    static func configUnset(_ key: String, in repo: URL? = nil) -> Bool {
        let r = run(["config", "--local", "--unset", key], in: repo)
        return r.ok || r.status == 5
    }

    /// True when the working directory is inside a git work tree.
    static func insideWorkTree(in repo: URL? = nil) -> Bool {
        run(["rev-parse", "--is-inside-work-tree"], in: repo).stdout
            .trimmingCharacters(in: .whitespacesAndNewlines) == "true"
    }
}
