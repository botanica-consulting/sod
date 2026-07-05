import ArgumentParser
import Foundation
import SEKeyStore

#if canImport(Darwin)
import Darwin
#endif

// MARK: - pure helpers (unit-tested in Tests/SodTests)

/// SSH public-key types we accept in a `.pub` line. (The sod key is always
/// ecdsa-sha2-nistp256; the wider set keeps the parser honest for any key a user points at.)
private let knownSshKeyTypes: Set<String> = [
    "ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
    "ssh-rsa", "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com",
]

/// Parse an OpenSSH `.pub` line into `(keyType, base64 blob)`, dropping any comment. Returns
/// nil if the first line isn't `<known-keytype> <base64-blob> [comment]`.
public func parsePubKeyTypeBlob(_ line: String) -> (keyType: String, blob: String)? {
    let firstLine = line.split(whereSeparator: \.isNewline).first.map(String.init) ?? line
    let fields = firstLine.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
    guard fields.count >= 2 else { return nil }
    let keyType = fields[0], blob = fields[1]
    guard knownSshKeyTypes.contains(keyType), Data(base64Encoded: blob) != nil else { return nil }
    return (keyType, blob)
}

/// Build an `allowed_signers` entry `<email> <keytype> <blob>` (comment dropped). nil if the
/// `.pub` is malformed.
public func allowedSignersLine(email: String, pubLine: String) -> String? {
    guard let (keyType, blob) = parsePubKeyTypeBlob(pubLine) else { return nil }
    return "\(email) \(keyType) \(blob)"
}

/// Whether `contents` already lists the key from `line`. Matches on the base64 blob token
/// (a long, unique string), ignoring comments, blank lines, principals, and any options — so
/// it dedupes correctly regardless of how the existing entry is written.
public func allowedSignersContains(contents: String, line: String) -> Bool {
    let ourFields = line.split(separator: " ").map(String.init)
    guard ourFields.count >= 3 else { return false }
    let blob = ourFields[2]
    for raw in contents.split(whereSeparator: \.isNewline) {
        let l = raw.trimmingCharacters(in: .whitespaces)
        if l.isEmpty || l.hasPrefix("#") { continue }
        if l.split(separator: " ").map(String.init).contains(blob) { return true }
    }
    return false
}

/// Cheap sanity check (not full RFC 5322): exactly one `@`, non-empty local + dotted domain,
/// no whitespace/control chars, doesn't start with `-`. Rejects garbage/injection before a
/// value reaches an argv.
public func isPlausibleEmail(_ s: String) -> Bool {
    guard !s.isEmpty, !s.hasPrefix("-") else { return false }
    if s.unicodeScalars.contains(where: { $0.value < 0x20 || $0 == " " }) { return false }
    let parts = s.split(separator: "@", omittingEmptySubsequences: false)
    guard parts.count == 2, !parts[0].isEmpty, !parts[1].isEmpty, parts[1].contains(".") else { return false }
    return true
}

/// Extract the owner from a GitHub remote URL — `git@github.com:owner/repo.git` or
/// `https://github.com/owner/repo(.git)`. nil if it isn't a github.com remote.
public func gitHubOwnerFromRemote(_ remote: String) -> String? {
    guard let r = remote.range(of: "github.com") else { return nil }
    let tail = remote[r.upperBound...].drop { $0 == ":" || $0 == "/" }
    guard let owner = tail.split(separator: "/").first, !owner.isEmpty else { return nil }
    return String(owner)
}

/// Extract the email from a git ident string like `Name <email> 1700000000 +0000`.
public func emailFromIdent(_ ident: String) -> String? {
    guard let lt = ident.firstIndex(of: "<") else { return nil }
    let after = ident.index(after: lt)
    guard let gt = ident[after...].firstIndex(of: ">") else { return nil }
    let email = String(ident[after..<gt])
    return email.isEmpty ? nil : email
}

// MARK: - plan model (pure)

/// A snapshot of the repo's current git-signing config, gathered by the I/O layer and handed
/// to the pure planner.
public struct GitSigningState: Equatable {
    public var gpgFormat: String?
    public var signingKey: String?
    public var allowedSignersFile: String?
    public var tagSign: Bool
    public var commitSignOn: Bool  // reported only — never set by us
    public var allowedSignersHasLine: Bool
    public init(
        gpgFormat: String? = nil, signingKey: String? = nil, allowedSignersFile: String? = nil,
        tagSign: Bool = false, commitSignOn: Bool = false, allowedSignersHasLine: Bool = false
    ) {
        self.gpgFormat = gpgFormat
        self.signingKey = signingKey
        self.allowedSignersFile = allowedSignersFile
        self.tagSign = tagSign
        self.commitSignOn = commitSignOn
        self.allowedSignersHasLine = allowedSignersHasLine
    }
}

/// The target configuration. We deliberately do NOT model `user.name`/`user.email`: git
/// synthesizes an identity for the tag on its own, so we never set or prompt for one — we only
/// need the effective email to use as the `allowed_signers` principal.
public struct GitSigningDesired: Equatable {
    public let pubPath: String
    public let allowedSignersPath: String
    public let email: String
    public let allowedSignersLine: String
    public let signTags: Bool
    public init(
        pubPath: String, allowedSignersPath: String, email: String, allowedSignersLine: String,
        signTags: Bool
    ) {
        self.pubPath = pubPath
        self.allowedSignersPath = allowedSignersPath
        self.email = email
        self.allowedSignersLine = allowedSignersLine
        self.signTags = signTags
    }
}

public enum GitSigningChange: Equatable {
    case setConfig(key: String, value: String)
    case appendAllowedSigners(path: String, line: String)
}

/// One line item in the plan, so the confirm UI can render ✓ / • / ✗ / ! and the applier can
/// filter to just the actual `.change`s.
public enum PlanItem: Equatable {
    case satisfied(String)  // already correct → ✓
    case change(GitSigningChange, describe: String)  // will modify → •
    case conflict(key: String, current: String, desired: String, describe: String)  // ✗, blocks unless --force
    case note(String)  // informational → !
}

public struct GitSigningPlan: Equatable {
    public let items: [PlanItem]
    public init(_ items: [PlanItem]) { self.items = items }

    public var changes: [GitSigningChange] {
        items.compactMap { if case let .change(c, _) = $0 { return c } else { return nil } }
    }
    public var hasConflicts: Bool {
        items.contains { if case .conflict = $0 { return true } else { return false } }
    }
    public var isNoop: Bool { changes.isEmpty && !hasConflicts }
}

/// Pure planner: compare current state to the desired config and produce the ordered list of
/// items. No I/O — this is the unit-tested core (like `sshCopyIdArgs` / `parsePlistProgram`).
public func computeGitSigningPlan(
    current: GitSigningState, desired: GitSigningDesired, force: Bool
) -> GitSigningPlan {
    var items: [PlanItem] = []

    func scalar(_ key: String, _ have: String?, _ want: String) {
        if have == nil {
            items.append(.change(.setConfig(key: key, value: want), describe: "git config --local \(key) \(want)"))
        } else if have == want {
            items.append(.satisfied("\(key) already \(want)"))
        } else if force {
            items.append(
                .change(
                    .setConfig(key: key, value: want),
                    describe: "git config --local \(key) \(want)   (overwrites \(have!))"))
        } else {
            items.append(
                .conflict(
                    key: key, current: have!, desired: want,
                    describe: "\(key) is \(have!) — refusing to overwrite (use --force)"))
        }
    }

    scalar("gpg.format", current.gpgFormat, "ssh")
    scalar("user.signingkey", current.signingKey, desired.pubPath)
    scalar("gpg.ssh.allowedSignersFile", current.allowedSignersFile, desired.allowedSignersPath)

    // allowed_signers line — additive only (never a conflict; we only add our own line).
    if current.allowedSignersHasLine {
        items.append(.satisfied("allowed_signers already lists your key"))
    } else {
        items.append(
            .change(
                .appendAllowedSigners(path: desired.allowedSignersPath, line: desired.allowedSignersLine),
                describe: "append to \(desired.allowedSignersPath):\n        \(desired.allowedSignersLine)"))
    }

    // tag.gpgsign — only when explicitly requested.
    if desired.signTags {
        if current.tagSign {
            items.append(.satisfied("tag.gpgsign already true"))
        } else {
            items.append(
                .change(.setConfig(key: "tag.gpgsign", value: "true"), describe: "git config --local tag.gpgsign true"))
        }
    }

    // commit.gpgsign — never a change; only flag it if already on (every commit would prompt).
    if current.commitSignOn {
        items.append(
            .note(
                "commit.gpgsign is on — every commit will prompt for Touch ID (unset: git config --unset commit.gpgsign)"
            ))
    }

    return GitSigningPlan(items)
}

// MARK: - command

public struct SetupGitSigning: ParsableCommand {
    public static let configuration = CommandConfiguration(
        commandName: "setup-git-signing",
        abstract: "Configure this repo to sign git tags/commits with your Secure-Enclave key.",
        discussion: """
            Points git's SSH signing at your sod public key (~/.ssh/id_sod.pub), served by the
            agent so Touch ID gates each signature. It configures the CURRENT repository only
            (.git/config) — no global config. It detects the current state, prints an explicit
            plan, and asks before changing anything; it is idempotent and refuses to overwrite
            an existing signing config (e.g. GPG) without --force. It sets gpg.format=ssh,
            user.signingkey, gpg.ssh.allowedSignersFile, and appends your key to the
            allowed_signers file. It never touches your git identity (user.name/user.email) and
            never prompts for an email — it derives the signer from git's own committer identity.
            It never sets commit.gpgsign, so ordinary commits are not signed and never prompt;
            sign deliberately with `git commit -S` / `git tag -s`, or opt into annotated tags
            with --sign-tags.
            """
    )

    @Flag(name: .long, help: "Also set tag.gpgsign=true (sign annotated tags).")
    var signTags = false

    @Option(
        name: .long,
        help: ArgumentHelp(
            "Override the allowed_signers principal (default: git's committer email).", valueName: "email"))
    var email: String?

    @Option(name: .long, help: ArgumentHelp("Public key file (default ~/.ssh/id_sod.pub).", valueName: "keyfile"))
    var key: String?

    @Flag(name: [.customShort("y"), .long], help: "Assume yes: apply without prompting.")
    var yes = false

    @Flag(name: .long, help: "Overwrite a conflicting existing signing config.")
    var force = false

    public init() {}

    public func run() throws {
        let stderr = FileHandle.standardError
        func fail(_ msg: String) -> Error {
            stderr.write(Data("sd setup-git-signing: \(msg)\n".utf8))
            return ExitCode.failure
        }

        // 1. git present (absolute path — the same binary GitRunner uses).
        guard GitRunner.isInstalled() else {
            throw fail(
                "git not found at \(GitRunner.binary.path) — install the Xcode Command Line Tools:  xcode-select --install"
            )
        }

        // 2. Inside a repo — signing is configured per-repo.
        guard GitRunner.insideWorkTree() else {
            throw ValidationError("run this inside a git repository — git SSH signing is configured per-repo")
        }

        // 3. Resolve + validate the public key.
        let pubPath = absolutePath(expandTilde(key ?? "~/.ssh/id_sod.pub"))
        guard !pubPath.hasPrefix("-") else { throw fail("refusing key path that starts with '-': \(pubPath)") }
        guard FileManager.default.fileExists(atPath: pubPath) else {
            throw fail("\(pubPath) not found — create your key first:  sd ssh-keygen")
        }
        guard let pubContents = try? String(contentsOfFile: pubPath, encoding: .utf8),
            parsePubKeyTypeBlob(pubContents) != nil
        else {
            throw fail("\(pubPath) is not a valid SSH public-key line (point --key at the .pub, not the opaque handle)")
        }

        // 4. Signer email for the allowed_signers principal. We never set user.name/user.email
        //    and never prompt: git already synthesizes an identity for the tag (config → env →
        //    GECOS + hostname), so we derive the exact email it will stamp and match it, so local
        //    `git tag -v` verifies. (The GitHub Verified badge is separate — it checks the tagger
        //    email, i.e. git's user.email, so that must be a verified GitHub email.)
        let effectiveEmail: String
        if let flag = email {
            guard isPlausibleEmail(flag) else { throw fail("implausible --email: \(flag)") }
            effectiveEmail = flag
        } else if let derived = gitCommitterEmail() {
            effectiveEmail = derived
        } else {
            throw fail("git could not determine your identity — set user.email or pass --email")
        }

        // 5. Build the desired config.
        let allowedSignersPath = absolutePath(expandTilde("~/.ssh/allowed_signers"))
        guard let signersLine = allowedSignersLine(email: effectiveEmail, pubLine: pubContents) else {
            throw fail("could not build an allowed_signers line from \(pubPath)")
        }
        let desired = GitSigningDesired(
            pubPath: pubPath, allowedSignersPath: allowedSignersPath, email: effectiveEmail,
            allowedSignersLine: signersLine, signTags: signTags)

        // 6. Read current state (repo-local) and compute the plan (pure).
        let signersContents = (try? String(contentsOfFile: allowedSignersPath, encoding: .utf8)) ?? ""
        let current = GitSigningState(
            gpgFormat: GitRunner.configGet("gpg.format"),
            signingKey: GitRunner.configGet("user.signingkey"),
            allowedSignersFile: GitRunner.configGet("gpg.ssh.allowedSignersFile"),
            tagSign: gitConfigBool("tag.gpgsign"),
            commitSignOn: gitConfigBool("commit.gpgsign"),
            allowedSignersHasLine: allowedSignersContains(contents: signersContents, line: signersLine))
        let plan = computeGitSigningPlan(current: current, desired: desired, force: force)

        // 7. Render, branch, apply.
        renderPlan(plan)
        if plan.isNoop {
            print("\ngit SSH signing is already configured for this repo. Nothing to do.")
            return
        }
        if plan.hasConflicts && !force {
            print("\nRefusing to overwrite the existing signing config. Re-run with --force to replace it.")
            throw ExitCode.failure
        }
        if !yes && !askApply() {
            print("Aborted — nothing changed.")
            return
        }
        print("")
        try applyChanges(plan.changes, stderr: stderr)
        printFooter(desired: desired)
    }
}

// MARK: - I/O helpers (file-private; not pure, not tested here)

private func absolutePath(_ p: String) -> String {
    p.hasPrefix("/") ? p : (FileManager.default.currentDirectoryPath as NSString).appendingPathComponent(p)
}

/// Interpret a git-config boolean value (`git config` prints these as literals).
private func gitConfigBool(_ key: String) -> Bool {
    ["true", "yes", "on", "1"].contains((GitRunner.configGet(key) ?? "").lowercased())
}

/// The email git will stamp on the tag — its effective committer identity (config → env →
/// auto-derived from GECOS + hostname). We never set it; we only match it in allowed_signers.
private func gitCommitterEmail() -> String? {
    let r = GitRunner.run(["var", "GIT_COMMITTER_IDENT"])
    guard r.ok else { return nil }
    return emailFromIdent(r.stdout.trimmingCharacters(in: .whitespacesAndNewlines))
}

private func renderPlan(_ plan: GitSigningPlan) {
    let paint = AnsiPaint(1)
    print("\n\(paint("sd setup-git-signing — plan (this repo)", "1"))\n")
    for item in plan.items {
        switch item {
        case .satisfied(let s): print("  \(paint("✓", "32")) \(s)")
        case .change(_, let d): print("  \(paint("•", "33")) \(d)")
        case .conflict(_, _, _, let d): print("  \(paint("✗", "31")) \(d)")
        case .note(let s): print("  \(paint("!", "33")) \(s)")
        }
    }
}

private func askApply() -> Bool {
    guard isatty(0) != 0 else {
        print("\nNon-interactive: re-run with -y to apply.")
        return false
    }
    FileHandle.standardOutput.write(Data("\nApply these changes? [y/N] ".utf8))
    let a = (readLine() ?? "").trimmingCharacters(in: .whitespaces).lowercased()
    return a == "y" || a == "yes"
}

private func applyChanges(_ changes: [GitSigningChange], stderr: FileHandle) throws {
    let paint = AnsiPaint(1)
    for change in changes {
        switch change {
        case .setConfig(let key, let value):
            guard GitRunner.configSet(key, value) else {
                stderr.write(Data("sd setup-git-signing: failed to set \(key)\n".utf8))
                throw ExitCode.failure
            }
            print("  \(paint("✓", "32")) set \(key) = \(value)")
        case .appendAllowedSigners(let path, let line):
            try appendAllowedSigners(path: path, line: line)
            print("  \(paint("✓", "32")) added your key to \(path)")
        }
    }
}

/// Append `line` to the allowed_signers file, creating the dir (0700) and file (0644) if
/// needed. On an existing file it appends in place (preserving its permissions and other
/// entries); it never rewrites lines it didn't add.
private func appendAllowedSigners(path: String, line: String) throws {
    let fm = FileManager.default
    let parent = (path as NSString).deletingLastPathComponent
    if !parent.isEmpty && !fm.fileExists(atPath: parent) {
        try fm.createDirectory(
            atPath: parent, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    }
    if fm.fileExists(atPath: path) {
        let existing = (try? String(contentsOfFile: path, encoding: .utf8)) ?? ""
        let prefix = (!existing.isEmpty && !existing.hasSuffix("\n")) ? "\n" : ""
        let fh = try FileHandle(forWritingTo: URL(fileURLWithPath: path))
        defer { try? fh.close() }
        fh.seekToEndOfFile()
        fh.write(Data((prefix + line + "\n").utf8))
    } else {
        guard fm.createFile(atPath: path, contents: Data((line + "\n").utf8), attributes: [.posixPermissions: 0o644])
        else {
            throw ExitCode.failure
        }
    }
}

private func printFooter(desired: GitSigningDesired) {
    print("")
    print("Done — this repo now signs with your Secure-Enclave key over SSH.")
    print("Commits are NOT auto-signed (by design). Sign deliberately:")
    print("    git tag -s <tag> -m <msg>     # ← Touch ID")
    print("    git commit -S                 # a single signed commit")
    if desired.signTags { print("Annotated tags will be signed automatically (tag.gpgsign=true).") }
    print("The sod agent must be running for Touch ID to work (sd install / sd doctor).")
    print("")
    print("Signing as \(desired.email). For GitHub's green \"Verified\" badge, git's own")
    print("user.email must be a verified GitHub email (that's the tagger line GitHub checks),")
    print("and the key must be registered as a Signing key — check:  sd doctor --github")
}
