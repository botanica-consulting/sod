import Foundation
import SSHWire
import SodKit

/// Peer-derived prompt context — pure, so it runs without a Secure Enclave or mock.
func runPeerContextSuite(_ h: Harness) {
    // ---- ssh destination from argv ----
    h.eq(sshDestination(argv: ["ssh", "user@host"]), "host", "user@host -> host")
    h.eq(sshDestination(argv: ["ssh", "host"]), "host", "bare host")
    h.eq(sshDestination(argv: ["ssh", "-p", "2222", "-i", "/k", "user@host"]), "host", "value options skipped")
    h.eq(sshDestination(argv: ["ssh", "-vT", "-o", "SendEnv=GIT_PROTOCOL", "git@github.com", "git-upload-pack", "'o/r.git'"]),
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
        try FileManager.default.createDirectory(at: repo.appendingPathComponent(".git"), withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: worktree, withIntermediateDirectories: true)
        try "gitdir: /elsewhere".write(to: worktree.appendingPathComponent(".git"), atomically: true, encoding: .utf8)
        try FileManager.default.createDirectory(at: plain, withIntermediateDirectories: true)
    } catch { h.fail("fixture setup failed: \(error)"); return }
    defer { try? FileManager.default.removeItem(at: root) }

    h.eq(gitRepoName(cwd: deep.path), "my-repo", "walks up from a subdirectory")
    h.eq(gitRepoName(cwd: repo.path), "my-repo", "repo root itself")
    h.eq(gitRepoName(cwd: worktree.path), "wt", ".git file (worktree) counts")
    h.eq(gitRepoName(cwd: plain.path), nil, "no .git above -> nil (fixture dir has none)")

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
    let inRepo = PeerContext(pid: 1, executable: "/usr/bin/ssh-keygen", cwd: deep.path, argv: ["ssh-keygen", "-Y", "sign"])
    let toHost = PeerContext(pid: 1, executable: "/usr/bin/ssh", cwd: "/", argv: ["ssh", "-T", "git@github.com"])
    let unsafe = PeerContext(pid: 1, executable: nil, cwd: "/", argv: ["ssh", "evil host"])

    h.eq(signReason(for: gitSig, peer: inRepo), "sign a git commit or tag in my-repo with your sod key", "git + repo context")
    h.eq(signReason(for: gitSig, peer: nil), "sign a git commit or tag with your sod key", "git, no peer -> generic")
    h.eq(signReason(for: gitSig, peer: toHost), "sign a git commit or tag with your sod key", "git, cwd outside any repo -> generic")
    h.eq(signReason(for: userauth, peer: toHost), "log in to github.com over SSH with your sod key", "userauth + host context")
    h.eq(signReason(for: userauth, peer: nil), "log in over SSH with your sod key", "userauth, no peer -> generic")
    h.eq(signReason(for: userauth, peer: unsafe), "log in over SSH with your sod key", "unsafe host name -> generic")
    h.eq(signReason(for: Data([1, 2, 3]), peer: toHost), "sign with your sod key", "unknown payload ignores context")
}
