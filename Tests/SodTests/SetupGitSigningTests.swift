import Foundation
import SodKit

/// Pure tests for the setup-git-signing planner and helpers. No git binary, no I/O — runs
/// unconditionally (like the Doctor/CopyId helper suites).
func runSetupGitSigningSuite(_ h: Harness) {
    let pub = "ecdsa-sha2-nistp256 QUJDRA== me@host"  // QUJDRA== decodes to "ABCD"

    // --- parsePubKeyTypeBlob ---
    if let (t, b) = parsePubKeyTypeBlob(pub) {
        h.eq(t, "ecdsa-sha2-nistp256", "parsePub: keytype")
        h.eq(b, "QUJDRA==", "parsePub: blob (comment dropped)")
    } else {
        h.fail("parsePub: expected a parse")
    }
    h.ok(parsePubKeyTypeBlob("ecdsa-sha2-nistp256\n") == nil, "parsePub: one field → nil")
    h.ok(parsePubKeyTypeBlob("ecdsa-sha2-nistp256 not!base64!") == nil, "parsePub: bad base64 → nil")
    h.ok(parsePubKeyTypeBlob("ssh-dss QUJDRA==") == nil, "parsePub: unknown keytype → nil")
    if let (t2, _) = parsePubKeyTypeBlob("ecdsa-sha2-nistp256 QUJDRA==\ngarbage") {
        h.eq(t2, "ecdsa-sha2-nistp256", "parsePub: multi-line uses first line")
    } else {
        h.fail("parsePub: multi-line")
    }

    // --- allowedSignersLine ---
    h.eq(
        allowedSignersLine(email: "me@x.com", pubLine: pub), "me@x.com ecdsa-sha2-nistp256 QUJDRA==",
        "signersLine: builds email keytype blob")
    h.ok(allowedSignersLine(email: "me@x.com", pubLine: "junk") == nil, "signersLine: bad pub → nil")

    // --- allowedSignersContains (matches on the blob token) ---
    let line = "me@x.com ecdsa-sha2-nistp256 QUJDRA=="
    h.ok(
        allowedSignersContains(contents: "other@y.com ecdsa-sha2-nistp256 QUJDRA==\n", line: line),
        "contains: same blob, different principal")
    h.ok(
        allowedSignersContains(contents: "# note\n\n  me@x.com ecdsa-sha2-nistp256 QUJDRA==  \n", line: line),
        "contains: ignores comments/blanks/whitespace")
    h.ok(
        !allowedSignersContains(contents: "me@x.com ecdsa-sha2-nistp256 QUJDRQ==\n", line: line),
        "contains: different blob → false")
    h.ok(!allowedSignersContains(contents: "", line: line), "contains: empty → false")

    // --- isPlausibleEmail ---
    h.ok(isPlausibleEmail("me@x.com"), "email: valid")
    h.ok(!isPlausibleEmail("nope"), "email: no @")
    h.ok(!isPlausibleEmail("a@b@c"), "email: two @")
    h.ok(!isPlausibleEmail("-x@y.z"), "email: leading dash")
    h.ok(!isPlausibleEmail("a b@c.d"), "email: whitespace")
    h.ok(!isPlausibleEmail("a@b"), "email: domain without a dot")

    // --- emailFromIdent (extract the email git will stamp) ---
    h.eq(emailFromIdent("Alon Livne <a@b.com> 1700000000 +0000"), "a@b.com", "ident: extracts email")
    h.ok(emailFromIdent("no angle brackets here") == nil, "ident: no <> → nil")
    h.ok(emailFromIdent("Name <> 1 +0") == nil, "ident: empty email → nil")

    // --- gitHubOwnerFromRemote ---
    h.eq(gitHubOwnerFromRemote("git@github.com:botanica-consulting/sod.git"), "botanica-consulting", "remote: scp form")
    h.eq(
        gitHubOwnerFromRemote("https://github.com/botanica-consulting/sod"), "botanica-consulting", "remote: https form"
    )
    h.ok(gitHubOwnerFromRemote("git@gitlab.com:owner/repo.git") == nil, "remote: non-github → nil")

    // --- computeGitSigningPlan ---
    let pubPath = "/Users/me/.ssh/id_sod.pub"
    let signersPath = "/Users/me/.ssh/allowed_signers"
    func desired(signTags: Bool = false, email: String = "me@x.com") -> GitSigningDesired {
        GitSigningDesired(
            pubPath: pubPath, allowedSignersPath: signersPath, email: email,
            allowedSignersLine: "\(email) ecdsa-sha2-nistp256 QUJDRA==",
            signTags: signTags)
    }
    func setsKey(_ plan: GitSigningPlan, _ key: String) -> Bool {
        plan.changes.contains { if case let .setConfig(k, _) = $0 { return k == key } else { return false } }
    }

    // fresh machine → all changes, no conflicts, and it NEVER touches the git identity
    let fresh = computeGitSigningPlan(current: GitSigningState(), desired: desired(), force: false)
    h.ok(!fresh.isNoop, "plan(fresh): not a no-op")
    h.ok(!fresh.hasConflicts, "plan(fresh): no conflicts")
    h.ok(fresh.changes.contains(.setConfig(key: "gpg.format", value: "ssh")), "plan(fresh): sets gpg.format=ssh")
    h.ok(
        fresh.changes.contains(.setConfig(key: "user.signingkey", value: pubPath)), "plan(fresh): sets user.signingkey")
    h.ok(
        fresh.changes.contains(.setConfig(key: "gpg.ssh.allowedSignersFile", value: signersPath)),
        "plan(fresh): sets allowedSignersFile")
    h.ok(
        fresh.changes.contains(.appendAllowedSigners(path: signersPath, line: line)),
        "plan(fresh): appends the signers line")
    h.ok(!setsKey(fresh, "user.email"), "plan(fresh): never sets user.email")
    h.ok(!setsKey(fresh, "user.name"), "plan(fresh): never sets user.name")
    h.ok(!setsKey(fresh, "tag.gpgsign"), "plan(fresh, no --sign-tags): no tag.gpgsign")

    // fully configured → no-op
    let full = GitSigningState(
        gpgFormat: "ssh", signingKey: pubPath, allowedSignersFile: signersPath, allowedSignersHasLine: true)
    h.ok(computeGitSigningPlan(current: full, desired: desired(), force: false).isNoop, "plan(fully configured): no-op")

    // gpg.format conflict
    let openpgp = GitSigningState(gpgFormat: "openpgp")
    let cPlan = computeGitSigningPlan(current: openpgp, desired: desired(), force: false)
    h.ok(cPlan.hasConflicts, "plan(openpgp): conflicts")
    h.ok(!setsKey(cPlan, "gpg.format"), "plan(openpgp, no force): does not change gpg.format")
    let cForce = computeGitSigningPlan(current: openpgp, desired: desired(), force: true)
    h.ok(!cForce.hasConflicts, "plan(openpgp, force): no conflict")
    h.ok(cForce.changes.contains(.setConfig(key: "gpg.format", value: "ssh")), "plan(openpgp, force): sets gpg.format")

    // signingkey conflict
    h.ok(
        computeGitSigningPlan(current: GitSigningState(signingKey: "/other/key.pub"), desired: desired(), force: false)
            .hasConflicts,
        "plan(signingkey conflict): conflicts")

    // allowed_signers already has the line
    let hasLine = GitSigningState(allowedSignersHasLine: true)
    h.ok(
        !computeGitSigningPlan(current: hasLine, desired: desired(), force: false).changes
            .contains(.appendAllowedSigners(path: signersPath, line: line)),
        "plan(signers has line): no append")

    // --sign-tags on → sets tag.gpgsign
    let tags = computeGitSigningPlan(current: GitSigningState(), desired: desired(signTags: true), force: false)
    h.ok(tags.changes.contains(.setConfig(key: "tag.gpgsign", value: "true")), "plan(--sign-tags): sets tag.gpgsign")

    // commit.gpgsign on → never set by us
    let commitOn = GitSigningState(
        gpgFormat: "ssh", signingKey: pubPath, allowedSignersFile: signersPath,
        commitSignOn: true, allowedSignersHasLine: true)
    h.ok(
        !setsKey(computeGitSigningPlan(current: commitOn, desired: desired(), force: false), "commit.gpgsign"),
        "plan: never sets commit.gpgsign")
}
