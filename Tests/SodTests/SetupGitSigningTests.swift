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

    // --- isPlausibleGitHubUser ---
    h.ok(isPlausibleGitHubUser("0xa10"), "ghuser: alphanumeric")
    h.ok(isPlausibleGitHubUser("botanica-consulting"), "ghuser: internal hyphen")
    h.ok(!isPlausibleGitHubUser(""), "ghuser: empty → false")
    h.ok(!isPlausibleGitHubUser("-nope"), "ghuser: leading hyphen")
    h.ok(!isPlausibleGitHubUser("nope-"), "ghuser: trailing hyphen")
    h.ok(!isPlausibleGitHubUser("a--b"), "ghuser: double hyphen")
    h.ok(!isPlausibleGitHubUser("has space"), "ghuser: whitespace")
    h.ok(!isPlausibleGitHubUser("bad@name"), "ghuser: symbol")
    h.ok(!isPlausibleGitHubUser(String(repeating: "a", count: 40)), "ghuser: over 39 chars")

    // --- githubNoReplyEmail (bare no-reply form; no id lookup / API) ---
    h.eq(githubNoReplyEmail("0xa10"), "0xa10@users.noreply.github.com", "noreply: builds bare form")
    h.ok(githubNoReplyEmail("bad name") == nil, "noreply: implausible username → nil")

    // --- computeGitSigningPlan ---
    let pubPath = "/Users/me/.ssh/id_sod.pub"
    let signersPath = "/Users/me/.ssh/allowed_signers"
    func desired(
        signCommits: Bool = true, signTags: Bool = true, email: String = "me@x.com",
        userEmailToSet: String? = nil
    ) -> GitSigningDesired {
        GitSigningDesired(
            pubPath: pubPath, allowedSignersPath: signersPath, email: email,
            allowedSignersLine: "\(email) ecdsa-sha2-nistp256 QUJDRA==",
            userEmailToSet: userEmailToSet, signCommits: signCommits, signTags: signTags)
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
    // base config signs BOTH commits and tags
    h.ok(
        fresh.changes.contains(.setConfig(key: "commit.gpgsign", value: "true")),
        "plan(fresh): sets commit.gpgsign=true")
    h.ok(fresh.changes.contains(.setConfig(key: "tag.gpgsign", value: "true")), "plan(fresh): sets tag.gpgsign=true")

    // fully configured (both signing bits already on) → no-op
    let full = GitSigningState(
        gpgFormat: "ssh", signingKey: pubPath, allowedSignersFile: signersPath,
        tagSign: true, commitSignOn: true, allowedSignersHasLine: true)
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

    // user.email — derived value written only when the user has no identity anywhere
    let noReply = "me@users.noreply.github.com"
    let setsEmail = computeGitSigningPlan(
        current: GitSigningState(), desired: desired(userEmailToSet: noReply), force: false)
    h.ok(
        setsEmail.changes.contains(.setConfig(key: "user.email", value: noReply)),
        "plan(no identity + derived): sets user.email")
    let keepsEmail = computeGitSigningPlan(
        current: GitSigningState(userEmail: "have@x.com"), desired: desired(userEmailToSet: noReply), force: false)
    h.ok(!setsKey(keepsEmail, "user.email"), "plan(user.email already set): never overwrites it")
    h.ok(keepsEmail.items.contains(.satisfied("user.email already have@x.com (left as-is)")), "plan: notes it left it")

    // opting out on a fresh repo → just skip that bit (nothing on to turn off)
    let noCommits = computeGitSigningPlan(
        current: GitSigningState(), desired: desired(signCommits: false), force: false)
    h.ok(!setsKey(noCommits, "commit.gpgsign"), "plan(--no-auto-sign-commits, fresh): no commit.gpgsign change")
    h.ok(setsKey(noCommits, "tag.gpgsign"), "plan(--no-auto-sign-commits, fresh): still signs tags")
    let noTags = computeGitSigningPlan(current: GitSigningState(), desired: desired(signTags: false), force: false)
    h.ok(!setsKey(noTags, "tag.gpgsign"), "plan(--no-auto-sign-tags, fresh): no tag.gpgsign change")
    h.ok(setsKey(noTags, "commit.gpgsign"), "plan(--no-auto-sign-tags, fresh): still signs commits")

    // opting out of a bit the repo already has ON → unset it (flags idempotent both ways)
    let commitOn = GitSigningState(
        gpgFormat: "ssh", signingKey: pubPath, allowedSignersFile: signersPath,
        tagSign: true, commitSignOn: true, allowedSignersHasLine: true)
    let optOut = computeGitSigningPlan(current: commitOn, desired: desired(signCommits: false), force: false)
    h.ok(
        optOut.changes.contains(.unsetConfig(key: "commit.gpgsign")),
        "plan(--no-auto-sign-commits, already on): unsets it")
    h.ok(
        !optOut.changes.contains(.unsetConfig(key: "tag.gpgsign")),
        "plan(--no-auto-sign-commits): leaves tag.gpgsign on")
}
