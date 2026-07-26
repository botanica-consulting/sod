---
title: "Touch ID for git signing: a setup and enforcement guide"
description: >
  Sign your git commits and release tags with a Secure Enclave key, so every signature costs
  a fingerprint and none of them can be produced off your Mac. Then make it stick: require
  signed commits with a GitHub ruleset, and gate releases on a signed tag in CI.
date: 2026-07-26
author: Botanica Software Labs
tags: [secure-enclave, touch-id, ssh, git, signing, release-engineering, supply-chain, github]
draft: true
---

<!--
  DRAFT. Text first. Resources to add later:
  - terminal capture of `git commit` triggering the Touch ID sheet
  - screenshot of the "Verified" badge on a sod commit and on a release tag
  - screenshot of the ruleset UI with "Require signed commits" checked
  Marked inline with [resource: …] placeholders.
-->

# Touch ID for git signing: a setup and enforcement guide

> **TL;DR** — Register your [sod](https://github.com/botanica-consulting/sod) key as a GitHub
> *signing* key, run `sd setup-git-signing` in your repo, and every commit and annotated tag
> gets signed by the Secure Enclave behind a Touch ID prompt. Then choose how hard you want it
> enforced: a GitHub ruleset can require signed **commits** on a branch, but GitHub *cannot*
> enforce signed **tags** — that one needs a CI check. Both recipes are below.

This is a how-to. If you want the argument for why hardware-backed signing is different in
kind from a key in `~/.ssh`, [skip to the reasoning](#why-a-secure-enclave-key-changes-the-claim);
otherwise start with [Setup](#part-1-setup).

---

## Part 1: Setup

You need sod installed and running. If it isn't, `sd install` and
[the Quickstart](https://github.com/botanica-consulting/sod#quickstart) take about a minute.
Check it's live before going further — you should be able to run `ssh -T git@github.com` and
see your username come back.

Setup is two halves: a one-time step on **GitHub** (tell it your key is allowed to *sign*),
then one command in your **repo**. sod deliberately never touches your GitHub account, so the
GitHub half is yours to do.

### 1. Register the sod key as a GitHub *signing* key

GitHub keeps *authentication* keys and *signing* keys in separate lists, and the same key can
sit in both. Your sod key is already registered for auth — that's how you push. Now add it a
second time, as a signing key. Without this registration your signatures are valid but GitHub
won't show the green **Verified** badge.

**With the `gh` CLI.** Adding a signing key needs a scope your token probably lacks, so grant
it once:

```sh
gh auth refresh -h github.com -s admin:ssh_signing_key
gh ssh-key add ~/.ssh/id_sod.pub --type signing --title "sod (Secure Enclave)"
```

**Or in the web UI** — no extra scope, nothing to install:

1. Copy the public key: `pbcopy < ~/.ssh/id_sod.pub`
2. Go to **Settings → SSH and GPG keys**, click **New SSH key**.
3. Set **Key type** to **Signing Key** — *not* Authentication Key — paste, title it, **Add SSH key**.
   [screenshot: the New-SSH-key form with Key type = Signing Key]
4. It appears under **SSH keys** with a "Signing Key" label.

### 2. Point the repo's git at the key

One command, run **inside** the repo:

```sh
sd setup-git-signing
```

It prints exactly what it will change, asks before touching anything, and is idempotent — re-run
it whenever. Everything it sets is **repo-local**; your global git config is left alone.

[resource: terminal capture — `sd setup-git-signing` showing its plan and the confirm prompt]

What it configures, and why each one:

| Setting | Value | Why |
|---|---|---|
| `gpg.format` | `ssh` | Sign with SSH keys instead of GPG. |
| `user.signingkey` | `~/.ssh/id_sod.pub` | The **public** key, deliberately — see below. |
| `gpg.ssh.allowedSignersFile` | `~/.ssh/allowed_signers` | So *you* can verify signatures locally. |
| `commit.gpgsign` | `true` | Sign every commit. |
| `tag.gpgsign` | `true` | Sign every annotated tag. |

It also appends your key to `~/.ssh/allowed_signers`, so local verification works immediately.

**Why point at the public key?** This is the load-bearing trick. Handing `user.signingkey` a
*public* key tells `ssh-keygen` to sign through the **ssh-agent** rather than reading a private
key off disk — and sod *is* that agent. So the chain is `git commit` → `ssh-keygen -Y sign` →
sod agent → Secure Enclave → Touch ID. There is no private key file for git to find, because
there is no private key file anywhere. (We tested this the blunt way: replaced the on-disk
private file with garbage. Signing still succeeded through the agent, and verification passed.)

**On the identity it needs.** For GitHub's **Verified** badge, the commit's email must be a
verified GitHub email. If you already have a `user.email` configured, sod leaves it alone. If
you have none, it asks for your GitHub username and sets a repo-local
`user.email=<user>@users.noreply.github.com` — a no-reply address that's verified for your
account by construction, so `--github-user alice` becomes `alice@users.noreply.github.com`.
It never sets `user.name`. (Don't know your username? `gh api user --jq .login`. Under `-y` it
can't prompt, so pass `--github-user` or `--email`.)

**If you don't want a tap per commit**, opt out per kind:

```sh
sd setup-git-signing --no-auto-sign-commits   # tags only; sign commits ad hoc with git commit -S
sd setup-git-signing --no-auto-sign-tags      # commits only
```

These are idempotent in both directions — opting out of a bit the repo already has on turns it
back off. Which of these you want depends on the enforcement tier you pick in Part 2, so decide
that first if you're unsure.

Notice what you didn't do: no `gpg --gen-key`, no keyserver, no expiry to babysit, no
passphrase, no global config to reason about. The key already existed; you gave it a second job.

### 3. Check it actually works

```sh
git commit --allow-empty -m "signing smoke test"   # ← Touch ID
git log --show-signature -1                        # "Good \"git\" signature for you@…"
```

[resource: terminal capture — the macOS Touch ID sheet appearing on `git commit`]

Verification prompts for nothing: it's a public-key operation. Only *signing* costs a finger.

Push it and GitHub should show **Verified** on the commit. If it shows **Unverified**, the
signature is fine but the email doesn't match a verified GitHub address, or the key isn't
registered as a *signing* key — recheck step 1.

---

## Part 2: Enforcement — pick a tier

Setup makes signing your default. It doesn't make it a *rule*: nothing stops you (or a
collaborator, or a stolen token) from pushing unsigned work. That gap is what enforcement
closes, and there are two very different places to close it.

The important thing to know up front, because it's counterintuitive and shapes both recipes:

> **GitHub can require signed commits. GitHub cannot require signed tags.**
> The `required_signatures` ruleset rule only ever inspects commits reachable from a branch.
> Applying it to a ruleset with `target: tag` is accepted by the API and does nothing at all to
> tag objects — an unsigned tag pushes clean. This is a
> [known and acknowledged limitation](https://github.com/orgs/community/discussions/154293)
> with no native fix, which is why Tier B below is a CI job rather than a checkbox.

| | Tier A — all commits | Tier B — releases only |
|---|---|---|
| **Protects** | every commit landing on a branch | the release boundary (tags) |
| **Mechanism** | GitHub ruleset, `required_signatures` | CI job running `git verify-tag` |
| **Enforced by** | GitHub, server-side | your workflow |
| **Taps** | one per commit | one per release |
| **Cost to contributors** | they must sign too | none |

They're complementary, not alternatives. Tier B is the higher-value one — it's the boundary
where "who decided to ship this?" gets answered — and it's the one GitHub won't do for you.

### Tier A: require signed commits on a branch

**In the UI:** **Settings → Rules → Rulesets → New ruleset**, target the branch (or
`~DEFAULT_BRANCH`), and check **Require signed commits**.

**Or via the API.** If you're adding the rule to a ruleset that already exists, there's a trap:
`rules` is replaced **wholesale**, so sending just the new rule silently deletes every other rule
in that ruleset. Read the current rules first, add to them, and send the array back:

```sh
gh api repos/OWNER/REPO/rulesets --jq '.[] | "\(.id)\t\(.name)"'   # find the id
gh api repos/OWNER/REPO/rulesets/RULESET_ID > ruleset.json          # read what's there
# edit ruleset.json: append {"type": "required_signatures"} to .rules
gh api -X PUT repos/OWNER/REPO/rulesets/RULESET_ID --input ruleset.json
```

Send *only* the `rules` key in the payload and GitHub leaves `conditions` and `bypass_actors`
untouched — which is what you want, since re-sending `bypass_actors` verbatim can trip over
actors the GET renders with a null `actor_id`. Confirm what actually took effect afterwards:

```sh
gh api repos/OWNER/REPO/rules/branches/BRANCH --jq '.[].type'
```

Four things to know before you turn it on:

- **Your existing history is grandfathered.** The rule only checks commits that aren't already
  reachable from another branch. You do *not* have to rewrite or re-sign the past.
- **GitHub's own commits still pass.** Web-UI edits and the squash/rebase/merge buttons produce
  commits signed by *GitHub's* key. They stay verified, so your web workflow survives — but be
  clear-eyed that those signatures attest GitHub made the commit, not that you were present.
- **Bypass actors are exempt.** If the ruleset lists org admins or the admin role under
  bypass, those people sail straight through and the rule is advisory for them. If you want it
  to bind *you*, put the rule in a ruleset with an empty bypass list.
- **It raises the bar for contributors.** On a public repo, every PR commit now needs a
  verified signature or it can't land. Say so in `CONTRIBUTING.md` — and note that any method
  GitHub verifies is fine, GPG included. Don't make signing sod-specific.

### Tier B: gate releases on a signed tag

Since GitHub won't check tag signatures, the workflow does. Two pieces.

**First, a committed trust root** — the keys allowed to ship. `.github/allowed_signers`:

```
# Format: <principal> namespaces="git" <keytype> <key>
# The principal must match the tagger's email exactly.
you@users.noreply.github.com namespaces="git" ecdsa-sha2-nistp256 AAAAE2VjZHNh…
```

Keeping this in-repo is the point: changing who may cut a release is a reviewed PR against a
protected branch, not a settings toggle someone can flip quietly. `namespaces="git"` scopes each
key to git signatures so it can't be used to verify signatures from some other namespace.

**Second, a job that runs before anything is built:**

```yaml
jobs:
  verify-tag:
    if: startsWith(github.ref, 'refs/tags/')
    runs-on: ubuntu-latest      # a public-key check: no macOS, no secrets, no Touch ID
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Verify the tag is signed by an approved maintainer key
        run: |
          set -euo pipefail
          TAG="${GITHUB_REF#refs/tags/}"
          # checkout can leave a lightweight ref pointing at the commit, which would make an
          # annotated tag look unsigned. Refetch the tag object itself.
          git fetch --force origin "refs/tags/$TAG:refs/tags/$TAG"

          if [ "$(git cat-file -t "$TAG")" != "tag" ]; then
            echo "::error::$TAG is a lightweight tag — release tags must be signed: git tag -s"
            exit 1
          fi

          git -c gpg.format=ssh \
              -c gpg.ssh.allowedSignersFile=.github/allowed_signers \
              verify-tag "$TAG"

  release:
    needs: [verify-tag]
    # verify-tag is skipped on a manual dispatch (no tag); a skipped dependency must not skip
    # the release with it. Only a real failure blocks.
    if: always() && needs.verify-tag.result != 'failure' && needs.verify-tag.result != 'cancelled'
    runs-on: macos-15
    steps:
      # … build, notarize, checksum, publish …
```

Three details worth not getting wrong:

- **Refetch the tag.** `actions/checkout` can leave a lightweight ref, which makes a perfectly
  signed annotated tag look unsigned. Without the explicit `git fetch` of `refs/tags/$TAG`, this
  gate fails confusingly or passes vacuously depending on the runner.
- **Reject lightweight tags explicitly.** `git verify-tag` on a lightweight tag is a
  less-obvious error than a message telling the maintainer to use `git tag -s`.
- **Mind the skip semantics.** A `needs:` on a conditional job will skip the dependent job too
  unless you guard with `always()` and check the result — which would silently disable your
  release pipeline for manual runs.

sod [enforces exactly this on itself](https://github.com/botanica-consulting/sod/blob/main/.github/workflows/release.yml).

---

## Cutting a release

With both tiers in place:

```sh
git commit -m "…"              # ← Touch ID (commit.gpgsign)
git tag -s v1.2.3 -m "v1.2.3"  # ← Touch ID: the tap that says "this is the release"
git push origin main v1.2.3
git tag -v v1.2.3              # verify locally — no prompt
```

The tag signature is the one that matters most. The Secure Enclave produces it only after your
fingerprint, and nothing about it exists anywhere a thief could have copied it from. Push the
tag and CI takes over: verify the signature, then build, notarize, checksum, publish — all
anchored to a ref a human put a finger on.

```
   you ──(git tag -s)──▶ signed tag ──(git push)──▶ GitHub
                                                      │
                                              tag push triggers CI
                                                      ▼
                                 verify-tag ──▶ build · notarize · publish
                                      │
                                  unsigned? ──▶ refuse to build
```

[resource: replace the ASCII sketch with a proper diagram]

> **About "one tap."** How many prompts you actually see depends on your remote. With an **SSH**
> remote, the push itself uses sod's Touch-ID-gated auth, so that's a separate tap on top of the
> signing ones. With an **HTTPS** remote (a stored credential or a `gh` token) the push doesn't
> involve sod at all — the signatures are still Enclave-backed, but the transport isn't. Worth
> knowing which you have: `git remote -v`. Either way the claim isn't a literal single touch;
> it's that *authorship* is hardware-bound and unforgeable.

---

## Why a Secure Enclave key changes the claim

Signed commits are not new, and plenty of people sign with a GPG or SSH key sitting in a file.
The difference is what a signature *proves*.

A key in `~/.ssh` or `~/.gnupg` proves that **something with access to that file** produced the
signature. That's a real claim, but it's a claim about a secret — and secrets get copied by
malware, backups, sync clients, and anyone who gets your laptop while it's unlocked. Once
copied, signatures can be minted anywhere, forever, silently.

sod serves an `ecdsa-sha2-nistp256` key **generated inside the Secure Enclave that never leaves
it**. `~/.ssh/id_sod` is an *opaque, device-bound handle* — there is no usable secret in that
file. Every signature is produced by the Enclave itself, and the Enclave requires Touch ID
(with passcode fallback) each time.

So the claim upgrades: not "something with the key signed this" but **"a person was physically
present at this specific Mac"**. There's no key material to exfiltrate and no way to sign on a
build box. Presence isn't a policy you opted into — it's a property of the key.

That's also why the same key does both jobs. It's already your authentication key; registering it
as a signing key means one key, no second keyring, no GPG.

---

## Verifying, as someone else

- **You, locally:** `git log --show-signature` / `git tag -v v1.2.3`, checked against your
  `allowed_signers`. No prompt.
- **Anyone, on GitHub:** the **Verified** badge. Zero setup for them.
- **Your team or CI:** a shared `allowed_signers` file plus `git verify-tag` in a checkout —
  Tier B, which is what turns "we sign releases" from a convention into a gate.

## Optional: add build provenance

A sod signature answers *who decided to ship this source*. It says nothing about *how the binary
was built*. GitHub has a keyless, Sigstore-backed mechanism for that, and the two compose:

```yaml
permissions:
  id-token: write
  attestations: write
  contents: write
steps:
  - uses: actions/attest-build-provenance@v1
    with:
      subject-path: "dist/sod-*.pkg"
```

```sh
gh attestation verify ./sod-1.2.3.pkg --repo OWNER/REPO
```

The finished story: **sod signs the intent (human presence); Sigstore attests the build (machine
provenance); notarization vouches for the installer.** Three answers to three different questions.

## Rotating the key

The key is non-exportable, so rotation *is* the recovery story — there's no backup to restore, by
design. It's cheap:

```sh
sd ssh-keygen -f ~/.ssh/id_sod
gh ssh-key add ~/.ssh/id_sod.pub --type signing --title "sod (rotated 2026-07)"
# update ~/.ssh/allowed_signers and .github/allowed_signers; retire the old key on GitHub
```

Signatures made with the old key keep verifying as long as the old public key stays in the
verifier's `allowed_signers` and in GitHub's record. Rotate the signing and authentication roles
together — it's one key doing both.

## The honest boundaries

- **GitHub cannot enforce signed tags.** Bears repeating, since it's the single most common wrong
  assumption here. `required_signatures` is commits-on-branches only. Tags need CI.
- **Bypass actors quietly undo Tier A.** A ruleset that exempts admins doesn't constrain admins.
  Check the bypass list before believing the rule.
- **GitHub's signatures aren't your signatures.** Web edits and merge buttons produce
  GitHub-signed commits. Verified, but not evidence you were present.
- **`gh`'s API uses its own OAuth token**, not your SSH key. sod gates git transport and signing;
  it doesn't gate `gh release edit`. "Hardware-gated" is not "every GitHub action needs a finger."
- **A tap per commit is a real cost.** Signing every commit means a prompt on every commit,
  including rebases and amends, and non-interactive tooling can't tap. If that's untenable, run
  `--no-auto-sign-commits` and keep Tier B — the release gate is where the value concentrates.
- **macOS + Secure Enclave only.** Needs Apple Silicon or a T2 chip, and Touch ID.

## Wrap

Signing has a reputation for being fiddly — keyrings, expiry, "why is it asking for my passphrase
in CI." With sod, the key you already use to reach GitHub becomes the key that vouches for your
work, the act of vouching is a fingerprint, and two mechanisms make it stick: a ruleset for
commits, a CI gate for tags. Everything downstream hangs off a ref a human touched.

---

*Want to try it? [Install sod](https://github.com/botanica-consulting/sod#install), then
`sd install`. A single notarized binary, built on nothing but Apple frameworks.*
