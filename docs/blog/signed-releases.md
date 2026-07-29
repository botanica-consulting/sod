---
title: "Signed and attested releases with sod + gh"
description: >
  Minimal setup: sign only your release tags with a Secure Enclave key — one Touch ID per
  release, none while you work — then let GitHub attest what it built from that tag. Two
  commands and six lines of YAML, after which every release carries a machine-checkable
  answer to "who authorised this" and "where did this binary come from".
date: 2026-07-29
author: Botanica Software Labs
tags: [secure-enclave, touch-id, ssh, git, signing, release-engineering, supply-chain, attestation, github]
draft: true
---

<!--
  DRAFT. Text first. Resources to add later:
  - terminal capture of `git tag -s` triggering the Touch ID sheet
  - screenshot of the Verified badge on a release tag
  - terminal capture of a successful `gh attestation verify`
  Marked inline with [resource: …] placeholders.
-->

# Signed and attested releases with sod + gh

> **TL;DR** — Register your [sod](https://github.com/botanica-consulting/sod) key as a GitHub
> *signing* key, run `sd setup-git-signing --no-auto-sign-commits`, and add six lines to your
> release workflow. From then on cutting a release costs exactly one Touch ID, the tag carries
> a **Verified** badge, and anyone can run one `gh` command to confirm your published binary
> was built by your CI from the commit you signed. Total setup: about two minutes.

A release has two separate questions attached to it, and most projects can't answer either.

**Who decided this release should exist?** Not "which account had a token" — which *human*.
A signed tag answers this, and if the signing key lives in a Secure Enclave, the answer comes
with a fingerprint attached: the signature could not have been produced anywhere but on that
Mac, by someone physically touching it.

**Is this binary actually what that source builds into?** A signature on a tag says nothing
about the `.pkg` on your releases page. An artifact attestation answers this one: GitHub
records what it built, from which commit, in which workflow, and signs that record.

Neither answers the other, and that's the point of doing both. The tag signature covers
source → human. The attestation covers source → artifact. Chain them and a stranger can walk
from a downloaded binary all the way back to a fingerprint on a laptop, without trusting your
word for any step.

This post is the minimal version. No branch rulesets, no commit signing, no CI gates —
just the two links of that chain.

---

## Part 1: tell GitHub your key is allowed to sign

GitHub keeps *authentication* keys and *signing* keys in two separate lists, and the same key
can sit in both. Your sod key is already in the auth list — that's how you push. It needs to be
in the signing list too, or your signatures will be perfectly valid and GitHub will still
refuse to show the green **Verified** badge.

sod deliberately never touches your GitHub account, so this half is yours to do. Adding a
signing key needs a scope your token probably lacks, so grant it once:

```sh
gh auth refresh -h github.com -s admin:ssh_signing_key
gh ssh-key add ~/.ssh/id_sod.pub --type signing --title "sod (Secure Enclave)"
```

Or paste the key at [github.com/settings/ssh/new](https://github.com/settings/ssh/new) with
the type set to **Signing key**. Either way it's one time per key, not per repo.

## Part 2: sign tags, not commits

```sh
sd setup-git-signing --no-auto-sign-commits
```

That's the whole repo-side setup. It points `user.signingkey` at your *public* key so
`ssh-keygen -Y sign` routes through the sod agent into the Secure Enclave, sets
`tag.gpgsign=true`, and leaves `commit.gpgsign` alone.

The flag is the interesting part. Signing every commit sounds more rigorous, but the Secure
Enclave asks for presence on *every* signature — there's no batching, by design — so a
twelve-commit branch is twelve Touch ID prompts. That friction is how good practices die.
Tags-only costs you **zero taps while you work and one per release**, which is a price nobody
resents paying, and it puts the signature exactly where the decision is: cutting a release.

If you do want signed commits too, drop the flag. The rest of this post is unchanged.

## Part 3: cut the tag

```sh
git tag -s v0.2.0 -m v0.2.0     # [resource: Touch ID sheet]
git push origin v0.2.0
```

[resource: screenshot — Verified badge on the tag]

Two things worth knowing, because both produce a release with no badge and neither is obvious:

**Lightweight tags can't be signed.** `git tag v0.2.0` with no `-m` or `-a` creates a bare ref
pointing at a commit — there's no tag object, so there's nothing to hold a signature. With
`tag.gpgsign=true` set, git won't let you make that mistake silently: a bare `git tag v0.2.0`
stops with `fatal: no tag message?` rather than quietly creating an unsignable tag.

**Don't cut releases from the GitHub web UI.** Creating a release from the Releases page makes
the tag server-side, where your Secure Enclave isn't. That tag is unsigned and unsignable
after the fact. Tag locally, push the tag, and let the workflow build the release.

## Part 4: attest the build

Now the other half of the chain. In your release workflow, widen the permissions:

```yaml
permissions:
  contents: write        # create the Release and upload assets
  id-token: write        # the OIDC token Sigstore signs the attestation against
  attestations: write    # store the attestation on the repo
```

and add one step, after you've built your artifacts and before you publish them:

```yaml
      - name: Attest the release artifacts
        uses: actions/attest-build-provenance@v4
        with:
          subject-checksums: dist/SHA256SUMS.txt
```

If you already generate a checksums file — and you should — `subject-checksums` attests
everything listed in it in a single step. Otherwise use `subject-path`, which takes a glob:
`subject-path: 'dist/*.pkg'`.

That's six lines. There is no key to generate, store, or rotate: the signing identity is the
workflow's own OIDC token, and GitHub does the rest. For a public repo the attestation is
recorded in the public-good Sigstore transparency log, so verification doesn't depend on
trusting you — or on GitHub still being cooperative later.

## Part 5: the payoff

Here's what a stranger can now do with nothing but your release URL:

```sh
gh release download v0.2.0 -R botanica-consulting/sod -p 'sod-*.pkg'

gh attestation verify sod-0.2.0.pkg -R botanica-consulting/sod \
  --source-ref refs/tags/v0.2.0
```

That checks the binary's digest against a signed provenance record and asserts it was built by
that repo's workflow from that tag. `--source-digest <sha>` pins the exact commit instead, and
`--signer-workflow botanica-consulting/sod/.github/workflows/release.yml` pins which workflow
was allowed to produce it — worth adding if you have more than one.

[resource: terminal capture — successful gh attestation verify]

Then close the loop back to the human:

```sh
git verify-tag v0.2.0
```

The badge on GitHub's tag page is the zero-effort version of this. `git verify-tag` is the
version that doesn't require trusting GitHub's rendering — it needs the signer's public key in
your `allowed_signers` file, which is a reasonable thing to ask of a downstream packager and
an unreasonable thing to ask of a casual user. Publish your signing key somewhere quotable and
let people choose their level.

Run both and the chain is closed:

| Question | Answered by | What it rests on |
|---|---|---|
| Which human authorised this release? | `git verify-tag` / the Verified badge | a key that cannot leave the Secure Enclave, used with a fingerprint |
| Which commit does that cover? | the tag object | the tag points at a commit SHA |
| Was this binary built from that commit? | `gh attestation verify --source-digest` | GitHub's OIDC identity, logged in Sigstore |

## What this does not do

Worth being precise, because the adjacent claims are tempting and false.

**This is provenance, not access control.** GitHub cannot enforce that tags are signed. The
`required_signatures` ruleset rule only ever inspects commits reachable from a *branch*; point
a ruleset at tags and it is silently inert. So anyone with write access can still push an
unsigned tag and cut a release from it — what they can't do is make it *look* like you did.
The absence of a badge is the signal. If you want to restrict who may create `refs/tags/v*`,
that's a separate ruleset and it gates GitHub accounts, not fingerprints.

**An attestation says where a binary came from, not that it's any good.** It proves your
workflow built it from that commit. If the commit contains a backdoor, the attestation
faithfully proves the backdoor was built by you, from that tag, on the record. That's still
worth a great deal — it's the difference between a supply-chain incident you can reconstruct
and one you can only guess at — but it is not a safety claim.

**A tap proves presence, not attention.** The Secure Enclave confirms a human was at the
keyboard when the signature was made. It cannot confirm that they read the diff.

What you get for two commands and six lines of YAML is this: every release you ship carries a
verifiable statement about who authorised it and where it came from, and the routine cost of
maintaining that is one fingerprint per release. That ratio is the reason to bother.

---

*sod is a Secure-Enclave-backed SSH agent and keygen for macOS —
[github.com/botanica-consulting/sod](https://github.com/botanica-consulting/sod).*
