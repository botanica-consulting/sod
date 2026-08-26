---
title: "How we sign our commits and releases — sod + GitHub attestations"
description: >
  Every commit we push and every release we cut at Botanica is signed by a key sealed in a
  Secure Enclave, and every release binary carries a GitHub build attestation. This is the
  setup: two commands, six lines of YAML, and what the combination does and does not prove.
date: 2026-08-26
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

# How we sign our commits and releases — sod + GitHub attestations

Every commit we push at Botanica, and every release we cut, is signed with a key that was
generated inside a Secure Enclave and has never existed anywhere else. We use
[sod](https://github.com/botanica-consulting/sod), our own Secure-Enclave SSH agent, so each
signature costs a Touch ID tap — presence, per signature, enforced by hardware rather than
by policy.

This post describes the setup as we run it, and the second half of the picture: GitHub's
build attestations, which cover the part of a release no local signature can reach.

## Why we sign releases at all

A release, as we see it, has two questions attached to it.

The first is *who decided this release should exist* — not which account held a token, but
which person. A signed tag answers it, and when the signing key lives in a Secure Enclave the
answer is unusually strong: the signature could not have been produced anywhere but on that
particular Mac, by someone physically touching it. A leaked laptop backup, a compromised CI
runner, a stolen PAT — none of them can forge it.

The second is *whether the binary on the releases page is actually what that source builds
into*. A tag signature says nothing about the `.pkg` next to it; the tag covers a commit, not
an artifact. This is where an attestation comes in — GitHub records what it built, from which
commit, in which workflow, and signs that record.

Neither mechanism answers the other's question, which is why we run both. The signature
covers source → human; the attestation covers source → artifact. Chained, they let a stranger
walk from a downloaded binary back to a fingerprint on a laptop without taking our word for
any step in between. Recent supply-chain incidents — compromised release workflows,
tampered artifacts published under trusted names — have mostly lived in exactly the gap
between those two links.

## Telling GitHub the key may sign

GitHub keeps *authentication* keys and *signing* keys in two separate lists, and the same key
can sit in both. Our sod keys were already in the auth list — that's how we push. Adding them
to the signing list is what makes the green **Verified** badge appear; without it the
signatures are still valid, GitHub just won't vouch for them.

sod deliberately never touches a GitHub account, so this step is manual:

```sh
gh auth refresh -h github.com -s admin:ssh_signing_key
gh ssh-key add ~/.ssh/id_sod.pub --type signing --title "sod (Secure Enclave)"
```

(Or paste the key at [github.com/settings/ssh/new](https://github.com/settings/ssh/new) with
the type set to **Signing key**.) Once per key, not per repo.

## Configuring the repo

```sh
sd setup-git-signing
```

That's the whole repo-side setup. It points `user.signingkey` at the *public* key so git's
SSH signing routes through the sod agent into the Secure Enclave, and turns on
`commit.gpgsign` and `tag.gpgsign` — every commit and every tag signed, by default.

The obvious objection is friction: the Secure Enclave asks for presence on every signature,
with no batching, so a day of work is a handful of taps. In practice we stopped noticing
within a week — a tap at commit time is quicker than the commit message. For those who
weigh it differently, `--no-auto-sign-commits` keeps signing for tags only, which still puts
a signature exactly where the release decision is made; the rest of this post is unchanged
either way.

## Cutting a release

```sh
git tag -s v0.2.0 -m v0.2.0     # [resource: Touch ID sheet]
git push origin v0.2.0
```

[resource: screenshot — Verified badge on the tag]

Two things we learned produce a badge-less release, neither of them loudly:

**Lightweight tags can't be signed.** `git tag v0.2.0` with no `-m` or `-a` creates a bare
ref with no tag object, so there is nothing to hold a signature. With `tag.gpgsign=true` set,
git at least refuses noisily — a bare `git tag v0.2.0` stops with `fatal: no tag message?`
rather than quietly creating an unsignable tag.

**Releases cut from the GitHub web UI are unsigned.** Creating a release from the Releases
page makes the tag server-side, where the Secure Enclave isn't. That tag is unsignable after
the fact. We tag locally, push the tag, and let the workflow build the release.

## Attesting the build

The other half of the chain lives in the release workflow. The permissions block gains two
entries:

```yaml
permissions:
  contents: write        # create the Release and upload assets
  id-token: write        # the OIDC token Sigstore signs the attestation against
  attestations: write    # store the attestation on the repo
```

and one step goes in after the artifacts are built:

```yaml
      - name: Attest the release artifacts
        uses: actions/attest-build-provenance@v4
        with:
          subject-checksums: dist/SHA256SUMS.txt
```

We already generate a checksums file, so `subject-checksums` attests everything in it at
once; `subject-path: 'dist/*.pkg'` works when there isn't one. There is no key to generate,
store, or rotate — the signing identity is the workflow's own OIDC token. For a public repo
the attestation also lands in the public Sigstore transparency log, so verifying it doesn't
depend on trusting us, or on GitHub remaining cooperative later.

## Verifying — what anyone can now check

With nothing but the release URL:

```sh
gh release download v0.2.0 -R botanica-consulting/sod -p 'sod-*.pkg'

gh attestation verify sod-0.2.0.pkg -R botanica-consulting/sod \
  --source-ref refs/tags/v0.2.0
```

That checks the binary's digest against a signed provenance record: built by that repo's
workflow, from that tag. `--source-digest <sha>` pins the exact commit instead, and
`--signer-workflow` pins which workflow was allowed to produce it — worth adding when a repo
has more than one.

[resource: terminal capture — successful gh attestation verify]

Then the loop closes back to the human:

```sh
git verify-tag v0.2.0
```

The badge on GitHub's tag page is the zero-effort version of this; `git verify-tag` is the
version that doesn't require trusting GitHub's rendering. It needs the signer's public key in
an `allowed_signers` file — a reasonable thing to ask of a downstream packager, less so of a
casual user, which is why we publish our signing keys somewhere quotable and let people pick
their level.

| Question | Answered by | Rests on |
|---|---|---|
| Which human authorised this release? | `git verify-tag` / the Verified badge | a key that cannot leave the Secure Enclave |
| Which commit does that cover? | the tag object | the tag points at a commit SHA |
| Was this binary built from that commit? | `gh attestation verify` | GitHub's OIDC identity, logged in Sigstore |

## What this does not get us

We try to be precise here, because the adjacent claims are tempting.

**This is provenance, not access control.** GitHub cannot enforce that tags are signed — the
`required_signatures` ruleset rule only inspects commits reachable from a *branch*; pointed
at tags it is silently inert. Anyone with write access can still push an unsigned tag; what
they cannot do is make it look like one of us did. The absence of a badge is the signal.

**An attestation says where a binary came from, not that it's any good.** If a commit
contains a backdoor, the attestation faithfully proves the backdoor was built by our
workflow, from that tag, on the record. That is still worth a great deal — it's the
difference between a supply-chain incident that can be reconstructed and one that can only
be guessed at — but it is not a safety claim.

**A tap proves presence, not attention.** The Secure Enclave confirms one of us was at the
keyboard when the signature was made. It cannot confirm we read the diff.

What the setup costs us is a tap per commit and one per release; what it buys is that every
release we ship carries a machine-checkable statement of who authorised it and where it came
from. We find that ratio easy to live with.

---

*sod is a Secure-Enclave-backed SSH agent and keygen for macOS —
[github.com/botanica-consulting/sod](https://github.com/botanica-consulting/sod). If you
haven't met it before, the [introduction](sod-intro.md) covers the everyday SSH side.*
