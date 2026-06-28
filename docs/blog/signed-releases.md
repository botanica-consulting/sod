---
title: "One tap to ship: hardware-signed releases with sod + gh"
description: >
  Use a Secure-Enclave SSH key (sod) to sign your release tags with Touch ID, and let
  GitHub Actions build and publish from the signed ref. Supply-chain-grade provenance,
  no GPG, one fingerprint.
date: 2026-06-28
author: Botanica Software Labs
tags: [secure-enclave, touch-id, ssh, release-engineering, supply-chain, github, gh]
draft: true
---

<!--
  DRAFT. Text first. Resources to add later:
  - terminal capture of `git tag -s` triggering the Touch ID sheet
  - screenshot of the "Verified" badge on a sod release/tag on GitHub
  - a small diagram: human signs the tag (presence) → CI builds the artifact (provenance)
  Marked inline with [resource: …] placeholders.
-->

# One tap to ship: hardware-signed releases with sod + gh

> **TL;DR** — Register your [sod](https://github.com/botanica-consulting/sod) key as a
> GitHub *signing* key, point git at it, and sign your release **tags**. The signature
> comes from the Secure Enclave and requires Touch ID, so the moment that actually
> matters — *"this is the commit we're shipping"* — is gated by your fingerprint, not by
> a token sitting on disk. Push the signed tag and CI does the rest.

## "Who shipped this?" is the question that matters

Most of the supply-chain conversation is about artifacts: checksums, SBOMs, build
provenance. All useful. But there's an earlier, more human link in the chain that's easy
to skip over: **who decided that *this exact commit* is the release, and can you prove
it was them?**

That decision is expressed as a **tag** (`v1.2.3`). If the tag is unsigned, anyone who
can push — a stolen token, a misconfigured CI bot, an unattended-but-unlocked laptop —
can mint a "release" that looks exactly like yours. A signed tag closes that gap: it
binds the release point to a key. And if that key lives in hardware and demands a
fingerprint to use, the binding is to *a person who was physically present*, not merely
to *a secret someone copied*.

That's the whole pitch of this post: **sign the intent, not every keystroke.** You don't
need to tap your way through a rebase. You need one deliberate, unforgeable signature at
the release boundary — and sod makes that signature a single Touch ID tap.

> **Why not sign every commit?** You can, but it's the wrong place to spend presence.
> Commits are high-frequency and often non-interactive (rebases, amends, scripts, CI), so
> per-commit hardware prompts are friction without much payoff — and the only way to make
> them bearable is a cache that dilutes the "presence on every signature" guarantee. Tags
> and releases are rare, deliberate, and high-value. That's where a fingerprint earns its
> keep.

## What sod brings to the table

[sod](https://github.com/botanica-consulting/sod) serves an `ecdsa-sha2-nistp256` SSH key
that is **generated inside the Secure Enclave and never leaves it**. The file on disk
(`~/.ssh/id_sod`) is an *opaque handle* — a device-bound blob with no usable secret in
it. Every time the key signs anything, the Secure Enclave requires Touch ID (with
passcode fallback).

Two properties make it a great release-signing key specifically:

1. **One key, two jobs.** It's already your *authentication* key — it's how you `git
   push` and `ssh` to GitHub. Register the *same* public key as a *signing* key and it now
   also proves authorship. No second keyring to manage, no GPG.
2. **You physically cannot sign off-device.** Because the on-disk handle isn't a usable
   private key, a signature can only be produced by the Secure Enclave, through the agent,
   with your finger. There's no key material to exfiltrate and no "sign it on the CI box"
   shortcut. Presence isn't a policy you opt into — it's a property of the key.

It's worth being precise about how the signing actually happens, because it's the crux:
git's SSH signing calls `ssh-keygen -Y sign`, which signs through the **ssh-agent** when
you point it at a public key whose private half isn't on disk. sod *is* that agent. So
`git tag -s` → `ssh-keygen -Y sign` → sod agent → Secure Enclave → Touch ID. (We verified
this end-to-end with a P-256 key whose on-disk private file was deliberately replaced with
garbage: signing still succeeds via the agent, and verification passes.)

## Setup (once)

Assumes sod is installed and running — if not, `sd install` and
[the Quickstart](https://github.com/botanica-consulting/sod#quickstart) get you there in a
minute. You should already be able to `ssh -T git@github.com` and see your username.

**1. Enlist the sod key as a GitHub *signing* key.** It's already your auth key; add the
same public key again, this time as a signing key:

```sh
gh ssh-key add ~/.ssh/id_sod.pub --type signing --title "sod (Secure Enclave)"
```

(GitHub keeps authentication keys and signing keys in separate lists; the same key can be
in both. The signing key is what turns your signatures into the green **Verified** badge —
provided the tagger email is one of your verified GitHub emails.)

**2. Point git at it for SSH signing:**

```sh
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_sod.pub
```

Note we point `user.signingkey` at the **public** key (`.pub`). That's deliberate: it tells
`ssh-keygen` to sign via the agent rather than looking for a private key on disk — which is
exactly what we want, since the private key lives in the Secure Enclave.

**3. Let git verify signatures locally**, and add yourself to the allow-list:

```sh
git config --global gpg.ssh.allowedSignersFile ~/.ssh/allowed_signers
printf '%s %s\n' "$(git config --get user.email)" "$(cut -d' ' -f1-2 ~/.ssh/id_sod.pub)" \
  >> ~/.ssh/allowed_signers
```

The `allowed_signers` format is `<email> <keytype> <key>` — `cut -d' ' -f1-2` drops the
trailing comment so you get just the type and the key material.

**4. (Optional) sign every annotated tag automatically**, so you can drop the `-s`:

```sh
git config --global tag.gpgsign true
```

That's the whole setup. Notice what you *didn't* do: no `gpg --gen-key`, no keyserver, no
expiry to babysit, no passphrase to type or stash. The key already existed; you just gave
it a second role.

## Cutting a release: the tap that matters

```sh
git tag -s v1.2.3 -m "v1.2.3"   # ← Touch ID: the Secure Enclave signs the tag
git push origin v1.2.3          # push the signed tag
git tag -v v1.2.3               # verify locally — a public-key check, no prompt
```

[resource: terminal capture — the macOS Touch ID sheet appearing on `git tag -s`]

The first line is the moment that counts. The Secure Enclave produces the signature only
after your fingerprint; nothing about that signature exists anywhere a thief could have
copied it from.

On GitHub, the tag (and any release built from it) shows the **Verified** badge.

[resource: screenshot — the "Verified" badge on a sod release tag]

> **About "one tap."** The *signature* is one deliberate tap. Pushing the tag uses sod's
> normal Touch-ID-gated SSH auth, like any `git push`, so strictly there's also an auth
> tap — and a planned short presence window (bounded by Apple's 5-minute cap on biometric
> reuse) would coalesce the two into a single prompt. The point isn't a literal single
> touch; it's that the release's *authorship* is hardware-bound and unforgeable.

### Let CI build from the signed ref

This is where it gets satisfying. If your release workflow triggers on tags, your entire
job as a human collapses to *signing the tag*. sod's own pipeline does exactly this — its
[`release.yml`](https://github.com/botanica-consulting/sod/blob/main/.github/workflows/release.yml)
runs on `push: tags: ["v*"]` and, from the signed commit, builds the notarized universal
`.pkg` + tarball, writes `SHA256SUMS.txt`, and opens the Homebrew tap PR. You sign; the
machines build, notarize, and publish — all anchored to a ref a human put their finger on.

```
   you ──(git tag -s)──▶ signed tag ──(git push)──▶ GitHub
                                                      │
                                              tag push triggers CI
                                                      ▼
                                   build · notarize · checksum · publish
```

[resource: replace the ASCII sketch above with a proper diagram]

## Optional: layer build provenance with `gh attestation`

sod's signature answers *who decided to ship this source*. It does **not** attest *how the
binary was built* — that's a different link in the chain, and GitHub has a keyless,
Sigstore-backed mechanism for it. The two are complementary; use both for defense in depth.

In the build job:

```yaml
permissions:
  id-token: write
  attestations: write
  contents: write
steps:
  # … build dist/sod-<version>.pkg …
  - uses: actions/attest-build-provenance@v1
    with:
      subject-path: "dist/sod-*.pkg"
```

And a consumer can verify the artifact's provenance:

```sh
gh attestation verify ./sod-1.2.3.pkg --repo botanica-consulting/sod
```

So the finished story is: **sod signs the source/intent (human presence); Sigstore attests
the build (machine provenance); Apple notarization vouches for the installer.** Three
independent answers to three different "can I trust this?" questions.

## Verifying a release

- **You, locally:** `git tag -v v1.2.3` (or `git log --show-signature`) checks the signature
  against your `allowed_signers`. No Touch ID — verification is a public-key operation.
- **Anyone, on GitHub:** the **Verified** badge on the tag/release. Zero setup for them.
- **Your team / CI, from the CLI:** distribute the maintainers' public keys in a shared
  `allowed_signers` file and run `git verify-tag` in a checkout. This lets a build pipeline
  *refuse to build* a tag that isn't signed by an approved key — turning "we sign releases"
  from a convention into an enforced gate.

## Rotating the key

Because the key is non-exportable, rotation is the recovery story (there's no backup to
restore — by design). It's cheap:

```sh
sd ssh-keygen -f ~/.ssh/id_sod                 # new Secure-Enclave key on this Mac
gh ssh-key add ~/.ssh/id_sod.pub --type signing --title "sod (rotated 2026-06)"
# update ~/.ssh/allowed_signers with the new line; remove the retired key from GitHub
```

Tags you signed with the old key keep verifying as long as the old public key stays in the
verifier's `allowed_signers` (and in GitHub's record). Rotate the *signing* role and the
*authentication* role together — it's the same key doing both.

## The honest boundaries

- **`gh`'s API uses its own OAuth token**, not your SSH key. sod gates git *transport* and
  *signing*; it doesn't gate API calls like `gh release edit`. Don't read "hardware-gated"
  as "every GitHub action requires your finger."
- **`gh attestation` ≠ sod.** It's keyless build provenance (Sigstore/OIDC), a complement
  to — not a replacement for — a human-presence signature on the source.
- **Per-commit signing stays a sidebar.** This flow is about the release boundary. If your
  org *requires* signed commits on protected branches, sod can do it, but lean on a short
  presence window so you tap once per session rather than once per commit.
- **macOS + Secure Enclave only.** The key needs Apple Silicon or a T2 chip and Touch ID.

## Wrap

Signing releases has a reputation for being fiddly — GPG keyrings, expiry, "why is my
passphrase being asked for in CI." With sod, the key you already use to reach GitHub
becomes the key that vouches for your releases, and the act of vouching is a single
fingerprint on the tag. Everything downstream — build, notarize, checksum, publish — hangs
off that one signed ref.

Ship less, prove more. One tap.

---

*Want to try it? [Install sod](https://github.com/botanica-consulting/sod#install), then
`sd install`. It's a single notarized binary, built on nothing but Apple frameworks.*
