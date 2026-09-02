# Sign in with sod

A tiny **challenge/response authentication** demo built entirely on stock tooling and your
Secure-Enclave key. No passwords, no PKI, no new cryptography — just `ssh-keygen -Y` and the
sod agent.

## The idea

sod's agent is a general-purpose signing oracle: `ssh-keygen -Y sign` will hand it *any*
namespaced blob to sign, and `ssh-keygen -Y verify` checks the result against an allow-list.
That's all you need for "prove you hold this key" auth:

```
verifier                          client (your Mac)
   │  1. challenge (random nonce) ──────────▶
   │                                          2. ssh-keygen -Y sign  ──▶ sod agent ──▶ Secure Enclave ──▶ Touch ID
   │  ◀──────────── 3. signature ─────────────
   │  4. ssh-keygen -Y verify
   │     against allowed_signers  ──▶ ✓ / ✗
```

The signature is produced **only** by the Secure Enclave, **only** after a fingerprint, and it
**binds the exact challenge bytes** — so it can't be replayed against a different nonce, and
there's no secret on disk for anyone to steal. The verifier needs nothing but the client's
public key in an `allowed_signers` file (and zero setup for the GitHub-style "Verified" path).

This is the same mechanism behind signed git tags — see
[`docs/blog/signed-releases.md`](../../docs/blog/signed-releases.md) — pointed at auth instead of releases.

## Run it

```sh
bash examples/sign-in-with-sod/demo.sh
```

It plays both roles locally over a throwaway agent: issues a random challenge, signs it with
**one Touch ID tap**, verifies it, then proves a *tampered* challenge is rejected. By default it
uses your `~/.ssh/id_sod` (creating one if absent); pass a path to use a different key:

```sh
bash examples/sign-in-with-sod/demo.sh ~/.ssh/some_other_sod_key
```

**Tap-free run** (for CI or a quick look), against a sod built with the mock backend:

```sh
SE_SSH_MOCK=1 swift build
SOD=.build/debug/sd SE_SSH_MOCK=1 bash examples/sign-in-with-sod/demo.sh /tmp/demo-key
```

## What a real deployment adds

This demo runs the handshake in one process. A real "Sign in with sod" just moves the three
messages over a transport — a WebSocket, an HTTP POST, an SSH connection — with two rules the
demo already follows:

- **The challenge must be server-issued, single-use, and time-boxed** (a fresh random nonce per
  login) so a captured signature can't be replayed.
- **The namespace** (`-n`, here `signin@sod.example`) **must be specific to your app** so a
  signature minted for one purpose can't be reused for another.

The server side is just `ssh-keygen -Y verify` against the user's public key — the same line
this script runs.
