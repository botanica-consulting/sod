#!/usr/bin/env bash
# "Sign in with sod" — a self-contained challenge/response demo.
#
# A *verifier* issues a random challenge; a *client* signs it with one Touch ID tap
# through the sod agent (stock `ssh-keygen -Y sign`); the verifier checks the signature
# with stock `ssh-keygen -Y verify` against an allow-list (`allowed_signers`). No
# passwords, no PKI, no new crypto — just the Secure-Enclave key you already have.
#
# This script plays both roles locally over a throwaway agent. Run it and approve the one
# Touch ID prompt. For a tap-free run, point it at a sod built with the mock backend:
#   SE_SSH_MOCK=1 swift build && SOD=.build/debug/sd SE_SSH_MOCK=1 bash demo.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
NS="signin@sod.example"   # signature namespace — verifier and client must agree
PRINCIPAL="demo@sod"      # the identity recorded in allowed_signers / passed to -I

# Locate the `sd` binary: $SOD override, then PATH, then a local build.
SOD="${SOD:-}"
if [ -z "$SOD" ]; then
  for cand in "$(command -v sd 2>/dev/null || true)" "$REPO/.build/release/sd" "$REPO/.build/debug/sd"; do
    if [ -n "$cand" ] && [ -x "$cand" ]; then SOD="$cand"; break; fi
  done
fi
[ -n "$SOD" ] && [ -x "$SOD" ] || { echo "sd not found — install sod or set SOD=/path/to/sd"; exit 1; }

command -v ssh-keygen >/dev/null || { echo "ssh-keygen not found (install OpenSSH)"; exit 1; }

# Throwaway key (default: your real ~/.ssh/id_sod; created if absent), agent, and workdir.
KEY="${1:-$HOME/.ssh/id_sod}"
PUB="$KEY.pub"
[ -f "$KEY" ] || { echo "creating a Secure-Enclave key at $KEY"; "$SOD" ssh-keygen -f "$KEY"; }

SOCK="/tmp/sod-signin.$$.sock"   # short path: macOS sun_path is <= 103 bytes
T="$(mktemp -d)"
cleanup() {
  "$SOD" ssh-agent -a "$SOCK" -k >/dev/null 2>&1 || true
  rm -rf "$T" "$SOCK" "$SOCK.pid"
}
trap cleanup EXIT

# Start a throwaway sod agent and load the key (the default key is auto-served, but be explicit
# so a custom key path also works). SSH_AUTH_SOCK is exported into this shell by the eval.
eval "$("$SOD" ssh-agent -E -a "$SOCK")"
"$SOD" ssh-add -a "$SOCK" "$KEY" >/dev/null

# ---- verifier: publish the allow-list (one line: principal, keytype, key) ----
SIGNERS="$T/allowed_signers"
printf '%s %s\n' "$PRINCIPAL" "$(cut -d' ' -f1-2 "$PUB")" > "$SIGNERS"

# ---- verifier: issue a fresh random challenge ----
CHALLENGE="$T/challenge"
head -c 32 /dev/urandom | base64 > "$CHALLENGE"
echo "→ challenge: $(cat "$CHALLENGE")"

# ---- client: sign the challenge through the agent (Touch ID fires here) ----
echo "→ signing the challenge with your sod key (approve the Touch ID prompt)…"
if ! ssh-keygen -Y sign -f "$PUB" -n "$NS" "$CHALLENGE" >/dev/null 2>"$T/sign.err"; then
  echo "✗ signing failed:"; cat "$T/sign.err"; exit 1   # e.g. the Touch ID prompt was declined
fi   # writes $CHALLENGE.sig

# ---- verifier: check the signature against the allow-list ----
if ssh-keygen -Y verify -f "$SIGNERS" -I "$PRINCIPAL" -n "$NS" -s "$CHALLENGE.sig" < "$CHALLENGE" >/dev/null 2>&1
then
  echo "✓ signed in as $PRINCIPAL — signature verified against the Secure-Enclave key"
else
  echo "✗ verification FAILED (unexpected)"; exit 1
fi

# ---- negative control: a tampered challenge must NOT verify ----
echo "tampered-with" >> "$CHALLENGE"
if ssh-keygen -Y verify -f "$SIGNERS" -I "$PRINCIPAL" -n "$NS" -s "$CHALLENGE.sig" < "$CHALLENGE" >/dev/null 2>&1
then
  echo "✗ a tampered challenge verified — that should never happen"; exit 1
else
  echo "✓ tampered challenge correctly rejected (the signature binds the exact bytes)"
fi
