#!/usr/bin/env bash
# Self-contained end-to-end test of the Secure-Enclave SSH setup.
# Spins up a throwaway sshd on 127.0.0.1:4022 (no sudo, no changes to your real SSH
# config), then runs the real flow: eval "$(sod ssh-agent -E)" -> sod ssh-add <key>
# -> ssh -i <key>. With a real Secure Enclave you approve ONE Touch ID prompt; under
# SE_SSH_MOCK=1 there are no prompts. Cleans up the agent + sshd on exit.
#
# Usage:
#   bash scripts/selftest.sh                 # uses ~/.ssh/id_sod (creates if missing)
#   bash scripts/selftest.sh /path/to/mykey  # uses your own -f keypair (creates if missing)
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
BIN=""
for d in "$REPO/.build/release" "$REPO/.build/debug"; do
  [ -x "$d/sod" ] && { BIN="$d"; break; }
done
[ -n "$BIN" ] || { echo "build first:  swift build -c release  (or SE_SSH_MOCK=1 swift build)"; exit 1; }
SOD="$BIN/sod"

KEY="${1:-$HOME/.ssh/id_sod}"
[ -f "$KEY" ] || { echo "creating SE key: $KEY"; "$SOD" ssh-keygen -f "$KEY"; }
echo "key: $KEY"

PORT=4022
SOCK="/tmp/sod-selftest.$$.sock"         # short path: macOS sun_path must be <=103 bytes
T="$(mktemp -d)"
cleanup() {
  "$SOD" ssh-agent -a "$SOCK" -k >/dev/null 2>&1 || true
  [ -n "${SSHD_PID:-}" ] && kill "$SSHD_PID" 2>/dev/null || true
  pkill -f "$SOCK" 2>/dev/null || true   # stop the agent this script started
  rm -rf "$T" "$SOCK" "$SOCK.pid"
}
trap cleanup EXIT

ssh-keygen -t ed25519 -f "$T/hostkey" -N "" -q
cp "$KEY.pub" "$T/authorized_keys"; chmod 600 "$T/authorized_keys"
cat > "$T/sshd_config" <<EOF
Port $PORT
ListenAddress 127.0.0.1
HostKey $T/hostkey
AuthorizedKeysFile $T/authorized_keys
PidFile $T/sshd.pid
StrictModes no
UsePAM no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
EOF

SSHD="$(command -v sshd || echo /opt/homebrew/sbin/sshd)"
"$SSHD" -D -e -p "$PORT" -f "$T/sshd_config" >"$T/sshd.log" 2>&1 &
SSHD_PID=$!
for _ in $(seq 1 50); do
  lsof -nP -iTCP:$PORT -sTCP:LISTEN 2>/dev/null | grep -q sshd && break
  sleep 0.1
done

echo "--- eval \"\$(sod ssh-agent -E -a $SOCK)\"  (start empty agent) ---"
eval "$("$SOD" ssh-agent -E -a "$SOCK")"
echo "SSH_AUTH_SOCK=$SSH_AUTH_SOCK"

echo "--- sod ssh-add $KEY   (load the key, no PIN prompt) ---"
"$SOD" ssh-add -a "$SOCK" "$KEY"
"$SOD" ssh-add -a "$SOCK" -l

echo "--- ssh -i $KEY   (approve the Touch ID prompt on a real Secure Enclave) ---"
ssh -i "$KEY" \
    -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o BatchMode=yes \
    -p "$PORT" 127.0.0.1 \
    'echo "SUCCESS: authenticated to $(hostname -s) as $(id -un) via the Secure Enclave"'
