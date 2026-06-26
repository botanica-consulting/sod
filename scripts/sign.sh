#!/usr/bin/env bash
# Code-sign dist/sod IFF $DEVELOPER_ID_APP is set; otherwise leave SwiftPM's ad-hoc
# signature in place (unsigned distribution). Hardened runtime + secure timestamp,
# and NO entitlements: the SE dataRepresentation + .userPresence model needs none.
set -euo pipefail
cd "$(dirname "$0")/.."
BIN="dist/sod"
[ -x "$BIN" ] || { echo "sign: build first (no $BIN — run: make universal)"; exit 1; }

if [ -z "${DEVELOPER_ID_APP:-}" ]; then
  echo "sign: DEVELOPER_ID_APP unset — leaving ad-hoc signature (unsigned distribution)."
  codesign -dvv "$BIN" 2>&1 | grep -E 'Signature|flags' || true
  exit 0
fi

codesign --force --timestamp --options runtime --sign "$DEVELOPER_ID_APP" "$BIN"
codesign --verify --strict --verbose=2 "$BIN"
codesign -dvvv "$BIN" 2>&1 | grep -E 'Authority|TeamIdentifier|flags|Timestamp' || true
echo "sign: signed with \$DEVELOPER_ID_APP (hardened runtime, timestamped, no entitlements)."
