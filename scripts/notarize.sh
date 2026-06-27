#!/usr/bin/env bash
# Submit the built .pkg to Apple notarization and staple the ticket. Credentials come
# from EITHER an App Store Connect API key passed directly (CI: NOTARY_KEY_PATH +
# NOTARY_KEY_ID + NOTARY_ISSUER_ID) OR a stored keychain profile (local convenience:
# NOTARY_PROFILE, created once via `xcrun notarytool store-credentials`). With neither,
# the step is skipped and the distribution stays un-notarized.
set -euo pipefail
cd "$(dirname "$0")/.."
PKG="$(ls -t dist/sod-*.pkg 2>/dev/null | head -1 || true)"
[ -n "$PKG" ] || { echo "notarize: no dist/sod-*.pkg — run: make pkg"; exit 1; }

AUTH=()
if [ -n "${NOTARY_KEY_PATH:-}" ] && [ -n "${NOTARY_KEY_ID:-}" ] && [ -n "${NOTARY_ISSUER_ID:-}" ]; then
  AUTH=(--key "$NOTARY_KEY_PATH" --key-id "$NOTARY_KEY_ID" --issuer "$NOTARY_ISSUER_ID")
  echo "notarize: using App Store Connect API key (id $NOTARY_KEY_ID)"
elif [ -n "${NOTARY_PROFILE:-}" ]; then
  AUTH=(--keychain-profile "$NOTARY_PROFILE")
  echo "notarize: using keychain profile '$NOTARY_PROFILE'"
else
  echo "notarize: no credentials (NOTARY_KEY_* or NOTARY_PROFILE) — skipping."
  exit 0
fi

echo "notarize: submitting $PKG (waits for result)…"
xcrun notarytool submit "$PKG" "${AUTH[@]}" --wait
echo "notarize: stapling $PKG"
xcrun stapler staple "$PKG"
xcrun stapler validate "$PKG"
spctl --assess --type install -vv "$PKG" || true
echo "notarize: done."
