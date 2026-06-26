#!/usr/bin/env bash
# Submit the built .pkg to Apple notarization and staple the ticket — only if
# $NOTARY_PROFILE names a stored notarytool keychain profile. One-time setup:
#   xcrun notarytool store-credentials "sod-notary" --apple-id you@example.com \
#         --team-id TEAMID1234 --password <app-specific-password>
set -euo pipefail
cd "$(dirname "$0")/.."
PKG="$(ls -t dist/sod-*.pkg 2>/dev/null | head -1 || true)"
[ -n "$PKG" ] || { echo "notarize: no dist/sod-*.pkg — run: make pkg"; exit 1; }

if [ -z "${NOTARY_PROFILE:-}" ]; then
  echo "notarize: NOTARY_PROFILE unset — skipping (distribution stays un-notarized)."
  exit 0
fi

echo "notarize: submitting $PKG via keychain profile '$NOTARY_PROFILE' (waits for result)…"
xcrun notarytool submit "$PKG" --keychain-profile "$NOTARY_PROFILE" --wait
echo "notarize: stapling $PKG"
xcrun stapler staple "$PKG"
xcrun stapler validate "$PKG"
spctl --assess --type install -vv "$PKG" || true
echo "notarize: done."
