#!/usr/bin/env bash
# On a tag build, render the Homebrew formula for THIS release — filling the download URL
# and the universal tarball's sha256 into homebrew/sod.rb's __VERSION__/__URL__/__SHA256__
# placeholders — and push it to the tap repo. After this, `brew install
# botanica-consulting/tap/sod` fetches the prebuilt, Developer-ID-signed binary (no Xcode,
# no source build). Invoked by release.yml only when HOMEBREW_TAP_TOKEN is set.
set -euo pipefail
cd "$(dirname "$0")/.."

: "${HOMEBREW_TAP_TOKEN:?publish-formula: HOMEBREW_TAP_TOKEN unset}"
TAG="${GITHUB_REF_NAME:?publish-formula: GITHUB_REF_NAME unset}"   # e.g. v0.1.0
VERSION="${TAG#v}"
TARBALL="dist/sod-${TAG}-universal.tar.gz"
[ -f "$TARBALL" ] || { echo "publish-formula: no $TARBALL — build the release first"; exit 1; }

SHA256="$(shasum -a 256 "$TARBALL" | awk '{print $1}')"
URL="https://github.com/botanica-consulting/sod/releases/download/${TAG}/sod-${TAG}-universal.tar.gz"

# Render the template. Use '|' delimiters since URL contains '/'.
FORMULA="$(sed \
  -e "s|__VERSION__|${VERSION}|g" \
  -e "s|__URL__|${URL}|g" \
  -e "s|__SHA256__|${SHA256}|g" \
  homebrew/sod.rb)"

TAP_REPO="botanica-consulting/homebrew-tap"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
git clone --depth 1 "https://x-access-token:${HOMEBREW_TAP_TOKEN}@github.com/${TAP_REPO}.git" "$WORK/tap"

mkdir -p "$WORK/tap/Formula"
printf '%s\n' "$FORMULA" > "$WORK/tap/Formula/sod.rb"

cd "$WORK/tap"
git config user.name "botanica-release-bot"
git config user.email "release-bot@botanica.consulting"
git add Formula/sod.rb
if git diff --cached --quiet; then
  echo "publish-formula: tap formula already current for ${TAG}"
  exit 0
fi
git commit -m "sod ${VERSION}: point formula at the released binary"
git push origin HEAD
echo "publish-formula: pushed Formula/sod.rb (sod ${VERSION}) to ${TAP_REPO}"
