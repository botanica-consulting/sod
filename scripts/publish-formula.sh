#!/usr/bin/env bash
# On a tag build, render the source-build Homebrew formula for THIS release — filling the
# tag and its commit SHA into homebrew/sod.rb's __TAG__/__REVISION__ placeholders — and
# push it to the tap so `brew install botanica-consulting/tap/sod` builds the tagged
# source. (brew = build-from-source by design; the signed .pkg is the prebuilt route.)
# Invoked by release.yml only when HOMEBREW_TAP_TOKEN is set; skipped otherwise.
set -euo pipefail
cd "$(dirname "$0")/.."

: "${HOMEBREW_TAP_TOKEN:?publish-formula: HOMEBREW_TAP_TOKEN unset}"
TAG="${GITHUB_REF_NAME:?publish-formula: GITHUB_REF_NAME unset}"   # e.g. v0.1.0
REVISION="$(git rev-parse HEAD)"                                   # the tagged commit

# Render the template (homebrew/sod.rb). Homebrew infers the version (0.1.0) from the tag.
FORMULA="$(sed \
  -e "s|__TAG__|${TAG}|g" \
  -e "s|__REVISION__|${REVISION}|g" \
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
git commit -m "sod ${TAG#v}: build-from-source formula at ${TAG} (${REVISION})"
git push origin HEAD
echo "publish-formula: pushed Formula/sod.rb (sod ${TAG#v}) to ${TAP_REPO}"
