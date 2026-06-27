#!/usr/bin/env bash
# On a tag build, render the source-build Homebrew formula for THIS release — filling the
# tag and its commit SHA into homebrew/sod.rb's __TAG__/__REVISION__ placeholders — and
# open a PR against the tap (botanica-consulting/homebrew-tap) updating Formula/sod.rb.
# A human merges that PR to publish, so a bad render never lands on the tap automatically.
# (brew = build-from-source by design; the signed .pkg is the prebuilt route.)
# Invoked by release.yml only when HOMEBREW_TAP_TOKEN is set; skipped otherwise.
# The token needs Contents: write + Pull requests: write on the tap.
set -euo pipefail
cd "$(dirname "$0")/.."

: "${HOMEBREW_TAP_TOKEN:?publish-formula: HOMEBREW_TAP_TOKEN unset}"
TAG="${GITHUB_REF_NAME:?publish-formula: GITHUB_REF_NAME unset}"   # e.g. v0.1.0
VERSION="${TAG#v}"
REVISION="$(git rev-parse HEAD)"                                   # the tagged commit

# Render the template (homebrew/sod.rb). Homebrew infers the version (0.1.0) from the tag.
FORMULA="$(sed \
  -e "s|__TAG__|${TAG}|g" \
  -e "s|__REVISION__|${REVISION}|g" \
  homebrew/sod.rb)"

TAP_REPO="botanica-consulting/homebrew-tap"
BRANCH="release/sod-${TAG}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
git clone --depth 1 "https://x-access-token:${HOMEBREW_TAP_TOKEN}@github.com/${TAP_REPO}.git" "$WORK/tap"

cd "$WORK/tap"
git config user.name "botanica-release-bot"
git config user.email "release-bot@botanica.consulting"
git switch -c "$BRANCH"
mkdir -p Formula
printf '%s\n' "$FORMULA" > Formula/sod.rb
git add Formula/sod.rb
if git diff --cached --quiet; then
  echo "publish-formula: tap formula already current for ${TAG}; nothing to PR"
  exit 0
fi
git commit -m "sod ${VERSION}: build-from-source formula at ${TAG} (${REVISION})"
git push --force origin "$BRANCH"   # idempotent if the workflow re-runs for the same tag

# Open the PR (or report the existing one). gh reads GH_TOKEN; same token, so it needs
# pull-requests:write in addition to contents:write.
export GH_TOKEN="$HOMEBREW_TAP_TOKEN"
if gh pr view "$BRANCH" --repo "$TAP_REPO" >/dev/null 2>&1; then
  echo "publish-formula: PR already open for ${BRANCH}: $(gh pr view "$BRANCH" --repo "$TAP_REPO" --json url -q .url)"
else
  gh pr create --repo "$TAP_REPO" --base main --head "$BRANCH" \
    --title "sod ${VERSION}" \
    --body "Automated by the sod release workflow: update \`Formula/sod.rb\` to **sod ${VERSION}** (build-from-source at \`${TAG}\`, commit \`${REVISION}\`). Merge to publish to the tap."
  echo "publish-formula: opened PR for ${BRANCH} on ${TAP_REPO}"
fi
