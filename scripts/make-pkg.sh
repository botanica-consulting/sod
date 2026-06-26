#!/usr/bin/env bash
# Build a distribution .pkg that installs sod to /usr/local/bin (+ its man page).
# A plain file copy — no install scripts (the LaunchAgent stays opt-in). Installer
# signing happens only if $DEVELOPER_ID_INSTALLER is set.
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${SOD_VERSION:-$(git describe --tags --always 2>/dev/null || echo 0.0.0)}"
VERSION="${VERSION#v}"
PKGID="consulting.botanica.sod"
ROOT="dist/root"
COMP="dist/sod-component.pkg"
OUT="dist/sod-${VERSION}.pkg"

[ -x dist/sod ] || { echo "make-pkg: build first (no dist/sod — run: make universal)"; exit 1; }

# Stage the payload tree.
rm -rf "$ROOT"
install -d "$ROOT/usr/local/bin" "$ROOT/usr/local/share/man/man1"
install -m 0755 dist/sod  "$ROOT/usr/local/bin/sod"
install -m 0644 man/sod.1 "$ROOT/usr/local/share/man/man1/sod.1"

# Strip extended attributes (quarantine/provenance) so pkgbuild doesn't embed
# AppleDouble (._*) sidecar files into the payload.
xattr -cr "$ROOT" 2>/dev/null || true

# License pane text comes from the repo LICENSE (single source of truth).
cp LICENSE packaging/resources/LICENSE.txt

# Component pkg (plain file copy, no scripts, no relocation).
pkgbuild --root "$ROOT" --identifier "$PKGID" --version "$VERSION" \
  --install-location "/" --ownership recommended "$COMP"

# Distribution pkg.
SIGN_ARGS=()
if [ -n "${DEVELOPER_ID_INSTALLER:-}" ]; then
  SIGN_ARGS=(--sign "$DEVELOPER_ID_INSTALLER")
  echo "make-pkg: installer-signing with \$DEVELOPER_ID_INSTALLER"
else
  echo "make-pkg: DEVELOPER_ID_INSTALLER unset — building UNSIGNED product pkg."
fi

productbuild --distribution packaging/Distribution.xml --resources packaging/resources \
  --package-path dist "${SIGN_ARGS[@]}" "$OUT"

echo "make-pkg: wrote $OUT"
pkgutil --check-signature "$OUT" 2>&1 | head -5 || true
