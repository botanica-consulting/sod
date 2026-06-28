#!/usr/bin/env bash
# Generate sd's shell completions from a built binary and lay them under a destination
# tree. swift-argument-parser emits the scripts, so they always match the actual CLI.
#
#   gen-completions.sh <sd-binary> [dest-root]
#
# dest-root defaults to "" (i.e. the real /usr/local) for `make install`; make-pkg.sh
# passes a staging root (dist/root) so the files land in the .pkg payload. Keeping the
# paths + filenames here means there's a single source of truth for both install routes.
set -euo pipefail

BIN="${1:?usage: gen-completions.sh <sd-binary> [dest-root]}"
ROOT="${2:-}"

zsh_dir="$ROOT/usr/local/share/zsh/site-functions"
bash_dir="$ROOT/usr/local/etc/bash_completion.d"
fish_dir="$ROOT/usr/local/share/fish/vendor_completions.d"

install -d "$zsh_dir" "$bash_dir" "$fish_dir"
"$BIN" --generate-completion-script zsh  > "$zsh_dir/_sd"
"$BIN" --generate-completion-script bash > "$bash_dir/sd"
"$BIN" --generate-completion-script fish > "$fish_dir/sd.fish"
chmod 0644 "$zsh_dir/_sd" "$bash_dir/sd" "$fish_dir/sd.fish"

echo "gen-completions: wrote zsh (_sd), bash (sd), fish (sd.fish) under ${ROOT:-}/usr/local"
