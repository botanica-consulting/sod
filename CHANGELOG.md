# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Single `sod` binary with `ssh-keygen` / `ssh-agent` / `ssh-add` subcommands
  (built on swift-argument-parser), replacing the separate `se-ssh-*` executables.
- `sod ssh-keygen -y` to reprint a public-key line from a handle; faithful
  `ssh-keygen`-style output with a SHA256 fingerprint.
- `sod ssh-agent`: persistent + reuse model on a fixed `~/.ssh/sod-agent.sock`,
  `-d` foreground mode, `-k` to kill, faithful `-s`/`-c` shell dialects, and
  `--install-launch-agent` / `--uninstall-launch-agent` for login auto-start.
- `sod ssh-add`: loads `~/.ssh/id_sod` by default; `-D` removes all keys.
- Packaging: universal (arm64+x86_64) binary, notarizable `.pkg` (signing opt-in),
  Homebrew tap formula, tag-driven GitHub Release workflow, and a man page.
- CI (GitHub Actions): lint, build matrix, mock unit + end-to-end tests, coverage.

### Changed
- Renamed the project from `se-ssh` to **`sod`** (Botanica Software Labs).
- Default key is now `~/.ssh/id_sod`; default socket `~/.ssh/sod-agent.sock`.
- New handle-file magic `SOD-HANDLE-v1`; the legacy `SE-SSH-HANDLE-v1` is still
  accepted on read, so existing keys keep working.

[Unreleased]: https://github.com/botanica-consulting/sod/commits/main
