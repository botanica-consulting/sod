# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Single `sd` binary with `ssh-keygen` / `ssh-agent` / `ssh-add` subcommands
  (built on swift-argument-parser), replacing the separate `se-ssh-*` executables.
- `sd ssh-keygen -y` to reprint a public-key line from a handle; faithful
  `ssh-keygen`-style output with a SHA256 fingerprint.
- `sd ssh-agent`: persistent + reuse model on a fixed `~/.ssh/sod-agent.sock`,
  `-d` foreground mode, `-k` to kill, and faithful `-s`/`-c` shell dialects.
- `sd install` / `sd uninstall`: one-step login setup — installs a per-user
  LaunchAgent and prints the shell-specific `SSH_AUTH_SOCK` line to paste into
  your startup file (detects zsh/bash/fish/csh).
- `sd ssh-add`: loads `~/.ssh/id_sod` by default; `-D` removes all keys.
- `sd doctor`: a read-only health check of your setup — Secure Enclave availability,
  the default key, the login agent (installed + loaded), the live socket and the key
  loaded in it, and whether `SSH_AUTH_SOCK` is set in the current shell and exported
  from its startup file — with actionable hints and a non-zero exit when unhealthy.
- Packaging: universal (arm64+x86_64) binary, notarizable `.pkg` (signing opt-in),
  Homebrew tap formula, tag-driven GitHub Release workflow, and a man page.
- CI (GitHub Actions): lint, build matrix, mock unit + end-to-end tests, coverage.

### Changed
- Renamed the project from `se-ssh` to **`sod`** (Botanica Software Labs).
- The invocable command is **`sd`** (in the spirit of `fd`/`rg`). The product name,
  repository, default key (`~/.ssh/id_sod`), agent socket, bundle identifiers, and
  handle-file magic all remain `sod`.
- Default key is now `~/.ssh/id_sod`; default socket `~/.ssh/sod-agent.sock`.
- New handle-file magic `SOD-HANDLE-v1`; the legacy `SE-SSH-HANDLE-v1` is still
  accepted on read, so existing keys keep working.

[Unreleased]: https://github.com/botanica-consulting/sod/commits/main
