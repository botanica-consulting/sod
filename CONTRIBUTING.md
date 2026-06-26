# Contributing to sod

Thanks for your interest! `sod` aims to be a lean, OpenSSH-faithful tool in the spirit
of `pass` and `wireguard-tools`. Please keep changes minimal and in that spirit.

## Principles

- **Stay lean.** No new dependencies beyond Apple's swift-argument-parser without a
  strong reason. No config files, no telemetry, no feature creep.
- **Be faithful.** Mirror the behavior, flags, and output of `ssh-keygen` / `ssh-agent`
  / `ssh-add` wherever it makes sense.
- **Keep the SE seam.** All Secure Enclave access goes through `KeyBackend`; never
  reach around it.

## Build & run

```sh
bash scripts/gen-version.sh        # writes Sources/sod/Version.swift (run before building)
swift build -c release             # real Secure-Enclave binary
SE_SSH_MOCK=1 swift build          # mock backend: no SE, no Touch ID (development)
```

A Swift 6 toolchain via **Command Line Tools is enough** — Xcode is not required.

## Tests

The suite is a dependency-free executable (no XCTest, so it runs under CLT). The
KeyStore and Agent suites are gated on the mock backend:

```sh
SE_SSH_MOCK=1 swift run sod-tests              # unit suites (wire + keystore + agent)
SE_SSH_MOCK=1 bash scripts/selftest.sh /tmp/k  # full mock end-to-end (no Touch ID)
```

Coverage (via llvm-cov, no XCTest needed):

```sh
bash scripts/coverage.sh           # prints a report + writes .build/coverage/sod.lcov
```

`SecureEnclaveBackend` reads ~0% coverage — it cannot run without a real Secure
Enclave. That is expected; don't "fix" it.

**Real-Secure-Enclave end-to-end is a manual, local step** (there's no SE or Touch ID
on CI). Before tagging a release, run on a real Mac and approve the Touch ID prompt:

```sh
swift build -c release && bash scripts/selftest.sh ~/keys/se/id
```

## Style

`swift format` (bundled with the toolchain) is the formatter and linter:

```sh
swift format --in-place --recursive Sources Tests   # autofix
swift format lint --strict --recursive Sources Tests # the CI gate
```

## Pull requests

- Keep the diff focused; update `CHANGELOG.md` under `## [Unreleased]`.
- Make sure `swift format lint --strict` and `SE_SSH_MOCK=1 swift run sod-tests` pass.
- Crypto / Secure Enclave changes (`Sources/SEKeyStore`, `Sources/SSHWire`) get extra
  review — explain the reasoning.
