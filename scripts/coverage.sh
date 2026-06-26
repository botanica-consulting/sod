#!/usr/bin/env bash
# Source-based coverage from the XCTest-free runner, via llvm-cov (works under CLT —
# no `swift test`/Xcode needed). Emits .build/coverage/sod.lcov + a console report.
# Note: SecureEnclaveBackend reads ~0% — it cannot run without a real Secure Enclave;
# that is expected, not a regression.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p .build/coverage

FLAGS=(-Xswiftc -profile-generate -Xswiftc -profile-coverage-mapping)
SE_SSH_MOCK=1 swift build --product sod-tests "${FLAGS[@]}"
BIN="$(SE_SSH_MOCK=1 swift build --product sod-tests "${FLAGS[@]}" --show-bin-path)/sod-tests"

LLVM_PROFILE_FILE="$PWD/.build/coverage/sod-tests.profraw" "$BIN"
xcrun llvm-profdata merge -sparse \
  .build/coverage/sod-tests.profraw -o .build/coverage/sod-tests.profdata

xcrun llvm-cov export "$BIN" \
  -instr-profile=.build/coverage/sod-tests.profdata \
  -format=lcov -ignore-filename-regex='\.build|Tests' \
  > .build/coverage/sod.lcov

xcrun llvm-cov report "$BIN" \
  -instr-profile=.build/coverage/sod-tests.profdata \
  -ignore-filename-regex='\.build|Tests' \
  Sources/SSHWire Sources/SEKeyStore Sources/SodKit
