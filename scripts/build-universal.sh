#!/usr/bin/env bash
# Build a universal (arm64 + x86_64) `sod` into dist/sod by building each slice
# natively and lipo-ing them together. A combined `swift build --arch a --arch b`
# routes through Xcode's xcbuild; building slices separately works under Command
# Line Tools too. The Secure Enclave exists on Apple Silicon AND T2 Intel Macs.
set -euo pipefail
cd "$(dirname "$0")/.."
bash scripts/gen-version.sh
mkdir -p dist

slices=()
for arch in arm64 x86_64; do
  echo "== building $arch slice =="
  swift build -c release --arch "$arch"
  slices+=("$(swift build -c release --arch "$arch" --show-bin-path)/sod")
done

lipo -create -output dist/sod "${slices[@]}"
echo "== dist/sod =="
file dist/sod
lipo -info dist/sod
