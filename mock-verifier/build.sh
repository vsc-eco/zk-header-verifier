#!/usr/bin/env bash
# Build the DEVNET mock ZK header verifier (test double — see mock-verifier/main.go).
# Same pinned tinygo toolchain + gc.custom flags as the real verifier (Makefile).
set -euo pipefail
cd "$(dirname "$0")/.."   # zk-header-verifier repo root
mkdir -p bin .cache
docker run --rm -u "$(id -u):$(id -g)" \
  -v "$(pwd)":/work -v "$(pwd)/.cache":/cache -e HOME=/cache -w /work \
  tinygo/tinygo@sha256:b216f534ddbf277444407b014a3328b5c1ade403cc397f3ab48a14789bf99d0e \
  tinygo build -gc=custom -scheduler=none -panic=trap -no-debug -target=wasm-unknown \
    -o bin/mock-verifier.wasm ./mock-verifier
echo "built bin/mock-verifier.wasm"
sha256sum bin/mock-verifier.wasm
