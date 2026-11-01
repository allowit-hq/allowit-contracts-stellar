#!/usr/bin/env bash
# Build policy/engine test fixtures, then every deployable default artifact.
#
# Cargo builds in its configured target directory, so a shared target directory reuses compiled
# dependencies across worktrees. Tests read the artifacts from ./target, so the script copies the
# deployable Wasm to target/wasm32v1-none/release and the test fixtures to target/test-fixtures.
# Test-feature builds use their own target directory, so the deployable release paths never hold a
# test artifact. A lock in the Cargo target directory runs one build at a time per target directory.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo_target=$(cargo metadata --locked --no-deps --format-version 1 |
  python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])')
mkdir -p "$cargo_target" target/test-fixtures
lock="$cargo_target/.build-contracts.lock"
if ! mkdir "$lock" 2>/dev/null; then
  echo "Another build-contracts.sh holds $lock; remove it if no build runs." >&2
  exit 1
fi
trap 'rmdir "$lock"' EXIT
python3 scripts/check-policy-bindings.py
stellar_bin="${STELLAR_BIN:-stellar}"
fixtures="$cargo_target/test-fixture-build"
CARGO_TARGET_DIR="$fixtures" "$stellar_bin" contract build --locked --package allowit-wallet-engine --features test-deny
cp "$fixtures/wasm32v1-none/release/allowit_wallet_engine.wasm" target/test-fixtures/engine_deny.wasm
CARGO_TARGET_DIR="$fixtures" "$stellar_bin" contract build --locked --package allowit-custom-policy --features test-catching
cp "$fixtures/wasm32v1-none/release/allowit_custom_policy.wasm" target/test-fixtures/custom_catching.wasm
# The Stellar CLI truncates a Wasm that it copies onto itself, so copy only from another directory.
if [ "$cargo_target" -ef target ]; then
  "$stellar_bin" contract build --locked
else
  "$stellar_bin" contract build --locked --out-dir target/wasm32v1-none/release
fi
