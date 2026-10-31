#!/usr/bin/env bash
# Build policy/engine test fixtures, then every deployable default artifact.
#
# Tests include the artifacts from the default target/ directory, so this script ignores
# CARGO_TARGET_DIR. Test-feature builds use their own target directory and are copied to
# target/test-fixtures, so the deployable release paths never hold a test artifact. Run one build
# or `cargo test` at a time per worktree; a lock stops a second concurrent build. Use another
# worktree for concurrent runs.
set -euo pipefail
cd "$(dirname "$0")/.."
unset CARGO_TARGET_DIR
# A cargo config build.target-dir would also redirect the deployable build away from ./target.
export CARGO_BUILD_TARGET_DIR="$PWD/target"
mkdir -p target/test-fixtures
lock=target/.build-contracts.lock
if ! mkdir "$lock" 2>/dev/null; then
  echo "Another build-contracts.sh holds $lock in this worktree; remove it if no build runs." >&2
  exit 1
fi
trap 'rmdir "$lock"' EXIT
python3 scripts/check-policy-bindings.py
stellar_bin="${STELLAR_BIN:-stellar}"
fixtures=target/test-fixture-build
CARGO_TARGET_DIR="$fixtures" "$stellar_bin" contract build --locked --package allowit-wallet-engine --features test-deny
cp "$fixtures/wasm32v1-none/release/allowit_wallet_engine.wasm" target/test-fixtures/engine_deny.wasm
CARGO_TARGET_DIR="$fixtures" "$stellar_bin" contract build --locked --package allowit-custom-policy --features test-catching
cp "$fixtures/wasm32v1-none/release/allowit_custom_policy.wasm" target/test-fixtures/custom_catching.wasm
"$stellar_bin" contract build --locked
