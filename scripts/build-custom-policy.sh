#!/usr/bin/env bash
# Build the Custom tier Wasm for one reviewed policy source.
#
#   scripts/build-custom-policy.sh SOURCE.rs OUT_DIR
#
# SOURCE.rs is the owner's one policy source. The contract compiles the on-chain part that Core
# derives from it, keeps the figures and state keys that Core names for that part, and embeds the
# SHA-256 of SOURCE.rs. `allowit-stellar-admin custom-build-inputs`, built from the same copy of
# the committed tree with its locked dependencies, writes those build inputs into the copy, as the
# build hook does, so the checkout stays unchanged and no input comes from anywhere else. The copy has a fixed path, so the same revision, source,
# toolchain and Stellar CLI give the same Wasm. It prints one JSON line:
#   {"source_digest": SHA-256 of SOURCE.rs, "wasm_hash": SHA-256 of the Wasm, "wasm": path}
# `source_digest` is the wallet's `source_hash`. `wasm_hash` is the executable hash that the owner
# binds.
set -euo pipefail
[ $# -eq 2 ] || { echo "usage: $0 SOURCE.rs OUT_DIR" >&2; exit 2; }
source_file=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
mkdir -p "$2"
out=$(cd "$2" && pwd)
cd "$(dirname "$0")/.."
stellar_bin="${STELLAR_BIN:-stellar}"
digest=$(shasum -a 256 "$source_file" | cut -d ' ' -f 1)
tree="${TMPDIR:-/tmp}/allowit-custom-policy-build"
lock="$tree.lock"
if ! mkdir "$lock" 2>/dev/null; then
  echo "Another build-custom-policy.sh holds $lock; remove it if no build runs." >&2
  exit 1
fi
trap 'rm -rf "$tree"; rmdir "$lock"' EXIT
rm -rf "$tree"
mkdir -p "$tree"
git archive --format=tar HEAD | tar -x -C "$tree"
# The committed tree's own build inputs give way to those of SOURCE.rs. The generator is the
# committed revision's, built from the copy, in a folder of the caller's Cargo build folder or of
# the checkout's ignored `target`, so a later run reuses it.
policy="$tree/contracts/allowit-custom-policy/policy"
inputs_target="${CARGO_TARGET_DIR:-$PWD/target}/custom-build-inputs"
(cd "$tree" && CARGO_TARGET_DIR="$inputs_target" cargo run --quiet --locked \
  --manifest-path crates/allowit-stellar/Cargo.toml \
  --bin allowit-stellar-admin -- custom-build-inputs "$source_file" "$policy" >&2)
(cd "$tree" && CARGO_TARGET_DIR="$tree/target" "$stellar_bin" contract build --locked \
  --package allowit-custom-policy --out-dir "$out" >&2)
wasm="$out/allowit_custom_policy.wasm"
wasm_hash=$(shasum -a 256 "$wasm" | cut -d ' ' -f 1)
printf '{"source_digest":"%s","wasm_hash":"%s","wasm":"%s"}\n' "$digest" "$wasm_hash" "$wasm"
