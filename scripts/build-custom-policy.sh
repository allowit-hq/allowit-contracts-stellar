#!/usr/bin/env bash
# Build the Custom tier Wasm for one reviewed policy source.
#
#   scripts/build-custom-policy.sh POLICY.rs OUT_DIR
#
# The contract compiles `contracts/allowit-custom-policy/policy/policy.rs` verbatim and embeds the
# SHA-256 of its bytes. This script builds a copy of the committed tree with POLICY.rs in that
# place, so the checkout stays unchanged. The copy has a fixed path, so the same revision, source,
# toolchain and Stellar CLI give the same Wasm. It prints one JSON line:
#   {"source_digest": SHA-256 of POLICY.rs, "wasm_hash": SHA-256 of the Wasm, "wasm": path}
# `source_digest` is the wallet `source_digest` of `--tier custom`. `wasm_hash` is the executable
# hash that the owner binds.
set -euo pipefail
[ $# -eq 2 ] || { echo "usage: $0 POLICY.rs OUT_DIR" >&2; exit 2; }
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
cp "$source_file" "$tree/contracts/allowit-custom-policy/policy/policy.rs"
(cd "$tree" && CARGO_TARGET_DIR="$tree/target" "$stellar_bin" contract build --locked \
  --package allowit-custom-policy --out-dir "$out" >&2)
wasm="$out/allowit_custom_policy.wasm"
wasm_hash=$(shasum -a 256 "$wasm" | cut -d ' ' -f 1)
printf '{"source_digest":"%s","wasm_hash":"%s","wasm":"%s"}\n' "$digest" "$wasm_hash" "$wasm"
