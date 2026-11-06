#!/bin/sh
set -eu

cd "$(dirname "$0")/.."
target_dir="${CARGO_TARGET_DIR:-$PWD/target/browser-owner-verifier}"
flags=$(printf '%s\037%s' "--remap-path-prefix=$PWD=/allowit-stellar" \
  "--remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo")
CARGO_ENCODED_RUSTFLAGS="$flags" cargo +1.98.0 rustc \
  --manifest-path stellar/core/Cargo.toml --locked --release --features browser-owner-verifier \
  --target wasm32-unknown-unknown --target-dir "$target_dir" --lib --crate-type cdylib
built="$target_dir/wasm32-unknown-unknown/release/allowit_stellar_wallet.wasm"
if [ "${1:-}" = "--update" ]; then
  mkdir -p browser/dist
  install -m 644 "$built" browser/dist/owner-verifier.wasm
else
  cmp "$built" browser/dist/owner-verifier.wasm
fi
