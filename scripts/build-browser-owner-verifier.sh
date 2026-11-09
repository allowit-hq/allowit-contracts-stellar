#!/bin/sh
set -eu

cd "$(dirname "$0")/.."
target_dir="${CARGO_TARGET_DIR:-$PWD/target/browser-owner-verifier}"
flags=$(printf '%s\037%s' "--remap-path-prefix=$PWD=/allowit-stellar" \
  "--remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo")
CARGO_ENCODED_RUSTFLAGS="$flags" cargo +1.98.0 rustc \
  --manifest-path crates/allowit-stellar/Cargo.toml --locked --release --features browser-owner-verifier \
  --target wasm32-unknown-unknown --target-dir "$target_dir" --lib --crate-type cdylib
built="$target_dir/wasm32-unknown-unknown/release/allowit_stellar.wasm"
# The package pins the verifier by this hash in its source and in dist/.
pins="npm/stellar/src/owner-verifier.ts npm/stellar/dist/owner-verifier.js"
hash=$(shasum -a 256 "$built" | cut -d ' ' -f 1)
if [ "${1:-}" = "--update" ]; then
  mkdir -p npm/stellar/dist
  install -m 644 "$built" npm/stellar/dist/owner-verifier.wasm
  for pin in $pins; do
    sed -i.bak "s/^const verifierHash = '[0-9a-f]*';$/const verifierHash = '$hash';/" "$pin"
    rm "$pin.bak"
  done
else
  cmp "$built" npm/stellar/dist/owner-verifier.wasm
fi
for pin in $pins; do
  grep -qx "const verifierHash = '$hash';" "$pin" || { echo "$pin does not pin $hash" >&2; exit 1; }
done
