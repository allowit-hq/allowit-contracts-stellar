#!/usr/bin/env bash
# The cargo that cargo-mutants calls (see .cargo/mutants.toml). The contract tests run the built
# Wasm (`include_bytes!` of target/...), so before the tests of a mutant are built, this rebuilds
# the Wasm from the mutated copy. Each build copy uses its own ./target, never a shared target
# directory: a mutant must not reach another build.
set -euo pipefail
unset CARGO
export CARGO_TARGET_DIR="$PWD/target"
if [ "${1-}" = test ] && [[ " $* " == *" --no-run "* ]]; then
  # A build that was stopped leaves the lock of build-contracts.sh; this copy runs one build at a time.
  rmdir target/.build-contracts.lock 2>/dev/null || true
  scripts/build-contracts.sh >&2
fi
exec cargo "$@"
