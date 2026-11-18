#!/bin/sh
# Runs a command with IP networking denied, as the review sandbox does: a test that binds a
# socket (even on 127.0.0.1), connects or resolves a name fails. Build first, then run the
# tests through this script, for example:
#   cargo test --locked --no-run && scripts/no-network.sh cargo test --locked --offline
# Linux: a systemd unit that may create no IP socket (needs sudo and systemd), as this user.
#   It passes HOME, PATH and the Cargo and rustup settings; pass others with `env NAME=VALUE`.
# macOS: the built-in sandbox with network access denied.
set -eu
if [ "$#" -eq 0 ]; then
  echo "usage: $0 command [argument...]" >&2
  exit 2
fi
case "$(uname -s)" in
Linux)
  set -- --setenv=HOME="$HOME" --setenv=PATH="$PATH" -- "$@"
  for name in CARGO_HOME CARGO_INCREMENTAL CARGO_TARGET_DIR CARGO_TERM_COLOR RUSTFLAGS RUSTUP_HOME RUSTUP_TOOLCHAIN; do
    eval "value=\${$name-}"
    if [ -n "$value" ]; then
      set -- --setenv="$name=$value" "$@"
    fi
  done
  exec sudo systemd-run --quiet --pipe --wait --same-dir --uid="$(id -u)" --gid="$(id -g)" \
    --property=PrivateNetwork=yes --property=RestrictAddressFamilies=AF_UNIX "$@"
  ;;
Darwin)
  exec sandbox-exec -p '(version 1)(allow default)(deny network*)' "$@"
  ;;
*)
  echo "$0: no network guard for $(uname -s)" >&2
  exit 2
  ;;
esac
