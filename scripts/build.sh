#!/usr/bin/env bash
# Check cross-repository pins, then build.
#
#   scripts/build.sh            fail on a stale pin, then build
#   scripts/build.sh --check    only check the pins and the locks
#   scripts/build.sh --update   rewrite stale pins and Cargo.lock, then build
#   scripts/build.sh --update <repo>...
#                               rewrite only the pins of the named repositories
#
# [workspace.metadata.allowit.track] says which revision each git repository
# must be pinned to. Keys are repository names:
#
#   repo = "head"                  the tip of the remote default branch
#   repo = { branch = "name" }     the tip of that branch
#   repo = { version = "1.2.3" }   the commit of tag v1.2.3
#
# Every git dependency needs an entry and a full `rev` in Cargo.toml.
# Packages inside this repository use path dependencies, share one version
# and are not pinned.
set -euo pipefail
cd "$(dirname "$0")/.."

usage="usage: scripts/build.sh [--check | --update [repo...]]"
mode=build
case "${1-}" in
  "") ;;
  --check) mode=check ;;
  --update) mode=update ;;
  *) echo "$usage" >&2; exit 2 ;;
esac
[ $# -gt 0 ] && shift
# Repositories named after --update. Empty means every repository.
names=$(printf '%s\n' "$@" | sed '/^$/d')
if [ -n "$names" ] && [ "$mode" != update ]; then echo "$usage" >&2; exit 2; fi

# Tracked and new manifests, so an unstaged workspace is checked too.
manifests=$(git ls-files --cached --others --exclude-standard -- '*Cargo.toml' \
  | while read -r m; do if [ -f "$m" ]; then echo "$m"; fi; done)
workspaces=$(for m in $manifests; do
  if grep -q '^\[workspace\]' "$m"; then echo "$m"; fi
done)
all=""
for m in $workspaces; do
  one=$(cargo metadata --no-deps --format-version 1 --manifest-path "$m") \
    || { echo "$m: cargo metadata failed" >&2; exit 1; }
  all="$all$one"$'\n'
done
meta=$(jq -s '{packages: (map(.packages) | add),
               tracks: map(.metadata.allowit.track // {} | to_entries[])}' <<<"$all")

if [ "$(jq '[.packages[].version] | unique | length' <<<"$meta")" != 1 ]; then
  echo "packages must share one version:" >&2
  jq -r '.packages[] | "  \(.name) \(.version)"' <<<"$meta" >&2
  exit 1
fi
conflicts=$(jq -r '.tracks | group_by(.key)[] | select(map(.value) | unique | length > 1)
                   | .[0].key' <<<"$meta")
if [ -n "$conflicts" ]; then
  echo "workspaces track these repositories differently: $conflicts" >&2
  exit 1
fi

# url, rev and package name of every git dependency.
pins=$(jq -r '
  [.packages[].dependencies[] | select((.source // "") | startswith("git+"))
   | [(.source | ltrimstr("git+") | sub("[?#].*"; "")),
      ([.source | capture("[?&]rev=(?<r>[^&#]+)").r] | first // "-"),
      .name] | @tsv] | unique[]' <<<"$meta")
urls=$(cut -f1 <<<"$pins" | sed '/^$/d' | sort -u)
clashes=$(for url in $urls; do basename "$url" .git; done | sort | uniq -d)
if [ -n "$clashes" ]; then
  echo "different git URLs share a repository name: $clashes" >&2
  exit 1
fi

for name in $names; do
  if ! grep -qxF "$name" < <(for url in $urls; do basename "$url" .git; done); then
    echo "$name: no git dependency on this repository" >&2
    exit 2
  fi
done

failed=0
stale=""
for url in $urls; do
  repo=$(basename "$url" .git)
  spec=$(jq -c --arg r "$repo" 'first(.tracks[] | select(.key == $r) | .value) // empty' <<<"$meta")
  case "$spec" in
    '"head"') ref=HEAD ;;
    '{"branch":'*) ref=refs/heads/$(jq -r .branch <<<"$spec") ;;
    '{"version":'*) ref=refs/tags/v$(jq -r .version <<<"$spec") ;;
    "") echo "$repo: no entry in [workspace.metadata.allowit.track]" >&2; failed=1; continue ;;
    *) echo "$repo: unknown tracking $spec" >&2; failed=1; continue ;;
  esac
  # An annotated tag lists its commit last, as <ref>^{}.
  want=$(git ls-remote "$url" "$ref" "$ref^{}" | awk 'END { print $1 }')
  if [ -z "$want" ]; then
    echo "$repo: $ref not found at $url" >&2
    failed=1
    continue
  fi
  while IFS=$'\t' read -r _ rev name; do
    [ "$rev" = "$want" ] && continue
    echo "$name: $repo $spec is $want, pinned ${rev/#-/no rev}" >&2
    if [ "$rev" = - ]; then failed=1; else stale="$stale $repo:$rev:$want"; fi
  done < <(awk -F'\t' -v u="$url" '$1 == u' <<<"$pins")
done
[ "$failed" = 0 ] || exit 1

if [ -n "$stale" ]; then
  if [ "$mode" != update ]; then
    echo "stale pins: run scripts/build.sh --update" >&2
    exit 1
  fi
  moves=""
  for entry in $stale; do
    repo=${entry%%:*}
    if [ -z "$names" ] || grep -qxF "$repo" <<<"$names"; then
      moves="$moves ${entry#*:}"
    else
      echo "$repo: stale pin left in place" >&2
      failed=1
    fi
  done
  for manifest in $manifests; do
    for pair in $moves; do
      sed -i.orig "s/${pair%%:*}/${pair##*:}/g" "$manifest" && rm "$manifest.orig"
    done
  done
fi
# Refresh every lock, also after an interrupted update whose pins already
# moved. Only packages whose requirements changed move in the locks.
if [ "$mode" = update ]; then
  for m in $workspaces; do cargo update --workspace --manifest-path "$m"; done
fi

# Each lock holds one copy of every git package, so an update that moves
# allowit-core ahead of a pinned dependency cannot add a second allowit-core.
for m in $workspaces; do
  lock=$(dirname "$m")/Cargo.lock
  if [ ! -f "$lock" ]; then
    echo "$lock: missing" >&2
    failed=1
    continue
  fi
  dups=$(awk '/^name = /{n=$3} /^source = "git\+/{print n}' "$lock" | sort | uniq -d | tr -d '"' | xargs)
  if [ -n "$dups" ]; then
    echo "$lock: more than one copy of git package $dups" >&2
    failed=1
  fi
  if ! cargo metadata --locked --format-version 1 --manifest-path "$m" >/dev/null; then
    echo "$lock: does not match $m" >&2
    failed=1
  fi
done
[ "$failed" = 0 ] || exit 1
[ "$mode" = check ] && exit 0

# Tests embed the contract Wasm from target/, so build it first.
scripts/build-contracts.sh
cargo build --workspace --all-targets --locked
cargo build --manifest-path stellar/core/Cargo.toml --all-targets --locked
