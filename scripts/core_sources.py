"""Resolve exact released Core tooling from this repository's locked portable dependency."""
import functools
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CANONICAL = "https://github.com/allowit-hq/allowit-core.git"


def _run(args):
    result = subprocess.run(args, cwd=ROOT, capture_output=True, timeout=60, check=False)
    if result.returncode:
        raise ValueError("Cannot resolve the locked Core tooling")
    return result.stdout


def _checked_file(root, revision, relative):
    path = (root / relative).resolve()
    if not path.is_relative_to(root):
        raise ValueError("Core tooling must remain inside its released source root")
    expected = _run(["git", "-C", str(root), "show", revision + ":" + relative])
    if path.read_bytes() != expected:
        raise ValueError("Core tooling differs from its locked release: " + relative)
    return path


@functools.lru_cache(maxsize=1)
def core_root():
    metadata = json.loads(_run(["cargo", "metadata", "--locked", "--format-version", "1"]))
    candidates = [package for package in metadata["packages"] if package["name"] == "allowit"]
    if len(candidates) != 1:
        raise ValueError("The build must resolve exactly one portable Core library")
    package = candidates[0]
    source = package.get("source") or ""
    identity = re.fullmatch(r"git\+" + re.escape(CANONICAL) + r"\?tag=(v\d+\.\d+\.\d+)#([0-9a-f]{40})", source)
    if identity is None:
        raise ValueError("The portable library must resolve to a released canonical Core tag")
    revision = identity.group(2)
    root = Path(package["manifest_path"]).resolve().parents[2]
    if _run(["git", "-C", str(root), "rev-parse", "HEAD"]).decode().strip() != revision:
        raise ValueError("Core checkout does not match its locked release")
    for relative in ("scripts/policy_source.py", "crates/allowit/src/lib.rs", "crates/allowit/src/core.rs"):
        _checked_file(root, revision, relative)
    return root


if __name__ == "__main__":
    paths = {"--portable-lib": "crates/allowit/src/lib.rs", "--helper": "scripts/policy_source.py"}
    if len(sys.argv) != 2 or sys.argv[1] not in paths:
        raise SystemExit("usage: core_sources.py --portable-lib|--helper")
    print(core_root() / paths[sys.argv[1]])
