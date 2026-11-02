#!/usr/bin/env python3
"""Write a public source/artifact manifest after an policy wallet build; contains no keys."""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ("allowit_simple_policy_engine", "allowit_common_policy_engine", "allowit_custom_policy", "allowit_wallet_engine", "allowit_engine_parent")
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--output", type=Path, help="Write the manifest to this explicit path; otherwise print to stdout only")
args = parser.parse_args()
files = [ROOT / "target/wasm32v1-none/release" / f"{name}.wasm" for name in CONTRACTS]
missing = [str(path.relative_to(ROOT)) for path in files if not path.is_file()]
if missing:
    parser.error("Build the policy wallet contracts first. Missing: " + ", ".join(missing))
source_files = [ROOT / name for name in ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml")]
source_files += sorted((ROOT / "crates").rglob("*.rs"))
source_files += sorted((ROOT / "crates").rglob("Cargo.toml"))
source_files += [ROOT / "scripts" / name for name in ("build-contracts.sh", "check-policy-bindings.py", "policy_source.py", "core_sources.py")]
manifest = {
    "schema": 2,
    "git_revision": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
    "network": None,
    "deployments": [],
    "sources": [{"path": str(path.relative_to(ROOT)), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()} for path in source_files],
    "artifacts": [{"name": path.name, "bytes": path.stat().st_size, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()} for path in files],
}
payload = json.dumps(manifest, indent=2) + "\n"
if args.output:
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(payload)
else:
    print(payload, end="")
