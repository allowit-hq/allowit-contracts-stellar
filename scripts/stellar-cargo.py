#!/usr/bin/env python3
"""Bridge Stellar CLI 28.1 package-based output lookup to Cargo library targets."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


def main():
    args = sys.argv[1:]
    status = subprocess.run([os.environ["ALLOWIT_REAL_CARGO"], *args]).returncode
    if status or not args or args[0] != "rustc":
        return status
    manifest = next((arg.split("=", 1)[1] for arg in args if arg.startswith("--manifest-path=")), None)
    if manifest is None:
        return 0
    metadata = json.loads(subprocess.check_output([os.environ["ALLOWIT_REAL_CARGO"], "metadata", "--locked", "--no-deps", "--format-version", "1", "--manifest-path", manifest], text=True))
    package_data = next(item for item in metadata["packages"] if Path(item["manifest_path"]).resolve() == Path(manifest).resolve())
    package = package_data["name"].replace("-", "_")
    library = next(item["name"] for item in package_data["targets"] if "cdylib" in item["crate_types"])
    if library != package:
        target = Path(metadata["target_directory"]) / "wasm32v1-none" / "release"
        # Copy instead of linking: the CLI rewrites metadata and optimizes this file.
        shutil.copyfile(target / (library + ".wasm"), target / (package + ".wasm"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
