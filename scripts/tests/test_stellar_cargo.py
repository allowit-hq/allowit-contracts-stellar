"""The pinned CLI's Cargo bridge preserves failures and independent Wasm bytes."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("stellar_cargo", Path(__file__).resolve().parents[1] / "stellar-cargo.py")
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)


class StellarCargoBridgeTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.manifest = self.root / "source/contracts/simple/Cargo.toml"
        self.manifest.parent.mkdir(parents=True)
        self.manifest.write_text("[package]\nname = 'allowit-simple-engine'\n")
        # The metadata target can be outside the checkout and differ from ./target.
        self.target = self.root / "external-cache/wasm32v1-none/release"
        self.target.mkdir(parents=True)
        self.original = self.target / "allowit_simple_policy_engine.wasm"
        self.original.write_bytes(b"\0asm\x01\0\0\0contract bytes")
        self.alias = self.target / "allowit_simple_engine.wasm"
        self.args = ["rustc", "--manifest-path=" + str(self.manifest), "--target=wasm32v1-none", "--release"]
        self.metadata = {"target_directory": str(self.target.parents[1]), "packages": [
            {"manifest_path": str(self.root / "other/Cargo.toml"), "name": "unrelated", "targets": []},
            {"manifest_path": str(self.manifest), "name": "allowit-simple-engine", "targets": [
                {"name": "example", "crate_types": ["bin"]},
                {"name": "allowit_simple_policy_engine", "crate_types": ["cdylib", "rlib"]}]}]}

    def invoke(self, status=0, args=None):
        args = self.args if args is None else args
        with patch.dict(os.environ, {"ALLOWIT_REAL_CARGO": "/tools/real-cargo"}), \
                patch.object(sys, "argv", ["cargo", *args]), \
                patch.object(bridge.subprocess, "run", return_value=SimpleNamespace(returncode=status)) as run, \
                patch.object(bridge.subprocess, "check_output", return_value=json.dumps(self.metadata)) as metadata:
            result = bridge.main()
        run.assert_called_once_with(["/tools/real-cargo", *args])
        return result, metadata

    def test_cargo_failure_preserves_status_and_existing_outputs(self):
        self.alias.write_bytes(b"previous artifact")
        result, metadata = self.invoke(status=37)
        self.assertEqual(result, 37)
        metadata.assert_not_called()
        self.assertEqual(self.alias.read_bytes(), b"previous artifact")
        self.assertEqual(self.original.read_bytes(), b"\0asm\x01\0\0\0contract bytes")

    def test_success_copies_named_cdylib_bytes_in_external_target(self):
        result, metadata = self.invoke()
        self.assertEqual(result, 0)
        metadata.assert_called_once_with(["/tools/real-cargo", "metadata", "--locked", "--no-deps", "--format-version", "1", "--manifest-path", str(self.manifest)], text=True)
        self.assertEqual(self.alias.read_bytes(), self.original.read_bytes())
        self.assertNotEqual(self.alias.stat().st_ino, self.original.stat().st_ino)
        # The CLI can rewrite its copy without altering Cargo's library output.
        self.alias.write_bytes(b"CLI metadata and optimization")
        self.assertEqual(self.original.read_bytes(), b"\0asm\x01\0\0\0contract bytes")

    def test_matching_library_and_package_names_need_no_copy(self):
        self.metadata["packages"][1]["name"] = "allowit-simple-policy-engine"
        original = self.original.read_bytes()
        result, metadata = self.invoke()
        self.assertEqual(result, 0)
        metadata.assert_called_once()
        self.assertEqual(self.original.read_bytes(), original)
        self.assertFalse(self.alias.exists())
        self.assertEqual(list(self.target.iterdir()), [self.original])

    def test_non_rustc_metadata_is_forwarded_without_inspection(self):
        args = ["metadata", "--format-version", "1", "--no-deps"]
        result, metadata = self.invoke(args=args)
        self.assertEqual(result, 0)
        metadata.assert_not_called()
        self.assertFalse(self.alias.exists())


if __name__ == "__main__":
    unittest.main()
