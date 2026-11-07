"""Reproducible verifier inputs and staging authority remain bounded."""
import fcntl
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import browser_verifier_build as verifier


class VerifierBuild(unittest.TestCase):
    def repository(self, path):
        path.mkdir()
        subprocess.run(["git", "init", "-q", path], check=True)
        for crate in verifier.CRATES:
            directory = path / crate
            (directory / "src").mkdir(parents=True)
            (directory / "Cargo.toml").write_text("exact manifest\n")
            (directory / "Cargo.lock").write_text("exact lock\n")
            (directory / "src/lib.rs").write_text("exact Rust source\n")
        subprocess.run(["git", "-C", path, "add", "."], check=True)
        subprocess.run(["git", "-C", path, "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
            "commit", "-qm", "Verifier inputs"], check=True)

    def test_committed_bytes_match_across_roots_and_exclude_runtime(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            snapshots = []
            for name in ("first", "second"):
                repository = root / name
                self.repository(repository)
                (repository / "runtime.env").write_text("unrelated runtime input\n")
                destination = root / (name + "-snapshot")
                verifier.stage_sources(repository, destination)
                snapshots.append({str(p.relative_to(destination)): p.read_bytes()
                    for p in destination.rglob("*") if p.is_file()})
            self.assertEqual(snapshots[0], snapshots[1])
            self.assertEqual(len(snapshots[0]), 6)
            self.assertNotIn("runtime.env", snapshots[0])

    def test_dirty_and_new_source_inputs_require_commit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            self.repository(repository)
            source = repository / verifier.CRATES[0] / "src/lib.rs"
            source.write_text("changed source\n")
            with self.assertRaisesRegex(ValueError, "Commit the Rust"):
                verifier.stage_sources(repository, root / "dirty")
            source.write_text("exact Rust source\n")
            source.with_name("new.rs").write_text("new source\n")
            with self.assertRaisesRegex(ValueError, "Commit the new Rust"):
                verifier.stage_sources(repository, root / "new")

    def test_committed_symlink_inputs_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            self.repository(repository)
            (repository / verifier.CRATES[0] / "src/link.rs").symlink_to("/etc/hosts")
            subprocess.run(["git", "-C", repository, "add", "."], check=True)
            subprocess.run(["git", "-C", repository, "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                "commit", "-qm", "Symlink input"], check=True)
            with self.assertRaisesRegex(ValueError, "committed regular"):
                verifier.stage_sources(repository, root / "snapshot")

    def test_foreign_unsafe_and_unrelated_staging_is_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / "staging"
            with verifier.locked_staging(directory):
                pass
            with patch.object(verifier.os, "getuid", return_value=os.getuid() + 1):
                with self.assertRaisesRegex(ValueError, "owned private"):
                    with verifier.locked_staging(directory):
                        self.fail("Foreign staging accepted")
            directory.chmod(0o755)
            with self.assertRaisesRegex(ValueError, "owned private"):
                with verifier.locked_staging(directory):
                    self.fail("Public staging accepted")
            directory.chmod(0o700)
            unrelated = directory / "unrelated"
            unrelated.write_text("preserve this file\n")
            with self.assertRaisesRegex(ValueError, "unrelated data"):
                with verifier.locked_staging(directory):
                    self.fail("Unrelated staging accepted")
            self.assertEqual(unrelated.read_text(), "preserve this file\n")
            link = root / "link"
            link.symlink_to(directory, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "owned private"):
                with verifier.locked_staging(link):
                    self.fail("Linked staging accepted")

    def test_concurrent_lock_is_bounded_and_prior_source_is_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "staging"
            with verifier.locked_staging(directory):
                with self.assertRaisesRegex(ValueError, "holds the staging lock"):
                    with verifier.locked_staging(directory, wait_seconds=0):
                        self.fail("Concurrent build acquired the lock")
            source = directory / "source"
            source.mkdir()
            retained = source / "retained.rs"
            retained.write_text("preserve prior source\n")
            with self.assertRaisesRegex(ValueError, "needs inspection"):
                with verifier.locked_staging(directory):
                    self.fail("Existing source accepted")
            self.assertEqual(retained.read_text(), "preserve prior source\n")

    def test_lock_symlink_and_cargo_credentials_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "staging"
            with verifier.locked_staging(directory):
                pass
            lock = directory / "lock"
            lock.unlink()
            marker = directory / "format"
            lock.symlink_to(marker)
            with self.assertRaises(OSError):
                with verifier.locked_staging(directory):
                    self.fail("Linked lock accepted")
            lock.unlink()
            credentials = directory / "cargo-home/credentials.toml"
            credentials.write_text("unrelated credential storage\n")
            with self.assertRaisesRegex(ValueError, "configuration or credentials"):
                with verifier.locked_staging(directory):
                    self.fail("Credential storage accepted")
            self.assertEqual(credentials.read_text(), "unrelated credential storage\n")
