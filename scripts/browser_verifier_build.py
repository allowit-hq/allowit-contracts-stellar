"""Build the owner verifier with stable Cargo identities on POSIX hosts."""
import contextlib
import fcntl
import hashlib
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import time

STAGING = Path("/tmp/allowit-stellar-owner-verifier-v1")
FORMAT = b"allowit-stellar-owner-verifier-v1\n"
CRATES = ("crates/allowit-stellar", "crates/policy-bindings")
INPUTS = tuple(f"{crate}/{item}" for crate in CRATES for item in ("Cargo.toml", "Cargo.lock", "src"))


def private_directory(path):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError(f"Expected an owned private directory: {path}")


def private_file(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
        raise ValueError(f"Expected an owned private regular file: {path}")
    return info


@contextlib.contextmanager
def locked_staging(path, wait_seconds=10):
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        private_directory(path)
    else:
        (path / "format").write_bytes(FORMAT)
        (path / "format").chmod(0o600)
    private_directory(path)
    private_file(path / "format")
    if (path / "format").read_bytes() != FORMAT or set(p.name for p in path.iterdir()) - {"format", "lock", "source", "cargo-home"}:
        raise ValueError("The verifier staging directory contains unrelated data")
    descriptor = os.open(path / "lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = private_file(path / "lock")
        opened = os.fstat(descriptor)
        if (info.st_dev, info.st_ino) != (opened.st_dev, opened.st_ino):
            raise ValueError("The verifier lock changed while opening")
        deadline = time.monotonic() + wait_seconds
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise ValueError("Another verifier build holds the staging lock") from None
                time.sleep(0.1)
        if (path / "source").exists() or (path / "source").is_symlink():
            raise ValueError("Existing verifier source staging needs inspection")
        cargo_home = path / "cargo-home"
        try:
            cargo_home.mkdir(mode=0o700)
        except FileExistsError:
            private_directory(cargo_home)
        for name in ("config", "config.toml", "credentials", "credentials.toml"):
            if (cargo_home / name).exists() or (cargo_home / name).is_symlink():
                raise ValueError("Verifier Cargo home contains configuration or credentials")
        yield path / "source", cargo_home
    finally:
        os.close(descriptor)


def stage_sources(root, destination):
    git = ["git", "--no-replace-objects", "-c", "core.hooksPath=/dev/null", "-C", str(root)]
    revision = subprocess.check_output([*git, "rev-parse", "HEAD"], text=True).strip()
    if subprocess.run([*git, "diff", "--quiet", revision, "--", *INPUTS]).returncode:
        raise ValueError("Commit the Rust verifier inputs before rebuilding")
    if subprocess.check_output([*git, "ls-files", "--others", "--exclude-standard", "--", *INPUTS]):
        raise ValueError("Commit the new Rust verifier inputs before rebuilding")
    entries = subprocess.check_output([*git, "ls-tree", "-rz", revision, "--", *INPUTS]).split(b"\0")
    destination.mkdir(mode=0o700)
    for entry in filter(None, entries):
        metadata, raw_path = entry.split(b"\t", 1)
        mode, kind, oid = metadata.decode().split()
        relative = Path(os.fsdecode(raw_path))
        if mode not in {"100644", "100755"} or kind != "blob" or relative.is_absolute() or ".." in relative.parts:
            raise ValueError("Verifier inputs must be committed regular files")
        data = subprocess.check_output([*git, "cat-file", "blob", oid])
        target = destination / relative
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        target.write_bytes(data)
    if subprocess.check_output([*git, "rev-parse", "HEAD"], text=True).strip() != revision:
        raise ValueError("The verifier source revision changed during staging")


def build(root, update=False):
    target = Path(os.environ.get("CARGO_TARGET_DIR", root / "target/browser-owner-verifier")).absolute()
    artifact = root / "npm/stellar/dist/owner-verifier.wasm"
    with locked_staging(STAGING) as (source, cargo_home):
        try:
            stage_sources(root, source)
            names = {"PATH", "HOME", "RUSTUP_HOME", "TMPDIR", "TMP", "TEMP", "SYSTEMROOT", "LANG", "LC_ALL"}
            environment = {name: value for name, value in os.environ.items() if name in names}
            environment["CARGO_HOME"] = str(cargo_home)
            environment["CARGO_ENCODED_RUSTFLAGS"] = "\x1f".join((
                f"--remap-path-prefix={source}=/allowit-stellar",
                f"--remap-path-prefix={cargo_home}=/cargo",
            ))
            subprocess.run(["cargo", "+1.98.0", "rustc", "--manifest-path", str(source / CRATES[0] / "Cargo.toml"),
                "--locked", "--release", "--features", "browser-owner-verifier", "--target", "wasm32-unknown-unknown",
                "--target-dir", str(target), "--lib", "--crate-type", "cdylib"], env=environment, check=True)
            built = target / "wasm32-unknown-unknown/release/allowit_stellar_wallet.wasm"
            if update:
                artifact.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(built, artifact)
                artifact.chmod(0o644)
            elif built.read_bytes() != artifact.read_bytes():
                digest = hashlib.sha256(built.read_bytes()).hexdigest()
                raise ValueError(f"The rebuilt owner verifier differs from the committed artifact (SHA-256 {digest})")
        finally:
            if source.is_dir() and not source.is_symlink():
                shutil.rmtree(source)


if __name__ == "__main__":
    os.umask(0o077)
    if sys.argv[1:] not in ([], ["--update"]):
        raise SystemExit("usage: build-browser-owner-verifier.sh [--update]")
    try:
        build(Path(__file__).resolve().parents[1], sys.argv[1:] == ["--update"])
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        raise SystemExit(str(error)) from None
