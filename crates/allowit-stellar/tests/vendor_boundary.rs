//! Runs the vendor-boundary eval, so `cargo test` fails when another vendor's code enters this repository.
use std::path::Path;
use std::process::Command;

fn scan(arg: Option<&str>) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut cmd = Command::new("node");
    cmd.arg("scripts/vendor-boundary.mjs").current_dir(&root);
    if let Some(arg) = arg {
        cmd.arg(arg);
    }
    let out = cmd
        .output()
        .expect("vendor-boundary needs Node 22 or later on PATH");
    assert!(
        out.status.success(),
        "vendor-boundary {arg:?} failed:\n{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn vendor_boundary_self_test() {
    scan(Some("--self-test"));
}

#[test]
fn vendor_boundary_has_no_findings() {
    scan(None);
}
