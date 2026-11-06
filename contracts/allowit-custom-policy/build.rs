//! Bind the contract to the exact bytes of its compiled policy source.
use sha2::{Digest, Sha256};
use std::{env, fs, path::Path};
fn main() {
    let manifest = Path::new(&env::var("CARGO_MANIFEST_DIR").unwrap()).to_path_buf();
    // The `test-catching` fixture compiles `src/catching_policy.rs` instead.
    let source = if env::var_os("CARGO_FEATURE_TEST_CATCHING").is_some() {
        manifest.join("src/catching_policy.rs")
    } else {
        manifest.join("policy/policy.rs")
    };
    println!("cargo:rerun-if-changed={}", source.display());
    let digest = Sha256::digest(fs::read(&source).unwrap());
    let bytes: Vec<String> = digest.iter().map(u8::to_string).collect();
    fs::write(
        Path::new(&env::var("OUT_DIR").unwrap()).join("source_hash.rs"),
        format!("[{}]", bytes.join(", ")),
    )
    .unwrap();
}
