//! Bind the contract to the exact bytes of the owner's policy source.
//!
//! The contract compiles `policy/policy.rs`. For a policy that names no server function, that
//! file is the owner's source. For a policy with server functions, it is the on-chain part that
//! Core derives from the owner's source, and `policy/source.rs` holds the owner's source. The
//! contract binds the hash of the owner's source in both cases.
use sha2::{Digest, Sha256};
use std::{env, fs, path::Path};
fn main() {
    let manifest = Path::new(&env::var("CARGO_MANIFEST_DIR").unwrap()).to_path_buf();
    let owner = manifest.join("policy/source.rs");
    println!("cargo:rerun-if-changed={}", owner.display());
    // The `test-catching` fixture compiles `src/catching_policy.rs` instead.
    let source = if env::var_os("CARGO_FEATURE_TEST_CATCHING").is_some() {
        manifest.join("src/catching_policy.rs")
    } else if owner.exists() {
        owner
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
