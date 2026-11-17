//! Bind the contract to its policy source and declare the figures that the policy reads.
//!
//! `SOURCE_HASH` is the SHA-256 of the owner's full source: `policy/source.rs` when it is present
//! (the owner's one source, from which the compiled on-chain policy is derived), else the compiled
//! `policy/policy.rs` itself. The owner's policy signature binds that hash, and the wallet stores it.
//!
//! `FIGURES` lists the cumulated figures that the compiled policy's checks read, so the wallet
//! keeps exactly those. Core's source gate admits rule calls only as `allowit::<rule>`, so a rule
//! name in the compiled source text marks its figure; any name that can reach the state or every
//! rule marks all figures. The scan reads comments too, which can only add figures.
use sha2::{Digest, Sha256};
use std::{env, fs, path::Path};

/// Rule names and the figures they read: `SPENT`, `CALLS`, `DAY_SPENT`, `DAY_TOTAL`.
const RULES: [(&str, u8); 4] = [
    ("lifetime_spending_limit", 1),
    ("call_limit", 2),
    ("daily_spending_limit", 4),
    ("daily_volume_limit", 8),
];
/// Names through which a policy reads the state or runs any rule: they keep every figure.
const ALL: [&str; 6] = [
    "state",
    "preflight",
    "RULES",
    "AllowitRule",
    "AllowitStandardState",
    "evaluate",
];

fn main() {
    let manifest = Path::new(&env::var("CARGO_MANIFEST_DIR").unwrap()).to_path_buf();
    // The `test-catching` fixture compiles `src/catching_policy.rs` instead.
    let policy = if env::var_os("CARGO_FEATURE_TEST_CATCHING").is_some() {
        manifest.join("src/catching_policy.rs")
    } else {
        manifest.join("policy/policy.rs")
    };
    let owner_source = manifest.join("policy/source.rs");
    println!("cargo:rerun-if-changed={}", policy.display());
    println!("cargo:rerun-if-changed={}", owner_source.display());
    let compiled = fs::read_to_string(&policy).unwrap();
    for forbidden in [
        "unsafe",
        "include!",
        "include_str!",
        "include_bytes!",
        "#[path",
    ] {
        assert!(
            !compiled.contains(forbidden),
            "a policy source is one safe file: it must not use `{forbidden}`"
        );
    }
    let source = if owner_source.exists() && env::var_os("CARGO_FEATURE_TEST_CATCHING").is_none() {
        fs::read(&owner_source).unwrap()
    } else {
        compiled.clone().into_bytes()
    };
    let digest = Sha256::digest(&source);
    let bytes: Vec<String> = digest.iter().map(u8::to_string).collect();
    let mut figures = 0u8;
    for (name, figure) in RULES {
        if compiled.contains(name) {
            figures |= figure;
        }
    }
    if ALL.iter().any(|name| compiled.contains(name)) {
        figures = 15;
    }
    let out = Path::new(&env::var("OUT_DIR").unwrap()).to_path_buf();
    fs::write(
        out.join("source_hash.rs"),
        format!("[{}]", bytes.join(", ")),
    )
    .unwrap();
    fs::write(out.join("figures.rs"), format!("{figures}")).unwrap();
}
