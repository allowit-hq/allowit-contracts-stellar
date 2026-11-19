//! Bind the contract to its policy source and declare the figures that the policy reads.
//!
//! `SOURCE_HASH` is the SHA-256 of the owner's full source: `policy/source.rs` when it is present
//! (the owner's one source, from which the compiled on-chain policy is derived), else the compiled
//! `policy/policy.rs` itself. The owner's policy signature binds that hash, and the wallet stores it.
//!
//! `FIGURES` lists the wallet entries that hold the cumulated figures that the compiled policy
//! reads, so the wallet keeps exactly those. Core's derivation names the figures
//! (`Derived::figures`), and the build reads their keys, one per line, from `policy/policy.figures`
//! beside the compiled policy: the rail's build hook writes both files from the owner's source,
//! and `state_keys::packed` gives the entries of each key. A fixture has its own figures file.
//!
//! `STATE` lists the policy's own state entries: every key of an `allowit::get_state` and
//! `allowit::set_state` call. A key is a string literal of 1 to 32 ASCII letters, digits or `_`;
//! a `day_` key lives one daily window, any other key the minimum persistent lifetime. The
//! storage key is the first four bytes of the key's SHA-256. The build refuses a key that is not
//! a literal, a write of a standard figure, more than `MAX_POLICY_STATE` keys and two keys with
//! one storage key. Reading a standard figure through `get_state` keeps that figure.
use sha2::{Digest, Sha256};
use std::{env, fs, path::Path};

/// The policy's state keys: the same scan as the rail's server evaluation, and the entries of its
/// figures.
// The build reads the keys; the server alone reads the value bound.
#[allow(dead_code)]
#[path = "state_keys.rs"]
mod state_keys;

fn main() {
    let manifest = Path::new(&env::var("CARGO_MANIFEST_DIR").unwrap()).to_path_buf();
    // The `test-catching` and `test-daily` fixtures compile their own sources instead, each with
    // its figures.
    let fixture = if env::var_os("CARGO_FEATURE_TEST_CATCHING").is_some() {
        Some(("src/catching_policy.rs", "src/catching_policy.figures"))
    } else if env::var_os("CARGO_FEATURE_TEST_DAILY").is_some() {
        Some(("src/daily_policy.rs", "src/daily_policy.figures"))
    } else {
        None
    };
    let (policy, figures) = fixture.unwrap_or(("policy/policy.rs", "policy/policy.figures"));
    let (policy, figures) = (manifest.join(policy), manifest.join(figures));
    let owner_source = manifest.join("policy/source.rs");
    println!("cargo:rerun-if-changed={}", policy.display());
    println!("cargo:rerun-if-changed={}", figures.display());
    println!("cargo:rerun-if-changed={}", owner_source.display());
    println!("cargo:rerun-if-changed=state_keys.rs");
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
    let source = if owner_source.exists() && fixture.is_none() {
        fs::read(&owner_source).unwrap()
    } else {
        compiled.clone().into_bytes()
    };
    let digest = Sha256::digest(&source);
    let bytes: Vec<String> = digest.iter().map(u8::to_string).collect();
    let entries = state_keys::declared(&compiled, |name| Sha256::digest(name).into())
        .unwrap_or_else(|error| panic!("{error}"));
    let figures = fs::read_to_string(&figures)
        .map_err(|error| error.to_string())
        .and_then(|keys| state_keys::packed(keys.lines()))
        .unwrap_or_else(|error| panic!("the figures of the compiled policy: {error}"));
    let state = format!(
        "&[{}]",
        entries
            .iter()
            .map(|entry| format!(
                "allowit_policy_wallet::AllowitStateKey {{ name: {:?}, key: {:#010x}, daily: {} }}",
                entry.name, entry.key, entry.daily
            ))
            .collect::<Vec<_>>()
            .join(", ")
    );
    let out = Path::new(&env::var("OUT_DIR").unwrap()).to_path_buf();
    fs::write(
        out.join("source_hash.rs"),
        format!("[{}]", bytes.join(", ")),
    )
    .unwrap();
    fs::write(out.join("figures.rs"), format!("{figures}")).unwrap();
    fs::write(out.join("state.rs"), state).unwrap();
}
