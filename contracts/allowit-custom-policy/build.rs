//! Bind the contract to its policy source and declare the figures that the policy reads.
//!
//! `SOURCE_HASH` is the SHA-256 of the owner's full source: `policy/source.rs` when it is present
//! (the owner's one source, from which the compiled on-chain policy is derived), else the compiled
//! `policy/policy.rs` itself. The owner's policy signature binds that hash, and the wallet stores it.
//!
//! `FIGURES` lists the cumulated figures that the compiled policy's checks read, so the wallet
//! keeps exactly those. Core's source gate admits rule calls only as `allowit::<rule>`, so a rule
//! name in the compiled source marks its figure; any name that can reach the whole state or every
//! rule marks all figures. The scan reads whole words, leaving out lines that start with `//`;
//! words in a literal or a trailing comment can only add figures.
//!
//! `STATE` lists the policy's own state entries: every key of an `allowit::get_state` and
//! `allowit::set_state` call. A key is a string literal of 1 to 32 ASCII letters, digits or `_`;
//! a `day_` key lives one daily window, any other key the minimum persistent lifetime. The
//! storage key is the first four bytes of the key's SHA-256. The build refuses a key that is not
//! a literal, a write of a standard figure, more than `MAX_POLICY_STATE` keys and two keys with
//! one storage key. Reading a standard figure through `get_state` keeps that figure.
use sha2::{Digest, Sha256};
use std::{env, fs, path::Path};

/// Rule names and the figures they read: `SPENT`, `CALLS`, `DAY_SPENT`, `DAY_TOTAL`.
const RULES: [(&str, u8); 4] = [
    ("lifetime_spending_limit", 1),
    ("call_limit", 2),
    ("daily_spending_limit", 4),
    ("daily_volume_limit", 8),
];
/// Names through which a policy reads the whole state or runs any rule: they keep every figure, as
/// does any other word that contains `state`, such as `ctx.state`.
const ALL: [&str; 5] = [
    "preflight",
    "RULES",
    "AllowitRule",
    "AllowitStandardState",
    "evaluate",
];

/// The policy's state keys: the same scan as the rail's server evaluation.
// The build reads the keys; the server alone reads the value bound.
#[allow(dead_code)]
#[path = "state_keys.rs"]
mod state_keys;

fn main() {
    let manifest = Path::new(&env::var("CARGO_MANIFEST_DIR").unwrap()).to_path_buf();
    // The `test-catching` and `test-daily` fixtures compile their own sources instead.
    let fixture = if env::var_os("CARGO_FEATURE_TEST_CATCHING").is_some() {
        Some("src/catching_policy.rs")
    } else if env::var_os("CARGO_FEATURE_TEST_DAILY").is_some() {
        Some("src/daily_policy.rs")
    } else {
        None
    };
    let policy = manifest.join(fixture.unwrap_or("policy/policy.rs"));
    let owner_source = manifest.join("policy/source.rs");
    println!("cargo:rerun-if-changed={}", policy.display());
    println!("cargo:rerun-if-changed={}", owner_source.display());
    println!("cargo:rerun-if-changed=state_keys.rs");
    let compiled = fs::read_to_string(&policy).unwrap();
    let code = without_comments(&compiled);
    let words: Vec<&str> = code
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|word| !word.is_empty())
        .collect();
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
    let mut figures = 0u8;
    for (name, figure) in RULES {
        if words.contains(&name) {
            figures |= figure;
        }
    }
    let (entries, read_figures) =
        state_keys::declared(&compiled, |name| Sha256::digest(name).into())
            .unwrap_or_else(|error| panic!("{error}"));
    figures |= read_figures;
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
    if words.iter().any(|word| {
        ALL.contains(word) || (word.contains("state") && !["get_state", "set_state"].contains(word))
    }) {
        figures = 15;
    }
    let out = Path::new(&env::var("OUT_DIR").unwrap()).to_path_buf();
    fs::write(
        out.join("source_hash.rs"),
        format!("[{}]", bytes.join(", ")),
    )
    .unwrap();
    fs::write(out.join("figures.rs"), format!("{figures}")).unwrap();
    fs::write(out.join("state.rs"), state).unwrap();
}

/// The source without the lines that start with `//`: doc and line comments. Such a line is a
/// comment or the inside of a literal, never code. Trailing and block comments stay in the scan,
/// which can only add figures.
fn without_comments(source: &str) -> String {
    source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}
