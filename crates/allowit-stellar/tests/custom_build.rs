//! The build of the Custom wallet Wasm from a policy source. These tests run the Stellar CLI and
//! the Rust toolchain and fetch crates, so they are ignored by default:
//!
//!   cargo test --locked --manifest-path crates/allowit-stellar/Cargo.toml --test custom_build -- --ignored
use allowit_core::vendor::{
    custom_build::{check_code_hash, code},
    plugin::RailPlugin,
};
use allowit_stellar::plugin::PLUGIN;

const NETWORK: &str = "stellar:testnet";
const SOURCE: &str = include_str!("../../../contracts/allowit-custom-policy/policy/policy.rs");

#[test]
#[ignore = "runs the Stellar CLI and fetches crates"]
fn the_same_source_builds_the_same_code_and_altered_source_builds_other_code() {
    let hook = PLUGIN.custom_wallet_build().unwrap();
    let work = tempfile::tempdir().unwrap();
    let first = hook.build(NETWORK, SOURCE, &work.path().join("a")).unwrap();
    // Another folder and a warm compiler cache give the same Wasm.
    let again = hook.build(NETWORK, SOURCE, &work.path().join("b")).unwrap();
    assert_eq!(first.code, again.code);
    assert_eq!(
        hook.code_hash(NETWORK, &first.code).unwrap(),
        first.code_hash
    );
    assert!(
        first.toolchain.starts_with("stellar 28.1.0"),
        "{}",
        first.toolchain
    );
    // `scripts/build-custom-policy.sh` builds the same Wasm from a checkout of this revision.
    if let Ok(expected) = std::env::var("ALLOWIT_EXPECTED_CUSTOM_WASM_HASH") {
        assert_eq!(
            allowit_core::vendor::custom_build::hex(&first.code_hash),
            expected
        );
    }
    // The owner's client builds the admitted source itself. Code built from altered source has
    // another hash, so the client refuses to sign a creation that names it.
    let altered = SOURCE.replace("pub fn execute", "/// Altered.\npub fn execute");
    assert_ne!(altered, SOURCE);
    let other = hook
        .build(NETWORK, &altered, &work.path().join("a"))
        .unwrap();
    assert_ne!(other.code_hash, first.code_hash);
    check_code_hash(&first.code_hash, &again.code_hash).unwrap();
    let error = check_code_hash(&first.code_hash, &other.code_hash).unwrap_err();
    assert_eq!(error.api_code.as_deref(), Some(code::CODE_HASH_MISMATCH));
}

/// A source with a server part: the contract compiles the on-chain part that Core derives, and
/// embeds the hash of the owner's whole source. So a change in the server part alone gives other
/// code, and the owner's client, which derives and builds the same part, gets the same hash.
#[test]
#[ignore = "runs the Stellar CLI and fetches crates"]
fn a_source_with_a_server_part_builds_its_on_chain_part_and_binds_the_whole_source() {
    const ONE: &str = "use allowit::prelude::*;\nuse allowit::AllowitDecision;\npub fn execute(ctx: &AllowitContext) -> allowit::Result {\n    allowit::payment_limit(ctx, &ctx.params[allowit::PAYMENT_LIMIT])?;\n    let visits: u64 = allowit::get_state(ctx, \"visits\")?.unwrap_or(0);\n    allowit::set_state(ctx, \"visits\", visits + 1)?;\n    let score = allowit::decision(ctx, &AllowitDecision { id: \"research\", query: \"Is this payment for research?\", deny_below: 3000, allow_above: 8000 })?;\n    allowit::set_state(ctx, \"last_score\", score)?;\n    Ok(())\n}\n";
    let hook = PLUGIN.custom_wallet_build().unwrap();
    let work = tempfile::tempdir().unwrap();
    let first = hook.build(NETWORK, ONE, &work.path().join("a")).unwrap();
    let again = hook.build(NETWORK, ONE, &work.path().join("b")).unwrap();
    assert_eq!(first.code, again.code);
    // The compiled file is the on-chain part, and the tree keeps the owner's source beside it.
    let policy = work
        .path()
        .join("a/tree/contracts/allowit-custom-policy/policy");
    let compiled = std::fs::read_to_string(policy.join("policy.rs")).unwrap();
    assert!(compiled.contains("\"visits\"") && !compiled.contains("decision"));
    assert_eq!(
        std::fs::read_to_string(policy.join("source.rs")).unwrap(),
        ONE
    );
    // The same on-chain part under another question is another source: other code.
    let other = ONE.replace("for research?", "for research data?");
    let other = hook.build(NETWORK, &other, &work.path().join("c")).unwrap();
    assert_ne!(other.code_hash, first.code_hash);
    // The on-chain part alone, as a source of its own, is a third source.
    let alone = hook
        .build(NETWORK, &compiled, &work.path().join("d"))
        .unwrap();
    assert_ne!(alone.code_hash, first.code_hash);
}
