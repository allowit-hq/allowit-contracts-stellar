//! Deterministic public compatibility fixture. These test keys are never used on chain.
use allowit_stellar_wallet::{AccountState, account_for_seed, owner::prepare_native_setup};
fn main() {
    let state = AccountState {
        address: account_for_seed(&[1; 32]),
        sequence: 10,
        master_weight: 1,
        low_threshold: 0,
        medium_threshold: 0,
        high_threshold: 0,
        signers: vec![],
    };
    let v = prepare_native_setup(
        &state,
        &account_for_seed(&[2; 32]),
        &account_for_seed(&[3; 32]),
        "stellar-setup-001",
        "stellar:testnet",
        100,
        1_800_000_000,
    )
    .unwrap();
    println!("{}", serde_json::to_string_pretty(&v).unwrap());
}
