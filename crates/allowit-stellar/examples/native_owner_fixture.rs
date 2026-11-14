//! Deterministic public compatibility fixture. These test keys are never used on chain.
use allowit_stellar::{
    AccountState, account_for_seed,
    owner::{SetupTerms, prepare_native_setup},
};
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
        &SetupTerms {
            wallet: &account_for_seed(&[4; 32]),
            agent: &account_for_seed(&[2; 32]),
            engine: &account_for_seed(&[3; 32]),
            request_id: "stellar-setup-001",
            network: "stellar:testnet",
            fee_per_operation: 100,
            starting_balance: None,
            trustline: None,
        },
        1_800_000_000,
    )
    .unwrap();
    println!("{}", serde_json::to_string_pretty(&v).unwrap());
}
