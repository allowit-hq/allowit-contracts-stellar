//! Source and schema bindings. The shared portability vectors run in `allowit-policy-wallet`:
//! `src/portability_tests.rs` compares the std-only host smoke with the Soroban backend and the
//! custom, standard and simple contracts.
extern crate std;
use super::*;
use allowit::{
    AllowitOperation, AllowitParams, AllowitRequest, AllowitStandardState, AllowitValue, CALL_CAP,
    DAY_SPENT_CAP, DAY_TOTAL_CAP, EXPIRY, OPERATIONS, RECIPIENTS, SPENT_CAP, TOKENS,
    TRANSACTION_CAP,
};
use soroban_sdk::{Address, Bytes, Map, String, Symbol, testutils::Address as _, vec};

/// Set one param of `ctx`, or unset it with `None`.
fn set(ctx: &mut AllowitContext, key: &str, value: Option<AllowitValue>) {
    let key = Symbol::new(&ctx.env, key);
    match value {
        Some(value) => ctx.params.0.set(key, value),
        None => {
            ctx.params.0.remove(key);
        }
    }
}

#[test]
fn custom_runner_maps_the_policy_result() {
    let env = Env::default();
    let recipient = Address::generate(&env);
    let asset = Address::generate(&env);
    let mut state = Map::new(&env);
    let current = AllowitStandardState {
        spent: 5,
        ..Default::default()
    };
    current.write(&mut state).unwrap();
    let mut ctx = AllowitContext {
        env: env.clone(),
        params: AllowitParams(Map::new(&env)),
        state,
        request: AllowitRequest {
            operation: AllowitOperation::sep41_transfer,
            asset: asset.clone(),
            recipient: recipient.clone(),
            amount: 10,
            token_in: asset.clone(),
            amount_in: 10,
            token_out: None,
            min_out: 0,
            now: 10,
            expires_at: 20,
            spent_units: 10,
            gas_units: 0,
            unpriced: false,
            args: AllowitParams(Map::new(&env)),
        },
    };
    let int = |n: i128| Some(AllowitValue::Int(n));
    let list = |a: &Address| {
        Some(AllowitValue::List(vec![
            &env,
            AllowitValue::Addr(a.clone()),
        ]))
    };
    let ops = |name: &str| {
        let name = AllowitValue::Str(String::from_str(&env, name));
        Some(AllowitValue::List(vec![&env, name]))
    };
    for (key, value) in [
        (TRANSACTION_CAP, int(10)),
        (SPENT_CAP, int(15)),
        (DAY_SPENT_CAP, int(10)),
        (DAY_TOTAL_CAP, int(10)),
        (CALL_CAP, int(1)),
        (RECIPIENTS, list(&recipient)),
        (TOKENS, list(&asset)),
        (EXPIRY, int(100)),
        (OPERATIONS, ops("transfer")),
    ] {
        set(&mut ctx, key, value);
    }
    let rules = Vec::new(&env);
    assert_eq!(AllowitCustom::check(&ctx, &rules), Ok(()));
    let mut denied = ctx.clone();
    set(&mut denied, SPENT_CAP, int(14));
    assert_eq!(
        AllowitCustom::check(&denied, &rules),
        Err(AllowitWalletError::PolicyDenied)
    );
    let mut unset = ctx.clone();
    set(&mut unset, EXPIRY, None);
    assert_eq!(
        AllowitCustom::check(&unset, &rules),
        Err(AllowitWalletError::InvalidParam)
    );
    // Only payments: a policy that allows only deposits denies this transfer.
    let mut deposits = ctx.clone();
    set(&mut deposits, OPERATIONS, ops("deposit"));
    assert_eq!(
        AllowitCustom::check(&deposits, &rules),
        Err(AllowitWalletError::PolicyDenied)
    );
}

#[test]
fn source_and_schema_bindings_match_their_exact_inputs() {
    let env = Env::default();
    let source = Bytes::from_slice(&env, include_bytes!("../policy/policy.rs"));
    assert_eq!(env.crypto().sha256(&source).to_array(), SOURCE_HASH);
    let schemas = [
        (
            allowit_wallet_protocol::ARGUMENT_SCHEMA_DESCRIPTOR,
            ARGUMENT_SCHEMA_HASH,
        ),
        (
            allowit_wallet_protocol::ROUTER_SWAP_SCHEMA_DESCRIPTOR,
            SWAP_SCHEMA_HASH,
        ),
        (
            allowit_wallet_protocol::SEP56_REDEEM_SCHEMA_DESCRIPTOR,
            REDEEM_SCHEMA_HASH,
        ),
    ];
    for ((descriptor, hash), operation) in schemas.into_iter().zip(ADMITTED_OPERATIONS) {
        let schema = Bytes::from_slice(&env, descriptor);
        assert_eq!(env.crypto().sha256(&schema).to_array(), hash);
        let descriptor = core::str::from_utf8(descriptor).unwrap();
        assert!(descriptor.contains(&operation.replace("::", ".")));
        assert!(AllowitCustom::admits_schema(
            &env,
            &BytesN::from_array(&env, &hash)
        ));
    }
    // Custom admits no deposit.
    let deposit = Bytes::from_slice(
        &env,
        allowit_wallet_protocol::SEP56_DEPOSIT_SCHEMA_DESCRIPTOR,
    );
    let deposit = env.crypto().sha256(&deposit).to_bytes();
    assert!(!AllowitCustom::admits_schema(&env, &deposit));
}
