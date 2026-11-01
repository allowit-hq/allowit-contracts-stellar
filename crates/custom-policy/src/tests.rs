//! Rule checks. The shared portability vectors run in `allowit-policy-wallet`:
//! `src/portability_tests.rs` compares the std-only host smoke with the Soroban backend and the
//! custom, standard and simple contracts.
extern crate std;
use super::*;
use allowit::{
    AllowitArgs, AllowitOperation, AllowitParams, AllowitRequest, AllowitStandardState,
    AllowitValue, CALL_LIMIT, DAILY_SPENDING_LIMIT, DAILY_VOLUME_LIMIT, DESTINATIONS, EXPIRES_AT,
    LIFETIME_SPENDING_LIMIT, OPERATIONS, PAYMENT_LIMIT, TOKENS,
};
use soroban_sdk::{
    Address, Map, String, Symbol, contract, contractimpl, testutils::Address as _, vec,
};

/// Contract scope in which a policy abort reports its contract error.
#[contract]
struct Scope;
#[contractimpl]
impl Scope {}

/// Set one param of `ctx`, or unset it with `None`.
fn set(ctx: &mut AllowitContext, key: &str, value: Option<AllowitValue>) {
    let key = Symbol::new(&ctx.env, key);
    let mut map = ctx.params.map().clone();
    match value {
        Some(value) => map.set(key, value),
        None => {
            map.remove(key);
        }
    }
    ctx.params = AllowitParams::new(&ctx.env, map).unwrap();
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
        params: AllowitParams::new(&env, Map::new(&env)).unwrap(),
        state,
        request: AllowitRequest {
            operation: AllowitOperation::transfer,
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
            args: AllowitArgs(Map::new(&env)),
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
        (PAYMENT_LIMIT, int(10)),
        (LIFETIME_SPENDING_LIMIT, int(15)),
        (DAILY_SPENDING_LIMIT, int(10)),
        (DAILY_VOLUME_LIMIT, int(10)),
        (CALL_LIMIT, int(1)),
        (DESTINATIONS, list(&recipient)),
        (TOKENS, list(&asset)),
        (EXPIRES_AT, int(100)),
        (OPERATIONS, ops("transfer")),
    ] {
        set(&mut ctx, key, value);
    }
    let rules = Vec::new(&env);
    assert_eq!(AllowitCustom::check(&ctx, &rules), Ok(()));
    let mut denied = ctx.clone();
    set(&mut denied, LIFETIME_SPENDING_LIMIT, int(14));
    assert_eq!(
        AllowitCustom::check(&denied, &rules),
        Err(AllowitWalletError::PolicyDenied)
    );
    // An unset param that the policy indexes aborts the whole contract call with `MissingParam`.
    let mut unset = ctx.clone();
    set(&mut unset, EXPIRES_AT, None);
    let scope = env.register(Scope, ());
    let run = env.try_as_contract::<_, allowit::AllowitError>(&scope, || {
        AllowitCustom::check(&unset, &rules)
    });
    assert_eq!(run, Err(Ok(allowit::AllowitError::MissingParam)));
    // Only payments: a policy that allows only deposits denies this transfer.
    let mut deposits = ctx.clone();
    set(&mut deposits, OPERATIONS, ops("deposit"));
    assert_eq!(
        AllowitCustom::check(&deposits, &rules),
        Err(AllowitWalletError::PolicyDenied)
    );
}
