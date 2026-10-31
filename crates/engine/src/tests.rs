use super::*;
use allowit::{AllowitOperation, AllowitRule, AllowitStandardState, RULES as ALL};
use soroban_sdk::{testutils::Address as _, vec};
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
/// Current state before a 40-unit priced transfer: after it, spent is 45 and day_total 43.
fn fixture(env: &Env) -> AllowitContext {
    let mut state = Map::new(env);
    let current = AllowitStandardState {
        calls: 1,
        spent: 5,
        day_spent: 5,
        day_total: 3,
        ..Default::default()
    };
    current.write(&mut state).unwrap();
    let asset = Address::generate(env);
    let recipient = Address::generate(env);
    let mut ctx = AllowitContext {
        env: env.clone(),
        params: AllowitParams(Map::new(env)),
        state,
        request: AllowitRequest {
            operation: AllowitOperation::sep41_transfer,
            asset: asset.clone(),
            recipient: recipient.clone(),
            amount: 40,
            token_in: asset.clone(),
            amount_in: 40,
            token_out: None,
            min_out: 0,
            now: 100,
            expires_at: 500,
            spent_units: 40,
            gas_units: 0,
            unpriced: false,
            args: AllowitParams(Map::new(env)),
        },
    };
    let int = |n: i128| Some(AllowitValue::Int(n));
    let text = |op: &str| AllowitValue::Str(soroban_sdk::String::from_str(env, op));
    let list = |a: &Address| Some(AllowitValue::List(vec![env, AllowitValue::Addr(a.clone())]));
    for (key, value) in [
        (allowit::TRANSACTION_CAP, int(100)),
        (allowit::SPENT_CAP, int(45)),
        (allowit::DAY_SPENT_CAP, int(50)),
        (allowit::DAY_TOTAL_CAP, int(100)),
        (allowit::CALL_CAP, int(3)),
        (allowit::RECIPIENTS, list(&recipient)),
        (allowit::TOKENS, list(&asset)),
        (allowit::EXPIRY, int(1_000)),
        (
            allowit::OPERATIONS,
            Some(AllowitValue::List(vec![env, text("transfer")])),
        ),
    ] {
        set(&mut ctx, key, value);
    }
    ctx
}
#[test]
fn native_contract_wrapper_matches_the_bundled_rule() {
    let env = Env::default();
    let ctx = fixture(&env);
    let call = || {
        AllowitEngine::day_total_cap(
            env.clone(),
            ctx.params.0.clone(),
            ctx.state.clone(),
            ctx.request.clone(),
        )
    };
    assert_eq!(
        call(),
        allowit::day_total_cap(&ctx, ctx.params.get(allowit::DAY_TOTAL_CAP))
    );
    assert_eq!(call(), Ok(57));
}
#[test]
fn engine_metadata_is_pure_release_data() {
    let env = Env::default();
    assert_eq!(AllowitEngine::engine_version(env.clone()), 4);
    assert!(env.auths().is_empty());
}

#[test]
fn compiled_engine_returns_bundled_pass_values_and_rule_errors() {
    const WASM: &[u8] =
        include_bytes!("../../../target/wasm32v1-none/release/allowit_wallet_engine.wasm");
    let env = Env::default();
    let id = env.register(WASM, ());
    let client = AllowitEngineClient::new(&env, &id);
    let mut ctx = fixture(&env);
    let c = &ctx;
    let p = |key| c.params.get(key);
    // The exhaustive match fails to compile when a rule lacks its engine method.
    for rule in ALL {
        match rule {
            AllowitRule::transaction_cap => {
                let v = allowit::transaction_cap(c, p(allowit::TRANSACTION_CAP));
                assert_eq!(
                    (client.transaction_cap(&c.params.0, &c.state, &c.request), v),
                    (60, Ok(60))
                );
            }
            AllowitRule::spent_cap => {
                let v = allowit::spent_cap(c, p(allowit::SPENT_CAP));
                assert_eq!(
                    (client.spent_cap(&c.params.0, &c.state, &c.request), v),
                    (0, Ok(0))
                );
            }
            AllowitRule::day_spent_cap => {
                let v = allowit::day_spent_cap(c, p(allowit::DAY_SPENT_CAP));
                assert_eq!(
                    (client.day_spent_cap(&c.params.0, &c.state, &c.request), v),
                    (5, Ok(5))
                );
            }
            AllowitRule::day_total_cap => {
                let v = allowit::day_total_cap(c, p(allowit::DAY_TOTAL_CAP));
                assert_eq!(
                    (client.day_total_cap(&c.params.0, &c.state, &c.request), v),
                    (57, Ok(57))
                );
            }
            AllowitRule::call_cap => {
                let v = allowit::call_cap(c, p(allowit::CALL_CAP));
                assert_eq!(
                    (client.call_cap(&c.params.0, &c.state, &c.request), v),
                    (1, Ok(1))
                );
            }
            AllowitRule::recipients => {
                let v = allowit::recipients(c, p(allowit::RECIPIENTS));
                assert_eq!(Ok(client.recipients(&c.params.0, &c.state, &c.request)), v);
                assert_eq!(v, Ok(c.request.recipient.clone()));
            }
            AllowitRule::tokens => {
                let v = allowit::tokens(c, p(allowit::TOKENS));
                assert_eq!(Ok(client.tokens(&c.params.0, &c.state, &c.request)), v);
                assert_eq!(v, Ok(c.request.asset.clone()));
            }
            AllowitRule::expiry => {
                let v = allowit::expiry(c, p(allowit::EXPIRY));
                assert_eq!(
                    (client.expiry(&c.params.0, &c.state, &c.request), v),
                    (900, Ok(900))
                );
            }
            AllowitRule::operations => {
                let v = allowit::operations(c, p(allowit::OPERATIONS));
                let op = client.operations(&c.params.0, &c.state, &c.request);
                assert_eq!(
                    (op, v),
                    (
                        soroban_sdk::String::from_str(&env, "transfer"),
                        Ok("transfer")
                    )
                );
            }
        }
    }
    set(
        &mut ctx,
        allowit::DAY_TOTAL_CAP,
        Some(AllowitValue::Int(42)),
    );
    assert_eq!(
        client.try_day_total_cap(&ctx.params.0, &ctx.state, &ctx.request),
        Err(Ok(AllowitError::DayTotalCapExceeded))
    );
    set(&mut ctx, allowit::SPENT_CAP, None);
    assert_eq!(
        client.try_spent_cap(&ctx.params.0, &ctx.state, &ctx.request),
        Err(Ok(AllowitError::MissingParam))
    );
    let deposits = AllowitValue::List(vec![
        &env,
        AllowitValue::Str(soroban_sdk::String::from_str(&env, "deposit")),
    ]);
    set(&mut ctx, allowit::OPERATIONS, Some(deposits));
    assert_eq!(
        client.try_operations(&ctx.params.0, &ctx.state, &ctx.request),
        Err(Ok(AllowitError::OperationNotAllowed))
    );
    // A failed rule reads and writes no more ledger entries than a passing one, so a failure at
    // apply time that simulation did not see stays within the simulated footprint.
    let passing = fixture(&env);
    assert_eq!(
        client.try_expiry(&passing.params.0, &passing.state, &passing.request),
        Ok(Ok(900))
    );
    let pass = env.cost_estimate().resources();
    assert_eq!(
        client.try_day_total_cap(&ctx.params.0, &ctx.state, &ctx.request),
        Err(Ok(AllowitError::DayTotalCapExceeded))
    );
    let fail = env.cost_estimate().resources();
    assert_eq!(fail.write_entries, 0);
    assert_eq!(fail.memory_read_entries, pass.memory_read_entries);
    assert_eq!(fail.disk_read_entries, pass.disk_read_entries);
}
