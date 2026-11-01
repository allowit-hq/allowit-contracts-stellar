use super::*;
use allowit::{AllowitArgs, AllowitOperation, AllowitRule, AllowitStandardState, RULES as ALL};
use soroban_sdk::{testutils::Address as _, vec};
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
        params: AllowitParams::new(env, Map::new(env)).unwrap(),
        state,
        request: AllowitRequest {
            operation: AllowitOperation::transfer,
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
            args: AllowitArgs(Map::new(env)),
        },
    };
    let int = |n: i128| Some(AllowitValue::Int(n));
    let text = |op: &str| AllowitValue::Str(soroban_sdk::String::from_str(env, op));
    let list = |a: &Address| Some(AllowitValue::List(vec![env, AllowitValue::Addr(a.clone())]));
    for (key, value) in [
        (allowit::PAYMENT_LIMIT, int(100)),
        (allowit::LIFETIME_SPENDING_LIMIT, int(45)),
        (allowit::DAILY_SPENDING_LIMIT, int(50)),
        (allowit::DAILY_VOLUME_LIMIT, int(100)),
        (allowit::CALL_LIMIT, int(3)),
        (allowit::DESTINATIONS, list(&recipient)),
        (allowit::TOKENS, list(&asset)),
        (allowit::EXPIRES_AT, int(1_000)),
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
fn compiled_engine_returns_bundled_pass_values_and_rule_errors() {
    const WASM: &[u8] =
        include_bytes!("../../../target/wasm32v1-none/release/allowit_wallet_engine.wasm");
    let env = Env::default();
    let id = env.register(WASM, ());
    let client = AllowitEngineClient::new(&env, &id);
    let mut ctx = fixture(&env);
    let c = &ctx;
    let p = |key| &c.params[key];
    // The exhaustive match fails to compile when a rule lacks its engine method.
    for rule in ALL {
        match rule {
            AllowitRule::payment_limit => {
                let v = allowit::payment_limit(c, p(allowit::PAYMENT_LIMIT));
                assert_eq!(
                    (
                        client.payment_limit(c.params.map(), &c.state, &c.request),
                        v
                    ),
                    (60, Ok(60))
                );
            }
            AllowitRule::lifetime_spending_limit => {
                let v = allowit::lifetime_spending_limit(c, p(allowit::LIFETIME_SPENDING_LIMIT));
                assert_eq!(
                    (
                        client.lifetime_spending_limit(c.params.map(), &c.state, &c.request),
                        v
                    ),
                    (0, Ok(0))
                );
            }
            AllowitRule::daily_spending_limit => {
                let v = allowit::daily_spending_limit(c, p(allowit::DAILY_SPENDING_LIMIT));
                assert_eq!(
                    (
                        client.daily_spending_limit(c.params.map(), &c.state, &c.request),
                        v
                    ),
                    (5, Ok(5))
                );
            }
            AllowitRule::daily_volume_limit => {
                let v = allowit::daily_volume_limit(c, p(allowit::DAILY_VOLUME_LIMIT));
                assert_eq!(
                    (
                        client.daily_volume_limit(c.params.map(), &c.state, &c.request),
                        v
                    ),
                    (57, Ok(57))
                );
            }
            AllowitRule::call_limit => {
                let v = allowit::call_limit(c, p(allowit::CALL_LIMIT));
                assert_eq!(
                    (client.call_limit(c.params.map(), &c.state, &c.request), v),
                    (1, Ok(1))
                );
            }
            AllowitRule::destinations => {
                let v = allowit::destinations(c, p(allowit::DESTINATIONS));
                assert_eq!(
                    Ok(client.destinations(c.params.map(), &c.state, &c.request)),
                    v
                );
                assert_eq!(v, Ok(c.request.recipient.clone()));
            }
            AllowitRule::tokens => {
                let v = allowit::tokens(c, p(allowit::TOKENS));
                assert_eq!(Ok(client.tokens(c.params.map(), &c.state, &c.request)), v);
                assert_eq!(v, Ok(c.request.asset.clone()));
            }
            AllowitRule::expires_at => {
                let v = allowit::expires_at(c, p(allowit::EXPIRES_AT));
                assert_eq!(
                    (client.expires_at(c.params.map(), &c.state, &c.request), v),
                    (900, Ok(900))
                );
            }
            AllowitRule::operations => {
                let v = allowit::operations(c, p(allowit::OPERATIONS));
                let op = client.operations(c.params.map(), &c.state, &c.request);
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
        allowit::DAILY_VOLUME_LIMIT,
        Some(AllowitValue::Int(42)),
    );
    assert_eq!(
        client.try_daily_volume_limit(ctx.params.map(), &ctx.state, &ctx.request),
        Err(Ok(AllowitError::DailyVolumeLimitExceeded))
    );
    set(&mut ctx, allowit::LIFETIME_SPENDING_LIMIT, None);
    assert_eq!(
        client.try_lifetime_spending_limit(ctx.params.map(), &ctx.state, &ctx.request),
        Err(Ok(AllowitError::MissingParam))
    );
    let deposits = AllowitValue::List(vec![
        &env,
        AllowitValue::Str(soroban_sdk::String::from_str(&env, "deposit")),
    ]);
    set(&mut ctx, allowit::OPERATIONS, Some(deposits));
    assert_eq!(
        client.try_operations(ctx.params.map(), &ctx.state, &ctx.request),
        Err(Ok(AllowitError::OperationNotAllowed))
    );
    // A failed rule reads and writes no more ledger entries than a passing one, so a failure at
    // apply time that simulation did not see stays within the simulated footprint.
    let passing = fixture(&env);
    assert_eq!(
        client.try_expires_at(passing.params.map(), &passing.state, &passing.request),
        Ok(Ok(900))
    );
    let pass = env.cost_estimate().resources();
    assert_eq!(
        client.try_daily_volume_limit(ctx.params.map(), &ctx.state, &ctx.request),
        Err(Ok(AllowitError::DailyVolumeLimitExceeded))
    );
    let fail = env.cost_estimate().resources();
    assert_eq!(fail.write_entries, 0);
    assert_eq!(fail.memory_read_entries, pass.memory_read_entries);
    assert_eq!(fail.disk_read_entries, pass.disk_read_entries);
}
