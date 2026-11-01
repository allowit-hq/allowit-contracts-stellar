//! Compile the authored custom policies against the allowit host backend without chain dependencies.
//! rustc --edition=2024 -Coverflow-checks=on --crate-type=rlib --crate-name=allowit --cfg 'feature="std"' crates/allowit/src/lib.rs
//! rustc --edition=2024 -Coverflow-checks=on --test --extern allowit=liballowit.rlib scripts/policy-smoke.rs
//! `cargo test` in `allowit-policy-wallet` runs these commands, then compares the
//! `vectors_print_host_outcomes` lines with the Soroban backend and the wallet contracts.
#[path = "../crates/custom-policy/src/branch_policy.rs"]
mod branch;
#[path = "../crates/custom-policy/src/catching_policy.rs"]
mod catching;
#[path = "../crates/custom-policy/policy/policy.rs"]
mod policy;
#[path = "policy-vectors.rs"]
mod vectors;
use allowit::prelude::*;
use allowit::{
    AllowitArgs, AllowitEnv, AllowitMap, AllowitRule, AllowitStandardState, AllowitTier, DAY, RULES,
};
use vectors::{Op, Ops, Outcome, Vector};

const NOW: u64 = 3 * DAY + 10;
/// The state map of standard values `s`.
fn map(s: &AllowitStandardState) -> AllowitMap {
    let mut state = AllowitMap::new();
    s.write(&mut state).unwrap();
    state
}
/// Params or args of `entries`, without the absent ones.
fn params<T: From<AllowitMap>>(entries: Vec<(&str, Option<AllowitValue>)>) -> T {
    let present = entries
        .into_iter()
        .filter_map(|(k, v)| Some((k.to_string(), v?)));
    T::from(present.collect::<AllowitMap>())
}
/// Set or, with `None`, unset `key` in params or args, as the server rebuilds them.
fn put<T: Clone + From<AllowitMap>>(params: &mut T, key: &str, value: Option<AllowitValue>)
where
    AllowitMap: From<T>,
{
    let mut map = AllowitMap::from(params.clone());
    match value {
        Some(value) => map.insert(key.to_string(), value),
        None => map.remove(key),
    };
    *params = map.into();
}
/// The result of `run` as an error code. A panic that names a failed read, such as an unset
/// `ctx.params[key]` (`allowit: MissingParam for `key``), stops `run` with that error, as
/// `evaluate` does; any other panic is `Panicked`.
fn stopped<T>(run: impl FnOnce() -> allowit::Result<T>) -> core::result::Result<T, u32> {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(run));
    result
        .unwrap_or_else(|panic| {
            let message = panic.downcast_ref::<String>().map_or("", String::as_str);
            let read = [AllowitError::MissingParam, AllowitError::InvalidParam]
                .into_iter()
                .find(|e| message.starts_with(&format!("allowit: {e:?} for ")));
            Err(read.unwrap_or(AllowitError::Panicked))
        })
        .map_err(|e| e as u32)
}
/// A `List` of `Addr` values.
fn list(items: Vec<Address>) -> AllowitValue {
    AllowitValue::List(items.into_iter().map(AllowitValue::Addr).collect())
}
/// An `Int` value.
fn int(n: impl Into<i128>) -> Option<AllowitValue> {
    Some(AllowitValue::Int(n.into()))
}
/// The `operations` value of `ops`.
fn operations(ops: &Ops) -> AllowitValue {
    let text = |name: &str| AllowitValue::Str(name.to_string());
    match ops {
        Ops::Text(name) => text(name),
        Ops::List(names) => AllowitValue::List(names.iter().map(|name| text(name)).collect()),
    }
}
/// Current state before a 10-unit priced transfer that passes every rule with exact headroom.
fn context() -> AllowitContext {
    let recipient = Address::new("GRECIPIENT");
    let asset = Address::new("CASSET");
    AllowitContext {
        env: AllowitEnv::new(),
        params: params(vec![
            (allowit::PAYMENT_LIMIT, int(10)),
            (allowit::LIFETIME_SPENDING_LIMIT, int(30)),
            (allowit::DAILY_SPENDING_LIMIT, int(20)),
            (allowit::DAILY_VOLUME_LIMIT, int(20)),
            (allowit::CALL_LIMIT, int(2)),
            (allowit::DESTINATIONS, Some(list(vec![recipient.clone()]))),
            (allowit::TOKENS, Some(list(vec![asset.clone()]))),
            (allowit::EXPIRES_AT, int(NOW + 100)),
            (
                allowit::OPERATIONS,
                Some(operations(&Ops::List(vec!["transfer"]))),
            ),
        ]),
        state: map(&AllowitStandardState {
            calls: 1,
            spent: 10,
            day: NOW / DAY,
            day_spent: 10,
            day_total: 10,
            ..Default::default()
        }),
        request: AllowitRequest {
            operation: AllowitOperation::transfer,
            asset,
            recipient,
            amount: 10,
            token_in: Address::new("CASSET"),
            amount_in: 10,
            token_out: None,
            min_out: 0,
            now: NOW,
            expires_at: NOW + 50,
            spent_units: 10,
            gas_units: 0,
            unpriced: false,
            args: params(Vec::new()),
        },
    }
}
/// Edit the standard values of `c.state`.
fn edit(c: &mut AllowitContext, change: impl FnOnce(&mut AllowitStandardState)) {
    let mut s = AllowitStandardState::read(&c.state).unwrap();
    change(&mut s);
    c.state = map(&s);
}
#[test]
fn approval_passes_with_exact_constraints() {
    let c = context();
    let p = |key| &c.params[key];
    assert_eq!(policy::execute(&c), Ok(()));
    assert_eq!(allowit::payment_limit(&c, p(allowit::PAYMENT_LIMIT)), Ok(0));
    assert_eq!(
        allowit::lifetime_spending_limit(&c, p(allowit::LIFETIME_SPENDING_LIMIT)),
        Ok(10)
    );
    assert_eq!(
        allowit::daily_spending_limit(&c, p(allowit::DAILY_SPENDING_LIMIT)),
        Ok(0)
    );
    assert_eq!(allowit::call_limit(&c, p(allowit::CALL_LIMIT)), Ok(0));
    assert_eq!(
        allowit::destinations(&c, p(allowit::DESTINATIONS)),
        Ok(c.request.recipient.clone())
    );
    assert_eq!(allowit::expires_at(&c, p(allowit::EXPIRES_AT)), Ok(100));
}
#[test]
fn approval_branch_policy_caps_deposits() {
    let mut c = context();
    edit(&mut c, |s| s.spent = 21);
    assert_eq!(branch::execute(&c), Ok(()));
    c.request.operation = AllowitOperation::deposit;
    assert_eq!(
        branch::execute(&c),
        Err(AllowitError::LifetimeSpendingLimitExceeded)
    );
}
#[test]
fn approval_denies_absent_params() {
    let mut c = context();
    put(&mut c.params, allowit::TOKENS, None);
    assert!(!c.params.contains(allowit::TOKENS) && c.params.contains(allowit::DESTINATIONS));
    // Indexing the unset param stops the run; `evaluate` denies with `MissingParam`.
    let custom = AllowitTier::Custom;
    let missing = Err(AllowitError::MissingParam);
    assert_eq!(allowit::evaluate(&c, policy::execute, custom), missing);
    let code = AllowitError::MissingParam as u32;
    assert_eq!(stopped(|| policy::execute(&c)), Err(code));
    // A key that no map can hold is unset too.
    let spaced = |c: &AllowitContext| allowit::call_limit(c, &c.params["call limit"]).map(drop);
    assert_eq!(allowit::evaluate(&c, spaced, custom), missing);
    assert_eq!(allowit::preflight(&c, AllowitRule::tokens), Ok(()));
}
#[test]
fn approval_continues_after_a_caught_rule_error_and_post_flight_applies_its_writes() {
    let mut c = context();
    put(&mut c.params, allowit::DAILY_SPENDING_LIMIT, int(19));
    let next = allowit::evaluate(&c, catching::execute, AllowitTier::Custom).unwrap();
    let mut after = c.clone();
    after.state = next;
    assert_eq!(
        allowit::get_state::<u64>(&after, vectors::OVER),
        Ok(Some(1))
    );
    assert_eq!(allowit::get_state::<u64>(&after, "calls"), Ok(Some(2)));
    // A standard wallet cannot store the write, so the same run denies there.
    assert_eq!(
        allowit::evaluate(&c, catching::execute, AllowitTier::Standard),
        Err(AllowitError::Unsupported)
    );
    // Twice counted, the policy returns the error and the run ends.
    allowit::set_state(&c, vectors::OVER, 2u64).unwrap();
    after.state = allowit::post_flight(&c, AllowitTier::Custom).unwrap();
    assert_eq!(
        catching::execute(&after),
        Err(AllowitError::DailySpendingLimitExceeded)
    );
}
#[test]
fn approval_reads_execution_params_and_custom_params() {
    let mut c = context();
    // The agent names an invoice; the owner's custom cap then bounds the payment.
    put(&mut c.request.args, vectors::INVOICE, int(7));
    assert!(c.request.args.contains(vectors::INVOICE));
    assert_eq!(
        allowit::evaluate(&c, catching::execute, AllowitTier::Custom),
        Err(AllowitError::MissingParam)
    );
    put(&mut c.params, vectors::INVOICE_CAP, int(9));
    assert_eq!(
        catching::execute(&c),
        Err(AllowitError::PaymentLimitExceeded)
    );
    assert_eq!(allowit::param::<i128>(&c, vectors::INVOICE_CAP), 9);
    put(&mut c.request.args, vectors::INVOICE, None);
    assert_eq!(catching::execute(&c), Ok(()));
}
/// Records a write, then denies.
fn denying(c: &AllowitContext) -> allowit::Result {
    allowit::set_state(c, "seen", 1u64)?;
    Err(AllowitError::Expired)
}
#[test]
fn approval_evaluate_keeps_no_write_of_a_denied_run_on_a_reused_env() {
    let c = context();
    let custom = AllowitTier::Custom;
    // Run bare, a denied policy leaves its write in the shared host buffer.
    assert_eq!(denying(&c), Err(AllowitError::Expired));
    let stale = allowit::post_flight(&c, custom).unwrap();
    assert_eq!(stale.get("seen"), Some(&AllowitValue::Int(1)));
    // `evaluate` clears the buffer on denial and before each run.
    assert_eq!(
        allowit::evaluate(&c, denying, custom),
        Err(AllowitError::Expired)
    );
    assert_eq!(
        allowit::post_flight(&c.clone(), custom)
            .unwrap()
            .get("seen"),
        None
    );
    let next = allowit::evaluate(&c.clone(), policy::execute, custom).unwrap();
    assert_eq!(next.get("seen"), None);
    allowit::set_state(&c, "seen", 1u64).unwrap();
    assert_eq!(allowit::evaluate(&c, policy::execute, custom), Ok(next));
}
/// The documented per-op policy on the host: a transfer within the owner's `payment_cap`.
fn per_op(ctx: &AllowitContext) -> allowit::Result {
    match allowit::operations(ctx, &ctx.params[allowit::OPERATIONS])? {
        "transfer" => {
            // "at most the payment cap per transfer"
            let amount: i128 = allowit::arg(ctx, "amount");
            let cap: i128 = allowit::param(ctx, "payment_cap");
            if amount > cap {
                panic!("transfer above payment_cap");
            }
        }
        _ => {}
    }
    Ok(())
}
/// Records a write, then runs `per_op`.
fn writing_per_op(c: &AllowitContext) -> allowit::Result {
    allowit::set_state(c, "seen", 1u64)?;
    per_op(c)
}
#[test]
fn approval_typed_reads_return_the_binding_type_and_a_policy_panic_denies_without_writes() {
    let mut c = context();
    put(&mut c.params, "payment_cap", int(10));
    put(&mut c.request.args, "amount", int(10));
    let destinations: Vec<Address> = allowit::param(&c, allowit::DESTINATIONS);
    let amount: u32 = allowit::arg(&c, "amount");
    let cap: u64 = allowit::param(&c, "payment_cap");
    assert_eq!(destinations, vec![c.request.recipient.clone()]);
    assert_eq!((amount, cap), (10, 10));
    let custom = AllowitTier::Custom;
    let next = allowit::evaluate(&c, writing_per_op, custom).unwrap();
    assert_eq!(next.get("seen"), Some(&AllowitValue::Int(1)));
    // A panic is a hard stop: the run denies, its write is discarded and the evaluator goes on.
    // A failed typed read denies with its error, any other panic with `Panicked`.
    let cases: [(&str, Option<AllowitValue>, AllowitError); 4] = [
        ("amount", int(11), AllowitError::Panicked),
        ("amount", None, AllowitError::MissingParam),
        (
            "amount",
            Some(AllowitValue::Bool(true)),
            AllowitError::InvalidParam,
        ),
        ("payment_cap", None, AllowitError::MissingParam),
    ];
    for (key, value, error) in cases {
        let mut bad = c.clone();
        if key == "amount" {
            put(&mut bad.request.args, key, value);
        } else {
            put(&mut bad.params, key, value);
        }
        assert_eq!(
            allowit::evaluate(&bad, writing_per_op, custom),
            Err(error),
            "{key}"
        );
        let after = allowit::post_flight(&bad, custom).unwrap();
        assert_eq!(after.get("seen"), None, "{key}");
    }
    assert_eq!(allowit::evaluate(&c, writing_per_op, custom), Ok(next));
    // A rule error stays catchable: `operations` returns it.
    put(
        &mut c.params,
        allowit::OPERATIONS,
        Some(operations(&Ops::List(vec!["deposit"]))),
    );
    assert_eq!(per_op(&c), Err(AllowitError::OperationNotAllowed));
}
#[test]
fn limits_empty_keys_are_invalid_param_as_onchain() {
    // A Soroban `Symbol` may be empty; no backend admits it as a params or args key.
    let mut empty = AllowitMap::new();
    empty.insert(String::new(), AllowitValue::Int(1));
    let invalid = Err(AllowitError::InvalidParam);
    assert_eq!(allowit::check_params(&empty, AllowitTier::Custom), invalid);
    assert_eq!(allowit::check_args(&empty), invalid);
    let mut c = context();
    c.request.args = empty.into();
    let custom = AllowitTier::Custom;
    assert_eq!(
        allowit::evaluate(&c, policy::execute, custom),
        Err(AllowitError::InvalidParam)
    );
}
#[test]
fn limits_boundary_denial_and_accounting() {
    let mut c = context();
    c.request.amount = 11;
    assert_eq!(policy::execute(&c), Err(AllowitError::PaymentLimitExceeded));
    let mut c = context();
    edit(&mut c, |s| s.day_spent = 11);
    assert_eq!(
        policy::execute(&c),
        Err(AllowitError::DailySpendingLimitExceeded)
    );
    let mut c = context();
    edit(&mut c, |s| s.unpriced = true);
    assert_eq!(policy::execute(&c), Err(AllowitError::Unpriced));
    let mut c = context();
    edit(&mut c, |s| s.day += 1);
    assert_eq!(policy::execute(&c), Err(AllowitError::InvalidState));
    let mut c = context();
    edit(&mut c, |s| s.calls = 2);
    assert_eq!(policy::execute(&c), Err(AllowitError::CallLimitExceeded));
    let mut c = context();
    put(
        &mut c.params,
        allowit::PAYMENT_LIMIT,
        Some(AllowitValue::Bool(true)),
    );
    assert_eq!(policy::execute(&c), Err(AllowitError::InvalidParam));
}
#[test]
fn approval_server_only_functions_compile_on_the_host_and_are_unsupported_until_filled() {
    let c = context();
    let asset = c.request.asset.clone();
    let price = allowit::AllowitPrice {
        from: asset.clone(),
        to: asset,
        amount: 1,
        price: 10_000_000,
        slip: 50,
    };
    assert_eq!(allowit::price(&c, &price), Err(AllowitError::Unsupported));
    let fetch = allowit::AllowitFetch {
        method: "GET",
        url: "https://example.com",
        data: "",
        pubkey: "",
    };
    assert_eq!(allowit::fetch(&c, &fetch), Err(AllowitError::Unsupported));
    let search = allowit::AllowitInternetSearch { query: "q" };
    assert_eq!(
        allowit::internet_search(&c, &search),
        Err(AllowitError::Unsupported)
    );
    let market = allowit::AllowitMarketplaceSearch { query: "q" };
    assert_eq!(
        allowit::marketplace_search(&c, &market),
        Err(AllowitError::Unsupported)
    );
    let screening = allowit::AllowitRequestScreening {
        query: "fraud",
        deny_below: 5_000,
    };
    assert_eq!(
        allowit::request_screening(&c, &screening),
        Err(AllowitError::Unsupported)
    );
    let ask = allowit::AllowitSystemOne {
        id: "invoices",
        query: "q",
        deny_below: 2_000,
        allow_above: 9_000,
    };
    assert_eq!(allowit::systemone(&c, &ask), Err(AllowitError::Unsupported));
    assert_eq!(
        allowit::clear_systemone_context(&c),
        Err(AllowitError::Unsupported)
    );
}

/// Host address text for each universe index.
fn address(index: usize) -> Address {
    Address::new(format!("CADDRESS{index}"))
}
fn host_context(v: &Vector) -> AllowitContext {
    let addresses = |items: &Option<Vec<usize>>| {
        let items = items.as_ref()?;
        Some(list(items.iter().map(|i| address(*i)).collect()))
    };
    let env = AllowitEnv::new();
    let mut state = map(&AllowitStandardState {
        calls: v.calls,
        spent: v.spent,
        unpriced: v.unpriced,
        day: v.day,
        day_spent: v.day_spent,
        day_total: v.day_total,
        day_unpriced: v.day_unpriced,
    });
    if let Some(over) = v.over {
        state.insert(vectors::OVER.to_string(), over.into());
    }
    for i in 0..v.extra_state {
        state.insert(vectors::state_key(i), AllowitValue::from(i as u64));
    }
    if !v.blob.is_empty() {
        let texts = v.blob.iter().map(|n| AllowitValue::Str("x".repeat(*n)));
        state.insert(
            vectors::BLOB.to_string(),
            AllowitValue::List(texts.collect()),
        );
    }
    let mut args: AllowitArgs = params(vec![(
        vectors::INVOICE,
        v.invoice.then(|| AllowitValue::Int(1)),
    )]);
    for i in 0..v.extra_args {
        put(
            &mut args,
            &vectors::arg_key(i),
            Some(AllowitValue::from(i as u64)),
        );
    }
    AllowitContext {
        env,
        params: params(vec![
            (allowit::PAYMENT_LIMIT, v.caps[0].map(AllowitValue::Int)),
            (
                allowit::LIFETIME_SPENDING_LIMIT,
                v.caps[1].map(AllowitValue::Int),
            ),
            (
                allowit::DAILY_SPENDING_LIMIT,
                v.caps[2].map(AllowitValue::Int),
            ),
            (
                allowit::DAILY_VOLUME_LIMIT,
                v.caps[3].map(AllowitValue::Int),
            ),
            (allowit::CALL_LIMIT, v.call_limit.map(AllowitValue::from)),
            (allowit::DESTINATIONS, addresses(&v.destinations)),
            (allowit::TOKENS, addresses(&v.tokens)),
            (
                allowit::EXPIRES_AT,
                v.expires_at_param.map(AllowitValue::from),
            ),
            (allowit::OPERATIONS, v.operations.as_ref().map(operations)),
            (vectors::INVOICE_CAP, v.invoice_cap.map(AllowitValue::Int)),
        ]),
        state,
        request: AllowitRequest {
            operation: match v.op {
                Op::Transfer => AllowitOperation::transfer,
                Op::Deposit => AllowitOperation::deposit,
                Op::Swap => AllowitOperation::swap,
                Op::Redeem => AllowitOperation::redeem,
            },
            asset: address(v.asset),
            recipient: address(v.recipient),
            amount: v.amount,
            token_in: address(v.token_in),
            amount_in: v.amount_in,
            token_out: v.token_out.map(address),
            min_out: v.min_out,
            now: v.now,
            expires_at: v.expires_at,
            spent_units: v.spent_units,
            gas_units: v.gas_units,
            unpriced: !v.priced,
            args,
        },
    }
}
/// A state map, as `vectors::state_line`.
fn line(c: &AllowitContext, state: AllowitMap) -> String {
    let mut after = c.clone();
    after.state = state;
    let s = AllowitStandardState::read(&after.state).unwrap();
    let over = allowit::get_state(&after, vectors::OVER).unwrap();
    vectors::state_line(
        s.calls,
        s.spent,
        s.unpriced,
        s.day,
        s.day_spent,
        s.day_total,
        s.day_unpriced,
        over,
    )
}
/// The Common wallet's policy with the full canonical prefix: every preflight in key order.
fn preflight(c: &AllowitContext) -> allowit::Result {
    RULES
        .into_iter()
        .try_for_each(|rule| allowit::preflight(c, rule))
}
/// Every outcome of one vector on the host backend.
fn host_outcome(v: &Vector) -> Outcome {
    let c = host_context(v);
    let code = |e: AllowitError| e as u32;
    let index = |a: Address| {
        let i = (0..vectors::ADDRESSES).position(|i| address(i) == a);
        format!("@{}", i.unwrap())
    };
    let run = |execute: &dyn Fn(&AllowitContext) -> allowit::Result, tier| {
        allowit::evaluate(&c, execute, tier)
            .map(|state| line(&c, state))
            .map_err(code)
    };
    let evaluate = |tier| run(&catching::execute, tier);
    Outcome {
        policy: stopped(|| policy::execute(&c)),
        branch: stopped(|| branch::execute(&c)),
        catching: stopped(|| catching::execute(&c)),
        rules: vec![
            stopped(|| allowit::payment_limit(&c, &c.params[allowit::PAYMENT_LIMIT]))
                .map(|v| v.to_string()),
            stopped(|| {
                allowit::lifetime_spending_limit(&c, &c.params[allowit::LIFETIME_SPENDING_LIMIT])
            })
            .map(|v| v.to_string()),
            stopped(|| allowit::daily_spending_limit(&c, &c.params[allowit::DAILY_SPENDING_LIMIT]))
                .map(|v| v.to_string()),
            stopped(|| allowit::daily_volume_limit(&c, &c.params[allowit::DAILY_VOLUME_LIMIT]))
                .map(|v| v.to_string()),
            stopped(|| allowit::call_limit(&c, &c.params[allowit::CALL_LIMIT]))
                .map(|v| v.to_string()),
            stopped(|| allowit::destinations(&c, &c.params[allowit::DESTINATIONS])).map(index),
            stopped(|| allowit::tokens(&c, &c.params[allowit::TOKENS])).map(index),
            stopped(|| allowit::expires_at(&c, &c.params[allowit::EXPIRES_AT]))
                .map(|v| v.to_string()),
            stopped(|| allowit::operations(&c, &c.params[allowit::OPERATIONS]))
                .map(|v| v.to_string()),
        ],
        preflight: RULES
            .into_iter()
            .map(|rule| allowit::preflight(&c, rule).map_err(code))
            .collect(),
        // The bare catching run above may have buffered a write; `evaluate` clears it first.
        next: run(&|_| Ok(()), AllowitTier::Custom),
        common: run(&preflight, AllowitTier::Standard),
        simple: run(&|_| Ok(()), AllowitTier::Standard),
        catching_next: evaluate(AllowitTier::Custom),
        catching_standard: evaluate(AllowitTier::Standard),
    }
}
/// Print the host outcome of every shared vector for the contract portability test.
#[test]
fn vectors_print_host_outcomes() {
    assert_eq!(vectors::MAX_STATE_BYTES, allowit::MAX_STATE_BYTES as usize);
    let all = vectors::vectors();
    for v in &all {
        println!("{}", host_outcome(v).line(v.name));
    }
    let base = host_outcome(&all[0]);
    assert_eq!(base.policy, Ok(()));
    assert_eq!(base.preflight, vec![Ok(()); 9]);
    assert_eq!(base.next, Ok("1/45/false/2/45/43/false/-".to_string()));
    assert_eq!(base.catching_standard, base.next);
    assert_eq!((&base.common, &base.simple), (&base.next, &base.next));
    let named = |name: &str| host_outcome(all.iter().find(|v| v.name == name).unwrap());
    let (invalid_param, invalid_state) = (AllowitError::InvalidParam, AllowitError::InvalidState);
    assert!(named("args_at_bound").next.is_ok());
    assert_eq!(named("args_over_bound").next, Err(invalid_param as u32));
    assert!(named("state_keys_at_bound").catching_next.is_ok());
    let over = named("state_keys_over_bound");
    assert_eq!(over.catching_next, Err(invalid_state as u32));
    assert!(over.next.is_ok());
    assert!(named("state_bytes_at_bound").catching_next.is_ok());
    let over = named("state_bytes_over_bound");
    assert_eq!(over.catching_next, Err(invalid_state as u32));
    assert!(over.next.is_ok());
    // A standard wallet rejects a custom param, also beside few canonical ones.
    let few = named("invoice_cap_beside_few_params");
    assert!(few.next.is_ok());
    assert_eq!(few.simple, Err(invalid_param as u32));
    assert_eq!(few.catching_standard, Err(invalid_param as u32));
    // A policy that allows only deposits denies a transfer and admits a deposit.
    let not_allowed = Err(AllowitError::OperationNotAllowed as u32);
    let only_deposits = named("only_deposits");
    assert_eq!(only_deposits.policy, not_allowed);
    assert_eq!(only_deposits.common.map(drop), not_allowed);
    assert_eq!(named("deposit_only_deposits").policy, Ok(()));
    assert_eq!(named("any_operation").policy, Ok(()));
    assert_eq!(named("custom_calls_only").policy, not_allowed);
    assert_eq!(named("empty_operations").policy, not_allowed);
    for name in ["operations_not_a_list", "unknown_operation"] {
        assert_eq!(named(name).rules[8], Err(invalid_param as u32), "{name}");
    }
    // Swaps and redeems pass every rule that admits them, and each rule denies its own way.
    for name in ["swap", "reverse_swap", "redeem"] {
        let outcome = named(name);
        assert_eq!(outcome.policy, Ok(()), "{name}");
        assert_eq!(outcome.preflight, vec![Ok(()); 9], "{name}");
    }
    assert_eq!(named("swap").rules[8], Ok("swap".to_string()));
    assert_eq!(named("redeem").rules[8], Ok("redeem".to_string()));
    assert_eq!(named("swap").rules[5], Ok("@4".to_string()));
    assert_eq!(named("redeem").rules[5], Ok("@2".to_string()));
    // A reverse swap counts its 40-unit asset floor; a forward swap its 40-unit input.
    assert_eq!(named("reverse_swap").rules[0], Ok("60".to_string()));
    assert_eq!(
        named("swap").next,
        Ok("1/8/false/2/8/43/false/-".to_string())
    );
    let denied = |e: AllowitError| Err(e as u32);
    let recipient = denied(AllowitError::DestinationNotAllowed);
    let token = denied(AllowitError::TokenNotAllowed);
    let cap = denied(AllowitError::PaymentLimitExceeded);
    assert_eq!(named("swap_unlisted_exchange").policy, recipient);
    assert_eq!(named("swap_other_token_not_allowed").policy, token);
    assert_eq!(
        named("reverse_swap_other_token_not_allowed").rules[6],
        Err(AllowitError::TokenNotAllowed as u32)
    );
    assert_eq!(named("swap_not_in_operations").policy, not_allowed);
    assert_eq!(named("redeem_not_in_operations").policy, not_allowed);
    assert_eq!(named("only_swaps").policy, not_allowed);
    assert_eq!(named("swap_over_payment_limit").policy, cap);
    assert_eq!(named("reverse_swap_floor_over_payment_limit").policy, cap);
}
