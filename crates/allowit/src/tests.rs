extern crate std;
use super::*;
use soroban::{admits, op_name_ok, read};
use soroban_sdk::{
    Env, IntoVal, Map, String, Symbol, TryFromVal, Val, contract, contractimpl,
    testutils::Address as _, vec, xdr::ToXdr,
};

/// Contract scope for the temporary-storage write buffer.
#[contract]
struct Scope;
#[contractimpl]
impl Scope {}

/// Fails to compile when a variant is added without extending `RULES`.
fn position(rule: AllowitRule) -> usize {
    match rule {
        AllowitRule::payment_limit => 0,
        AllowitRule::lifetime_spending_limit => 1,
        AllowitRule::daily_spending_limit => 2,
        AllowitRule::daily_volume_limit => 3,
        AllowitRule::call_limit => 4,
        AllowitRule::destinations => 5,
        AllowitRule::tokens => 6,
        AllowitRule::expires_at => 7,
        AllowitRule::operations => 8,
    }
}

/// The state map of standard values `s`.
fn map(env: &Env, s: &AllowitStandardState) -> AllowitMap {
    let mut state = Map::new(env);
    s.write(&mut state).unwrap();
    state
}

/// Edit the standard values of `ctx.state`.
fn edit(ctx: &mut AllowitContext, change: impl FnOnce(&mut AllowitStandardState)) {
    let mut s = AllowitStandardState::read(&ctx.state).unwrap();
    change(&mut s);
    s.write(&mut ctx.state).unwrap();
}

/// A list of addresses.
fn list(env: &Env, items: &[&Address]) -> AllowitValue {
    let mut out = soroban_sdk::Vec::new(env);
    for item in items {
        out.push_back(AllowitValue::Addr((*item).clone()));
    }
    AllowitValue::List(out)
}

/// Set or, with `None`, unset one param of `ctx`.
fn set(ctx: &mut AllowitContext, key: &str, value: impl Into<Option<AllowitValue>>) {
    let key = Symbol::new(&ctx.env, key);
    let mut map = ctx.params.map().clone();
    match value.into() {
        Some(value) => map.set(key, value),
        None => {
            map.remove(key);
        }
    }
    ctx.params = AllowitParams::new(&ctx.env, map).unwrap();
}

/// An integer value.
fn int(n: i128) -> AllowitValue {
    AllowitValue::Int(n)
}

/// A text value.
fn text_value(env: &Env, text: &str) -> AllowitValue {
    AllowitValue::Str(String::from_str(env, text))
}

/// A `List` of `Str` op names, an `operations` value.
fn ops(env: &Env, names: &[&str]) -> AllowitValue {
    let mut out = soroban_sdk::Vec::new(env);
    for name in names {
        out.push_back(text_value(env, name));
    }
    AllowitValue::List(out)
}

/// Current state before a 40-unit priced transfer: after it, spent and day_spent are 45 and
/// day_total is 43.
fn fixture(env: &Env) -> AllowitContext {
    let asset = Address::generate(env);
    let recipient = Address::generate(env);
    let mut ctx = AllowitContext {
        env: env.clone(),
        params: AllowitParams::new(env, Map::new(env)).unwrap(),
        state: map(
            env,
            &AllowitStandardState {
                calls: 1,
                spent: 5,
                day: 1,
                day_spent: 5,
                day_total: 3,
                ..Default::default()
            },
        ),
        request: AllowitRequest {
            operation: AllowitOperation::transfer,
            asset: asset.clone(),
            recipient: recipient.clone(),
            amount: 40,
            token_in: asset.clone(),
            amount_in: 40,
            token_out: None,
            min_out: 0,
            now: DAY + 100,
            expires_at: DAY + 500,
            spent_units: 40,
            gas_units: 0,
            unpriced: false,
            args: AllowitArgs(Map::new(env)),
        },
    };
    for (key, value) in [
        (PAYMENT_LIMIT, int(100)),
        (LIFETIME_SPENDING_LIMIT, int(1000)),
        (DAILY_SPENDING_LIMIT, int(500)),
        (DAILY_VOLUME_LIMIT, int(600)),
        (CALL_LIMIT, int(3)),
        (DESTINATIONS, list(env, &[&recipient])),
        (TOKENS, list(env, &[&asset])),
        (EXPIRES_AT, int(999_999)),
        (OPERATIONS, ops(env, &["transfer"])),
    ] {
        set(&mut ctx, key, value);
    }
    ctx
}

#[test]
fn rules_return_exact_passing_constraints_after_this_operation() {
    let env = Env::default();
    let ctx = fixture(&env);
    let p = |key| &ctx.params[key];
    assert_eq!(payment_limit(&ctx, p(PAYMENT_LIMIT)), Ok(60));
    assert_eq!(
        lifetime_spending_limit(&ctx, p(LIFETIME_SPENDING_LIMIT)),
        Ok(955)
    );
    assert_eq!(daily_spending_limit(&ctx, p(DAILY_SPENDING_LIMIT)), Ok(455));
    assert_eq!(daily_volume_limit(&ctx, p(DAILY_VOLUME_LIMIT)), Ok(557));
    assert_eq!(call_limit(&ctx, p(CALL_LIMIT)), Ok(1));
    assert_eq!(
        destinations(&ctx, p(DESTINATIONS)),
        Ok(ctx.request.recipient.clone())
    );
    assert_eq!(tokens(&ctx, p(TOKENS)), Ok(ctx.request.asset.clone()));
    assert_eq!(expires_at(&ctx, p(EXPIRES_AT)), Ok(999_999 - DAY - 100));
    assert_eq!(operations(&ctx, p(OPERATIONS)), Ok("transfer"));
    for rule in RULES {
        assert_eq!(preflight(&ctx, rule), Ok(()));
    }
    assert_eq!(
        check_params(ctx.params.map(), AllowitTier::Standard),
        Ok(())
    );
    // Gas counts toward the daily gross total only.
    let mut gas = ctx.clone();
    gas.request.gas_units = 7;
    gas.request.spent_units = 47;
    assert_eq!(
        lifetime_spending_limit(&gas, p(LIFETIME_SPENDING_LIMIT)),
        Ok(948)
    );
    assert_eq!(daily_volume_limit(&gas, p(DAILY_VOLUME_LIMIT)), Ok(550));
    // An empty state map is a fresh wallet: every standard value is zero.
    let mut fresh = ctx.clone();
    fresh.state = Map::new(&env);
    assert_eq!(
        lifetime_spending_limit(&fresh, p(LIFETIME_SPENDING_LIMIT)),
        Ok(960)
    );
    assert_eq!(daily_volume_limit(&fresh, p(DAILY_VOLUME_LIMIT)), Ok(560));
    assert_eq!(call_limit(&fresh, p(CALL_LIMIT)), Ok(2));
}

#[test]
fn rules_read_any_key_and_param_returns_the_typed_value() {
    let env = Env::default();
    let mut ctx = fixture(&env);
    // A rule may read a custom key: the policy defines it.
    set(&mut ctx, "vendor_cap", int(39));
    assert_eq!(
        payment_limit(&ctx, &ctx.params["vendor_cap"]),
        Err(AllowitError::PaymentLimitExceeded)
    );
    assert_eq!(param::<i128>(&ctx, "vendor_cap"), 39);
    assert_eq!(param::<u32>(&ctx, "vendor_cap"), 39);
    assert_eq!(
        param::<AllowitValue>(&ctx, "vendor_cap"),
        AllowitValue::Int(39)
    );
    let tokens: soroban_sdk::Vec<Address> = param(&ctx, TOKENS);
    assert_eq!(tokens, vec![&env, ctx.request.asset.clone()]);
    let names: soroban_sdk::Vec<AllowitValue> = param(&ctx, OPERATIONS);
    assert_eq!(names, vec![&env, text_value(&env, "transfer")]);
    // A key that no map can hold is unset, the same on both backends.
    assert!(ctx.params.contains("vendor_cap") && !ctx.params.contains("vendor cap"));
    // Execution params reach policy through the request.
    set(&mut ctx, "vendor_cap", None);
    ctx.request
        .args
        .0
        .set(Symbol::new(&env, "invoice"), AllowitValue::Int(7));
    assert!(ctx.request.args.contains("invoice") && !ctx.request.args.contains("order"));
    assert_eq!(arg::<u64>(&ctx, "invoice"), 7);
    assert!(!ctx.params.contains("vendor_cap"));
}

#[test]
fn params_decode_their_entries_once_and_admit_at_most_max_params() {
    let env = Env::default();
    let mut map = Map::new(&env);
    for i in 0..MAX_PARAMS {
        let key = Symbol::new(&env, &std::format!("key_{i}"));
        map.set(key, AllowitValue::Int(i.into()));
    }
    let params = AllowitParams::new(&env, map.clone()).unwrap();
    for i in 0..MAX_PARAMS {
        let key = std::format!("key_{i}");
        assert_eq!(params[key.as_str()], AllowitValue::Int(i.into()));
        assert!(params.contains(&key));
    }
    assert_eq!(params.map(), &map);
    map.set(Symbol::new(&env, "one_more"), AllowitValue::Int(0));
    let invalid = Some(AllowitError::InvalidParam);
    assert_eq!(AllowitParams::new(&env, map).err(), invalid);
    // An entry that does not decode is invalid instead of aborting.
    let raw: Map<Symbol, Val> = Map::from_array(&env, [(Symbol::new(&env, "k"), 1u32.into())]);
    let raw = AllowitMap::try_from_val(&env, &raw.to_val()).unwrap();
    assert_eq!(AllowitParams::new(&env, raw).err(), invalid);
}

/// A policy step as a contract call, so a typed read that fails aborts it as it aborts a wallet.
/// Its own module keeps `Result` the standard one for the generated client.
mod policy_step {
    extern crate std;
    use crate::{AllowitContext, AllowitMap, AllowitParams, AllowitRequest, AllowitValue};
    use crate::{arg, param};
    use soroban_sdk::{Env, Map, String, contract, contractimpl};
    use std::string::ToString;
    #[contract]
    pub struct Policy;
    #[contractimpl]
    impl Policy {
        /// The headroom of the agent's `amount` arg under the owner's `swap_cap` param.
        pub fn headroom(env: Env, params: AllowitMap, request: AllowitRequest) -> i128 {
            let state = Map::new(&env);
            let params = AllowitParams::new(&env, params).unwrap();
            let ctx = AllowitContext {
                env,
                params,
                state,
                request,
            };
            let amount: i128 = arg(&ctx, "amount");
            let cap: i128 = param(&ctx, "swap_cap");
            cap - amount
        }

        /// The owner's param `key`, read by index as authored policy reads it.
        pub fn indexed(env: Env, params: AllowitMap, key: String) -> AllowitValue {
            let params = AllowitParams::new(&env, params).unwrap();
            params[key.to_string().as_str()].clone()
        }
    }
}
use policy_step::{Policy, PolicyClient};

#[test]
fn a_failed_typed_read_aborts_the_contract_call_with_its_allowit_error() {
    let env = Env::default();
    let id = env.register(Policy, ());
    let client = PolicyClient::new(&env, &id);
    let mut ctx = fixture(&env);
    set(&mut ctx, "swap_cap", int(50));
    let amount = Symbol::new(&env, "amount");
    ctx.request
        .args
        .0
        .set(amount.clone(), AllowitValue::Int(20));
    assert_eq!(client.headroom(ctx.params.map(), &ctx.request), 30);
    let code = |error: AllowitError| Err(Ok(soroban_sdk::Error::from(error)));
    let call = |c: &AllowitContext| client.try_headroom(c.params.map(), &c.request);
    // A missing key is `MissingParam` and a value of another type or range `InvalidParam`.
    let mut bad = ctx.clone();
    bad.request.args.0.remove(amount.clone());
    assert_eq!(call(&bad), code(AllowitError::MissingParam));
    let mut bad = ctx.clone();
    bad.request.args.0.set(amount, AllowitValue::Bool(true));
    assert_eq!(call(&bad), code(AllowitError::InvalidParam));
    let mut bad = ctx.clone();
    set(&mut bad, "swap_cap", None);
    assert_eq!(call(&bad), code(AllowitError::MissingParam));
    set(&mut bad, "swap_cap", text_value(&env, "50"));
    assert_eq!(call(&bad), code(AllowitError::InvalidParam));
}

#[test]
fn operations_admit_named_ops_star_and_custom_forms() {
    let env = Env::default();
    let mut ctx = fixture(&env);
    let pool = "custom:CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let not = Err(AllowitError::OperationNotAllowed);
    // A transfer is `transfer`; a deposit is `deposit`.
    assert_eq!(
        operations(&ctx, &ops(&env, &["deposit", "transfer"])),
        Ok("transfer")
    );
    assert_eq!(operations(&ctx, &(text_value(&env, "*"))), Ok("transfer"));
    assert_eq!(operations(&ctx, &ops(&env, &[])), not);
    let custom = std::format!("{pool}.swap");
    for names in [
        &["deposit", "swap", "redeem"][..],
        &["custom", "custom.transfer", custom.as_str()][..],
    ] {
        assert_eq!(operations(&ctx, &ops(&env, names)), not, "{names:?}");
    }
    ctx.request.operation = AllowitOperation::deposit;
    assert_eq!(operations(&ctx, &ops(&env, &["deposit"])), Ok("deposit"));
    assert_eq!(operations(&ctx, &ops(&env, &["transfer"])), not);
    // Custom forms: any custom call, one function on any contract, or one contract's function.
    let swap = custom.as_bytes();
    for entry in ["custom", "custom.swap", custom.as_str()] {
        assert!(admits(entry.as_bytes(), swap), "{entry}");
        assert!(!admits(entry.as_bytes(), b"transfer"), "{entry}");
    }
    let other = std::format!("{}B.swap", &pool[..pool.len() - 1]);
    for entry in ["custom.claim", other.as_str(), "swap", "transfer"] {
        assert!(!admits(entry.as_bytes(), swap), "{entry}");
    }
    assert!(admits(b"*", swap) && admits(b"*", b"deposit"));
    // Only op names are valid entries.
    for name in [
        "transfer",
        "swap",
        "deposit",
        "redeem",
        "custom",
        "custom.swap",
        custom.as_str(),
    ] {
        assert!(op_name_ok(name.as_bytes()), "{name}");
    }
    // The contract text is rail-neutral: any ASCII letters or digits, as on the host backend.
    for name in ["custom:pool.claim", "custom:c1.swap"] {
        assert!(op_name_ok(name.as_bytes()), "{name}");
    }
    let long = std::format!("custom.{}", "f".repeat(33));
    for name in [
        "",
        "*",
        "pay",
        "Transfer",
        "custom.",
        "custom:",
        "custom:.swap",
        "custom:po-ol.swap",
        "custom:po_ol.swap",
        "custom:pool.",
        "custom.a-b",
        &long,
    ] {
        assert!(!op_name_ok(name.as_bytes()), "{name}");
    }
    let bad = Err(AllowitError::InvalidParam);
    let invalid = [
        text_value(&env, "transfer"),
        ops(&env, &["*"]),
        ops(&env, &["transfer", "pay"]),
        AllowitValue::List(vec![&env, AllowitValue::Int(1)]),
        int(1),
    ];
    for value in invalid {
        assert_eq!(operations(&ctx, &value), bad, "{value:?}");
    }
}

#[test]
fn operations_admit_a_custom_call_by_its_contract_and_function() {
    let env = Env::default();
    let mut ctx = fixture(&env);
    let pool = Address::generate(&env);
    let mut strkey = [0u8; 56];
    pool.to_string().copy_into_slice(&mut strkey);
    let named = std::format!("custom:{}.swap", core::str::from_utf8(&strkey).unwrap());
    let other = std::format!("custom:C{}.swap", "A".repeat(55));
    let call =
        |function: &str| AllowitOperation::custom(pool.clone(), String::from_str(&env, function));
    ctx.request.operation = call("swap");
    let not = Err(AllowitError::OperationNotAllowed);
    assert_eq!(operations(&ctx, &(text_value(&env, "*"))), Ok("custom"));
    for entry in ["custom", "custom.swap", named.as_str()] {
        assert_eq!(
            operations(&ctx, &ops(&env, &[entry])),
            Ok("custom"),
            "{entry}"
        );
    }
    for entry in ["swap", "transfer", "custom.claim", other.as_str()] {
        assert_eq!(operations(&ctx, &ops(&env, &[entry])), not, "{entry}");
    }
    // A call that no op name can express, such as a function that is not a `Symbol`, is admitted
    // by no entry, not even `*`.
    ctx.request.operation = call("a-b");
    assert_eq!(operations(&ctx, &(text_value(&env, "*"))), not);
    assert_eq!(operations(&ctx, &ops(&env, &["custom"])), not);
}

#[test]
fn unset_params_abort_when_indexed_and_skip_only_in_preflight() {
    let env = Env::default();
    let id = env.register(Policy, ());
    let client = PolicyClient::new(&env, &id);
    let mut ctx = fixture(&env);
    let missing = Err(Ok(soroban_sdk::Error::from(AllowitError::MissingParam)));
    let index = |c: &AllowitContext, key: &str| {
        client.try_indexed(c.params.map(), &String::from_str(&env, key))
    };
    // Indexing a set key returns its value; an unset key, also one that no map can hold, aborts
    // the contract call with `MissingParam` before any rule runs.
    assert_eq!(index(&ctx, CALL_LIMIT), Ok(Ok(int(3))));
    assert_eq!(index(&ctx, "vendor_cap"), missing);
    assert_eq!(index(&ctx, "vendor cap"), missing);
    ctx.params = AllowitParams::new(&env, Map::new(&env)).unwrap();
    for rule in RULES {
        assert_eq!(index(&ctx, rule.key()), missing, "{rule:?}");
        assert!(!ctx.params.contains(rule.key()));
    }
    // Only the standard preflight skips an absent param, whatever the request and state hold.
    ctx.request.amount = 0;
    ctx.request.now = ctx.request.expires_at + 1;
    edit(&mut ctx, |s| {
        s.day = u64::MAX;
        s.unpriced = true;
        s.calls = u64::MAX;
    });
    for rule in RULES {
        assert_eq!(preflight(&ctx, rule), Ok(()));
    }
    // A present param is checked by preflight exactly as by the rule.
    set(&mut ctx, LIFETIME_SPENDING_LIMIT, int(1000));
    assert_eq!(
        preflight(&ctx, AllowitRule::lifetime_spending_limit),
        Err(AllowitError::Unpriced)
    );
    set(&mut ctx, EXPIRES_AT, int(u64::MAX.into()));
    assert_eq!(
        preflight(&ctx, AllowitRule::expires_at),
        Err(AllowitError::Expired)
    );
    set(&mut ctx, CALL_LIMIT, int(u64::MAX.into()));
    assert_eq!(
        preflight(&ctx, AllowitRule::call_limit),
        Err(AllowitError::Overflow)
    );
}

#[test]
fn params_of_the_wrong_type_or_range_are_invalid_param() {
    let env = Env::default();
    let ctx = fixture(&env);
    let text = AllowitValue::Str(String::from_str(&env, "100"));
    let flag = AllowitValue::Bool(true);
    let address = AllowitValue::Addr(ctx.request.recipient.clone());
    let bad = Err(AllowitError::InvalidParam);
    for value in [text.clone(), flag, address.clone(), int(-1)] {
        assert_eq!(payment_limit(&ctx, &value), bad);
        assert_eq!(lifetime_spending_limit(&ctx, &value), bad);
        assert_eq!(daily_spending_limit(&ctx, &value), bad);
        assert_eq!(daily_volume_limit(&ctx, &value), bad);
    }
    for value in [text, int(-1), int(i128::from(u64::MAX) + 1)] {
        assert_eq!(call_limit(&ctx, &value), Err(AllowitError::InvalidParam));
        assert_eq!(expires_at(&ctx, &value), Err(AllowitError::InvalidParam));
    }
    // A list must hold only addresses, wherever the match is.
    let recipient = AllowitValue::Addr(ctx.request.recipient.clone());
    let mixed = AllowitValue::List(vec![&env, recipient, AllowitValue::Int(1)]);
    for value in [address, int(1), mixed] {
        assert_eq!(destinations(&ctx, &value), Err(AllowitError::InvalidParam));
        assert_eq!(tokens(&ctx, &value), Err(AllowitError::InvalidParam));
    }
}

#[test]
fn boundary_equality_passes_with_zero_headroom_and_one_more_denies() {
    let env = Env::default();
    let mut ctx = fixture(&env);
    assert_eq!(payment_limit(&ctx, &int(40)), Ok(0));
    assert_eq!(lifetime_spending_limit(&ctx, &int(45)), Ok(0));
    assert_eq!(daily_spending_limit(&ctx, &int(45)), Ok(0));
    assert_eq!(daily_volume_limit(&ctx, &int(43)), Ok(0));
    assert_eq!(call_limit(&ctx, &int(2)), Ok(0));
    let r = ctx.request.clone();
    assert_eq!(
        expires_at(&ctx, &int(r.expires_at.into())),
        Ok(r.expires_at - r.now)
    );
    assert_eq!(
        expires_at(&ctx, &int((r.now + 1).into())),
        Err(AllowitError::Expired)
    );
    assert_eq!(
        payment_limit(&ctx, &int(39)),
        Err(AllowitError::PaymentLimitExceeded)
    );
    assert_eq!(
        lifetime_spending_limit(&ctx, &int(44)),
        Err(AllowitError::LifetimeSpendingLimitExceeded)
    );
    assert_eq!(
        daily_spending_limit(&ctx, &int(44)),
        Err(AllowitError::DailySpendingLimitExceeded)
    );
    assert_eq!(
        daily_volume_limit(&ctx, &int(42)),
        Err(AllowitError::DailyVolumeLimitExceeded)
    );
    assert_eq!(
        call_limit(&ctx, &int(1)),
        Err(AllowitError::CallLimitExceeded)
    );
    // This operation counts as a call, so a zero limit always denies.
    ctx.state = Map::new(&env);
    assert_eq!(
        call_limit(&ctx, &int(0)),
        Err(AllowitError::CallLimitExceeded)
    );
    assert_eq!(call_limit(&ctx, &int(1)), Ok(0));
}

#[test]
fn accounting_caps_check_only_the_facts_they_read() {
    let env = Env::default();
    let base = fixture(&env);
    type Cap = fn(&AllowitContext, &AllowitValue) -> Result<i128>;
    let caps: [Cap; 3] = [
        lifetime_spending_limit,
        daily_spending_limit,
        daily_volume_limit,
    ];
    let passing = [955, 955, 957];
    let edits: [fn(&mut AllowitContext); 11] = [
        |c| c.request.amount = 0,
        |c| edit(c, |s| s.day -= 1),
        |c| edit(c, |s| s.day += 1),
        |c| edit(c, |s| s.spent = -1),
        |c| edit(c, |s| s.day_spent = -1),
        |c| edit(c, |s| s.day_total = -1),
        |c| edit(c, |s| s.unpriced = true),
        |c| edit(c, |s| s.day_unpriced = true),
        |c| c.request.unpriced = true,
        |c| c.request.spent_units = -1,
        |c| c.request.gas_units = -1,
    ];
    use AllowitError::{InvalidParam as P, InvalidState as S, Unpriced as U};
    // Expected result per edit, for lifetime_spending_limit, daily_spending_limit and daily_volume_limit. `None` passes,
    // `Some(Ok(v))` passes with `v`.
    let rolled = Some(Ok(1000 - 40));
    let expected: [[Option<core::result::Result<i128, AllowitError>>; 3]; 11] = [
        [None, None, Some(Ok(997))],
        // Daily values of an earlier day roll over to zero; a later day is invalid.
        [None, rolled, rolled],
        [None, Some(Err(S)), Some(Err(S))],
        [Some(Err(S)), None, None],
        [None, Some(Err(S)), None],
        [None, None, Some(Err(S))],
        [Some(Err(U)), None, None],
        [None, Some(Err(U)), Some(Err(U))],
        [Some(Err(U)), Some(Err(U)), Some(Err(U))],
        [Some(Err(P)), Some(Err(P)), None],
        [None, None, Some(Err(P))],
    ];
    for (i, (change, expected)) in edits.iter().zip(expected).enumerate() {
        let mut ctx = base.clone();
        change(&mut ctx);
        for (j, cap) in caps.iter().enumerate() {
            let want = expected[j].unwrap_or(Ok(passing[j]));
            assert_eq!(cap(&ctx, &int(1000)), want, "edit {i} limit {j}");
        }
    }
    let mut ctx = base.clone();
    ctx.request.amount = 0;
    assert_eq!(
        payment_limit(&ctx, &int(100)),
        Err(AllowitError::InvalidParam)
    );
    // A standard key of another type is invalid state for every rule that reads state.
    let mut ctx = base.clone();
    ctx.state
        .set(Symbol::new(&env, "calls"), AllowitValue::Bool(true));
    assert_eq!(call_limit(&ctx, &int(3)), Err(AllowitError::InvalidState));
    assert_eq!(
        lifetime_spending_limit(&ctx, &int(1000)),
        Err(AllowitError::InvalidState)
    );
    assert_eq!(payment_limit(&ctx, &int(100)), Ok(60));
    // A negative count is outside its range.
    ctx.state
        .set(Symbol::new(&env, "calls"), AllowitValue::Int(-1));
    assert_eq!(call_limit(&ctx, &int(3)), Err(AllowitError::InvalidState));
    // Sums that leave the integer range overflow.
    let mut ctx = base.clone();
    edit(&mut ctx, |s| s.spent = i128::MAX);
    assert_eq!(
        lifetime_spending_limit(&ctx, &int(1)),
        Err(AllowitError::Overflow)
    );
}

#[test]
fn preflight_enforces_every_present_param_with_its_rule_error() {
    let env = Env::default();
    let other = Address::generate(&env);
    for rule in RULES {
        let mut ctx = fixture(&env);
        let now = ctx.request.now;
        let (value, expected) = match rule {
            AllowitRule::payment_limit => (int(39), AllowitError::PaymentLimitExceeded),
            AllowitRule::lifetime_spending_limit => {
                (int(44), AllowitError::LifetimeSpendingLimitExceeded)
            }
            AllowitRule::daily_spending_limit => {
                (int(44), AllowitError::DailySpendingLimitExceeded)
            }
            AllowitRule::daily_volume_limit => (int(42), AllowitError::DailyVolumeLimitExceeded),
            AllowitRule::call_limit => (int(1), AllowitError::CallLimitExceeded),
            AllowitRule::destinations => {
                (list(&env, &[&other]), AllowitError::DestinationNotAllowed)
            }
            AllowitRule::tokens => (list(&env, &[&other]), AllowitError::TokenNotAllowed),
            AllowitRule::expires_at => (int(now.into()), AllowitError::Expired),
            AllowitRule::operations => (ops(&env, &["deposit"]), AllowitError::OperationNotAllowed),
        };
        set(&mut ctx, rule.key(), value);
        assert_eq!(preflight(&ctx, rule), Err(expected));
        // Only the edited rule denies.
        for other in RULES.into_iter().filter(|r| *r != rule) {
            assert_eq!(preflight(&ctx, other), Ok(()));
        }
    }
}

#[test]
fn allowlists_match_exact_addresses_and_empty_lists_deny() {
    let env = Env::default();
    let ctx = fixture(&env);
    let other = Address::generate(&env);
    let r = &ctx.request;
    assert_eq!(
        destinations(&ctx, &(list(&env, &[]))),
        Err(AllowitError::DestinationNotAllowed)
    );
    assert_eq!(
        destinations(&ctx, &(list(&env, &[&other]))),
        Err(AllowitError::DestinationNotAllowed)
    );
    assert_eq!(
        destinations(&ctx, &(list(&env, &[&other, &r.recipient]))),
        Ok(r.recipient.clone())
    );
    assert_eq!(
        tokens(&ctx, &(list(&env, &[]))),
        Err(AllowitError::TokenNotAllowed)
    );
    assert_eq!(
        tokens(&ctx, &(list(&env, &[&r.recipient]))),
        Err(AllowitError::TokenNotAllowed)
    );
}

#[test]
fn expires_at_bounds_params_and_request() {
    let env = Env::default();
    let mut ctx = fixture(&env);
    let now = ctx.request.now;
    assert_eq!(
        expires_at(&ctx, &int(now.into())),
        Err(AllowitError::Expired)
    );
    // A request cannot outlive the params.
    let last = ctx.request.expires_at - 1;
    assert_eq!(
        expires_at(&ctx, &int(last.into())),
        Err(AllowitError::Expired)
    );
    ctx.request.expires_at = now;
    assert_eq!(
        expires_at(&ctx, &int((now + 10).into())),
        Err(AllowitError::Expired)
    );
}

#[test]
fn rules_encode_as_their_canonical_names_and_other_names_do_not_decode() {
    let env = Env::default();
    let symbol = |name: &str| -> Val { vec![&env, Symbol::new(&env, name)].into_val(&env) };
    for (i, rule) in RULES.into_iter().enumerate() {
        assert_eq!(position(rule), i);
        let name = std::format!("{rule:?}");
        assert_eq!(rule.key(), name);
        assert_eq!(rule.to_xdr(&env), symbol(&name).to_xdr(&env));
        assert_eq!(
            AllowitRule::try_from_val(&env, &symbol(&name)).ok(),
            Some(rule)
        );
    }
    for name in [
        "set_cap_per_day",
        "cap_per_transaction",
        "require_recipient",
        "require_asset",
        "allow_actions",
        "state_remove",
        "fail",
        "daily_cap",
        "total_cap",
        "recipient",
        "token",
        "per_transfer",
        "max_calls",
        "daily_limit",
        "Spent_cap",
        "",
    ] {
        // The host rejects an unknown variant symbol; inside a contract the invocation aborts.
        let decoded = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            AllowitRule::try_from_val(&env, &symbol(name)).ok()
        }));
        assert!(matches!(decoded, Ok(None) | Err(_)));
    }
}

#[test]
fn standard_params_admit_only_canonical_keys_with_their_types() {
    let env = Env::default();
    let ctx = fixture(&env);
    let standard = |params: &AllowitMap| check_params(params, AllowitTier::Standard);
    assert_eq!(standard(&Map::new(&env)), Ok(()));
    // Zero caps and an empty allowlist are valid configuration that denies.
    let mut zero = ctx.params.map().clone();
    zero.set(Symbol::new(&env, CALL_LIMIT), AllowitValue::Int(0));
    zero.set(Symbol::new(&env, DESTINATIONS), list(&env, &[]));
    assert_eq!(standard(&zero), Ok(()));
    let text = AllowitValue::Str(String::from_str(&env, "x"));
    let address = AllowitValue::Addr(ctx.request.asset.clone());
    let too_big = AllowitValue::Int(i128::from(u64::MAX) + 1);
    let bad: [(&str, AllowitValue); 10] = [
        ("vendor_cap", AllowitValue::Int(1)),
        (PAYMENT_LIMIT, AllowitValue::Int(-1)),
        (DAILY_VOLUME_LIMIT, text.clone()),
        (CALL_LIMIT, too_big.clone()),
        (EXPIRES_AT, AllowitValue::Bool(true)),
        (DESTINATIONS, address.clone()),
        (TOKENS, AllowitValue::List(vec![&env, text.clone()])),
        (OPERATIONS, text),
        (OPERATIONS, ops(&env, &["transfer", "pay"])),
        (OPERATIONS, AllowitValue::List(vec![&env, address])),
    ];
    for (key, value) in bad {
        let mut params = ctx.params.map().clone();
        params.set(Symbol::new(&env, key), value.clone());
        assert_eq!(standard(&params), Err(AllowitError::InvalidParam), "{key}");
        // Custom admits any bounded key and value; its policy defines them.
        assert_eq!(check_params(&params, AllowitTier::Custom), Ok(()), "{key}");
    }
    // `operations` is `*` or a list of op names, which may be empty.
    for value in [
        text_value(&env, "*"),
        ops(&env, &[]),
        ops(&env, &["custom", "swap"]),
    ] {
        let mut params = ctx.params.map().clone();
        params.set(Symbol::new(&env, OPERATIONS), value);
        assert_eq!(standard(&params), Ok(()));
    }
    // A custom key beside fewer than nine canonical keys passes the count check and still
    // rejects.
    let mut few = Map::new(&env);
    few.set(Symbol::new(&env, PAYMENT_LIMIT), AllowitValue::Int(1));
    few.set(Symbol::new(&env, "vendor_cap"), AllowitValue::Int(5));
    assert_eq!(standard(&few), Err(AllowitError::InvalidParam));
    assert_eq!(check_params(&few, AllowitTier::Custom), Ok(()));
}

/// A list of texts of the given byte lengths.
fn texts(env: &Env, lengths: &[usize]) -> AllowitValue {
    let mut out = soroban_sdk::Vec::new(env);
    for n in lengths {
        out.push_back(AllowitValue::Str(String::from_str(env, &"x".repeat(*n))));
    }
    AllowitValue::List(out)
}

#[test]
fn encoded_size_bounds_cover_the_xdr_of_every_value() {
    let env = Env::default();
    let account = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
    let addresses = [Address::generate(&env), Address::from_str(&env, account)];
    let mut values = std::vec![
        AllowitValue::Int(i128::MIN),
        AllowitValue::Int(i128::MAX),
        AllowitValue::Bool(true),
        texts(&env, &[MAX_TEXT as usize; MAX_ITEMS as usize]),
        AllowitValue::List(vec![&env, texts(&env, &[1, 2, 3]), AllowitValue::Int(0)]),
    ];
    values.extend(addresses.iter().cloned().map(AllowitValue::Addr));
    values.extend((0..=MAX_TEXT as usize).map(|n| texts(&env, &[n])));
    // A map adds a 12-byte header and, per entry, its key, each at most 32 bytes here.
    let (mut map, mut total) = (Map::new(&env), 12);
    for (i, value) in values.iter().enumerate() {
        let bound = check_value(value).unwrap();
        assert!(value.clone().to_xdr(&env).len() <= bound, "{i}");
        map.set(Symbol::new(&env, &std::format!("{i:0>32}")), value.clone());
        total += KEY_BYTES + bound;
    }
    assert!(map.to_xdr(&env).len() <= total);
}

#[test]
fn params_args_and_state_stay_within_their_byte_budgets() {
    let env = Env::default();
    let id = env.register(Scope, ());
    let mut ctx = fixture(&env);
    // 40 + 80 + 48 * (80 + 256) for `a`, and 40 + 80 + 16 for `b`: exactly 16 KiB.
    let budget = |last: usize| {
        let mut map = Map::new(&env);
        map.set(Symbol::new(&env, "a"), texts(&env, &[256; 48]));
        let b = AllowitValue::Str(String::from_str(&env, &"x".repeat(last)));
        map.set(Symbol::new(&env, "b"), b);
        map
    };
    let invalid = Err(AllowitError::InvalidParam);
    assert_eq!(MAX_PARAM_BYTES, 16 * 1024);
    assert_eq!(MAX_ARG_BYTES, 16 * 1024);
    assert_eq!(check_params(&budget(16), AllowitTier::Custom), Ok(()));
    assert_eq!(check_params(&budget(17), AllowitTier::Custom), invalid);
    assert_eq!(check_args(&budget(16)), Ok(()));
    assert_eq!(check_args(&budget(17)), invalid);
    // The largest standard params map fits.
    let mut standard = ctx.params.map().clone();
    let full: std::vec::Vec<Address> = (0..MAX_ITEMS).map(|_| Address::generate(&env)).collect();
    let full = list(&env, &full.iter().collect::<std::vec::Vec<_>>());
    standard.set(Symbol::new(&env, DESTINATIONS), full.clone());
    standard.set(Symbol::new(&env, TOKENS), full);
    assert_eq!(standard.len(), 9);
    assert_eq!(check_params(&standard, AllowitTier::Standard), Ok(()));
    // Beside full allowlists, 28 `operations` entries that name a Stellar contract's longest
    // function fit and 29 do not.
    let longest = std::format!("custom:C{}.{}", "A".repeat(55), "f".repeat(32));
    for (n, fits) in [(28, Ok(())), (29, invalid)] {
        let names = std::vec![longest.as_str(); n];
        standard.set(Symbol::new(&env, OPERATIONS), ops(&env, &names));
        assert_eq!(check_params(&standard, AllowitTier::Standard), fits, "{n}");
    }
    // The seven standard keys take 7 * 120 bytes, `blob` 40 + 80 + 45 * 336 and `tail` 40 + 80
    // + 184: exactly 16 KiB.
    assert_eq!(MAX_STATE_BYTES, 16 * 1024);
    ctx.state
        .set(Symbol::new(&env, "blob"), texts(&env, &[256; 45]));
    let tail = |n: usize| AllowitValue::Str(String::from_str(&env, &"x".repeat(n)));
    env.as_contract(&id, || {
        let custom = |c: &AllowitContext| post_flight(c, AllowitTier::Custom);
        set_state(&ctx, "tail", tail(184)).unwrap();
        assert!(custom(&ctx).is_ok());
        set_state(&ctx, "tail", tail(185)).unwrap();
        assert_eq!(custom(&ctx), Err(AllowitError::InvalidState));
    });
}

#[test]
fn custom_params_args_and_state_values_stay_within_their_bounds() {
    let env = Env::default();
    let id = env.register(Scope, ());
    let ctx = fixture(&env);
    let entries = |n: u32| {
        let mut map = Map::new(&env);
        for i in 0..n {
            let key = std::format!("key_{i}");
            map.set(Symbol::new(&env, &key), AllowitValue::Int(i.into()));
        }
        map
    };
    let custom = |params: &AllowitMap| check_params(params, AllowitTier::Custom);
    assert_eq!(custom(&entries(MAX_PARAMS)), Ok(()));
    assert_eq!(
        custom(&entries(MAX_PARAMS + 1)),
        Err(AllowitError::InvalidParam)
    );
    assert_eq!(check_args(&entries(MAX_ARGS)), Ok(()));
    assert_eq!(
        check_args(&entries(MAX_ARGS + 1)),
        Err(AllowitError::InvalidParam)
    );
    // At most MAX_ITEMS nested values, counted through nested lists, and MAX_TEXT bytes.
    let items = |n: u32| {
        let mut out = soroban_sdk::Vec::new(&env);
        for i in 0..n {
            out.push_back(AllowitValue::Int(i.into()));
        }
        out
    };
    let text = |n: usize| AllowitValue::Str(String::from_str(&env, &"x".repeat(n)));
    let fits = |value: &AllowitValue| check_value(value).map(drop);
    assert_eq!(fits(&AllowitValue::List(items(MAX_ITEMS))), Ok(()));
    let over = AllowitValue::List(items(MAX_ITEMS + 1));
    assert_eq!(fits(&over), Err(AllowitError::InvalidParam));
    let inner = AllowitValue::List(items(MAX_ITEMS - 1));
    let nested = AllowitValue::List(vec![&env, inner.clone()]);
    assert_eq!(fits(&nested), Ok(()));
    let nested = AllowitValue::List(vec![&env, inner, AllowitValue::Int(0)]);
    assert_eq!(fits(&nested), Err(AllowitError::InvalidParam));
    assert_eq!(fits(&text(MAX_TEXT as usize)), Ok(()));
    let long = text(MAX_TEXT as usize + 1);
    assert_eq!(fits(&long), Err(AllowitError::InvalidParam));
    let mut params = Map::new(&env);
    params.set(Symbol::new(&env, "memo"), long.clone());
    assert_eq!(custom(&params), Err(AllowitError::InvalidParam));
    assert_eq!(check_args(&params), Err(AllowitError::InvalidParam));
    // A malformed entry does not decode and is invalid instead of aborting.
    let raw: Map<Symbol, Val> = Map::from_array(&env, [(Symbol::new(&env, "k"), 1u32.into())]);
    let raw = AllowitMap::try_from_val(&env, &raw.to_val()).unwrap();
    assert_eq!(custom(&raw), Err(AllowitError::InvalidParam));
    // State writes stay within the same bounds.
    env.as_contract(&id, || {
        assert_eq!(
            set_state(&ctx, "memo", long),
            Err(AllowitError::InvalidParam)
        );
        assert_eq!(
            set_state(&ctx, "memo", over),
            Err(AllowitError::InvalidParam)
        );
        assert_eq!(set_state(&ctx, "memo", text(3)), Ok(()));
    });
}

#[test]
fn empty_keys_in_params_and_args_are_invalid_param_as_on_the_host() {
    let env = Env::default();
    let id = env.register(Scope, ());
    let mut ctx = fixture(&env);
    // A `Symbol` may be empty; the host's text keys reject it, so the chain rejects it too.
    let empty = Map::from_array(&env, [(Symbol::new(&env, ""), AllowitValue::Int(1))]);
    let invalid = Err(AllowitError::InvalidParam);
    assert_eq!(check_params(&empty, AllowitTier::Custom), invalid);
    assert_eq!(check_params(&empty, AllowitTier::Standard), invalid);
    assert_eq!(check_args(&empty), invalid);
    ctx.request.args = AllowitArgs(empty);
    env.as_contract(&id, || {
        let run = evaluate(&ctx, |_| Ok(()), AllowitTier::Custom);
        assert_eq!(run, Err(AllowitError::InvalidParam));
    });
}

#[test]
fn evaluate_checks_args_as_the_wallet_does_before_the_policy_runs() {
    let env = Env::default();
    let id = env.register(Scope, ());
    let mut ctx = fixture(&env);
    for i in 0..=MAX_ARGS {
        let key = Symbol::new(&env, &std::format!("arg_{i}"));
        ctx.request.args.0.set(key, AllowitValue::Bool(true));
    }
    env.as_contract(&id, || {
        // The server cannot approve a request that the wallet kernel rejects.
        let run = evaluate(&ctx, writer, AllowitTier::Custom);
        assert_eq!(run, Err(AllowitError::InvalidParam));
        assert_eq!(
            read::<u64>(&post_flight(&ctx, AllowitTier::Custom).unwrap(), "seen"),
            Ok(None)
        );
        ctx.request.args.0.remove(Symbol::new(&env, "arg_0"));
        assert!(evaluate(&ctx, writer, AllowitTier::Custom).is_ok());
    });
}

#[test]
fn evaluate_checks_standard_params_as_the_wallet_does() {
    let env = Env::default();
    let id = env.register(Scope, ());
    let mut ctx = fixture(&env);
    set(&mut ctx, EXPIRES_AT, None);
    set(&mut ctx, "vendor_cap", int(5));
    env.as_contract(&id, || {
        // A standard wallet that kept a Custom param after a code change rejects it on admission.
        let run = evaluate(&ctx, |_| Ok(()), AllowitTier::Standard);
        assert_eq!(run, Err(AllowitError::InvalidParam));
        assert!(evaluate(&ctx, |_| Ok(()), AllowitTier::Custom).is_ok());
    });
}

#[test]
fn post_flight_bounds_the_number_of_state_keys() {
    let env = Env::default();
    let id = env.register(Scope, ());
    let mut ctx = fixture(&env);
    let custom = |c: &AllowitContext| post_flight(c, AllowitTier::Custom);
    // The fixture state holds the seven standard keys; fill the policy keys up to one short.
    for i in 0..MAX_STATE_KEYS - 8 {
        let key = Symbol::new(&env, &std::format!("key_{i}"));
        ctx.state.set(key, AllowitValue::Int(i.into()));
    }
    env.as_contract(&id, || {
        // Replacing a key keeps the count; one new key reaches the bound; two pass it.
        set_state(&ctx, "key_0", 9u64).unwrap();
        set_state(&ctx, "last", 1u64).unwrap();
        let full = custom(&ctx).unwrap();
        assert_eq!(full.len(), MAX_STATE_KEYS);
        set_state(&ctx, "last", 1u64).unwrap();
        set_state(&ctx, "extra", 1u64).unwrap();
        assert_eq!(custom(&ctx), Err(AllowitError::InvalidState));
        // At the bound, operations that write no new key still pass.
        let mut at = ctx.clone();
        at.state = full;
        set_state(&at, "last", 2u64).unwrap();
        assert!(custom(&at).is_ok());
        set_state(&at, "next", 1u64).unwrap();
        assert_eq!(custom(&at), Err(AllowitError::InvalidState));
    });
}

/// Catches a lifetime spending limit error, reads it and continues; propagates the daily spending
/// limit error.
fn catching(ctx: &AllowitContext) -> Result {
    if let Err(error) = lifetime_spending_limit(ctx, &ctx.params[LIFETIME_SPENDING_LIMIT]) {
        set_state(ctx, "caught", error as u64)?;
    }
    daily_spending_limit(ctx, &ctx.params[DAILY_SPENDING_LIMIT])?;
    Ok(())
}

#[test]
fn a_caught_rule_error_lets_the_policy_continue_and_only_a_returned_error_denies() {
    let env = Env::default();
    let id = env.register(Scope, ());
    let mut ctx = fixture(&env);
    env.as_contract(&id, || {
        set(&mut ctx, LIFETIME_SPENDING_LIMIT, int(1));
        assert_eq!(catching(&ctx), Ok(()));
        // The policy saw the error and recorded it; the Custom post-flight applies the write.
        let next = post_flight(&ctx, AllowitTier::Custom).unwrap();
        let code = AllowitError::LifetimeSpendingLimitExceeded as u64;
        assert_eq!(read::<u64>(&next, "caught"), Ok(Some(code)));
        set(&mut ctx, DAILY_SPENDING_LIMIT, int(1));
        assert_eq!(
            catching(&ctx),
            Err(AllowitError::DailySpendingLimitExceeded)
        );
    });
}

#[test]
fn post_flight_adds_this_operation_to_current_state_then_applies_policy_writes() {
    let env = Env::default();
    let id = env.register(Scope, ());
    let ctx = fixture(&env);
    let custom = |c: &AllowitContext| post_flight(c, AllowitTier::Custom);
    env.as_contract(&id, || {
        let next = custom(&ctx).unwrap();
        let s = AllowitStandardState::read(&next).unwrap();
        let expected = AllowitStandardState {
            calls: 2,
            spent: 45,
            day: 1,
            day_spent: 45,
            day_total: 43,
            ..Default::default()
        };
        assert_eq!(s, expected);
        // Without policy writes, both tiers compute the same state.
        assert_eq!(post_flight(&ctx, AllowitTier::Standard), Ok(next.clone()));
        // A rule that passes on the current state holds on the post-flight state.
        let left = lifetime_spending_limit(&ctx, &ctx.params[LIFETIME_SPENDING_LIMIT]).unwrap();
        assert_eq!(1000 - s.spent, left);
        let left = call_limit(&ctx, &ctx.params[CALL_LIMIT]).unwrap();
        assert_eq!(3 - s.calls, left);

        // The next day rolls the daily values over; unpriced marks both liabilities.
        let mut later = ctx.clone();
        later.request.now += DAY;
        later.request.unpriced = true;
        later.request.spent_units = 0;
        let s = AllowitStandardState::read(&custom(&later).unwrap()).unwrap();
        let expected = AllowitStandardState {
            calls: 2,
            spent: 5,
            unpriced: true,
            day: 2,
            day_spent: 0,
            day_total: 40,
            day_unpriced: true,
        };
        assert_eq!(s, expected);

        // Policy writes apply after the standard update and may replace a standard key.
        set_state(&ctx, "mine", 7i128).unwrap();
        set_state(&ctx, "calls", 99u64).unwrap();
        set_state(&ctx, "mine", ctx.request.asset.clone()).unwrap();
        // Reads see the state before this operation.
        assert_eq!(get_state::<i128>(&ctx, "mine"), Ok(None));
        assert_eq!(get_state::<u64>(&ctx, "calls"), Ok(Some(1)));
        let next = custom(&ctx).unwrap();
        let asset = ctx.request.asset.clone();
        assert_eq!(read::<Address>(&next, "mine"), Ok(Some(asset)));
        assert_eq!(read::<u64>(&next, "calls"), Ok(Some(99)));
        // The buffer is consumed: neither a temporary entry nor a later write remains.
        use soroban_sdk::testutils::storage::Temporary as _;
        assert!(env.storage().temporary().all().is_empty());
        let next = custom(&ctx).unwrap();
        assert_eq!(read::<AllowitValue>(&next, "mine"), Ok(None));
        assert_eq!(read::<u64>(&next, "calls"), Ok(Some(2)));
    });
}

#[test]
fn standard_post_flight_denies_every_policy_write_and_consumes_it() {
    let env = Env::default();
    let id = env.register(Scope, ());
    let ctx = fixture(&env);
    env.as_contract(&id, || {
        // A standard wallet stores only standard keys, so the host denies what the chain drops.
        for key in ["mine", SPENT, CALLS] {
            set_state(&ctx, key, 1u64).unwrap();
            assert_eq!(
                post_flight(&ctx, AllowitTier::Standard),
                Err(AllowitError::Unsupported),
                "{key}"
            );
            assert_eq!(
                post_flight(&ctx, AllowitTier::Standard),
                post_flight(&ctx, AllowitTier::Custom)
            );
        }
        set_state(&ctx, "mine", 1u64).unwrap();
        let writer = |c: &AllowitContext| set_state(c, "mine", 2u64);
        assert_eq!(
            evaluate(&ctx, writer, AllowitTier::Standard),
            Err(AllowitError::Unsupported)
        );
        let next = evaluate(&ctx, writer, AllowitTier::Custom).unwrap();
        assert_eq!(read::<u64>(&next, "mine"), Ok(Some(2)));
    });
}

#[test]
fn post_flight_and_state_access_reject_invalid_keys_values_days_and_overflow() {
    let env = Env::default();
    let id = env.register(Scope, ());
    let ctx = fixture(&env);
    let custom = |c: &AllowitContext| post_flight(c, AllowitTier::Custom);
    env.as_contract(&id, || {
        for key in ["", "has space", "dash-key", "x".repeat(33).as_str()] {
            assert_eq!(set_state(&ctx, key, 1u64), Err(AllowitError::InvalidParam));
            assert_eq!(get_state::<u64>(&ctx, key), Err(AllowitError::InvalidParam));
        }
        assert_eq!(set_state(&ctx, &"x".repeat(32), 1u64), Ok(()));
        assert!(custom(&ctx).is_ok());
        assert_eq!(
            get_state::<bool>(&ctx, "calls"),
            Err(AllowitError::InvalidState)
        );
        type Edit = fn(&mut AllowitContext);
        let cases: [(Edit, AllowitError); 7] = [
            // A standard key of another type fails the decode before any write applies.
            (
                |c| {
                    c.state
                        .set(Symbol::new(&c.env, "calls"), AllowitValue::Bool(true))
                },
                AllowitError::InvalidState,
            ),
            (|c| edit(c, |s| s.day += 1), AllowitError::InvalidState),
            (|c| edit(c, |s| s.spent = -1), AllowitError::InvalidState),
            (
                |c| edit(c, |s| s.day_total = -1),
                AllowitError::InvalidState,
            ),
            (|c| edit(c, |s| s.calls = u64::MAX), AllowitError::Overflow),
            (|c| edit(c, |s| s.spent = i128::MAX), AllowitError::Overflow),
            (|c| c.request.gas_units = -1, AllowitError::InvalidParam),
        ];
        for (change, error) in cases {
            let mut bad = ctx.clone();
            change(&mut bad);
            set_state(&bad, "mine", 1u64).unwrap();
            assert_eq!(custom(&bad), Err(error));
            // A failed post-flight still consumed the buffer.
            assert_eq!(read::<u64>(&custom(&ctx).unwrap(), "mine"), Ok(None));
        }
    });
}

#[test]
fn post_flight_denies_policy_writes_that_leave_standard_state_undecodable() {
    let env = Env::default();
    let id = env.register(Scope, ());
    let ctx = fixture(&env);
    let custom = |c: &AllowitContext| post_flight(c, AllowitTier::Custom);
    env.as_contract(&id, || {
        type Write = fn(&AllowitContext) -> Result;
        let writes: [Write; 10] = [
            |c| set_state(c, "calls", true),
            |c| set_state(c, "calls", -1i128),
            |c| set_state(c, "spent", -1i128),
            |c| set_state(c, "day_total", -1i128),
            |c| set_state(c, "day", c.request.now / DAY + 1),
            |c| set_state(c, "unpriced", 1u64),
            // Totals with no room for the next call or a positive amount overflow every later
            // standard update before a repair write applies.
            |c| set_state(c, "calls", u64::MAX),
            |c| set_state(c, "spent", i128::MAX),
            |c| set_state(c, "day_spent", i128::MAX),
            |c| set_state(c, "day_total", i128::MAX),
        ];
        for write in writes {
            write(&ctx).unwrap();
            // Stored, the write would fail every later operation; the operation denies instead.
            assert_eq!(custom(&ctx), Err(AllowitError::InvalidState));
            assert!(custom(&ctx).is_ok());
        }
        // Valid replacements of standard keys still apply last.
        set_state(&ctx, "day", 0u64).unwrap();
        set_state(&ctx, "spent", 0i128).unwrap();
        let next = custom(&ctx).unwrap();
        assert_eq!(read::<u64>(&next, "day"), Ok(Some(0)));
        assert_eq!(read::<i128>(&next, "spent"), Ok(Some(0)));
        // The highest totals that leave room for one more call and one more unit still apply.
        set_state(&ctx, "calls", u64::MAX - 1).unwrap();
        set_state(&ctx, "spent", i128::MAX - 1).unwrap();
        let next = custom(&ctx).unwrap();
        assert_eq!(read::<u64>(&next, "calls"), Ok(Some(u64::MAX - 1)));
    });
}

/// Records a write, then denies unless the call limit admits this operation.
fn writer(ctx: &AllowitContext) -> Result {
    set_state(ctx, "seen", 1u64)?;
    call_limit(ctx, &ctx.params[CALL_LIMIT])?;
    Ok(())
}

#[test]
fn evaluate_discards_writes_of_a_denied_or_stale_run() {
    let env = Env::default();
    let id = env.register(Scope, ());
    let mut ctx = fixture(&env);
    let custom = AllowitTier::Custom;
    env.as_contract(&id, || {
        // A stale write from outside this evaluation does not reach its post-flight.
        set_state(&ctx, "stale", 1u64).unwrap();
        let next = evaluate(&ctx, writer, custom).unwrap();
        assert_eq!(read::<u64>(&next, "stale"), Ok(None));
        assert_eq!(read::<u64>(&next, "seen"), Ok(Some(1)));
        // A denial returns its error and leaves no write behind.
        set(&mut ctx, CALL_LIMIT, int(0));
        assert_eq!(
            evaluate(&ctx, writer, custom),
            Err(AllowitError::CallLimitExceeded)
        );
        let next = post_flight(&ctx, custom).unwrap();
        assert_eq!(read::<u64>(&next, "seen"), Ok(None));
    });
}

#[test]
fn values_convert_to_and_from_their_scalars() {
    let env = Env::default();
    let address = Address::generate(&env);
    assert_eq!(AllowitValue::from(5u64), AllowitValue::Int(5));
    assert_eq!(u64::try_from(AllowitValue::Int(5)), Ok(5));
    assert_eq!(
        u64::try_from(AllowitValue::Int(-1)),
        Err(AllowitError::InvalidParam)
    );
    assert_eq!(
        bool::try_from(AllowitValue::Int(1)),
        Err(AllowitError::InvalidParam)
    );
    let value = AllowitValue::from(address.clone());
    assert_eq!(Address::try_from(value.clone()), Ok(address));
    assert_eq!(i128::try_from(value), Err(AllowitError::InvalidParam));
    // A value round-trips through its contract encoding.
    let list = AllowitValue::List(vec![&env, AllowitValue::Bool(true)]);
    let raw: Val = list.clone().into_val(&env);
    assert_eq!(AllowitValue::try_from_val(&env, &raw), Ok(list));
}
