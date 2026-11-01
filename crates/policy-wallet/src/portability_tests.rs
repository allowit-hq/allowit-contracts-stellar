//! Four-target portability test. One shared vector set (`scripts/policy-vectors.rs`) runs through:
//!
//! 1. the host backend: `scripts/policy-smoke.rs` compiled with plain `rustc` against `allowit`
//!    with only the `std` feature, so a policy that names `soroban_sdk` or a wallet crate fails;
//! 2. `AllowitCustomPolicy`: the Soroban backend of the same sources, then the real custom Wasm,
//!    and the `test-catching` fixture Wasm, whose policy catches a daily cap error, continues and
//!    writes its own state key;
//! 3. `AllowitCommonPolicyEngine`: the real standard Wasm with the policy's leading-rule prefix;
//! 4. `AllowitSimplePolicyEngine`: the real simple Wasm, which has no rules.
//!
//! Host and Soroban outcomes must be identical on every pass value, error and post-flight state.
//! Each vector holds the current state before the operation. The custom contract must return the
//! mapped policy result, and the catching fixture the mapped catching result. The standard
//! contract must return the mapped first prefix preflight error, which skips absent params, and
//! rejects a custom param. The simple contract runs no rules. Every contract then returns the
//! shared post-flight result and stores exactly the post-flight state that the host computed.
//! Kernel violations reject identically in every contract.
//!
//! Policy writes: Custom stores them; the standard tiers run only the canonical prefix onchain,
//! so the host's standard post-flight denies them. The host's standard evaluation also rejects a
//! custom param, as the standard contract does on admission. The server's evaluation therefore
//! equals the stored state for every tier.
extern crate std;
use super::tests::{CATCHING, COMMON, CUSTOM, Fixture, SIMPLE, transfer_args};
use super::*;
use allowit::{AllowitError, AllowitStandardState, AllowitTier, RULES};
use allowit_wallet_protocol::{AllowitExpense, AllowitTransferArgs};
use soroban_sdk::{
    testutils::{Address as _, Ledger},
    token::StellarAssetClient,
};
use std::{
    format,
    path::Path,
    process::Command,
    string::{String as Text, ToString},
    vec::Vec as List,
};

#[path = "../../custom-policy/src/branch_policy.rs"]
mod branch;
#[path = "../../custom-policy/src/catching_policy.rs"]
mod catching;
#[path = "../../custom-policy/policy/policy.rs"]
mod sample;
mod vectors {
    use super::std::{self, format, string::String, vec, vec::Vec};
    include!("../../../scripts/policy-vectors.rs");
}
use vectors::{Op, Ops, Outcome, Vector};

/// Every rule error, indexed by its code minus one.
const ERRORS: [AllowitError; 16] = [
    AllowitError::MissingParam,
    AllowitError::TransactionCapExceeded,
    AllowitError::SpentCapExceeded,
    AllowitError::DaySpentCapExceeded,
    AllowitError::DayTotalCapExceeded,
    AllowitError::CallCapExceeded,
    AllowitError::RecipientNotAllowed,
    AllowitError::TokenNotAllowed,
    AllowitError::Expired,
    AllowitError::Unpriced,
    AllowitError::InvalidParam,
    AllowitError::InvalidState,
    AllowitError::Overflow,
    AllowitError::Unsupported,
    AllowitError::OperationNotAllowed,
    AllowitError::Panicked,
];
/// The wallet error of a rule error code.
fn wallet_error(code: u32) -> u32 {
    let error = ERRORS[code as usize - 101];
    assert_eq!(error as u32, code);
    AllowitWalletError::from(error) as u32
}

/// Build the host smoke with plain `rustc` against `allowit` with only the `std` feature, run it
/// and return its vector lines.
fn host_lines() -> List<Text> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let out = root
        .join("target/policy-smoke")
        .join(std::process::id().to_string());
    std::fs::create_dir_all(&out).unwrap();
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
    let lib = out.join("liballowit.rlib");
    let bin = out.join("policy-smoke");
    let run = |command: &mut Command| {
        let output = command.current_dir(&root).output().unwrap();
        assert!(
            output.status.success(),
            "{}{}",
            Text::from_utf8_lossy(&output.stdout),
            Text::from_utf8_lossy(&output.stderr)
        );
        Text::from_utf8(output.stdout).unwrap()
    };
    // Overflow checks are explicit, as in the contract release profile and the offchain server.
    run(Command::new(&rustc)
        .args([
            "--edition=2024",
            "-Coverflow-checks=on",
            "--crate-type=rlib",
            "--crate-name=allowit",
        ])
        .args([
            "--cfg",
            "feature=\"std\"",
            "crates/allowit/src/lib.rs",
            "-o",
        ])
        .arg(&lib));
    run(Command::new(&rustc)
        .args([
            "--edition=2024",
            "-Coverflow-checks=on",
            "--test",
            "--extern",
        ])
        .arg(format!("allowit={}", lib.display()))
        .args(["scripts/policy-smoke.rs", "-o"])
        .arg(&bin));
    let stdout = run(Command::new(&bin).args([
        "vectors_print_host_outcomes",
        "--exact",
        "--nocapture",
        "--test-threads=1",
    ]));
    std::fs::remove_dir_all(&out).unwrap();
    // libtest prints the test name without a newline before the first captured line.
    stdout
        .lines()
        .filter_map(|line| line.find("vector ").map(|i| line[i..].to_string()))
        .collect()
}

/// A `List` of the universe addresses at `items`, or `None`.
fn list(env: &Env, universe: &[Address], items: &Option<List<usize>>) -> Option<AllowitValue> {
    let mut out = Vec::new(env);
    for i in items.as_ref()? {
        out.push_back(AllowitValue::Addr(universe[*i].clone()));
    }
    Some(AllowitValue::List(out))
}
/// The `operations` value of `ops`.
fn operations(env: &Env, ops: &Ops) -> AllowitValue {
    let text = |name: &str| AllowitValue::Str(soroban_sdk::String::from_str(env, name));
    match ops {
        Ops::Text(name) => text(name),
        Ops::List(names) => {
            let mut out = Vec::new(env);
            for name in names {
                out.push_back(text(name));
            }
            AllowitValue::List(out)
        }
    }
}
/// A key => value map of `entries`, without the absent ones.
fn map(env: &Env, entries: &[(&str, Option<AllowitValue>)]) -> Map<Symbol, AllowitValue> {
    let mut out = Map::new(env);
    for (key, value) in entries {
        if let Some(value) = value {
            out.set(Symbol::new(env, key), value.clone());
        }
    }
    out
}
/// The params of a vector: its canonical params and the custom `invoice_cap`.
fn params(env: &Env, universe: &[Address], v: &Vector) -> Map<Symbol, AllowitValue> {
    let int = |n: Option<i128>| n.map(AllowitValue::Int);
    map(
        env,
        &[
            (allowit::TRANSACTION_CAP, int(v.caps[0])),
            (allowit::SPENT_CAP, int(v.caps[1])),
            (allowit::DAY_SPENT_CAP, int(v.caps[2])),
            (allowit::DAY_TOTAL_CAP, int(v.caps[3])),
            (allowit::CALL_CAP, v.call_cap.map(AllowitValue::from)),
            (allowit::RECIPIENTS, list(env, universe, &v.recipients)),
            (allowit::TOKENS, list(env, universe, &v.tokens)),
            (allowit::EXPIRY, v.expiry.map(AllowitValue::from)),
            (
                allowit::OPERATIONS,
                v.operations.as_ref().map(|ops| operations(env, ops)),
            ),
            (vectors::INVOICE_CAP, int(v.invoice_cap)),
        ],
    )
}
/// The agent's execution params of a vector, with its filler args.
fn args(env: &Env, v: &Vector) -> Map<Symbol, AllowitValue> {
    let mut args = map(
        env,
        &[(vectors::INVOICE, v.invoice.then_some(AllowitValue::Int(1)))],
    );
    for i in 0..v.extra_args {
        let key = Symbol::new(env, &vectors::arg_key(i));
        args.set(key, AllowitValue::from(i as u64));
    }
    args
}
/// The current state map of a vector, with the catching policy's key when set and its filler keys.
fn state_map(env: &Env, v: &Vector) -> Map<Symbol, AllowitValue> {
    let mut state = Map::new(env);
    let s = AllowitStandardState {
        calls: v.calls,
        spent: v.spent,
        unpriced: v.unpriced,
        day: v.day,
        day_spent: v.day_spent,
        day_total: v.day_total,
        day_unpriced: v.day_unpriced,
    };
    s.write(&mut state).unwrap();
    if let Some(over) = v.over {
        state.set(Symbol::new(env, vectors::OVER), over.into());
    }
    for i in 0..v.extra_state {
        let key = Symbol::new(env, &vectors::state_key(i));
        state.set(key, AllowitValue::from(i as u64));
    }
    if !v.blob.is_empty() {
        let mut texts = Vec::new(env);
        for n in &v.blob {
            let text = soroban_sdk::String::from_str(env, &"x".repeat(*n));
            texts.push_back(AllowitValue::Str(text));
        }
        state.set(Symbol::new(env, vectors::BLOB), AllowitValue::List(texts));
    }
    state
}
/// A state map as `vectors::state_line`.
fn line(env: &Env, state: &Map<Symbol, AllowitValue>) -> Text {
    let s = AllowitStandardState::read(state).unwrap();
    let over = state
        .get(Symbol::new(env, vectors::OVER))
        .map(|value| u64::try_from(value).unwrap());
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
fn context(env: &Env, universe: &[Address], v: &Vector) -> AllowitContext {
    AllowitContext {
        env: env.clone(),
        params: AllowitParams(params(env, universe, v)),
        state: state_map(env, v),
        request: AllowitRequest {
            operation: match v.op {
                Op::Transfer => AllowitOperation::transfer,
                Op::Deposit => AllowitOperation::deposit,
                Op::Swap => AllowitOperation::swap,
                Op::Redeem => AllowitOperation::redeem,
            },
            asset: universe[v.asset].clone(),
            recipient: universe[v.recipient].clone(),
            amount: v.amount,
            token_in: universe[v.token_in].clone(),
            amount_in: v.amount_in,
            token_out: v.token_out.map(|i| universe[i].clone()),
            min_out: v.min_out,
            now: v.now,
            expires_at: v.expires_at,
            spent_units: v.spent_units,
            gas_units: v.gas_units,
            unpriced: !v.priced,
            args: AllowitParams(args(env, v)),
        },
    }
}
/// Soroban backend outcome, inside a contract so policy writes have temporary storage.
fn soroban_outcome(env: &Env, contract: &Address, universe: &[Address], v: &Vector) -> Outcome {
    env.as_contract(contract, || {
        let c = context(env, universe, v);
        let p = |key| c.params.get(key);
        let code = |e: AllowitError| e as u32;
        let index = |a: Address| format!("@{}", universe.iter().position(|x| *x == a).unwrap());
        let run = |execute: &dyn Fn(&AllowitContext) -> allowit::Result, tier| {
            allowit::evaluate(&c, execute, tier)
                .map(|state| line(env, &state))
                .map_err(code)
        };
        let evaluate = |tier| run(&catching::execute, tier);
        // The Common wallet's policy with the full canonical prefix.
        let prefix = |c: &AllowitContext| {
            RULES
                .into_iter()
                .try_for_each(|rule| allowit::preflight(c, rule))
        };
        let rules: List<Result<Text, u32>> = [
            allowit::transaction_cap(&c, p(allowit::TRANSACTION_CAP)).map(|v| v.to_string()),
            allowit::spent_cap(&c, p(allowit::SPENT_CAP)).map(|v| v.to_string()),
            allowit::day_spent_cap(&c, p(allowit::DAY_SPENT_CAP)).map(|v| v.to_string()),
            allowit::day_total_cap(&c, p(allowit::DAY_TOTAL_CAP)).map(|v| v.to_string()),
            allowit::call_cap(&c, p(allowit::CALL_CAP)).map(|v| v.to_string()),
            allowit::recipients(&c, p(allowit::RECIPIENTS)).map(index),
            allowit::tokens(&c, p(allowit::TOKENS)).map(index),
            allowit::expiry(&c, p(allowit::EXPIRY)).map(|v| v.to_string()),
            allowit::operations(&c, p(allowit::OPERATIONS)).map(|v| v.to_string()),
        ]
        .into_iter()
        .map(|r| r.map_err(code))
        .collect();
        Outcome {
            policy: sample::execute(&c).map_err(code),
            branch: branch::execute(&c).map_err(code),
            catching: catching::execute(&c).map_err(code),
            rules,
            preflight: RULES
                .into_iter()
                .map(|rule| allowit::preflight(&c, rule).map_err(code))
                .collect(),
            // The bare catching run above may have buffered a write; `evaluate` clears it first.
            next: run(&|_| Ok(()), AllowitTier::Custom),
            common: run(&prefix, AllowitTier::Standard),
            simple: run(&|_| Ok(()), AllowitTier::Standard),
            catching_next: evaluate(AllowitTier::Custom),
            catching_standard: evaluate(AllowitTier::Standard),
        }
    })
}

/// The leading canonical calls of the sample policy, as `scripts/policy_source.py` derives them
/// for the standard contract.
fn sample_prefix() -> List<AllowitRule> {
    let source = include_str!("../../custom-policy/policy/policy.rs");
    let (_, body) = source
        .split_once("pub fn execute(ctx: &AllowitContext) -> allowit::Result {")
        .unwrap();
    let mut rules = List::new();
    for line in body.lines().map(str::trim) {
        if line.is_empty() || line.starts_with("//") {
            continue;
        }
        let call = line
            .strip_prefix("allowit::")
            .and_then(|call| call.strip_suffix("))?;"))
            .and_then(|call| call.split_once("(ctx, ctx.params.get(allowit::"));
        let Some(rule) = call.and_then(|(rule, key)| {
            let i = RULES.iter().position(|r| std::format!("{r:?}") == rule)?;
            (rule.to_uppercase() == key).then_some(RULES[i])
        }) else {
            break;
        };
        rules.push(rule);
    }
    rules
}

/// Whether every tier's owner configuration admits an `operations` value: `*` or a list of op names.
fn operations_valid(ops: &Ops) -> bool {
    let name = |name: &&str| {
        ["transfer", "swap", "deposit", "redeem", "custom"].contains(name)
            || name.starts_with("custom.")
            || name.starts_with("custom:")
    };
    match ops {
        Ops::Text(text) => *text == "*",
        Ops::List(names) => names.iter().all(name),
    }
}

/// Whether the kernel and owner configuration can produce the vector through `execute` of a
/// transfer: a transfer of the installed asset whose expense bounds, when priced, attest principal plus gas, with args that the kernel
/// admits and params that every tier admits. The kernel rejects more args with
/// `InvalidInvocation` before any policy runs.
fn realizable(v: &Vector) -> bool {
    let cost = if v.priced {
        v.gas_units >= 0 && v.spent_units == v.amount + v.gas_units
    } else {
        v.spent_units == 0 && v.gas_units == 0
    };
    v.op == Op::Transfer
        && v.extra_args + usize::from(v.invoice) <= vectors::MAX_ARGS
        && v.asset == vectors::ASSET
        && v.amount > 0
        && v.expires_at > v.now
        && cost
        && v.caps.iter().flatten().all(|cap| *cap >= 0)
        && v.operations.as_ref().is_none_or(operations_valid)
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Tier {
    Custom,
    Common,
    Simple,
    /// The custom contract compiled with the catching policy.
    Catching,
}
/// Every deployed contract that the vectors run through.
const TIERS: [Tier; 4] = [Tier::Custom, Tier::Common, Tier::Simple, Tier::Catching];
/// One deployed wallet Wasm and its address universe.
struct Wallet {
    f: Fixture,
    tier: Tier,
    universe: List<Address>,
    operations: core::cell::Cell<u64>,
}
impl Wallet {
    /// Deploy the tier's Wasm, fund it and bind Common to the sample policy's prefix.
    fn new(tier: Tier) -> Self {
        let f = Fixture::new(Self::wasm(tier), false);
        f.env.mock_all_auths();
        StellarAssetClient::new(&f.env, &f.asset).mint(&f.wallet, &1_000_000);
        f.env.mock_auths(&[]);
        let mut universe = List::from([f.asset.clone(), f.recipient.clone()]);
        while universe.len() < vectors::ADDRESSES {
            universe.push(Address::generate(&f.env));
        }
        let wallet = Self {
            f,
            tier,
            universe,
            operations: core::cell::Cell::new(0),
        };
        if tier == Tier::Common {
            wallet.bind(&sample_prefix());
        }
        wallet
    }
    /// The deployed Wasm of a tier.
    fn wasm(tier: Tier) -> &'static [u8] {
        match tier {
            Tier::Custom => CUSTOM,
            Tier::Common => COMMON,
            Tier::Simple => SIMPLE,
            Tier::Catching => CATCHING,
        }
    }
    /// Bind the standard contract to an authored policy's leading-rule prefix.
    fn bind(&self, prefix: &[AllowitRule]) {
        let env = &self.f.env;
        let mut rules = Vec::new(env);
        for rule in prefix {
            rules.push_back(*rule);
        }
        let module = env
            .crypto()
            .sha256(&Bytes::from_slice(env, Self::wasm(self.tier)));
        let digest = standard_prefix_digest(
            env,
            &Symbol::new(env, "common_policy_engine"),
            &module.to_bytes(),
            &self.f.asset,
            &rules,
        );
        env.as_contract(&self.f.wallet, || {
            let mut state = state(env).unwrap();
            state.rules = rules;
            state.source_digest = digest;
            store(env, &state);
        });
    }
    /// Install the vector's params and current state, and move the ledger to the request time.
    /// The owner can change param values without code redeployment.
    fn seed(&self, v: &Vector, paused: bool) {
        let env = &self.f.env;
        env.ledger().with_mut(|l| l.timestamp = v.now);
        env.as_contract(&self.f.wallet, || {
            let mut s = state(env).unwrap();
            s.params = params(env, &self.universe, v);
            s.policy_state = state_map(env, v);
            s.paused = paused;
            store(env, &s);
        });
    }
    fn request(&self, v: &Vector) -> AllowitExecutionRequest {
        let env = &self.f.env;
        let s = self.f.client().state();
        let b = self.f.client().policy_binding();
        let operation = self.operations.get() + 1;
        self.operations.set(operation);
        let mut id = [0u8; 32];
        id[24..].copy_from_slice(&operation.to_be_bytes());
        let expense = AllowitExpenseBounds {
            asset: self.f.asset.clone(),
            decimals: 7,
            gas_units: v.gas_units,
            conversion_units: 0,
            spent_units: v.spent_units,
            max_fee_stroops: u32::try_from(v.gas_units).unwrap(),
            observed_ledger: 1,
            day: v.now / 86_400,
        };
        AllowitExecutionRequest {
            source_hash: if matches!(self.tier, Tier::Custom | Tier::Catching) {
                b.source_digest.clone()
            } else {
                BytesN::from_array(env, &[9; 32])
            },
            expense: if v.priced {
                AllowitExpense::Priced(expense)
            } else {
                AllowitExpense::Unpriced
            },
            policy_instance: b.policy_instance,
            operation_id: BytesN::from_array(env, &id),
            nonce: s.nonce,
            deployment_version: s.deployment_version,
            expires_at: v.expires_at,
            args: args(env, v),
            module_digest: b.module_digest,
            operation: AllowitStellarOperation::Transfer(AllowitTransferArgs {
                token: self.universe[v.asset].clone(),
                to: self.universe[v.recipient].clone(),
                amount: v.amount,
            }),
        }
    }
    fn execute(&self, e: &AllowitExecutionRequest) -> Result<(), u32> {
        let f = &self.f;
        f.auth(
            &[&f.agent, &f.server],
            "execute",
            (e.clone(),).into_val(&f.env),
        );
        match f.client().try_execute(e) {
            Ok(Ok(_)) => Ok(()),
            Err(Ok(error)) => Err(error as u32),
            other => panic!("{:?} {:?}", self.tier, other.is_ok()),
        }
    }
}

#[test]
fn one_vector_set_has_matching_outcomes_on_host_custom_standard_and_simple() {
    assert_eq!(vectors::MAX_ARGS, allowit::MAX_ARGS as usize);
    assert_eq!(
        vectors::MAX_POLICY_KEYS + 7,
        allowit::MAX_STATE_KEYS as usize
    );
    assert_eq!(vectors::MAX_STATE_BYTES, allowit::MAX_STATE_BYTES as usize);
    let all = vectors::vectors();
    let host = host_lines();
    assert_eq!(host.len(), all.len());
    let wallets = TIERS.map(Wallet::new);
    let custom = &wallets[0];
    let prefix = sample_prefix();
    assert_eq!(prefix, RULES);
    let mut realized = 0;
    // Realized vectors where the catching policy caught a rule error and the operation succeeded.
    let mut caught = List::new();
    for (v, host) in all.iter().zip(&host) {
        // 1 and 2: the host smoke and the Soroban backend agree on every pass value, error and
        // post-flight state.
        let outcome = soroban_outcome(&custom.f.env, &custom.f.wallet, &custom.universe, v);
        assert_eq!(*host, outcome.line(v.name));
        if !realizable(v) {
            continue;
        }
        realized += 1;
        let next = outcome.next.clone().map(|_| ());
        let first_prefix_error = prefix
            .iter()
            .map(|rule| outcome.preflight[RULES.iter().position(|r| r == rule).unwrap()])
            .find(Result::is_err);
        // A standard evaluation admits only canonical params, as the standard contract does
        // after a direct seed, then runs the prefix and the plain post-flight.
        let custom_param = v
            .invoice_cap
            .map_or(Ok(()), |_| Err(AllowitError::InvalidParam as u32));
        let common = custom_param
            .and(first_prefix_error.unwrap_or(Ok(())))
            .and(next);
        assert_eq!(outcome.common.clone().map(|_| ()), common, "{}", v.name);
        let simple = custom_param.and(next);
        assert_eq!(outcome.simple.clone().map(|_| ()), simple, "{}", v.name);
        let expected = |tier: Tier| {
            match tier {
                Tier::Custom => outcome.policy.and(next),
                Tier::Common => outcome.common.clone().map(|_| ()),
                Tier::Simple => outcome.simple.clone().map(|_| ()),
                Tier::Catching => outcome.catching_next.clone().map(|_| ()),
            }
            .map_err(wallet_error)
        };
        // A standard evaluation rejects a custom param, denies the catching policy's write and
        // otherwise equals the plain post-flight, which the standard tiers store.
        let wrote = outcome.catching_next != outcome.catching.and(outcome.next.clone());
        let standard = custom_param.map(|()| Text::new()).and(if wrote {
            Err(AllowitError::Unsupported as u32)
        } else {
            outcome.catching.and(outcome.next.clone())
        });
        assert_eq!(outcome.catching_standard, standard, "{}", v.name);
        let unset = v.caps.contains(&None)
            || v.call_cap.is_none()
            || v.recipients.is_none()
            || v.tokens.is_none()
            || v.expiry.is_none()
            || v.operations.is_none();
        if !unset && v.invoice_cap.is_none() {
            assert_eq!(expected(Tier::Common), expected(Tier::Custom), "{}", v.name);
        }
        if outcome.catching.is_ok() && outcome.policy.is_err() {
            caught.push(v.name);
        }
        for wallet in &wallets {
            wallet.seed(v, false);
            let result = wallet.execute(&wallet.request(v));
            assert_eq!(
                result,
                expected(wallet.tier),
                "{} {:?}",
                v.name,
                wallet.tier
            );
            // The contract stored exactly the post-flight state that the host computed.
            if result.is_ok() {
                let stored = line(&wallet.f.env, &wallet.f.client().policy_state());
                let want = match wallet.tier {
                    Tier::Catching => outcome.catching_next.clone(),
                    _ => outcome.next.clone(),
                };
                assert_eq!(Ok(stored), want, "{} {:?}", v.name, wallet.tier);
            }
        }
    }
    assert_eq!(realized, 49);
    // The deployed catching Wasm let these continue after a caught rule error and wrote its key.
    for name in ["over_day_spent_cap", "over_day_spent_cap_counted_once"] {
        assert!(caught.contains(&name), "{name} {caught:?}");
    }
}

#[test]
fn kernel_violations_reject_identically_in_every_contract() {
    use AllowitWalletError as W;
    let v = vectors::base();
    assert!(realizable(&v));
    for wallet in TIERS.map(Wallet::new) {
        let tier = wallet.tier;
        let reject = |change: &dyn Fn(&mut AllowitExecutionRequest), paused: bool| {
            wallet.seed(&v, paused);
            let mut e = wallet.request(&v);
            change(&mut e);
            wallet.execute(&e)
        };
        let transfer = |e: &mut AllowitExecutionRequest,
                        edit: &dyn Fn(&mut AllowitTransferArgs)| {
            edit(transfer_args(e))
        };
        let other = wallet.universe[vectors::OTHER].clone();
        let asset = |e: &mut AllowitExecutionRequest| transfer(e, &|a| a.token = other.clone());
        let to_self =
            |e: &mut AllowitExecutionRequest| transfer(e, &|a| a.to = wallet.f.wallet.clone());
        let expired = |e: &mut AllowitExecutionRequest| e.expires_at = v.now;
        let stale = |e: &mut AllowitExecutionRequest| e.nonce += 1;
        assert_eq!(
            reject(&asset, false),
            Err(W::InvalidInvocation as u32),
            "{tier:?}"
        );
        assert_eq!(
            reject(&to_self, false),
            Err(W::InvalidRecipient as u32),
            "{tier:?}"
        );
        assert_eq!(reject(&expired, false), Err(W::Expired as u32), "{tier:?}");
        assert_eq!(
            reject(&stale, false),
            Err(W::StaleRequest as u32),
            "{tier:?}"
        );
        assert_eq!(reject(&|_| {}, true), Err(W::Paused as u32), "{tier:?}");
        // The same request passes, then its single-use operation ID rejects.
        wallet.seed(&v, false);
        let e = wallet.request(&v);
        assert_eq!(wallet.execute(&e), Ok(()), "{tier:?}");
        let mut replay = wallet.request(&v);
        replay.operation_id = e.operation_id;
        assert_eq!(wallet.execute(&replay), Err(W::Replay as u32), "{tier:?}");
    }
}

/// The server signs only an approved `evaluate`, and every tier then stores exactly the state it
/// returned. The catching policy's write counts on Custom; a standard tier cannot store it, so the
/// host denies it there, where the chain alone would drop the write and diverge.
#[test]
fn every_tier_stores_exactly_the_state_that_the_server_evaluates() {
    let base = vectors::base();
    let mut over = base.clone();
    over.caps[2] = Some(44);
    let custom = Wallet::new(Tier::Catching);
    let common = Wallet::new(Tier::Common);
    // The catching policy's prefix is its leading `recipients` call.
    common.bind(&[AllowitRule::recipients]);
    let simple = Wallet::new(Tier::Simple);
    for (wallet, tier) in [
        (&custom, AllowitTier::Custom),
        (&common, AllowitTier::Standard),
        (&simple, AllowitTier::Standard),
    ] {
        let env = &wallet.f.env;
        for v in [&base, &over] {
            wallet.seed(v, false);
            let chain = wallet.f.client().policy_state();
            let host = env.as_contract(&wallet.f.wallet, || {
                let mut c = context(env, &wallet.universe, v);
                c.state = chain.clone();
                allowit::evaluate(&c, catching::execute, tier)
            });
            let written = v.caps[2] == Some(44);
            if tier == AllowitTier::Standard && written {
                assert_eq!(host, Err(AllowitError::Unsupported), "{:?}", wallet.tier);
                // Danger: signed anyway, the chain stores a state without the counted write.
                assert_eq!(wallet.execute(&wallet.request(v)), Ok(()));
                let stored = wallet.f.client().policy_state();
                assert!(!stored.contains_key(Symbol::new(env, vectors::OVER)));
                continue;
            }
            let next = host.unwrap();
            assert_eq!(next.contains_key(Symbol::new(env, vectors::OVER)), written);
            assert_eq!(
                wallet.execute(&wallet.request(v)),
                Ok(()),
                "{:?}",
                wallet.tier
            );
            assert_eq!(wallet.f.client().policy_state(), next, "{:?}", wallet.tier);
        }
    }
}

/// The agent's execution params reach a Custom policy, are covered by the agent and server
/// authorization, stay within their bound, and the standard tiers ignore them.
#[test]
fn execution_params_reach_custom_policy_are_signed_and_standard_tiers_ignore_them() {
    let mut v = vectors::base();
    v.invoice_cap = Some(39);
    let custom = Wallet::new(Tier::Catching);
    custom.seed(&v, false);
    assert_eq!(custom.execute(&custom.request(&v)), Ok(()));
    v.invoice = true;
    let capped = Err(wallet_error(AllowitError::TransactionCapExceeded as u32));
    assert_eq!(custom.execute(&custom.request(&v)), capped);
    v.invoice_cap = Some(40);
    custom.seed(&v, false);
    assert_eq!(custom.execute(&custom.request(&v)), Ok(()));
    // The standard tiers store no custom param and ignore the args.
    v.invoice_cap = None;
    for tier in [Tier::Common, Tier::Simple] {
        let wallet = Wallet::new(tier);
        wallet.seed(&v, false);
        assert_eq!(wallet.execute(&wallet.request(&v)), Ok(()), "{tier:?}");
    }
    for wallet in TIERS.map(Wallet::new) {
        let (f, env) = (&wallet.f, &wallet.f.env);
        wallet.seed(&v, false);
        // Agent and server sign the full invocation: a changed arg fails authorization.
        let signed = wallet.request(&v);
        f.auth(
            &[&f.agent, &f.server],
            "execute",
            (signed.clone(),).into_val(env),
        );
        let mut changed = signed.clone();
        changed
            .args
            .set(Symbol::new(env, vectors::INVOICE), AllowitValue::Int(2));
        assert!(matches!(f.client().try_execute(&changed), Err(Err(_))));
        // More than MAX_ARGS keys, or an oversized value, reject in the kernel.
        let mut many = wallet.request(&v);
        for i in 0..=allowit::MAX_ARGS {
            let key = Symbol::new(env, &std::format!("key_{i}"));
            many.args.set(key, AllowitValue::Bool(true));
        }
        let invalid = Err(AllowitWalletError::InvalidInvocation as u32);
        assert_eq!(wallet.execute(&many), invalid, "{:?}", wallet.tier);
        let mut long = wallet.request(&v);
        let text = soroban_sdk::String::from_str(env, &"x".repeat(257));
        long.args
            .set(Symbol::new(env, "memo"), AllowitValue::Str(text));
        assert_eq!(wallet.execute(&long), invalid, "{:?}", wallet.tier);
        assert_eq!(wallet.f.client().state().nonce, 0, "{:?}", wallet.tier);
    }
}
