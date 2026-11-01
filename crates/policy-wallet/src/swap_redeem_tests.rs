//! Swap and redeem through the compiled wallets: the intercepted door, where the agent sends the
//! plain router or vault call that a simple wallet would sign and the wallet's `__check_auth`
//! runs the policy, and the `execute` door, which observes the effects and keeps a receipt.
extern crate std;
use super::tests::*;
use super::*;
use allowit::{AllowitStandardState, OPERATIONS, RECIPIENTS, TOKENS, TRANSACTION_CAP};
use allowit_sep56_test_vault::AllowitSep56TestVaultClient;
use allowit_wallet_protocol::AllowitExpense;
use ed25519_dalek::{Signer, SigningKey};
use soroban_sdk::{
    InvokeError, contract, contractimpl,
    testutils::{Address as _, Ledger, MockAuthInvoke},
    token::StellarAssetClient,
    vec,
    xdr::SorobanAuthorizationEntry,
};

const VAULT: &[u8] =
    include_bytes!("../../../target/wasm32v1-none/release/allowit_sep56_test_vault.wasm");

/// Test pair: holds output reserves and pays them out for the router.
#[contract]
pub struct MockPair;
#[contractimpl]
impl MockPair {
    /// Pay `amount` of `token` to `to`.
    pub fn pay(env: Env, token: Address, to: Address, amount: i128) {
        token::Client::new(&env, &token).transfer(&env.current_contract_address(), &to, &amount);
    }
}

/// Test router with the Soroswap `swap_exact_tokens_for_tokens` shape: `to.require_auth()`, the
/// deadline and minimum-output checks, then `path[0].transfer(to, pair, amount_in)` and the
/// pair's payment of `amount_in * rate / 100` to `to`. Behavior 1 debits one unit more, 2 pays
/// one unit less than it reports.
#[contract]
pub struct MockRouter;
#[contractimpl]
impl MockRouter {
    /// Fix the pair, the rate in percent and the behavior.
    pub fn __constructor(env: Env, pair: Address, rate: i128, behavior: u32) {
        env.storage().instance().set(&0u32, &(pair, rate, behavior));
    }
    /// The pair of every token pair.
    pub fn router_pair_for(env: Env, _token_a: Address, _token_b: Address) -> Address {
        let (pair, _, _): (Address, i128, u32) = env.storage().instance().get(&0u32).unwrap();
        pair
    }
    /// Swap exactly `amount_in` of `path[0]` for at least `amount_out_min` of the last token.
    pub fn swap_exact_tokens_for_tokens(
        env: Env,
        amount_in: i128,
        amount_out_min: i128,
        path: Vec<Address>,
        to: Address,
        deadline: u64,
    ) -> Vec<i128> {
        let (pair, rate, behavior): (Address, i128, u32) =
            env.storage().instance().get(&0u32).unwrap();
        to.require_auth();
        assert!(env.ledger().timestamp() <= deadline, "expired");
        let out = amount_in * rate / 100;
        assert!(out >= amount_out_min, "insufficient output amount");
        let debit = if behavior == 1 {
            amount_in + 1
        } else {
            amount_in
        };
        token::Client::new(&env, &path.get_unchecked(0)).transfer(&to, &pair, &debit);
        let paid = if behavior == 2 { out - 1 } else { out };
        let last = path.get_unchecked(path.len() - 1);
        MockPairClient::new(&env, &pair).pay(&last, &to, &paid);
        let mut amounts = Vec::new(&env);
        amounts.push_back(amount_in);
        for _ in 1..path.len() {
            amounts.push_back(out);
        }
        amounts
    }
}

/// A router, its pair and a second Stellar Asset Contract to swap the wallet asset for.
struct Pool {
    router: Address,
    pair: Address,
    token: Address,
}
fn pool(f: &Fixture, rate: i128, behavior: u32) -> Pool {
    f.env.mock_all_auths();
    let token = f
        .env
        .register_stellar_asset_contract_v2(Address::generate(&f.env))
        .address();
    let pair = f.env.register(MockPair, ());
    let router = f.env.register(MockRouter, (pair.clone(), rate, behavior));
    StellarAssetClient::new(&f.env, &token).mint(&pair, &1_000_000);
    StellarAssetClient::new(&f.env, &f.asset).mint(&pair, &1_000_000);
    f.env.mock_auths(&[]);
    Pool {
        router,
        pair,
        token,
    }
}
/// A test vault of `behavior` that holds assets to redeem and has credited the wallet 100 shares.
fn vault(f: &Fixture, behavior: u32) -> Address {
    let vault = f.env.register(VAULT, (f.asset.clone(), behavior));
    f.env.mock_all_auths();
    StellarAssetClient::new(&f.env, &f.asset).mint(&vault, &1_000);
    f.env.mock_auths(&[]);
    AllowitSep56TestVaultClient::new(&f.env, &vault).mint_shares(&f.wallet, &100);
    vault
}
fn shares(f: &Fixture, vault: &Address) -> i128 {
    AllowitSep56TestVaultClient::new(&f.env, vault).balance(&f.wallet)
}
fn balance(f: &Fixture, token: &Address) -> i128 {
    token::Client::new(&f.env, token).balance(&f.wallet)
}
/// Install `recipients` and `tokens` beside the fixture's own and the `operations` list through an
/// owner packet. Common also gets the `operations` rule, bound to its prefix digest.
fn allow(f: &Fixture, recipients: &[&Address], tokens: &[&Address], ops: &[&str]) {
    let mut d = f.deployment();
    let mut all_recipients = std::vec![&f.recipient];
    all_recipients.extend_from_slice(recipients);
    let mut all_tokens = std::vec![&f.asset];
    all_tokens.extend_from_slice(tokens);
    set_param(
        &mut d.params,
        RECIPIENTS,
        Some(addresses(&f.env, &all_recipients)),
    );
    set_param(&mut d.params, TOKENS, Some(addresses(&f.env, &all_tokens)));
    set_param(&mut d.params, OPERATIONS, Some(op_names(&f.env, ops)));
    if !d.rules.is_empty() && !d.rules.iter().any(|r| r == AllowitRule::operations) {
        d.rules.push_back(AllowitRule::operations);
        let module = f.env.crypto().sha256(&Bytes::from_slice(&f.env, COMMON));
        d.source_digest = standard_prefix_digest(
            &f.env,
            &Symbol::new(&f.env, "common_policy_engine"),
            &module.to_bytes(),
            &f.asset,
            &d.rules,
        );
    }
    f.auth(&[&f.owner], "deploy_policy", (d.clone(),).into_val(&f.env));
    f.client().deploy_policy(&d);
}
/// Change one owner param.
fn set(f: &Fixture, key: &str, value: Option<AllowitValue>) {
    let mut d = f.deployment();
    set_param(&mut d.params, key, value);
    f.auth(&[&f.owner], "deploy_policy", (d.clone(),).into_val(&f.env));
    f.client().deploy_policy(&d);
}
const OPS: [&str; 4] = ["transfer", "deposit", "swap", "redeem"];
/// Expense bounds of a conversion: conversion loss plus gas is spent.
fn bounds(f: &Fixture, gas: i128, conversion: i128) -> AllowitExpenseBounds {
    AllowitExpenseBounds {
        asset: f.asset.clone(),
        decimals: 7,
        gas_units: gas,
        conversion_units: conversion,
        spent_units: conversion + gas,
        max_fee_stroops: u32::try_from(gas).unwrap(),
        observed_ledger: 1,
        day: f.env.ledger().timestamp() / 86_400,
    }
}
fn path(env: &Env, tokens: &[&Address]) -> Vec<Address> {
    let mut path = Vec::new(env);
    for token in tokens {
        path.push_back((*token).clone());
    }
    path
}
/// A swap request through `pool` along `tokens`, with conversion bound `conversion`.
fn swap_request(
    f: &Fixture,
    pool: &Pool,
    tokens: &[&Address],
    amount_in: i128,
    amount_out_min: i128,
) -> (AllowitExecutionRequest, AllowitSwapArgs) {
    let mut e = f.execution(amount_in);
    let args = AllowitSwapArgs {
        router: pool.router.clone(),
        amount_in,
        amount_out_min,
        path: path(&f.env, tokens),
        deadline: e.expires_at,
    };
    e.operation = AllowitStellarOperation::Swap(args.clone());
    e.expense = AllowitExpense::Priced(bounds(f, 0, 3));
    (e, args)
}
/// Edit the swap arguments of `e`.
fn reswap(e: &mut AllowitExecutionRequest, edit: impl FnOnce(&mut AllowitSwapArgs)) {
    let AllowitStellarOperation::Swap(args) = &mut e.operation else {
        panic!("not a swap");
    };
    edit(args);
}
fn redeem_request(
    f: &Fixture,
    vault: &Address,
    shares: i128,
    min_assets: i128,
) -> AllowitExecutionRequest {
    let mut e = f.execution(min_assets);
    e.operation = AllowitStellarOperation::Redeem(AllowitRedeemArgs {
        vault: vault.clone(),
        shares,
        min_assets,
    });
    e.expense = AllowitExpense::Priced(bounds(f, 0, 0));
    e
}
fn deposit_request(f: &Fixture, vault: &Address, assets: i128) -> AllowitExecutionRequest {
    let mut e = f.execution(assets);
    e.operation = AllowitStellarOperation::Deposit(AllowitDepositArgs {
        vault: vault.clone(),
        assets,
        min_shares: assets,
    });
    e.expense = AllowitExpense::Priced(bounds(f, 0, 0));
    e
}
/// The plain router call a simple wallet signs: the swap with its one debit to the pair.
fn swap_entry(
    f: &Fixture,
    pool: &Pool,
    e: &AllowitExecutionRequest,
    args: &AllowitSwapArgs,
    nonce: i64,
) -> SorobanAuthorizationEntry {
    let token_in = args.path.get_unchecked(0);
    let debit = [MockAuthInvoke {
        contract: &token_in,
        fn_name: "transfer",
        args: (f.wallet.clone(), pool.pair.clone(), args.amount_in).into_val(&f.env),
        sub_invokes: &[],
    }];
    let root = MockAuthInvoke {
        contract: &pool.router,
        fn_name: "swap_exact_tokens_for_tokens",
        args: swap_call(f, args),
        sub_invokes: &debit,
    };
    f.signed_entry(&f.wallet, &root, nonce, &|payload| {
        f.authorization(e.clone(), payload).into_val(&f.env)
    })
}
/// The plain vault call a simple wallet signs.
fn redeem_entry(
    f: &Fixture,
    vault: &Address,
    e: &AllowitExecutionRequest,
    shares: i128,
    nonce: i64,
) -> SorobanAuthorizationEntry {
    let root = MockAuthInvoke {
        contract: vault,
        fn_name: "redeem",
        args: redeem_call(f, shares),
        sub_invokes: &[],
    };
    f.signed_entry(&f.wallet, &root, nonce, &|payload| {
        f.authorization(e.clone(), payload).into_val(&f.env)
    })
}
fn swap_call(f: &Fixture, a: &AllowitSwapArgs) -> Vec<Val> {
    (
        a.amount_in,
        a.amount_out_min,
        a.path.clone(),
        f.wallet.clone(),
        a.deadline,
    )
        .into_val(&f.env)
}
fn redeem_call(f: &Fixture, shares: i128) -> Vec<Val> {
    let w = f.wallet.clone();
    (shares, w.clone(), w.clone(), w).into_val(&f.env)
}
/// The agent's plain router call.
fn router_swap(f: &Fixture, pool: &Pool, a: &AllowitSwapArgs) -> bool {
    MockRouterClient::new(&f.env, &pool.router)
        .try_swap_exact_tokens_for_tokens(
            &a.amount_in,
            &a.amount_out_min,
            &a.path,
            &f.wallet,
            &a.deadline,
        )
        .is_ok()
}
/// The agent's plain vault call.
fn vault_redeem(f: &Fixture, vault: &Address, shares: i128) -> bool {
    AllowitSep56TestVaultClient::new(&f.env, vault)
        .try_redeem(&shares, &f.wallet, &f.wallet, &f.wallet)
        .is_ok()
}
fn call(f: &Fixture, contract: &Address, function: &str, args: Vec<Val>) -> Context {
    Context::Contract(ContractContext {
        contract: contract.clone(),
        fn_name: Symbol::new(&f.env, function),
        args,
    })
}
fn swap_contexts(f: &Fixture, pool: &Pool, a: &AllowitSwapArgs) -> Vec<Context> {
    let debit = (f.wallet.clone(), pool.pair.clone(), a.amount_in).into_val(&f.env);
    vec![
        &f.env,
        call(
            f,
            &pool.router,
            "swap_exact_tokens_for_tokens",
            swap_call(f, a),
        ),
        call(f, &a.path.get_unchecked(0), "transfer", debit),
    ]
}
/// Run the wallet's `__check_auth` directly on `contexts`.
fn check(
    f: &Fixture,
    e: &AllowitExecutionRequest,
    contexts: &Vec<Context>,
) -> Result<(), Result<AllowitWalletError, InvokeError>> {
    let payload = BytesN::from_array(&f.env, &[5; 32]);
    f.env.try_invoke_contract_check_auth::<AllowitWalletError>(
        &f.wallet,
        &payload,
        f.authorization(e.clone(), &payload).into_val(&f.env),
        contexts,
    )
}
fn execute(
    f: &Fixture,
    e: &AllowitExecutionRequest,
) -> Result<(), Result<AllowitWalletError, InvokeError>> {
    f.auth(
        &[&f.agent, &f.server],
        "execute",
        (e.clone(),).into_val(&f.env),
    );
    f.client().try_execute(e).map(|_| ())
}
fn marked(f: &Fixture, e: &AllowitExecutionRequest) -> bool {
    let key = Key::Operation(e.operation_id.clone());
    f.env
        .as_contract(&f.wallet, || f.env.storage().persistent().has(&key))
}
/// The wallet holds no allowance of `tokens` for any of `spenders`.
fn assert_no_allowance(f: &Fixture, tokens: &[&Address], spenders: &[&Address]) {
    for token in tokens {
        let client = token::Client::new(&f.env, token);
        for spender in spenders {
            assert_eq!(client.allowance(&f.wallet, spender), 0);
        }
    }
}
const TIERS: [&[u8]; 3] = [SIMPLE, COMMON, CUSTOM];

#[test]
fn intercepted_swap_runs_the_policy_in_check_auth_and_settles_natively() {
    for wasm in TIERS {
        let f = Fixture::new(wasm, true);
        let p = pool(&f, 95, 0);
        allow(&f, &[&p.router], &[&p.token], &OPS);
        let (e, a) = swap_request(&f, &p, &[&f.asset, &p.token], 50, 47);
        f.env.set_auths(&[swap_entry(&f, &p, &e, &a, 1)]);
        assert!(router_swap(&f, &p, &a));
        assert_eq!((f.balance(), balance(&f, &p.token)), (950, 47));
        let state = f.client().state();
        assert_eq!(state.nonce, 1);
        assert!(marked(&f, &e));
        let history = f.history();
        // A forward swap charges its conversion bound and counts its input as gross volume.
        assert_eq!(
            (history.calls, history.spent, history.day_total),
            (1, 3, 50)
        );
        assert_no_allowance(&f, &[&f.asset, &p.token], &[&p.router, &p.pair]);
        // The same operation cannot run again, even under a fresh host nonce.
        f.env.set_auths(&[swap_entry(&f, &p, &e, &a, 2)]);
        assert!(!router_swap(&f, &p, &a));
        assert_eq!(
            check(&f, &e, &swap_contexts(&f, &p, &a)),
            Err(Ok(AllowitWalletError::Replay))
        );
        assert_eq!((f.balance(), f.client().state()), (950, state));
    }
}

#[test]
fn intercepted_reverse_swap_pays_the_other_token_and_counts_the_asset_floor() {
    for wasm in TIERS {
        let f = Fixture::new(wasm, true);
        let p = pool(&f, 95, 0);
        f.env.mock_all_auths();
        StellarAssetClient::new(&f.env, &p.token).mint(&f.wallet, &100);
        f.env.mock_auths(&[]);
        allow(&f, &[&p.router], &[&p.token], &OPS);
        let (e, a) = swap_request(&f, &p, &[&p.token, &f.asset], 100, 40);
        f.env.set_auths(&[swap_entry(&f, &p, &e, &a, 1)]);
        assert!(router_swap(&f, &p, &a));
        assert_eq!((f.balance(), balance(&f, &p.token)), (1095, 0));
        let history = f.history();
        assert_eq!((history.calls, history.day_total), (1, 40));
    }
}

#[test]
fn intercepted_swap_is_denied_by_operations_tokens_caps_and_unknown_routers() {
    for wasm in [COMMON, CUSTOM] {
        let f = Fixture::new(wasm, true);
        let p = pool(&f, 95, 0);
        let denied = Err(Ok(AllowitWalletError::PolicyDenied));
        let cases: [(&str, &dyn Fn()); 4] = [
            ("operations", &|| {
                allow(&f, &[&p.router], &[&p.token], &["transfer", "redeem"])
            }),
            ("tokens", &|| allow(&f, &[&p.router], &[], &OPS)),
            ("transaction_cap", &|| {
                allow(&f, &[&p.router], &[&p.token], &OPS);
                set(&f, TRANSACTION_CAP, Some(AllowitValue::Int(49)));
            }),
            ("recipients", &|| allow(&f, &[], &[&p.token], &OPS)),
        ];
        for (name, configure) in cases {
            configure();
            let (e, a) = swap_request(&f, &p, &[&f.asset, &p.token], 50, 47);
            assert_eq!(check(&f, &e, &swap_contexts(&f, &p, &a)), denied, "{name}");
            f.env.set_auths(&[swap_entry(&f, &p, &e, &a, 7)]);
            assert!(!router_swap(&f, &p, &a), "{name}");
            assert_eq!(f.balance(), 1000, "{name}");
            assert_eq!(f.client().state().nonce, 0, "{name}");
            assert!(!marked(&f, &e), "{name}");
            set(&f, TRANSACTION_CAP, Some(AllowitValue::Int(100)));
        }
        // Control: the same swap passes once every rule admits it.
        allow(&f, &[&p.router], &[&p.token], &OPS);
        let (e, a) = swap_request(&f, &p, &[&f.asset, &p.token], 50, 47);
        assert_eq!(check(&f, &e, &swap_contexts(&f, &p, &a)), Ok(()));
    }
}

#[test]
fn intercepted_swap_accepts_only_the_plain_router_tree() {
    let f = Fixture::new(SIMPLE, true);
    let p = pool(&f, 95, 0);
    let (e, a) = swap_request(&f, &p, &[&f.asset, &p.token], 50, 47);
    let good = swap_contexts(&f, &p, &a);
    let root = good.get_unchecked(0);
    let debit = |to: &Address, amount: i128| {
        call(
            &f,
            &f.asset,
            "transfer",
            (f.wallet.clone(), to.clone(), amount).into_val(&f.env),
        )
    };
    let mut lowered = a.clone();
    lowered.amount_out_min = 40;
    let invalid = Err(Ok(AllowitWalletError::InvalidInvocation));
    let unsupported = Err(Ok(AllowitWalletError::UnsupportedOperation));
    // The x402 agent is a classic account.
    let account = f.agent.clone();
    let cases = [
        // The router's root alone, or with an extra node.
        (vec![&f.env, root.clone()], invalid),
        (
            vec![&f.env, root.clone(), debit(&p.pair, 50), debit(&p.pair, 50)],
            invalid,
        ),
        // A signed tree whose minimum output or receiver differs from the signed execution.
        (
            vec![
                &f.env,
                call(
                    &f,
                    &p.router,
                    "swap_exact_tokens_for_tokens",
                    swap_call(&f, &lowered),
                ),
                debit(&p.pair, 50),
            ],
            invalid,
        ),
        (
            vec![
                &f.env,
                call(
                    &f,
                    &p.router,
                    "swap_exact_tokens_for_tokens",
                    (
                        50i128,
                        47i128,
                        a.path.clone(),
                        f.recipient.clone(),
                        a.deadline,
                    )
                        .into_val(&f.env),
                ),
                debit(&p.pair, 50),
            ],
            invalid,
        ),
        // Another router function or contract.
        (
            vec![
                &f.env,
                call(
                    &f,
                    &p.router,
                    "swap_tokens_for_exact_tokens",
                    swap_call(&f, &a),
                ),
                debit(&p.pair, 50),
            ],
            unsupported,
        ),
        (
            vec![
                &f.env,
                call(
                    &f,
                    &p.pair,
                    "swap_exact_tokens_for_tokens",
                    swap_call(&f, &a),
                ),
                debit(&p.pair, 50),
            ],
            unsupported,
        ),
        // A debit of another amount, to the wallet, the router or an account, or of another token.
        (vec![&f.env, root.clone(), debit(&p.pair, 51)], invalid),
        (vec![&f.env, root.clone(), debit(&f.wallet, 50)], invalid),
        (vec![&f.env, root.clone(), debit(&p.router, 50)], invalid),
        (vec![&f.env, root.clone(), debit(&account, 50)], invalid),
        (
            vec![
                &f.env,
                root.clone(),
                call(
                    &f,
                    &f.asset,
                    "transfer",
                    (f.recipient.clone(), p.pair.clone(), 50i128).into_val(&f.env),
                ),
            ],
            invalid,
        ),
        (
            vec![
                &f.env,
                root.clone(),
                call(
                    &f,
                    &p.token,
                    "transfer",
                    (f.wallet.clone(), p.pair.clone(), 50i128).into_val(&f.env),
                ),
            ],
            unsupported,
        ),
        (
            vec![
                &f.env,
                root.clone(),
                call(
                    &f,
                    &f.asset,
                    "approve",
                    (f.wallet.clone(), p.pair.clone(), 50i128).into_val(&f.env),
                ),
            ],
            unsupported,
        ),
    ];
    for (i, (contexts, expected)) in cases.into_iter().enumerate() {
        assert_eq!(check(&f, &e, &contexts), expected, "case {i}");
    }
    assert_eq!(f.client().state().nonce, 0);
    assert_eq!(check(&f, &e, &good), Ok(()));
    assert_eq!(f.client().state().nonce, 1);
}

/// An edit of swap arguments.
type Edit<'a> = dyn Fn(&mut AllowitSwapArgs) + 'a;
#[test]
fn swap_kernel_invariants_reject_before_any_policy() {
    // The intercepted door with raw-key signers, then `execute` with mocked signers.
    for x402 in [true, false] {
        let f = Fixture::new(SIMPLE, x402);
        let p = pool(&f, 95, 0);
        let other = f
            .env
            .register_stellar_asset_contract_v2(Address::generate(&f.env))
            .address();
        use AllowitWalletError as W;
        let asset = f.asset.clone();
        let token = p.token.clone();
        let wallet = f.wallet.clone();
        let router = p.router.clone();
        let cases: [(&str, W, &Edit); 11] = [
            (
                "router is the wallet",
                W::InvalidInvocation,
                &|a: &mut AllowitSwapArgs| a.router = wallet.clone(),
            ),
            (
                "no asset endpoint",
                W::InvalidInvocation,
                &|a: &mut AllowitSwapArgs| a.path = path(&f.env, &[&token, &other]),
            ),
            (
                "both asset endpoints",
                W::InvalidInvocation,
                &|a: &mut AllowitSwapArgs| a.path = path(&f.env, &[&asset, &token, &asset]),
            ),
            (
                "one token",
                W::InvalidInvocation,
                &|a: &mut AllowitSwapArgs| a.path = path(&f.env, &[&asset]),
            ),
            (
                "five tokens",
                W::InvalidInvocation,
                &|a: &mut AllowitSwapArgs| {
                    a.path = path(&f.env, &[&asset, &other, &other, &other, &token])
                },
            ),
            (
                "wallet in path",
                W::InvalidInvocation,
                &|a: &mut AllowitSwapArgs| a.path = path(&f.env, &[&asset, &wallet, &token]),
            ),
            (
                "late deadline",
                W::InvalidInvocation,
                &|a: &mut AllowitSwapArgs| a.deadline += 1,
            ),
            (
                "router is the asset",
                W::InvalidInvocation,
                &|a: &mut AllowitSwapArgs| a.router = asset.clone(),
            ),
            (
                "contract token",
                W::UnsupportedAsset,
                &|a: &mut AllowitSwapArgs| a.path = path(&f.env, &[&asset, &router]),
            ),
            (
                "zero input",
                W::InvalidAmount,
                &|a: &mut AllowitSwapArgs| a.amount_in = 0,
            ),
            (
                "zero minimum",
                W::InvalidAmount,
                &|a: &mut AllowitSwapArgs| a.amount_out_min = 0,
            ),
        ];
        for (name, error, edit) in cases {
            let (mut e, a) = swap_request(&f, &p, &[&f.asset, &p.token], 50, 47);
            reswap(&mut e, edit);
            let result = if x402 {
                check(&f, &e, &swap_contexts(&f, &p, &a))
            } else {
                execute(&f, &e)
            };
            assert_eq!(result, Err(Ok(error)), "{name}");
        }
        if !x402 {
            continue;
        }
        // A deposit has no intercepted form.
        let v = vault(&f, 0);
        let e = deposit_request(&f, &v, 50);
        let contexts = vec![
            &f.env,
            call(
                &f,
                &v,
                "deposit",
                (50i128, f.wallet.clone(), f.wallet.clone(), f.wallet.clone()).into_val(&f.env),
            ),
        ];
        assert_eq!(check(&f, &e, &contexts), Err(Ok(W::UnsupportedOperation)));
        assert_eq!(f.client().state().nonce, 0);
        assert_eq!(f.balance(), 1000);
    }
}

#[test]
fn intercepted_swap_keeps_kernel_gates_signatures_and_the_disabled_door() {
    use AllowitWalletError as W;
    let f = Fixture::new(COMMON, true);
    let p = pool(&f, 95, 0);
    allow(&f, &[&p.router], &[&p.token], &OPS);
    let (e, a) = swap_request(&f, &p, &[&f.asset, &p.token], 50, 47);
    let contexts = swap_contexts(&f, &p, &a);
    let mut stale = e.clone();
    stale.nonce += 1;
    assert_eq!(check(&f, &stale, &contexts), Err(Ok(W::StaleRequest)));
    let mut old = e.clone();
    old.deployment_version -= 1;
    assert_eq!(check(&f, &old, &contexts), Err(Ok(W::StaleRequest)));
    // A bad server signature aborts.
    let payload = BytesN::from_array(&f.env, &[5; 32]);
    let mut auth = f.authorization(e.clone(), &payload);
    auth.server_signature = BytesN::from_array(&f.env, &[0; 64]);
    assert_eq!(
        f.env.try_invoke_contract_check_auth::<W>(
            &f.wallet,
            &payload,
            auth.into_val(&f.env),
            &contexts
        ),
        Err(Err(InvokeError::Abort))
    );
    // Expiry and pause.
    f.env.ledger().with_mut(|l| l.timestamp = e.expires_at);
    assert_eq!(check(&f, &e, &contexts), Err(Ok(W::Expired)));
    f.env.ledger().with_mut(|l| l.timestamp = 86_410);
    f.auth(
        &[&f.owner],
        "set_pause",
        (true, e.deployment_version + 1).into_val(&f.env),
    );
    f.client().set_pause(&true, &(e.deployment_version + 1));
    let (e, a) = swap_request(&f, &p, &[&f.asset, &p.token], 50, 47);
    assert_eq!(
        check(&f, &e, &swap_contexts(&f, &p, &a)),
        Err(Ok(W::Paused))
    );
    assert_eq!((f.client().state().nonce, f.balance()), (0, 1000));
    // With custom-account authorization disabled the intercepted door rejects and `execute` swaps.
    let f = Fixture::new(COMMON, false);
    let p = pool(&f, 95, 0);
    allow(&f, &[&p.router], &[&p.token], &OPS);
    let (e, a) = swap_request(&f, &p, &[&f.asset, &p.token], 50, 47);
    assert_eq!(
        check(&f, &e, &swap_contexts(&f, &p, &a)),
        Err(Ok(W::UnsupportedOperation))
    );
    assert_eq!(execute(&f, &e), Ok(()));
    assert_eq!((f.balance(), balance(&f, &p.token)), (950, 47));
}

#[test]
fn router_minimum_output_failure_rolls_back_the_state_written_in_check_auth() {
    for wasm in TIERS {
        let f = Fixture::new(wasm, true);
        let p = pool(&f, 95, 0);
        allow(&f, &[&p.router], &[&p.token], &OPS);
        let before = f.client().state();
        // The router quotes 47 for 50: a minimum of 48 fails after the wallet admitted the swap
        // at its first `require_auth`, so the state, nonce and marker it wrote roll back.
        let (e, a) = swap_request(&f, &p, &[&f.asset, &p.token], 50, 48);
        f.env.set_auths(&[swap_entry(&f, &p, &e, &a, 1)]);
        assert!(!router_swap(&f, &p, &a));
        assert_eq!(f.client().state(), before);
        assert!(!marked(&f, &e));
        assert_eq!((f.balance(), balance(&f, &p.token)), (1000, 0));
        // The wallet admits this exact request: only the router's minimum failed.
        assert_eq!(check(&f, &e, &swap_contexts(&f, &p, &a)), Ok(()));
        assert_eq!(f.client().state().nonce, 1);
    }
}

#[test]
fn intercepted_redeem_runs_the_policy_and_a_double_authorizing_vault_counts_twice() {
    for wasm in TIERS {
        let f = Fixture::new(wasm, true);
        let v = vault(&f, 0);
        allow(&f, &[&v], &[], &OPS);
        let e = redeem_request(&f, &v, 40, 40);
        f.env.set_auths(&[redeem_entry(&f, &v, &e, 40, 1)]);
        assert!(vault_redeem(&f, &v, 40));
        assert_eq!((f.balance(), shares(&f, &v)), (1040, 60));
        assert_eq!(f.client().state().nonce, 1);
        let history = f.history();
        assert_eq!(
            (history.calls, history.day_total, history.spent),
            (1, 40, 0)
        );
        assert_no_allowance(&f, &[&f.asset], &[&v]);
        // A vault that also authorizes the owner in the same frame needs a second entry.
        let twice = vault(&f, 20);
        allow(&f, &[&twice], &[], &OPS);
        let e = redeem_request(&f, &twice, 40, 40);
        f.env.set_auths(&[redeem_entry(&f, &twice, &e, 40, 2)]);
        assert!(!vault_redeem(&f, &twice, 40));
        assert_eq!((f.balance(), shares(&f, &twice)), (1040, 100));
        assert_eq!(f.client().state().nonce, 1);
        // A second signed entry with its own execution is a second operation: the wallet admits
        // both, so the one real redeem uses two nonces and counts twice in the policy state.
        let mut second = e.clone();
        second.nonce += 1;
        let mut id = [0u8; 32];
        id[24..].copy_from_slice(&(second.nonce + 1).to_be_bytes());
        second.operation_id = BytesN::from_array(&f.env, &id);
        f.env.set_auths(&[
            redeem_entry(&f, &twice, &e, 40, 2),
            redeem_entry(&f, &twice, &second, 40, 3),
        ]);
        assert!(vault_redeem(&f, &twice, 40));
        assert_eq!((f.balance(), shares(&f, &twice)), (1080, 60));
        assert_eq!(f.client().state().nonce, 3);
        let history = f.history();
        assert_eq!(
            (history.calls, history.day_total, history.spent),
            (3, 120, 0)
        );
    }
}

#[test]
fn redeem_is_denied_by_operations_and_unknown_vaults_and_checks_its_tree() {
    use AllowitWalletError as W;
    for wasm in [COMMON, CUSTOM] {
        let f = Fixture::new(wasm, true);
        let v = vault(&f, 0);
        let contexts = vec![&f.env, call(&f, &v, "redeem", redeem_call(&f, 40))];
        allow(&f, &[&v], &[], &["transfer", "swap"]);
        let e = redeem_request(&f, &v, 40, 40);
        assert_eq!(check(&f, &e, &contexts), Err(Ok(W::PolicyDenied)));
        allow(&f, &[], &[], &OPS);
        let e = redeem_request(&f, &v, 40, 40);
        assert_eq!(check(&f, &e, &contexts), Err(Ok(W::PolicyDenied)));
        allow(&f, &[&v], &[], &OPS);
        let e = redeem_request(&f, &v, 40, 40);
        // Another share amount, receiver or function, and an extra node, reject.
        let w = f.wallet.clone();
        let r = f.recipient.clone();
        for (contexts, error) in [
            (
                vec![&f.env, call(&f, &v, "redeem", redeem_call(&f, 41))],
                W::InvalidInvocation,
            ),
            (
                vec![
                    &f.env,
                    call(
                        &f,
                        &v,
                        "redeem",
                        (40i128, r, w.clone(), w.clone()).into_val(&f.env),
                    ),
                ],
                W::InvalidInvocation,
            ),
            (
                vec![&f.env, call(&f, &v, "withdraw", redeem_call(&f, 40))],
                W::UnsupportedOperation,
            ),
            (
                vec![&f.env, contexts.get_unchecked(0), contexts.get_unchecked(0)],
                W::InvalidInvocation,
            ),
        ] {
            assert_eq!(check(&f, &e, &contexts), Err(Ok(error)));
        }
        assert_eq!(check(&f, &e, &contexts), Ok(()));
    }
    // Kernel invariants: the wallet or the asset as vault and positive amounts.
    let f = Fixture::new(SIMPLE, true);
    let v = vault(&f, 0);
    let contexts = vec![&f.env, call(&f, &v, "redeem", redeem_call(&f, 40))];
    let cases = [
        (f.wallet.clone(), 40, 40, W::InvalidInvocation),
        (f.asset.clone(), 40, 40, W::InvalidInvocation),
        (v.clone(), 0, 40, W::InvalidAmount),
        (v.clone(), 40, 0, W::InvalidAmount),
    ];
    for (field, (vault, shares, min_assets, error)) in cases.into_iter().enumerate() {
        let e = redeem_request(&f, &vault, shares, min_assets);
        assert_eq!(check(&f, &e, &contexts), Err(Ok(error)), "{field}");
    }
    assert_eq!(f.client().state().nonce, 0);
}

#[test]
fn execute_redeem_checks_observed_effects_and_keeps_a_receipt() {
    for wasm in TIERS {
        let f = Fixture::new(wasm, false);
        let v = vault(&f, 0);
        allow(&f, &[&v], &[], &OPS);
        let e = redeem_request(&f, &v, 40, 40);
        assert_eq!(execute(&f, &e), Ok(()));
        assert_eq!((f.balance(), shares(&f, &v)), (1040, 60));
        let receipt = f.client().redeem_receipt(&e.operation_id).unwrap();
        assert_eq!((receipt.shares, receipt.assets), (40, 40));
        assert_eq!((receipt.vault, receipt.asset), (v.clone(), f.asset.clone()));
        assert_eq!(receipt.owner, f.wallet);
        assert_eq!(f.client().state().nonce, 1);
        assert_no_allowance(&f, &[&f.asset], &[&v]);
        // A minimum above the payment rolls back.
        let e = redeem_request(&f, &v, 40, 41);
        let before = f.client().state();
        assert_eq!(execute(&f, &e), Err(Ok(AllowitWalletError::InvalidEffects)));
        assert_eq!(f.client().state(), before);
        assert!(!marked(&f, &e));
    }
    // Short payment, a lied return and an over-burn roll everything back.
    for behavior in [21, 22, 23] {
        let f = Fixture::new(COMMON, false);
        let v = vault(&f, behavior);
        allow(&f, &[&v], &[], &OPS);
        let before = f.client().state();
        let history = f.history();
        let e = redeem_request(&f, &v, 40, 39);
        assert_eq!(
            execute(&f, &e),
            Err(Ok(AllowitWalletError::InvalidEffects)),
            "{behavior}"
        );
        assert_eq!(f.client().state(), before);
        assert_eq!(f.history(), history);
        assert_eq!((f.balance(), shares(&f, &v)), (1000, 100));
        assert_eq!(f.client().redeem_receipt(&e.operation_id), None);
        assert!(!marked(&f, &e));
    }
    // A vault fee that its own preview hides must stay within the attested conversion bound.
    for (conversion, result) in [
        (2, Err(Ok(AllowitWalletError::InvalidEffects))),
        (3, Ok(())),
    ] {
        let f = Fixture::new(COMMON, false);
        let v = vault(&f, 25);
        allow(&f, &[&v], &[], &OPS);
        let before = f.client().state();
        let mut e = redeem_request(&f, &v, 40, 37);
        e.expense = AllowitExpense::Priced(bounds(&f, 0, conversion));
        assert_eq!(execute(&f, &e), result, "{conversion}");
        if result.is_ok() {
            assert_eq!((f.balance(), shares(&f, &v)), (1037, 60));
            assert_eq!(
                f.client().redeem_receipt(&e.operation_id).unwrap().assets,
                37
            );
            assert_eq!(f.history().spent, 3);
        } else {
            assert_eq!(f.client().state(), before);
            assert_eq!((f.balance(), shares(&f, &v)), (1000, 100));
            assert!(!marked(&f, &e));
        }
    }
    // Through `execute` the vault authorizes against the invoking wallet, also twice.
    let f = Fixture::new(COMMON, false);
    let v = vault(&f, 20);
    allow(&f, &[&v], &[], &OPS);
    assert_eq!(execute(&f, &redeem_request(&f, &v, 40, 40)), Ok(()));
}

#[test]
fn execute_swap_checks_observed_effects_and_keeps_a_receipt() {
    for wasm in TIERS {
        let f = Fixture::new(wasm, false);
        let p = pool(&f, 95, 0);
        allow(&f, &[&p.router], &[&p.token], &OPS);
        let (e, _) = swap_request(&f, &p, &[&f.asset, &p.token], 50, 47);
        assert_eq!(execute(&f, &e), Ok(()));
        assert_eq!((f.balance(), balance(&f, &p.token)), (950, 47));
        let receipt = f.client().swap_receipt(&e.operation_id).unwrap();
        assert_eq!((receipt.amount_in, receipt.amount_out), (50, 47));
        assert_eq!(
            (receipt.token_in, receipt.token_out),
            (f.asset.clone(), p.token.clone())
        );
        assert_eq!(receipt.router, p.router);
        assert_eq!((f.history().spent, f.history().day_total), (3, 50));
        assert_no_allowance(&f, &[&f.asset, &p.token], &[&p.router, &p.pair]);
    }
    // A router that pays less than it reports, debits more than authorized, or misses the minimum
    // rolls everything back.
    for (behavior, min) in [(2, 46), (1, 47), (0, 48)] {
        let f = Fixture::new(COMMON, false);
        let p = pool(&f, 95, behavior);
        allow(&f, &[&p.router], &[&p.token], &OPS);
        let before = f.client().state();
        let (e, _) = swap_request(&f, &p, &[&f.asset, &p.token], 50, min);
        let result = execute(&f, &e);
        if behavior == 2 {
            assert_eq!(result, Err(Ok(AllowitWalletError::InvalidEffects)));
        } else {
            assert!(result.is_err());
        }
        assert_eq!(f.client().state(), before, "{behavior}");
        assert_eq!(
            (f.balance(), balance(&f, &p.token)),
            (1000, 0),
            "{behavior}"
        );
        assert_eq!(f.client().swap_receipt(&e.operation_id), None);
    }
}

#[test]
fn swap_and_redeem_expense_classes_are_checked() {
    let f = Fixture::new(COMMON, false);
    let p = pool(&f, 95, 0);
    allow(&f, &[&p.router], &[&p.token], &OPS);
    let invalid = Err(Ok(AllowitWalletError::InvalidInvocation));
    // A forward swap cannot lose more than its input.
    let (mut e, _) = swap_request(&f, &p, &[&f.asset, &p.token], 50, 47);
    e.expense = AllowitExpense::Priced(bounds(&f, 0, 51));
    assert_eq!(execute(&f, &e), invalid);
    // Spent units must equal conversion plus gas.
    let mut cost = bounds(&f, 0, 3);
    cost.spent_units = 50;
    let (mut e, _) = swap_request(&f, &p, &[&f.asset, &p.token], 50, 47);
    e.expense = AllowitExpense::Priced(cost.clone());
    assert_eq!(execute(&f, &e), invalid);
    let v = vault(&f, 0);
    allow(&f, &[&p.router, &v], &[&p.token], &OPS);
    let mut e = redeem_request(&f, &v, 40, 40);
    e.expense = AllowitExpense::Priced(cost);
    assert_eq!(execute(&f, &e), invalid);
    assert_eq!(f.client().state().nonce, 0);
    // Control: a redeem may count a conversion loss.
    let mut e = redeem_request(&f, &v, 40, 40);
    e.expense = AllowitExpense::Priced(bounds(&f, 0, 2));
    assert_eq!(execute(&f, &e), Ok(()));
    assert_eq!(f.history().spent, 2);
}

/// The host refused a call into a contract already on the call stack.
fn reentry_refused(env: &Env) -> bool {
    let events = env.host().get_diagnostic_events().unwrap();
    std::format!("{events:?}").contains("Contract re-entry is not allowed")
}
/// A real native authorization entry of the agent or the server for `execute(e)`.
fn signer(
    f: &Fixture,
    key: &SigningKey,
    e: &AllowitExecutionRequest,
    nonce: i64,
) -> SorobanAuthorizationEntry {
    let account = if *key == f.akey { &f.agent } else { &f.server };
    let invoke = MockAuthInvoke {
        contract: &f.wallet,
        fn_name: "execute",
        args: (e.clone(),).into_val(&f.env),
        sub_invokes: &[],
    };
    f.signed_entry(account, &invoke, nonce, &|payload| {
        let signature = AccountSignature {
            public_key: BytesN::from_array(&f.env, &key.verifying_key().to_bytes()),
            signature: BytesN::from_array(&f.env, &key.sign(&payload.to_array()).to_bytes()),
        };
        vec![&f.env, signature].into_val(&f.env)
    })
}

/// A vault that the wallet's own `execute` deposit calls cannot start an intercepted swap or
/// redeem for the wallet: the host refuses the wallet's `__check_auth` while the wallet is on the
/// call stack, and everything rolls back.
#[test]
fn a_hostile_vault_cannot_start_an_intercepted_swap_or_redeem_during_execute() {
    for swap in [true, false] {
        let f = Fixture::new(COMMON, true);
        add_account(&f.env, &f.akey);
        add_account(&f.env, &f.skey);
        let p = pool(&f, 95, 0);
        let other = vault(&f, 0);
        let hostile = vault(&f, 13);
        allow(&f, &[&p.router, &other, &hostile], &[&p.token], &OPS);
        let (mut inner, a) = swap_request(&f, &p, &[&f.asset, &p.token], 50, 47);
        inner.nonce = 1;
        inner.operation_id = BytesN::from_array(&f.env, &[9; 32]);
        let (contract, function, args, entry) = if swap {
            let entry = swap_entry(&f, &p, &inner, &a, 36);
            (
                p.router.clone(),
                "swap_exact_tokens_for_tokens",
                swap_call(&f, &a),
                entry,
            )
        } else {
            let mut inner = redeem_request(&f, &other, 40, 40);
            inner.nonce = 1;
            inner.operation_id = BytesN::from_array(&f.env, &[9; 32]);
            let entry = redeem_entry(&f, &other, &inner, 40, 36);
            (other.clone(), "redeem", redeem_call(&f, 40), entry)
        };
        AllowitSep56TestVaultClient::new(&f.env, &hostile).set_callback(
            &contract,
            &Symbol::new(&f.env, function),
            &args,
        );
        let e = deposit_request(&f, &hostile, 50);
        f.env.set_auths(&[
            signer(&f, &f.akey, &e, 34),
            signer(&f, &f.skey, &e, 35),
            entry,
        ]);
        let before = f.client().state();
        assert!(!reentry_refused(&f.env));
        assert_eq!(f.client().try_execute(&e), Err(Err(InvokeError::Abort)));
        assert!(reentry_refused(&f.env), "{swap}");
        assert_eq!(f.client().state(), before);
        assert_eq!((f.balance(), balance(&f, &p.token)), (1000, 0));
        assert_eq!(shares(&f, &other), 100);
        assert_eq!(f.history(), AllowitStandardState::default());
    }
}

#[test]
fn rule_input_carries_swap_and_redeem_facts() {
    let f = Fixture::new(COMMON, false);
    let p = pool(&f, 95, 0);
    let state = f.client().state();
    let mut e = f.execution(1);
    e.expense = AllowitExpense::Unpriced;
    e.operation = AllowitStellarOperation::Swap(AllowitSwapArgs {
        router: p.router.clone(),
        amount_in: 50,
        amount_out_min: 47,
        path: path(&f.env, &[&f.asset, &p.token]),
        deadline: 1,
    });
    let ctx = rule_input(&f.env, &state, &e);
    let r = &ctx.request;
    assert_eq!(r.operation, AllowitOperation::swap);
    assert_eq!((r.recipient.clone(), r.amount), (p.router.clone(), 50));
    assert_eq!((r.token_in.clone(), r.amount_in), (f.asset.clone(), 50));
    assert_eq!(
        (r.token_out.clone(), r.min_out),
        (Some(p.token.clone()), 47)
    );
    e.operation = AllowitStellarOperation::Swap(AllowitSwapArgs {
        router: p.router.clone(),
        amount_in: 100,
        amount_out_min: 40,
        path: path(&f.env, &[&p.token, &f.asset]),
        deadline: 1,
    });
    let ctx = rule_input(&f.env, &state, &e);
    let r = &ctx.request;
    assert_eq!(
        (r.amount, r.token_in.clone(), r.amount_in),
        (40, p.token.clone(), 100)
    );
    assert_eq!(r.token_out, Some(f.asset.clone()));
    e.operation = AllowitStellarOperation::Redeem(AllowitRedeemArgs {
        vault: p.pair.clone(),
        shares: 30,
        min_assets: 25,
    });
    let ctx = rule_input(&f.env, &state, &e);
    let r = &ctx.request;
    assert_eq!(r.operation, AllowitOperation::redeem);
    assert_eq!((r.recipient.clone(), r.amount), (p.pair.clone(), 25));
    assert_eq!((r.token_in.clone(), r.amount_in), (p.pair.clone(), 30));
    assert_eq!(
        (r.token_out.clone(), r.min_out),
        (Some(f.asset.clone()), 25)
    );
}
