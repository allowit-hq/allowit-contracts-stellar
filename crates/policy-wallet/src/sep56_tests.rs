//! Deposit tests execute compiled custody and hostile vault Wasm through the native host.
extern crate std;
use super::tests::*;
use super::*;
use allowit::{
    AllowitStandardState, CALL_LIMIT, DAILY_SPENDING_LIMIT, DAILY_VOLUME_LIMIT, DESTINATIONS,
    LIFETIME_SPENDING_LIMIT,
};
use allowit_wallet_protocol::AllowitExpense;
use soroban_sdk::{IntoVal, testutils::Address as _, vec};

use allowit_sep56_test_vault::AllowitSep56TestVaultClient;
const VAULT: &[u8] =
    include_bytes!("../../../target/wasm32v1-none/release/allowit_sep56_test_vault.wasm");

fn vault(f: &Fixture, behavior: u32, underlying: Option<Address>) -> Address {
    f.env.register(
        VAULT,
        (underlying.unwrap_or_else(|| f.asset.clone()), behavior),
    )
}
fn allow_recipient(f: &Fixture, vault: &Address) {
    if f.client().state().rules.is_empty() {
        return;
    }
    let mut d = f.deployment();
    // Common's explicitly selected recipient rule must also allow the deposit target.
    let destinations = addresses(&f.env, &[vault, &f.recipient]);
    set_param(&mut d.params, DESTINATIONS, Some(destinations));
    f.auth(&[&f.owner], "deploy_policy", (d.clone(),).into_val(&f.env));
    f.client().deploy_policy(&d);
}
fn request(
    f: &Fixture,
    vault: &Address,
    assets: i128,
    min_shares: i128,
) -> AllowitExecutionRequest {
    let mut e = f.execution(assets);
    e.expense = AllowitExpense::Priced(AllowitExpenseBounds {
        gas_units: 0,
        conversion_units: 0,
        spent_units: 0,
        max_fee_stroops: 0,
        observed_ledger: 1,
        day: f.env.ledger().timestamp() / 86_400,
    });
    e.operation = AllowitStellarOperation::Deposit(AllowitDepositArgs {
        vault: vault.clone(),
        assets,
        min_shares,
    });
    e
}
fn execute(
    f: &Fixture,
    e: &AllowitExecutionRequest,
) -> Result<
    Result<AllowitTransferReceipt, soroban_sdk::ConversionError>,
    Result<AllowitWalletError, soroban_sdk::InvokeError>,
> {
    f.auth(
        &[&f.agent, &f.server],
        "execute",
        (e.clone(),).into_val(&f.env),
    );
    f.client().try_execute(e)
}
fn assert_unchanged(
    f: &Fixture,
    vault: &Address,
    op: &BytesN<32>,
    before: &AllowitState,
    history: &AllowitStandardState,
) {
    assert_eq!(f.balance(), 1000);
    assert_eq!(
        AllowitSep56TestVaultClient::new(&f.env, vault).balance(&f.wallet),
        0
    );
    assert_eq!(f.client().state(), *before);
    assert_eq!(f.history(), *history);
    assert_eq!(f.client().deposit_receipt(op), None);
    // The replay marker written with the state rolled back too.
    let marker = Key::Operation(op.clone());
    assert!(
        !f.env
            .as_contract(&f.wallet, || f.env.storage().persistent().has(&marker))
    );
}

#[test]
fn deposit_compiled_simple_and_common_wallets_bind_and_retain_actual_effects() {
    for wasm in [SIMPLE, COMMON] {
        let f = Fixture::new(wasm, false);
        let vault = vault(&f, 0, None);
        allow_recipient(&f, &vault);
        let e = request(&f, &vault, 50, 50);
        let binding = f.client().policy_binding();
        assert!(binding.operations.contains(AllowitOperation::deposit));
        let receipt = execute(&f, &e).unwrap().unwrap();
        assert_eq!(receipt.amount, 50);
        assert_eq!(receipt.to, vault);
        assert_eq!(f.balance(), 950);
        assert_eq!(
            AllowitSep56TestVaultClient::new(&f.env, &vault).balance(&f.wallet),
            50
        );
        let deposited = f.client().deposit_receipt(&e.operation_id).unwrap();
        assert_eq!(deposited.assets, 50);
        assert_eq!(deposited.shares, 50);
        assert_eq!(deposited.vault, vault);
        assert_eq!(deposited.asset, f.asset);
        assert_eq!(deposited.receiver, f.wallet);
        assert_eq!(f.client().state().nonce, 1);
        assert_eq!(f.history().spent, 0);
        assert_eq!(f.history().day_spent, 0);
        assert_eq!(f.history().day_total, 50);
        assert_eq!(f.history().calls, 1);
        assert_eq!(execute(&f, &e), Err(Ok(AllowitWalletError::Replay)));
        assert_eq!(f.balance(), 950);
        assert_eq!(f.client().deposit_receipt(&e.operation_id), Some(deposited));
    }
}

#[test]
fn deposit_vault_target_is_controlled_only_by_authored_recipient_rule() {
    let f = Fixture::new(COMMON, false);
    let vault = vault(&f, 0, None);
    let e = request(&f, &vault, 50, 50);
    assert_eq!(execute(&f, &e), Err(Ok(AllowitWalletError::PolicyDenied)));
    assert_eq!(f.balance(), 1000);
    assert_eq!(f.client().state().nonce, 0);
    allow_recipient(&f, &vault);
    let e = request(&f, &vault, 50, 50);
    assert!(execute(&f, &e).is_ok());
}

#[test]
fn deposit_rejects_the_wallet_or_its_asset_as_vault_and_nonpositive_bounds() {
    let f = Fixture::new(SIMPLE, false);
    let vault = vault(&f, 0, None);
    allow_recipient(&f, &vault);
    // The wallet is never its own vault, and the wallet asset is never a vault.
    for target in [&f.wallet, &f.asset] {
        assert_eq!(
            execute(&f, &request(&f, target, 50, 50)),
            Err(Ok(AllowitWalletError::InvalidInvocation))
        );
    }
    for (assets, shares) in [(0, 1), (-1, 1), (1, 0), (1, -1)] {
        assert_eq!(
            execute(&f, &request(&f, &vault, assets, shares)),
            Err(Ok(AllowitWalletError::InvalidAmount))
        );
    }
    assert_eq!(f.balance(), 1000);
    assert_eq!(f.client().state().nonce, 0);
}

#[test]
fn deposit_wrong_asset_under_mint_and_lied_credit_roll_back_everything() {
    for behavior in [1, 2] {
        let f = Fixture::new(COMMON, false);
        let vault = vault(&f, behavior, None);
        allow_recipient(&f, &vault);
        let e = request(&f, &vault, 50, 50);
        let before = f.client().state();
        let spent = f.history();
        assert_eq!(execute(&f, &e), Err(Ok(AllowitWalletError::InvalidEffects)));
        assert_unchanged(&f, &vault, &e.operation_id, &before, &spent);
    }
    let f = Fixture::new(COMMON, false);
    let wrong = f
        .env
        .register_stellar_asset_contract_v2(Address::generate(&f.env))
        .address();
    let vault = vault(&f, 0, Some(wrong));
    allow_recipient(&f, &vault);
    let e = request(&f, &vault, 50, 50);
    let before = f.client().state();
    let spent = f.history();
    assert_eq!(
        execute(&f, &e),
        Err(Ok(AllowitWalletError::UnsupportedAsset))
    );
    assert_unchanged(&f, &vault, &e.operation_id, &before, &spent);
}

#[test]
fn deposit_under_mint_within_the_valuation_bound_still_requires_min_shares() {
    let f = Fixture::new(COMMON, false);
    let vault = vault(&f, 1, None);
    allow_recipient(&f, &vault);
    // One unit of conversion cost admits the vault's valuation of 49 shares; min_shares does not.
    let mut e = request(&f, &vault, 50, 50);
    set_cost(&f, &mut e, 0, 1);
    let before = f.client().state();
    let spent = f.history();
    assert_eq!(execute(&f, &e), Err(Ok(AllowitWalletError::InvalidEffects)));
    assert_unchanged(&f, &vault, &e.operation_id, &before, &spent);
    let mut e = request(&f, &vault, 50, 49);
    set_cost(&f, &mut e, 0, 1);
    assert_eq!(execute(&f, &e).unwrap().unwrap().amount, 50);
}

#[test]
fn deposit_exact_nested_authorization_rejects_extra_debit_short_debit_and_allowance() {
    for behavior in [3, 4, 5, 7] {
        let f = Fixture::new(COMMON, false);
        let vault = vault(&f, behavior, None);
        allow_recipient(&f, &vault);
        let e = request(&f, &vault, 50, 50);
        let before = f.client().state();
        let spent = f.history();
        assert!(execute(&f, &e).is_err());
        assert_unchanged(&f, &vault, &e.operation_id, &before, &spent);
    }
}

/// The wallet holds no token allowance for any of `spenders`.
fn assert_no_allowance(f: &Fixture, spenders: &[&Address], step: &str) {
    let token = token::Client::new(&f.env, &f.asset);
    for spender in [
        &f.recipient,
        &f.agent,
        &f.server,
        &f.owner,
        &f.asset,
        &f.wallet,
    ]
    .into_iter()
    .chain(spenders.iter().copied())
    {
        assert_eq!(token.allowance(&f.wallet, spender), 0, "{step}");
    }
}

/// Custody authorizes one exact transfer per operation and never approves a spender, so no
/// operation leaves a token allowance: not a transfer, an x402 transfer or a deposit, and not a
/// deposit into a vault that tries to approve itself.
#[test]
fn no_operation_leaves_the_wallet_a_token_allowance() {
    for wasm in [SIMPLE, COMMON, CUSTOM] {
        let f = Fixture::new(wasm, false);
        let honest = vault(&f, 0, None);
        let approving = vault(&f, 5, None);
        let vaults = [&honest, &approving];
        assert_no_allowance(&f, &vaults, "before");
        f.transfer(10);
        assert_no_allowance(&f, &vaults, "transfer");
        // Custom admits no deposit.
        if wasm != CUSTOM {
            allow_destinations(&f, &[&honest, &approving, &f.recipient]);
            assert!(execute(&f, &request(&f, &honest, 50, 50)).is_ok());
            assert_no_allowance(&f, &vaults, "deposit");
            assert!(execute(&f, &request(&f, &approving, 50, 50)).is_err());
            assert_no_allowance(&f, &vaults, "approving vault");
        }
        // The x402 hook authorizes the agent's SAC transfer with native signatures.
        let x402 = Fixture::new(wasm, true);
        x402.env
            .set_auths(&[x402.host_entry(x402.execution(10), 10, 1)]);
        token::Client::new(&x402.env, &x402.asset).transfer(&x402.wallet, &x402.recipient, &10);
        assert_eq!(x402.client().state().nonce, 1);
        assert_no_allowance(&x402, &[], "x402 transfer");
    }
}

#[test]
fn custom_policy_runs_no_deposit() {
    let f = Fixture::new(CUSTOM, false);
    let vault = vault(&f, 0, None);
    allow_recipient(&f, &vault);
    let e = request(&f, &vault, 50, 50);
    assert_eq!(
        execute(&f, &e),
        Err(Ok(AllowitWalletError::UnsupportedOperation))
    );
    let operations = f.client().policy_binding().operations;
    assert!(!operations.contains(AllowitOperation::deposit));
    assert_eq!(f.balance(), 1000);
}

#[test]
fn deposit_vault_upgrade_cannot_hide_inconsistent_effects_and_rolls_back_all_usage() {
    let f = Fixture::new(COMMON, false);
    let vault = vault(&f, 8, None);
    allow_recipient(&f, &vault);
    let original_code = vault.executable();
    let hash = f
        .env
        .deployer()
        .upload_contract_wasm(Bytes::from_slice(&f.env, SIMPLE));
    AllowitSep56TestVaultClient::new(&f.env, &vault).set_upgrade(&hash);
    let e = request(&f, &vault, 50, 50);
    let before = f.client().state();
    let spent = f.history();
    assert!(execute(&f, &e).is_err());
    assert_eq!(vault.executable(), original_code);
    assert_unchanged(&f, &vault, &e.operation_id, &before, &spent);
}

#[test]
fn rule_input_carries_typed_operations_and_the_vault_as_recipient() {
    let f = Fixture::new(COMMON, false);
    let vault = vault(&f, 0, None);
    let state = f.client().state();
    let deposit = AllowitStellarOperation::Deposit(AllowitDepositArgs {
        vault: vault.clone(),
        assets: 5,
        min_shares: 5,
    });
    let expense = AllowitExpenseBounds {
        gas_units: 2,
        conversion_units: 1,
        spent_units: 3,
        max_fee_stroops: 2,
        observed_ledger: 1,
        day: 1,
    };
    let mut e = f.execution(5);
    e.expires_at = 86_500;
    e.operation = deposit;
    e.expense = AllowitExpense::Priced(expense);
    set_param(&mut e.args, "invoice", Some(AllowitValue::Int(7)));
    let ctx = rule_input(&f.env, &state, &e);
    assert_eq!((ctx.request.now, ctx.request.expires_at), (86_410, 86_500));
    assert_eq!(ctx.request.operation, AllowitOperation::deposit);
    assert_eq!(ctx.request.recipient, vault);
    assert_eq!(ctx.request.asset, f.asset);
    assert_eq!(ctx.request.amount, 5);
    assert_eq!((ctx.request.spent_units, ctx.request.gas_units), (3, 2));
    assert!(!ctx.request.unpriced);
    assert_eq!(ctx.state, state.policy_state);
    assert_eq!(ctx.params.0, state.params);
    assert_eq!(ctx.request.args.0, e.args);
    e.expense = AllowitExpense::Unpriced;
    let unpriced = rule_input(&f.env, &state, &e);
    assert!(unpriced.request.unpriced);
    assert_eq!(
        (unpriced.request.spent_units, unpriced.request.gas_units),
        (0, 0)
    );
    assert_eq!(
        f.execution(1).operation.to_core(),
        AllowitOperation::transfer
    );
}

#[test]
fn ordinary_recipient_allowlist_admits_multiple_vaults_and_denies_other_targets() {
    let f = Fixture::new(COMMON, false);
    let a = vault(&f, 0, None);
    let b = vault(&f, 0, None);
    let denied = vault(&f, 0, None);
    let mut d = f.deployment();
    set_param(
        &mut d.params,
        DESTINATIONS,
        Some(addresses(&f.env, &[&a, &b])),
    );
    f.auth(&[&f.owner], "deploy_policy", (d.clone(),).into_val(&f.env));
    f.client().deploy_policy(&d);
    for target in [&a, &b] {
        assert!(execute(&f, &request(&f, target, 40, 40)).is_ok());
    }
    let e = request(&f, &denied, 40, 40);
    assert_eq!(execute(&f, &e), Err(Ok(AllowitWalletError::PolicyDenied)));
    assert_eq!(f.balance(), 920);
    assert_eq!(f.client().state().nonce, 2);
    assert_eq!(f.history().day_total, 80);
    assert_eq!(f.client().deposit_receipt(&e.operation_id), None);
}

fn set_cost(f: &Fixture, e: &mut AllowitExecutionRequest, gas: i128, conversion: i128) {
    let principal = match &e.operation {
        AllowitStellarOperation::Transfer(args) => args.amount,
        _ => conversion,
    };
    e.expense = AllowitExpense::Priced(AllowitExpenseBounds {
        gas_units: gas,
        conversion_units: conversion,
        spent_units: principal + gas,
        max_fee_stroops: u32::try_from(gas).unwrap(),
        observed_ledger: 100,
        day: f.env.ledger().timestamp() / 86400,
    });
}
#[test]
fn native_xlm_expense_caps_separate_deposit_principal_from_costs_and_daily_total() {
    let f = Fixture::new_native(COMMON);
    let v = vault(&f, 11, None);
    allow_recipient(&f, &v);
    let mut e = request(&f, &v, 50, 50);
    set_cost(&f, &mut e, 3, 2);
    assert!(execute(&f, &e).is_ok());
    assert_eq!(f.history().spent, 5);
    assert_eq!(f.history().day_spent, 5);
    assert_eq!(f.history().day_total, 53);
    assert_eq!(f.balance(), 950);
    assert_eq!(
        f.client().deposit_receipt(&e.operation_id).unwrap().shares,
        50
    );
    // A payment spends principal as well as its attributable gas ceiling.
    let f = Fixture::new_native(COMMON);
    let mut e = f.execution(50);
    set_cost(&f, &mut e, 3, 0);
    assert!(execute(&f, &e).is_ok());
    assert_eq!(f.history().spent, 53);
    assert_eq!(f.history().day_total, 53);
}
#[test]
fn expense_and_gross_cap_denials_and_valuation_bound_roll_back_atomic_effects() {
    for (field, limit) in [(0, 4i128), (1, 4), (2, 52)] {
        let f = Fixture::new_native(COMMON);
        let v = vault(&f, 11, None);
        allow_recipient(&f, &v);
        let mut d = f.deployment();
        let key = [
            LIFETIME_SPENDING_LIMIT,
            DAILY_SPENDING_LIMIT,
            DAILY_VOLUME_LIMIT,
        ][field];
        set_param(&mut d.params, key, Some(AllowitValue::Int(limit)));
        f.auth(&[&f.owner], "deploy_policy", (d.clone(),).into_val(&f.env));
        f.client().deploy_policy(&d);
        let mut e = request(&f, &v, 50, 50);
        set_cost(&f, &mut e, 3, 2);
        let before = f.client().state();
        let spent = f.history();
        assert_eq!(execute(&f, &e), Err(Ok(AllowitWalletError::PolicyDenied)));
        assert_unchanged(&f, &v, &e.operation_id, &before, &spent);
    }
    // A preview of `i128::MIN` exceeds the bound without overflow.
    for (behavior, conversion) in [(11, 1), (12, 0), (14, 0)] {
        let f = Fixture::new_native(COMMON);
        let v = vault(&f, behavior, None);
        allow_recipient(&f, &v);
        let mut e = request(&f, &v, 50, 50);
        set_cost(&f, &mut e, 3, conversion);
        let before = f.client().state();
        let spent = f.history();
        assert_eq!(execute(&f, &e), Err(Ok(AllowitWalletError::InvalidEffects)));
        assert_unchanged(&f, &v, &e.operation_id, &before, &spent);
    }
}
#[test]
fn economic_class_gas_and_observation_facts_cannot_be_forged() {
    let f = Fixture::new_native(COMMON);
    for mutation in 0..5 {
        let mut e = f.execution(50);
        set_cost(&f, &mut e, 3, 0);
        let mut c = e.expense.bounds().unwrap().clone();
        match mutation {
            0 => {
                c.conversion_units = 1;
                c.spent_units = 4;
            } // Ordinary payment cannot claim swap classification.
            1 => c.spent_units = 1,
            2 => c.gas_units = 2,
            3 => c.day += 1,
            _ => c.observed_ledger = 101,
        }
        e.expense = AllowitExpense::Priced(c);
        assert_eq!(
            execute(&f, &e),
            Err(Ok(AllowitWalletError::InvalidInvocation))
        );
        assert_eq!(f.balance(), 1000);
        assert_eq!(f.client().state().nonce, 0);
    }
}
#[test]
fn standard_prefix_digest_hashes_its_documented_tuple_and_binds_context() {
    use soroban_sdk::xdr::{Limits, ScAddress, ScVal, WriteXdr};
    let env = Env::default();
    let kind = Symbol::new(&env, "common_policy_engine");
    let module = BytesN::from_array(&env, &[1; 32]);
    let asset = Address::from_str(
        &env,
        "CABAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAFNSZ",
    );
    let rules = vec![
        &env,
        AllowitRule::lifetime_spending_limit,
        AllowitRule::destinations,
    ];
    // The documented definition, built from raw XDR values: SHA-256 of the vector (domain, kind,
    // module, asset, rules), where each rule is a one-symbol vector of its name.
    let symbol = |name: &str| ScVal::Symbol(name.try_into().unwrap());
    let list = |items: std::vec::Vec<ScVal>| ScVal::Vec(Some(items.try_into().unwrap()));
    let tuple = list(std::vec![
        symbol("allowit_std_prefix"),
        symbol("common_policy_engine"),
        ScVal::Bytes([1u8; 32].to_vec().try_into().unwrap()),
        ScVal::Address(ScAddress::from(&asset)),
        list(std::vec![
            list(std::vec![symbol("lifetime_spending_limit")]),
            list(std::vec![symbol("destinations")]),
        ]),
    ]);
    let encoded = WriteXdr::to_xdr(&tuple, Limits::none()).unwrap();
    let expected = env
        .crypto()
        .sha256(&Bytes::from_slice(&env, &encoded))
        .to_bytes();
    assert_eq!(
        standard_prefix_digest(&env, &kind, &module, &asset, &rules),
        expected
    );
    let reversed = vec![
        &env,
        AllowitRule::destinations,
        AllowitRule::lifetime_spending_limit,
    ];
    assert_ne!(
        standard_prefix_digest(&env, &kind, &module, &asset, &reversed),
        expected
    );
    assert_ne!(
        standard_prefix_digest(
            &env,
            &kind,
            &BytesN::from_array(&env, &[3; 32]),
            &asset,
            &rules
        ),
        expected
    );
    assert_ne!(
        standard_prefix_digest(&env, &kind, &module, &Address::generate(&env), &rules),
        expected
    );
}
#[test]
fn owner_params_update_preserves_prefix_code_usage_and_revokes_old_revision() {
    let f = Fixture::new(COMMON, false);
    f.transfer(50);
    let original = f.client().state();
    let code = f.wallet.executable();
    let inflight = f.execution(1);
    let mut d = f.deployment();
    set_param(&mut d.params, LIFETIME_SPENDING_LIMIT, None);
    set_param(&mut d.params, DAILY_SPENDING_LIMIT, None);
    f.auth(&[&f.owner], "deploy_policy", (d.clone(),).into_val(&f.env));
    f.client().deploy_policy(&d);
    assert_eq!(f.wallet.executable(), code);
    assert_eq!(f.client().state().source_digest, original.source_digest);
    assert_eq!(f.client().state().nonce, original.nonce);
    assert_eq!(
        execute(&f, &inflight),
        Err(Ok(AllowitWalletError::StaleRequest))
    );
    f.transfer(20);
    // Protected history counts every success, including those while a cap was unset.
    assert_eq!(f.history().spent, 70);
    assert_eq!(f.history().day_spent, 70);
    assert_eq!(f.history().day_total, 70);
    assert_eq!(f.history().calls, 2);
    let mut d = f.deployment();
    set_param(
        &mut d.params,
        LIFETIME_SPENDING_LIMIT,
        Some(AllowitValue::Int(75)),
    );
    set_param(
        &mut d.params,
        DAILY_SPENDING_LIMIT,
        Some(AllowitValue::Int(75)),
    );
    f.auth(&[&f.owner], "deploy_policy", (d.clone(),).into_val(&f.env));
    f.client().deploy_policy(&d);
    let next = f.execution(6);
    assert_eq!(
        execute(&f, &next),
        Err(Ok(AllowitWalletError::PolicyDenied))
    );
    assert_eq!(f.balance(), 930);
    assert_eq!(f.history().spent, 70);
    assert_eq!(f.client().state().nonce, 2);
    assert_eq!(f.client().state().source_digest, original.source_digest);
}

#[test]
fn disabled_caps_keep_unpriced_history_and_daily_unknown_expires_only_at_rollover() {
    use soroban_sdk::testutils::Ledger;
    let f = Fixture::new(COMMON, false);
    let mut d = f.deployment();
    set_param(&mut d.params, LIFETIME_SPENDING_LIMIT, None);
    set_param(&mut d.params, DAILY_SPENDING_LIMIT, None);
    set_param(&mut d.params, DAILY_VOLUME_LIMIT, None);
    set_param(&mut d.params, CALL_LIMIT, None);
    f.auth(&[&f.owner], "deploy_policy", (d.clone(),).into_val(&f.env));
    f.client().deploy_policy(&d);
    let mut e = f.execution(20);
    e.expense = AllowitExpense::Unpriced;
    execute(&f, &e).unwrap().unwrap();
    let history = f.history();
    assert_eq!(history.calls, 1);
    assert_eq!(history.day_total, 20);
    assert_eq!(history.spent, 0); // Unpriced is an explicit liability, never a zero-cost assertion.
    assert!(history.unpriced && history.day_unpriced);
    let mut d = f.deployment();
    set_param(
        &mut d.params,
        LIFETIME_SPENDING_LIMIT,
        Some(AllowitValue::Int(1000)),
    );
    f.auth(&[&f.owner], "deploy_policy", (d.clone(),).into_val(&f.env));
    f.client().deploy_policy(&d);
    assert_eq!(
        execute(&f, &f.execution(1)),
        Err(Ok(AllowitWalletError::PolicyDenied))
    );
    assert_eq!(f.history(), history);
    let mut d = f.deployment();
    set_param(&mut d.params, LIFETIME_SPENDING_LIMIT, None);
    set_param(
        &mut d.params,
        DAILY_SPENDING_LIMIT,
        Some(AllowitValue::Int(1000)),
    );
    set_param(
        &mut d.params,
        DAILY_VOLUME_LIMIT,
        Some(AllowitValue::Int(1000)),
    );
    f.auth(&[&f.owner], "deploy_policy", (d.clone(),).into_val(&f.env));
    f.client().deploy_policy(&d);
    assert_eq!(
        execute(&f, &f.execution(1)),
        Err(Ok(AllowitWalletError::PolicyDenied))
    );
    f.env.ledger().with_mut(|l| l.timestamp += 86_400);
    execute(&f, &f.execution(1)).unwrap().unwrap();
    let history = f.history();
    assert_eq!(history.calls, 2);
    assert_eq!(history.day_total, 1);
    assert_eq!(history.day_spent, 1);
    assert!(!history.day_unpriced && history.unpriced);
}
#[test]
fn reenabled_call_limit_counts_operations_while_disabled() {
    let f = Fixture::new(COMMON, false);
    let mut d = f.deployment();
    set_param(&mut d.params, CALL_LIMIT, None);
    f.auth(&[&f.owner], "deploy_policy", (d.clone(),).into_val(&f.env));
    f.client().deploy_policy(&d);
    f.transfer(1);
    f.transfer(1);
    let mut d = f.deployment();
    set_param(&mut d.params, CALL_LIMIT, Some(AllowitValue::Int(2)));
    f.auth(&[&f.owner], "deploy_policy", (d.clone(),).into_val(&f.env));
    f.client().deploy_policy(&d);
    assert_eq!(
        execute(&f, &f.execution(1)),
        Err(Ok(AllowitWalletError::PolicyDenied))
    );
    assert_eq!(f.history().calls, 2);
}

#[test]
fn issued_asset_normalized_gas_is_signed_and_keeps_native_amount_checks() {
    let f = Fixture::new(COMMON, false);
    let v = vault(&f, 11, None);
    allow_recipient(&f, &v);
    let mut e = request(&f, &v, 50, 50);
    set_cost(&f, &mut e, 3, 2);
    let mut cost = e.expense.bounds().unwrap().clone();
    cost.max_fee_stroops = 100;
    e.expense = AllowitExpense::Priced(cost);
    assert!(execute(&f, &e).is_ok());
    assert_eq!(f.history().spent, 5);
    assert_eq!(f.history().day_total, 53);
    assert_eq!(f.balance(), 950);
    for mutation in 0..3 {
        let f = Fixture::new(COMMON, false);
        let mut e = f.execution(50);
        set_cost(&f, &mut e, 3, 0);
        let mut cost = e.expense.bounds().unwrap().clone();
        cost.max_fee_stroops = 100;
        match mutation {
            0 => cost.gas_units = -1,
            1 => cost.gas_units = 0,
            _ => cost.max_fee_stroops = 0,
        };
        e.expense = AllowitExpense::Priced(cost);
        assert_eq!(
            execute(&f, &e),
            Err(Ok(AllowitWalletError::InvalidInvocation))
        );
        assert_eq!(f.balance(), 1000);
        assert_eq!(f.client().state().nonce, 0);
    }
    for missing_server in [false, true] {
        let f = Fixture::new(COMMON, false);
        let mut e = f.execution(50);
        set_cost(&f, &mut e, 3, 0);
        let mut cost = e.expense.bounds().unwrap().clone();
        cost.max_fee_stroops = 100;
        e.expense = AllowitExpense::Priced(cost);
        f.auth(
            &[if missing_server { &f.agent } else { &f.server }],
            "execute",
            (e.clone(),).into_val(&f.env),
        );
        assert!(f.client().try_execute(&e).is_err());
        assert_eq!(f.balance(), 1000);
        assert_eq!(f.client().state().nonce, 0);
    }
}

/// The host refused a call into a contract already on the call stack.
fn reentry_refused(env: &Env) -> bool {
    let events = env.host().get_diagnostic_events().unwrap();
    std::format!("{events:?}").contains("Contract re-entry is not allowed")
}

/// Install `destinations` as the `destinations` param through an owner packet.
fn allow_destinations(f: &Fixture, destinations: &[&Address]) {
    let mut d = f.deployment();
    set_param(
        &mut d.params,
        DESTINATIONS,
        Some(addresses(&f.env, destinations)),
    );
    f.auth(&[&f.owner], "deploy_policy", (d.clone(),).into_val(&f.env));
    f.client().deploy_policy(&d);
}

#[test]
fn reentrant_vault_cannot_call_execute_back_and_the_operation_rolls_back() {
    // Control: a harmless callback leaves the deposit valid.
    let f = Fixture::new(COMMON, false);
    let v = vault(&f, 13, None);
    allow_recipient(&f, &v);
    let callback = AllowitSep56TestVaultClient::new(&f.env, &v);
    callback.set_callback(
        &f.asset,
        &Symbol::new(&f.env, "decimals"),
        &Vec::new(&f.env),
    );
    assert!(execute(&f, &request(&f, &v, 50, 50)).is_ok());
    // The vault calls `execute` back with a request that would be the valid next one.
    let f = Fixture::new(COMMON, false);
    let v = vault(&f, 13, None);
    allow_recipient(&f, &v);
    let e = request(&f, &v, 50, 50);
    let mut inner = f.execution(10);
    inner.nonce = 1;
    inner.operation_id = BytesN::from_array(&f.env, &[7; 32]);
    let callback = AllowitSep56TestVaultClient::new(&f.env, &v);
    let args: Vec<Val> = (inner.clone(),).into_val(&f.env);
    callback.set_callback(&f.wallet, &Symbol::new(&f.env, "execute"), &args);
    let before = f.client().state();
    let spent = f.history();
    // Authorization never decides this case: every signer is mocked.
    f.env.mock_all_auths_allowing_non_root_auth();
    assert_eq!(
        f.client().try_execute(&e),
        Err(Err(soroban_sdk::InvokeError::Abort))
    );
    assert!(reentry_refused(&f.env));
    f.env.mock_auths(&[]);
    assert_unchanged(&f, &v, &e.operation_id, &before, &spent);
    assert_eq!(f.client().deposit_receipt(&inner.operation_id), None);
}

#[test]
fn reentrant_vault_cannot_use_the_x402_path_during_an_operation() {
    use soroban_sdk::testutils::MockAuthInvoke;
    let f = Fixture::new(COMMON, true);
    add_account(&f.env, &f.akey);
    add_account(&f.env, &f.skey);
    let hostile = vault(&f, 13, None);
    let honest = vault(&f, 0, None);
    allow_destinations(&f, &[&hostile, &honest, &f.recipient]);
    // The hostile vault pulls one more unit from the wallet through the token, which asks the
    // wallet's x402 `__check_auth` for an agent and server approval.
    let pull_args: Vec<Val> = (f.wallet.clone(), hostile.clone(), 1i128).into_val(&f.env);
    AllowitSep56TestVaultClient::new(&f.env, &hostile).set_callback(
        &f.asset,
        &Symbol::new(&f.env, "transfer"),
        &pull_args,
    );
    let pull = MockAuthInvoke {
        contract: &f.asset,
        fn_name: "transfer",
        args: pull_args.clone(),
        sub_invokes: &[],
    };
    let x402 = |id: u8, nonce: i64| {
        let (mut approval, _) = x402_request(&f, &hostile, 1);
        approval.operation_id = BytesN::from_array(&f.env, &[id; 32]);
        f.signed_entry(&f.wallet, &pull, nonce, &|payload| {
            f.authorization(approval.clone(), payload).into_val(&f.env)
        })
    };
    let signer = |key: &ed25519_dalek::SigningKey, e: &AllowitExecutionRequest, nonce: i64| {
        let account = if *key == f.akey { &f.agent } else { &f.server };
        use ed25519_dalek::Signer;
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
    };
    // Control: the x402 approval alone authorizes the pull.
    f.env.set_auths(&[x402(9, 31)]);
    token::Client::new(&f.env, &f.asset).transfer(&f.wallet, &hostile, &1);
    assert_eq!((f.balance(), f.client().state().nonce), (999, 1));
    // Control: real agent and server entries authorize a deposit into an honest vault.
    let e = request(&f, &honest, 50, 50);
    f.env
        .set_auths(&[signer(&f.akey, &e, 32), signer(&f.skey, &e, 33)]);
    assert!(f.client().try_execute(&e).is_ok());
    assert_eq!((f.balance(), f.client().state().nonce), (949, 2));
    // The same signers and a fresh x402 approval for the pull cannot reenter the wallet while its
    // deposit into the hostile vault runs. Everything rolls back.
    let e = request(&f, &hostile, 50, 50);
    f.env.set_auths(&[
        signer(&f.akey, &e, 34),
        signer(&f.skey, &e, 35),
        x402(10, 36),
    ]);
    let before = f.client().state();
    assert!(!reentry_refused(&f.env));
    assert_eq!(
        f.client().try_execute(&e),
        Err(Err(soroban_sdk::InvokeError::Abort))
    );
    assert!(reentry_refused(&f.env));
    assert_eq!(f.client().state(), before);
    assert_eq!(f.balance(), 949);
    assert_eq!(f.client().deposit_receipt(&e.operation_id), None);
    let shares = AllowitSep56TestVaultClient::new(&f.env, &hostile).balance(&f.wallet);
    assert_eq!(shares, 0);
}

#[test]
fn deposit_effect_failure_after_the_state_write_rolls_back_state_nonce_and_replay_marker() {
    // The vault values the minted shares two units low; the conversion bound admits one.
    let f = Fixture::new_native(COMMON);
    let v = vault(&f, 11, None);
    allow_recipient(&f, &v);
    let mut e = request(&f, &v, 50, 50);
    set_cost(&f, &mut e, 3, 1);
    let before = f.client().state();
    let spent = f.history();
    assert_eq!(execute(&f, &e), Err(Ok(AllowitWalletError::InvalidEffects)));
    assert_unchanged(&f, &v, &e.operation_id, &before, &spent);
    // The same operation then runs once with an honest bound.
    let mut e2 = request(&f, &v, 50, 50);
    e2.operation_id = e.operation_id.clone();
    set_cost(&f, &mut e2, 3, 2);
    assert!(execute(&f, &e2).is_ok());
    assert_eq!(f.history().calls, 1);
    assert_eq!(f.client().state().nonce, 1);
}

/// Run `admit` alone, as `execute` does before any token or vault call, and check that it
/// already stored post-flight state, the next nonce and the replay marker without moving funds.
fn admit_stores_before_effects<P: AllowitPolicy>(wasm: &[u8]) {
    let f = Fixture::new(wasm, false);
    let v = vault(&f, 0, None);
    allow_recipient(&f, &v);
    let shares = AllowitSep56TestVaultClient::new(&f.env, &v);
    for i in 0..2 {
        let e = if i == 0 {
            f.execution(10)
        } else {
            request(&f, &v, 50, 50)
        };
        let before = f.client().state();
        f.env.as_contract(&f.wallet, || {
            let state = state(&f.env).unwrap();
            validate_operation(&f.env, &e, &state).unwrap();
            let ctx = rule_input(&f.env, &state, &e);
            let want = allowit::post_flight(&ctx, AllowitTier::Standard).unwrap();
            admit::<P>(&f.env, &e, state).unwrap();
            let stored = load(&f.env, None).unwrap();
            assert_eq!(stored.policy_state, want);
            assert_eq!(stored.nonce, before.nonce + 1);
            let marker = Key::Operation(e.operation_id.clone());
            assert!(f.env.storage().persistent().has(&marker));
        });
        // No token or vault call has run yet.
        assert_eq!(f.balance(), 1000, "{i}");
        assert_eq!(shares.balance(&f.wallet), 0, "{i}");
        assert_eq!(f.history().calls, before.nonce + 1, "{i}");
    }
}

#[test]
fn admit_writes_post_flight_state_nonce_and_replay_marker_before_any_external_call() {
    admit_stores_before_effects::<AllowitSimple>(SIMPLE);
    admit_stores_before_effects::<AllowitCommon>(COMMON);
}

#[test]
fn policy_and_kernel_denials_win_over_failing_effects_because_admission_runs_first() {
    let f = Fixture::new(COMMON, false);
    // The wrong-asset vault fails its first effect check; the wallet cannot fund 5000.
    let v = vault(&f, 0, Some(f.recipient.clone()));
    let before = f.client().state();
    assert_eq!(
        execute(&f, &request(&f, &v, 50, 50)),
        Err(Ok(AllowitWalletError::PolicyDenied))
    );
    assert_eq!(
        execute(&f, &f.execution(5000)),
        Err(Ok(AllowitWalletError::PolicyDenied))
    );
    assert_eq!(f.client().state(), before);
    // Control: once the recipient rule admits the vault, its effect fails on its own.
    allow_recipient(&f, &v);
    assert_eq!(
        execute(&f, &request(&f, &v, 50, 50)),
        Err(Ok(AllowitWalletError::UnsupportedAsset))
    );
    // Simple has no rules: a kernel denial still wins over the unfunded transfer.
    let f = Fixture::new(SIMPLE, false);
    let mut stale = f.execution(5000);
    stale.nonce += 1;
    assert_eq!(
        execute(&f, &stale),
        Err(Ok(AllowitWalletError::StaleRequest))
    );
    // Control: admitted, the same transfer fails on its own.
    assert_eq!(
        execute(&f, &f.execution(5000)),
        Err(Ok(AllowitWalletError::InsufficientFunds))
    );
}

/// Native SEP-56 vault that records, at the wallet's first external call, whether the wallet's
/// replay marker is already stored and the wallet's asset balance, then deposits honestly.
#[soroban_sdk::contract]
struct AllowitOrderProbe;
/// Probe configuration: underlying asset, observed wallet and observed operation.
type ProbeConfig = (Address, Address, BytesN<32>);
#[soroban_sdk::contractimpl]
impl AllowitOrderProbe {
    /// Fix the underlying asset, the wallet and the operation to observe.
    pub fn __constructor(env: Env, asset: Address, wallet: Address, operation_id: BytesN<32>) {
        env.storage()
            .instance()
            .set(&0u32, &(asset, wallet, operation_id));
    }
    /// The underlying asset. The first call, the wallet's first external call of a deposit,
    /// records the observation.
    pub fn query_asset(env: Env) -> Address {
        let (asset, wallet, operation): ProbeConfig = env.storage().instance().get(&0u32).unwrap();
        if !env.storage().instance().has(&1u32) {
            let marker = Key::Operation(operation);
            let stored = env.as_contract(&wallet, || env.storage().persistent().has(&marker));
            let funds = token::Client::new(&env, &asset).balance(&wallet);
            env.storage().instance().set(&1u32, &(stored, funds));
        }
        asset
    }
    /// The first call's observation: replay marker stored, and the wallet's asset balance.
    pub fn observed(env: Env) -> (bool, i128) {
        env.storage().instance().get(&1u32).unwrap()
    }
    /// Pull `assets` from `from` under its delegated authorization and credit equal shares.
    pub fn deposit(env: Env, assets: i128, receiver: Address, from: Address, _op: Address) -> i128 {
        let (asset, _, _): ProbeConfig = env.storage().instance().get(&0u32).unwrap();
        let vault = env.current_contract_address();
        token::Client::new(&env, &asset).transfer(&from, &vault, &assets);
        let shares = Self::balance(env.clone(), receiver.clone()) + assets;
        env.storage().instance().set(&receiver, &shares);
        assets
    }
    /// Share balance of `id`.
    pub fn balance(env: Env, id: Address) -> i128 {
        env.storage().instance().get(&id).unwrap_or(0)
    }
    /// Shares redeem one to one.
    pub fn preview_redeem(_env: Env, shares: i128) -> i128 {
        shares
    }
}

/// The order seen from outside: when the wallet first calls out, the replay marker is already
/// stored and no funds have moved. The probe sees only the persistent marker, because the host
/// writes the wallet's instance storage, which holds the state and nonce, when its frame exits.
/// `admit_stores_before_effects` pins that the state and nonce are stored before any effect; the
/// two tests together catch a mutant that moves either write after an external call.
#[test]
fn the_first_external_call_sees_admission_stored_and_no_funds_moved() {
    for wasm in [SIMPLE, COMMON] {
        let f = Fixture::new(wasm, false);
        let operation = f.execution(50).operation_id;
        let probe = f.env.register(
            AllowitOrderProbe,
            (f.asset.clone(), f.wallet.clone(), operation),
        );
        allow_recipient(&f, &probe);
        let e = request(&f, &probe, 50, 50);
        assert!(execute(&f, &e).is_ok());
        let observed = AllowitOrderProbeClient::new(&f.env, &probe).observed();
        assert_eq!(observed, (true, 1000));
        assert_eq!((f.balance(), f.client().state().nonce), (950, 1));
        assert_eq!(f.history().calls, 1);
    }
}
