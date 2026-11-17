//! The Custom wallet of a policy with server functions, as compiled Wasm.
//!
//! The owner writes one source. The server evaluates all of it before it signs. The contract
//! compiles the on-chain part that Core derives from the source and binds the hash of the
//! owner's source. These tests run the Wasm that `scripts/build-contracts.sh` builds from the
//! sample mandate and its on-chain part.
extern crate std;
use super::tests::{DERIVED, DERIVED_SOURCE, Fixture, denial, set_param, transfer_args};
use super::*;
use allowit::AllowitError;
use soroban_sdk::{IntoVal, testutils::Address as _};

const ONCHAIN_PART: &[u8] =
    include_bytes!("../../allowit-stellar/tests/fixtures/sample-mandate.onchain.rs");

fn digest(env: &Env, bytes: &[u8]) -> BytesN<32> {
    env.crypto()
        .sha256(&Bytes::from_slice(env, bytes))
        .to_bytes()
}

fn execute(
    f: &Fixture,
    e: &AllowitExecutionRequest,
) -> Result<AllowitTransferReceipt, Result<AllowitWalletError, soroban_sdk::InvokeError>> {
    f.auth(
        &[&f.agent, &f.server],
        "execute",
        (e.clone(),).into_val(&f.env),
    );
    f.client().try_execute(e).map(|receipt| receipt.unwrap())
}

/// The wallet binds the hash of the owner's source, not of the part that it compiles. A
/// request that names the hash of the on-chain part is not a request of this policy.
#[test]
fn the_wallet_binds_the_owners_source_and_compiles_its_on_chain_part() {
    let f = Fixture::new(DERIVED, false);
    assert_ne!(DERIVED_SOURCE, ONCHAIN_PART);
    let binding = f.client().policy_binding();
    assert_eq!(binding.source_digest, digest(&f.env, DERIVED_SOURCE));
    let mut e = f.execution(10);
    assert_eq!(e.source_hash, digest(&f.env, DERIVED_SOURCE));
    e.source_hash = digest(&f.env, ONCHAIN_PART);
    assert_eq!(
        execute(&f, &e),
        Err(Ok(AllowitWalletError::InvalidInvocation))
    );
    assert_eq!(f.balance(), 1_000);
}

/// A request that the server signed and that keeps every kept rule passes. The contract reads
/// none of the owner's text: the request passes without those params too.
#[test]
fn an_allowed_request_passes_and_the_contract_reads_no_server_param() {
    let f = Fixture::new(DERIVED, false);
    execute(&f, &f.execution(60)).unwrap();
    assert_eq!(f.balance(), 940);
    assert_eq!(f.history().calls, 1);

    let mut p = f.deployment();
    for key in [
        "catalog_query",
        "report_url",
        "report_key",
        "web_query",
        "report_purchase",
        "position_review",
    ] {
        set_param(&mut p.params, key, None);
    }
    assert!(f.deploy_raw(f.packet(&p)));
    execute(&f, &f.execution(40)).unwrap();
    assert_eq!(f.balance(), 900);
}

/// The contract never runs for a request that the server did not sign: the server signs only
/// after it evaluated the whole source, with its server functions.
#[test]
fn a_request_that_the_server_did_not_sign_is_refused() {
    let f = Fixture::new(DERIVED, false);
    let e = f.execution(10);
    let before = f.client().state();
    for signers in [&[&f.agent][..], &[&f.server][..], &[][..]] {
        f.auth(signers, "execute", (e.clone(),).into_val(&f.env));
        assert_eq!(
            f.client().try_execute(&e),
            Err(Err(soroban_sdk::InvokeError::Abort))
        );
    }
    // The server signed another request: this one differs in its amount.
    let mut other = e.clone();
    transfer_args(&mut other).amount = 11;
    f.auth(
        &[&f.agent, &f.server],
        "execute",
        (e.clone(),).into_val(&f.env),
    );
    assert_eq!(
        f.client().try_execute(&other),
        Err(Err(soroban_sdk::InvokeError::Abort))
    );
    assert_eq!(f.client().state(), before);
    assert_eq!(f.balance(), 1_000);
}

/// A request that the server signed and that breaks a kept rule is refused with that rule's
/// code, whatever the server decided.
#[test]
fn a_server_signed_request_that_breaks_a_kept_rule_is_refused() {
    let f = Fixture::new(DERIVED, false);
    let before = f.client().state();
    // "Bound expenses": more than `report_limit`.
    assert_eq!(
        execute(&f, &f.execution(101)),
        denial(DERIVED, AllowitError::PaymentLimitExceeded)
    );
    // "Buy evidence only from approved sellers".
    let mut stranger = f.execution(10);
    transfer_args(&mut stranger).to = Address::generate(&f.env);
    assert_eq!(
        execute(&f, &stranger),
        denial(DERIVED, AllowitError::DestinationNotAllowed)
    );
    assert_eq!(f.client().state(), before);
    assert_eq!(f.balance(), 1_000);
    // The daily spending limit of 150: 100 passes, 60 more does not.
    execute(&f, &f.execution(100)).unwrap();
    assert_eq!(
        execute(&f, &f.execution(60)),
        denial(DERIVED, AllowitError::DailySpendingLimitExceeded)
    );
    // The owner's thresholds stay on chain as a check of the params: the on-chain part keeps
    // the assertion that does not depend on a server function.
    let mut p = f.deployment();
    set_param(&mut p.params, "deny_below", Some(AllowitValue::Int(9_000)));
    assert!(f.deploy_raw(f.packet(&p)));
    assert_eq!(
        execute(&f, &f.execution(10)),
        Err(Err(soroban_sdk::InvokeError::Abort))
    );
    assert_eq!(f.balance(), 900);
}
