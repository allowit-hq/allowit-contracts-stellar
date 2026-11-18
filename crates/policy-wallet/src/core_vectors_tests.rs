//! Execute the transactions that `crates/allowit-stellar` builds on the Soroban host with the
//! released Simple, Common and Custom wallet Wasm and the deployer.
//!
//! `crates/allowit-stellar/tests/policy_wallet.rs` runs each tier's complete workflow (the owner's
//! creation and funding through the deployer, transfer, SEP-56 deposit and redeem, pause, resume,
//! params update, transfer, recovery and stop) and records every transaction, the ledger at which
//! it settled, the host result it expects and the wallet's `state` view that it computes after
//! it. Here each recorded host function runs at its ledger with its exact recorded authorization
//! entries and transaction source: an execution's entry carries the agent's and the server's
//! real Ed25519 signatures, which the wallet's `__check_auth` verifies, and the owner authorizes
//! as the source account. The host result and the `state` view must equal the recorded ones, so
//! the rail's encodings, its figures and the contracts match byte for byte.
extern crate std;
use super::tests::{COMMON, CUSTOM, SIMPLE, VAULT, add_account, native_sac};
use ed25519_dalek::SigningKey;
use soroban_sdk::{
    Address, Env, Symbol, TryFromVal, Val,
    testutils::Ledger,
    xdr::{self, Limits, ReadXdr},
};
use std::{string::String, vec::Vec};

const VECTORS: &str =
    include_str!("../../allowit-stellar/tests/fixtures/policy-wallet-vectors.txt");
const DEPLOYER: &[u8] =
    include_bytes!("../../../target/wasm32v1-none/release/allowit_deployer.wasm");

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}
fn header(name: &str) -> String {
    VECTORS
        .lines()
        .find_map(|line| line.strip_prefix(name)?.strip_prefix(' '))
        .unwrap()
        .into()
}
fn contract(env: &Env, name: &str) -> Address {
    Address::try_from_val(
        env,
        &xdr::ScVal::Address(
            xdr::ScAddress::from_xdr(unhex(&header(name)), Limits::none()).unwrap(),
        ),
    )
    .unwrap()
}
/// The recorded steps of one tier: name, ledger, transaction, host result and state after it.
fn steps(kind: &str) -> Vec<(String, u32, xdr::Transaction, xdr::ScVal, xdr::ScVal)> {
    VECTORS
        .lines()
        .filter(|line| line.starts_with(&std::format!("{kind} ")))
        .map(|line| {
            let parts: Vec<&str> = line.split(' ').collect();
            assert_eq!(parts.len(), 6);
            (
                parts[1].into(),
                parts[2].parse().unwrap(),
                xdr::Transaction::from_xdr(unhex(parts[3]), Limits::none()).unwrap(),
                xdr::ScVal::from_xdr(unhex(parts[4]), Limits::none()).unwrap(),
                xdr::ScVal::from_xdr(unhex(parts[5]), Limits::none()).unwrap(),
            )
        })
        .collect()
}

fn run(kind: &str, wasm: &[u8]) -> Vec<String> {
    let env = Env::new_with_config(soroban_sdk::testutils::EnvTestConfig {
        capture_snapshot_at_drop: false,
    });
    let network: [u8; 32] = unhex(&header("network")).try_into().unwrap();
    env.ledger().with_mut(|l| {
        l.network_id = network;
        l.timestamp = header("timestamp").parse().unwrap();
    });
    let host = env.host();
    let asset = native_sac(&env);
    // The owner, agent, server, recipient and the server's sending account.
    for seed in [[1u8; 32], [2; 32], [3; 32], [6; 32], [10; 32]] {
        add_account(&env, &SigningKey::from_bytes(&seed));
    }
    env.register_at(&contract(&env, "vault"), VAULT, (asset.clone(), 0u32));
    env.register_at(&contract(&env, "deployer"), DEPLOYER, ());
    host.invoke_function(xdr::HostFunction::UploadContractWasm(
        wasm.to_vec().try_into().unwrap(),
    ))
    .unwrap();
    let mut wallet = None;
    let mut ran = Vec::new();
    for (name, ledger, tx, expected, state) in steps(kind) {
        env.ledger().with_mut(|l| l.sequence_number = ledger);
        let xdr::MuxedAccount::Ed25519(source) = &tx.source_account else {
            panic!()
        };
        let xdr::OperationBody::InvokeHostFunction(op) = &tx.operations[0].body else {
            panic!()
        };
        host.set_source_account(xdr::AccountId(xdr::PublicKey::PublicKeyTypeEd25519(
            source.clone(),
        )))
        .unwrap();
        env.set_auths(&op.auth);
        let result = host
            .invoke_function(op.host_function.clone())
            .unwrap_or_else(|e| panic!("{kind} {name}: {e:?}"));
        assert_eq!(result, expected, "{kind} {name} result");
        if name == "create" {
            wallet = Some(Address::try_from_val(&env, &result).unwrap());
        }
        let stored: Val = env.invoke_contract(
            wallet.as_ref().unwrap(),
            &Symbol::new(&env, "state"),
            soroban_sdk::Vec::new(&env),
        );
        let stored = xdr::ScVal::try_from_val(&env, &stored).unwrap();
        assert_eq!(stored, state, "{kind} {name} state");
        ran.push(name);
    }
    ran
}

const WORKFLOW: [&str; 10] = [
    "create",
    "transfer",
    "deposit",
    "redeem",
    "pause",
    "resume",
    "params",
    "transfer_v3",
    "recover",
    "stop",
];

#[test]
fn simple_wallet_executes_the_signer_workflow() {
    assert_eq!(run("simple_policy_engine", SIMPLE), WORKFLOW);
}

#[test]
fn common_wallet_executes_the_signer_workflow() {
    assert_eq!(run("common_policy_engine", COMMON), WORKFLOW);
}

#[test]
fn custom_wallet_executes_the_signer_workflow() {
    assert_eq!(run("custom_policy", CUSTOM), WORKFLOW);
}
