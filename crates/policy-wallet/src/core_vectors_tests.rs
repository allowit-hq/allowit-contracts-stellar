//! Execute the transactions that `stellar/core` builds on the Soroban host with the released
//! Simple, Common and Custom wallet Wasm.
//!
//! `stellar/core/tests/policy_wallet.rs` runs each tier's complete workflow (create, transfer,
//! SEP-56 deposit and redeem, pause, resume, params update, transfer and recovery) and records
//! every transaction, the host result it expects and the wallet State it computes after it. Here each
//! recorded host function runs with its exact recorded authorization entries and transaction
//! source: the service entry carries its real Ed25519 account signature, and the agent and owner
//! authorize as the source account. The host result and the stored State must equal the
//! recorded ones, so the signer's encodings, receipts and host post-flight state match the
//! contracts byte for byte.
extern crate std;
use super::tests::{COMMON, CUSTOM, SIMPLE, add_account};
use ed25519_dalek::SigningKey;
use soroban_sdk::{
    Address, Env, Symbol, TryFromVal, Val,
    testutils::Ledger,
    token,
    xdr::{self, Limits, ReadXdr},
};
use std::{string::String, vec::Vec};

const VECTORS: &str =
    include_str!("../../../stellar/core/tests/fixtures/policy-wallet-vectors.txt");
const VAULT: &[u8] =
    include_bytes!("../../../target/wasm32v1-none/release/allowit_sep56_test_vault.wasm");

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
/// The recorded steps of one tier: name, transaction, host result and State after it.
fn steps(kind: &str) -> Vec<(String, xdr::Transaction, xdr::ScVal, xdr::ScVal)> {
    VECTORS
        .lines()
        .filter(|line| line.starts_with(&std::format!("{kind} ")))
        .map(|line| {
            let parts: Vec<&str> = line.split(' ').collect();
            assert_eq!(parts.len(), 5);
            (
                parts[1].into(),
                xdr::Transaction::from_xdr(unhex(parts[2]), Limits::none()).unwrap(),
                xdr::ScVal::from_xdr(unhex(parts[3]), Limits::none()).unwrap(),
                xdr::ScVal::from_xdr(unhex(parts[4]), Limits::none()).unwrap(),
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
        // After every recorded observation ledger and before every signature expiry.
        l.sequence_number = header("ledger").parse::<u32>().unwrap() + 30;
    });
    let host = env.host();
    let asset = host
        .invoke_function(xdr::HostFunction::CreateContract(xdr::CreateContractArgs {
            contract_id_preimage: xdr::ContractIdPreimage::Asset(xdr::Asset::Native),
            executable: xdr::ContractExecutable::StellarAsset,
        }))
        .unwrap();
    let asset = Address::try_from_val(&env, &asset).unwrap();
    for seed in [[1u8; 32], [2; 32], [3; 32], [6; 32]] {
        add_account(&env, &SigningKey::from_bytes(&seed));
    }
    let funder = add_account(&env, &SigningKey::from_bytes(&[44; 32]));
    // The header is the vault's `ScAddress` XDR.
    let vault = Address::try_from_val(
        &env,
        &xdr::ScVal::Address(
            xdr::ScAddress::from_xdr(unhex(&header("vault")), Limits::none()).unwrap(),
        ),
    )
    .unwrap();
    env.register_at(&vault, VAULT, (asset.clone(), 0u32));
    host.invoke_function(xdr::HostFunction::UploadContractWasm(
        wasm.to_vec().try_into().unwrap(),
    ))
    .unwrap();
    let mut wallet = None;
    let mut ran = Vec::new();
    for (name, tx, expected, state) in steps(kind) {
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
            let created = Address::try_from_val(&env, &result).unwrap();
            env.mock_all_auths();
            token::Client::new(&env, &asset).transfer(&funder, &created, &500_000_000);
            wallet = Some(created);
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

#[test]
fn simple_wallet_executes_the_signer_workflow() {
    assert_eq!(
        run("simple_policy_engine", SIMPLE),
        [
            "create",
            "transfer",
            "deposit",
            "redeem",
            "pause",
            "resume",
            "params",
            "transfer_v3",
            "recover"
        ]
    );
}

#[test]
fn common_wallet_executes_the_signer_workflow() {
    assert_eq!(
        run("common_policy_engine", COMMON),
        [
            "create",
            "transfer",
            "deposit",
            "redeem",
            "pause",
            "resume",
            "params",
            "transfer_v3",
            "recover"
        ]
    );
}

#[test]
fn custom_wallet_executes_the_signer_workflow() {
    assert_eq!(
        run("custom_policy", CUSTOM),
        [
            "create",
            "transfer",
            "pause",
            "resume",
            "params",
            "transfer_v3",
            "recover"
        ]
    );
}
