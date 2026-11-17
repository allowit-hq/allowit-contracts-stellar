//! The signers, weights and thresholds of a Native wallet account on the real Testnet ledger.
//!
//! The unit tests of `allowit_stellar::owner` apply the setup and each owner action to a model
//! of a classic account. This test submits them: it sets up a wallet with fresh keys, then
//! sends the same transactions under each set of signers and reads what the network did. It
//! is ignored by default. Run it with:
//!
//!   ALLOWIT_LIVE_TESTNET=1 cargo test --locked --test native_wallet_authority -- --ignored --nocapture
//!
//! It funds the fresh owner from the Testnet faucet, prints public values only and closes the
//! wallet at its end.
use allowit_stellar::owner::{self, WalletAction, WalletRoles, WalletStatus};
use allowit_stellar::owner_intent::{
    ExpectedOwnerIntent, OwnerAction, OwnerLimits, OwnerTransaction, validate_native_setup,
    validate_owner_transaction,
};
use allowit_stellar::*;
use ed25519_dalek::{Signer, SigningKey};
use std::collections::BTreeMap;
use stellar_xdr::{self as x, ReadXdr, WriteXdr};

const NETWORK: &str = "stellar:testnet";
const RPC: &str = "https://soroban-testnet.stellar.org";
const XLM: i64 = 10_000_000;

struct Roles {
    owner: String,
    agent: String,
    server: String,
    wallet: String,
}
impl Roles {
    fn of(&self) -> WalletRoles<'_> {
        WalletRoles {
            wallet: &self.wallet,
            owner: &self.owner,
            agent: &self.agent,
            engine: &self.server,
        }
    }
}

fn fresh_key() -> SigningKey {
    let mut seed = [0u8; 32];
    std::io::Read::read_exact(&mut std::fs::File::open("/dev/urandom").unwrap(), &mut seed)
        .unwrap();
    SigningKey::from_bytes(&seed)
}
fn key_account(key: &SigningKey) -> String {
    account_for_public_key(&key.verifying_key().to_bytes())
}
fn clock() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn sign(tx: &x::Transaction, keys: &[&SigningKey]) -> String {
    let digest = transaction_hash(NETWORK, tx).unwrap();
    let signatures: Vec<_> = keys
        .iter()
        .map(|key| x::DecoratedSignature {
            hint: x::SignatureHint(key.verifying_key().to_bytes()[28..].try_into().unwrap()),
            signature: x::Signature(key.sign(&digest).to_bytes().to_vec().try_into().unwrap()),
        })
        .collect();
    x::TransactionEnvelope::Tx(x::TransactionV1Envelope {
        tx: tx.clone(),
        signatures: signatures.try_into().unwrap(),
    })
    .to_xdr_base64(x::Limits::none())
    .unwrap()
}
/// What the ledger did with a transaction.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Applied,
    /// The transaction result code, with each operation result code of a failed transaction,
    /// such as `TxBadAuth` or `TxFailed[OpBadAuth]`.
    Refused(String),
}
/// The codes of a transaction result. A refusal is asserted by its code: a transaction that
/// fails for another reason, such as a missing destination, proves nothing about its signers.
fn refusal(label: &str, result_xdr: Option<&str>) -> Outcome {
    let result = x::TransactionResult::from_xdr_base64(
        result_xdr.unwrap_or_else(|| panic!("{label}: no transaction result")),
        x::Limits::none(),
    )
    .unwrap_or_else(|_| panic!("{label}: unreadable transaction result"));
    let code = match &result.result {
        x::TransactionResultResult::TxFailed(operations) => format!(
            "TxFailed[{}]",
            operations
                .iter()
                .map(|operation| operation.name())
                .collect::<Vec<_>>()
                .join(",")
        ),
        other => other.name().to_owned(),
    };
    Outcome::Refused(code)
}
/// The signatures do not reach the threshold of the transaction itself.
fn below_transaction_threshold() -> Outcome {
    Outcome::Refused("TxBadAuth".into())
}
/// The signatures reach the transaction, and its one operation needs a higher threshold.
fn below_operation_threshold() -> Outcome {
    Outcome::Refused("TxFailed[OpBadAuth]".into())
}
/// Send a signed transaction and wait for its result.
fn settle(rpc: &rpc::HttpRpc, label: &str, envelope: &str) -> Outcome {
    let hash = hex(&rpc::signed_transaction_hash(NETWORK, envelope).unwrap());
    let sent = rpc::Rpc::call(
        rpc,
        "sendTransaction",
        serde_json::json!({ "transaction": envelope }),
    )
    .unwrap();
    let status = sent["status"].as_str().unwrap_or_default().to_owned();
    if status == "ERROR" {
        let outcome = refusal(label, sent["errorResultXdr"].as_str());
        println!("{label}: refused at submission, {hash}, {outcome:?}");
        return outcome;
    }
    assert!(
        matches!(status.as_str(), "PENDING" | "DUPLICATE"),
        "{label}: {sent}"
    );
    for _ in 0..40 {
        std::thread::sleep(std::time::Duration::from_secs(2));
        let got =
            rpc::Rpc::call(rpc, "getTransaction", serde_json::json!({ "hash": hash })).unwrap();
        match got["status"].as_str() {
            Some("SUCCESS") => {
                println!("{label}: applied, {hash}");
                return Outcome::Applied;
            }
            Some("FAILED") => {
                let outcome = refusal(label, got["resultXdr"].as_str());
                println!("{label}: failed on the ledger, {hash}, {outcome:?}");
                return outcome;
            }
            _ => {}
        }
    }
    panic!("{label}: no result for {hash}");
}
/// One transaction of the wallet account itself, as the agent and the server would sign it.
fn wallet_transaction(rpc: &rpc::HttpRpc, wallet: &str, body: x::OperationBody) -> x::Transaction {
    let state = rpc::get_account(rpc, wallet).unwrap();
    x::Transaction {
        source_account: x::MuxedAccount::Ed25519(x::Uint256(account_key(wallet).unwrap())),
        fee: 100,
        seq_num: x::SequenceNumber(state.sequence + 1),
        cond: x::Preconditions::Time(x::TimeBounds {
            min_time: x::TimePoint(0),
            max_time: x::TimePoint(clock() + 120),
        }),
        memo: x::Memo::None,
        operations: vec![x::Operation {
            source_account: None,
            body,
        }]
        .try_into()
        .unwrap(),
        ext: x::TransactionExt::V0,
    }
}
fn payment(to: &str, units: i64) -> x::OperationBody {
    x::OperationBody::Payment(x::PaymentOp {
        destination: x::MuxedAccount::Ed25519(x::Uint256(account_key(to).unwrap())),
        asset: x::Asset::Native,
        amount: units,
    })
}
/// Prepare one owner action with the rail, check it against the owner's own intent and sign
/// it with the owner key alone.
fn owner_step(
    rpc: &rpc::HttpRpc,
    roles: &Roles,
    owner: &SigningKey,
    action: WalletAction,
) -> String {
    let owner_state = rpc::get_account(rpc, &roles.owner).unwrap();
    let wallet_state = rpc::get_account(rpc, &roles.wallet).unwrap();
    let now = clock();
    let packet: OwnerTransaction = owner::prepare_wallet_action(
        &owner_state,
        &wallet_state,
        roles.of(),
        &action,
        &x::Asset::Native,
        NETWORK,
        100,
        now,
    )
    .unwrap();
    let expected = ExpectedOwnerIntent {
        limits: OwnerLimits {
            network: NETWORK.into(),
            owner: roles.owner.clone(),
            next_sequence: owner_state.sequence + 1,
            max_fee_stroops: 10_000,
            valid_until: now + 300,
        },
        action: OwnerAction::Wallet {
            owner_state,
            wallet_state,
            agent: roles.agent.clone(),
            engine: roles.server.clone(),
            action,
            asset_symbol: "XLM".into(),
            asset_issuer: None,
        },
    };
    validate_owner_transaction(&packet, &expected, now)
        .unwrap()
        .sign_with(now, |digest| Ok(owner.sign(digest).to_bytes()))
        .unwrap()
}

#[test]
#[ignore = "live Testnet: set ALLOWIT_LIVE_TESTNET=1"]
fn a_native_wallet_on_testnet_obeys_its_signers_weights_and_thresholds() {
    if std::env::var("ALLOWIT_LIVE_TESTNET").as_deref() != Ok("1") {
        eprintln!("skipped: set ALLOWIT_LIVE_TESTNET=1");
        return;
    }
    let rpc = rpc::HttpRpc::new(RPC).unwrap();
    let (owner, agent, server, stranger) = (fresh_key(), fresh_key(), fresh_key(), fresh_key());
    let owner_account = key_account(&owner);
    println!(
        "faucet: {}",
        owner::fund_testnet_account(&owner_account, None).unwrap()
    );
    // The product makes the setup key at random, signs the creation with it once and drops
    // it. This test keeps the seed, to show below that the key has no authority after setup.
    let agent_account = key_account(&agent);
    let wallet_own = fresh_key();
    let wallet_key = owner::WalletKey::from_seed(&wallet_own.to_bytes());
    let roles = Roles {
        owner: owner_account,
        agent: agent_account,
        server: key_account(&server),
        wallet: wallet_key.account(),
    };
    println!(
        "owner {} agent {} server {} wallet {}",
        roles.owner, roles.agent, roles.server, roles.wallet
    );

    // Setup: one transaction, the owner's signature and the wallet key's one signature.
    let owner_state = rpc::get_account(&rpc, &roles.owner).unwrap();
    let now = clock();
    let starting = owner::wallet_reserve(false) + 10 * XLM;
    let terms = owner::SetupTerms {
        wallet: &roles.wallet,
        agent: &roles.agent,
        engine: &roles.server,
        request_id: "authority-live-0001",
        network: NETWORK,
        fee_per_operation: 100,
        starting_balance: Some(starting),
        trustline: None,
    };
    let setup = owner::prepare_native_setup(&owner_state, &terms, now).unwrap();
    let expected = ExpectedOwnerIntent {
        limits: OwnerLimits {
            network: NETWORK.into(),
            owner: roles.owner.clone(),
            next_sequence: owner_state.sequence + 1,
            max_fee_stroops: 10_000,
            valid_until: now + 300,
        },
        action: OwnerAction::NativeSetup {
            state: owner_state,
            wallet: roles.wallet.clone(),
            agent: roles.agent.clone(),
            engine: roles.server.clone(),
            request_id: "authority-live-0001".into(),
            fee_per_operation: 100,
            starting_balance: Some(starting),
            trustline: None,
            created_at: now,
        },
    };
    let signed = validate_native_setup(&setup, &expected, now)
        .unwrap()
        .sign_with_wallet_key(now, |digest| Ok(owner.sign(digest).to_bytes()), &wallet_key)
        .unwrap();
    assert_eq!(
        settle(&rpc, "setup by the owner", &signed),
        Outcome::Applied
    );

    // The ledger holds exactly the roles.
    let live = rpc::get_account(&rpc, &roles.wallet).unwrap();
    println!(
        "wallet on the ledger: own key {}, thresholds {}/{}/{}, signers {:?}",
        live.master_weight,
        live.low_threshold,
        live.medium_threshold,
        live.high_threshold,
        live.signers
            .iter()
            .map(|s| (s.key.as_str(), s.weight))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        live.wallet_status(&roles.owner, &roles.agent, &roles.server)
            .unwrap(),
        WalletStatus::Active
    );

    // No automated key pays alone, and the setup key pays never again.
    assert_eq!(key_account(&wallet_own), roles.wallet);
    for (label, keys) in [
        ("payment by the agent alone", vec![&agent]),
        ("payment by the server alone", vec![&server]),
        ("payment by the setup key alone", vec![&wallet_own]),
        ("payment by a stranger", vec![&stranger]),
        (
            "payment by the agent and the setup key",
            vec![&agent, &wallet_own],
        ),
    ] {
        let tx = wallet_transaction(&rpc, &roles.wallet, payment(&roles.owner, XLM));
        assert_eq!(
            settle(&rpc, label, &sign(&tx, &keys)),
            below_transaction_threshold(),
            "{label}"
        );
    }
    // Agent and server together pay.
    let tx = wallet_transaction(&rpc, &roles.wallet, payment(&roles.owner, XLM));
    assert_eq!(
        settle(
            &rpc,
            "payment by the agent and the server",
            &sign(&tx, &[&agent, &server])
        ),
        Outcome::Applied
    );
    // Agent and server together change no signer, no threshold and merge nothing.
    let stranger_key = x::SignerKey::Ed25519(x::Uint256(stranger.verifying_key().to_bytes()));
    for (label, body) in [
        (
            "agent and server add a signer",
            x::OperationBody::SetOptions(x::SetOptionsOp {
                signer: Some(x::Signer {
                    key: stranger_key.clone(),
                    weight: 3,
                }),
                ..Default::default()
            }),
        ),
        (
            "agent and server lower the thresholds",
            x::OperationBody::SetOptions(x::SetOptionsOp {
                low_threshold: Some(1),
                med_threshold: Some(1),
                high_threshold: Some(1),
                ..Default::default()
            }),
        ),
        (
            "agent and server remove the owner",
            x::OperationBody::SetOptions(x::SetOptionsOp {
                signer: Some(x::Signer {
                    key: x::SignerKey::Ed25519(x::Uint256(owner.verifying_key().to_bytes())),
                    weight: 0,
                }),
                ..Default::default()
            }),
        ),
        (
            "agent and server restore the setup key",
            x::OperationBody::SetOptions(x::SetOptionsOp {
                master_weight: Some(3),
                ..Default::default()
            }),
        ),
        (
            "agent and server merge the account",
            x::OperationBody::AccountMerge(x::MuxedAccount::Ed25519(x::Uint256(
                owner.verifying_key().to_bytes(),
            ))),
        ),
    ] {
        let tx = wallet_transaction(&rpc, &roles.wallet, body);
        // Each of these needs the high threshold, and the ledger refuses its signers. The
        // code is asserted: a merge also fails while the account has signers, and that
        // failure would prove nothing about the threshold.
        assert_eq!(
            settle(&rpc, label, &sign(&tx, &[&agent, &server])),
            below_operation_threshold(),
            "{label}"
        );
    }
    assert_eq!(
        rpc::get_account(&rpc, &roles.wallet)
            .unwrap()
            .wallet_status(&roles.owner, &roles.agent, &roles.server)
            .unwrap(),
        WalletStatus::Active,
        "no refused transaction changed the roles"
    );

    // The ledger held exactly the signers, weights and thresholds of the architecture.
    assert_eq!(live.master_weight, 0);
    assert_eq!(
        (
            live.low_threshold,
            live.medium_threshold,
            live.high_threshold
        ),
        (2, 2, 3)
    );
    let weights: BTreeMap<_, _> = live
        .signers
        .iter()
        .map(|s| (s.key.clone(), s.weight))
        .collect();
    assert_eq!(
        weights,
        BTreeMap::from([
            (roles.owner.clone(), 3),
            (roles.agent.clone(), 1),
            (roles.server.clone(), 1),
        ])
    );
    // The owner alone pauses. Then agent and server together pay nothing.
    let step = owner_step(&rpc, &roles, &owner, WalletAction::Pause);
    assert_eq!(
        settle(&rpc, "pause by the owner alone", &step),
        Outcome::Applied
    );
    assert_eq!(
        rpc::get_account(&rpc, &roles.wallet)
            .unwrap()
            .wallet_status(&roles.owner, &roles.agent, &roles.server)
            .unwrap(),
        WalletStatus::Paused
    );
    let tx = wallet_transaction(&rpc, &roles.wallet, payment(&roles.owner, XLM));
    assert_eq!(
        settle(
            &rpc,
            "payment by the agent and the server of a paused wallet",
            &sign(&tx, &[&agent, &server])
        ),
        below_transaction_threshold()
    );
    // The owner alone withdraws from the paused wallet, resumes it and closes it.
    let step = owner_step(
        &rpc,
        &roles,
        &owner,
        WalletAction::Withdraw {
            units: XLM,
            recipient: None,
        },
    );
    assert_eq!(
        settle(&rpc, "withdrawal by the owner alone", &step),
        Outcome::Applied
    );
    let step = owner_step(&rpc, &roles, &owner, WalletAction::Resume);
    assert_eq!(
        settle(&rpc, "resume by the owner alone", &step),
        Outcome::Applied
    );
    let step = owner_step(
        &rpc,
        &roles,
        &owner,
        WalletAction::Close { token_balance: 0 },
    );
    assert_eq!(
        settle(&rpc, "close by the owner alone", &step),
        Outcome::Applied
    );
    assert!(
        rpc::find_account(&rpc, &roles.wallet).unwrap().is_none(),
        "the closed wallet account no longer exists"
    );
}
