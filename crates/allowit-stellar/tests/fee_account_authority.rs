//! The signers, weights and thresholds of a fee account on the real Testnet ledger.
//!
//! A fee account sends the operations of one policy wallet and pays their network fees. The
//! owner's deployment creates and funds it; the agent holds a key and no account. The unit
//! tests of `allowit_stellar::owner` apply its setup and each owner action to a model of a
//! classic account. This test submits them: it sets up a fee account with fresh keys, then
//! sends transactions under each set of signers and reads what the network did. It is ignored
//! by default. Run it with:
//!
//!   ALLOWIT_LIVE_TESTNET=1 cargo test --locked --test fee_account_authority -- --ignored --nocapture
//!
//! It funds the fresh owner from the Testnet faucet and no other key, prints public values
//! only and closes the fee account at its end.
use allowit_stellar::owner::{self, WalletAction, WalletRoles, WalletStatus};
use allowit_stellar::owner_intent::{
    ExpectedOwnerIntent, OwnerAction, OwnerLimits, OwnerTransaction, validate_owner_transaction,
    validate_signed_owner_transaction,
};
use allowit_stellar::*;
use ed25519_dalek::{Signer, SigningKey};
use std::collections::BTreeMap;
use stellar_xdr::{self as x, ReadXdr, WriteXdr};

const NETWORK: &str = "stellar:testnet";
const RPC: &str = "https://soroban-testnet.stellar.org";
const XLM: i64 = 10_000_000;

/// The roles of a fee account: `wallet` is the fee account itself.
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
/// One transaction of the fee account itself, under the signatures that the test names.
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
/// Prepare one owner action on the fee account with the rail, check it against the owner's
/// own intent and sign it with the owner key alone.
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
fn balance(rpc: &rpc::HttpRpc, account: &str) -> i64 {
    rpc::native_balance(rpc, account).unwrap().balance
}

#[test]
#[ignore = "live Testnet: set ALLOWIT_LIVE_TESTNET=1"]
fn a_fee_account_on_testnet_obeys_its_signers_weights_and_thresholds() {
    if std::env::var("ALLOWIT_LIVE_TESTNET").as_deref() != Ok("1") {
        eprintln!("skipped: set ALLOWIT_LIVE_TESTNET=1");
        return;
    }
    let rpc = rpc::HttpRpc::new(RPC).unwrap();
    let (owner, agent, server, stranger) = (fresh_key(), fresh_key(), fresh_key(), fresh_key());
    let owner_account = key_account(&owner);
    // Only the owner has funds. The agent, the server and the stranger hold keys.
    println!(
        "faucet: {}",
        owner::fund_testnet_account(&owner_account, None).unwrap()
    );
    // The product makes the setup key at random, signs the creation with it once and drops
    // it. This test keeps the seed, to show below that the key has no authority after setup.
    let agent_account = key_account(&agent);
    let policy_wallet = stellar_strkey::Contract(hash(agent_account.as_bytes())).to_string();
    let own = fresh_key();
    let account_key_once = owner::WalletKey::from_seed(&own.to_bytes());
    let roles = Roles {
        owner: owner_account,
        agent: agent_account,
        server: key_account(&server),
        wallet: account_key_once.account(),
    };
    println!(
        "owner {} agent {} server {} fee account {} for policy wallet {}",
        roles.owner, roles.agent, roles.server, roles.wallet, policy_wallet
    );
    assert!(
        rpc::find_account(&rpc, &roles.agent).unwrap().is_none(),
        "the agent key has no account"
    );

    // Setup: one transaction from the owner's account creates the fee account with its
    // reserve and the fee float and sets its signers. The owner signs it, and the account's
    // own key signs it once.
    let owner_state = rpc::get_account(&rpc, &roles.owner).unwrap();
    let now = clock();
    let request_id = owner::fee_account_request_id(&hash(policy_wallet.as_bytes()));
    let setup = owner::prepare_fee_account_setup(
        &owner_state,
        &owner::FeeAccountTerms {
            account: &roles.wallet,
            agent: &roles.agent,
            engine: &roles.server,
            request_id: &request_id,
            network: NETWORK,
            fee_per_operation: 100,
        },
        now,
    )
    .unwrap();
    let packet = owner::setup_transaction(&setup).unwrap();
    assert_eq!(packet.action, owner::CREATE_FEE_ACCOUNT);
    let expected = ExpectedOwnerIntent {
        limits: OwnerLimits {
            network: NETWORK.into(),
            owner: roles.owner.clone(),
            next_sequence: owner_state.sequence + 1,
            max_fee_stroops: 10_000,
            valid_until: now + 300,
        },
        action: OwnerAction::FeeAccountSetup {
            state: owner_state,
            account: roles.wallet.clone(),
            agent: roles.agent.clone(),
            engine: roles.server.clone(),
            request_id,
        },
    };
    let signed = validate_owner_transaction(&packet, &expected, now)
        .unwrap()
        .sign_with_wallet_key(
            now,
            |digest| Ok(owner.sign(digest).to_bytes()),
            &account_key_once,
        )
        .unwrap();
    // The server takes this step only with both signatures.
    validate_signed_owner_transaction(&packet, &signed).unwrap();
    let x::TransactionEnvelope::Tx(both) =
        x::TransactionEnvelope::from_xdr_base64(&signed, x::Limits::none()).unwrap()
    else {
        panic!()
    };
    let owner_only = sign(&both.tx, &[&owner]);
    assert!(validate_signed_owner_transaction(&packet, &owner_only).is_err());
    // The network refuses the signer operations without the new account's own signature.
    let Outcome::Refused(code) =
        settle(&rpc, "setup with the owner's signature alone", &owner_only)
    else {
        panic!("the new account's own key must sign its signer operations")
    };
    assert!(code.contains("OpBadAuth"), "{code}");
    assert!(rpc::find_account(&rpc, &roles.wallet).unwrap().is_none());
    // A setup that fails at any one of its operations leaves no account: the ledger applies a
    // transaction whole or not at all. Each case carries both signatures and one operation
    // that the ledger refuses. The owner pays the fee and holds everything else.
    for failing in 0..4usize {
        let owner_state = rpc::get_account(&rpc, &roles.owner).unwrap();
        let before = balance(&rpc, &roles.owner);
        let setup = owner::prepare_fee_account_setup(
            &owner_state,
            &owner::FeeAccountTerms {
                account: &roles.wallet,
                agent: &roles.agent,
                engine: &roles.server,
                request_id: &owner::fee_account_request_id(&hash(policy_wallet.as_bytes())),
                network: NETWORK,
                fee_per_operation: 100,
            },
            clock(),
        )
        .unwrap();
        let x::TransactionEnvelope::Tx(envelope) = x::TransactionEnvelope::from_xdr_base64(
            &owner::setup_transaction(&setup).unwrap().transaction_xdr,
            x::Limits::none(),
        )
        .unwrap() else {
            panic!()
        };
        let mut tx = envelope.tx;
        let mut operations = tx.operations.to_vec();
        assert_eq!(operations.len(), 4);
        match &mut operations[failing].body {
            // A starting balance below the reserve of an account.
            x::OperationBody::CreateAccount(create) => create.starting_balance = 1,
            // A signer that is the account's own key.
            x::OperationBody::SetOptions(options) => {
                options.signer = Some(x::Signer {
                    key: x::SignerKey::Ed25519(x::Uint256(own.verifying_key().to_bytes())),
                    weight: 1,
                })
            }
            _ => panic!(),
        }
        tx.operations = operations.try_into().unwrap();
        let label = format!("setup that fails at operation {} of 4", failing + 1);
        let Outcome::Refused(code) = settle(&rpc, &label, &sign(&tx, &[&owner, &own])) else {
            panic!("{label} must fail")
        };
        assert!(code.starts_with("TxFailed"), "{code}");
        assert!(rpc::find_account(&rpc, &roles.wallet).unwrap().is_none());
        let paid = before - balance(&rpc, &roles.owner);
        assert!((0..=400).contains(&paid), "{paid}");
        println!(
            "  after it: no fee account exists; the owner paid {paid} stroops of fee and holds the rest"
        );
    }
    // The refused transaction used the owner's sequence, so the setup is prepared again.
    let owner_state = rpc::get_account(&rpc, &roles.owner).unwrap();
    let now = clock();
    let request_id = owner::fee_account_request_id(&hash(policy_wallet.as_bytes()));
    let setup = owner::prepare_fee_account_setup(
        &owner_state,
        &owner::FeeAccountTerms {
            account: &roles.wallet,
            agent: &roles.agent,
            engine: &roles.server,
            request_id: &request_id,
            network: NETWORK,
            fee_per_operation: 100,
        },
        now,
    )
    .unwrap();
    let packet = owner::setup_transaction(&setup).unwrap();
    let x::TransactionEnvelope::Tx(unsigned) =
        x::TransactionEnvelope::from_xdr_base64(&packet.transaction_xdr, x::Limits::none())
            .unwrap()
    else {
        panic!()
    };
    assert_eq!(key_account(&own), roles.wallet);
    let signed = sign(&unsigned.tx, &[&owner, &own]);
    validate_signed_owner_transaction(&packet, &signed).unwrap();
    let before = balance(&rpc, &roles.owner);
    assert_eq!(
        settle(&rpc, "setup by the owner", &signed),
        Outcome::Applied
    );
    // The owner paid the reserve, the float and the fee of four operations.
    assert_eq!(
        before - balance(&rpc, &roles.owner),
        owner::fee_account_starting_balance() + 400
    );
    assert_eq!(
        balance(&rpc, &roles.wallet),
        owner::fee_account_starting_balance()
    );

    // The ledger holds exactly the roles.
    let live = rpc::get_account(&rpc, &roles.wallet).unwrap();
    println!(
        "fee account on the ledger: own key {}, thresholds {}/{}/{}, signers {:?}, balance {}",
        live.master_weight,
        live.low_threshold,
        live.medium_threshold,
        live.high_threshold,
        live.signers
            .iter()
            .map(|s| (s.key.as_str(), s.weight))
            .collect::<Vec<_>>(),
        balance(&rpc, &roles.wallet)
    );
    assert_eq!(
        live.wallet_status(&roles.owner, &roles.agent, &roles.server)
            .unwrap(),
        WalletStatus::Active
    );
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

    let stranger_key = x::SignerKey::Ed25519(x::Uint256(stranger.verifying_key().to_bytes()));
    let owner_muxed = x::MuxedAccount::Ed25519(x::Uint256(owner.verifying_key().to_bytes()));
    let attempts = || -> Vec<(&'static str, x::OperationBody)> {
        vec![
            ("pays the fee float out", payment(&roles.owner, XLM)),
            (
                "adds a signer",
                x::OperationBody::SetOptions(x::SetOptionsOp {
                    signer: Some(x::Signer {
                        key: stranger_key.clone(),
                        weight: 3,
                    }),
                    ..Default::default()
                }),
            ),
            (
                "lowers the thresholds",
                x::OperationBody::SetOptions(x::SetOptionsOp {
                    low_threshold: Some(1),
                    med_threshold: Some(1),
                    high_threshold: Some(1),
                    ..Default::default()
                }),
            ),
            (
                "removes the owner",
                x::OperationBody::SetOptions(x::SetOptionsOp {
                    signer: Some(x::Signer {
                        key: x::SignerKey::Ed25519(x::Uint256(owner.verifying_key().to_bytes())),
                        weight: 0,
                    }),
                    ..Default::default()
                }),
            ),
            (
                "restores the setup key",
                x::OperationBody::SetOptions(x::SetOptionsOp {
                    master_weight: Some(3),
                    ..Default::default()
                }),
            ),
            (
                "merges the account",
                x::OperationBody::AccountMerge(owner_muxed.clone()),
            ),
        ]
    };
    // The agent alone, the server alone, the setup key and a stranger do nothing: the
    // network refuses each transaction before any operation.
    for (who, keys) in [
        ("the agent alone", vec![&agent]),
        ("the server alone", vec![&server]),
        ("the setup key alone", vec![&own]),
        ("a stranger", vec![&stranger]),
        ("the agent and the setup key", vec![&agent, &own]),
    ] {
        for (what, body) in attempts() {
            let label = format!("{who} {what}");
            let tx = wallet_transaction(&rpc, &roles.wallet, body);
            assert_eq!(
                settle(&rpc, &label, &sign(&tx, &keys)),
                below_transaction_threshold(),
                "{label}"
            );
        }
    }
    // Agent and server together reach the payment threshold of the ledger: there the rail's
    // co-sign path is the bound, and it signs only the wallet operation that the server
    // prepared. Together they change no signer, no threshold and merge nothing.
    for (what, body) in attempts().into_iter().skip(1) {
        let label = format!("the agent and the server {what}");
        let tx = wallet_transaction(&rpc, &roles.wallet, body);
        assert_eq!(
            settle(&rpc, &label, &sign(&tx, &[&agent, &server])),
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
    assert_eq!(
        balance(&rpc, &roles.wallet),
        owner::fee_account_starting_balance(),
        "no refused transaction moved the float"
    );
    assert!(
        rpc::find_account(&rpc, &roles.agent).unwrap().is_none(),
        "the agent key still has no account"
    );
    // A payment needs only the payment threshold, which the agent and the server reach
    // together: the ledger lets the two keys move the float. The rail is the bound here. It
    // gives the server's signature only to the wallet operation that the server prepared.
    let tx = wallet_transaction(&rpc, &roles.wallet, payment(&roles.owner, XLM));
    assert_eq!(
        settle(
            &rpc,
            "the agent and the server pay from the fee account",
            &sign(&tx, &[&agent, &server])
        ),
        Outcome::Applied
    );
    let after_payment = owner::fee_account_starting_balance() - XLM - 100;
    assert_eq!(balance(&rpc, &roles.wallet), after_payment);

    // The owner alone refills, takes the float back and closes the account.
    let step = owner_step(&rpc, &roles, &owner, WalletAction::Fund { units: 3 * XLM });
    assert_eq!(
        settle(&rpc, "refill by the owner alone", &step),
        Outcome::Applied
    );
    assert_eq!(balance(&rpc, &roles.wallet), after_payment + 3 * XLM);
    let spendable = rpc::native_balance(&rpc, &roles.wallet)
        .unwrap()
        .spendable(0);
    assert_eq!(
        spendable,
        after_payment + 3 * XLM - owner::wallet_reserve(false)
    );
    let step = owner_step(
        &rpc,
        &roles,
        &owner,
        WalletAction::ReturnFees { units: spendable },
    );
    assert_eq!(
        settle(&rpc, "return of the fee float by the owner alone", &step),
        Outcome::Applied
    );
    // The account stays with exactly its reserve and its roles.
    assert_eq!(balance(&rpc, &roles.wallet), owner::wallet_reserve(false));
    let before = balance(&rpc, &roles.owner);
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
        "the closed fee account no longer exists"
    );
    // The reserve returned to the owner, less the fee of the four closing operations.
    assert_eq!(
        balance(&rpc, &roles.owner) - before,
        owner::wallet_reserve(false) - 400
    );
}
