//! Native owner builders exercised through complete RPC responses and independent legacy XDR.
use allowit_stellar_wallet::{
    self as n,
    admin::*,
    owner_intent::*,
    rpc::{self, Rpc},
    *,
};
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Mutex};
use stellar_xdr as x;
const NETWORK: &str = "stellar:testnet";
const NOW: u64 = 1_800_000_000;
const SOURCE: &str = "use allowit::prelude::*;\npub fn execute(ctx: &AllowitContext) -> allowit::Result { allowit::payment_limit(ctx, &ctx.params[allowit::PAYMENT_LIMIT])?; Ok(()) }";
fn account(n: u8) -> String {
    account_for_seed(&[n; 32])
}
fn config() -> WalletConfig {
    PolicyInstallation {
        network: NETWORK.into(),
        policy_instance: [7; 32],
        owner: account(11),
        agent: account(12),
        server: account(13),
        tier: PolicyTier::Simple,
        params: PolicyParams(BTreeMap::from([(
            "payment_limit".into(),
            PolicyValue::Int(500),
        )])),
        asset_symbol: "XLM".into(),
        asset_issuer: None,
        policy_source: SOURCE.into(),
        module_digest: hash(b"reviewed host fixture code"),
        max_fee_stroops: 10_000,
    }
    .wallet_config()
    .unwrap()
}
fn keys(c: &WalletConfig) -> Vec<x::LedgerKey> {
    vec![
        x::LedgerKey::ContractData(x::LedgerKeyContractData {
            contract: address(&c.wallet).unwrap(),
            key: x::ScVal::LedgerKeyContractInstance,
            durability: x::ContractDataDurability::Persistent,
        }),
        x::LedgerKey::ContractCode(x::LedgerKeyContractCode {
            hash: x::Hash(c.module_digest),
        }),
    ]
}
fn resources(footprint: Vec<x::LedgerKey>) -> x::SorobanTransactionData {
    x::SorobanTransactionData {
        ext: x::SorobanTransactionDataExt::V0,
        resources: x::SorobanResources {
            footprint: x::LedgerFootprint {
                read_only: footprint.try_into().unwrap(),
                read_write: x::VecM::default(),
            },
            instructions: 1000,
            disk_read_bytes: 0,
            write_bytes: 0,
        },
        resource_fee: 1000,
    }
}
struct Chain {
    entries: BTreeMap<String, Value>,
    bad: u8,
    raw: Mutex<Vec<x::Transaction>>,
    receipt: Value,
    network: String,
}
impl Chain {
    fn new(c: &WalletConfig) -> Self {
        let a = x::LedgerEntryData::Account(x::AccountEntry {
            account_id: x::AccountId(x::PublicKey::PublicKeyTypeEd25519(x::Uint256(
                account_key(&c.owner).unwrap(),
            ))),
            seq_num: x::SequenceNumber(41),
            balance: 1_000_000_000,
            thresholds: x::Thresholds([1, 0, 0, 0]),
            ..Default::default()
        });
        let account_key = x::LedgerKey::Account(x::LedgerKeyAccount {
            account_id: x::AccountId(x::PublicKey::PublicKeyTypeEd25519(x::Uint256(
                account_key(&c.owner).unwrap(),
            ))),
        });
        let code = x::LedgerEntryData::ContractCode(x::ContractCodeEntry {
            ext: x::ContractCodeEntryExt::V0,
            hash: x::Hash(c.module_digest),
            code: b"reviewed host fixture code".to_vec().try_into().unwrap(),
        });
        let instance = x::LedgerEntryData::ContractData(x::ContractDataEntry {
            ext: x::ExtensionPoint::V0,
            contract: address(&c.wallet).unwrap(),
            key: x::ScVal::LedgerKeyContractInstance,
            durability: x::ContractDataDurability::Persistent,
            val: x::ScVal::ContractInstance(x::ScContractInstance {
                executable: x::ContractExecutable::Wasm(x::Hash(c.module_digest)),
                storage: None,
            }),
        });
        let settings = x::LedgerEntryData::ConfigSetting(x::ConfigSettingEntry::StateArchival(
            x::StateArchivalSettings {
                max_entry_ttl: 1000,
                ..Default::default()
            },
        ));
        let mut entries = BTreeMap::new();
        for (key, data) in [
            (account_key, a),
            (keys(c)[0].clone(), instance),
            (keys(c)[1].clone(), code),
            (
                x::LedgerKey::ConfigSetting(x::LedgerKeyConfigSetting {
                    config_setting_id: x::ConfigSettingId::StateArchival,
                }),
                settings,
            ),
        ] {
            entries.insert(xdr(&key).unwrap(),json!({"key":xdr(&key).unwrap(),"xdr":xdr(&data).unwrap(),"liveUntilLedgerSeq":520}));
        }
        Self {
            entries,
            network: c.network.clone(),
            bad: 0,
            raw: Mutex::new(vec![]),
            receipt: json!({"status":"NOT_FOUND","oldestLedger":1,"latestLedger":120,"latestLedgerCloseTime":NOW+301}),
        }
    }
}
impl Rpc for Chain {
    fn call(&self, method: &str, params: Value) -> n::Result<Value> {
        Ok(match method {
            "getNetwork" => json!({"passphrase":passphrase(&self.network)?}),
            "getLatestLedger" => json!({"sequence":120}),
            "getLedgerEntries" => {
                json!({"latestLedger":120,"entries":params["keys"].as_array().unwrap().iter().filter_map(|k|self.entries.get(k.as_str().unwrap())).collect::<Vec<_>>()})
            }
            "getTransaction" => self.receipt.clone(),
            "simulateTransaction" => {
                let x::TransactionEnvelope::Tx(e) = read(params["transaction"].as_str().unwrap())?
                else {
                    panic!()
                };
                self.raw.lock().unwrap().push(e.tx.clone());
                let (value, mut auth, mut footprint) = match &e.tx.operations[0].body {
                    x::OperationBody::InvokeHostFunction(op) => {
                        let x::HostFunction::InvokeContract(call) = &op.host_function else {
                            panic!()
                        };
                        if call.function_name.0.as_slice() == b"preview_redeem" {
                            assert!(params["authMode"].is_null());
                            return Ok(
                                json!({"latestLedger":120,"results":[{"xdr":xdr(&x::ScVal::I128(x::Int128Parts{hi:0,lo:500}))?,"auth":[]}]}),
                            );
                        }
                        assert_eq!(params["authMode"], "record");
                        (
                            x::ScVal::Void,
                            vec![x::SorobanAuthorizationEntry {
                                credentials: x::SorobanCredentials::SourceAccount,
                                root_invocation: x::SorobanAuthorizedInvocation {
                                    function: x::SorobanAuthorizedFunction::ContractFn(
                                        call.clone(),
                                    ),
                                    sub_invocations: x::VecM::default(),
                                },
                            }],
                            vec![],
                        )
                    }
                    x::OperationBody::ExtendFootprintTtl(_) => {
                        let x::TransactionExt::V1(data) = &e.tx.ext else {
                            panic!()
                        };
                        (
                            x::ScVal::Void,
                            vec![],
                            data.resources.footprint.read_only.to_vec(),
                        )
                    }
                    _ => panic!(),
                };
                if self.bad == 1 {
                    auth.clear();
                }
                if self.bad == 2 {
                    footprint.clear();
                }
                let mut response = json!({"latestLedger":120,"results":[{"xdr":xdr(&value)?,"auth":auth.iter().map(xdr).collect::<n::Result<Vec<_>>>()?}],"minResourceFee":"1000","transactionData":xdr(&resources(footprint))?});
                if self.bad == 3 {
                    response["restorePreamble"] = json!({});
                }
                if self.bad == 4 {
                    response["minResourceFee"] = json!("999");
                }
                response
            }
            _ => return Err(format!("Unexpected native call {method}")),
        })
    }
}
// This transaction is the former server builder's exact layout, independent of Deployer.
fn legacy(
    c: &WalletConfig,
    body: x::OperationBody,
    data: x::SorobanTransactionData,
) -> x::Transaction {
    x::Transaction {
        source_account: x::MuxedAccount::Ed25519(x::Uint256(account_key(&c.owner).unwrap())),
        fee: 1100,
        seq_num: x::SequenceNumber(42),
        cond: x::Preconditions::Time(x::TimeBounds {
            min_time: x::TimePoint(0),
            max_time: x::TimePoint(NOW + 300),
        }),
        memo: x::Memo::None,
        operations: vec![x::Operation {
            source_account: None,
            body,
        }]
        .try_into()
        .unwrap(),
        ext: x::TransactionExt::V1(data),
    }
}
fn deployer(chain: &Chain) -> Deployer<'_> {
    Deployer {
        rpc: chain,
        network: NETWORK,
        now: NOW,
        max_fee_stroops: 10_000,
    }
}
#[test]
fn fund_and_renewal_match_legacy_server_bytes_and_independent_owner_validation() {
    let c = config();
    let chain = Chain::new(&c);
    let fund = deployer(&chain).fund(&c, 500).unwrap();
    let call = x::InvokeContractArgs {
        contract_address: address(&c.asset).unwrap(),
        function_name: x::ScSymbol(b"transfer".to_vec().try_into().unwrap()),
        args: vec![
            x::ScVal::Address(address(&c.owner).unwrap()),
            x::ScVal::Address(address(&c.wallet).unwrap()),
            x::ScVal::I128(x::Int128Parts { hi: 0, lo: 500 }),
        ]
        .try_into()
        .unwrap(),
    };
    let auth = x::SorobanAuthorizationEntry {
        credentials: x::SorobanCredentials::SourceAccount,
        root_invocation: x::SorobanAuthorizedInvocation {
            function: x::SorobanAuthorizedFunction::ContractFn(call.clone()),
            sub_invocations: x::VecM::default(),
        },
    };
    let expected = legacy(
        &c,
        x::OperationBody::InvokeHostFunction(x::InvokeHostFunctionOp {
            host_function: x::HostFunction::InvokeContract(call),
            auth: vec![auth].try_into().unwrap(),
        }),
        resources(vec![]),
    );
    assert_eq!(
        fund.transaction_xdr,
        xdr(&x::TransactionEnvelope::Tx(x::TransactionV1Envelope {
            tx: expected.clone(),
            signatures: x::VecM::default()
        }))
        .unwrap()
    );
    assert_eq!(
        fund.transaction_hash,
        transaction_hash(NETWORK, &expected).unwrap()
    );
    let renewed = deployer(&chain).extend_wallet(&c, 999).unwrap();
    let expected = legacy(
        &c,
        x::OperationBody::ExtendFootprintTtl(x::ExtendFootprintTtlOp {
            ext: x::ExtensionPoint::V0,
            extend_to: 999,
        }),
        resources(keys(&c)),
    );
    assert_eq!(
        renewed.transaction_xdr,
        xdr(&x::TransactionEnvelope::Tx(x::TransactionV1Envelope {
            tx: expected.clone(),
            signatures: x::VecM::default()
        }))
        .unwrap()
    );
    assert_eq!(
        renewed.transaction_hash,
        transaction_hash(NETWORK, &expected).unwrap()
    );
    assert!(deployer(&chain).extend_wallet(&c, 120 + 999).is_err());
    for (packet, action) in [
        (
            fund,
            OwnerAction::Fund {
                asset: c.asset.clone(),
                from: c.owner.clone(),
                to: c.wallet.clone(),
                amount: 500,
            },
        ),
        (
            renewed,
            OwnerAction::Extend {
                wallet: c.wallet.clone(),
                wasm_hash: c.module_digest,
                extend_to: 999,
            },
        ),
    ] {
        validate_owner_transaction(
            &packet,
            &ExpectedOwnerIntent {
                limits: OwnerLimits {
                    network: NETWORK.into(),
                    owner: c.owner.clone(),
                    next_sequence: 42,
                    max_fee_stroops: 10_000,
                    valid_until: NOW + 300,
                },
                action,
            },
            NOW,
        )
        .unwrap();
    }
    for bad in [1, 3, 4] {
        let mut chain = Chain::new(&c);
        chain.bad = bad;
        assert!(deployer(&chain).fund(&c, 500).is_err(), "fund {bad}");
    }
    for bad in [2, 3, 4] {
        let mut chain = Chain::new(&c);
        chain.bad = bad;
        assert!(
            deployer(&chain).extend_wallet(&c, 999).is_err(),
            "extend {bad}"
        );
    }
    assert!(deployer(&chain).fund(&c, 0).is_err());
}
#[test]
fn observation_and_original_settlement_do_not_invent_missing_entries_or_receipts() {
    let c = config();
    let mut chain = Chain::new(&c);
    assert!(rpc::code_uploaded(&chain, NETWORK, &c.module_digest).unwrap());
    assert!(rpc::contract_exists(&chain, NETWORK, &c.wallet).unwrap());
    let packet = deployer(&chain).fund(&c, 500).unwrap();
    assert_eq!(
        rpc::owner_settlement(&chain, NETWORK, &packet.transaction_xdr).unwrap(),
        rpc::OwnerSettlement::Unknown
    );
    for (field, value) in [
        ("latestLedgerCloseTime", json!(NOW + 300)),
        ("oldestLedger", json!(121)),
        ("latestLedger", json!(119)),
    ] {
        let old = chain.receipt[field].clone();
        chain.receipt[field] = value;
        let result = rpc::owner_settlement(&chain, NETWORK, &packet.transaction_xdr);
        if field == "oldestLedger" {
            assert!(result.is_err());
        } else {
            assert_eq!(result.unwrap(), rpc::OwnerSettlement::Unknown);
        }
        chain.receipt[field] = old;
    }
    let key = xdr(&keys(&c)[0]).unwrap();
    chain.entries.get_mut(&key).unwrap()["liveUntilLedgerSeq"] = json!(119);
    assert!(rpc::contract_exists(&chain, NETWORK, &c.wallet).is_err());
    chain.entries.remove(&key);
    assert!(!rpc::contract_exists(&chain, NETWORK, &c.wallet).unwrap());
    let key = xdr(&keys(&c)[1]).unwrap();
    chain.entries.get_mut(&key).unwrap()["xdr"] = json!("broken");
    assert!(rpc::code_uploaded(&chain, NETWORK, &c.module_digest).is_err());
}
#[test]
fn installation_preserves_policy_instance_salt_and_constructor_binding() {
    let c = config();
    let mut old = b"allowit-stellar-wallet-salt-v1\0".to_vec();
    old.extend_from_slice(&c.policy_instance);
    assert_eq!(wallet_salt(&c.policy_instance), hash(old));
    assert_eq!(
        c.wallet,
        wallet_address(NETWORK, &c.owner, &wallet_salt(&c.policy_instance)).unwrap()
    );
    let constructor = PolicyConfig::for_policy(&c, false).unwrap();
    constructor.constructor_args().unwrap();
    assert_eq!(c.source_hash, hash(SOURCE));
    assert_eq!(c.asset, sac_address(NETWORK, &x::Asset::Native).unwrap());
    assert_eq!(c.rules, Vec::<String>::new());
}

#[test]
fn common_values_keep_variant_and_native_address_validation() {
    use allowit_policy_sdk::policy::PolicyValue as Common;
    let address = account(11);
    for value in [
        allowit::AllowitValue::Addr(allowit::Address::new(address.clone())),
        allowit::AllowitValue::Str(address),
        allowit::AllowitValue::Int(i128::MIN),
        allowit::AllowitValue::List(vec![allowit::AllowitValue::Bool(true)].into()),
    ] {
        let common = Common(value);
        let native = PolicyValue::from_core(&common).unwrap();
        assert_eq!(native.to_core().unwrap(), common);
    }
    assert!(
        PolicyValue::from_core(&Common(allowit::AllowitValue::Addr(allowit::Address::new(
            "not a Stellar address"
        ))))
        .is_err()
    );
}

#[test]
fn owner_readiness_and_native_diagnostics_remain_distinct_from_signing() {
    let mut prepared = PreparedOwnerOperation {
        network: NETWORK.into(),
        wallet: config().wallet,
        owner: account(11),
        function: "set_pause".into(),
        deployment_version: 2,
        transaction_xdr: "untrusted metadata only".into(),
        transaction_hash: [7; 32],
        expires_at: NOW + 300,
        required_authorizers: vec![account(11)],
        pending_authorizers: vec![account(12)],
        warnings: vec![],
    };
    assert!(prepared.owner_transaction().is_err());
    prepared.pending_authorizers.clear();
    assert_eq!(
        prepared.owner_transaction().unwrap().transaction_xdr,
        prepared.transaction_xdr
    );
    let outer = stellar_strkey::Contract([8; 32]).to_string();
    let inner = stellar_strkey::Contract([9; 32]).to_string();
    let text = format!(
        "HostError: Error(Contract, #7)\ncontract:{outer}, topics:[error, Error(Contract, #8)]\ncontract:{inner}, topics:[error, Error(Contract, #7)]"
    );
    assert_eq!(
        rpc::simulation_fault(&text, &[]).unwrap(),
        rpc::ContractFault {
            code: 7,
            contract: None
        }
    );
    assert_eq!(
        rpc::simulation_fault("Error(Contract, #42)", &["invalid XDR".into()])
            .unwrap()
            .code,
        42
    );
    assert!(rpc::simulation_fault("unavailable", &[]).is_none());
    let c = config();
    let chain = Chain::new(&c);
    let source = rpc::get_account(&chain, &c.owner).unwrap();
    assert_eq!(
        rpc::vault_redeemable(&chain, &c, &source, &outer, 10).unwrap(),
        500
    );
    assert!(rpc::vault_redeemable(&chain, &c, &source, &outer, -1).is_err());
}

struct Mixed<'a> {
    chain: &'a Chain,
    mode: u8,
    seen: std::sync::atomic::AtomicUsize,
    original: String,
}
impl Rpc for Mixed<'_> {
    fn call(&self, method: &str, params: Value) -> n::Result<Value> {
        let mut r = self.chain.call(method, params)?;
        if method == "getTransaction" && self.mode == 0 {
            // First native lookup missed just before ingestion, then the separately sampled range advanced.
            // A second lookup after the advertised horizon finds the originally signed transaction.
            let count = self.seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if count == 0 {
                r["latestLedger"] = json!(122);
                r["latestLedgerCloseTime"] = json!(NOW + 302);
            } else {
                let tr = x::TransactionResult {
                    fee_charged: 1100,
                    result: x::TransactionResultResult::TxSuccess(Default::default()),
                    ext: x::TransactionResultExt::V0,
                };
                r = json!({"status":"SUCCESS","ledger":121,"envelopeXdr":self.original,"resultXdr":xdr(&tr)?});
            }
        }
        if self.mode == 1 && method == "getTransaction" {
            r["txHash"] = json!(hex(&[19; 32]));
        }
        if self.mode == 4 && method == "getTransaction" {
            r["latestLedger"] = json!(u64::MAX);
        }
        if self.mode == 2 && method == "simulateTransaction" {
            r["latestLedger"] = json!(1);
        }
        if self.mode == 3
            && method == "getLedgerEntries"
            && r["entries"].as_array().is_some_and(|v| v.len() == 1)
        {
            r["latestLedger"] = json!(1);
        }
        if self.mode == 5 && method == "simulateTransaction" {
            r.as_object_mut().unwrap().remove("latestLedger");
        }
        if self.mode == 6 && method == "simulateTransaction" {
            r["latestLedger"] = json!(121);
        }
        if matches!(self.mode, 7 | 8)
            && method == "getLedgerEntries"
            && r["entries"].as_array().is_some_and(|v| v.len() == 1)
        {
            if self.mode == 7 {
                r.as_object_mut().unwrap().remove("latestLedger");
            } else {
                r["latestLedger"] = json!(121);
            }
        }
        if self.mode == 9
            && method == "getLedgerEntries"
            && r["entries"].as_array().is_some_and(|v| v.len() == 1)
        {
            let mut data: x::LedgerEntryData = read(r["entries"][0]["xdr"].as_str().unwrap())?;
            if let x::LedgerEntryData::Account(a) = &mut data {
                if self.seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst) > 0 {
                    a.seq_num.0 += 1;
                }
                r["entries"][0]["xdr"] = json!(xdr(&data)?);
            }
        }
        if self.mode == 10
            && method == "getLatestLedger"
            && self.seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst) > 0
        {
            r["sequence"] = json!(119);
        }
        Ok(r)
    }
}
#[test]
fn history_miss_stays_unknown_until_original_receipt() {
    let c = config();
    let chain = Chain::new(&c);
    let p = deployer(&chain).fund(&c, 500).unwrap();
    let signed = sign_owner_transaction(NETWORK, &p.transaction_xdr, &[11; 32]).unwrap();
    let mixed = Mixed {
        chain: &chain,
        mode: 0,
        seen: 0.into(),
        original: signed.clone(),
    };
    assert_eq!(
        rpc::owner_settlement(&mixed, NETWORK, &signed).unwrap(),
        rpc::OwnerSettlement::Unknown
    );
    assert!(matches!(
        rpc::owner_settlement(&mixed, NETWORK, &signed).unwrap(),
        rpc::OwnerSettlement::Settled(_)
    ));
}
#[test]
fn contradictory_hash_and_invalid_history_ledgers_reject() {
    let c = config();
    let chain = Chain::new(&c);
    let p = deployer(&chain).fund(&c, 500).unwrap();
    for mode in [1, 4] {
        let m = Mixed {
            chain: &chain,
            mode,
            seen: 0.into(),
            original: String::new(),
        };
        assert!(rpc::owner_settlement(&m, NETWORK, &p.transaction_xdr).is_err());
    }
}
#[test]
fn builders_reject_stale_missing_future_and_changed_observations() {
    let c = config();
    let chain = Chain::new(&c);
    for mode in [2, 3, 5, 6, 7, 8, 9, 10] {
        let mixed = Mixed {
            chain: &chain,
            mode,
            seen: 0.into(),
            original: String::new(),
        };
        let d = Deployer {
            rpc: &mixed,
            network: NETWORK,
            now: NOW,
            max_fee_stroops: 10_000,
        };
        assert!(d.fund(&c, 500).is_err(), "fund mode{mode}");
        mixed.seen.store(0, std::sync::atomic::Ordering::SeqCst);
        assert!(d.extend_wallet(&c, 999).is_err(), "extend mode{mode}");
    }
}
struct Advancing<'a> {
    chain: &'a Chain,
    heads: std::sync::atomic::AtomicUsize,
}
impl Rpc for Advancing<'_> {
    fn call(&self, m: &str, p: Value) -> n::Result<Value> {
        let mut v = self.chain.call(m, p)?;
        if m == "getLatestLedger" {
            v["sequence"] =
                json!(120 + self.heads.fetch_add(1, std::sync::atomic::Ordering::SeqCst));
        }
        if m == "getLedgerEntries" {
            for e in v["entries"].as_array_mut().unwrap() {
                e["liveUntilLedgerSeq"] = json!(120);
            }
        }
        Ok(v)
    }
}
#[test]
fn resource_visibility_rejects_expiry_at_closing_head() {
    let c = config();
    let chain = Chain::new(&c);
    let moving = Advancing {
        chain: &chain,
        heads: 0.into(),
    };
    assert!(rpc::code_uploaded(&moving, NETWORK, &c.module_digest).is_err());
    assert_eq!(moving.heads.load(std::sync::atomic::Ordering::SeqCst), 2);
}
#[test]
fn public_aliases_preserve_literal_packet_network() {
    let mut c = config();
    c.network = "stellar:mainnet".into();
    c.asset = sac_address(&c.network, &x::Asset::Native).unwrap();
    c.wallet = wallet_address(&c.network, &c.owner, &wallet_salt(&c.policy_instance)).unwrap();
    c.source_digest = policy::installed_source_digest(
        c.tier.unwrap(),
        &c.module_digest,
        &c.asset,
        &c.rules,
        &c.policy_source,
    )
    .unwrap();
    validate_config(&c).unwrap();
    let chain = Chain::new(&c);
    let d = Deployer {
        rpc: &chain,
        network: "stellar:pubnet",
        now: NOW,
        max_fee_stroops: 10_000,
    };
    assert_eq!(
        network_id(d.network).unwrap(),
        network_id(&c.network).unwrap()
    );
    assert_eq!(d.fund(&c, 500).unwrap().network, c.network);
    assert_eq!(d.extend_wallet(&c, 999).unwrap().network, c.network);
    let mut other = c.clone();
    other.network = "stellar:pubnet".into();
    let opposite = Deployer {
        network: "stellar:mainnet",
        ..d
    };
    assert_eq!(opposite.fund(&other, 500).unwrap().network, other.network);
    assert_eq!(
        opposite.extend_wallet(&other, 999).unwrap().network,
        other.network
    );
    let wrong = Deployer {
        network: NETWORK,
        ..opposite
    };
    assert!(wrong.fund(&c, 500).is_err());
    assert!(wrong.extend_wallet(&c, 999).is_err());
}

#[test]
fn unsigned_funding_does_not_establish_destination_trust() {
    let c = config();
    let mut chain = Chain::new(&c);
    chain.entries.remove(&xdr(&keys(&c)[0]).unwrap());
    assert!(!rpc::contract_exists(&chain, NETWORK, &c.wallet).unwrap());
    assert!(deployer(&chain).fund(&c, 500).is_ok());
}
#[test]
fn terminal_host_error_controls_fault_classification() {
    let event = x::DiagnosticEvent {
        in_successful_contract_call: true,
        event: x::ContractEvent {
            ext: x::ExtensionPoint::V0,
            contract_id: Some(x::ContractId(x::Hash([7; 32]))),
            type_: x::ContractEventType::Contract,
            body: x::ContractEventBody::V0(x::ContractEventV0 {
                topics: vec![
                    x::ScVal::Symbol(x::ScSymbol(b"error".to_vec().try_into().unwrap())),
                    x::ScVal::Error(x::ScError::Contract(7)),
                ]
                .try_into()
                .unwrap(),
                data: x::ScVal::Void,
            }),
        },
    };
    for terminal in [
        "HostError: Error(Budget, ExceededLimit)",
        "HostError: Error(Budget, ExceededLimit)\nEvent log: Error(Contract, #7)",
    ] {
        assert!(rpc::simulation_fault(terminal, &[xdr(&event).unwrap()]).is_none());
    }
    let actual =
        rpc::simulation_fault("HostError: Error(Contract, #8)", &[xdr(&event).unwrap()]).unwrap();
    assert_eq!(
        actual,
        rpc::ContractFault {
            code: 8,
            contract: None
        }
    );
}

#[test]
fn terminal_receipts_keep_success_and_failure_distinct_and_reject_contradictory_ranges() {
    let c = config();
    let mut chain = Chain::new(&c);
    let packet = deployer(&chain).fund(&c, 500).unwrap();
    let signed = sign_owner_transaction(NETWORK, &packet.transaction_xdr, &[11; 32]).unwrap();
    for failed in [false, true] {
        let result = x::TransactionResult {
            fee_charged: 1100,
            result: if failed {
                x::TransactionResultResult::TxFailed(Default::default())
            } else {
                x::TransactionResultResult::TxSuccess(Default::default())
            },
            ext: x::TransactionResultExt::V0,
        };
        let valid = json!({"status":if failed {"FAILED"} else {"SUCCESS"},"txHash":hex(&packet.transaction_hash),"oldestLedger":120,"latestLedger":122,"ledger":121,"envelopeXdr":signed,"resultXdr":xdr(&result).unwrap()});
        chain.receipt = valid.clone();
        let rpc::OwnerSettlement::Settled(receipt) =
            rpc::owner_settlement(&chain, NETWORK, &packet.transaction_xdr).unwrap()
        else {
            panic!()
        };
        assert_eq!(
            receipt.status,
            if failed {
                OperationStatus::Failed
            } else {
                OperationStatus::Confirmed
            }
        );
        for (key, value) in [
            ("txHash", json!(hex(&[19; 32]))),
            ("ledger", json!(123)),
            ("ledger", json!(119)),
            ("ledger", json!(0)),
            ("oldestLedger", json!(u64::MAX)),
            ("latestLedger", json!(0)),
        ] {
            chain.receipt = valid.clone();
            chain.receipt[key] = value;
            assert!(
                rpc::owner_settlement(&chain, NETWORK, &packet.transaction_xdr).is_err(),
                "{key}"
            );
        }
    }
}
#[test]
fn inclusive_resource_ttl_must_survive_the_closing_head() {
    let c = config();
    let mut chain = Chain::new(&c);
    for key in keys(&c) {
        chain.entries.get_mut(&xdr(&key).unwrap()).unwrap()["liveUntilLedgerSeq"] = json!(120);
    }
    assert!(rpc::code_uploaded(&chain, NETWORK, &c.module_digest).unwrap());
    assert!(rpc::contract_exists(&chain, NETWORK, &c.wallet).unwrap());
    assert_eq!(
        rpc::wallet_lifetime(&chain, NETWORK, &c.wallet, &c.module_digest)
            .unwrap()
            .code_live_until,
        120
    );
    let moving = || Advancing {
        chain: &chain,
        heads: 0.into(),
    };
    assert!(rpc::code_uploaded(&moving(), NETWORK, &c.module_digest).is_err());
    assert!(rpc::contract_exists(&moving(), NETWORK, &c.wallet).is_err());
    assert!(rpc::wallet_lifetime(&moving(), NETWORK, &c.wallet, &c.module_digest).is_err());
}

#[test]
fn external_owner_bytes_match_retained_identity_without_fresh_admission() {
    let c = config();
    let chain = Chain::new(&c);
    let mut packet = deployer(&chain).fund(&c, 500).unwrap();
    let mut persisted = serde_json::to_value(&packet).unwrap();
    assert_eq!(
        serde_json::from_value::<OwnerTransaction>(persisted.clone()).unwrap(),
        packet
    );
    assert!(persisted.get("transactionXdr").is_some());
    persisted["unexpected"] = json!(true);
    assert!(serde_json::from_value::<OwnerTransaction>(persisted).is_err());
    let x::TransactionEnvelope::Tx(mut original) = read(&packet.transaction_xdr).unwrap() else {
        panic!()
    };
    original.tx.cond = x::Preconditions::Time(x::TimeBounds {
        min_time: x::TimePoint(0),
        max_time: x::TimePoint(1),
    });
    packet.expires_at = 1;
    packet.transaction_hash = transaction_hash(NETWORK, &original.tx).unwrap();
    packet.transaction_xdr = xdr(&x::TransactionEnvelope::Tx(original)).unwrap();
    let signed = sign_owner_transaction(NETWORK, &packet.transaction_xdr, &[11; 32]).unwrap();
    assert_eq!(
        validate_signed_owner_transaction(&packet, &signed).unwrap(),
        packet.transaction_hash
    );
    let x::TransactionEnvelope::Tx(envelope) = read(&signed).unwrap() else {
        panic!()
    };
    for variant in 0..6 {
        let mut changed = envelope.clone();
        let mut sigs = changed.signatures.to_vec();
        match variant {
            0 => sigs.clear(),
            1 => sigs[0].hint.0 = [0; 4],
            2 => sigs[0].signature = x::Signature(vec![0; 64].try_into().unwrap()),
            3 => sigs.push(sigs[0].clone()),
            4 => sigs[0].signature = x::Signature(vec![0; 63].try_into().unwrap()),
            _ => changed.tx.fee += 1,
        }
        changed.signatures = sigs.try_into().unwrap();
        assert!(
            validate_signed_owner_transaction(
                &packet,
                &xdr(&x::TransactionEnvelope::Tx(changed)).unwrap()
            )
            .is_err(),
            "variant{variant}"
        );
    }
    let mut changed = packet.clone();
    changed.transaction_hash = [9; 32];
    assert!(validate_signed_owner_transaction(&changed, &signed).is_err());
    changed = packet.clone();
    changed.network = "stellar:pubnet".into();
    assert!(validate_signed_owner_transaction(&changed, &signed).is_err());
    changed = packet;
    changed.transaction_xdr = signed.clone();
    assert!(validate_signed_owner_transaction(&changed, &signed).is_err());
}
