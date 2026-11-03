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
            bad: 0,
            raw: Mutex::new(vec![]),
            receipt: json!({"status":"NOT_FOUND","oldestLedger":1,"latestLedger":120,"latestLedgerCloseTime":NOW+301}),
        }
    }
}
impl Rpc for Chain {
    fn call(&self, method: &str, params: Value) -> n::Result<Value> {
        Ok(match method {
            "getNetwork" => json!({"passphrase":passphrase(NETWORK)?}),
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
        rpc::owner_settlement(&chain, NETWORK, &packet.transaction_xdr, 120).unwrap(),
        rpc::OwnerSettlement::NeverApplied
    );
    for (field, value) in [
        ("latestLedgerCloseTime", json!(NOW + 300)),
        ("oldestLedger", json!(121)),
        ("latestLedger", json!(119)),
    ] {
        let old = chain.receipt[field].clone();
        chain.receipt[field] = value;
        assert_eq!(
            rpc::owner_settlement(&chain, NETWORK, &packet.transaction_xdr, 120).unwrap(),
            rpc::OwnerSettlement::Unknown
        );
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
        "contract:{outer}, topics:[error, Error(Contract, #8)]\ncontract:{inner}, topics:[error, Error(Contract, #7)]"
    );
    assert_eq!(
        rpc::simulation_fault(&text, &[]).unwrap(),
        rpc::ContractFault {
            code: 7,
            contract: Some(inner)
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
