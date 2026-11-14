//! Synthetic owner ledger fixtures. The caller supplies transport and observed submissions.
use crate as native;
use crate::provider::runtime::owner_client::workflow::{self, OwnerPolicy};
use native::rpc;
use serde_json::{Value, json};
use std::sync::Mutex;
use stellar_xdr as x;
use x::{ReadXdr, WriteXdr};
pub fn account(n: u8) -> String {
    native::account_for_seed(&[n; 32])
}
pub(crate) fn enc(v: &impl WriteXdr) -> String {
    v.to_xdr_base64(x::Limits::none()).unwrap()
}
pub(crate) fn addr(v: &str) -> x::ScAddress {
    native::address(v).unwrap()
}
pub(crate) fn symbol(v: &str) -> x::ScSymbol {
    x::ScSymbol(v.try_into().unwrap())
}
pub(crate) fn money(v: i128) -> x::ScVal {
    x::ScVal::I128(x::Int128Parts {
        hi: (v >> 64) as i64,
        lo: v as u64,
    })
}
pub(crate) fn hash(tx: &x::Transaction) -> [u8; 32] {
    use base64::Engine;
    native::hash(
        base64::engine::general_purpose::STANDARD
            .decode(enc(&x::TransactionSignaturePayload {
                network_id: x::Hash(native::network_id("stellar:testnet").unwrap()),
                tagged_transaction: x::TransactionSignaturePayloadTaggedTransaction::Tx(tx.clone()),
            }))
            .unwrap(),
    )
}
pub fn wasm() -> Vec<u8> {
    let mut meta = 0u32.to_be_bytes().to_vec();
    for bytes in [b"allowit_custody_layout".as_slice(), b"4"] {
        meta.extend((bytes.len() as u32).to_be_bytes());
        meta.extend(bytes);
        meta.resize(meta.len().div_ceil(4) * 4, 0);
    }
    let mut section = vec![b"contractmetav0".len() as u8];
    section.extend(b"contractmetav0");
    section.extend(meta);
    let mut bytes = b"\0asm\x01\0\0\0".to_vec();
    bytes.extend([0, section.len() as u8]);
    bytes.extend(section);
    bytes
}
pub fn selection() -> OwnerPolicy {
    let policy =
        serde_json::from_value(super::owner_generation_fixture()["policy"].clone()).unwrap();
    workflow::deployment_policy(policy, &account(11), &account(12), &account(13), &wasm()).unwrap()
}
pub fn fresh(owner: &str) -> native::AccountState {
    native::AccountState {
        address: owner.into(),
        sequence: 41,
        master_weight: 1,
        low_threshold: 0,
        medium_threshold: 0,
        high_threshold: 0,
        signers: vec![],
    }
}
pub fn account_entry(state: &native::AccountState) -> Value {
    let entry = x::LedgerEntryData::Account(x::AccountEntry {
        account_id: x::AccountId(x::PublicKey::PublicKeyTypeEd25519(x::Uint256(
            native::account_key(&state.address).unwrap(),
        ))),
        balance: 100_000_000_000,
        seq_num: x::SequenceNumber(state.sequence),
        num_sub_entries: state.signers.len() as u32,
        inflation_dest: None,
        flags: 0,
        home_domain: Default::default(),
        thresholds: x::Thresholds([
            state.master_weight as u8,
            state.low_threshold as u8,
            state.medium_threshold as u8,
            state.high_threshold as u8,
        ]),
        signers: state
            .signers
            .iter()
            .map(|s| x::Signer {
                key: x::SignerKey::Ed25519(x::Uint256(native::account_key(&s.key).unwrap())),
                weight: s.weight,
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
        ext: x::AccountEntryExt::V0,
    });
    json!({"entries":[{"xdr":enc(&entry)}]})
}
pub fn fund_step(c: &native::WalletConfig, units: i128, now: u64) -> Value {
    let call = x::InvokeContractArgs {
        contract_address: addr(&c.asset),
        function_name: symbol("transfer"),
        args: vec![
            x::ScVal::Address(addr(&c.owner)),
            x::ScVal::Address(addr(&c.wallet)),
            money(units),
        ]
        .try_into()
        .unwrap(),
    };
    let auth = x::SorobanAuthorizationEntry {
        credentials: x::SorobanCredentials::SourceAccount,
        root_invocation: x::SorobanAuthorizedInvocation {
            function: x::SorobanAuthorizedFunction::ContractFn(call.clone()),
            sub_invocations: Default::default(),
        },
    };
    let tx = x::Transaction {
        source_account: x::MuxedAccount::Ed25519(x::Uint256(
            native::account_key(&c.owner).unwrap(),
        )),
        fee: 1100,
        seq_num: x::SequenceNumber(42),
        cond: x::Preconditions::Time(x::TimeBounds {
            min_time: x::TimePoint(0),
            max_time: x::TimePoint(now + 300),
        }),
        memo: x::Memo::None,
        operations: vec![x::Operation {
            source_account: None,
            body: x::OperationBody::InvokeHostFunction(x::InvokeHostFunctionOp {
                host_function: x::HostFunction::InvokeContract(call),
                auth: vec![auth].try_into().unwrap(),
            }),
        }]
        .try_into()
        .unwrap(),
        ext: x::TransactionExt::V1(x::SorobanTransactionData {
            ext: x::SorobanTransactionDataExt::V0,
            resources: x::SorobanResources {
                footprint: Default::default(),
                instructions: 100_000,
                disk_read_bytes: 100,
                write_bytes: 100,
            },
            resource_fee: 1000,
        }),
    };
    json!({"action":"fund","network":"stellar:testnet","transactionHash":native::hex(&hash(&tx)),"payload":enc(&x::TransactionEnvelope::Tx(x::TransactionV1Envelope{tx,signatures:Default::default()})),"expiresAt":now+300})
}
/// The owner step of a params update: one `deploy_policy` call of the owner on the wallet.
pub fn update_step(
    c: &native::WalletConfig,
    deployment: &native::admin::PolicyDeployment,
    version: u64,
    now: u64,
) -> Value {
    let call = x::InvokeContractArgs {
        contract_address: addr(&c.wallet),
        function_name: symbol("deploy_policy"),
        args: vec![
            deployment
                .scval(allowit_core::admin::DeploymentVersion(version))
                .unwrap(),
        ]
        .try_into()
        .unwrap(),
    };
    let auth = x::SorobanAuthorizationEntry {
        credentials: x::SorobanCredentials::SourceAccount,
        root_invocation: x::SorobanAuthorizedInvocation {
            function: x::SorobanAuthorizedFunction::ContractFn(call.clone()),
            sub_invocations: Default::default(),
        },
    };
    let tx = x::Transaction {
        source_account: x::MuxedAccount::Ed25519(x::Uint256(
            native::account_key(&c.owner).unwrap(),
        )),
        fee: 1100,
        seq_num: x::SequenceNumber(42),
        cond: x::Preconditions::Time(x::TimeBounds {
            min_time: x::TimePoint(0),
            max_time: x::TimePoint(now + 300),
        }),
        memo: x::Memo::None,
        operations: vec![x::Operation {
            source_account: None,
            body: x::OperationBody::InvokeHostFunction(x::InvokeHostFunctionOp {
                host_function: x::HostFunction::InvokeContract(call),
                auth: vec![auth].try_into().unwrap(),
            }),
        }]
        .try_into()
        .unwrap(),
        ext: x::TransactionExt::V1(x::SorobanTransactionData {
            ext: x::SorobanTransactionDataExt::V0,
            resources: x::SorobanResources {
                footprint: Default::default(),
                instructions: 100_000,
                disk_read_bytes: 100,
                write_bytes: 100,
            },
            resource_fee: 1000,
        }),
    };
    json!({"action":"update_params","network":"stellar:testnet","transactionHash":native::hex(&hash(&tx)),"payload":enc(&x::TransactionEnvelope::Tx(x::TransactionV1Envelope{tx,signatures:Default::default()})),"expiresAt":now+300})
}
pub fn receipt(signed: &str) -> Value {
    let result = x::TransactionResult {
        fee_charged: 300,
        result: x::TransactionResultResult::TxSuccess(Default::default()),
        ext: x::TransactionResultExt::V0,
    };
    json!({"status":"SUCCESS","ledger":120,"envelopeXdr":signed,"resultXdr":enc(&result)})
}
pub struct OwnerLedger {
    pub config: native::WalletConfig,
    pub source: Mutex<native::AccountState>,
    pub direct_signed: Mutex<Option<String>>,
    pub lose_direct: bool,
    pub events: Mutex<Vec<String>>,
    /// The params, configuration revision and recorded usage that the wallet holds after an
    /// owner update. `None` is the installation's params at revision 1 with no usage.
    pub installed: Mutex<Option<(native::PolicyParams, u64, native::PolicyParams)>>,
}
impl OwnerLedger {
    pub fn new(c: native::WalletConfig) -> Self {
        Self {
            source: Mutex::new(fresh(&c.owner)),
            config: c,
            direct_signed: Mutex::new(None),
            lose_direct: false,
            events: Mutex::new(vec![]),
            installed: Mutex::new(None),
        }
    }
}
impl OwnerLedger {
    pub fn call(
        &self,
        method: &str,
        params: Value,
        owner_submissions: &[Value],
    ) -> native::Result<Value> {
        self.events.lock().unwrap().push(method.into());
        let c = &self.config;
        match method {
            "getNetwork" => Ok(json!({"passphrase":native::passphrase(&c.network)?})),
            "getLatestLedger" => Ok(json!({"sequence":120})),
            "getLedgerEntries" => {
                let key = x::LedgerKey::from_xdr_base64(
                    params["keys"][0].as_str().unwrap(),
                    x::Limits::none(),
                )
                .unwrap();
                if matches!(key, x::LedgerKey::ConfigSetting(_)) {
                    let archival = x::LedgerEntryData::ConfigSetting(
                        x::ConfigSettingEntry::StateArchival(x::StateArchivalSettings {
                            max_entry_ttl: 1000,
                            ..Default::default()
                        }),
                    );
                    let instance = x::LedgerEntryData::ContractData(x::ContractDataEntry {
                        ext: x::ExtensionPoint::V0,
                        contract: addr(&c.wallet),
                        key: x::ScVal::LedgerKeyContractInstance,
                        durability: x::ContractDataDurability::Persistent,
                        val: x::ScVal::ContractInstance(x::ScContractInstance {
                            executable: x::ContractExecutable::Wasm(x::Hash(c.module_digest)),
                            storage: None,
                        }),
                    });
                    let code = x::LedgerEntryData::ContractCode(x::ContractCodeEntry {
                        ext: x::ContractCodeEntryExt::V0,
                        hash: x::Hash(c.module_digest),
                        code: wasm().try_into().unwrap(),
                    });
                    return Ok(
                        json!({"latestLedger":120,"entries":[{"xdr":enc(&archival)},{"xdr":enc(&instance),"liveUntilLedgerSeq":520},{"xdr":enc(&code),"liveUntilLedgerSeq":1119}]}),
                    );
                }
                if let x::LedgerKey::Account(a) = key {
                    let x::PublicKey::PublicKeyTypeEd25519(k) = a.account_id.0;
                    let who = [&c.owner, &c.agent, &c.server]
                        .into_iter()
                        .find(|a| native::account_key(a).unwrap() == k.0)
                        .expect("known fixture account")
                        .to_owned();
                    let state = if who == c.owner {
                        self.source.lock().unwrap().clone()
                    } else {
                        fresh(&who)
                    };
                    return Ok(account_entry(&state));
                }
                let (params, deployment_version, policy_state) = self
                    .installed
                    .lock()
                    .unwrap()
                    .clone()
                    .unwrap_or((c.params.clone(), 1, Default::default()));
                let state = native::contract::CustodyState {
                    policy_state,
                    contract_version: native::CONTRACT_VERSION,
                    owner: c.owner.clone(),
                    agent: c.agent.clone(),
                    server: c.server.clone(),
                    asset: c.asset.clone(),
                    policy_instance: c.policy_instance,
                    source_digest: c.source_digest,
                    rules: c.rules.clone(),
                    params,
                    x402_enabled: false,
                    token: c.asset_symbol.clone(),
                    deployment_version,
                    nonce: 0,
                    paused: false,
                }
                .scval()?;
                let data = x::LedgerEntryData::ContractData(x::ContractDataEntry {
                    ext: x::ExtensionPoint::V0,
                    contract: addr(&c.wallet),
                    key: x::ScVal::LedgerKeyContractInstance,
                    durability: x::ContractDataDurability::Persistent,
                    val: x::ScVal::ContractInstance(x::ScContractInstance {
                        executable: x::ContractExecutable::Wasm(x::Hash(c.module_digest)),
                        storage: Some(
                            vec![x::ScMapEntry {
                                key: x::ScVal::U32(0),
                                val: state,
                            }]
                            .try_into()
                            .unwrap(),
                        ),
                    }),
                });
                Ok(json!({"entries":[{"xdr":enc(&data)}]}))
            }
            "simulateTransaction" => {
                let b = native::contract::PolicyBinding {
                    engine_kind: c.tier.unwrap().kind().into(),
                    contract_version: native::CONTRACT_VERSION,
                    policy_instance: c.policy_instance,
                    module_digest: c.module_digest,
                    source_digest: c.source_digest,
                    operations: vec![
                        native::OperationKind::Transfer,
                        native::OperationKind::Swap,
                        native::OperationKind::Deposit,
                        native::OperationKind::Redeem,
                    ],
                }
                .scval()?;
                Ok(json!({"results":[{"xdr":enc(&b)}]}))
            }
            "getTransaction" => {
                let signed = self.direct_signed.lock().unwrap().clone().or_else(|| {
                    owner_submissions
                        .iter()
                        .find(|v| {
                            native::hex(
                                &rpc::signed_transaction_hash(
                                    &c.network,
                                    v["payload"].as_str().unwrap(),
                                )
                                .unwrap(),
                            ) == params["hash"]
                        })
                        .map(|v| v["payload"].as_str().unwrap().into())
                });
                Ok(signed
                    .filter(|s| {
                        native::hex(&rpc::signed_transaction_hash(&c.network, s).unwrap())
                            == params["hash"]
                    })
                    .map(|s| {
                        if let x::TransactionEnvelope::Tx(e) =
                            x::TransactionEnvelope::from_xdr_base64(&s, x::Limits::none()).unwrap()
                        {
                            let mut state = self.source.lock().unwrap();
                            state.sequence = state.sequence.max(e.tx.seq_num.0);
                        }
                        receipt(&s)
                    })
                    .unwrap_or(json!({"status":"NOT_FOUND"})))
            }
            "sendTransaction" => {
                let signed = params["transaction"].as_str().unwrap().to_owned();
                let h = rpc::signed_transaction_hash(&c.network, &signed)?;
                *self.direct_signed.lock().unwrap() = Some(signed);
                let mut state = self.source.lock().unwrap();
                state.sequence += 1;
                state.master_weight = 3;
                state.low_threshold = 2;
                state.medium_threshold = 2;
                state.high_threshold = 3;
                state.signers = vec![
                    native::AccountSigner {
                        key: c.agent.clone(),
                        weight: 1,
                    },
                    native::AccountSigner {
                        key: c.server.clone(),
                        weight: 1,
                    },
                ];
                if self.lose_direct {
                    Err("lost native reply".into())
                } else {
                    Ok(json!({"status":"PENDING","hash":native::hex(&h)}))
                }
            }
            _ => Err(format!("unexpected test RPC {method}")),
        }
    }
}

/// Synthetic native installation using the recorded portable source and exact current server payload fields.
pub fn native_selection() -> OwnerPolicy {
    let mut selection = selection();
    let c = &mut selection.config;
    c.route = native::WalletRoute::Native;
    c.wallet = c.owner.clone();
    c.tier = None;
    c.max_fee_stroops = 100_000;
    c.source_digest = [0; 32];
    let b = &mut selection.policy.runtime.instance_binding;
    let d = &b.portable;
    let identity = json!({"language":d.language,"tier":d.tier,"rules":d.rules,"sourceHash":d.source_hash,"paramsHash":d.params_hash});
    c.module_digest = native::hash(serde_json_canonicalizer::to_vec(&identity).unwrap());
    b.wallet = c.wallet.clone();
    b.route = "native".into();
    b.tier = None;
    b.template = None;
    b.module_digest = native::hex(&c.module_digest);
    b.max_fee_stroops = c.max_fee_stroops;
    selection.policy.runtime.wallet.kind = "owner-wallet".into();
    selection.policy.runtime.wallet.profile = "allowit-native-v1".into();
    selection.validate().unwrap();
    selection
}
pub fn consent(selection: &OwnerPolicy) -> Value {
    let c = &selection.config;
    let p = &selection.policy;
    let d = &p.runtime.instance_binding.portable;
    // Field list is the server03b source_approval_message protocol, independently encoded for HTTP replay.
    let payload = json!({"version":1,"policyId":p.id,"revision":p.revision,"network":c.network,"wallet":c.wallet,"route":c.route,"policyInstance":native::hex(&c.policy_instance),"source":p.code,"sourceHash":p.source_hash,"irHash":"","moduleDigest":native::hex(&c.module_digest),"asset":c.asset,"assetSymbol":c.asset_symbol,"assetIssuer":c.asset_issuer,"maxFeeStroops":c.max_fee_stroops,"language":d.language,"tier":d.tier,"rules":d.rules,"params":d.params,"paramsHash":d.params_hash});
    let message = format!(
        "AllowIt Native policy approval v1\n{}",
        serde_json_canonicalizer::to_string(&payload).unwrap()
    );
    json!({"payload":payload,"message":message,"method":"sep53","required":c.route==native::WalletRoute::Native})
}
pub fn descriptor(selection: &OwnerPolicy) -> Value {
    let c = &selection.config;
    let p = &selection.policy;
    json!({"version":1,"profile":native::PROFILE,"network":c.network,"policyId":p.id,"sourceHash":p.source_hash,"irHash":"","moduleDigest":native::hex(&c.module_digest),"wallet":c.wallet,"route":c.route,"config":c,"language":"allowit-portable-v1","portable":p.runtime.instance_binding.portable,"endpoints":{"execute":"/api/native/execute","status":"/api/native/execute/status"}})
}
pub fn configured_source(c: &native::WalletConfig) -> native::AccountState {
    native::AccountState {
        address: c.owner.clone(),
        sequence: 42,
        master_weight: 3,
        low_threshold: 2,
        medium_threshold: 2,
        high_threshold: 3,
        signers: vec![
            native::AccountSigner {
                key: c.agent.clone(),
                weight: 1,
            },
            native::AccountSigner {
                key: c.server.clone(),
                weight: 1,
            },
        ],
    }
}

pub(crate) fn change_step(step: &mut Value, change: impl FnOnce(&mut x::Transaction)) {
    let mut envelope = x::TransactionEnvelope::from_xdr_base64(
        step["payload"].as_str().unwrap(),
        x::Limits::none(),
    )
    .unwrap();
    let x::TransactionEnvelope::Tx(e) = &mut envelope else {
        panic!()
    };
    change(&mut e.tx);
    step["transactionHash"] = json!(native::hex(&hash(&e.tx)));
    step["payload"] = json!(enc(&envelope));
}
pub fn extend_step(c: &native::WalletConfig, target: u32, now: u64) -> Value {
    let mut step = fund_step(c, 10_000_000, now);
    step["action"] = json!("extend");
    change_step(&mut step, |tx| {
        tx.operations = vec![x::Operation {
            source_account: None,
            body: x::OperationBody::ExtendFootprintTtl(x::ExtendFootprintTtlOp {
                ext: x::ExtensionPoint::V0,
                extend_to: target,
            }),
        }]
        .try_into()
        .unwrap();
        let x::TransactionExt::V1(data) = &mut tx.ext else {
            panic!()
        };
        data.resources.footprint = x::LedgerFootprint {
            read_only: vec![
                x::LedgerKey::ContractData(x::LedgerKeyContractData {
                    contract: addr(&c.wallet),
                    key: x::ScVal::LedgerKeyContractInstance,
                    durability: x::ContractDataDurability::Persistent,
                }),
                x::LedgerKey::ContractCode(x::LedgerKeyContractCode {
                    hash: x::Hash(c.module_digest),
                }),
            ]
            .try_into()
            .unwrap(),
            read_write: Default::default(),
        };
    });
    step
}

pub fn approved_descriptor(selection: &OwnerPolicy) -> Value {
    let mut value = descriptor(selection);
    let digest =
        native::signing::signed_message_digest(consent(selection)["message"].as_str().unwrap());
    let signature = super::sign_digest([11; 32], &digest);
    value["sourceApproval"] = json!({"revision":selection.policy.revision,"signatures":[{"signer":selection.config.owner,"signature":signature.to_vec()}]});
    value
}
