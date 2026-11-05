//! Synthetic native fixture and loopback RPC. It performs no actual chain or Wasm execution.
#![allow(dead_code)]
use super::wire;
use crate::provider::runtime::owner_client::{
    OwnerSigner,
    workflow::{self, OwnerPolicy},
};
use allowit_stellar_wallet as native;
use ed25519_dalek::{Signer, SigningKey};
use native::rpc::{self, Rpc};
use serde_json::{Value, json};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use stellar_xdr as x;
use x::{ReadXdr, WriteXdr};
pub(crate) fn account(n: u8) -> String {
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
pub(crate) fn wasm() -> Vec<u8> {
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
pub(crate) fn selection() -> OwnerPolicy {
    let policy = serde_json::from_value(wire::fixture()["policy"].clone()).unwrap();
    workflow::deployment_policy(policy, &account(11), &account(12), &account(13), &wasm()).unwrap()
}
pub(crate) fn fresh(owner: &str) -> native::AccountState {
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
pub(crate) fn account_entry(state: &native::AccountState) -> Value {
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
pub(crate) fn fund_step(c: &native::WalletConfig, units: i128, now: u64) -> Value {
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
    json!({"action":"fund","network":"stellar:testnet","transactionHash":native::hex(&hash(&tx)),"transactionXdr":enc(&x::TransactionEnvelope::Tx(x::TransactionV1Envelope{tx,signatures:Default::default()})),"expiresAt":now+300})
}
pub(crate) fn receipt(signed: &str) -> Value {
    let result = x::TransactionResult {
        fee_charged: 300,
        result: x::TransactionResultResult::TxSuccess(Default::default()),
        ext: x::TransactionResultExt::V0,
    };
    json!({"status":"SUCCESS","ledger":120,"envelopeXdr":signed,"resultXdr":enc(&result)})
}
pub(crate) struct Key<'a> {
    pub(crate) calls: AtomicUsize,
    pub(crate) bad: bool,
    pub(crate) before: Option<&'a dyn Fn()>,
}
impl OwnerSigner for Key<'_> {
    fn account(&self) -> &str {
        std::sync::OnceLock::get_or_init(&OWNER_ACCOUNT, || account(11))
    }
    fn sign_hash(&self, digest: &[u8; 32]) -> native::Result<[u8; 64]> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(f) = self.before {
            f();
        }
        Ok(if self.bad {
            [0; 64]
        } else {
            SigningKey::from_bytes(&[11; 32]).sign(digest).to_bytes()
        })
    }
}
static OWNER_ACCOUNT: std::sync::OnceLock<String> = std::sync::OnceLock::new();
pub(crate) fn key() -> Key<'static> {
    Key {
        calls: AtomicUsize::new(0),
        bad: false,
        before: None,
    }
}
pub(crate) struct Chain {
    pub(crate) config: native::WalletConfig,
    pub(crate) server: Option<Arc<Mutex<wire::State>>>,
    pub(crate) source: Mutex<native::AccountState>,
    pub(crate) direct_signed: Mutex<Option<String>>,
    pub(crate) lose_direct: bool,
    pub(crate) events: Mutex<Vec<String>>,
}
impl Chain {
    pub(crate) fn new(c: native::WalletConfig) -> Self {
        Self {
            source: Mutex::new(fresh(&c.owner)),
            config: c,
            server: None,
            direct_signed: Mutex::new(None),
            lose_direct: false,
            events: Mutex::new(vec![]),
        }
    }
}
impl Rpc for Chain {
    fn call(&self, method: &str, params: Value) -> native::Result<Value> {
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
                let state = native::contract::CustodyState {
                    policy_state: Default::default(),
                    contract_version: native::CONTRACT_VERSION,
                    owner: c.owner.clone(),
                    agent: c.agent.clone(),
                    server: c.server.clone(),
                    asset: c.asset.clone(),
                    policy_instance: c.policy_instance,
                    source_digest: c.source_digest,
                    rules: c.rules.clone(),
                    params: c.params.clone(),
                    x402_enabled: false,
                    token: c.asset_symbol.clone(),
                    deployment_version: 1,
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
                    self.server.as_ref().and_then(|s| {
                        s.lock()
                            .unwrap()
                            .owner_submissions
                            .iter()
                            .find(|v| {
                                native::hex(
                                    &rpc::signed_transaction_hash(
                                        &c.network,
                                        v["transactionXdr"].as_str().unwrap(),
                                    )
                                    .unwrap(),
                                ) == params["hash"]
                            })
                            .map(|v| v["transactionXdr"].as_str().unwrap().into())
                    })
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

/// The CLI exercises actual Core HTTP/RPC against the synthetic native fixture.
pub(crate) struct RpcServer {
    pub(crate) url: String,
    pub(crate) chain: Arc<Chain>,
    pub(crate) stop: Arc<std::sync::atomic::AtomicBool>,
    pub(crate) task: Option<std::thread::JoinHandle<()>>,
}
impl RpcServer {
    pub(crate) fn new(chain: Chain) -> Self {
        use std::{
            io::{Read, Write},
            net::TcpListener,
            thread,
            time::Duration,
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let chain = Arc::new(chain);
        let actor = chain.clone();
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let quitting = stop.clone();
        let task = thread::spawn(move || {
            while !quitting.load(Ordering::Relaxed) {
                let (mut stream, _) = match listener.accept() {
                    Ok(s) => s,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(e) => panic!("{e}"),
                };
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut headers = vec![];
                while !headers.ends_with(b"\r\n\r\n") {
                    assert!(headers.len() < 16_384);
                    let mut b = [0];
                    stream.read_exact(&mut b).unwrap();
                    headers.push(b[0]);
                }
                let headers = String::from_utf8(headers).unwrap();
                let len = headers
                    .lines()
                    .filter_map(|l| l.split_once(':'))
                    .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                    .unwrap()
                    .1
                    .trim()
                    .parse()
                    .unwrap();
                let mut body = vec![0; len];
                stream.read_exact(&mut body).unwrap();
                let request: Value = serde_json::from_slice(&body).unwrap();
                let result = actor.call(
                    request["method"].as_str().unwrap(),
                    request["params"].clone(),
                );
                let value = match result {
                    Ok(result) => json!({"jsonrpc":"2.0","id":request["id"],"result":result}),
                    Err(message) => {
                        json!({"jsonrpc":"2.0","id":request["id"],"error":{"code":-32000,"message":message}})
                    }
                };
                let bytes = serde_json::to_vec(&value).unwrap();
                write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",bytes.len()).unwrap();
                stream.write_all(&bytes).unwrap();
            }
        });
        Self {
            url,
            chain,
            stop,
            task: Some(task),
        }
    }
}
impl Drop for RpcServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let done = self.task.take().unwrap().join();
        if !std::thread::panicking() {
            done.expect("native RPC fixture failed");
        }
    }
}

/// Synthetic native installation using the recorded portable source and exact current server payload fields.
pub(crate) fn native_selection() -> OwnerPolicy {
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
    selection.policy.runtime.wallet.profile = "allowit-stellar-native-v1".into();
    selection.validate().unwrap();
    selection
}
pub(crate) fn consent(selection: &OwnerPolicy) -> Value {
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
pub(crate) fn descriptor(selection: &OwnerPolicy) -> Value {
    let c = &selection.config;
    let p = &selection.policy;
    json!({"version":1,"profile":native::PROFILE,"network":c.network,"policyId":p.id,"sourceHash":p.source_hash,"irHash":"","moduleDigest":native::hex(&c.module_digest),"wallet":c.wallet,"route":c.route,"config":c,"language":"allowit-portable-v1","portable":p.runtime.instance_binding.portable,"endpoints":{"execute":"/api/native/execute","status":"/api/native/execute/status"}})
}
pub(crate) fn configured_source(c: &native::WalletConfig) -> native::AccountState {
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
        step["transactionXdr"].as_str().unwrap(),
        x::Limits::none(),
    )
    .unwrap();
    let x::TransactionEnvelope::Tx(e) = &mut envelope else {
        panic!()
    };
    change(&mut e.tx);
    step["transactionHash"] = json!(native::hex(&hash(&e.tx)));
    step["transactionXdr"] = json!(enc(&envelope));
}
pub(crate) fn extend_step(c: &native::WalletConfig, target: u32, now: u64) -> Value {
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

pub(crate) fn approved_descriptor(selection: &OwnerPolicy) -> Value {
    let mut value = descriptor(selection);
    let digest =
        native::signing::signed_message_digest(consent(selection)["message"].as_str().unwrap());
    let signature = SigningKey::from_bytes(&[11; 32]).sign(&digest).to_bytes();
    value["sourceApproval"] = json!({"revision":selection.policy.revision,"signatures":[{"signer":selection.config.owner,"signature":signature.to_vec()}]});
    value
}
