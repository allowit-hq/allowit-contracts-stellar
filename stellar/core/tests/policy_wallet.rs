//! End-to-end policy wallet workflows of all three tiers through the public API, against a
//! model Stellar RPC: upload, create, discover, transfer, deposit, receipts, pause, params
//! update and recovery. The run records `fixtures/policy-wallet-vectors.txt`, which
//! `crates/policy-wallet/src/core_vectors_tests.rs` executes on the Soroban host with the real
//! wallet Wasm.
//!
//! Regenerate after a contract or encoding change: run `scripts/build-contracts.sh`, then
//! `ALLOWIT_UPDATE_VECTORS=1 cargo test --test policy_wallet` in `stellar/core`.
use allowit::AllowitTier;
use allowit_policy_sdk::admin::{Admin, DeploymentVersion};
use allowit_policy_sdk::typed_workflow::*;
use allowit_stellar_wallet::admin::*;
use allowit_stellar_wallet::contract::{CustodyState, PolicyBinding};
use allowit_stellar_wallet::*;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::Mutex;
use stellar_strkey::Contract;
use stellar_xdr as x;
use x::{Limits, ReadXdr, WriteXdr};

const NETWORK: &str = "stellar:testnet";
/// 08:00 UTC on day 20833, far from a day boundary.
const NOW: u64 = 1_800_000_000;
const LEDGER: u32 = 1_000;
const OWNER: [u8; 32] = [1; 32];
const AGENT: [u8; 32] = [2; 32];
const SERVER: [u8; 32] = [3; 32];
const RECIPIENT: [u8; 32] = [6; 32];
const MAX_FEE: u32 = 1_000_000;
const SOURCE: &str = include_str!("../../../crates/custom-policy/policy/policy.rs");
const VECTORS: &str = "tests/fixtures/policy-wallet-vectors.txt";

fn vault() -> String {
    Contract([0x56; 32]).to_string()
}
fn xlm() -> String {
    sac_address(NETWORK, &x::Asset::Native).unwrap()
}
fn b64<T: WriteXdr>(v: &T) -> String {
    v.to_xdr_base64(Limits::none()).unwrap()
}
fn de<T: ReadXdr>(v: &str) -> T {
    T::from_xdr_base64(v, Limits::none()).unwrap()
}
fn hexs(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn wf(value: &str) -> AccountId {
    match address(value).unwrap() {
        x::ScAddress::Account(x::AccountId(x::PublicKey::PublicKeyTypeEd25519(k))) => AccountId {
            chain: Chain::Stellar,
            kind: AccountKind::Wallet,
            address: k.0,
        },
        x::ScAddress::Contract(id) => AccountId {
            chain: Chain::Stellar,
            kind: AccountKind::Contract,
            address: id.0.0,
        },
        _ => panic!(),
    }
}
fn field<'a>(v: &'a x::ScVal, name: &str) -> &'a x::ScVal {
    let x::ScVal::Map(Some(m)) = v else { panic!() };
    &m.iter()
        .find(|e| matches!(&e.key, x::ScVal::Symbol(s) if s.0.as_slice() == name.as_bytes()))
        .unwrap()
        .val
}
fn int(v: &x::ScVal) -> i128 {
    let x::ScVal::I128(p) = v else { panic!() };
    (i128::from(p.hi) << 64) | i128::from(p.lo)
}
fn addr(v: &x::ScVal) -> String {
    let x::ScVal::Address(a) = v else { panic!() };
    address_text(a).unwrap()
}
fn digest(v: &x::ScVal) -> [u8; 32] {
    let x::ScVal::Bytes(b) = v else { panic!() };
    b.as_slice().try_into().unwrap()
}

type Step = (String, String, x::ScVal, Option<x::ScVal>);
/// The wallet a model chain holds.
struct Wallet {
    address: String,
    tier: PolicyTier,
    module: [u8; 32],
    state: CustodyState,
    balance: i128,
    shares: i128,
    receipts: BTreeMap<[u8; 32], (x::ScVal, Option<x::ScVal>)>,
}
#[derive(Default)]
struct Model {
    ledger: u32,
    now: u64,
    accounts: BTreeMap<String, AccountState>,
    code: BTreeMap<[u8; 32], PolicyTier>,
    tiers: BTreeMap<[u8; 32], PolicyTier>,
    wallet: Option<Wallet>,
    settled: BTreeMap<String, String>,
    /// (name, signed envelope, expected host result, wallet State after it) of each settled
    /// transaction.
    steps: Vec<Step>,
    pending_name: String,
}
/// A model of Stellar RPC and the layout 4 wallet. It records authorization like Stellar RPC,
/// applies settled effects and computes post-flight state with the `allowit` host backend.
struct ModelChain(Mutex<Model>);
impl ModelChain {
    fn new(tiers: BTreeMap<[u8; 32], PolicyTier>) -> Self {
        let mut model = Model {
            ledger: LEDGER,
            now: NOW,
            tiers,
            ..Default::default()
        };
        for seed in [OWNER, AGENT, SERVER, RECIPIENT, [51; 32]] {
            let address = account_for_seed(&seed);
            model.accounts.insert(
                address.clone(),
                AccountState {
                    address,
                    sequence: 10,
                    master_weight: 1,
                    low_threshold: 0,
                    medium_threshold: 0,
                    high_threshold: 0,
                    signers: vec![],
                },
            );
        }
        Self(Mutex::new(model))
    }
    fn step(&self, name: &str) {
        self.0.lock().unwrap().pending_name = name.into();
    }
    fn fund(&self, amount: i128) {
        self.0.lock().unwrap().wallet.as_mut().unwrap().balance += amount;
    }
    fn state(&self) -> CustodyState {
        self.0
            .lock()
            .unwrap()
            .wallet
            .as_ref()
            .unwrap()
            .state
            .clone()
    }
}
fn binding(w: &Wallet, schema: [u8; 32]) -> x::ScVal {
    PolicyBinding {
        engine_kind: w.tier.kind().into(),
        contract_version: CONTRACT_VERSION,
        policy_instance: w.state.policy_instance,
        module_digest: w.module,
        source_digest: w.state.source_digest,
        argument_schema_digest: schema,
        entrypoint: "execute".into(),
    }
    .scval()
    .unwrap()
}
fn admits(tier: PolicyTier, schema: &[u8; 32]) -> bool {
    *schema == OperationKind::Transfer.schema_digest()
        || (tier != PolicyTier::Custom && *schema == OperationKind::Deposit.schema_digest())
}
fn account_entry(a: &AccountState) -> x::LedgerEntryData {
    x::LedgerEntryData::Account(x::AccountEntry {
        account_id: x::AccountId(x::PublicKey::PublicKeyTypeEd25519(x::Uint256(
            account_key(&a.address).unwrap(),
        ))),
        balance: 1_000_000_000,
        seq_num: x::SequenceNumber(a.sequence),
        num_sub_entries: 0,
        inflation_dest: None,
        flags: 0,
        home_domain: Default::default(),
        thresholds: x::Thresholds([
            a.master_weight as u8,
            a.low_threshold as u8,
            a.medium_threshold as u8,
            a.high_threshold as u8,
        ]),
        signers: Default::default(),
        ext: x::AccountEntryExt::V0,
    })
}
fn source_of(tx: &x::Transaction) -> String {
    let x::MuxedAccount::Ed25519(k) = &tx.source_account else {
        panic!()
    };
    stellar_strkey::ed25519::PublicKey(k.0).to_string()
}
fn host_op(tx: &x::Transaction) -> &x::InvokeHostFunctionOp {
    let x::OperationBody::InvokeHostFunction(op) = &tx.operations[0].body else {
        panic!()
    };
    op
}
impl rpc::Rpc for ModelChain {
    fn call(&self, method: &str, params: Value) -> Result<Value> {
        let mut m = self.0.lock().unwrap();
        match method {
            "getNetwork" => Ok(json!({"passphrase": passphrase(NETWORK)?})),
            "getLatestLedger" => Ok(json!({"sequence": m.ledger})),
            "getLedgerEntries" => {
                let encoded = params["keys"][0].as_str().unwrap();
                let key: x::LedgerKey = de(encoded);
                let entry = match &key {
                    x::LedgerKey::Account(a) => {
                        let x::PublicKey::PublicKeyTypeEd25519(k) = &a.account_id.0;
                        let address = stellar_strkey::ed25519::PublicKey(k.0).to_string();
                        m.accounts.get(&address).map(account_entry)
                    }
                    x::LedgerKey::ContractData(data) => m.wallet.as_ref().and_then(|w| {
                        if data.contract != address(&w.address).unwrap() {
                            return None;
                        }
                        let val = if data.key == x::ScVal::LedgerKeyContractInstance {
                            x::ScVal::ContractInstance(x::ScContractInstance {
                                executable: x::ContractExecutable::Wasm(x::Hash(w.module)),
                                storage: Some(
                                    vec![x::ScMapEntry {
                                        key: x::ScVal::U32(0),
                                        val: w.state.scval().unwrap(),
                                    }]
                                    .try_into()
                                    .unwrap(),
                                ),
                            })
                        } else {
                            let x::ScVal::Vec(Some(parts)) = &data.key else {
                                return None;
                            };
                            let id = digest(&parts[1]);
                            let (transfer, deposit) = w.receipts.get(&id)?;
                            match &parts[0] {
                                x::ScVal::Symbol(s) if s.0.as_slice() == b"Operation" => {
                                    transfer.clone()
                                }
                                _ => deposit.clone()?,
                            }
                        };
                        Some(x::LedgerEntryData::ContractData(x::ContractDataEntry {
                            ext: x::ExtensionPoint::V0,
                            contract: data.contract.clone(),
                            key: data.key.clone(),
                            durability: data.durability,
                            val,
                        }))
                    }),
                    _ => None,
                };
                let entries: Vec<Value> = entry
                    .into_iter()
                    .map(|e| json!({"key": encoded, "xdr": b64(&e), "liveUntilLedgerSeq": m.ledger + 10_000}))
                    .collect();
                Ok(json!({"latestLedger": m.ledger, "entries": entries}))
            }
            "simulateTransaction" => {
                let x::TransactionEnvelope::Tx(env) = de(params["transaction"].as_str().unwrap())
                else {
                    panic!()
                };
                let op = host_op(&env.tx);
                let source = source_of(&env.tx);
                let record = params["authMode"] == "record";
                if record && !op.auth.is_empty() {
                    return Ok(
                        json!({"error": "cannot set authMode to 'record' with an auth footprint"}),
                    );
                }
                let entry =
                    |who: &str,
                     function: x::SorobanAuthorizedFunction,
                     subs: Vec<x::SorobanAuthorizedInvocation>| {
                        x::SorobanAuthorizationEntry {
                            credentials: if who == source {
                                x::SorobanCredentials::SourceAccount
                            } else {
                                x::SorobanCredentials::Address(x::SorobanAddressCredentials {
                                    address: address(who).unwrap(),
                                    nonce: 4242,
                                    signature_expiration_ledger: 0,
                                    signature: x::ScVal::Void,
                                })
                            },
                            root_invocation: x::SorobanAuthorizedInvocation {
                                function,
                                sub_invocations: subs.try_into().unwrap(),
                            },
                        }
                    };
                let (result, required): (x::ScVal, Vec<x::SorobanAuthorizationEntry>) = match &op
                    .host_function
                {
                    x::HostFunction::UploadContractWasm(code) => (
                        x::ScVal::Bytes(x::ScBytes(
                            hash(code.as_slice()).to_vec().try_into().unwrap(),
                        )),
                        vec![],
                    ),
                    x::HostFunction::CreateContractV2(args) => {
                        let x::ContractIdPreimage::Address(from) = &args.contract_id_preimage
                        else {
                            panic!()
                        };
                        let derived = admin::wallet_address(
                            NETWORK,
                            &address_text(&from.address)?,
                            &from.salt.0,
                        )?;
                        let child = x::SorobanAuthorizedInvocation {
                            function: x::SorobanAuthorizedFunction::ContractFn(
                                x::InvokeContractArgs {
                                    contract_address: address(&derived)?,
                                    function_name: x::ScSymbol(
                                        b"__constructor".to_vec().try_into().unwrap(),
                                    ),
                                    args: args.constructor_args.clone(),
                                },
                            ),
                            sub_invocations: Default::default(),
                        };
                        (
                            x::ScVal::Address(address(&derived)?),
                            vec![entry(
                                &source,
                                x::SorobanAuthorizedFunction::CreateContractV2HostFn(args.clone()),
                                vec![child],
                            )],
                        )
                    }
                    x::HostFunction::InvokeContract(call) => {
                        let function = std::str::from_utf8(call.function_name.0.as_slice())
                            .unwrap()
                            .to_string();
                        let root = x::SorobanAuthorizedFunction::ContractFn(call.clone());
                        let Some(w) = m.wallet.as_ref() else {
                            return Ok(json!({"error": "no wallet"}));
                        };
                        if call.contract_address != address(&w.address)? {
                            assert_eq!(function, "balance");
                            return Ok(
                                json!({"results":[{"xdr": b64(&x::ScVal::I128(x::Int128Parts{hi:(w.balance>>64) as i64, lo: w.balance as u64}))}]}),
                            );
                        }
                        match function.as_str() {
                            "policy_binding" => {
                                (binding(w, OperationKind::Transfer.schema_digest()), vec![])
                            }
                            "policy_binding_for" => {
                                let schema = digest(&call.args[0]);
                                if !admits(w.tier, &schema) {
                                    return Ok(json!({"error": "HostError: Error(Contract, #16)"}));
                                }
                                (binding(w, schema), vec![])
                            }
                            "execute" => {
                                let request = &call.args[0];
                                if w.state.paused {
                                    return Ok(json!({"error": "HostError: Error(Contract, #6)"}));
                                }
                                let receipt = receipt_of(w, request);
                                (
                                    receipt,
                                    vec![
                                        entry(&w.state.agent, root.clone(), vec![]),
                                        entry(&w.state.server, root, vec![]),
                                    ],
                                )
                            }
                            "deploy_policy" => {
                                let next = addr(field(&call.args[0], "owner"));
                                let mut auth = vec![entry(&w.state.owner, root.clone(), vec![])];
                                if next != w.state.owner {
                                    auth.push(entry(&next, root, vec![]));
                                }
                                (x::ScVal::Void, auth)
                            }
                            "set_pause" | "recover" => {
                                (x::ScVal::Void, vec![entry(&w.state.owner, root, vec![])])
                            }
                            other => panic!("unexpected wallet call {other}"),
                        }
                    }
                    _ => panic!(),
                };
                let auth = if record || op.auth.is_empty() {
                    required
                } else {
                    for need in &required {
                        let who = match &need.credentials {
                            x::SorobanCredentials::Address(c) => Some(&c.address),
                            _ => None,
                        };
                        let present = op.auth.iter().any(|e| match (&e.credentials, who) {
                            (x::SorobanCredentials::SourceAccount, None) => true,
                            (x::SorobanCredentials::Address(c), Some(w)) => {
                                &c.address == w && c.signature != x::ScVal::Void
                            }
                            _ => false,
                        });
                        if !present {
                            return Ok(
                                json!({"error": "require_auth has no matching signed entry"}),
                            );
                        }
                    }
                    op.auth.to_vec()
                };
                let fee = if record { 1_000i64 } else { 1_500 };
                Ok(json!({
                    "minResourceFee": fee.to_string(),
                    "transactionData": b64(&x::SorobanTransactionData { resource_fee: fee, ..Default::default() }),
                    "results": [{"xdr": b64(&result), "auth": auth.iter().map(b64).collect::<Vec<_>>()}],
                }))
            }
            "sendTransaction" => {
                let signed = params["transaction"].as_str().unwrap().to_string();
                let x::TransactionEnvelope::Tx(env) = de(&signed) else {
                    panic!()
                };
                assert!(!env.signatures.is_empty());
                let tx_hash = hexs(&hash(
                    x::TransactionSignaturePayload {
                        network_id: x::Hash(network_id(NETWORK)?),
                        tagged_transaction: x::TransactionSignaturePayloadTaggedTransaction::Tx(
                            env.tx.clone(),
                        ),
                    }
                    .to_xdr(Limits::none())
                    .unwrap(),
                ));
                if m.settled.contains_key(&tx_hash) {
                    return Ok(json!({"hash": tx_hash, "status": "DUPLICATE"}));
                }
                let source = source_of(&env.tx);
                let account = m.accounts.get_mut(&source).unwrap();
                assert_eq!(env.tx.seq_num.0, account.sequence + 1, "sequence");
                account.sequence += 1;
                let result = apply(&mut m, &env.tx);
                let name = std::mem::take(&mut m.pending_name);
                let state = m.wallet.as_ref().map(|w| w.state.scval().unwrap());
                m.steps.push((name, signed.clone(), result, state));
                m.settled.insert(tx_hash.clone(), signed);
                m.ledger += 1;
                Ok(json!({"hash": tx_hash, "status": "PENDING"}))
            }
            "getTransaction" => {
                let tx_hash = params["hash"].as_str().unwrap();
                let Some(envelope) = m.settled.get(tx_hash) else {
                    return Ok(json!({"status": "NOT_FOUND"}));
                };
                let result = x::TransactionResult {
                    fee_charged: 100,
                    result: x::TransactionResultResult::TxSuccess(Default::default()),
                    ext: x::TransactionResultExt::V0,
                };
                Ok(
                    json!({"status": "SUCCESS", "ledger": m.ledger, "envelopeXdr": envelope, "resultXdr": b64(&result)}),
                )
            }
            other => panic!("unexpected RPC {other}"),
        }
    }
}
/// The receipt `execute` returns for `request` on `w`.
fn receipt_of(w: &Wallet, request: &x::ScVal) -> x::ScVal {
    let invocation = field(request, "invocation");
    let arguments: x::ScVal = {
        let x::ScVal::Bytes(b) = field(invocation, "arguments") else {
            panic!()
        };
        x::ScVal::from_xdr(b.as_slice(), Limits::none()).unwrap()
    };
    let schema = digest(field(invocation, "argument_schema_digest"));
    let (to, amount) = if schema == OperationKind::Transfer.schema_digest() {
        (
            addr(field(&arguments, "to")),
            int(field(&arguments, "amount")),
        )
    } else {
        (
            addr(field(&arguments, "vault")),
            int(field(&arguments, "assets")),
        )
    };
    let x::ScVal::U64(nonce) = field(request, "nonce") else {
        panic!()
    };
    let x::ScVal::U64(version) = field(request, "deployment_version") else {
        panic!()
    };
    TransferReceipt {
        operation_id: digest(field(request, "operation_id")),
        token: w.state.asset.clone(),
        from: w.address.clone(),
        to,
        amount,
        nonce: *nonce,
        deployment_version: *version,
    }
    .scval()
    .unwrap()
}
/// Apply one settled transaction to the model and return the host result it produces.
fn apply(m: &mut Model, tx: &x::Transaction) -> x::ScVal {
    let op = host_op(tx);
    match &op.host_function {
        x::HostFunction::UploadContractWasm(code) => {
            let h = hash(code.as_slice());
            let tier = m.tiers[&h];
            m.code.insert(h, tier);
            x::ScVal::Bytes(x::ScBytes(h.to_vec().try_into().unwrap()))
        }
        x::HostFunction::CreateContractV2(args) => {
            let x::ContractExecutable::Wasm(module) = &args.executable else {
                panic!()
            };
            let tier = m.code[&module.0];
            let x::ContractIdPreimage::Address(from) = &args.contract_id_preimage else {
                panic!()
            };
            let wallet =
                admin::wallet_address(NETWORK, &address_text(&from.address).unwrap(), &from.salt.0)
                    .unwrap();
            let config = &args.constructor_args[0];
            let x::ScVal::Bool(x402_enabled) = field(config, "x402_enabled") else {
                panic!()
            };
            let state = CustodyState {
                policy_state: PolicyParams::default(),
                contract_version: CONTRACT_VERSION,
                owner: addr(field(config, "owner")),
                agent: addr(field(config, "agent")),
                server: addr(field(config, "server")),
                asset: addr(field(config, "asset")),
                policy_instance: digest(field(config, "policy_instance")),
                source_digest: digest(field(config, "source_digest")),
                rules: policy::rules_from_scval(field(config, "rules")).unwrap(),
                params: PolicyParams::from_scval(field(config, "params")).unwrap(),
                x402_enabled: *x402_enabled,
                token: "XLM".into(),
                deployment_version: 0,
                nonce: 0,
                paused: false,
            };
            m.wallet = Some(Wallet {
                address: wallet.clone(),
                tier,
                module: module.0,
                state,
                balance: 0,
                shares: 0,
                receipts: BTreeMap::new(),
            });
            x::ScVal::Address(address(&wallet).unwrap())
        }
        x::HostFunction::InvokeContract(call) => {
            let now = m.now;
            let w = m.wallet.as_mut().unwrap();
            match call.function_name.0.as_slice() {
                b"execute" => execute(w, &call.args[0], now),
                b"set_pause" => {
                    let (x::ScVal::Bool(paused), x::ScVal::U64(version)) =
                        (&call.args[0], &call.args[1])
                    else {
                        panic!()
                    };
                    assert_eq!(*version, w.state.deployment_version + 1);
                    w.state.paused = *paused;
                    w.state.deployment_version = *version;
                    x::ScVal::Void
                }
                b"deploy_policy" => {
                    let d = &call.args[0];
                    let x::ScVal::U64(version) = field(d, "deployment_version") else {
                        panic!()
                    };
                    assert_eq!(*version, w.state.deployment_version + 1);
                    w.state.deployment_version = *version;
                    w.state.owner = addr(field(d, "owner"));
                    w.state.agent = addr(field(d, "agent"));
                    w.state.server = addr(field(d, "server"));
                    w.state.source_digest = digest(field(d, "source_digest"));
                    w.state.rules = policy::rules_from_scval(field(d, "rules")).unwrap();
                    w.state.params = PolicyParams::from_scval(field(d, "params")).unwrap();
                    x::ScVal::Void
                }
                b"recover" => {
                    w.balance -= int(&call.args[1]);
                    x::ScVal::Void
                }
                other => panic!("unexpected {other:?}"),
            }
        }
        _ => panic!(),
    }
}
/// Admit one execution as the kernel does and apply its effects and post-flight state.
fn execute(w: &mut Wallet, request: &x::ScVal, now: u64) -> x::ScVal {
    let receipt = receipt_of(w, request);
    let x::ScVal::U64(nonce) = field(request, "nonce") else {
        panic!()
    };
    assert_eq!(*nonce, w.state.nonce, "stale nonce");
    let x::ScVal::U64(expires_at) = field(request, "expires_at") else {
        panic!()
    };
    let (spent, gas, unpriced) = match field(request, "expense") {
        x::ScVal::Bytes(b) => {
            let e = x::ScVal::from_xdr(b.as_slice(), Limits::none()).unwrap();
            (
                int(field(&e, "spent_units")),
                int(field(&e, "gas_units")),
                false,
            )
        }
        _ => (0, 0, true),
    };
    let args = PolicyParams::from_scval(field(request, "args")).unwrap();
    let schema = digest(field(
        field(request, "invocation"),
        "argument_schema_digest",
    ));
    let deposit = schema == OperationKind::Deposit.schema_digest();
    let ctx = allowit::AllowitContext {
        env: allowit::AllowitEnv::new(),
        params: w.state.params.allowit().into(),
        state: w.state.policy_state.allowit(),
        request: allowit::AllowitRequest {
            operation: if deposit {
                allowit::AllowitOperation::sep56_deposit
            } else {
                allowit::AllowitOperation::sep41_transfer
            },
            asset: allowit::Address::new(w.state.asset.clone()),
            recipient: allowit::Address::new(addr(field(&receipt, "to"))),
            amount: int(field(&receipt, "amount")),
            now,
            expires_at: *expires_at,
            spent_units: spent,
            gas_units: gas,
            unpriced,
            args: args.allowit().into(),
        },
    };
    let tier = if w.tier == PolicyTier::Custom {
        AllowitTier::Custom
    } else {
        AllowitTier::Standard
    };
    w.state.policy_state = PolicyParams::from_allowit(&allowit::post_flight(&ctx, tier).unwrap());
    w.state.nonce += 1;
    let amount = int(field(&receipt, "amount"));
    w.balance -= amount;
    let id = digest(field(request, "operation_id"));
    let share = deposit.then(|| {
        w.shares += amount;
        DepositReceipt {
            operation_id: id,
            vault: addr(field(&receipt, "to")),
            asset: w.state.asset.clone(),
            from: w.address.clone(),
            receiver: w.address.clone(),
            operator: w.address.clone(),
            assets: amount,
            shares: amount,
            nonce: *nonce,
            deployment_version: w.state.deployment_version,
        }
        .scval()
        .unwrap()
    });
    w.receipts.insert(id, (receipt.clone(), share));
    receipt
}

/// One canonical request of the agent.
fn request(c: &WalletConfig, id: u8, deposit: Option<i128>, amount: i128) -> ExecutionRequest {
    let (instruction, beneficiary) = match deposit {
        None => (
            NativeInstruction::StellarCall {
                contract: wf(&c.asset),
                schema_digest: OperationKind::Transfer.schema_digest(),
                function: "transfer".into(),
                arguments: vec![
                    AbiValue::Account(wf(&c.wallet)),
                    AbiValue::Account(wf(&account_for_seed(&RECIPIENT))),
                    AbiValue::Signed128(amount),
                ],
            },
            account_for_seed(&RECIPIENT),
        ),
        Some(min_shares) => (
            NativeInstruction::StellarCall {
                contract: wf(&vault()),
                schema_digest: OperationKind::Deposit.schema_digest(),
                function: "deposit".into(),
                arguments: vec![
                    AbiValue::Signed128(amount),
                    AbiValue::Account(wf(&c.wallet)),
                    AbiValue::Account(wf(&c.wallet)),
                    AbiValue::Account(wf(&c.wallet)),
                    AbiValue::Signed128(min_shares),
                ],
            },
            vault(),
        ),
    };
    let units = u64::try_from(amount).unwrap();
    ExecutionRequest {
        operation: OperationRef {
            policy_instance: c.policy_instance,
            nonce: [id; 32],
        },
        input: ExecutionInput::Instructions(vec![instruction]),
        effect_bounds: vec![WorkflowEffectBound {
            asset: WorkflowAsset::Token(AssetId {
                network: network_id(NETWORK).unwrap(),
                token: wf(&c.asset),
            }),
            source: wf(&c.wallet),
            beneficiary: wf(&beneficiary),
            max_debit: units.into(),
            min_credit: units.into(),
            max_burn: 0u64.into(),
        }],
        fee_bounds: Some(vec![WorkflowFeeBound {
            payer: wf(&c.agent),
            asset: WorkflowAsset::Native {
                chain: Chain::Stellar,
                network: network_id(NETWORK).unwrap(),
            },
            max_fee: u64::from(MAX_FEE).into(),
        }]),
        evidence: vec![],
    }
}
fn terms(principal: i128, ledger: u32) -> ExecutionTerms {
    ExecutionTerms {
        args: PolicyParams::default(),
        expense: Some(ExpenseBounds::xlm(principal, 0, MAX_FEE, ledger - 1, NOW).unwrap()),
    }
}
#[derive(Default)]
struct Store(Option<(SignedOperation, OperationStatus)>);
impl rpc::OperationStore for Store {
    fn record(&mut self, _: [u8; 32], s: &SignedOperation, status: OperationStatus) -> Result<()> {
        self.0 = Some((s.clone(), status));
        Ok(())
    }
    fn load(&self, _: [u8; 32]) -> Result<Option<(SignedOperation, OperationStatus)>> {
        Ok(self.0.clone())
    }
}
/// Agent and service run one operation: prepare, service authorization, enforce simulation,
/// agent signature, submission and receipt.
fn run(
    chain: &ModelChain,
    c: &WalletConfig,
    r: &ExecutionRequest,
    t: &ExecutionTerms,
    name: &str,
) -> Result<rpc::ExecutionReceipt> {
    let prepared = rpc::prepare_with(chain, c, r, t, None, NOW, NOW + 300)?;
    let served = authorize_server(&prepared, &SERVER, NOW, None)?;
    let simulated = rpc::simulate(chain, &served)?;
    let proof = sign(&simulated, &AGENT, NOW)?;
    let signed = authorize(&simulated, &[proof], NOW)?;
    chain.step(name);
    let mut store = Store::default();
    let status = rpc::submit(chain, &mut store, &signed, NOW)?;
    assert_eq!(status, OperationStatus::Submitted);
    assert_eq!(
        rpc::recover(chain, &mut store, r.operation.nonce)?,
        OperationStatus::Confirmed
    );
    let receipt = rpc::operation_receipt(chain, c, &r.operation.nonce)?.ok_or("no receipt")?;
    assert_eq!(receipt.transfer, rpc::expected_receipt(&simulated)?);
    Ok(receipt)
}
fn owner_submit(chain: &ModelChain, name: &str, xdr: &str) {
    chain.step(name);
    let signed = sign_owner_transaction(NETWORK, xdr, &OWNER).unwrap();
    let receipt = rpc::send_and_poll(
        chain,
        NETWORK,
        &signed,
        rpc::Poll {
            attempts: 2,
            interval: std::time::Duration::ZERO,
        },
    )
    .unwrap();
    assert_eq!(receipt.status, OperationStatus::Confirmed);
}
fn params() -> PolicyParams {
    policy::params_from_json(
        &json!({
            "transaction_cap": 50_000_000,
            "spent_cap": 1_000_000_000,
            "day_spent_cap": 500_000_000,
            "day_total_cap": 500_000_000,
            "call_cap": 10,
            "recipients": [account_for_seed(&RECIPIENT), vault()],
            "tokens": [xlm()],
            "expiry": NOW + 30 * 86_400,
            "operations": ["transfer", "deposit"],
        }),
        Some(PolicyTier::Common),
    )
    .unwrap()
}
/// Synthetic policy wallet code for one tier: a Wasm module that declares custody layout 4.
fn stand_in_wasm(tier: PolicyTier) -> Vec<u8> {
    let mut meta = 0u32.to_be_bytes().to_vec();
    for text in [b"allowit_custody_layout".as_slice(), b"4"] {
        meta.extend((text.len() as u32).to_be_bytes());
        meta.extend(text);
        meta.resize(meta.len().div_ceil(4) * 4, 0);
    }
    let section = |name: &[u8], body: &[u8]| {
        let mut payload = vec![name.len() as u8];
        payload.extend(name);
        payload.extend(body);
        let mut out = vec![0u8, payload.len() as u8];
        out.extend(payload);
        out
    };
    let mut wasm = b"\0asm\x01\0\0\0".to_vec();
    wasm.extend(section(b"contractmetav0", &meta));
    wasm.extend(section(b"stand_in", tier.kind().as_bytes()));
    wasm
}
fn wasm_for(tier: PolicyTier) -> Vec<u8> {
    let name = match tier {
        PolicyTier::Simple => "allowit_simple_policy_engine",
        PolicyTier::Common => "allowit_common_policy_engine",
        PolicyTier::Custom => "allowit_custom_policy",
    };
    if std::env::var_os("ALLOWIT_UPDATE_VECTORS").is_some() {
        std::fs::read(format!("../../target/wasm32v1-none/release/{name}.wasm"))
            .expect("run scripts/build-contracts.sh before regenerating vectors")
    } else {
        stand_in_wasm(tier)
    }
}

/// The complete workflow of one tier; returns the recorded steps.
fn workflow(tier: PolicyTier) -> Vec<Step> {
    let wasm = wasm_for(tier);
    let module = hash(&wasm);
    let chain = ModelChain::new(BTreeMap::from([(module, tier)]));
    let owner = account_for_seed(&OWNER);
    let deployer = Deployer {
        rpc: &chain,
        network: NETWORK,
        now: NOW,
        max_fee_stroops: MAX_FEE,
    };
    // 1. Upload the tier's wallet code.
    let upload = deployer.upload_wasm(&owner, &wasm).unwrap();
    assert_eq!(upload.wasm_hash, module);
    owner_submit(&chain, "upload", &upload.transaction_xdr);
    // 2. Install: derive the wallet, bind the portable source to the tier and create it.
    let salt = [tier as u8 + 0x11; 32];
    let mut c = WalletConfig {
        network: NETWORK.into(),
        policy_instance: [7; 32],
        wallet: admin::wallet_address(NETWORK, &owner, &salt).unwrap(),
        owner: owner.clone(),
        agent: account_for_seed(&AGENT),
        server: account_for_seed(&SERVER),
        route: WalletRoute::PolicyWallet,
        tier: Some(tier),
        language: PolicyLanguage::Portable,
        rules: policy::tier_rules(tier, SOURCE).unwrap(),
        params: params(),
        source_digest: [0; 32],
        asset: xlm(),
        asset_symbol: "XLM".into(),
        asset_issuer: None,
        policy_source: SOURCE.into(),
        source_hash: hash(SOURCE),
        module_digest: module,
        max_fee_stroops: MAX_FEE,
    };
    c.source_digest =
        policy::installed_source_digest(tier, &module, &c.asset, &c.rules, SOURCE).unwrap();
    let config = PolicyConfig::for_policy(&c, false).unwrap();
    let created = deployer.create_wallet(&config, &wasm, salt).unwrap();
    assert_eq!(created.wallet.as_deref(), Some(c.wallet.as_str()));
    owner_submit(&chain, "create", &created.transaction_xdr);
    chain.fund(1_000_000_000);
    // 3. Discovery reads the live binding, params and state.
    let found = rpc::trusted_state_for_discovery(&chain, &c, None).unwrap();
    assert!(!found.paused);
    assert_eq!(found.state.contract_version, Some(CONTRACT_VERSION));
    // 4. A transfer, priced with server-attested gas in XLM.
    let ledger = chain.0.lock().unwrap().ledger;
    let transfer = request(&c, 1, None, 10_000_000);
    let receipt = run(
        &chain,
        &c,
        &transfer,
        &terms(10_000_000, ledger),
        "transfer",
    )
    .unwrap();
    assert_eq!(receipt.transfer.to, account_for_seed(&RECIPIENT));
    assert!(receipt.deposit.is_none());
    let standard = chain.state().policy_state;
    assert_eq!(standard.get("calls"), Some(&PolicyValue::Int(1)));
    assert_eq!(
        standard.get("spent"),
        Some(&PolicyValue::Int(10_000_000 + i128::from(MAX_FEE)))
    );
    // A transfer over the cap is denied on the host before any signature.
    let ledger = chain.0.lock().unwrap().ledger;
    let over = request(&c, 9, None, 60_000_000);
    assert!(
        rpc::prepare_with(
            &chain,
            &c,
            &over,
            &terms(60_000_000, ledger),
            None,
            NOW,
            NOW + 300
        )
        .unwrap_err()
        .contains("TransactionCapExceeded")
    );
    // 5. A SEP-56 deposit: Simple and Common admit it, Custom's compiled schema does not.
    let ledger = chain.0.lock().unwrap().ledger;
    let deposit = request(&c, 2, Some(5_000_000), 5_000_000);
    let priced = ExecutionTerms {
        args: PolicyParams::default(),
        expense: Some(ExpenseBounds::xlm(0, 0, MAX_FEE, ledger - 1, NOW).unwrap()),
    };
    if tier == PolicyTier::Custom {
        assert!(
            run(&chain, &c, &deposit, &priced, "deposit")
                .unwrap_err()
                .contains("binding")
        );
    } else {
        let receipt = run(&chain, &c, &deposit, &priced, "deposit").unwrap();
        let shares = receipt.deposit.unwrap();
        assert_eq!(
            (shares.vault.as_str(), shares.assets, shares.shares),
            (vault().as_str(), 5_000_000, 5_000_000)
        );
    }
    // 6. The owner pauses and resumes at the next deployment versions.
    let mut owner_admin = Admin::new(OwnerAdmin {
        rpc: &chain,
        config: &c,
        now: NOW,
    });
    let paused = owner_admin.set_pause(true, DeploymentVersion(1)).unwrap();
    owner_submit(&chain, "pause", &paused.transaction_xdr);
    assert!(
        rpc::trusted_state(&chain, &c, None)
            .unwrap_err()
            .contains("paused")
    );
    assert!(
        rpc::trusted_state_for_discovery(&chain, &c, None)
            .unwrap()
            .paused
    );
    let resumed = owner_admin.set_pause(false, DeploymentVersion(2)).unwrap();
    owner_submit(&chain, "resume", &resumed.transaction_xdr);
    // 7. Params update without new code: a lower transaction cap.
    let mut lower = params();
    lower
        .0
        .insert("transaction_cap".into(), PolicyValue::Int(20_000_000));
    let (deployment, check) =
        PolicyDeployment::for_source(&c, SOURCE, lower.clone(), false).unwrap();
    assert!(check.warnings.is_empty());
    let updated = owner_admin
        .deploy_policy(DeploymentVersion(3), deployment)
        .unwrap();
    owner_submit(&chain, "params", &updated.transaction_xdr);
    assert_eq!(chain.state().params, lower);
    let ledger = chain.0.lock().unwrap().ledger;
    let again = request(&c, 3, None, 15_000_000);
    let receipt = run(
        &chain,
        &c,
        &again,
        &terms(15_000_000, ledger),
        "transfer_v3",
    )
    .unwrap();
    assert_eq!(receipt.transfer.deployment_version, 3);
    let ledger = chain.0.lock().unwrap().ledger;
    let blocked = request(&c, 4, None, 25_000_000);
    assert!(
        rpc::prepare_with(
            &chain,
            &c,
            &blocked,
            &terms(25_000_000, ledger),
            None,
            NOW,
            NOW + 300
        )
        .unwrap_err()
        .contains("TransactionCapExceeded")
    );
    // 8. Recovery of part of the balance to the owner.
    let recovered = owner_admin.vendor().config.owner.clone();
    let mut admin = OwnerAdmin {
        rpc: &chain,
        config: &c,
        now: NOW,
    };
    let recovery = admin.recover_to(&recovered, 100_000_000).unwrap();
    owner_submit(&chain, "recover", &recovery.transaction_xdr);
    let model = chain.0.lock().unwrap();
    model.steps.clone()
}

#[test]
fn simple_common_and_custom_wallets_run_the_complete_workflow() {
    let mut lines = vec![
        "# Recorded by stellar/core tests/policy_wallet.rs; executed by crates/policy-wallet/src/core_vectors_tests.rs.".to_string(),
        format!("network {}", hexs(&network_id(NETWORK).unwrap())),
        format!("timestamp {NOW}"),
        format!("ledger {LEDGER}"),
        format!("vault {}", hexs(&address(&vault()).unwrap().to_xdr(Limits::none()).unwrap())),
    ];
    for tier in [PolicyTier::Simple, PolicyTier::Common, PolicyTier::Custom] {
        let steps = workflow(tier);
        let names: Vec<_> = steps.iter().map(|s| s.0.as_str()).collect();
        let mut expected = vec!["upload", "create", "transfer"];
        if tier != PolicyTier::Custom {
            expected.push("deposit");
        }
        expected.extend(["pause", "resume", "params", "transfer_v3", "recover"]);
        assert_eq!(names, expected);
        for (name, envelope, result, state) in steps {
            if name == "upload" {
                continue;
            }
            let x::TransactionEnvelope::Tx(env) = de(&envelope) else {
                panic!()
            };
            lines.push(format!(
                "{} {} {} {} {}",
                tier.kind(),
                name,
                hexs(&env.tx.to_xdr(Limits::none()).unwrap()),
                hexs(&result.to_xdr(Limits::none()).unwrap()),
                hexs(&state.unwrap().to_xdr(Limits::none()).unwrap()),
            ));
        }
    }
    let text = lines.join("\n") + "\n";
    if std::env::var_os("ALLOWIT_UPDATE_VECTORS").is_some() {
        std::fs::write(VECTORS, text).unwrap();
        return;
    }
    // Stand-in code changes module digests, so only the recorded structure is compared here;
    // the contract-side test executes the recorded bytes with the real Wasm.
    let recorded = std::fs::read_to_string(VECTORS).unwrap();
    let shape = |t: &str| {
        t.lines()
            .map(|l| l.split(' ').take(2).collect::<Vec<_>>().join(" "))
            .collect::<Vec<_>>()
    };
    assert_eq!(shape(&recorded), shape(&text));
}

#[test]
fn recorded_vectors_decode_to_the_exact_workflow_packets() {
    // Every recorded transaction is a canonical layout 4 packet that this crate built: the
    // constructor and owner packets decode with the contract encoders, and each execution
    // carries the full source identity of the shared policy source.
    let recorded = std::fs::read_to_string(VECTORS).unwrap();
    let mut executions = 0;
    for line in recorded.lines().filter(|l| !l.starts_with('#')) {
        let parts: Vec<_> = line.split(' ').collect();
        if parts.len() != 5 {
            continue;
        }
        let bytes = (0..parts[2].len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&parts[2][i..i + 2], 16).unwrap())
            .collect::<Vec<_>>();
        let tx = x::Transaction::from_xdr(&bytes, Limits::none()).unwrap();
        let op = host_op(&tx);
        match (&op.host_function, parts[1]) {
            (x::HostFunction::CreateContractV2(args), "create") => {
                admin::validate_auth(NETWORK, &op.host_function, &op.auth, None).unwrap();
                let config = &args.constructor_args[0];
                assert_eq!(
                    PolicyParams::from_scval(field(config, "params")).unwrap(),
                    params()
                );
            }
            (x::HostFunction::InvokeContract(call), name)
                if name.starts_with("transfer") || name == "deposit" =>
            {
                assert_eq!(call.function_name.0.as_slice(), b"execute");
                assert_eq!(digest(field(&call.args[0], "source_hash")), hash(SOURCE));
                assert_eq!(op.auth.len(), 2);
                executions += 1;
            }
            (x::HostFunction::InvokeContract(_), _) => {}
            _ => panic!("unexpected recorded step {}", parts[1]),
        }
    }
    assert_eq!(executions, 8);
}
