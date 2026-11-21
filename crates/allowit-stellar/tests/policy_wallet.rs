//! End-to-end policy wallet workflows of all three tiers through the public API, against a
//! model Stellar RPC: code upload by the server, the owner's one creation and funding through the
//! deployer, discovery, transfer, deposit, redeem, pause, params update, recovery and the stop.
//! The run records `fixtures/policy-wallet-vectors.txt`, which
//! `crates/policy-wallet/src/core_vectors_tests.rs` executes on the Soroban host with the real
//! wallet and deployer Wasm.
//!
//! Regenerate after a contract or encoding change: run `scripts/build-contracts.sh`, then
//! `ALLOWIT_UPDATE_VECTORS=1 cargo test --test policy_wallet` in `crates/allowit-stellar`.
use allowit_core::AllowitTier;
use allowit_core::admin::{Admin, DeploymentVersion};
use allowit_stellar::admin::*;
use allowit_stellar::packed::{self, CALLS, DAY_SPENT, DAY_TOTAL, SPENT};
use allowit_stellar::workflow::*;
use allowit_stellar::*;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
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
/// The server's sending account: the source of every agent operation, which pays its fee and
/// receives the wallet's gas repayment. It also uploads the wallet code.
const SENDER: [u8; 32] = [10; 32];
/// The installed fee ceiling and the owner-signed gas cap.
const MAX_FEE: u32 = 1_000_000;
/// The resource fee of a recording simulation.
const RECORD_FEE: i64 = 1_500;
/// The resource fee of the sending account's enforcing simulation.
const ENFORCE_FEE: i64 = 1_000;
/// The resource fee of a code restoration in the model.
const RENEW_FEE: i64 = 4_000;
/// The XLM that the owner's creation moves into the wallet.
const FUNDING: i128 = 500_000_000;
const DAY_LEDGERS: u32 = 17_280;
const SOURCE: &str = include_str!("../../../contracts/allowit-custom-policy/policy/policy.rs");
const VECTORS: &str = "tests/fixtures/policy-wallet-vectors.txt";

fn vault() -> String {
    Contract([0x56; 32]).to_string()
}
fn xlm() -> String {
    sac_address(NETWORK, &x::Asset::Native).unwrap()
}
fn deployer() -> String {
    admin::deployer_address(NETWORK).unwrap()
}
fn sender() -> String {
    account_for_seed(&SENDER)
}
/// The gas that a wallet repays and counts for one operation: the fee bound of the recording
/// simulation's resource fee.
fn gas() -> i128 {
    i128::from(fee_bound(RECORD_FEE).unwrap())
}
fn b64<T: WriteXdr>(v: &T) -> String {
    v.to_xdr_base64(Limits::none()).unwrap()
}
fn de<T: ReadXdr>(v: &str) -> T {
    T::from_xdr_base64(v, Limits::none()).unwrap()
}
fn unhexs(text: &str) -> [u8; 32] {
    let bytes: Vec<u8> = (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect();
    bytes.try_into().unwrap()
}
fn hexs(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn items(v: &x::ScVal) -> &[x::ScVal] {
    let x::ScVal::Vec(Some(v)) = v else { panic!() };
    v.as_slice()
}
fn field<'a>(v: &'a x::ScVal, name: &str) -> &'a x::ScVal {
    let x::ScVal::Map(Some(m)) = v else { panic!() };
    &m.iter()
        .find(|e| matches!(&e.key, x::ScVal::Symbol(s) if s.0.as_slice() == name.as_bytes()))
        .unwrap()
        .val
}
fn symbol(v: &x::ScVal) -> String {
    let x::ScVal::Symbol(s) = v else { panic!() };
    String::from_utf8(s.0.to_vec()).unwrap()
}
fn int(v: &x::ScVal) -> i128 {
    let x::ScVal::I128(p) = v else { panic!() };
    (i128::from(p.hi) << 64) | i128::from(p.lo)
}
fn wide(v: i128) -> x::ScVal {
    x::ScVal::I128(x::Int128Parts {
        hi: (v >> 64) as i64,
        lo: v as u64,
    })
}
fn addr(v: &x::ScVal) -> String {
    let x::ScVal::Address(a) = v else { panic!() };
    address_text(a).unwrap()
}
fn digest(v: &x::ScVal) -> [u8; 32] {
    let x::ScVal::Bytes(b) = v else { panic!() };
    b.as_slice().try_into().unwrap()
}
fn bytes(v: &[u8]) -> x::ScVal {
    x::ScVal::Bytes(x::ScBytes(v.to_vec().try_into().unwrap()))
}
fn sc_map(fields: Vec<(&str, x::ScVal)>) -> x::ScVal {
    let mut entries: Vec<_> = fields
        .into_iter()
        .map(|(name, val)| x::ScMapEntry {
            key: x::ScVal::Symbol(x::ScSymbol(name.as_bytes().to_vec().try_into().unwrap())),
            val,
        })
        .collect();
    entries.sort_by(|a, b| a.key.cmp(&b.key));
    x::ScVal::Map(Some(entries.try_into().unwrap()))
}
fn leb(mut v: u128, out: &mut Vec<u8>) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// (name, signed envelope, settlement ledger, host result, wallet state after it)
type Step = (String, String, u32, x::ScVal, Option<x::ScVal>);
/// What the wallet stores besides its configuration, as the kernel writes it.
#[derive(Clone, Debug, Default, PartialEq)]
struct Stored {
    /// `t`: spent, calls and the unpriced flag.
    total: Option<(u64, u32, bool)>,
    /// `d`: end ledger, kept daily set, unpriced flag, day spent and day total.
    daily: Option<(u32, u8, bool, i128, i128)>,
}
/// The wallet a model chain holds.
struct Wallet {
    address: String,
    tier: PolicyTier,
    config: packed::Configuration,
    stored: Stored,
    /// The server's account of every execution, from its receipts: every standard figure, as
    /// Core's post-flight computes it.
    served: packed::Figures,
    /// XLM: the asset, and the gas the wallet repays.
    balance: i128,
    shares: i128,
}
/// The figures that the wallet's checks read: the standard rules with their params set, or the
/// figures the Custom build finds in its source.
fn kept(tier: PolicyTier, c: &packed::Configuration) -> u8 {
    if tier == PolicyTier::Custom {
        custom_figures(SOURCE)
    } else {
        packed::standard_kept(&c.rules, &c.params)
    }
}
/// The Custom build's scan of the source (`contracts/allowit-custom-policy/build.rs`): the
/// figures of each limit rule it names, or all of them when it reads the whole state.
fn custom_figures(source: &str) -> u8 {
    let words: BTreeSet<&str> = source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .flat_map(|line| line.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')))
        .filter(|word| !word.is_empty())
        .collect();
    if words.iter().any(|word| {
        word.contains("state")
            || [
                "preflight",
                "RULES",
                "AllowitRule",
                "AllowitStandardState",
                "evaluate",
            ]
            .contains(word)
    }) {
        return SPENT | CALLS | DAY_SPENT | DAY_TOTAL;
    }
    [
        ("lifetime_spending_limit", SPENT),
        ("call_limit", CALLS),
        ("daily_spending_limit", DAY_SPENT),
        ("daily_volume_limit", DAY_TOTAL),
    ]
    .iter()
    .filter(|(word, _)| words.contains(word))
    .fold(0, |kept, (_, figure)| kept | figure)
}
impl Wallet {
    fn kept(&self) -> u8 {
        kept(self.tier, &self.config)
    }
    /// The figures that `kept` reads at `ledger`, as the kernel's `read_figures` reads them.
    fn figures(&self, kept: u8, ledger: u32) -> packed::Figures {
        let mut f = packed::Figures::default();
        if kept & (SPENT | CALLS) != 0
            && let Some((spent, calls, unpriced)) = self.stored.total
        {
            if kept & SPENT != 0 {
                f.spent = i128::from(spent);
                f.unpriced = unpriced;
            }
            if kept & CALLS != 0 {
                f.calls = u64::from(calls);
            }
        }
        if kept & (DAY_SPENT | DAY_TOTAL) != 0
            && let Some((end, mask, unpriced, day_spent, day_total)) = self.stored.daily
            && ledger <= end
        {
            f.day_ends = end;
            f.day_unpriced = unpriced;
            if mask & DAY_SPENT != 0 {
                f.day_spent = day_spent;
            }
            if mask & DAY_TOTAL != 0 {
                f.day_total = day_total;
            }
        }
        f
    }
    fn write_total(&mut self, kept: u8, f: &packed::Figures) {
        let spent = kept & SPENT != 0;
        self.stored.total = Some((
            if spent { f.spent as u64 } else { 0 },
            if kept & CALLS != 0 { f.calls as u32 } else { 0 },
            spent && f.unpriced,
        ));
    }
    fn t_bytes(&self) -> Option<Vec<u8>> {
        let (spent, calls, unpriced) = self.stored.total?;
        let mut out = spent.to_be_bytes().to_vec();
        out.extend((calls | if unpriced { 1 << 31 } else { 0 }).to_be_bytes());
        Some(out)
    }
    fn d_bytes(&self) -> Option<Vec<u8>> {
        let (end, mask, unpriced, day_spent, day_total) = self.stored.daily?;
        let mut out = end.to_be_bytes().to_vec();
        out.push(mask);
        out.push(u8::from(unpriced));
        if mask & DAY_SPENT != 0 {
            leb(day_spent as u128, &mut out);
        }
        if mask & DAY_TOTAL != 0 {
            leb(day_total as u128, &mut out);
        }
        Some(out)
    }
    /// The wallet's `state` view at `ledger`.
    fn view(&self, ledger: u32) -> x::ScVal {
        let c = &self.config;
        let kept = self.kept();
        let f = self.figures(kept, ledger);
        sc_map(vec![
            ("contract_version", x::ScVal::U32(u32::from(packed::LAYOUT))),
            ("owner", x::ScVal::Address(address(&c.owner).unwrap())),
            ("agent", bytes(&account_key(&c.agent).unwrap())),
            ("server", bytes(&account_key(&c.server).unwrap())),
            ("asset", x::ScVal::Address(address(&c.asset).unwrap())),
            ("deployment_version", x::ScVal::U32(c.deployment_version)),
            ("paused", x::ScVal::Bool(c.paused)),
            ("source_hash", bytes(&c.source_hash)),
            ("gas_cap", wide(c.gas_cap)),
            ("kept", x::ScVal::U32(u32::from(kept))),
            ("rules", policy::rules_scval(&c.rules).unwrap()),
            ("params", c.params.scval().unwrap()),
            (
                "figures",
                sc_map(vec![
                    ("calls", x::ScVal::U64(f.calls)),
                    ("spent", wide(f.spent)),
                    ("unpriced", x::ScVal::Bool(f.unpriced)),
                    ("day_spent", wide(f.day_spent)),
                    ("day_total", wide(f.day_total)),
                    ("day_unpriced", x::ScVal::Bool(f.day_unpriced)),
                    ("day_ends", x::ScVal::U32(f.day_ends)),
                ]),
            ),
        ])
    }
}
/// A Standard wallet keeps only the params of its rules.
fn installed_params(tier: PolicyTier, rules: &[String], params: &PolicyParams) -> PolicyParams {
    if tier == PolicyTier::Custom {
        return params.clone();
    }
    PolicyParams(
        params
            .0
            .iter()
            .filter(|(key, _)| rules.contains(key))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
    )
}
#[derive(Default)]
struct Model {
    ledger: u32,
    now: u64,
    accounts: BTreeMap<String, AccountState>,
    code: BTreeMap<[u8; 32], PolicyTier>,
    /// The uploaded code by its hash.
    code_bytes: BTreeMap<[u8; 32], Vec<u8>>,
    /// Uploaded code past its lifetime: Stellar RPC serves it with a live-until ledger of 0, an
    /// upload of it fails, and nothing renews it.
    lapsed_code: BTreeSet<[u8; 32]>,
    /// The live-until ledger of uploaded code, when not the head and 10,000 ledgers.
    code_live_until: BTreeMap<[u8; 32], u32>,
    /// The network's minimum lifetime of a persistent entry, when not 120,960 ledgers.
    persistent_lifetime: Option<u32>,
    /// The next renewals fail when the ledger applies them: the code keeps its lifetime and the
    /// source still pays the fee.
    failing_renewal: bool,
    /// The transactions that the ledger included and failed.
    failed: BTreeSet<String>,
    /// The fee that the next receipts report as charged, when not the usual 100 stroops.
    charged_fee: Option<i64>,
    /// An upload simulation of lapsed code restores the code entry in place instead of failing.
    upload_restores_in_place: bool,
    /// A read that finds no entry omits the entry list.
    omit_empty_entries: bool,
    /// Reads of code entries fail, as a broken transport does.
    failing_code_reads: bool,
    /// Another transaction uploads the code of the next upload just before its simulation.
    uploaded_meanwhile: bool,
    /// The next upload simulations also write another entry than the code.
    upload_names_another_entry: bool,
    /// Another sending account renews the code just after the next renewal's simulation.
    renewed_after_simulation: bool,
    /// Another sending account uploads the code just after the next upload's simulation.
    uploaded_after_simulation: bool,
    /// The upload of `uploaded_meanwhile` came from the upload's own source, whose sequence it
    /// advanced.
    uploaded_by_source: bool,
    tiers: BTreeMap<[u8; 32], PolicyTier>,
    wallet: Option<Wallet>,
    settled: BTreeMap<String, String>,
    steps: Vec<Step>,
    /// The next submission is not accepted (`TRY_AGAIN_LATER`) while another account uploads
    /// this code.
    retry_later_uploads: Option<(Vec<u8>, PolicyTier)>,
    /// The network rejects the next submission.
    reject_next_send: bool,
    /// The endpoint serves another network.
    foreign_network: bool,
    /// Every contract instance is past its lifetime: the RPC serves it with a live-until ledger
    /// of 0.
    lapsed_instances: bool,
    /// The code that the wallet's instance runs, when its owner installed other code outside
    /// Allowit; its tier's code otherwise.
    running: Option<[u8; 32]>,
    /// The ledger holds each settled transaction inside a fee bump of another source.
    fee_bumped: bool,
    pending_name: String,
    /// The resource fee of the next enforcing simulations.
    enforce_fee: i64,
    /// The wallet's consumed authorization nonces.
    nonces: BTreeSet<i64>,
    /// The wallet's `allowit` events: ledger, operation id and transaction hash.
    events: Vec<(u32, x::ScVal, String)>,
}
/// A model of Stellar RPC, the deployer and the layout 5 wallet. It records authorization like
/// Stellar RPC, verifies the agent's and the server's signatures where the wallet's
/// `__check_auth` runs, applies settled effects and computes the kept figures with Core's
/// post-flight, as the kernel does.
struct ModelChain(Mutex<Model>);
impl ModelChain {
    fn new(tiers: BTreeMap<[u8; 32], PolicyTier>) -> Self {
        let mut model = Model {
            ledger: LEDGER,
            now: NOW,
            tiers,
            enforce_fee: ENFORCE_FEE,
            ..Default::default()
        };
        for seed in [OWNER, AGENT, SERVER, RECIPIENT, SENDER, [51; 32]] {
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
    /// Another sending account renewed the code `code`: it lives the network's minimum lifetime of
    /// a persistent entry from the head.
    fn renewed(&self, code: [u8; 32]) {
        let mut m = self.0.lock().unwrap();
        let until = m.ledger + m.persistent_lifetime.unwrap_or(120_960);
        m.code_live_until.insert(code, until);
    }
    fn step(&self, name: &str) {
        self.0.lock().unwrap().pending_name = name.into();
    }
    fn ledger(&self) -> u32 {
        self.0.lock().unwrap().ledger
    }
    /// The server's accounting of the wallet: the figures of every execution, which a Simple
    /// or Common wallet does not keep.
    fn accounting(&self) -> rpc::NativeAccounting {
        let m = self.0.lock().unwrap();
        let f = m
            .wallet
            .as_ref()
            .map(|w| w.served.clone())
            .unwrap_or_default();
        rpc::NativeAccounting {
            spent_daily: f.day_spent,
            spent_total: f.spent,
            spent_day: NOW / 86_400,
            volume_daily: f.day_total,
            unpriced_total: f.unpriced,
            unpriced_daily: f.day_unpriced,
            calls: f.calls,
            ..Default::default()
        }
    }
    fn figures(&self) -> packed::Figures {
        let m = self.0.lock().unwrap();
        let w = m.wallet.as_ref().unwrap();
        w.figures(w.kept(), m.ledger)
    }
    fn config(&self) -> packed::Configuration {
        self.0
            .lock()
            .unwrap()
            .wallet
            .as_ref()
            .unwrap()
            .config
            .clone()
    }
    fn balance(&self) -> i128 {
        self.0.lock().unwrap().wallet.as_ref().unwrap().balance
    }
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
fn tx_hash(tx: &x::Transaction) -> [u8; 32] {
    hash(
        x::TransactionSignaturePayload {
            network_id: x::Hash(network_id(NETWORK).unwrap()),
            tagged_transaction: x::TransactionSignaturePayloadTaggedTransaction::Tx(tx.clone()),
        }
        .to_xdr(Limits::none())
        .unwrap(),
    )
}
/// The owner's authorization tree of `deployer.deploy`: the creation with its constructor, then
/// one transfer per funding item.
fn deploy_tree(call: &x::InvokeContractArgs) -> (String, Vec<x::SorobanAuthorizedInvocation>) {
    let [owner, wasm, salt, constructor, funding] = call.args.as_slice() else {
        panic!()
    };
    let owner = addr(owner);
    let salt = digest(salt);
    let wallet = admin::wallet_address(NETWORK, &owner, &salt).unwrap();
    let args: x::VecM<x::ScVal> = items(constructor).to_vec().try_into().unwrap();
    let create = x::CreateContractArgsV2 {
        contract_id_preimage: x::ContractIdPreimage::Address(x::ContractIdPreimageFromAddress {
            address: address(&owner).unwrap(),
            salt: x::Uint256(salt),
        }),
        executable: x::ContractExecutable::Wasm(x::Hash(digest(wasm))),
        constructor_args: args.clone(),
    };
    let mut subs = vec![x::SorobanAuthorizedInvocation {
        function: x::SorobanAuthorizedFunction::CreateContractV2HostFn(create),
        sub_invocations: vec![x::SorobanAuthorizedInvocation {
            function: x::SorobanAuthorizedFunction::ContractFn(x::InvokeContractArgs {
                contract_address: address(&wallet).unwrap(),
                function_name: x::ScSymbol(b"__constructor".to_vec().try_into().unwrap()),
                args,
            }),
            sub_invocations: Default::default(),
        }]
        .try_into()
        .unwrap(),
    }];
    for item in items(funding) {
        let [asset, amount] = items(item) else {
            panic!()
        };
        subs.push(x::SorobanAuthorizedInvocation {
            function: x::SorobanAuthorizedFunction::ContractFn(x::InvokeContractArgs {
                contract_address: address(&addr(asset)).unwrap(),
                function_name: x::ScSymbol(b"transfer".to_vec().try_into().unwrap()),
                args: vec![
                    x::ScVal::Address(address(&owner).unwrap()),
                    x::ScVal::Address(address(&wallet).unwrap()),
                    amount.clone(),
                ]
                .try_into()
                .unwrap(),
            }),
            sub_invocations: Default::default(),
        });
    }
    (wallet, subs)
}
/// The agent's and the server's signatures in the wallet's entry, checked against its payload.
fn verify_cosignatures(m: &Model, entry: &x::SorobanAuthorizationEntry) -> Result<()> {
    let w = m.wallet.as_ref().ok_or("no wallet")?;
    let x::SorobanCredentials::Address(c) = &entry.credentials else {
        return Err("the wallet authorizes with address credentials".into());
    };
    if c.address != address(&w.address)? {
        return Err("another address".into());
    }
    if m.nonces.contains(&c.nonce) {
        return Err("nonce already used".into());
    }
    if c.signature_expiration_ledger < m.ledger {
        return Err("signature expired".into());
    }
    let payload = hash(
        x::HashIdPreimage::SorobanAuthorization(x::HashIdPreimageSorobanAuthorization {
            network_id: x::Hash(network_id(NETWORK)?),
            nonce: c.nonce,
            signature_expiration_ledger: c.signature_expiration_ledger,
            invocation: entry.root_invocation.clone(),
        })
        .to_xdr(Limits::none())
        .unwrap(),
    );
    let parts = items(&c.signature);
    if parts.len() != 2 {
        return Err("two cosignatures".into());
    }
    for (part, key) in parts.iter().zip([&w.config.agent, &w.config.server]) {
        let x::ScVal::Bytes(sig) = part else {
            return Err("a cosignature is bytes".into());
        };
        let sig =
            ed25519_dalek::Signature::from_slice(sig.as_slice()).map_err(|e| e.to_string())?;
        VerifyingKey::from_bytes(&account_key(key)?)
            .unwrap()
            .verify(&payload, &sig)
            .map_err(|_| "invalid cosignature".to_string())?;
    }
    Ok(())
}
impl rpc::Rpc for ModelChain {
    fn call(&self, method: &str, params: Value) -> Result<Value> {
        let mut m = self.0.lock().unwrap();
        match method {
            "getNetwork" => Ok(json!({"passphrase": passphrase(if m.foreign_network {
                "stellar:pubnet"
            } else {
                NETWORK
            })?})),
            "getLatestLedger" => Ok(json!({"sequence": m.ledger})),
            "getLedgerEntries" => {
                let mut entries: Vec<Value> = Vec::new();
                for encoded in params["keys"].as_array().unwrap() {
                    let encoded = encoded.as_str().unwrap();
                    let key: x::LedgerKey = de(encoded);
                    if m.failing_code_reads && matches!(key, x::LedgerKey::ContractCode(_)) {
                        return Err("The RPC is unreachable".into());
                    }
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
                            let val = match &data.key {
                                x::ScVal::LedgerKeyContractInstance => {
                                    x::ScVal::ContractInstance(x::ScContractInstance {
                                        executable: x::ContractExecutable::Wasm(x::Hash(
                                            m.running.unwrap_or(
                                                *m.code
                                                    .iter()
                                                    .find(|(_, tier)| **tier == w.tier)
                                                    .unwrap()
                                                    .0,
                                            ),
                                        )),
                                        storage: Some(
                                            vec![x::ScMapEntry {
                                                key: x::ScVal::Symbol(x::ScSymbol(
                                                    b"c".to_vec().try_into().unwrap(),
                                                )),
                                                val: bytes(&packed::encode(&w.config).unwrap()),
                                            }]
                                            .try_into()
                                            .unwrap(),
                                        ),
                                    })
                                }
                                x::ScVal::Symbol(s)
                                    if s.0.as_slice() == b"t"
                                        && data.durability
                                            == x::ContractDataDurability::Persistent =>
                                {
                                    bytes(&w.t_bytes()?)
                                }
                                x::ScVal::Symbol(s)
                                    if s.0.as_slice() == b"d"
                                        && data.durability
                                            == x::ContractDataDurability::Temporary =>
                                {
                                    // A temporary entry lives through its window's end ledger.
                                    if m.ledger > w.stored.daily?.0 {
                                        return None;
                                    }
                                    bytes(&w.d_bytes()?)
                                }
                                _ => return None,
                            };
                            Some(x::LedgerEntryData::ContractData(x::ContractDataEntry {
                                ext: x::ExtensionPoint::V0,
                                contract: data.contract.clone(),
                                key: data.key.clone(),
                                durability: data.durability,
                                val,
                            }))
                        }),
                        x::LedgerKey::ConfigSetting(x::LedgerKeyConfigSetting {
                            config_setting_id: x::ConfigSettingId::StateArchival,
                        }) => Some(x::LedgerEntryData::ConfigSetting(
                            x::ConfigSettingEntry::StateArchival(x::StateArchivalSettings {
                                max_entry_ttl: 3_110_400,
                                min_persistent_ttl: m.persistent_lifetime.unwrap_or(120_960),
                                ..Default::default()
                            }),
                        )),
                        x::LedgerKey::ContractCode(code) => {
                            m.code_bytes.get(&code.hash.0).map(|bytes| {
                                x::LedgerEntryData::ContractCode(x::ContractCodeEntry {
                                    ext: x::ContractCodeEntryExt::V0,
                                    hash: code.hash.clone(),
                                    code: bytes.clone().try_into().unwrap(),
                                })
                            })
                        }
                        _ => None,
                    };
                    let live_until = match &key {
                        x::LedgerKey::ContractCode(code)
                            if m.lapsed_code.contains(&code.hash.0) =>
                        {
                            0
                        }
                        x::LedgerKey::ContractCode(code) => m
                            .code_live_until
                            .get(&code.hash.0)
                            .copied()
                            .unwrap_or(m.ledger + 10_000),
                        x::LedgerKey::ContractData(x::LedgerKeyContractData {
                            key: x::ScVal::LedgerKeyContractInstance,
                            ..
                        }) if m.lapsed_instances => 0,
                        _ => m.ledger + 10_000,
                    };
                    entries.extend(entry.into_iter().map(
                    |e| json!({"key": encoded, "xdr": b64(&e), "lastModifiedLedgerSeq": 1, "liveUntilLedgerSeq": live_until}),
                ));
                }
                if entries.is_empty() && m.omit_empty_entries {
                    return Ok(json!({"latestLedger": m.ledger}));
                }
                Ok(json!({"latestLedger": m.ledger, "entries": entries}))
            }
            "simulateTransaction" => {
                let x::TransactionEnvelope::Tx(env) = de(params["transaction"].as_str().unwrap())
                else {
                    panic!()
                };
                if let x::OperationBody::ExtendFootprintTtl(_) = &env.tx.operations[0].body {
                    let x::TransactionExt::V1(data) = &env.tx.ext else {
                        return Ok(json!({"error": "a renewal names its footprint"}));
                    };
                    let codes: Vec<[u8; 32]> = data
                        .resources
                        .footprint
                        .read_only
                        .iter()
                        .filter_map(|key| match key {
                            x::LedgerKey::ContractCode(code) => Some(code.hash.0),
                            _ => None,
                        })
                        .collect();
                    if codes.iter().any(|code| m.lapsed_code.contains(code)) {
                        return Ok(json!({
                            "latestLedger": m.ledger,
                            "error": "trying to extend an archived entry",
                        }));
                    }
                    if std::mem::take(&mut m.renewed_after_simulation) {
                        let until = m.ledger + m.persistent_lifetime.unwrap_or(120_960);
                        for code in codes {
                            m.code_live_until.insert(code, until);
                        }
                    }
                    let data = x::SorobanTransactionData {
                        resource_fee: RENEW_FEE,
                        ..data.clone()
                    };
                    return Ok(json!({
                        "latestLedger": m.ledger,
                        "minResourceFee": RENEW_FEE.to_string(),
                        "transactionData": b64(&data),
                    }));
                }
                let op = host_op(&env.tx);
                if let x::HostFunction::UploadContractWasm(code) = &op.host_function
                    && m.lapsed_code.contains(&hash(code.as_slice()))
                {
                    if !m.upload_restores_in_place {
                        return Ok(
                            json!({"error": "trying to access an archived contract code entry"}),
                        );
                    }
                    // A simulation that restores the archived code entry in the upload's own
                    // transaction.
                    let code_hash = hash(code.as_slice());
                    let key = x::LedgerKey::ContractCode(x::LedgerKeyContractCode {
                        hash: x::Hash(code_hash),
                    });
                    let data = x::SorobanTransactionData {
                        ext: x::SorobanTransactionDataExt::V1(x::SorobanResourcesExtV0 {
                            archived_soroban_entries: vec![0].try_into().unwrap(),
                        }),
                        resources: x::SorobanResources {
                            footprint: x::LedgerFootprint {
                                read_only: Default::default(),
                                read_write: vec![key].try_into().unwrap(),
                            },
                            instructions: 0,
                            disk_read_bytes: 0,
                            write_bytes: 0,
                        },
                        resource_fee: RECORD_FEE,
                    };
                    return Ok(json!({
                        "latestLedger": m.ledger,
                        "minResourceFee": RECORD_FEE.to_string(),
                        "transactionData": b64(&data),
                        "results": [{"xdr": b64(&bytes(&code_hash)), "auth": []}],
                    }));
                }
                let source = source_of(&env.tx);
                let record = params["authMode"] == "record";
                if record && !op.auth.is_empty() {
                    return Ok(
                        json!({"error": "cannot set authMode to 'record' with an auth footprint"}),
                    );
                }
                let entry = |who: &str, root: x::SorobanAuthorizedFunction, subs| {
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
                            function: root,
                            sub_invocations: subs,
                        },
                    }
                };
                let mut wallet_call = false;
                let mut footprint = x::LedgerFootprint::default();
                let (result, required): (x::ScVal, Vec<x::SorobanAuthorizationEntry>) = match &op
                    .host_function
                {
                    x::HostFunction::UploadContractWasm(code) => {
                        let code_hash = hash(code.as_slice());
                        if m.uploaded_meanwhile {
                            m.uploaded_meanwhile = false;
                            let tier = m.tiers[&code_hash];
                            m.code.insert(code_hash, tier);
                            m.code_bytes.insert(code_hash, code.to_vec());
                            if m.uploaded_by_source {
                                m.accounts.get_mut(&source).unwrap().sequence += 1;
                            }
                        }
                        // As the host: an upload reads the entry of code that the network holds
                        // and writes it otherwise.
                        let key: x::VecM<x::LedgerKey> =
                            vec![x::LedgerKey::ContractCode(x::LedgerKeyContractCode {
                                hash: x::Hash(code_hash),
                            })]
                            .try_into()
                            .unwrap();
                        if m.code_bytes.contains_key(&code_hash) {
                            footprint.read_only = key;
                        } else {
                            footprint.read_write = key;
                        }
                        if m.uploaded_after_simulation {
                            m.uploaded_after_simulation = false;
                            let tier = m.tiers[&code_hash];
                            m.code.insert(code_hash, tier);
                            m.code_bytes.insert(code_hash, code.to_vec());
                        }
                        if m.upload_names_another_entry {
                            let mut written = footprint.read_write.to_vec();
                            written.push(x::LedgerKey::ContractCode(x::LedgerKeyContractCode {
                                hash: x::Hash([0x5b; 32]),
                            }));
                            footprint.read_write = written.try_into().unwrap();
                        }
                        (bytes(&code_hash), vec![])
                    }
                    x::HostFunction::InvokeContract(call)
                        if call.contract_address == address(&deployer())? =>
                    {
                        assert_eq!(call.function_name.0.as_slice(), b"deploy");
                        let (wallet, subs) = deploy_tree(call);
                        if !m.code.contains_key(&digest(&call.args[1])) {
                            return Ok(json!({"error": "the code is not uploaded"}));
                        }
                        (
                            x::ScVal::Address(address(&wallet)?),
                            vec![entry(
                                &addr(&call.args[0]),
                                x::SorobanAuthorizedFunction::ContractFn(call.clone()),
                                subs.try_into().unwrap(),
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
                            return Ok(json!({"results":[{"xdr": b64(&wide(w.balance))}]}));
                        }
                        wallet_call = true;
                        let owner = w.config.owner.clone();
                        match function.as_str() {
                            "execute" => {
                                if w.config.paused {
                                    return Ok(json!({"error": "HostError: Error(Contract, #6)"}));
                                }
                                let wallet = w.address.clone();
                                (
                                    x::ScVal::Void,
                                    vec![entry(&wallet, root, Default::default())],
                                )
                            }
                            "deploy_policy" => {
                                let next = addr(field(&call.args[0], "owner"));
                                let mut auth =
                                    vec![entry(&owner, root.clone(), Default::default())];
                                if next != owner {
                                    auth.push(entry(&next, root, Default::default()));
                                }
                                (x::ScVal::Void, auth)
                            }
                            "set_pause" | "recover" | "stop" => (
                                x::ScVal::Void,
                                vec![entry(&owner, root, Default::default())],
                            ),
                            other => panic!("unexpected wallet call {other}"),
                        }
                    }
                    _ => panic!(),
                };
                let auth = if record || op.auth.is_empty() {
                    required
                } else {
                    for need in &required {
                        let present =
                            op.auth
                                .iter()
                                .any(|e| match (&e.credentials, &need.credentials) {
                                    (
                                        x::SorobanCredentials::SourceAccount,
                                        x::SorobanCredentials::SourceAccount,
                                    ) => true,
                                    (
                                        x::SorobanCredentials::Address(c),
                                        x::SorobanCredentials::Address(n),
                                    ) => c.address == n.address && c.signature != x::ScVal::Void,
                                    _ => false,
                                });
                        if !present {
                            return Ok(
                                json!({"error": "require_auth has no matching signed entry"}),
                            );
                        }
                    }
                    // The wallet's `__check_auth` runs in enforce mode.
                    if wallet_call
                        && let x::HostFunction::InvokeContract(call) = &op.host_function
                        && call.function_name.0.as_slice() == b"execute"
                        && let Err(e) = verify_cosignatures(&m, &op.auth[0])
                    {
                        return Ok(json!({ "error": e }));
                    }
                    op.auth.to_vec()
                };
                let fee = if record { RECORD_FEE } else { m.enforce_fee };
                Ok(json!({
                    "latestLedger": m.ledger,
                    "minResourceFee": fee.to_string(),
                    "transactionData": b64(&x::SorobanTransactionData {
                        resource_fee: fee,
                        resources: x::SorobanResources { footprint, ..Default::default() },
                        ..Default::default()
                    }),
                    "results": [{"xdr": b64(&result), "auth": auth.iter().map(b64).collect::<Vec<_>>()}],
                }))
            }
            "sendTransaction" => {
                let signed = params["transaction"].as_str().unwrap().to_string();
                let x::TransactionEnvelope::Tx(env) = de(&signed) else {
                    panic!()
                };
                let digest = tx_hash(&env.tx);
                let tx_hash = hexs(&digest);
                if std::mem::take(&mut m.reject_next_send) {
                    return Ok(
                        json!({"hash": tx_hash, "status": "ERROR", "errorResultXdr": "AAAAAAAAAGT////7AAAAAA=="}),
                    );
                }
                if m.settled.contains_key(&tx_hash) {
                    return Ok(json!({"hash": tx_hash, "status": "DUPLICATE"}));
                }
                if let Some((wasm, tier)) = m.retry_later_uploads.take() {
                    m.code.insert(hash(&wasm), tier);
                    m.code_bytes.insert(hash(&wasm), wasm);
                    return Ok(json!({"hash": tx_hash, "status": "TRY_AGAIN_LATER"}));
                }
                // The source signs alone.
                let source = source_of(&env.tx);
                let [signature] = env.signatures.as_slice() else {
                    panic!("one source signature")
                };
                VerifyingKey::from_bytes(&account_key(&source)?)
                    .unwrap()
                    .verify(
                        &digest,
                        &ed25519_dalek::Signature::from_slice(signature.signature.as_slice())
                            .unwrap(),
                    )
                    .expect("the source's signature");
                let account = m.accounts.get_mut(&source).unwrap();
                assert_eq!(env.tx.seq_num.0, account.sequence + 1, "sequence");
                account.sequence += 1;
                let ledger = m.ledger;
                if let x::OperationBody::ExtendFootprintTtl(op) = &env.tx.operations[0].body {
                    let x::TransactionExt::V1(data) = &env.tx.ext else {
                        panic!("a renewal names its footprint")
                    };
                    for key in data.resources.footprint.read_only.iter() {
                        let x::LedgerKey::ContractCode(code) = key else {
                            panic!("the model renews code only")
                        };
                        assert!(
                            !m.lapsed_code.contains(&code.hash.0),
                            "renewal of lapsed code"
                        );
                        if !m.failing_renewal {
                            m.code_live_until.insert(code.hash.0, ledger + op.extend_to);
                        }
                    }
                    if m.failing_renewal {
                        m.failed.insert(tx_hash.clone());
                    }
                    let name = std::mem::take(&mut m.pending_name);
                    m.steps
                        .push((name, signed.clone(), ledger, x::ScVal::Void, None));
                    m.settled.insert(tx_hash.clone(), signed);
                    m.ledger += 1;
                    return Ok(json!({"hash": tx_hash, "status": "PENDING"}));
                }
                let result = apply(&mut m, &env.tx);
                // An execution publishes `allowit` with its operation id.
                if let x::HostFunction::InvokeContract(call) = &host_op(&env.tx).host_function
                    && call.function_name.0.as_slice() == b"execute"
                {
                    m.events
                        .push((ledger, items(&call.args[0])[0].clone(), tx_hash.clone()));
                }
                let name = std::mem::take(&mut m.pending_name);
                let state = m.wallet.as_ref().map(|w| w.view(ledger));
                m.steps.push((name, signed.clone(), ledger, result, state));
                m.settled.insert(tx_hash.clone(), signed);
                m.ledger += 1;
                Ok(json!({"hash": tx_hash, "status": "PENDING"}))
            }
            "getEvents" => {
                // A page after a cursor starts at the ledger after it; one page scans every
                // ledger up to the head.
                let start = match params["pagination"]["cursor"].as_str() {
                    Some(cursor) => {
                        let toid: u64 = cursor.split_once('-').unwrap().0.parse().unwrap();
                        ((toid >> 32) + 1) as u32
                    }
                    None => params["startLedger"].as_u64().unwrap() as u32,
                };
                let filter = &params["filters"][0];
                let wallet = m.wallet.as_ref().map(|w| w.address.clone());
                assert_eq!(filter["contractIds"][0].as_str(), wallet.as_deref());
                let topics = &filter["topics"][0];
                assert_eq!(
                    topics[0],
                    json!(b64(&x::ScVal::Symbol("allowit".try_into().unwrap())))
                );
                let events: Vec<Value> = m
                    .events
                    .iter()
                    .filter(|(ledger, id, _)| *ledger >= start && json!(b64(id)) == topics[1])
                    .map(|(ledger, _, hash)| json!({"ledger": ledger, "txHash": hash}))
                    .collect();
                let cursor = format!(
                    "{:019}-{:010}",
                    (u64::from(m.ledger) << 32) | 0xffff_ffff,
                    u32::MAX
                );
                Ok(json!({"events": events, "latestLedger": m.ledger, "cursor": cursor}))
            }
            "getTransaction" => {
                let tx_hash = params["hash"].as_str().unwrap();
                let Some(envelope) = m.settled.get(tx_hash) else {
                    return Ok(json!({"status": "NOT_FOUND"}));
                };
                let failed = m.failed.contains(tx_hash);
                let envelope = if m.fee_bumped {
                    let x::TransactionEnvelope::Tx(inner) = de(envelope) else {
                        panic!()
                    };
                    b64(&x::TransactionEnvelope::TxFeeBump(
                        x::FeeBumpTransactionEnvelope {
                            tx: x::FeeBumpTransaction {
                                fee_source: x::MuxedAccount::Ed25519(x::Uint256([9; 32])),
                                fee: i64::from(inner.tx.fee) * 2,
                                inner_tx: x::FeeBumpTransactionInnerTx::Tx(inner),
                                ext: x::FeeBumpTransactionExt::V0,
                            },
                            signatures: Default::default(),
                        },
                    ))
                } else {
                    envelope.clone()
                };
                let envelope = &envelope;
                let result = x::TransactionResult {
                    fee_charged: m.charged_fee.unwrap_or(100),
                    result: if failed {
                        x::TransactionResultResult::TxFailed(Default::default())
                    } else {
                        x::TransactionResultResult::TxSuccess(Default::default())
                    },
                    ext: x::TransactionResultExt::V0,
                };
                // A fee bump reports the inner transaction's result, which its wrapper paid.
                let result = if m.fee_bumped {
                    let pair = x::InnerTransactionResultPair {
                        transaction_hash: x::Hash(unhexs(tx_hash)),
                        result: x::InnerTransactionResult {
                            fee_charged: 0,
                            result: if failed {
                                x::InnerTransactionResultResult::TxFailed(Default::default())
                            } else {
                                x::InnerTransactionResultResult::TxSuccess(Default::default())
                            },
                            ext: x::InnerTransactionResultExt::V0,
                        },
                    };
                    x::TransactionResult {
                        fee_charged: 200,
                        result: if failed {
                            x::TransactionResultResult::TxFeeBumpInnerFailed(pair)
                        } else {
                            x::TransactionResultResult::TxFeeBumpInnerSuccess(pair)
                        },
                        ext: x::TransactionResultExt::V0,
                    }
                } else {
                    result
                };
                Ok(
                    json!({"status": if failed { "FAILED" } else { "SUCCESS" }, "txHash": tx_hash, "ledger": m.ledger, "envelopeXdr": envelope, "resultXdr": b64(&result)}),
                )
            }
            other => panic!("unexpected RPC {other}"),
        }
    }
}
/// Apply one settled transaction to the model and return the host result it produces.
fn apply(m: &mut Model, tx: &x::Transaction) -> x::ScVal {
    let op = host_op(tx);
    match &op.host_function {
        x::HostFunction::UploadContractWasm(code) => {
            let h = hash(code.as_slice());
            let tier = m.tiers[&h];
            m.code.insert(h, tier);
            m.code_bytes.insert(h, code.to_vec());
            bytes(&h)
        }
        x::HostFunction::InvokeContract(call)
            if call.contract_address == address(&deployer()).unwrap() =>
        {
            let (wallet, _) = deploy_tree(call);
            let tier = m.code[&digest(&call.args[1])];
            let config = &items(&call.args[3])[0];
            let rules = policy::rules_from_scval(field(config, "rules")).unwrap();
            let raw = |name| account_for_public_key(&digest(field(config, name)));
            let mut w = Wallet {
                address: wallet.clone(),
                tier,
                config: packed::Configuration {
                    layout: packed::LAYOUT,
                    paused: false,
                    deployment_version: 0,
                    owner: addr(field(config, "owner")),
                    agent: raw("agent"),
                    server: raw("server"),
                    asset: addr(field(config, "asset")),
                    source_hash: digest(field(config, "source_hash")),
                    gas_cap: int(field(config, "gas_cap")),
                    params: installed_params(
                        tier,
                        &rules,
                        &PolicyParams::from_scval(field(config, "params")).unwrap(),
                    ),
                    rules,
                },
                stored: Stored::default(),
                served: packed::Figures::default(),
                balance: 0,
                shares: 0,
            };
            // `t` exists from the deployment when a check reads a total.
            let kept = w.kept();
            if kept & (SPENT | CALLS) != 0 {
                w.write_total(kept, &packed::Figures::default());
            }
            for item in items(&call.args[4]) {
                let [asset, amount] = items(item) else {
                    panic!()
                };
                assert_eq!(addr(asset), xlm());
                w.balance += int(amount);
            }
            m.wallet = Some(w);
            x::ScVal::Address(address(&wallet).unwrap())
        }
        x::HostFunction::InvokeContract(call) => {
            let (now, ledger) = (m.now, m.ledger);
            if call.function_name.0.as_slice() == b"execute" {
                let x::SorobanCredentials::Address(c) = &op.auth[0].credentials else {
                    panic!()
                };
                verify_cosignatures(m, &op.auth[0]).unwrap();
                m.nonces.insert(c.nonce);
            }
            let w = m.wallet.as_mut().unwrap();
            let next = |w: &Wallet, v: &x::ScVal| {
                let x::ScVal::U32(version) = v else { panic!() };
                assert_eq!(*version, w.config.deployment_version + 1);
                *version
            };
            match call.function_name.0.as_slice() {
                b"execute" => execute(w, &call.args[0], now, ledger, &source_of(tx)),
                b"set_pause" => {
                    let x::ScVal::Bool(paused) = &call.args[0] else {
                        panic!()
                    };
                    w.config.deployment_version = next(w, &call.args[1]);
                    w.config.paused = *paused;
                    x::ScVal::Void
                }
                b"stop" => {
                    w.config.deployment_version = next(w, &call.args[0]);
                    w.config.paused = true;
                    w.balance = 0;
                    x::ScVal::Void
                }
                b"deploy_policy" => {
                    let d = &call.args[0];
                    w.config.deployment_version = next(w, field(d, "deployment_version"));
                    assert_eq!(field(d, "wasm_hash"), &x::ScVal::Void);
                    w.config.owner = addr(field(d, "owner"));
                    w.config.agent = account_for_public_key(&digest(field(d, "agent")));
                    w.config.server = account_for_public_key(&digest(field(d, "server")));
                    w.config.source_hash = digest(field(d, "source_hash"));
                    w.config.gas_cap = int(field(d, "gas_cap"));
                    w.config.rules = policy::rules_from_scval(field(d, "rules")).unwrap();
                    w.config.params = installed_params(
                        w.tier,
                        &w.config.rules,
                        &PolicyParams::from_scval(field(d, "params")).unwrap(),
                    );
                    // `t` follows the totals that the new configuration keeps.
                    let kept = w.kept();
                    let totals = w.figures(SPENT | CALLS, ledger);
                    if kept & (SPENT | CALLS) != 0 {
                        w.write_total(kept, &totals);
                    } else {
                        w.stored.total = None;
                    }
                    x::ScVal::Void
                }
                b"recover" => {
                    assert_eq!(addr(&call.args[0]), xlm());
                    w.balance -= int(&call.args[2]);
                    x::ScVal::Void
                }
                other => panic!("unexpected {other:?}"),
            }
        }
        _ => panic!(),
    }
}
/// Run one execution as the kernel does: the checks, the kept figures, the effects and the gas
/// repayment to the sending account.
fn execute(w: &mut Wallet, request: &x::ScVal, now: u64, ledger: u32, source: &str) -> x::ScVal {
    let [_, version, expires_at, operation, expense, gas, payee, args] = items(request) else {
        panic!()
    };
    let x::ScVal::U32(version) = version else {
        panic!()
    };
    assert_eq!(*version, w.config.deployment_version, "stale request");
    assert!(!w.config.paused);
    let x::ScVal::U64(expires_at) = expires_at else {
        panic!()
    };
    assert!(*expires_at > now);
    let (spent, gas_units, unpriced) = match items(expense) {
        [name, gas, _, spent, _] if symbol(name) == "Priced" => (int(spent), int(gas), false),
        [name] if symbol(name) == "Unpriced" => (0, 0, true),
        _ => panic!(),
    };
    let gas = int(gas);
    assert!(gas >= 0 && gas <= w.config.gas_cap);
    // As the kernel checks: gas is counted exactly when some is repaid, and an XLM wallet counts
    // the repaid stroops.
    assert_eq!(gas == 0, gas_units == 0, "counted gas");
    if w.config.asset == xlm() {
        assert_eq!(gas_units, gas, "an XLM wallet counts the repaid stroops");
    }
    // The sending account receives the repayment.
    assert_eq!(addr(payee), source);
    let operation = items(operation);
    let asset = w.config.asset.clone();
    let (kind, recipient, amount, token_in, amount_in, token_out, min_out) =
        match symbol(&operation[0]).as_str() {
            "Transfer" => {
                let amount = int(&operation[3]);
                (
                    allowit_core::AllowitOperation::transfer,
                    addr(&operation[2]),
                    amount,
                    addr(&operation[1]),
                    amount,
                    None,
                    0,
                )
            }
            "Deposit" => {
                let vault = addr(&operation[1]);
                let assets = int(&operation[2]);
                (
                    allowit_core::AllowitOperation::deposit,
                    vault.clone(),
                    assets,
                    asset.clone(),
                    assets,
                    Some(vault),
                    int(&operation[3]),
                )
            }
            "Redeem" => {
                let vault = addr(&operation[1]);
                let min_assets = int(&operation[3]);
                (
                    allowit_core::AllowitOperation::redeem,
                    vault.clone(),
                    min_assets,
                    vault,
                    int(&operation[2]),
                    Some(asset.clone()),
                    min_assets,
                )
            }
            _ => panic!(),
        };
    // Every standard figure after this execution, from the figures before it, as Core's
    // post-flight computes them.
    let advance = |w: &Wallet, before: &packed::Figures| -> packed::Figures {
        let state = PolicyStateSnapshot {
            custom: Default::default(),
            params: w.config.params.clone(),
            rules: w.config.rules.clone(),
            source_hash: w.config.source_hash,
            figures: before.clone(),
        }
        .standard_state(now);
        let ctx = allowit_core::AllowitContext {
            env: allowit_core::AllowitEnv::new(),
            params: w.config.params.allowit().into(),
            state: state.allowit(),
            request: allowit_core::AllowitRequest {
                operation: kind.clone(),
                asset: allowit_core::Address::new(asset.clone()),
                recipient: allowit_core::Address::new(recipient.clone()),
                amount,
                token_in: allowit_core::Address::new(token_in.clone()),
                amount_in,
                token_out: token_out.clone().map(allowit_core::Address::new),
                min_out,
                now,
                expires_at: *expires_at,
                spent_units: spent,
                gas_units,
                unpriced,
                args: PolicyParams::from_scval(args).unwrap().allowit().into(),
            },
        };
        let after = PolicyParams::from_allowit(
            &allowit_core::post_flight(&ctx, AllowitTier::Standard).unwrap(),
        );
        let number = |key: &str| match after.get(key) {
            Some(PolicyValue::Int(v)) => *v,
            other => panic!("{key}: {other:?}"),
        };
        let flag = |key: &str| matches!(after.get(key), Some(PolicyValue::Bool(true)));
        packed::Figures {
            calls: number("calls") as u64,
            spent: number("spent"),
            unpriced: flag("unpriced"),
            day_spent: number("day_spent"),
            day_total: number("day_total"),
            day_unpriced: flag("day_unpriced"),
            day_ends: before.day_ends,
        }
    };
    // The server counts every execution; its day stays open for the whole model run.
    let served = advance(
        w,
        &packed::Figures {
            day_ends: u32::MAX,
            ..w.served.clone()
        },
    );
    let kept = w.kept();
    let runs = w.tier == PolicyTier::Custom || !w.config.rules.is_empty();
    if runs && kept != 0 {
        let before = w.figures(kept, ledger);
        let figures = advance(w, &before);
        let totals = |f: &packed::Figures| {
            (
                if kept & SPENT != 0 { f.spent } else { 0 },
                if kept & CALLS != 0 { f.calls } else { 0 },
                kept & SPENT != 0 && f.unpriced,
            )
        };
        if kept & (SPENT | CALLS) != 0
            && (w.stored.total.is_none() || totals(&figures) != totals(&before))
        {
            w.write_total(kept, &figures);
        }
        if kept & (DAY_SPENT | DAY_TOTAL) != 0
            && (figures.day_spent, figures.day_total, figures.day_unpriced)
                != (before.day_spent, before.day_total, before.day_unpriced)
        {
            let end = if before.day_ends != 0 {
                before.day_ends
            } else {
                ledger + DAY_LEDGERS - 1
            };
            w.stored.daily = Some((
                end,
                kept & (DAY_SPENT | DAY_TOTAL),
                figures.day_unpriced,
                if kept & DAY_SPENT != 0 {
                    figures.day_spent
                } else {
                    0
                },
                if kept & DAY_TOTAL != 0 {
                    figures.day_total
                } else {
                    0
                },
            ));
        }
    }
    // The model vault converts one to one.
    match symbol(&operation[0]).as_str() {
        "Transfer" => w.balance -= amount_in,
        "Deposit" => {
            w.balance -= amount_in;
            w.shares += amount_in;
        }
        _ => {
            w.shares -= amount_in;
            w.balance += amount_in;
        }
    }
    w.balance -= gas;
    w.served = served;
    x::ScVal::Void
}

/// A chain whose wallet policy reads the gas of a request, as a Custom policy that reads
/// `ctx.request.gas_units` can. It refuses every simulated request that carries one of the
/// `refused` gas amounts. With `cost`, a recording simulation of a request above the lowest fee
/// bound needs the resource fee that `cost` gives for its gas.
struct ReadsGas<'a> {
    chain: &'a ModelChain,
    refused: &'a [i128],
    cost: Option<fn(i128) -> i64>,
}
impl rpc::Rpc for ReadsGas<'_> {
    fn call(&self, method: &str, params: Value) -> Result<Value> {
        let mut gas = None;
        if method == "simulateTransaction" {
            let x::TransactionEnvelope::Tx(env) = de(params["transaction"].as_str().unwrap())
            else {
                panic!()
            };
            if let x::HostFunction::InvokeContract(call) = &host_op(&env.tx).host_function
                && call.function_name.0.as_slice() == b"execute"
                && let [name, units, ..] = items(&items(&call.args[0])[4])
                && symbol(name) == "Priced"
            {
                gas = Some(int(units));
            }
            if gas.is_some_and(|gas| self.refused.contains(&gas)) {
                return Ok(json!({"error": "the policy refuses this gas"}));
            }
        }
        let record = params["authMode"] == "record";
        let mut reply = self.chain.call(method, params)?;
        if let (Some(cost), Some(gas)) = (self.cost, gas)
            && record
            && gas > i128::from(INCLUSION_FEE_STROOPS)
            && reply.get("error").is_none()
        {
            let fee = cost(gas);
            reply["minResourceFee"] = json!(fee.to_string());
            reply["transactionData"] = json!(b64(&x::SorobanTransactionData {
                resource_fee: fee,
                ..Default::default()
            }));
        }
        Ok(reply)
    }
}

fn terms(principal: i128, ledger: u32) -> ExecutionTerms {
    ExecutionTerms {
        args: PolicyParams::default(),
        expense: Some(ExpenseBounds::xlm(principal, 0, MAX_FEE, ledger - 1, NOW).unwrap()),
        gas: None,
        sender: Some(sender()),
        gas_carry: 0,
    }
}
fn seal(chain: &ModelChain, authorized: &SignedOperation) -> Result<SignedOperation> {
    rpc::seal(chain, authorized, |hash| {
        Ok(SigningKey::from_bytes(&SENDER).sign(hash).to_bytes())
    })
}
/// The server prepares and signs, the agent signs, and the sending account seals and submits.
fn authorized(
    chain: &ModelChain,
    c: &WalletConfig,
    r: &ExecutionRequest,
    t: &ExecutionTerms,
) -> Result<SignedOperation> {
    let prepared = rpc::prepare_with(chain, c, r, t, Some(chain.accounting()), NOW, NOW + 300)?;
    let served = authorize_server(&prepared, &SERVER, NOW, None)?;
    let simulated = rpc::simulate(chain, &served)?;
    let proof = sign(&simulated, &AGENT, NOW)?;
    authorize(&simulated, &[proof], NOW)
}
fn run(
    chain: &ModelChain,
    c: &WalletConfig,
    r: &ExecutionRequest,
    t: &ExecutionTerms,
    name: &str,
) -> Result<SignedOperation> {
    let signed = authorized(chain, c, r, t)?;
    // The signed expense holds the fee bound of this operation, not the caller's ceiling; for
    // XLM the gas that the wallet repays to the sending account is that bound.
    let bound = signed.prepared.terms.expense.as_ref().ok_or("no expense")?;
    assert_eq!(
        (bound.gas_units, i128::from(bound.max_fee_stroops)),
        (gas(), gas())
    );
    assert_eq!(
        bound.spent_units - bound.gas_units,
        t.expense
            .as_ref()
            .map_or(0, |e| e.spent_units - e.gas_units)
    );
    let sealed = seal(chain, &signed)?;
    // The sending account declares the bound: the enforcing simulation needs less.
    let x::TransactionEnvelope::Tx(envelope) = de(&sealed.transaction_xdr) else {
        panic!()
    };
    assert_eq!(i128::from(envelope.tx.fee), gas());
    assert_eq!(source_of(&envelope.tx), sender());
    chain.step(name);
    assert_eq!(
        rpc::broadcast(chain, &sealed, NOW)?,
        rpc::Broadcast::Submitted
    );
    assert_eq!(
        rpc::status_by_hash(chain, &c.network, &sealed.transaction_hash)?,
        OperationStatus::Confirmed
    );
    let settled =
        rpc::receipt_by_hash(chain, &c.network, &sealed.transaction_hash)?.ok_or("no receipt")?;
    rpc::validate_settled_policy_packet(&sealed, &settled)?;
    // The settled transaction reports the gas that the wallet counted for it and repaid.
    assert_eq!(rpc::counted_gas_units(&settled)?, gas());
    assert_eq!(rpc::repaid_gas_stroops(&settled)?, gas() as u128);
    let failed = rpc::VerifiedReceipt {
        status: OperationStatus::Failed,
        ..settled
    };
    assert_eq!(rpc::counted_gas_units(&failed)?, 0);
    assert_eq!(rpc::repaid_gas_stroops(&failed)?, 0);
    Ok(sealed)
}
fn submit(chain: &ModelChain, name: &str, xdr: &str, seed: &[u8; 32]) {
    chain.step(name);
    let signed = sign_owner_transaction(NETWORK, xdr, seed).unwrap();
    assert_eq!(
        rpc::send_transaction(chain, NETWORK, &signed).unwrap(),
        rpc::Broadcast::Submitted
    );
    let hash = rpc::signed_transaction_hash(NETWORK, &signed).unwrap();
    let receipt = rpc::receipt_by_hash(chain, NETWORK, &hash)
        .unwrap()
        .unwrap();
    assert_eq!(receipt.status, OperationStatus::Confirmed);
    // An owner or upload transaction is no wallet execution: no limit counts gas for it, and
    // the wallet repays none.
    assert_eq!(rpc::counted_gas_units(&receipt).unwrap(), 0);
    assert_eq!(rpc::repaid_gas_stroops(&receipt).unwrap(), 0);
}
fn owner_submit(chain: &ModelChain, name: &str, xdr: &str) {
    submit(chain, name, xdr, &OWNER);
}
fn params() -> PolicyParams {
    policy::params_from_json(
        &json!({
            "payment_limit": 50_000_000,
            "lifetime_spending_limit": 1_000_000_000,
            "daily_spending_limit": 500_000_000,
            "daily_volume_limit": 500_000_000,
            "call_limit": 10,
            "destinations": [account_for_seed(&RECIPIENT), vault()],
            "tokens": [xlm()],
            "expires_at": NOW + 30 * 86_400,
            "operations": ["transfer", "deposit", "redeem"],
        }),
        Some(PolicyTier::Common),
    )
    .unwrap()
}
/// Synthetic policy wallet code for one tier: a Wasm module that declares custody layout 5.
fn stand_in_wasm(tier: PolicyTier) -> Vec<u8> {
    let mut meta = 0u32.to_be_bytes().to_vec();
    for text in [b"allowit_custody_layout".as_slice(), b"5"] {
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

struct DeploymentLedgerClock {
    chain: ModelChain,
    after_simulation: Mutex<Option<u32>>,
    slow_account: bool,
    changed_owner: bool,
    wrong_network: bool,
}

impl rpc::Rpc for DeploymentLedgerClock {
    fn call(&self, method: &str, params: Value) -> Result<Value> {
        let mut response = self.chain.call(method, params)?;
        let mut elapsed = self.after_simulation.lock().unwrap();
        if method == "simulateTransaction" {
            *elapsed = Some(0);
        } else if let Some(calls) = elapsed.as_mut() {
            // The next ledger closes after two RPC round trips. A slow account read lands past
            // the five-ledger observation window.
            let ledger = LEDGER
                + if self.slow_account {
                    6
                } else if *calls < 2 {
                    1
                } else {
                    2
                };
            *calls += 1;
            match method {
                "getLatestLedger" => response["sequence"] = json!(ledger),
                "getNetwork" if self.wrong_network => {
                    response["passphrase"] = json!(passphrase("stellar:mainnet")?);
                }
                "getLedgerEntries" => {
                    response["latestLedger"] = json!(ledger);
                    if self.changed_owner {
                        let mut entry: x::LedgerEntryData =
                            de(response["entries"][0]["xdr"].as_str().unwrap());
                        let x::LedgerEntryData::Account(account) = &mut entry else {
                            panic!("expected the source account entry");
                        };
                        account.seq_num.0 += 1;
                        response["entries"][0]["xdr"] = json!(b64(&entry));
                    }
                }
                _ => {}
            }
        }
        Ok(response)
    }
}

#[test]
fn custom_upload_checks_its_source_before_the_next_ledger() {
    let wasm = stand_in_wasm(PolicyTier::Custom);
    let module = hash(&wasm);
    for (slow_account, changed_owner, wrong_network) in [
        (false, false, false),
        (true, false, false),
        (false, true, false),
        (false, false, true),
    ] {
        let chain = DeploymentLedgerClock {
            chain: ModelChain::new(BTreeMap::from([(module, PolicyTier::Custom)])),
            after_simulation: Mutex::new(None),
            slow_account,
            changed_owner,
            wrong_network,
        };
        let deployer = Deployer {
            rpc: &chain,
            network: NETWORK,
            now: NOW,
            max_fee_stroops: MAX_FEE,
        };
        let prepared = deployer.upload_wasm(&sender(), &wasm);
        if slow_account || changed_owner || wrong_network {
            assert!(
                prepared.is_err(),
                "stale, changed or wrong-network source observation"
            );
        } else {
            let packet = prepared.unwrap().expect("the code is not on the network");
            assert_eq!(packet.wasm_hash, module);
            assert_eq!(packet.source, sender());
        }
    }
}

/// The installation of a tier's wallet, before its creation.
fn installation(tier: PolicyTier, module: [u8; 32], salt: [u8; 32]) -> WalletConfig {
    let owner = account_for_seed(&OWNER);
    let rules = policy::tier_rules(tier, SOURCE).unwrap();
    let mut c = WalletConfig {
        network: NETWORK.into(),
        policy_instance: [7; 32],
        wallet: admin::wallet_address(NETWORK, &owner, &salt).unwrap(),
        owner,
        agent: account_for_seed(&AGENT),
        server: account_for_seed(&SERVER),
        route: WalletRoute::PolicyWallet,
        tier: Some(tier),
        language: PolicyLanguage::Portable,
        params: params(),
        rules,
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
    c
}
/// The server uploads the code; the owner creates and funds the wallet with one signature.
fn create(chain: &ModelChain, tier: PolicyTier, wasm: &[u8], salt: [u8; 32]) -> WalletConfig {
    let module = hash(wasm);
    let d = Deployer {
        rpc: chain,
        network: NETWORK,
        now: NOW,
        max_fee_stroops: MAX_FEE,
    };
    if let Some(upload) = d.upload_wasm(&sender(), wasm).unwrap() {
        assert_eq!(upload.wasm_hash, module);
        submit(chain, "upload", &upload.transaction_xdr, &SENDER);
    }
    let c = installation(tier, module, salt);
    let config = PolicyConfig::for_policy(&c).unwrap();
    let created = d
        .deploy_and_fund(&deployer(), &config, wasm, salt, &[(xlm(), FUNDING)])
        .unwrap();
    assert_eq!(created.wallet.as_deref(), Some(c.wallet.as_str()));
    assert_eq!(created.function, "create_wallet");
    owner_submit(chain, "create", &created.transaction_xdr);
    assert_eq!(chain.balance(), FUNDING);
    c
}
/// The trusted state with the server's sending account as the source of the next operation.
fn sending_state(chain: &ModelChain, c: &WalletConfig) -> TrustedState {
    let mut state = rpc::trusted_state(chain, c, Some(chain.accounting())).unwrap();
    state.source = rpc::get_account(chain, &sender()).unwrap();
    state
}

/// The complete workflow of one tier; returns the recorded steps.
fn workflow(tier: PolicyTier) -> Vec<Step> {
    let wasm = wasm_for(tier);
    let module = hash(&wasm);
    let chain = ModelChain::new(BTreeMap::from([(module, tier)]));
    // 1. The server uploads the code; the owner creates and funds the wallet.
    let c = create(&chain, tier, &wasm, [tier as u8 + 0x11; 32]);
    // 2. Discovery reads the live configuration and figures.
    let found = rpc::trusted_state_for_discovery(&chain, &c, None).unwrap();
    assert!(!found.paused);
    assert_eq!(found.state.contract_version, Some(CONTRACT_VERSION));
    // 3. A transfer, priced with server-attested gas in XLM.
    let recipient = account_for_seed(&RECIPIENT);
    let state = sending_state(&chain, &c);
    let ledger = chain.ledger();
    let transfer = request::transfer(&c, &state, [1; 32], &recipient, 10_000_000).unwrap();
    // A policy can refuse the lowest fee bound alone. The fee is then simulated at the ceiling,
    // and the signed bound is the same. A refusal of both is the refusal of the lowest bound.
    let priced = |refused: &[i128], cost: Option<fn(i128) -> i64>| {
        rpc::prepare_with(
            &ReadsGas {
                chain: &chain,
                refused,
                cost,
            },
            &c,
            &transfer,
            &terms(10_000_000, ledger),
            Some(chain.accounting()),
            NOW,
            NOW + 300,
        )
    };
    let lowest = i128::from(INCLUSION_FEE_STROOPS);
    let bound = priced(&[lowest], None).unwrap().terms.expense.unwrap();
    assert_eq!(
        (bound.gas_units, bound.spent_units),
        (gas(), 10_000_000 + gas())
    );
    for refused in [&[lowest, i128::from(MAX_FEE)][..], &[gas()][..]] {
        assert!(
            priced(refused, None)
                .unwrap_err()
                .contains("rejected the exact policy operation")
        );
    }
    // A policy can need more resources with the priced gas than with the lowest bound. The
    // operation is then priced from its own simulation: 3,000 + 100 + 30.
    let repriced = priced(&[], Some(|_| 3_000)).unwrap();
    let bound = repriced.terms.expense.as_ref().unwrap();
    assert_eq!((bound.gas_units, bound.max_fee_stroops), (3_130, 3_130));
    // A resource fee inside the margin of the signed bound prices nothing again.
    let inside = priced(&[], Some(|_| gas() as i64 - 100)).unwrap();
    assert_eq!(inside.terms.expense.as_ref().unwrap().gas_units, gas());
    // A quote above the wallet's gas cap is priced within the gas cap: a fee that fits it is
    // not raised above it by the margin of the bound, which the wallet would refuse to repay.
    // 995,000 + 100 fits 1,000,000; with the margin the bound would be 1,005,050.
    let quoted = ExecutionTerms {
        expense: Some(ExpenseBounds::xlm(10_000_000, 0, MAX_FEE * 2, ledger - 1, NOW).unwrap()),
        ..terms(10_000_000, ledger)
    };
    let within = rpc::prepare_with(
        &ReadsGas {
            chain: &chain,
            refused: &[],
            cost: Some(|_| 995_000),
        },
        &c,
        &transfer,
        &quoted,
        Some(chain.accounting()),
        NOW,
        NOW + 300,
    )
    .unwrap();
    let bound = within.terms.expense.as_ref().unwrap();
    assert_eq!(
        (bound.gas_units, bound.max_fee_stroops),
        (i128::from(MAX_FEE), MAX_FEE)
    );
    assert_eq!(
        within.terms.repaid_stroops().unwrap(),
        i128::from(c.max_fee_stroops)
    );
    for cost in [(|gas| gas as i64) as fn(i128) -> i64, |_| {
        i64::from(MAX_FEE)
    }] {
        assert!(
            priced(&[], Some(cost))
                .unwrap_err()
                .contains("exceeds approved fee bound")
        );
    }
    // The sending account's enforcing simulation sets the final fee: the signed bound while the
    // fee fits it, the higher required fee up to the installed ceiling, and no seal above it.
    // The wallet repays the signed gas either way; the server carries a difference.
    let signed = authorized(&chain, &c, &transfer, &terms(10_000_000, ledger)).unwrap();
    for (enforce_fee, fee) in [
        (ENFORCE_FEE, Some(gas() as u32)),
        (gas() as i64, Some(gas() as u32 + 100)),
        (i64::from(MAX_FEE) - 99, None),
    ] {
        chain.0.lock().unwrap().enforce_fee = enforce_fee;
        match seal(&chain, &signed) {
            Ok(sealed) => {
                let x::TransactionEnvelope::Tx(envelope) = de(&sealed.transaction_xdr) else {
                    panic!()
                };
                assert_eq!(Some(envelope.tx.fee), fee);
            }
            Err(e) => assert!(fee.is_none(), "{enforce_fee}: {e}"),
        }
    }
    chain.0.lock().unwrap().enforce_fee = ENFORCE_FEE;
    // A tampered cosignature fails the wallet's check in the enforcing simulation.
    let mut forged = signed.clone();
    let x::TransactionEnvelope::Tx(mut envelope) = de(&forged.transaction_xdr) else {
        panic!()
    };
    let mut operations = envelope.tx.operations.to_vec();
    let x::OperationBody::InvokeHostFunction(op) = &mut operations[0].body else {
        panic!()
    };
    let mut auth = op.auth.to_vec();
    let x::SorobanCredentials::Address(credentials) = &mut auth[0].credentials else {
        panic!()
    };
    credentials.signature = contract::cosignatures(&[9; 64], &[9; 64]).unwrap();
    op.auth = auth.try_into().unwrap();
    envelope.tx.operations = operations.try_into().unwrap();
    forged.transaction_xdr = b64(&x::TransactionEnvelope::Tx(envelope));
    assert!(seal(&chain, &forged).is_err());
    let before = chain.balance();
    run(
        &chain,
        &c,
        &transfer,
        &terms(10_000_000, ledger),
        "transfer",
    )
    .unwrap();
    assert_eq!(chain.balance(), before - 10_000_000 - gas());
    let figures = chain.figures();
    let kept = kept(tier, &chain.config());
    assert_eq!(
        (figures.calls, figures.spent),
        (
            if kept & CALLS != 0 { 1 } else { 0 },
            if kept & SPENT != 0 {
                10_000_000 + gas()
            } else {
                0
            }
        )
    );
    // The same authorization runs once.
    assert!(seal(&chain, &signed).is_err());
    // A transfer over the payment limit is denied before any signature: by the server's
    // evaluation over its accounting, and for Common and Custom on the host too. Simple runs no
    // rule on chain; Custom runs its source, not prefix rules.
    let state = sending_state(&chain, &c);
    let ledger = chain.ledger();
    let over = request::transfer(&c, &state, [9; 32], &recipient, 60_000_000).unwrap();
    assert_eq!(c.rules.is_empty(), tier != PolicyTier::Common);
    assert!(
        rpc::prepare_with(
            &chain,
            &c,
            &over,
            &terms(60_000_000, ledger),
            Some(chain.accounting()),
            NOW,
            NOW + 300
        )
        .unwrap_err()
        .contains("PaymentLimitExceeded")
    );
    // Without the server's accounting, a Simple or Common wallet is not authorized.
    let needs = kept != packed::ALL;
    assert_eq!(
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
        .contains("needs the server's accounting"),
        needs
    );
    // 4. A SEP-56 deposit, then a redeem of part of its shares.
    let ledger = chain.ledger();
    let deposit = request::deposit(&c, &state, [2; 32], &vault(), 5_000_000, 5_000_000).unwrap();
    let priced = |ledger: u32| ExecutionTerms {
        args: PolicyParams::default(),
        expense: Some(ExpenseBounds::xlm(0, 0, MAX_FEE, ledger - 1, NOW).unwrap()),
        gas: None,
        sender: Some(sender()),
        gas_carry: 0,
    };
    run(&chain, &c, &deposit, &priced(ledger), "deposit").unwrap();
    let ledger = chain.ledger();
    let redeem = request::redeem(&c, &state, [5; 32], &vault(), 2_000_000, 2_000_000).unwrap();
    run(&chain, &c, &redeem, &priced(ledger), "redeem").unwrap();
    // 5. The owner pauses and resumes at the next deployment versions.
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
    // 6. Params update without new code: a lower payment limit.
    let mut lower = params();
    lower
        .0
        .insert("payment_limit".into(), PolicyValue::Int(20_000_000));
    // The daily limit leaves room for 15,001,000 more units.
    // The server's accounting counts every execution; a wallet that keeps the day's spent
    // agrees with it.
    let day_spent = chain.accounting().spent_daily;
    if kept & DAY_SPENT != 0 {
        assert_eq!(chain.figures().day_spent, day_spent);
    }
    lower.0.insert(
        "daily_spending_limit".into(),
        PolicyValue::Int(day_spent + 15_001_000),
    );
    let (deployment, check) = PolicyDeployment::for_source(&c, SOURCE, lower.clone()).unwrap();
    assert!(check.warnings.is_empty());
    let updated = owner_admin
        .deploy_policy(DeploymentVersion(3), deployment)
        .unwrap();
    owner_submit(&chain, "params", &updated.transaction_xdr);
    assert_eq!(
        chain.config().params,
        installed_params(tier, &c.rules, &lower)
    );
    let c = WalletConfig { params: lower, ..c };
    let state = sending_state(&chain, &c);
    let ledger = chain.ledger();
    let has = |rule: &str| tier == PolicyTier::Custom || c.rules.iter().any(|r| r == rule);
    // A debit that fits the daily limit with the lowest fee, and not with the fee bound that the
    // wallet counts, is denied on the host before any signature.
    let over = request::transfer(&c, &state, [8; 32], &recipient, 15_000_000).unwrap();
    if has("daily_spending_limit") {
        assert!(
            rpc::prepare_with(
                &chain,
                &c,
                &over,
                &terms(15_000_000, ledger),
                Some(chain.accounting()),
                NOW,
                NOW + 300
            )
            .unwrap_err()
            .contains("DailySpendingLimitExceeded")
        );
    }
    // A debit that fits with the counted fee bound runs. The caller's fee ceiling would not fit.
    let again = request::transfer(&c, &state, [3; 32], &recipient, 14_999_000).unwrap();
    assert!(14_999_000 + gas() <= 15_001_000 && 14_999_000 + i128::from(MAX_FEE) > 15_001_000);
    let sealed = run(
        &chain,
        &c,
        &again,
        &terms(14_999_000, ledger),
        "transfer_v3",
    )
    .unwrap();
    let x::TransactionEnvelope::Tx(envelope) = de(&sealed.transaction_xdr) else {
        panic!()
    };
    let x::HostFunction::InvokeContract(call) = &host_op(&envelope.tx).host_function else {
        panic!()
    };
    assert_eq!(items(&call.args[0])[1], x::ScVal::U32(3));
    let ledger = chain.ledger();
    let blocked = request::transfer(&c, &state, [4; 32], &recipient, 25_000_000).unwrap();
    if has("payment_limit") {
        assert!(
            rpc::prepare_with(
                &chain,
                &c,
                &blocked,
                &terms(25_000_000, ledger),
                Some(chain.accounting()),
                NOW,
                NOW + 300
            )
            .unwrap_err()
            .contains("PaymentLimitExceeded")
        );
    }
    // 7. Recovery of part of the balance to the owner, then the owner's stop: one call that
    // pauses the wallet and returns the rest.
    let mut admin = OwnerAdmin {
        rpc: &chain,
        config: &c,
        now: NOW,
    };
    let recovery = admin.recover_to(&c.owner, 100_000_000).unwrap();
    owner_submit(&chain, "recover", &recovery.transaction_xdr);
    let stop = admin.stop(DeploymentVersion(4)).unwrap();
    owner_submit(&chain, "stop", &stop.transaction_xdr);
    assert_eq!(chain.balance(), 0);
    assert!(chain.config().paused);
    let model = chain.0.lock().unwrap();
    model.steps.clone()
}

/// A tier's wallet on a model chain after one settled transfer, with its installation.
fn wallet_with_usage(tier: PolicyTier) -> (ModelChain, WalletConfig) {
    let wasm = wasm_for(tier);
    let module = hash(&wasm);
    let chain = ModelChain::new(BTreeMap::from([(module, tier)]));
    let c = create(&chain, tier, &wasm, [tier as u8 + 0x21; 32]);
    let state = sending_state(&chain, &c);
    let ledger = chain.ledger();
    let transfer = request::transfer(
        &c,
        &state,
        [1; 32],
        &account_for_seed(&RECIPIENT),
        10_000_000,
    )
    .unwrap();
    run(
        &chain,
        &c,
        &transfer,
        &terms(10_000_000, ledger),
        "transfer",
    )
    .unwrap();
    (chain, c)
}
/// The server's owner step of a params update is the packet that the owner reconstructs from
/// the installation alone. The settled update keeps the recorded figures, moves the
/// configuration revision by one, and is refused at any other revision.
#[test]
fn owner_params_update_step_matches_the_owner_reconstruction_and_keeps_usage() {
    use allowit_core::AllowitValue as V;
    use allowit_core::policy::PolicyValue as CoreValue;
    use allowit_core::vendor::plugin::RailPlugin;
    use allowit_core::vendor::profiles::Description;
    use allowit_core::vendor::runtime::{Installation, ParamsUpdate, Transport};
    use allowit_stellar::owner_intent::{
        ExpectedOwnerIntent, OwnerAction, OwnerLimits, OwnerTransaction, validate_owner_transaction,
    };
    use allowit_stellar::provider::params_update;
    use std::sync::Arc;
    struct Wire(Arc<ModelChain>);
    impl Transport for Wire {
        fn call(&self, method: &str, params: Value) -> allowit_core::client::error::Result<Value> {
            rpc::Rpc::call(&*self.0, method, params)
                .map_err(allowit_core::client::error::Error::config)
        }
    }
    for tier in [PolicyTier::Common, PolicyTier::Custom] {
        let (chain, c) = wallet_with_usage(tier);
        let chain = Arc::new(chain);
        let before = chain.config();
        let figures = chain.figures();
        assert_eq!(figures.calls, 1, "{tier:?}");
        let verified = params_update::verify(&*chain, "policy", &c).unwrap();
        assert!(verified.matches, "{tier:?} {:?}", verified.comparisons);
        let change = |units: i128, expected_revision| ParamsUpdate {
            policy_id: "policy".into(),
            expected_revision,
            changes: [("daily_spending_limit".to_owned(), CoreValue(V::Int(units)))].into(),
        };
        let revision = u64::from(before.deployment_version);
        let update = change(250_000_000, Some(revision));
        // The owner changed the gas cap on the ledger: an update from this installation would
        // write the old gas cap back, so it is refused, and verification names the difference.
        let other_gas_cap = WalletConfig {
            max_fee_stroops: MAX_FEE - 1,
            ..c.clone()
        };
        assert!(
            params_update::installed(&*chain, &other_gas_cap, &update)
                .unwrap_err()
                .to_string()
                .contains("gas cap")
        );
        let differs = params_update::verify(&*chain, "policy", &other_gas_cap).unwrap();
        assert!(!differs.matches);
        let gas_cap_row = serde_json::to_value(&differs.comparisons)
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row.to_string().contains("gasCap"))
            .cloned()
            .unwrap();
        assert!(
            gas_cap_row.to_string().contains(&(MAX_FEE - 1).to_string()),
            "{gas_cap_row}"
        );
        let owners = allowit_stellar::PLUGIN.owner_runtime();
        let document = owners
            .configuration(NETWORK, &serde_json::to_vec(&c).unwrap())
            .unwrap();
        let installation = Installation {
            description: Description {
                network: NETWORK.into(),
                wallet: c.wallet.clone(),
                agent: c.agent.clone(),
                policy_id: "policy".into(),
                owner: c.owner.clone(),
                server: c.server.clone(),
                asset: c.asset.clone(),
                asset_symbol: c.asset_symbol.clone(),
                source: c.policy_source.clone(),
                source_hash: hex(&c.source_hash),
                module_digest: hex(&c.module_digest),
                params: document.params.clone(),
            },
            config: document.document().to_owned(),
            export: None,
            authority: None,
        };
        let provider = allowit_stellar::PLUGIN
            .runtime(NETWORK, Arc::new(Wire(chain.clone())))
            .unwrap();
        // Another revision than the wallet holds and an unknown param are refused before a
        // packet exists. A standard tier also refuses a value outside the rule's range; a
        // Custom wallet takes any typed value, and the server checks the range of a rule.
        let mut refusals = vec![
            change(250_000_000, Some(revision + 1)),
            ParamsUpdate {
                changes: [("vendor_limit".to_owned(), CoreValue(V::Int(1)))].into(),
                ..update.clone()
            },
        ];
        if tier != PolicyTier::Custom {
            refusals.push(change(-1, Some(revision)));
        }
        for refused in refusals {
            assert!(
                provider
                    .prepare_params_update(&installation, &refused, u64::from(MAX_FEE), NOW)
                    .is_err(),
                "{tier:?}"
            );
        }
        // A fee limit below the simulated fee, or below the network minimum, prepares nothing.
        // The limit never raises the installed ceiling.
        for limit in [0, 99, 100, RECORD_FEE as u64 + 99] {
            assert!(
                provider
                    .prepare_params_update(&installation, &update, limit, NOW)
                    .is_err(),
                "{tier:?} {limit}"
            );
        }
        let packet = provider
            .prepare_params_update(&installation, &update, u64::MAX, NOW)
            .unwrap();
        let step = owners.step(NETWORK, &packet).unwrap();
        let x::TransactionEnvelope::Tx(envelope) = de(&step.payload) else {
            panic!()
        };
        assert!(envelope.tx.fee <= MAX_FEE, "{tier:?}");
        assert_eq!(step.action, params_update::ACTION);
        // The owner validates the step against its own reconstruction of the packet.
        let transaction = OwnerTransaction {
            network: NETWORK.into(),
            action: step.action.clone(),
            transaction_xdr: step.payload.clone(),
            transaction_hash: step.hash,
            expires_at: step.expires_at,
        };
        let source = rpc::get_account(&*chain, &c.owner).unwrap();
        let intent = |update: &ParamsUpdate, version: u64| ExpectedOwnerIntent {
            limits: OwnerLimits {
                network: NETWORK.into(),
                owner: c.owner.clone(),
                next_sequence: source.sequence + 1,
                max_fee_stroops: MAX_FEE,
                valid_until: NOW + 300,
            },
            action: OwnerAction::UpdatePolicy {
                wallet: c.wallet.clone(),
                deployment: Box::new(params_update::deployment(&c, update).unwrap()),
                version,
            },
        };
        let next_version = revision + 1;
        validate_owner_transaction(&transaction, &intent(&update, next_version), NOW).unwrap();
        // Another value, another revision or another wallet is not the owner's intent.
        assert!(
            validate_owner_transaction(
                &transaction,
                &intent(&change(260_000_000, None), next_version),
                NOW
            )
            .is_err()
        );
        assert!(
            validate_owner_transaction(&transaction, &intent(&update, next_version + 1), NOW)
                .is_err()
        );
        let mut elsewhere = intent(&update, next_version);
        if let OwnerAction::UpdatePolicy { wallet, .. } = &mut elsewhere.action {
            *wallet = vault();
        }
        assert!(validate_owner_transaction(&transaction, &elsewhere, NOW).is_err());
        owner_submit(&chain, "update_params", &step.payload);
        // The figures carry over; only the params and the revision changed.
        let after = chain.config();
        let next = params_update::updated_config(&c, &update).unwrap();
        assert_eq!(after.params, next.params, "{tier:?}");
        assert_eq!(u64::from(after.deployment_version), next_version);
        assert_eq!(chain.figures(), figures);
        assert_eq!(
            (&after.source_hash, &after.rules, &after.owner),
            (&before.source_hash, &before.rules, &before.owner)
        );
        // The stored installation after the update is the one that the ledger now matches.
        let stored = owners.with_params(&document, &update).unwrap();
        assert_eq!(
            serde_json::from_slice::<WalletConfig>(stored.bytes()).unwrap(),
            next
        );
        let fresh = params_update::verify(&*chain, "policy", &next).unwrap();
        assert!(fresh.matches, "{tier:?} {:?}", fresh.comparisons);
        assert_eq!(fresh.state.revision, next_version);
        assert_eq!(fresh.state.counters, verified.state.counters);
        assert_eq!(fresh.state.counters_from, "ledger");
        assert_eq!(fresh.state.counters.as_ref().unwrap().calls, 1, "{tier:?}");
        let stale = params_update::verify(&*chain, "policy", &c).unwrap();
        assert!(!stale.matches);
        // The same update cannot be prepared again: the wallet moved to the next revision, and
        // the earlier installation no longer describes it.
        assert!(
            provider
                .prepare_params_update(&installation, &update, u64::from(MAX_FEE), NOW)
                .is_err()
        );
    }
}
#[test]
fn a_fee_bound_covers_the_declared_fee_and_lowers_gas_rounded_up() {
    for (resource, bound) in [
        (0i64, 100u32),
        (1, 102),
        (100, 201),
        (101, 203),
        (RECORD_FEE, 1_615),
        (2_644_142, 2_670_684),
    ] {
        assert_eq!(fee_bound(resource).unwrap(), bound, "{resource}");
        assert!(i64::from(bound) >= resource + i64::from(INCLUSION_FEE_STROOPS));
    }
    assert!(fee_bound(-1).is_err());
    assert!(fee_bound(i64::from(u32::MAX) - 100).is_err());
    // XLM: the gas is the bound itself.
    let xlm = ExpenseBounds::xlm(2_000_000, 0, 5_000_000, 9, NOW).unwrap();
    let lowered = xlm.with_fee_bound(2_670_684).unwrap();
    assert_eq!(
        (
            lowered.gas_units,
            lowered.spent_units,
            lowered.max_fee_stroops
        ),
        (2_670_684, 4_670_684, 2_670_684)
    );
    assert_eq!(
        (
            lowered.observed_ledger,
            lowered.day,
            lowered.conversion_units
        ),
        (xlm.observed_ledger, xlm.day, 0)
    );
    assert_eq!(xlm.with_fee_bound(5_000_000).unwrap(), xlm);
    // Another asset at 0.1234567 units per stroop: a 5,000,000-stroop ceiling is 617,284 units,
    // and a 2,670,684-stroop bound is 329,714 units at that rate. Lowered gas rounds up.
    let priced = ExpenseBounds {
        gas_units: 617_284,
        spent_units: 700 + 617_284,
        conversion_units: 700,
        ..xlm.clone()
    };
    let lowered = priced.with_fee_bound(2_670_684).unwrap();
    assert_eq!((lowered.gas_units, lowered.spent_units), (329_715, 330_415));
    assert!(lowered.gas_units >= 329_714 && lowered.conversion_units == 700);
    assert_eq!(priced.with_fee_bound(1).unwrap().gas_units, 1);
    for fee in [0, 5_000_001] {
        assert!(xlm.with_fee_bound(fee).is_err(), "{fee}");
    }
    // A gas carry: the wallet repays the bound less the carry, at least zero, and an XLM wallet
    // counts exactly that. The fee bound stays.
    let bound = xlm.with_fee_bound(2_670_684).unwrap();
    assert_eq!(bound.with_gas_carry(0).unwrap(), bound);
    let carried = bound.with_gas_carry(670_684).unwrap();
    assert_eq!(
        (
            carried.gas_units,
            carried.spent_units,
            carried.max_fee_stroops,
            bound.repaid_after_carry(670_684)
        ),
        (2_000_000, 4_000_000, 2_670_684, 2_000_000)
    );
    let covered = bound.with_gas_carry(3_000_000).unwrap();
    assert_eq!(
        (
            covered.gas_units,
            covered.spent_units,
            bound.repaid_after_carry(3_000_000),
            bound.repaid_after_carry(u128::MAX)
        ),
        (0, 2_000_000, 0, 0)
    );
    // Another asset: the gas falls in proportion and rounds up, so it stays above zero while the
    // wallet repays any stroop.
    let other = priced.with_fee_bound(2_670_684).unwrap();
    let half = other.with_gas_carry(1_335_342).unwrap();
    assert_eq!((half.gas_units, half.spent_units), (164_858, 165_558));
    assert_eq!(other.with_gas_carry(2_670_683).unwrap().gas_units, 1);
    assert_eq!(other.with_gas_carry(2_670_684).unwrap().gas_units, 0);
    let negative = ExpenseBounds {
        gas_units: -1,
        ..xlm
    };
    assert!(negative.with_fee_bound(100).is_err());
}

#[test]
fn simple_common_and_custom_wallets_run_the_complete_workflow() {
    let mut lines = vec![
        "# Recorded by crates/allowit-stellar/tests/policy_wallet.rs; executed by crates/policy-wallet/src/core_vectors_tests.rs.".to_string(),
        format!("network {}", hexs(&network_id(NETWORK).unwrap())),
        format!("timestamp {NOW}"),
        format!("vault {}", hexs(&address(&vault()).unwrap().to_xdr(Limits::none()).unwrap())),
        format!("deployer {}", hexs(&address(&deployer()).unwrap().to_xdr(Limits::none()).unwrap())),
    ];
    for tier in [PolicyTier::Simple, PolicyTier::Common, PolicyTier::Custom] {
        let steps = workflow(tier);
        let names: Vec<_> = steps.iter().map(|s| s.0.as_str()).collect();
        assert_eq!(
            names,
            [
                "upload",
                "create",
                "transfer",
                "deposit",
                "redeem",
                "pause",
                "resume",
                "params",
                "transfer_v3",
                "recover",
                "stop"
            ]
        );
        for (name, envelope, ledger, result, state) in steps {
            if name == "upload" {
                continue;
            }
            let x::TransactionEnvelope::Tx(env) = de(&envelope) else {
                panic!()
            };
            lines.push(format!(
                "{} {} {} {} {} {}",
                tier.kind(),
                name,
                ledger,
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
    // Every recorded transaction is a layout 5 packet that this crate built: the creation goes
    // through the deployer with the owner's whole tree, and each execution carries the wallet's
    // own authorization with both cosignatures and is sent from the server's sending account.
    let recorded = std::fs::read_to_string(VECTORS).unwrap();
    let mut executions = 0;
    for line in recorded.lines().filter(|l| !l.starts_with('#')) {
        let parts: Vec<_> = line.split(' ').collect();
        if parts.len() != 6 {
            continue;
        }
        let bytes = (0..parts[3].len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&parts[3][i..i + 2], 16).unwrap())
            .collect::<Vec<_>>();
        let tx = x::Transaction::from_xdr(&bytes, Limits::none()).unwrap();
        let op = host_op(&tx);
        let x::HostFunction::InvokeContract(call) = &op.host_function else {
            panic!("unexpected recorded step {}", parts[1])
        };
        match parts[1] {
            "create" => {
                assert_eq!(call.contract_address, address(&deployer()).unwrap());
                admin::validate_auth(NETWORK, &op.host_function, &op.auth, None).unwrap();
                let config = &items(&call.args[3])[0];
                assert_eq!(digest(field(config, "source_hash")), hash(SOURCE));
                assert_eq!(source_of(&tx), account_for_seed(&OWNER));
            }
            name if name.starts_with("transfer") || name == "deposit" || name == "redeem" => {
                assert_eq!(call.function_name.0.as_slice(), b"execute");
                assert_eq!(source_of(&tx), sender());
                let [entry] = op.auth.as_slice() else {
                    panic!()
                };
                let x::SorobanCredentials::Address(c) = &entry.credentials else {
                    panic!()
                };
                assert_eq!(items(&c.signature).len(), 2);
                assert_eq!(addr(&items(&call.args[0])[6]), sender());
                executions += 1;
            }
            _ => assert_eq!(source_of(&tx), account_for_seed(&OWNER)),
        }
    }
    assert_eq!(executions, 12);
}
#[test]
fn the_sending_account_is_the_gas_payee_and_the_gas_follows_the_priced_expense() {
    let wasm = wasm_for(PolicyTier::Simple);
    let chain = ModelChain::new(BTreeMap::from([(hash(&wasm), PolicyTier::Simple)]));
    let c = create(&chain, PolicyTier::Simple, &wasm, [0x31; 32]);
    let state = sending_state(&chain, &c);
    let r = request::transfer(&c, &state, [1; 32], &account_for_seed(&RECIPIENT), 1).unwrap();
    // A policy wallet request names no fee payer; the terms name the sending account.
    assert!(r.fee_bounds.is_none());
    let mut t = terms(1, chain.ledger());
    assert_eq!(gas_payee(&r, &t).unwrap(), sender());
    // Preparation repays the priced fee bound, not the caller's ceiling.
    let prepared =
        rpc::prepare_with(&chain, &c, &r, &t, Some(chain.accounting()), NOW, NOW + 300).unwrap();
    let bound = prepared.terms.expense.as_ref().unwrap();
    assert_eq!(bound.gas_units, i128::from(bound.max_fee_stroops));
    assert!(bound.max_fee_stroops < MAX_FEE);
    // An explicit repayment to another account conflicts with the sending account.
    t.gas = Some(GasRepayment {
        stroops: 1,
        payee: account_for_seed(&RECIPIENT),
    });
    assert!(
        gas_payee(&r, &t)
            .unwrap_err()
            .contains("name other accounts")
    );
    // Without a sending account the operation has no gas payee.
    t.gas = None;
    t.sender = None;
    assert!(
        gas_payee(&r, &t)
            .unwrap_err()
            .contains("needs the server's sending account")
    );
}
#[test]
fn a_simple_wallet_counts_the_gross_volume_of_a_lossless_deposit() {
    let wasm = wasm_for(PolicyTier::Simple);
    let chain = ModelChain::new(BTreeMap::from([(hash(&wasm), PolicyTier::Simple)]));
    let mut c = create(&chain, PolicyTier::Simple, &wasm, [0x32; 32]);
    // A Simple wallet stores no params: the server holds them and evaluates its limits.
    c.params
        .0
        .insert("daily_volume_limit".into(), PolicyValue::Int(6_000_000));
    let state = sending_state(&chain, &c);
    let ledger = chain.ledger();
    let deposit = request::deposit(&c, &state, [2; 32], &vault(), 5_000_000, 5_000_000).unwrap();
    let lossless = ExecutionTerms {
        args: PolicyParams::default(),
        expense: Some(ExpenseBounds::xlm(0, 0, MAX_FEE, ledger - 1, NOW).unwrap()),
        gas: None,
        sender: Some(sender()),
        gas_carry: 0,
    };
    run(&chain, &c, &deposit, &lossless, "deposit").unwrap();
    // The deposit spent only its gas; its gross amount fills the day's volume.
    let account = chain.accounting();
    assert_eq!(
        (account.spent_daily, account.volume_daily),
        (gas(), 5_000_000 + gas())
    );
    let state = sending_state(&chain, &c);
    let ledger = chain.ledger();
    let recipient = account_for_seed(&RECIPIENT);
    let headroom = 6_000_000 - account.volume_daily - gas();
    let over = request::transfer(&c, &state, [3; 32], &recipient, headroom + 1).unwrap();
    assert!(
        rpc::prepare_with(
            &chain,
            &c,
            &over,
            &terms(headroom + 1, ledger),
            Some(chain.accounting()),
            NOW,
            NOW + 300
        )
        .unwrap_err()
        .contains("DailyVolumeLimitExceeded")
    );
    let within = request::transfer(&c, &state, [4; 32], &recipient, headroom).unwrap();
    run(&chain, &c, &within, &terms(headroom, ledger), "transfer").unwrap();
    assert_eq!(chain.accounting().volume_daily, 6_000_000);
}
/// A chain whose wallet entry `t` lapsed, and with `instance` the wallet's instance too: the
/// ledger reports them no longer live, and each simulation restores them in place. With
/// `preamble`, a simulation asks for a separate restoration first.
struct Lapsed<'a> {
    chain: &'a ModelChain,
    preamble: bool,
    instance: bool,
    /// A code entry that the simulation restores in place too.
    code: Option<[u8; 32]>,
}
impl rpc::Rpc for Lapsed<'_> {
    fn call(&self, method: &str, params: Value) -> Result<Value> {
        let mut reply = self.chain.call(method, params)?;
        if method == "getLedgerEntries" && self.instance {
            for entry in reply["entries"].as_array_mut().unwrap() {
                let data: x::LedgerEntryData = de(entry["xdr"].as_str().unwrap());
                if matches!(data, x::LedgerEntryData::ContractData(_)) {
                    entry["liveUntilLedgerSeq"] = json!(0);
                }
            }
        }
        if method == "simulateTransaction"
            && reply.get("error").is_none()
            && let Some(data) = reply["transactionData"].as_str()
        {
            if self.preamble {
                reply["restorePreamble"] =
                    json!({"minResourceFee": "1000", "transactionData": data});
            } else {
                let wallet = self
                    .chain
                    .0
                    .lock()
                    .unwrap()
                    .wallet
                    .as_ref()
                    .unwrap()
                    .address
                    .clone();
                let mut data: x::SorobanTransactionData = de(data);
                let entry = |key: x::ScVal| {
                    x::LedgerKey::ContractData(x::LedgerKeyContractData {
                        contract: address(&wallet).unwrap(),
                        key,
                        durability: x::ContractDataDurability::Persistent,
                    })
                };
                let mut lapsed = vec![entry(x::ScVal::Symbol("t".try_into().unwrap()))];
                if self.instance {
                    lapsed.push(entry(x::ScVal::LedgerKeyContractInstance));
                }
                if let Some(code) = self.code {
                    lapsed.push(x::LedgerKey::ContractCode(x::LedgerKeyContractCode {
                        hash: x::Hash(code),
                    }));
                }
                let archived: Vec<u32> = (0..lapsed.len() as u32).collect();
                data.resources.footprint.read_write = lapsed.try_into().unwrap();
                data.ext = x::SorobanTransactionDataExt::V1(x::SorobanResourcesExtV0 {
                    archived_soroban_entries: archived.try_into().unwrap(),
                });
                reply["transactionData"] = json!(b64(&data));
            }
        }
        Ok(reply)
    }
}
/// What a confirmed operation adds to the figures that the server keeps for a Simple wallet is
/// what the wallet counts for it: one call, its signed spent units, and its gross amount with its
/// gas in the day's volume. A lossless deposit spends only its gas.
#[test]
fn the_usage_of_an_operation_is_what_the_wallet_counts() {
    let wasm = wasm_for(PolicyTier::Simple);
    let chain = ModelChain::new(BTreeMap::from([(hash(&wasm), PolicyTier::Simple)]));
    let c = create(&chain, PolicyTier::Simple, &wasm, [0x37; 32]);
    let recipient = account_for_seed(&RECIPIENT);
    for (id, name) in [(1u8, "transfer"), (2, "deposit")] {
        let state = sending_state(&chain, &c);
        let ledger = chain.ledger();
        let (request, t) = if name == "transfer" {
            (
                request::transfer(&c, &state, [id; 32], &recipient, 1_000_000).unwrap(),
                terms(1_000_000, ledger),
            )
        } else {
            (
                request::deposit(&c, &state, [id; 32], &vault(), 5_000_000, 5_000_000).unwrap(),
                ExecutionTerms {
                    expense: Some(ExpenseBounds::xlm(0, 0, MAX_FEE, ledger - 1, NOW).unwrap()),
                    ..terms(0, ledger)
                },
            )
        };
        let before = chain.accounting();
        let signed = run(&chain, &c, &request, &t, name).unwrap();
        let usage = operation_usage(&signed.prepared).unwrap().unwrap();
        let after = chain.accounting();
        assert!(usage.gas_units > 0 && !usage.unpriced, "{name}");
        assert_eq!(after.calls, before.calls + 1, "{name}");
        assert_eq!(
            after.spent_total - before.spent_total,
            usage.spent_units,
            "{name}"
        );
        assert_eq!(
            after.spent_daily - before.spent_daily,
            usage.spent_units,
            "{name}"
        );
        assert_eq!(
            after.volume_daily - before.volume_daily,
            usage.amount_units + usage.gas_units,
            "{name}"
        );
    }
}
#[test]
fn a_lapsed_entry_restores_in_the_operation_that_needs_it() {
    let wasm = wasm_for(PolicyTier::Common);
    let chain = ModelChain::new(BTreeMap::from([(hash(&wasm), PolicyTier::Common)]));
    let c = create(&chain, PolicyTier::Common, &wasm, [0x33; 32]);
    let state = sending_state(&chain, &c);
    let ledger = chain.ledger();
    let recipient = account_for_seed(&RECIPIENT);
    let transfer = request::transfer(&c, &state, [1; 32], &recipient, 1_000_000).unwrap();
    let lapsed = Lapsed {
        chain: &chain,
        preamble: false,
        instance: false,
        code: None,
    };
    let prepared = rpc::prepare_with(
        &lapsed,
        &c,
        &transfer,
        &terms(1_000_000, ledger),
        Some(chain.accounting()),
        NOW,
        NOW + 300,
    )
    .unwrap();
    let served = authorize_server(&prepared, &SERVER, NOW, None).unwrap();
    let simulated = rpc::simulate(&lapsed, &served).unwrap();
    let proof = sign(&simulated, &AGENT, NOW).unwrap();
    let signed = authorize(&simulated, &[proof], NOW).unwrap();
    let sealed = rpc::seal(&lapsed, &signed, |hash| {
        Ok(SigningKey::from_bytes(&SENDER).sign(hash).to_bytes())
    })
    .unwrap();
    // The sealed transaction restores `t` itself, and its fee pays for that.
    let x::TransactionEnvelope::Tx(envelope) = de(&sealed.transaction_xdr) else {
        panic!()
    };
    let x::TransactionExt::V1(data) = &envelope.tx.ext else {
        panic!()
    };
    assert!(matches!(
        &data.ext,
        x::SorobanTransactionDataExt::V1(ext) if ext.archived_soroban_entries.as_slice() == [0]
    ));
    chain.step("transfer");
    assert_eq!(
        rpc::broadcast(&chain, &sealed, NOW).unwrap(),
        rpc::Broadcast::Submitted
    );
    // An entry that needs a separate restoration first prepares nothing.
    let preamble = Lapsed {
        chain: &chain,
        preamble: true,
        instance: false,
        code: None,
    };
    let state = sending_state(&chain, &c);
    let ledger = chain.ledger();
    let again = request::transfer(&c, &state, [2; 32], &recipient, 1_000_000).unwrap();
    assert!(
        rpc::prepare_with(
            &preamble,
            &c,
            &again,
            &terms(1_000_000, ledger),
            Some(chain.accounting()),
            NOW,
            NOW + 300
        )
        .unwrap_err()
        .contains("separate restoration")
    );
}
#[test]
fn an_explicit_gas_repayment_keeps_its_gas_through_pricing() {
    let wasm = wasm_for(PolicyTier::Common);
    let chain = ModelChain::new(BTreeMap::from([(hash(&wasm), PolicyTier::Common)]));
    let c = create(&chain, PolicyTier::Common, &wasm, [0x34; 32]);
    let recipient = account_for_seed(&RECIPIENT);
    // The server repays the whole gas cap once, and later less after a carry.
    for (id, repaid) in [(1u8, i128::from(MAX_FEE)), (2, 500)] {
        let state = sending_state(&chain, &c);
        let ledger = chain.ledger();
        let transfer = request::transfer(&c, &state, [id; 32], &recipient, 1_000_000).unwrap();
        let explicit = ExecutionTerms {
            expense: Some(ExpenseBounds {
                gas_units: repaid,
                spent_units: 1_000_000 + repaid,
                ..ExpenseBounds::xlm(1_000_000, 0, MAX_FEE, ledger - 1, NOW).unwrap()
            }),
            gas: Some(GasRepayment {
                stroops: repaid,
                payee: sender(),
            }),
            ..terms(1_000_000, ledger)
        };
        let prepared = rpc::prepare_with(
            &chain,
            &c,
            &transfer,
            &explicit,
            Some(chain.accounting()),
            NOW,
            NOW + 300,
        )
        .unwrap();
        // Only the transaction's fee bound moved.
        let expense = prepared.terms.expense.as_ref().unwrap();
        assert_eq!(
            (
                expense.gas_units,
                expense.spent_units,
                expense.max_fee_stroops
            ),
            (repaid, 1_000_000 + repaid, gas() as u32)
        );
        let before = chain.balance();
        let served = authorize_server(&prepared, &SERVER, NOW, None).unwrap();
        let simulated = rpc::simulate(&chain, &served).unwrap();
        let proof = sign(&simulated, &AGENT, NOW).unwrap();
        let signed = authorize(&simulated, &[proof], NOW).unwrap();
        let sealed = seal(&chain, &signed).unwrap();
        chain.step("transfer");
        assert_eq!(
            rpc::broadcast(&chain, &sealed, NOW).unwrap(),
            rpc::Broadcast::Submitted
        );
        assert_eq!(chain.balance(), before - 1_000_000 - repaid);
    }
    // Counted gas that differs from the repayment is refused before any signature.
    let state = sending_state(&chain, &c);
    let ledger = chain.ledger();
    let transfer = request::transfer(&c, &state, [3; 32], &recipient, 1_000_000).unwrap();
    let mismatched = ExecutionTerms {
        gas: Some(GasRepayment {
            stroops: 500,
            payee: sender(),
        }),
        ..terms(1_000_000, ledger)
    };
    assert!(
        rpc::prepare_with(
            &chain,
            &c,
            &transfer,
            &mismatched,
            Some(chain.accounting()),
            NOW,
            NOW + 300
        )
        .unwrap_err()
        .contains("differs from the gas that the wallet repays")
    );
}
#[test]
fn the_server_revalidates_its_own_authorized_preparation() {
    // The engine's order: prepare, authorize as the server, then revalidate before the agent's
    // signature joins and the sending account seals.
    for tier in [PolicyTier::Simple, PolicyTier::Common] {
        let wasm = wasm_for(tier);
        let chain = ModelChain::new(BTreeMap::from([(hash(&wasm), tier)]));
        let c = create(&chain, tier, &wasm, [0x38; 32]);
        let state = sending_state(&chain, &c);
        let ledger = chain.ledger();
        let recipient = account_for_seed(&RECIPIENT);
        let transfer = request::transfer(&c, &state, [1; 32], &recipient, 1_000_000).unwrap();
        let prepared = rpc::prepare_with(
            &chain,
            &c,
            &transfer,
            &terms(1_000_000, ledger),
            Some(chain.accounting()),
            NOW,
            NOW + 300,
        )
        .unwrap();
        let served = authorize_server(&prepared, &SERVER, NOW, None).unwrap();
        rpc::revalidate_prepared(&chain, &served, NOW).unwrap_or_else(|e| panic!("{tier:?}: {e}"));
    }
}
#[test]
fn a_contract_wallet_reports_the_roles_that_its_configuration_holds() {
    let wasm = wasm_for(PolicyTier::Common);
    let chain = ModelChain::new(BTreeMap::from([(hash(&wasm), PolicyTier::Common)]));
    let c = create(&chain, PolicyTier::Common, &wasm, [0x37; 32]);
    // A contract wallet has no account signers: discovery names the owner, agent and server
    // that its configuration holds on chain, and weighs them as a keypair wallet's account does.
    let live = rpc::trusted_state_for_discovery(&chain, &c, Some(chain.accounting())).unwrap();
    let state = &live.state;
    assert_eq!(
        (&state.owner, &state.agent, &state.server),
        (&c.owner, &c.agent, &c.server)
    );
    let weight = |key: &str| state.policy_role_weight(key).unwrap();
    assert_eq!(
        (
            weight(&c.owner),
            weight(&c.agent),
            weight(&c.server),
            weight(&account_for_seed(&RECIPIENT))
        ),
        (3, 1, 1, 0)
    );
    // The wallet's own address has no role, and text that is no address is refused.
    assert_eq!(weight(&c.wallet), 0);
    assert!(state.policy_role_weight("not an address").is_err());
}
/// A repayment never exceeds the wallet's gas cap: a fee bound above it, less no carry, is refused.
#[test]
fn a_repayment_never_exceeds_the_gas_cap() {
    let ceiling = ExpenseBounds::xlm(5, 0, 2_000, LEDGER, NOW).unwrap();
    assert!(ceiling.with_repayment(1_009, 0, 1_000).is_err());
    // After a carry the repayment fits.
    assert_eq!(
        ceiling.with_repayment(1_009, 100, 1_000).unwrap().gas_units,
        909
    );
}
/// A wallet that counts an asset other than XLM converts its repayment once, at the rate of the
/// server's ceiling.
#[test]
fn a_repayment_of_another_asset_counts_units_at_the_ceiling_rate() {
    // The ceiling prices 1,000,000 stroops at 10 asset units, over a principal of 5.
    let ceiling = ExpenseBounds {
        gas_units: 10,
        spent_units: 15,
        ..ExpenseBounds::xlm(5, 0, 1_000_000, LEDGER, NOW).unwrap()
    };
    // Without a carry the conversion is the fee bound's own.
    assert_eq!(
        ceiling.with_repayment(2_000, 0, 1_000_000).unwrap(),
        ceiling.with_fee_bound(2_000).unwrap()
    );
}
#[test]
fn a_gas_carry_lowers_the_repayment_and_the_gas_that_the_wallet_counts() {
    let wasm = wasm_for(PolicyTier::Common);
    let chain = ModelChain::new(BTreeMap::from([(hash(&wasm), PolicyTier::Common)]));
    let c = create(&chain, PolicyTier::Common, &wasm, [0x36; 32]);
    let recipient = account_for_seed(&RECIPIENT);
    // A carry below the priced bound leaves the rest to repay; a carry above it repays nothing
    // and counts no gas. The transaction still declares the whole bound.
    for (id, carry) in [(1u8, 300u128), (2, gas() as u128 * 3)] {
        let state = sending_state(&chain, &c);
        let ledger = chain.ledger();
        let transfer = request::transfer(&c, &state, [id; 32], &recipient, 1_000_000).unwrap();
        let carried = ExecutionTerms {
            gas_carry: carry,
            ..terms(1_000_000, ledger)
        };
        let prepared = rpc::prepare_with(
            &chain,
            &c,
            &transfer,
            &carried,
            Some(chain.accounting()),
            NOW,
            NOW + 300,
        )
        .unwrap();
        let repaid = (gas() - carry as i128).max(0);
        let expense = prepared.terms.expense.as_ref().unwrap();
        assert_eq!(
            (
                expense.gas_units,
                expense.spent_units,
                i128::from(expense.max_fee_stroops)
            ),
            (repaid, 1_000_000 + repaid, gas())
        );
        let before = chain.balance();
        let served = authorize_server(&prepared, &SERVER, NOW, None).unwrap();
        let simulated = rpc::simulate(&chain, &served).unwrap();
        let proof = sign(&simulated, &AGENT, NOW).unwrap();
        let signed = authorize(&simulated, &[proof], NOW).unwrap();
        let sealed = seal(&chain, &signed).unwrap();
        let x::TransactionEnvelope::Tx(envelope) = de(&sealed.transaction_xdr) else {
            panic!()
        };
        assert_eq!(i128::from(envelope.tx.fee), gas());
        chain.step("transfer");
        assert_eq!(
            rpc::broadcast(&chain, &sealed, NOW).unwrap(),
            rpc::Broadcast::Submitted
        );
        assert_eq!(chain.balance(), before - 1_000_000 - repaid);
        let settled = rpc::receipt_by_hash(&chain, &c.network, &sealed.transaction_hash)
            .unwrap()
            .unwrap();
        rpc::validate_settled_policy_packet(&sealed, &settled).unwrap();
        assert_eq!(
            (
                rpc::repaid_gas_stroops(&settled).unwrap(),
                rpc::counted_gas_units(&settled).unwrap()
            ),
            (repaid as u128, repaid)
        );
    }
    // An explicit repayment takes no carry.
    let state = sending_state(&chain, &c);
    let ledger = chain.ledger();
    let transfer = request::transfer(&c, &state, [3; 32], &recipient, 1_000_000).unwrap();
    let both = ExecutionTerms {
        expense: Some(ExpenseBounds {
            gas_units: 500,
            spent_units: 1_000_500,
            ..ExpenseBounds::xlm(1_000_000, 0, MAX_FEE, ledger - 1, NOW).unwrap()
        }),
        gas: Some(GasRepayment {
            stroops: 500,
            payee: sender(),
        }),
        gas_carry: 100,
        ..terms(1_000_000, ledger)
    };
    assert!(
        rpc::prepare_with(
            &chain,
            &c,
            &transfer,
            &both,
            Some(chain.accounting()),
            NOW,
            NOW + 300
        )
        .unwrap_err()
        .contains("takes no gas carry")
    );
}
#[test]
fn recovery_finds_a_policy_wallet_execution_by_its_event() {
    use allowit_stellar::provider::runtime::Runtime;
    let wasm = wasm_for(PolicyTier::Common);
    let chain = std::sync::Arc::new(ModelChain::new(BTreeMap::from([(
        hash(&wasm),
        PolicyTier::Common,
    )])));
    let c = create(&chain, PolicyTier::Common, &wasm, [0x35; 32]);
    let state = sending_state(&chain, &c);
    let ledger = chain.ledger();
    let recipient = account_for_seed(&RECIPIENT);
    let transfer = request::transfer(&c, &state, [1; 32], &recipient, 1_000_000).unwrap();
    let signed = run(&chain, &c, &transfer, &terms(1_000_000, ledger), "transfer").unwrap();
    let prepared = &signed.prepared;
    // The sealed transaction is another one than the prepared transaction.
    assert_ne!(signed.transaction_hash, prepared.transaction_hash);
    let runtime = Runtime::from_rpc(chain.clone());
    let observed = runtime.observe_authorizations([prepared]);
    assert_eq!(observed.len(), 1);
    let found = &observed[0];
    assert_eq!(found.receipt.transaction_hash, signed.transaction_hash);
    assert_eq!(found.signed.transaction_xdr, signed.transaction_xdr);
    // An operation that never ran has no event.
    let state = sending_state(&chain, &c);
    let other = request::transfer(&c, &state, [2; 32], &recipient, 1_000_000).unwrap();
    let unsent = authorized(&chain, &c, &other, &terms(1_000_000, chain.ledger())).unwrap();
    assert!(
        runtime
            .observe_authorizations([&unsent.prepared])
            .is_empty()
    );
}
#[test]
fn a_creation_funds_the_asset_and_the_gas_and_recovery_returns_both() {
    let mut c = installation(PolicyTier::Common, [1; 32], [2; 32]);
    let xlm = xlm();
    // An XLM wallet takes one amount: its gas is its asset.
    assert_eq!(
        admin::creation_funding(&c, 5, 0).unwrap(),
        vec![(xlm.clone(), 5)]
    );
    assert!(
        admin::creation_funding(&c, 5, 7)
            .unwrap_err()
            .contains("XLM")
    );
    // A wallet of another asset also takes the XLM from which it repays network fees.
    c.asset = Contract([77; 32]).to_string();
    assert_eq!(
        admin::creation_funding(&c, 5, 7).unwrap(),
        vec![(c.asset.clone(), 5), (xlm.clone(), 7)]
    );
    assert_eq!(
        admin::creation_funding(&c, 0, 7).unwrap(),
        vec![(xlm.clone(), 7)]
    );
    assert!(admin::creation_funding(&c, -1, 0).is_err());
    // A recovery of everything returns the asset, then the XLM, then nothing.
    assert_eq!(
        admin::next_recovery(&c.asset, &xlm, 3, 9),
        Some(c.asset.as_str())
    );
    assert_eq!(
        admin::next_recovery(&c.asset, &xlm, 0, 9),
        Some(xlm.as_str())
    );
    assert_eq!(admin::next_recovery(&c.asset, &xlm, 0, 0), None);
    assert_eq!(admin::next_recovery(&xlm, &xlm, 0, 0), None);
}
/// The JSON document of a signed packet.
fn code_doc(p: &allowit_core::vendor::runtime::Signed) -> Value {
    serde_json::from_slice(p.bytes()).unwrap()
}
/// What the SDK engine does with a wallet code transaction, for this crate's tests: prepare it,
/// send it while it is needed until the network accepts it, and read its receipt. A
/// transaction that the ledger included and failed is an error that names it and the fee that
/// its source paid.
trait SendCode {
    /// Upload `wasm`.
    fn send_code(
        &self,
        i: &allowit_core::vendor::runtime::Installation,
        wasm: &[u8],
        max_fee: u64,
    ) -> allowit_core::client::error::Result<Option<allowit_core::vendor::runtime::Receipt>>;
    /// Renew the live code `code` once it is due.
    fn renew_code(
        &self,
        code: &[u8; 32],
        max_fee: u64,
    ) -> allowit_core::client::error::Result<Option<allowit_core::vendor::runtime::Receipt>>;
}
impl<T: allowit_core::vendor::RuntimeProvider + ?Sized> SendCode for T {
    fn send_code(
        &self,
        i: &allowit_core::vendor::runtime::Installation,
        wasm: &[u8],
        max_fee: u64,
    ) -> allowit_core::client::error::Result<Option<allowit_core::vendor::runtime::Receipt>> {
        let prepared = self.prepare_code_within(i, wasm, max_fee, NOW)?;
        send_prepared(self, prepared)
    }
    fn renew_code(
        &self,
        code: &[u8; 32],
        max_fee: u64,
    ) -> allowit_core::client::error::Result<Option<allowit_core::vendor::runtime::Receipt>> {
        let prepared = self.prepare_code_renewal(code, max_fee, NOW)?;
        send_prepared(self, prepared)
    }
}
fn send_prepared<T: allowit_core::vendor::RuntimeProvider + ?Sized>(
    provider: &T,
    prepared: Option<allowit_core::vendor::runtime::Signed>,
) -> allowit_core::client::error::Result<Option<allowit_core::vendor::runtime::Receipt>> {
    use allowit_core::client::error::Error;
    use allowit_core::vendor::runtime::Status;
    let Some(signed) = prepared else {
        return Ok(None);
    };
    let mut status = Status::Prepared;
    for _ in 0..3 {
        if !provider.code_needed(&signed)? {
            return Ok(None);
        }
        status = provider.broadcast(&signed, NOW)?;
        if status != Status::Prepared {
            break;
        }
    }
    if status == Status::Prepared {
        return Err(Error::config(
            "The network did not accept the code transaction",
        ));
    }
    let receipt = provider
        .observe(&signed)?
        .ok_or_else(|| Error::config("The code transaction has no receipt"))?;
    let info = receipt.info()?;
    if info.status != Status::Confirmed {
        return Err(
            Error::config("The wallet code transaction failed on the ledger").with_details(json!({
                "transactionHash": hexs(&info.transaction_hash),
                "nativeUnits": info.fee.native_units.to_string(),
            })),
        );
    }
    Ok(Some(receipt))
}
/// The server's runtime from the plugin sends with the server's own accounts, and so does its
/// diagnostic session: a code upload through either reaches them, and so does the renewal of
/// shared code before it lapses. Nothing restores code that lapsed.
#[test]
fn the_sending_runtime_and_its_diagnostic_session_send_with_the_servers_accounts() {
    use allowit_core::vendor::plugin::RailPlugin;
    use allowit_core::vendor::profiles::Description;
    use allowit_core::vendor::runtime::SendingAccounts;
    use allowit_core::vendor::runtime::{Installation, Transport};
    use std::sync::Arc;
    struct Wire(Arc<ModelChain>);
    impl Transport for Wire {
        fn call(&self, method: &str, params: Value) -> allowit_core::client::error::Result<Value> {
            rpc::Rpc::call(&*self.0, method, params)
                .map_err(allowit_core::client::error::Error::config)
        }
    }
    struct Sending;
    // Every signature that a sending account gives: a refusal before signing gives none.
    static SIGNATURES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let signatures = || SIGNATURES.load(std::sync::atomic::Ordering::SeqCst);
    impl SendingAccounts for Sending {
        fn account(&self) -> allowit_core::client::error::Result<String> {
            Ok(sender())
        }
        fn sign(
            &self,
            account: &str,
            hash: &[u8; 32],
        ) -> allowit_core::client::error::Result<Vec<u8>> {
            assert_eq!(account, sender());
            SIGNATURES.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(SigningKey::from_bytes(&SENDER)
                .sign(hash)
                .to_bytes()
                .to_vec())
        }
    }
    // Sending accounts that are all leased; another account may renew the code `renews` at the
    // same time.
    struct Leased(Arc<ModelChain>, Option<[u8; 32]>);
    impl SendingAccounts for Leased {
        fn account(&self) -> allowit_core::client::error::Result<String> {
            if let Some(code) = self.1 {
                self.0.renewed(code);
            }
            Err(allowit_core::client::error::Error::config(
                "All sending accounts are leased",
            ))
        }
        fn sign(&self, _: &str, _: &[u8; 32]) -> allowit_core::client::error::Result<Vec<u8>> {
            panic!("a leased account signs nothing")
        }
    }
    // A sending account whose signer refuses while another account renews the code.
    struct Refusing(Arc<ModelChain>, [u8; 32]);
    // A sending account whose signer gives a signature that does not verify while another
    // account renews the code.
    struct Garbled(Arc<ModelChain>, [u8; 32]);
    impl SendingAccounts for Garbled {
        fn account(&self) -> allowit_core::client::error::Result<String> {
            Ok(sender())
        }
        fn sign(&self, _: &str, _: &[u8; 32]) -> allowit_core::client::error::Result<Vec<u8>> {
            self.0.renewed(self.1);
            Ok(vec![0; 64])
        }
    }
    impl SendingAccounts for Refusing {
        fn account(&self) -> allowit_core::client::error::Result<String> {
            Ok(sender())
        }
        fn sign(&self, _: &str, _: &[u8; 32]) -> allowit_core::client::error::Result<Vec<u8>> {
            self.0.renewed(self.1);
            Err(allowit_core::client::error::Error::config(
                "The signer is unavailable",
            ))
        }
    }
    let wasm = wasm_for(PolicyTier::Common);
    let chain = Arc::new(ModelChain::new(BTreeMap::from([(
        hash(&wasm),
        PolicyTier::Common,
    )])));
    let c = create(&chain, PolicyTier::Common, &wasm, [0x36; 32]);
    let owners = allowit_stellar::PLUGIN.owner_runtime();
    let document = owners
        .configuration(NETWORK, &serde_json::to_vec(&c).unwrap())
        .unwrap();
    let installation = Installation {
        description: Description {
            network: NETWORK.into(),
            wallet: c.wallet.clone(),
            agent: c.agent.clone(),
            policy_id: "policy".into(),
            owner: c.owner.clone(),
            server: c.server.clone(),
            asset: c.asset.clone(),
            asset_symbol: c.asset_symbol.clone(),
            source: c.policy_source.clone(),
            source_hash: hex(&c.source_hash),
            module_digest: hex(&c.module_digest),
            params: document.params.clone(),
        },
        config: document.document().to_owned(),
        export: None,
        authority: None,
    };
    let provider = allowit_stellar::PLUGIN
        .sending_runtime(NETWORK, Arc::new(Wire(chain.clone())), Arc::new(Sending))
        .unwrap();
    // The plain runtime has no sending account.
    let plain = allowit_stellar::PLUGIN
        .runtime(NETWORK, Arc::new(Wire(chain.clone())))
        .unwrap();
    let unsent = wasm_for(PolicyTier::Custom);
    assert!(
        plain
            .send_code(&installation, &unsent, u64::from(u32::MAX))
            .unwrap_err()
            .message
            .contains("no sending account")
    );
    let session = provider.diagnostic_session(&installation).unwrap().unwrap();
    // Code that the ledger does not hold yet: the session's sending account uploads it.
    let other = wasm_for(PolicyTier::Simple);
    chain
        .0
        .lock()
        .unwrap()
        .tiers
        .insert(hash(&other), PolicyTier::Simple);
    let signed = signatures();
    // An upload whose simulation writes another entry than the code is refused.
    chain.0.lock().unwrap().upload_names_another_entry = true;
    let refused = session
        .provider
        .send_code(&installation, &other, u64::from(u32::MAX))
        .unwrap_err();
    assert!(
        refused.message.contains("another entry than its code"),
        "{}",
        refused.message
    );
    chain.0.lock().unwrap().upload_names_another_entry = false;
    // Another transaction uploads the code after it was read: the upload's simulation only
    // reads the code entry, so nothing is signed or sent.
    chain.0.lock().unwrap().uploaded_meanwhile = true;
    assert!(
        session
            .provider
            .send_code(&installation, &other, u64::from(u32::MAX))
            .unwrap()
            .is_none()
    );
    assert_eq!(signatures(), signed);
    {
        let mut m = chain.0.lock().unwrap();
        assert!(!m.uploaded_meanwhile);
        m.code.remove(&hash(&other));
        m.code_bytes.remove(&hash(&other));
    }
    // So with a fee ceiling below the upload's fee: an upload that is not needed costs nothing,
    // so no ceiling refuses it.
    chain.0.lock().unwrap().uploaded_meanwhile = true;
    assert!(
        session
            .provider
            .send_code(&installation, &other, 100)
            .unwrap()
            .is_none()
    );
    // Another sending account uploads the code just after the simulation, which still writes
    // its entry: the code, read again before the signature, is live, and nothing is signed.
    {
        let mut m = chain.0.lock().unwrap();
        m.code.remove(&hash(&other));
        m.code_bytes.remove(&hash(&other));
        m.uploaded_after_simulation = true;
    }
    assert!(
        session
            .provider
            .send_code(&installation, &other, u64::from(u32::MAX))
            .unwrap()
            .is_none()
    );
    assert_eq!(signatures(), signed);
    {
        let mut m = chain.0.lock().unwrap();
        assert!(!m.uploaded_after_simulation);
        m.code.remove(&hash(&other));
        m.code_bytes.remove(&hash(&other));
    }
    // So with a fee ceiling below the upload's fee: no upload is needed, so no ceiling refuses it.
    chain.0.lock().unwrap().uploaded_after_simulation = true;
    assert!(
        session
            .provider
            .send_code(&installation, &other, 100)
            .unwrap()
            .is_none()
    );
    {
        let mut m = chain.0.lock().unwrap();
        m.code.remove(&hash(&other));
        m.code_bytes.remove(&hash(&other));
    }
    // The sending account's own upload lands during the simulation, which then sees its sequence
    // change and refuses: the code, read again, is live, and nothing is needed.
    {
        let mut m = chain.0.lock().unwrap();
        m.uploaded_meanwhile = true;
        m.uploaded_by_source = true;
    }
    assert!(
        session
            .provider
            .send_code(&installation, &other, u64::from(u32::MAX))
            .unwrap()
            .is_none()
    );
    assert_eq!(signatures(), signed);
    {
        let mut m = chain.0.lock().unwrap();
        m.uploaded_by_source = false;
        m.code.remove(&hash(&other));
        m.code_bytes.remove(&hash(&other));
    }
    // The server pays the upload, within its fee ceiling: a ceiling below the simulated fee
    // refuses it before anything is signed or sent.
    let refused = session
        .provider
        .send_code(&installation, &other, 100)
        .unwrap_err();
    assert!(
        refused
            .message
            .contains("exceeds the explicitly selected ceiling"),
        "{}",
        refused.message
    );
    assert!(!chain.0.lock().unwrap().code.contains_key(&hash(&other)));
    // A ceiling outside the native fee range is refused too.
    assert!(
        session
            .provider
            .send_code(&installation, &other, u64::MAX)
            .is_err()
    );
    assert_eq!(signatures(), signed);
    chain.step("upload");
    let receipt = session
        .provider
        .send_code(&installation, &other, u64::from(u32::MAX))
        .unwrap();
    assert!(receipt.is_some());
    assert!(chain.0.lock().unwrap().code.contains_key(&hash(&other)));
    // An upload of live code prepares nothing.
    assert!(
        Deployer {
            rpc: &*chain,
            network: NETWORK,
            now: NOW,
            max_fee_stroops: u32::MAX,
        }
        .upload_wasm(&sender(), &other)
        .unwrap()
        .is_none()
    );
    // The ledger holds it now: nothing is sent.
    assert!(
        session
            .provider
            .send_code(&installation, &other, u64::from(u32::MAX))
            .unwrap()
            .is_none()
    );
    // The runtime itself uploads with the same accounts.
    chain
        .0
        .lock()
        .unwrap()
        .tiers
        .insert(hash(&unsent), PolicyTier::Custom);
    chain.step("upload");
    assert!(
        provider
            .send_code(&installation, &unsent, u64::from(u32::MAX))
            .unwrap()
            .is_some()
    );
    // The installation's code lapsed: it is not present, and nothing restores it. The upload step
    // refuses it before anything is signed or sent.
    let installed = c.module_digest;
    chain.0.lock().unwrap().lapsed_code.insert(installed);
    // The wallet's instance is live and its code lapsed: the wallet is expired.
    let expired = provider.resources(&installation).unwrap_err();
    assert_eq!(
        provider.problem(&expired).code,
        allowit_core::vendor::runtime::CONTRACT_EXPIRED,
        "{}",
        expired.message
    );
    let (signed, sent) = (signatures(), chain.0.lock().unwrap().steps.len());
    let refused = provider
        .send_code(&installation, &wasm, u64::from(u32::MAX))
        .unwrap_err();
    assert_eq!(
        provider.problem(&refused).code,
        allowit_core::vendor::runtime::CONTRACT_EXPIRED,
        "{}",
        refused.message
    );
    assert_eq!(signatures(), signed);
    assert_eq!(chain.0.lock().unwrap().steps.len(), sent);
    // An upload simulation that restores the archived code entry in place is refused too.
    chain.0.lock().unwrap().upload_restores_in_place = true;
    let deployer = Deployer {
        rpc: &*chain,
        network: NETWORK,
        now: NOW,
        max_fee_stroops: u32::MAX,
    };
    let refused = deployer.upload_wasm(&sender(), &wasm).unwrap_err();
    assert!(refused.contains("nothing restores"), "{refused}");
    {
        let mut m = chain.0.lock().unwrap();
        m.upload_restores_in_place = false;
        m.lapsed_code.remove(&installed);
    }
    // A read that finds no entry can omit the entry list: the code is absent.
    chain.0.lock().unwrap().omit_empty_entries = true;
    assert_eq!(
        rpc::code_state(&*chain, NETWORK, &[0x5a; 32]).unwrap(),
        rpc::CodeState::Absent
    );
    chain.0.lock().unwrap().omit_empty_entries = false;
    // The server renews the code that wallets share before it lapses. Once at most half of the
    // network's minimum lifetime of a persistent entry is left, a renewal extends the code to that
    // lifetime, from a sending account, within the ceiling, with the code entry alone in its
    // read-only footprint. It renews nothing before.
    let lifetime = 120_960;
    let ceiling = u64::try_from(RENEW_FEE).unwrap() + 100;
    let due = |left: u32| {
        let head = chain.ledger();
        chain
            .0
            .lock()
            .unwrap()
            .code_live_until
            .insert(installed, head + left);
    };
    due(lifetime / 2 + 1);
    let signed = signatures();
    assert!(provider.renew_code(&installed, ceiling).unwrap().is_none());
    due(lifetime / 2);
    assert!(
        plain
            .renew_code(&installed, ceiling)
            .unwrap_err()
            .message
            .contains("no sending account")
    );
    assert!(
        provider
            .renew_code(&installed, 100)
            .unwrap_err()
            .message
            .contains("exceeds the explicitly selected ceiling")
    );
    assert_eq!(signatures(), signed);
    chain.step("renew");
    assert!(provider.renew_code(&installed, ceiling).unwrap().is_some());
    {
        let m = chain.0.lock().unwrap();
        let (name, signed, ledger, ..) = m.steps.last().unwrap();
        assert_eq!(name, "renew");
        let x::TransactionEnvelope::Tx(env) = de(signed) else {
            panic!()
        };
        assert!(matches!(
            env.tx.operations.as_slice(),
            [x::Operation {
                body: x::OperationBody::ExtendFootprintTtl(x::ExtendFootprintTtlOp { extend_to, .. }),
                ..
            }] if *extend_to == lifetime
        ));
        let x::TransactionExt::V1(data) = &env.tx.ext else {
            panic!()
        };
        assert_eq!(
            data.resources.footprint.read_only.as_slice(),
            [x::LedgerKey::ContractCode(x::LedgerKeyContractCode {
                hash: x::Hash(installed)
            })]
        );
        assert!(data.resources.footprint.read_write.is_empty());
        assert_eq!(source_of(&env.tx), sender());
        assert_eq!(m.code_live_until[&installed], ledger + lifetime);
    }
    assert!(provider.renew_code(&installed, ceiling).unwrap().is_none());
    // The network's own lifetime decides: a network whose entries live longer renews earlier.
    chain.0.lock().unwrap().persistent_lifetime = Some(lifetime * 4);
    assert!(
        provider
            .prepare_code_renewal(&installed, ceiling, NOW)
            .unwrap()
            .is_some()
    );
    chain.0.lock().unwrap().persistent_lifetime = None;
    // Lapsed code is not renewed: nothing restores it. Neither is code that the network does not
    // have, nor code that an endpoint of another network or a failed read reports.
    let signed = signatures();
    chain.0.lock().unwrap().lapsed_code.insert(installed);
    for refusal in [
        provider.renew_code(&installed, ceiling),
        provider.renew_code(&[0x5b; 32], ceiling),
    ] {
        let refused = refusal.unwrap_err();
        assert!(
            refused.message.contains("nothing restores it")
                || refused.message.contains("not on the network"),
            "{}",
            refused.message
        );
    }
    chain.0.lock().unwrap().lapsed_code.remove(&installed);
    due(lifetime / 2);
    chain.0.lock().unwrap().foreign_network = true;
    assert!(provider.renew_code(&installed, ceiling).is_err());
    chain.0.lock().unwrap().foreign_network = false;
    chain.0.lock().unwrap().failing_code_reads = true;
    assert!(provider.renew_code(&installed, ceiling).is_err());
    chain.0.lock().unwrap().failing_code_reads = false;
    assert_eq!(signatures(), signed);
    // Another sending account renews the code just after the simulation: read again before the
    // signature, the code needs nothing, and nothing is signed.
    chain.0.lock().unwrap().renewed_after_simulation = true;
    assert!(provider.renew_code(&installed, ceiling).unwrap().is_none());
    assert!(!chain.0.lock().unwrap().renewed_after_simulation);
    assert_eq!(signatures(), signed);
    // Every sending account is leased while another account renews the code: nothing is needed,
    // so the allocation's refusal does not stand. While the code stays due, it stands.
    let leased = |renews| {
        allowit_stellar::PLUGIN
            .sending_runtime(
                NETWORK,
                Arc::new(Wire(chain.clone())),
                Arc::new(Leased(chain.clone(), renews)),
            )
            .unwrap()
    };
    due(lifetime / 2);
    assert!(
        leased(Some(installed))
            .renew_code(&installed, ceiling)
            .unwrap()
            .is_none()
    );
    due(lifetime / 2);
    let refused = leased(None).renew_code(&installed, ceiling).unwrap_err();
    assert!(refused.message.contains("leased"), "{}", refused.message);
    // The signer refuses, or gives a signature that does not verify, while another account renews
    // the code: nothing is needed.
    for runtime in [
        allowit_stellar::PLUGIN
            .sending_runtime(
                NETWORK,
                Arc::new(Wire(chain.clone())),
                Arc::new(Refusing(chain.clone(), installed)),
            )
            .unwrap(),
        allowit_stellar::PLUGIN
            .sending_runtime(
                NETWORK,
                Arc::new(Wire(chain.clone())),
                Arc::new(Garbled(chain.clone(), installed)),
            )
            .unwrap(),
    ] {
        due(lifetime / 2);
        assert!(runtime.renew_code(&installed, ceiling).unwrap().is_none());
    }
    // A renewal that the ledger includes but fails leaves the code's lifetime as it was. It is an
    // error that names the transaction and the fee that the sending account paid.
    due(lifetime / 2);
    chain.0.lock().unwrap().failing_renewal = true;
    chain.step("failed renewal");
    let failed = provider.renew_code(&installed, ceiling).unwrap_err();
    assert!(
        failed.message.contains("failed on the ledger"),
        "{}",
        failed.message
    );
    {
        let mut m = chain.0.lock().unwrap();
        let x::TransactionEnvelope::Tx(env) = de(&m.steps.last().unwrap().1) else {
            panic!()
        };
        assert_eq!(
            failed.details.as_ref().unwrap(),
            &json!({"transactionHash": hexs(&tx_hash(&env.tx)), "nativeUnits": "100"})
        );
        m.failing_renewal = false;
    }
    assert!(
        provider
            .prepare_code_renewal(&installed, ceiling, NOW)
            .unwrap()
            .is_some()
    );
    chain.renewed(installed);
    // A code transaction is a signed packet that the caller sends: the rail prepares it, signed
    // by the sending account, and sends nothing. Its identity is its transaction hash.
    let absent = |m: &mut Model| {
        m.code.remove(&hash(&unsent));
        m.code_bytes.remove(&hash(&unsent));
    };
    let upload_ceiling = u64::from(u32::MAX);
    {
        use allowit_core::vendor::runtime::{Kind, Status};
        absent(&mut chain.0.lock().unwrap());
        let signed = signatures();
        let code = provider
            .prepare_code_within(&installation, &unsent, upload_ceiling, NOW)
            .unwrap()
            .unwrap();
        assert_eq!(signatures(), signed + 1);
        let info = code.info().unwrap();
        assert_eq!(info.operation_id, info.transaction_hash);
        assert_eq!(info.wallet, sender());
        provider.validate_signed(&code, NOW).unwrap();
        assert!(
            provider
                .validate_signed(&code, info.expires_at + 1)
                .is_err()
        );
        assert!(code.preparation().is_err());
        assert!(provider.code_needed(&code).unwrap());
        // Its exact bytes restore, and bytes that differ do not: an envelope without the
        // source's signature, or an upload named a renewal.
        let raw =
            |value: &Value| serde_json::value::RawValue::from_string(value.to_string()).unwrap();
        let document: Value = serde_json::from_slice(code.bytes()).unwrap();
        assert!(
            allowit_stellar::PLUGIN
                .restore(Kind::Signed, raw(&document))
                .is_ok()
        );
        let mut unsigned = document.clone();
        unsigned["signedXdr"] = unsigned["code"]["transactionXdr"].clone();
        assert!(
            allowit_stellar::PLUGIN
                .restore(Kind::Signed, raw(&unsigned))
                .is_err()
        );
        let mut renamed = document.clone();
        renamed["code"]["function"] = json!("renew_code");
        assert!(
            allowit_stellar::PLUGIN
                .restore(Kind::Signed, raw(&renamed))
                .is_err()
        );
        // The network does not accept it yet while another account uploads the code: nothing is
        // pending, the transaction is no longer needed, and it is not sent again.
        chain.0.lock().unwrap().retry_later_uploads = Some((unsent.clone(), PolicyTier::Custom));
        assert_eq!(provider.broadcast(&code, NOW).unwrap(), Status::Prepared);
        assert!(!provider.code_needed(&code).unwrap());
        assert!(provider.observe(&code).unwrap().is_none());
        // A transaction that the network rejects is not pending and cost nothing: it was not
        // accepted.
        absent(&mut chain.0.lock().unwrap());
        let code = provider
            .prepare_code_within(&installation, &unsent, upload_ceiling, NOW)
            .unwrap()
            .unwrap();
        chain.0.lock().unwrap().reject_next_send = true;
        assert_eq!(provider.broadcast(&code, NOW).unwrap(), Status::Prepared);
        assert!(provider.observe(&code).unwrap().is_none());
        // Sent, it uploads the code, and its receipt is the caller's.
        chain
            .0
            .lock()
            .unwrap()
            .tiers
            .insert(hash(&unsent), PolicyTier::Custom);
        chain.step("upload by a code transaction");
        assert_eq!(provider.broadcast(&code, NOW).unwrap(), Status::Submitted);
        assert_eq!(provider.status(&code).unwrap(), Status::Confirmed);
        let receipt = provider.observe(&code).unwrap().unwrap();
        receipt.verify_operation(&code).unwrap();
        assert_eq!(receipt.info().unwrap().status, Status::Confirmed);
        assert!(!provider.code_needed(&code).unwrap());
        // A retained receipt that reports a fee above the declared fee does not verify.
        let x::TransactionEnvelope::Tx(signed) = de(code_doc(&code)["signedXdr"].as_str().unwrap())
        else {
            panic!()
        };
        let mut retained: Value = serde_json::from_slice(receipt.bytes()).unwrap();
        let mut result: x::TransactionResult = de(retained["resultXdr"].as_str().unwrap());
        result.fee_charged = i64::from(signed.tx.fee) + 1;
        retained["resultXdr"] = json!(b64(&result));
        let inflated = allowit_core::vendor::runtime::Receipt(
            allowit_stellar::PLUGIN
                .restore(Kind::Receipt, raw(&retained))
                .unwrap(),
        );
        assert!(inflated.verify_operation(&code).is_err());
        // A code transaction pays its own fee: a retained receipt that says it settled a payment
        // authorization does not verify.
        let mut settling: Value = serde_json::from_slice(receipt.bytes()).unwrap();
        settling["settles"] = json!(vec![5u8; 32]);
        let settling = allowit_core::vendor::runtime::Receipt(
            allowit_stellar::PLUGIN
                .restore(Kind::Receipt, raw(&settling))
                .unwrap(),
        );
        assert!(settling.verify_operation(&code).is_err());
        // A send never returns a final status: a rejected send of bytes that the ledger already
        // included is pending, and only its receipt is final.
        chain.0.lock().unwrap().reject_next_send = true;
        assert_eq!(provider.broadcast(&code, NOW).unwrap(), Status::Submitted);
        // The ledger holds the same transaction inside another source's fee bump: that is no
        // receipt of this transaction, whose source would not have paid its fee.
        chain.0.lock().unwrap().fee_bumped = true;
        assert!(provider.observe(&code).is_err());
        chain.0.lock().unwrap().fee_bumped = false;
        assert!(provider.observe(&code).unwrap().is_some());
        // A renewal is the same kind of packet, and needed only while it is due.
        due(lifetime / 2);
        let renewal = provider
            .prepare_code_renewal(&installed, ceiling, NOW)
            .unwrap()
            .unwrap();
        let info = renewal.info().unwrap();
        assert_eq!(info.operation_id, info.transaction_hash);
        provider.validate_signed(&renewal, NOW).unwrap();
        assert!(provider.code_needed(&renewal).unwrap());
        let document = code_doc(&renewal);
        let mut renamed = document.clone();
        renamed["code"]["function"] = json!("upload_wasm");
        assert!(
            allowit_stellar::PLUGIN
                .restore(Kind::Signed, raw(&renamed))
                .is_err()
        );
        chain.renewed(installed);
        assert!(!provider.code_needed(&renewal).unwrap());
    }
    // The packet binds its time bound, its source's signature hint and a footprint of the code
    // entry alone.
    {
        use allowit_core::vendor::runtime::Kind;
        let raw =
            |value: &Value| serde_json::value::RawValue::from_string(value.to_string()).unwrap();
        let refused = |document: &Value| {
            allowit_stellar::PLUGIN
                .restore(Kind::Signed, raw(document))
                .is_err()
        };
        absent(&mut chain.0.lock().unwrap());
        let code = provider
            .prepare_code_within(&installation, &unsent, upload_ceiling, NOW)
            .unwrap()
            .unwrap();
        let document = code_doc(&code);
        assert!(!refused(&document));
        let mut later = document.clone();
        later["code"]["expiresAt"] = json!(code.info().unwrap().expires_at + 100);
        assert!(refused(&later));
        let mut hinted = document.clone();
        let x::TransactionEnvelope::Tx(mut envelope) = de(document["signedXdr"].as_str().unwrap())
        else {
            panic!()
        };
        let mut signatures = envelope.signatures.to_vec();
        signatures[0].hint = x::SignatureHint([0; 4]);
        envelope.signatures = signatures.try_into().unwrap();
        hinted["signedXdr"] = json!(b64(&x::TransactionEnvelope::Tx(envelope)));
        assert!(refused(&hinted));
        // The packet holds nothing outside the signature.
        let mut anchored = document.clone();
        anchored["ledger"] = json!(1);
        assert!(refused(&anchored));
        // A preparation that carries a signature is not the server's unsigned preparation.
        let mut presigned = document.clone();
        presigned["code"]["transactionXdr"] = presigned["signedXdr"].clone();
        assert!(refused(&presigned));
        // Re-signed by its source with other bounds: a time bound of zero, which Stellar reads as
        // none, or bounds by ledgers.
        let resigned = |document: &Value, change: &dyn Fn(&mut x::Transaction, &mut Value)| {
            let mut document = document.clone();
            let x::TransactionEnvelope::Tx(mut envelope) =
                de(document["code"]["transactionXdr"].as_str().unwrap())
            else {
                panic!()
            };
            change(&mut envelope.tx, &mut document);
            let digest = tx_hash(&envelope.tx);
            document["code"]["transactionXdr"] =
                json!(b64(&x::TransactionEnvelope::Tx(envelope.clone())));
            document["code"]["transactionHash"] = json!(digest.to_vec());
            envelope.signatures = vec![x::DecoratedSignature {
                hint: x::SignatureHint(account_key(&sender()).unwrap()[28..].try_into().unwrap()),
                signature: x::Signature(
                    SigningKey::from_bytes(&SENDER)
                        .sign(&digest)
                        .to_bytes()
                        .to_vec()
                        .try_into()
                        .unwrap(),
                ),
            }]
            .try_into()
            .unwrap();
            document["signedXdr"] = json!(b64(&x::TransactionEnvelope::Tx(envelope)));
            document
        };
        let expires = code.info().unwrap().expires_at;
        assert!(!refused(&resigned(&document, &|_, _| {})));
        assert!(refused(&resigned(&document, &|tx, document| {
            tx.cond = x::Preconditions::Time(x::TimeBounds {
                min_time: x::TimePoint(0),
                max_time: x::TimePoint(0),
            });
            document["code"]["expiresAt"] = json!(0);
        })));
        assert!(refused(&resigned(&document, &|tx, _| {
            tx.cond = x::Preconditions::V2(x::PreconditionsV2 {
                time_bounds: Some(x::TimeBounds {
                    min_time: x::TimePoint(0),
                    max_time: x::TimePoint(expires),
                }),
                ledger_bounds: Some(x::LedgerBounds {
                    min_ledger: 1,
                    max_ledger: 61,
                }),
                min_seq_num: None,
                min_seq_age: x::Duration(0),
                min_seq_ledger_gap: 0,
                extra_signers: Default::default(),
            });
        })));
        // An upload re-signed by its source with another entry in its footprint, or with its code
        // entry read-only, as a renewal names it.
        let widen = |extra: bool| {
            move |tx: &mut x::Transaction, _: &mut Value| {
                let x::TransactionExt::V1(data) = &mut tx.ext else {
                    panic!()
                };
                let mut written = data.resources.footprint.read_write.to_vec();
                if extra {
                    written.push(x::LedgerKey::ContractCode(x::LedgerKeyContractCode {
                        hash: x::Hash([0x77; 32]),
                    }));
                } else {
                    data.resources.footprint.read_only = written.clone().try_into().unwrap();
                    written.clear();
                }
                data.resources.footprint.read_write = written.try_into().unwrap();
            }
        };
        assert!(refused(&resigned(&document, &widen(true))));
        assert!(refused(&resigned(&document, &widen(false))));
        // A renewal re-signed with its code entry written, or with no extension.
        due(lifetime / 2);
        let renewal = code_doc(
            &provider
                .prepare_code_renewal(&installed, ceiling, NOW)
                .unwrap()
                .unwrap(),
        );
        assert!(!refused(&renewal));
        assert!(refused(&resigned(&renewal, &|tx, _| {
            let x::TransactionExt::V1(data) = &mut tx.ext else {
                panic!()
            };
            data.resources.footprint.read_write =
                std::mem::take(&mut data.resources.footprint.read_only);
        })));
        assert!(refused(&resigned(&renewal, &|tx, _| {
            let mut operations = tx.operations.to_vec();
            operations[0].body = x::OperationBody::ExtendFootprintTtl(x::ExtendFootprintTtlOp {
                ext: x::ExtensionPoint::V0,
                extend_to: 0,
            });
            tx.operations = operations.try_into().unwrap();
        })));
        chain.renewed(installed);
        let mut m = chain.0.lock().unwrap();
        m.code.insert(hash(&unsent), PolicyTier::Custom);
        m.code_bytes.insert(hash(&unsent), unsent.clone());
    }
}
/// A wallet whose instance or code lapsed takes no owner step either. Funding transfers to the
/// wallet without calling it, so its lifetimes are read first; an extension reads them too; and an
/// owner step refuses a simulation that would restore any code of the wallet, also code that the
/// owner installed outside Allowit, which the installation does not name. Each answers
/// `contract_expired`.
/// The admission read (`rpc::trusted_state`, the provider's `snapshot`), which installation,
/// activation and execution use, refuses a wallet whose params are not the ones that its
/// deployment stores (`installed_params`): a Standard wallet whose owner's update outside
/// Allowit dropped `daily_spending_limit` and kept its rules and source. Discovery still reads
/// it, so its owner can pause or stop it.
#[test]
fn an_admission_read_refuses_a_wallet_that_dropped_an_approved_param() {
    let tier = PolicyTier::Common;
    let wasm = wasm_for(tier);
    let chain = ModelChain::new(BTreeMap::from([(hash(&wasm), tier)]));
    let c = create(&chain, tier, &wasm, [0x5d; 32]);
    assert!(c.rules.iter().any(|rule| rule == "daily_spending_limit"));
    assert!(c.params.0.contains_key("daily_spending_limit"));
    rpc::trusted_state(&chain, &c, Some(chain.accounting())).unwrap();
    let mut owner_admin = Admin::new(OwnerAdmin {
        rpc: &chain,
        config: &c,
        now: NOW,
    });
    let mut dropped = c.params.clone();
    dropped.0.remove("daily_spending_limit");
    let (deployment, _) = PolicyDeployment::for_source(&c, SOURCE, dropped).unwrap();
    let updated = owner_admin
        .deploy_policy(DeploymentVersion(1), deployment)
        .unwrap();
    owner_submit(&chain, "params", &updated.transaction_xdr);
    assert!(!chain.config().params.0.contains_key("daily_spending_limit"));
    let refused = rpc::trusted_state(&chain, &c, Some(chain.accounting())).unwrap_err();
    assert_eq!(refused.to_string(), rpc::PARAMS_DIFFER);
    assert!(rpc::trusted_state_for_discovery(&chain, &c, None).is_ok());
}

#[test]
fn a_lapsed_wallet_takes_no_owner_step() {
    use allowit_core::vendor::plugin::RailPlugin;
    use allowit_core::vendor::profiles::Description;
    use allowit_core::vendor::runtime::{Installation, OwnerAction, Transport};
    use std::sync::Arc;
    struct Wire(Arc<ModelChain>);
    impl Transport for Wire {
        fn call(&self, method: &str, params: Value) -> allowit_core::client::error::Result<Value> {
            rpc::Rpc::call(&*self.0, method, params)
                .map_err(allowit_core::client::error::Error::config)
        }
    }
    let wasm = wasm_for(PolicyTier::Common);
    let chain = Arc::new(ModelChain::new(BTreeMap::from([(
        hash(&wasm),
        PolicyTier::Common,
    )])));
    let c = create(&chain, PolicyTier::Common, &wasm, [0x38; 32]);
    let document = allowit_stellar::PLUGIN
        .owner_runtime()
        .configuration(NETWORK, &serde_json::to_vec(&c).unwrap())
        .unwrap();
    let installation = Installation {
        description: Description {
            network: NETWORK.into(),
            wallet: c.wallet.clone(),
            agent: c.agent.clone(),
            policy_id: "policy".into(),
            owner: c.owner.clone(),
            server: c.server.clone(),
            asset: c.asset.clone(),
            asset_symbol: c.asset_symbol.clone(),
            source: c.policy_source.clone(),
            source_hash: hex(&c.source_hash),
            module_digest: hex(&c.module_digest),
            params: document.params.clone(),
        },
        config: document.document().to_owned(),
        export: None,
        authority: None,
    };
    let provider = allowit_stellar::PLUGIN
        .runtime(NETWORK, Arc::new(Wire(chain.clone())))
        .unwrap();
    let expired = |action: OwnerAction| {
        let refused = provider
            .prepare_owner(&installation, action, u64::from(c.max_fee_stroops), NOW)
            .unwrap_err();
        let problem = provider.problem(&refused);
        assert_eq!(
            problem.code,
            allowit_core::vendor::runtime::CONTRACT_EXPIRED,
            "{}",
            refused.message
        );
    };
    // Its instance lapsed: nothing is simulated or signed, and its resources say so.
    chain.0.lock().unwrap().lapsed_instances = true;
    let refused = provider.resources(&installation).unwrap_err();
    assert_eq!(
        provider.problem(&refused).code,
        allowit_core::vendor::runtime::CONTRACT_EXPIRED
    );
    expired(OwnerAction::Fund { units: 5 });
    expired(OwnerAction::Extend);
    chain.0.lock().unwrap().lapsed_instances = false;
    // Its code lapsed: so do its resources.
    chain.0.lock().unwrap().lapsed_code.insert(c.module_digest);
    let refused = provider.resources(&installation).unwrap_err();
    assert_eq!(
        provider.problem(&refused).code,
        allowit_core::vendor::runtime::CONTRACT_EXPIRED
    );
    expired(OwnerAction::Fund { units: 5 });
    expired(OwnerAction::Extend);
    // Its owner installed other code outside Allowit, which runs: the installation's code that
    // lapsed is not the wallet's, so the wallet did not lapse; it runs other code.
    chain.0.lock().unwrap().running = Some([0x42; 32]);
    let refused = provider.resources(&installation).unwrap_err();
    assert_ne!(
        provider.problem(&refused).code,
        allowit_core::vendor::runtime::CONTRACT_EXPIRED,
        "{}",
        refused.message
    );
    // The deployment's own code for a wallet whose ledger code is not its configuration's.
    assert_eq!(
        provider.problem(&refused).code,
        allowit_core::vendor::custom_build::code::CODE_HASH_MISMATCH,
        "{}",
        refused.message
    );
    // The other code that it runs, on the network, lapsed too: the wallet lapsed.
    let other = wasm_for(PolicyTier::Simple);
    {
        let mut m = chain.0.lock().unwrap();
        m.code_bytes.insert(hash(&other), other.clone());
        m.running = Some(hash(&other));
        m.lapsed_code.insert(hash(&other));
    }
    let refused = provider.resources(&installation).unwrap_err();
    assert_eq!(
        provider.problem(&refused).code,
        allowit_core::vendor::runtime::CONTRACT_EXPIRED,
        "{}",
        refused.message
    );
    // Live, that other code is still not the installation's.
    chain.0.lock().unwrap().lapsed_code.remove(&hash(&other));
    let refused = provider.resources(&installation).unwrap_err();
    // The deployment's own code for a wallet whose ledger code is not its configuration's.
    assert_eq!(
        provider.problem(&refused).code,
        allowit_core::vendor::custom_build::code::CODE_HASH_MISMATCH,
        "{}",
        refused.message
    );
    chain.0.lock().unwrap().running = None;
    chain.0.lock().unwrap().lapsed_code.remove(&c.module_digest);
    // The owner installed other code outside Allowit, and that code lapsed: the stop's simulation
    // would restore it, and is refused.
    let lapsed = Lapsed {
        chain: &chain,
        preamble: false,
        instance: false,
        code: Some([0x42; 32]),
    };
    let mut owner = OwnerAdmin {
        rpc: &lapsed,
        config: &c,
        now: NOW,
    };
    let version = owner.deployment_version().unwrap().0 + 1;
    let refused = owner.stop(DeploymentVersion(version)).unwrap_err();
    assert_eq!(refused.to_string(), rpc::CONTRACT_EXPIRED);
    // A recovery of a wallet that holds nothing: a live wallet has nothing to return, a lapsed one
    // is `contract_expired`, whether its instance or its code lapsed.
    chain.0.lock().unwrap().wallet.as_mut().unwrap().balance = 0;
    let recover = || {
        OwnerAdmin {
            rpc: &*chain,
            config: &c,
            now: NOW,
        }
        .recover_all()
        .unwrap_err()
        .to_string()
    };
    assert_eq!(recover(), allowit_stellar::admin::NO_RECOVERABLE_BALANCE);
    chain.0.lock().unwrap().lapsed_instances = true;
    assert_eq!(recover(), rpc::CONTRACT_EXPIRED);
    // A withdrawal whose simulation fails, as one above the balance does: a lapsed wallet is
    // `contract_expired` all the same, before anything is simulated.
    struct Rejecting<'a>(&'a ModelChain);
    impl rpc::Rpc for Rejecting<'_> {
        fn call(&self, method: &str, params: Value) -> Result<Value> {
            if method == "simulateTransaction" {
                return Ok(json!({"error": "HostError: the transfer exceeds the balance"}));
            }
            self.0.call(method, params)
        }
    }
    let withdrawn = OwnerAdmin {
        rpc: &Rejecting(&chain),
        config: &c,
        now: NOW,
    }
    .recover_to(&c.owner, 1_000_000)
    .unwrap_err();
    assert_eq!(withdrawn.to_string(), rpc::CONTRACT_EXPIRED);
    chain.0.lock().unwrap().lapsed_instances = false;
    chain.0.lock().unwrap().lapsed_code.insert(c.module_digest);
    assert_eq!(recover(), rpc::CONTRACT_EXPIRED);
    chain.0.lock().unwrap().lapsed_code.remove(&c.module_digest);
}
/// A transport that answers nothing: for the rail's naming of a problem, which reads no ledger.
struct NoTransport;
impl allowit_core::vendor::runtime::Transport for NoTransport {
    fn call(&self, _: &str, _: Value) -> allowit_core::client::error::Result<Value> {
        Err(allowit_core::client::error::Error::config("no transport"))
    }
}
/// A wallet whose instance lapsed is expired, and nothing restores it: the agent's payment and the
/// owner's stop are refused with `CONTRACT_EXPIRED` before anything is signed or sent, and the
/// rail names that problem `contract_expired`. A lapsed `t` alone still restores in the operation
/// that needs it.
#[test]
fn a_lapsed_wallet_is_expired_before_anything_is_signed_or_sent() {
    let wasm = wasm_for(PolicyTier::Common);
    let chain = ModelChain::new(BTreeMap::from([(hash(&wasm), PolicyTier::Common)]));
    let c = create(&chain, PolicyTier::Common, &wasm, [0x37; 32]);
    let lapsed = Lapsed {
        chain: &chain,
        preamble: false,
        instance: true,
        code: None,
    };
    let mut state = rpc::trusted_state(&lapsed, &c, Some(chain.accounting())).unwrap();
    state.source = rpc::get_account(&lapsed, &sender()).unwrap();
    let ledger = chain.ledger();
    let recipient = account_for_seed(&RECIPIENT);
    let transfer = request::transfer(&c, &state, [1; 32], &recipient, 1_000_000).unwrap();
    let sent = chain.0.lock().unwrap().steps.len();
    let refused = rpc::prepare_with(
        &lapsed,
        &c,
        &transfer,
        &terms(1_000_000, ledger),
        Some(chain.accounting()),
        NOW,
        NOW + 300,
    )
    .unwrap_err();
    assert_eq!(refused.to_string(), rpc::CONTRACT_EXPIRED);
    let problem = allowit_core::vendor::plugin::RailPlugin::runtime(
        &allowit_stellar::PLUGIN,
        NETWORK,
        std::sync::Arc::new(NoTransport),
    )
    .unwrap()
    .problem(&allowit_core::client::error::Error::config(
        refused.to_string(),
    ));
    assert_eq!(
        (problem.status, problem.code),
        (409, allowit_core::vendor::runtime::CONTRACT_EXPIRED)
    );
    // The owner's stop too.
    let mut owner = OwnerAdmin {
        rpc: &lapsed,
        config: &c,
        now: NOW,
    };
    let version = owner.deployment_version().unwrap().0 + 1;
    let refused = owner.stop(DeploymentVersion(version)).unwrap_err();
    assert_eq!(refused.to_string(), rpc::CONTRACT_EXPIRED);
    assert_eq!(chain.0.lock().unwrap().steps.len(), sent);
}
