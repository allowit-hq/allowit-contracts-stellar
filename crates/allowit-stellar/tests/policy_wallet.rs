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
const RESTORE_FEE: i64 = 4_000;
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
    /// Uploaded code past its lifetime: Stellar RPC serves it with a live-until ledger of 0,
    /// an upload of it fails and a `RestoreFootprint` of its entry makes it live again.
    lapsed_code: BTreeSet<[u8; 32]>,
    /// The next restorations fail when the ledger applies them: the code stays lapsed and the
    /// source still pays the fee.
    failing_restore: bool,
    /// The archived entries that a restoration's simulation names, by their index in the
    /// read-write footprint.
    restore_archived: Vec<u32>,
    /// The transactions that the ledger included and failed.
    failed: BTreeSet<String>,
    /// Another transaction restores lapsed code just before the next restoration's simulation.
    restored_meanwhile: bool,
    /// That transaction came from the restoration's own source, whose sequence it advanced.
    restored_by_source: bool,
    /// The fee that the next receipts report as charged, when not the usual 100 stroops.
    charged_fee: Option<i64>,
    /// The RPC serves no archived entry: a read of lapsed code finds nothing.
    hide_archived: bool,
    /// An upload simulation of lapsed code restores the code entry in place instead of failing.
    upload_restores_in_place: bool,
    /// A read that finds no entry omits the entry list.
    omit_empty_entries: bool,
    /// The network refuses the simulation of the next restorations.
    refused_restore: bool,
    /// Reads of code entries fail, as a broken transport does.
    failing_code_reads: bool,
    /// Another transaction uploads the code of the next upload just before its simulation.
    uploaded_meanwhile: bool,
    /// The next upload simulations also write another entry than the code.
    upload_names_another_entry: bool,
    /// Another sending account restores the code just after the next restoration's simulation.
    restored_after_simulation: bool,
    /// Another sending account uploads the code just after the next upload's simulation.
    uploaded_after_simulation: bool,
    /// The upload of `uploaded_meanwhile` came from the upload's own source, whose sequence it
    /// advanced.
    uploaded_by_source: bool,
    /// The next submission is not accepted (`TRY_AGAIN_LATER`) while another account restores
    /// this code.
    retry_later_restores: Option<[u8; 32]>,
    /// The next reads of code entries come from a node that trails: it serves the code as
    /// lapsed at the head before another account's restoration, and the head then closes one
    /// more ledger.
    stale_code_reads: u32,
    /// The `stale_code_reads` that the answer `TRY_AGAIN_LATER` starts.
    stale_reads_on_retry_later: u32,
    /// The next reads of code entries answer at a ledger before the head that was read just
    /// before them, from a node that trails; the entry itself is current.
    behind_head_code_reads: u32,
    /// The `behind_head_code_reads` that a restoration's simulation starts.
    behind_reads_on_restore_simulation: u32,
    /// The heads that the next `getLatestLedger` calls answer, as nodes behind a load balancer
    /// that do not agree.
    heads: std::collections::VecDeque<u32>,
    /// The ledgers at which replicas that trail answer the next reads of code entries: they serve
    /// the code as lapsed.
    replica_code_reads: std::collections::VecDeque<u32>,
    /// The `heads` and `replica_code_reads` that the answer `TRY_AGAIN_LATER` starts.
    heads_on_retry_later: Vec<u32>,
    replica_reads_on_retry_later: Vec<u32>,
    tiers: BTreeMap<[u8; 32], PolicyTier>,
    wallet: Option<Wallet>,
    settled: BTreeMap<String, String>,
    steps: Vec<Step>,
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
            "getNetwork" => Ok(json!({"passphrase": passphrase(NETWORK)?})),
            "getLatestLedger" => {
                let head = m.heads.pop_front().unwrap_or(m.ledger);
                Ok(json!({"sequence": head}))
            }
            "getLedgerEntries" => {
                let encoded = params["keys"][0].as_str().unwrap();
                let key: x::LedgerKey = de(encoded);
                if m.failing_code_reads && matches!(key, x::LedgerKey::ContractCode(_)) {
                    return Err("The RPC is unreachable".into());
                }
                if let x::LedgerKey::ContractCode(code) = &key
                    && let Some(bytes) = m.code_bytes.get(&code.hash.0).cloned()
                    && let Some(ledger) = m.replica_code_reads.pop_front()
                {
                    let entry = x::LedgerEntryData::ContractCode(x::ContractCodeEntry {
                        ext: x::ContractCodeEntryExt::V0,
                        hash: code.hash.clone(),
                        code: bytes.try_into().unwrap(),
                    });
                    return Ok(json!({
                        "latestLedger": ledger,
                        "entries": [{"key": encoded, "xdr": b64(&entry), "liveUntilLedgerSeq": 0}],
                    }));
                }
                if m.stale_code_reads > 0
                    && let x::LedgerKey::ContractCode(code) = &key
                    && let Some(bytes) = m.code_bytes.get(&code.hash.0).cloned()
                {
                    m.stale_code_reads -= 1;
                    let observed = m.ledger;
                    m.ledger += 1;
                    let entry = x::LedgerEntryData::ContractCode(x::ContractCodeEntry {
                        ext: x::ContractCodeEntryExt::V0,
                        hash: code.hash.clone(),
                        code: bytes.try_into().unwrap(),
                    });
                    return Ok(json!({
                        "latestLedger": observed,
                        "entries": [{"key": encoded, "xdr": b64(&entry), "liveUntilLedgerSeq": 0}],
                    }));
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
                                        *m.code
                                            .iter()
                                            .find(|(_, tier)| **tier == w.tier)
                                            .unwrap()
                                            .0,
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
                                    && data.durability == x::ContractDataDurability::Persistent =>
                            {
                                bytes(&w.t_bytes()?)
                            }
                            x::ScVal::Symbol(s)
                                if s.0.as_slice() == b"d"
                                    && data.durability == x::ContractDataDurability::Temporary =>
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
                    x::LedgerKey::ContractCode(code)
                        if m.hide_archived && m.lapsed_code.contains(&code.hash.0) =>
                    {
                        None
                    }
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
                    x::LedgerKey::ContractCode(code) if m.lapsed_code.contains(&code.hash.0) => 0,
                    _ => m.ledger + 10_000,
                };
                let entries: Vec<Value> = entry
                    .into_iter()
                    .map(|e| json!({"key": encoded, "xdr": b64(&e), "liveUntilLedgerSeq": live_until}))
                    .collect();
                let mut latest = m.ledger;
                if m.behind_head_code_reads > 0 && matches!(key, x::LedgerKey::ContractCode(_)) {
                    m.behind_head_code_reads -= 1;
                    latest -= 1;
                }
                if entries.is_empty() && m.omit_empty_entries {
                    return Ok(json!({"latestLedger": latest}));
                }
                Ok(json!({"latestLedger": latest, "entries": entries}))
            }
            "simulateTransaction" => {
                let x::TransactionEnvelope::Tx(env) = de(params["transaction"].as_str().unwrap())
                else {
                    panic!()
                };
                if let x::OperationBody::RestoreFootprint(_) = &env.tx.operations[0].body {
                    let x::TransactionExt::V1(data) = &env.tx.ext else {
                        return Ok(json!({"error": "a restoration names its footprint"}));
                    };
                    if m.refused_restore {
                        return Ok(json!({
                            "latestLedger": m.ledger,
                            "error": "the restoration cannot be simulated",
                        }));
                    }
                    if m.restored_meanwhile {
                        for key in data.resources.footprint.read_write.iter() {
                            if let x::LedgerKey::ContractCode(code) = key {
                                m.lapsed_code.remove(&code.hash.0);
                            }
                        }
                        if m.restored_by_source {
                            m.accounts.get_mut(&source_of(&env.tx)).unwrap().sequence += 1;
                        }
                    }
                    let mut data = x::SorobanTransactionData {
                        resource_fee: RESTORE_FEE,
                        ..data.clone()
                    };
                    // As Stellar RPC, the simulation restores only entries that are archived.
                    let archived: Vec<x::LedgerKey> = data
                        .resources
                        .footprint
                        .read_write
                        .iter()
                        .filter(|key| {
                            matches!(key, x::LedgerKey::ContractCode(code) if m.lapsed_code.contains(&code.hash.0))
                        })
                        .cloned()
                        .collect();
                    data.resources.footprint.read_write = archived.try_into().unwrap();
                    m.behind_head_code_reads =
                        std::mem::take(&mut m.behind_reads_on_restore_simulation);
                    if m.restored_after_simulation {
                        m.restored_after_simulation = false;
                        for key in data.resources.footprint.read_write.iter() {
                            if let x::LedgerKey::ContractCode(code) = key {
                                m.lapsed_code.remove(&code.hash.0);
                            }
                        }
                    }
                    if !m.restore_archived.is_empty() {
                        data.ext = x::SorobanTransactionDataExt::V1(x::SorobanResourcesExtV0 {
                            archived_soroban_entries: m
                                .restore_archived
                                .clone()
                                .try_into()
                                .unwrap(),
                        });
                    }
                    return Ok(json!({
                        "latestLedger": m.ledger,
                        "minResourceFee": RESTORE_FEE.to_string(),
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
                if m.settled.contains_key(&tx_hash) {
                    return Ok(json!({"hash": tx_hash, "status": "DUPLICATE"}));
                }
                if let Some(code) = m.retry_later_restores.take() {
                    m.lapsed_code.remove(&code);
                    m.stale_code_reads = std::mem::take(&mut m.stale_reads_on_retry_later);
                    m.heads = std::mem::take(&mut m.heads_on_retry_later).into();
                    m.replica_code_reads =
                        std::mem::take(&mut m.replica_reads_on_retry_later).into();
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
                if let x::OperationBody::RestoreFootprint(_) = &env.tx.operations[0].body {
                    let x::TransactionExt::V1(data) = &env.tx.ext else {
                        panic!("a restoration names its footprint")
                    };
                    for key in data.resources.footprint.read_write.iter() {
                        let x::LedgerKey::ContractCode(code) = key else {
                            panic!("the model restores code only")
                        };
                        assert!(m.lapsed_code.contains(&code.hash.0), "restore of live code");
                        if !m.failing_restore {
                            m.lapsed_code.remove(&code.hash.0);
                        }
                    }
                    if m.failing_restore {
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
                let start = params["startLedger"].as_u64().unwrap() as u32;
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
                Ok(json!({"events": events, "latestLedger": m.ledger}))
            }
            "getTransaction" => {
                let tx_hash = params["hash"].as_str().unwrap();
                let Some(envelope) = m.settled.get(tx_hash) else {
                    return Ok(json!({"status": "NOT_FOUND"}));
                };
                let failed = m.failed.contains(tx_hash);
                let result = x::TransactionResult {
                    fee_charged: m.charged_fee.unwrap_or(100),
                    result: if failed {
                        x::TransactionResultResult::TxFailed(Default::default())
                    } else {
                        x::TransactionResultResult::TxSuccess(Default::default())
                    },
                    ext: x::TransactionResultExt::V0,
                };
                Ok(
                    json!({"status": if failed { "FAILED" } else { "SUCCESS" }, "ledger": m.ledger, "envelopeXdr": envelope, "resultXdr": b64(&result)}),
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
        gas_due: 0,
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
        gas_due: 0,
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
        gas_due: 0,
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
/// A wallet that counts an asset other than XLM converts its whole repayment once, at the rate of
/// the server's ceiling: a due that fills the gas cap counts the ceiling's asset units, not the
/// rounded units of a small fee bound scaled up to the repayment.
#[test]
fn a_repayment_never_exceeds_the_gas_cap() {
    let ceiling = ExpenseBounds::xlm(5, 0, 2_000, LEDGER, NOW).unwrap();
    // A fee bound above the gas cap, less no carry, is a repayment above it: refused, with a
    // due or without.
    for due in [0, 100] {
        assert!(
            ceiling.with_repayment(1_009, 0, due, 1_000).is_err(),
            "{due}"
        );
    }
    // After a carry the repayment fits, and the due fills the rest of the gas cap.
    let (bounds, part) = ceiling.with_repayment(1_009, 100, 500, 1_000).unwrap();
    assert_eq!((part, bounds.gas_units), (91, 1_000));
}
#[test]
fn a_gas_due_of_another_asset_counts_units_at_the_ceiling_rate() {
    // The ceiling prices 1,000,000 stroops at 10 asset units, over a principal of 5.
    let ceiling = ExpenseBounds {
        gas_units: 10,
        spent_units: 15,
        ..ExpenseBounds::xlm(5, 0, 1_000_000, LEDGER, NOW).unwrap()
    };
    let (priced, part) = ceiling
        .with_repayment(2_000, 0, 2_000_000, 1_000_000)
        .unwrap();
    // Without a carry or a due the conversion is the fee bound's own.
    assert_eq!(
        ceiling.with_repayment(2_000, 0, 0, 1_000_000).unwrap().0,
        ceiling.with_fee_bound(2_000).unwrap()
    );
    // The repayment is the bound of 2,000 and 998,000 of the due: the whole ceiling.
    assert_eq!(part, 998_000);
    assert_eq!(
        (priced.gas_units, priced.spent_units, priced.max_fee_stroops),
        (10, 15, 2_000)
    );
}
/// A fee that the server paid for the operation outside its transaction, such as the restoration
/// of the wallet's lapsed code, joins the repayment as far as the wallet's gas cap allows, after
/// the carry. The priced terms keep the part that the wallet repays, the wallet counts it as gas,
/// and the transaction still declares only its own fee bound.
#[test]
fn a_gas_due_joins_the_repayment_within_the_gas_cap() {
    let wasm = wasm_for(PolicyTier::Common);
    let chain = ModelChain::new(BTreeMap::from([(hash(&wasm), PolicyTier::Common)]));
    let c = create(&chain, PolicyTier::Common, &wasm, [0x37; 32]);
    let recipient = account_for_seed(&RECIPIENT);
    let gas_cap = i128::from(c.max_fee_stroops);
    // A due that fits, a due beyond the gas cap and a due after a carry.
    for (id, carry, due) in [
        (1u8, 0u128, 500u128),
        (2, 0, gas_cap as u128 * 2),
        (3, 300, 1_000),
    ] {
        let state = sending_state(&chain, &c);
        let ledger = chain.ledger();
        let transfer = request::transfer(&c, &state, [id; 32], &recipient, 1_000_000).unwrap();
        let owed = ExecutionTerms {
            gas_carry: carry,
            gas_due: due,
            ..terms(1_000_000, ledger)
        };
        let prepared = rpc::prepare_with(
            &chain,
            &c,
            &transfer,
            &owed,
            Some(chain.accounting()),
            NOW,
            NOW + 300,
        )
        .unwrap();
        let base = (gas() - carry as i128).max(0);
        let part = (due as i128).min(gas_cap - base);
        let repaid = base + part;
        assert!(repaid <= gas_cap);
        assert_eq!(prepared.terms.gas_due, part as u128, "{id}");
        assert_eq!(prepared.terms.repaid_stroops().unwrap(), repaid);
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
        assert_eq!(
            (
                rpc::repaid_gas_stroops(&settled).unwrap(),
                rpc::counted_gas_units(&settled).unwrap()
            ),
            (repaid as u128, repaid)
        );
    }
    // A due of any size repays what fits under the gas cap.
    let state = sending_state(&chain, &c);
    let transfer = request::transfer(&c, &state, [4; 32], &recipient, 1_000_000).unwrap();
    let unbounded = ExecutionTerms {
        gas_due: u128::MAX,
        ..terms(1_000_000, chain.ledger())
    };
    let prepared = rpc::prepare_with(
        &chain,
        &c,
        &transfer,
        &unbounded,
        Some(chain.accounting()),
        NOW,
        NOW + 300,
    )
    .unwrap();
    assert_eq!(prepared.terms.repaid_stroops().unwrap(), gas_cap);
    // Local preparation admits no repayment above the gas cap, as the wallet does not.
    let ledger = chain.ledger();
    let mut over = terms(1_000_000, ledger);
    over.gas_due = 500;
    let expense = over.expense.as_mut().unwrap();
    expense.gas_units = gas_cap + 500;
    expense.spent_units = 1_000_000 + gas_cap + 500;
    assert_eq!(over.repaid_stroops().unwrap(), gas_cap + 500);
    let refused = allowit_stellar::prepare_with(&c, &transfer, &over, &state, NOW, NOW + 300)
        .unwrap_err()
        .to_string();
    assert!(refused.contains("gas cap"), "{refused}");
    // The owner changed the gas cap on the ledger: an installation with another gas cap would
    // price repayments that the wallet refuses, so its operations are refused until it is
    // verified again.
    let stale = WalletConfig {
        max_fee_stroops: c.max_fee_stroops + 1,
        ..c.clone()
    };
    let refused = rpc::prepare_with(
        &chain,
        &stale,
        &transfer,
        &terms(1_000_000, chain.ledger()),
        Some(chain.accounting()),
        NOW,
        NOW + 300,
    )
    .unwrap_err();
    assert!(refused.contains("gas cap"), "{refused}");
    // An explicit repayment takes no due, priced or not: an unpriced operation does not drop it.
    let unpriced = ExecutionTerms {
        expense: None,
        gas: Some(GasRepayment {
            stroops: 0,
            payee: sender(),
        }),
        gas_due: 500,
        ..terms(1_000_000, chain.ledger())
    };
    let refused = rpc::prepare_with(
        &chain,
        &c,
        &transfer,
        &unpriced,
        Some(chain.accounting()),
        NOW,
        NOW + 300,
    )
    .unwrap_err();
    assert!(refused.contains("takes no gas due"), "{refused}");
    // An explicit repayment takes no due.
    let explicit = ExecutionTerms {
        gas: Some(GasRepayment {
            stroops: 500,
            payee: sender(),
        }),
        gas_due: 100,
        ..terms(1_000_000, chain.ledger())
    };
    assert!(explicit.repaid_stroops().is_err());
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
/// The server's runtime from the plugin sends with the server's own accounts, and so does its
/// diagnostic session: a code upload through either reaches them. Code that lapsed is restored
/// from those accounts, never uploaded again.
#[test]
fn the_sending_runtime_and_its_diagnostic_session_send_with_the_servers_accounts() {
    use allowit_core::vendor::plugin::RailPlugin;
    use allowit_core::vendor::profiles::Description;
    use allowit_core::vendor::runtime::SendingAccounts;
    use allowit_core::vendor::runtime::{Installation, Poll, Transport};
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
    // Sending accounts that are all leased; another account may restore the code `restores` at
    // the same time.
    struct Leased(Arc<ModelChain>, Option<[u8; 32]>);
    impl SendingAccounts for Leased {
        fn account(&self) -> allowit_core::client::error::Result<String> {
            if let Some(code) = self.1 {
                self.0.0.lock().unwrap().lapsed_code.remove(&code);
            }
            Err(allowit_core::client::error::Error::config(
                "All sending accounts are leased",
            ))
        }
        fn sign(&self, _: &str, _: &[u8; 32]) -> allowit_core::client::error::Result<Vec<u8>> {
            panic!("a leased account signs nothing")
        }
    }
    // A sending account whose signer gives a signature that does not verify while another
    // account restores the code.
    struct Garbled(Arc<ModelChain>, [u8; 32]);
    impl SendingAccounts for Garbled {
        fn account(&self) -> allowit_core::client::error::Result<String> {
            Ok(sender())
        }
        fn sign(&self, _: &str, _: &[u8; 32]) -> allowit_core::client::error::Result<Vec<u8>> {
            self.0.0.lock().unwrap().lapsed_code.remove(&self.1);
            Ok(vec![0; 64])
        }
    }
    // A sending account whose signer is overtaken: another account restores the code while it
    // signs, and the signature is valid.
    struct Overtaken(Arc<ModelChain>, [u8; 32]);
    impl SendingAccounts for Overtaken {
        fn account(&self) -> allowit_core::client::error::Result<String> {
            Ok(sender())
        }
        fn sign(&self, _: &str, hash: &[u8; 32]) -> allowit_core::client::error::Result<Vec<u8>> {
            self.0.0.lock().unwrap().lapsed_code.remove(&self.1);
            Ok(SigningKey::from_bytes(&SENDER)
                .sign(hash)
                .to_bytes()
                .to_vec())
        }
    }
    // A sending account whose signer refuses while another account restores the code.
    struct Refusing(Arc<ModelChain>, [u8; 32]);
    impl SendingAccounts for Refusing {
        fn account(&self) -> allowit_core::client::error::Result<String> {
            Ok(sender())
        }
        fn sign(&self, _: &str, _: &[u8; 32]) -> allowit_core::client::error::Result<Vec<u8>> {
            self.0.0.lock().unwrap().lapsed_code.remove(&self.1);
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
            .upload_code(&installation, &unsent, Poll::default(), NOW)
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
    // A restoration simulation that names an archived entry outside its footprint is refused
    // before anything is signed, also when the footprint is empty, as for absent code.
    chain.0.lock().unwrap().restore_archived = vec![0];
    let refused = session
        .provider
        .upload_code_within(
            &installation,
            &other,
            u64::from(u32::MAX),
            Poll::default(),
            NOW,
        )
        .unwrap_err();
    assert!(
        refused.message.contains("outside the read-write footprint"),
        "{}",
        refused.message
    );
    chain.0.lock().unwrap().restore_archived.clear();
    // An upload whose simulation writes another entry than the code is refused.
    chain.0.lock().unwrap().upload_names_another_entry = true;
    let refused = session
        .provider
        .upload_code_within(
            &installation,
            &other,
            u64::from(u32::MAX),
            Poll::default(),
            NOW,
        )
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
            .upload_code_within(
                &installation,
                &other,
                u64::from(u32::MAX),
                Poll::default(),
                NOW,
            )
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
            .upload_code_within(&installation, &other, 100, Poll::default(), NOW)
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
            .upload_code_within(
                &installation,
                &other,
                u64::from(u32::MAX),
                Poll::default(),
                NOW,
            )
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
            .upload_code_within(&installation, &other, 100, Poll::default(), NOW)
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
            .upload_code_within(
                &installation,
                &other,
                u64::from(u32::MAX),
                Poll::default(),
                NOW,
            )
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
        .upload_code_within(&installation, &other, 100, Poll::default(), NOW)
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
            .upload_code_within(&installation, &other, u64::MAX, Poll::default(), NOW)
            .is_err()
    );
    assert_eq!(signatures(), signed);
    chain.step("upload");
    let receipt = session
        .provider
        .upload_code_within(
            &installation,
            &other,
            u64::from(u32::MAX),
            Poll::default(),
            NOW,
        )
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
            .upload_code(&installation, &other, Poll::default(), NOW)
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
            .upload_code(&installation, &unsent, Poll::default(), NOW)
            .unwrap()
            .is_some()
    );
    // The installation's code lapsed: it is not present, and the server's upload step restores
    // it from a sending account, within the ceiling, with the code entry as its only footprint.
    let installed = c.module_digest;
    chain.0.lock().unwrap().lapsed_code.insert(installed);
    assert!(!provider.resources(&installation).unwrap().code_present);
    let signed = signatures();
    let refused = provider
        .upload_code_within(&installation, &wasm, 100, Poll::default(), NOW)
        .unwrap_err();
    assert!(
        refused
            .message
            .contains("exceeds the explicitly selected ceiling"),
        "{}",
        refused.message
    );
    assert!(chain.0.lock().unwrap().lapsed_code.contains(&installed));
    assert_eq!(signatures(), signed);
    chain.step("restore");
    let restored = provider
        .upload_code_within(
            &installation,
            &wasm,
            u64::try_from(RESTORE_FEE).unwrap() + 100,
            Poll::default(),
            NOW,
        )
        .unwrap();
    assert!(restored.is_some());
    {
        let m = chain.0.lock().unwrap();
        assert!(m.lapsed_code.is_empty());
        let (name, signed, ..) = m.steps.last().unwrap();
        assert_eq!(name, "restore");
        let x::TransactionEnvelope::Tx(env) = de(signed) else {
            panic!()
        };
        assert!(matches!(
            env.tx.operations.as_slice(),
            [x::Operation {
                body: x::OperationBody::RestoreFootprint(_),
                ..
            }]
        ));
        let x::TransactionExt::V1(data) = &env.tx.ext else {
            panic!()
        };
        assert_eq!(
            data.resources.footprint.read_write.as_slice(),
            [x::LedgerKey::ContractCode(x::LedgerKeyContractCode {
                hash: x::Hash(installed)
            })]
        );
        assert!(data.resources.footprint.read_only.is_empty());
        assert_eq!(source_of(&env.tx), sender());
    }
    assert_eq!(
        rpc::code_state(&*chain, NETWORK, &installed).unwrap(),
        rpc::CodeState::Live
    );
    assert!(
        provider
            .upload_code(&installation, &wasm, Poll::default(), NOW)
            .unwrap()
            .is_none()
    );
    // Before a wallet operation the server restores the installation's lapsed code by its hash,
    // without its bytes, and nothing when the code is live.
    let ceiling = u64::try_from(RESTORE_FEE).unwrap() + 100;
    assert!(
        provider
            .restore_code_within(&installation, ceiling, Poll::default(), NOW)
            .unwrap()
            .is_none()
    );
    chain.0.lock().unwrap().lapsed_code.insert(installed);
    let signed = signatures();
    assert!(
        plain
            .restore_code_within(&installation, ceiling, Poll::default(), NOW)
            .unwrap_err()
            .message
            .contains("no sending account")
    );
    assert!(
        provider
            .restore_code_within(&installation, 100, Poll::default(), NOW)
            .unwrap_err()
            .message
            .contains("exceeds the explicitly selected ceiling")
    );
    assert_eq!(signatures(), signed);
    chain.step("restore before an operation");
    assert!(
        provider
            .restore_code_within(&installation, ceiling, Poll::default(), NOW)
            .unwrap()
            .is_some()
    );
    {
        let m = chain.0.lock().unwrap();
        assert!(m.lapsed_code.is_empty());
        assert_eq!(m.steps.last().unwrap().0, "restore before an operation");
    }
    // A simulation that names an archived entry outside the restoration's footprint is refused
    // before anything is signed.
    {
        let mut m = chain.0.lock().unwrap();
        m.lapsed_code.insert(installed);
        m.restore_archived = vec![1];
    }
    let sent = chain.0.lock().unwrap().steps.len();
    let signed = signatures();
    let refused = provider
        .restore_code_within(&installation, ceiling, Poll::default(), NOW)
        .unwrap_err();
    assert_eq!(signatures(), signed);
    assert!(
        refused.message.contains("outside the read-write footprint"),
        "{}",
        refused.message
    );
    {
        let mut m = chain.0.lock().unwrap();
        assert_eq!(m.steps.len(), sent);
        assert!(m.lapsed_code.contains(&installed));
        m.restore_archived.clear();
        // The next restoration fails when the ledger applies it.
        m.failing_restore = true;
    }
    // A restoration that the ledger includes but fails leaves the code lapsed. It is an error,
    // not a receipt of live code, and it names the transaction and the fee that the sending
    // account paid for it, which the server accounts for.
    chain.step("failed restoration");
    let failed = provider
        .restore_code_within(&installation, ceiling, Poll::default(), NOW)
        .unwrap_err();
    assert!(
        failed.message.contains("failed on the ledger"),
        "{}",
        failed.message
    );
    {
        let m = chain.0.lock().unwrap();
        assert!(m.lapsed_code.contains(&installed));
        let (name, signed, ..) = m.steps.last().unwrap();
        assert_eq!(name, "failed restoration");
        let x::TransactionEnvelope::Tx(env) = de(signed) else {
            panic!()
        };
        let details = failed
            .details
            .as_ref()
            .expect("the failed restoration's details");
        assert_eq!(
            details,
            &json!({"transactionHash": hexs(&tx_hash(&env.tx)), "nativeUnits": "100"})
        );
    }
    // The upload step refuses a failed restoration too.
    chain.step("failed restoration of the upload step");
    assert!(
        provider
            .upload_code_within(&installation, &wasm, ceiling, Poll::default(), NOW)
            .unwrap_err()
            .message
            .contains("failed on the ledger")
    );
    assert!(chain.0.lock().unwrap().lapsed_code.contains(&installed));
    // A receipt that reports a fee above the fee that its transaction declared is refused, and
    // names no fee to charge.
    chain.0.lock().unwrap().charged_fee = Some(i64::from(u32::MAX));
    chain.step("failed restoration with an inflated fee");
    let inflated = provider
        .restore_code_within(&installation, ceiling, Poll::default(), NOW)
        .unwrap_err();
    assert!(
        inflated
            .message
            .contains("above the fee of its transaction"),
        "{}",
        inflated.message
    );
    assert!(inflated.details.is_none());
    chain.0.lock().unwrap().charged_fee = None;
    // The next restoration that the ledger applies makes the code live.
    chain.0.lock().unwrap().failing_restore = false;
    chain.step("restore after a failure");
    assert!(
        provider
            .restore_code_within(&installation, ceiling, Poll::default(), NOW)
            .unwrap()
            .is_some()
    );
    assert!(chain.0.lock().unwrap().lapsed_code.is_empty());
    // Another request restores the code after this one read it as lapsed: the simulation of the
    // restoration names no entry, the code is live, and nothing is sent. When that request sent
    // from the same account, the account changed during the simulation: the code, read again,
    // is live all the same.
    for by_source in [false, true] {
        {
            let mut m = chain.0.lock().unwrap();
            m.lapsed_code.insert(installed);
            m.restored_meanwhile = true;
            m.restored_by_source = by_source;
        }
        let sent = chain.0.lock().unwrap().steps.len();
        let signed = signatures();
        assert!(
            provider
                .restore_code_within(&installation, ceiling, Poll::default(), NOW)
                .unwrap()
                .is_none(),
            "{by_source}"
        );
        assert_eq!(signatures(), signed);
        let mut m = chain.0.lock().unwrap();
        assert_eq!(m.steps.len(), sent);
        assert!(m.lapsed_code.is_empty());
        m.restored_meanwhile = false;
        m.restored_by_source = false;
    }
    // An RPC that serves no archived entry reads lapsed code as absent. A simulated restoration
    // of the code entry tells them apart: the step before an operation restores the code, and
    // the upload step restores it instead of uploading it again, which the network refuses.
    {
        let mut m = chain.0.lock().unwrap();
        m.lapsed_code.insert(installed);
        m.hide_archived = true;
    }
    assert_eq!(
        rpc::code_state(&*chain, NETWORK, &installed).unwrap(),
        rpc::CodeState::Absent
    );
    for (name, upload) in [
        ("restore of unread code", false),
        ("upload step of unread code", true),
    ] {
        chain.0.lock().unwrap().lapsed_code.insert(installed);
        chain.step(name);
        let restored = if upload {
            provider.upload_code_within(&installation, &wasm, ceiling, Poll::default(), NOW)
        } else {
            provider.restore_code_within(&installation, ceiling, Poll::default(), NOW)
        };
        assert!(restored.unwrap().is_some(), "{name}");
        let m = chain.0.lock().unwrap();
        assert!(m.lapsed_code.is_empty(), "{name}");
        let (step, signed, ..) = m.steps.last().unwrap();
        assert_eq!(step, name);
        let x::TransactionEnvelope::Tx(env) = de(signed) else {
            panic!()
        };
        assert!(matches!(
            env.tx.operations.as_slice(),
            [x::Operation {
                body: x::OperationBody::RestoreFootprint(_),
                ..
            }]
        ));
    }
    // A restoration of such code that the ledger fails is reported as a restoration, the
    // operation that the sending account sent, not as an upload.
    {
        let mut m = chain.0.lock().unwrap();
        m.lapsed_code.insert(installed);
        m.failing_restore = true;
    }
    chain.step("failed restoration of unread code");
    let failed = provider
        .restore_code_within(&installation, ceiling, Poll::default(), NOW)
        .unwrap_err();
    assert!(
        failed
            .message
            .contains("restoration of the wallet code failed"),
        "{}",
        failed.message
    );
    chain.0.lock().unwrap().failing_restore = false;
    chain.step("restore of unread code after a failure");
    assert!(
        provider
            .restore_code_within(&installation, ceiling, Poll::default(), NOW)
            .unwrap()
            .is_some()
    );
    chain.0.lock().unwrap().hide_archived = false;
    // An upload simulation that restores the archived code entry in place is refused: lapsed
    // code is restored by a restoration of the code entry alone, never uploaded. The upload step
    // restores it.
    {
        let mut m = chain.0.lock().unwrap();
        m.lapsed_code.insert(installed);
        m.upload_restores_in_place = true;
    }
    let deployer = Deployer {
        rpc: &*chain,
        network: NETWORK,
        now: NOW,
        max_fee_stroops: u32::MAX,
    };
    let refused = deployer.upload_wasm(&sender(), &wasm).unwrap_err();
    assert!(refused.contains("restored, not uploaded"), "{refused}");
    chain.step("upload step of code that an upload would restore");
    assert!(
        provider
            .upload_code_within(&installation, &wasm, ceiling, Poll::default(), NOW)
            .unwrap()
            .is_some()
    );
    {
        let mut m = chain.0.lock().unwrap();
        assert!(m.lapsed_code.is_empty());
        let x::TransactionEnvelope::Tx(env) = de(&m.steps.last().unwrap().1) else {
            panic!()
        };
        assert!(matches!(
            env.tx.operations.as_slice(),
            [x::Operation {
                body: x::OperationBody::RestoreFootprint(_),
                ..
            }]
        ));
        m.upload_restores_in_place = false;
    }
    // A read that finds no entry can omit the entry list: the code is absent.
    chain.0.lock().unwrap().omit_empty_entries = true;
    assert_eq!(
        rpc::code_state(&*chain, NETWORK, &[0x5a; 32]).unwrap(),
        rpc::CodeState::Absent
    );
    chain.0.lock().unwrap().omit_empty_entries = false;
    // A restoration whose simulation the network refuses restores nothing, and the code is read
    // again. A read that fails is an error, not absent code that an upload would replace.
    {
        let mut m = chain.0.lock().unwrap();
        m.refused_restore = true;
        m.failing_code_reads = true;
    }
    let refused = deployer
        .restore_code(&sender(), installed)
        .expect_err("a failed read is an error");
    assert!(refused.contains("unreachable"), "{refused}");
    // Code that the read finds lapsed has an archived entry that the restoration did not name:
    // that is refused too, never read as absent.
    chain.0.lock().unwrap().failing_code_reads = false;
    chain.0.lock().unwrap().lapsed_code.insert(installed);
    let refused = deployer
        .restore_code(&sender(), installed)
        .expect_err("lapsed code that a restoration does not name is an error");
    assert!(refused.contains("lapsed"), "{refused}");
    let signed = signatures();
    let refused = provider
        .upload_code_within(&installation, &wasm, ceiling, Poll::default(), NOW)
        .unwrap_err();
    assert!(refused.message.contains("lapsed"), "{}", refused.message);
    assert_eq!(signatures(), signed);
    // Live code needs nothing, whatever the simulation answers.
    chain.0.lock().unwrap().lapsed_code.remove(&installed);
    assert!(matches!(
        deployer.restore_code(&sender(), installed).unwrap(),
        CodeRestoration::Live
    ));
    chain.0.lock().unwrap().refused_restore = false;
    // Another sending account restores the code just after the simulation, which still names
    // the entry: the code, read again before the signature, is live, and nothing is signed.
    {
        let mut m = chain.0.lock().unwrap();
        m.lapsed_code.insert(installed);
        m.restored_after_simulation = true;
    }
    let signed = signatures();
    assert!(
        provider
            .restore_code_within(&installation, ceiling, Poll::default(), NOW)
            .unwrap()
            .is_none()
    );
    assert_eq!(signatures(), signed);
    {
        let m = chain.0.lock().unwrap();
        assert!(!m.restored_after_simulation);
        assert!(!m.lapsed_code.contains(&installed));
    }
    // So with a fee ceiling below the restoration's fee: no restoration is needed, so no ceiling
    // refuses it.
    {
        let mut m = chain.0.lock().unwrap();
        m.lapsed_code.insert(installed);
        m.restored_after_simulation = true;
    }
    assert!(
        provider
            .restore_code_within(&installation, 100, Poll::default(), NOW)
            .unwrap()
            .is_none()
    );
    assert_eq!(signatures(), signed);
    assert!(!chain.0.lock().unwrap().lapsed_code.contains(&installed));
    // Every sending account is leased while another account restores the code: no restoration
    // is needed, so the allocation's refusal does not stand.
    chain.0.lock().unwrap().lapsed_code.insert(installed);
    let leased = |restores| {
        allowit_stellar::PLUGIN
            .sending_runtime(
                NETWORK,
                Arc::new(Wire(chain.clone())),
                Arc::new(Leased(chain.clone(), restores)),
            )
            .unwrap()
    };
    assert!(
        leased(Some(installed))
            .restore_code_within(&installation, ceiling, Poll::default(), NOW)
            .unwrap()
            .is_none()
    );
    // While the code stays lapsed, the refusal stands.
    chain.0.lock().unwrap().lapsed_code.insert(installed);
    let refused = leased(None)
        .restore_code_within(&installation, ceiling, Poll::default(), NOW)
        .unwrap_err();
    assert!(refused.message.contains("leased"), "{}", refused.message);
    // The signer refuses while another account restores the code: nothing is needed.
    assert!(
        allowit_stellar::PLUGIN
            .sending_runtime(
                NETWORK,
                Arc::new(Wire(chain.clone())),
                Arc::new(Refusing(chain.clone(), installed)),
            )
            .unwrap()
            .restore_code_within(&installation, ceiling, Poll::default(), NOW)
            .unwrap()
            .is_none()
    );
    assert!(!chain.0.lock().unwrap().lapsed_code.contains(&installed));
    // The signature does not verify while another account restores the code: nothing is needed.
    chain.0.lock().unwrap().lapsed_code.insert(installed);
    assert!(
        allowit_stellar::PLUGIN
            .sending_runtime(
                NETWORK,
                Arc::new(Wire(chain.clone())),
                Arc::new(Garbled(chain.clone(), installed)),
            )
            .unwrap()
            .restore_code_within(&installation, ceiling, Poll::default(), NOW)
            .unwrap()
            .is_none()
    );
    // A node that trails serves the code as lapsed after another account restored it: a
    // negative read that trails the closing head does not decide a paid transaction, and the
    // code is read again.
    let signed = signatures();
    {
        let mut m = chain.0.lock().unwrap();
        m.lapsed_code.insert(installed);
        m.restored_after_simulation = true;
        m.stale_code_reads = 2;
    }
    assert!(
        provider
            .restore_code_within(&installation, ceiling, Poll::default(), NOW)
            .unwrap()
            .is_none()
    );
    assert_eq!(signatures(), signed);
    assert_eq!(chain.0.lock().unwrap().stale_code_reads, 0);
    // The network does not accept the restoration yet, and another account restores the code
    // meanwhile: the restoration is not sent again.
    {
        let mut m = chain.0.lock().unwrap();
        m.lapsed_code.insert(installed);
        m.retry_later_restores = Some(installed);
    }
    let quick = Poll {
        attempts: 3,
        interval: std::time::Duration::ZERO,
    };
    assert!(
        provider
            .restore_code_within(&installation, ceiling, quick, NOW)
            .unwrap()
            .is_none()
    );
    {
        let m = chain.0.lock().unwrap();
        assert!(m.retry_later_restores.is_none());
        assert!(!m.lapsed_code.contains(&installed));
    }
    // So when the read before the repeated send trails the closing head: that read does not
    // decide, and the code is read again.
    {
        let mut m = chain.0.lock().unwrap();
        m.lapsed_code.insert(installed);
        m.retry_later_restores = Some(installed);
        m.stale_reads_on_retry_later = 1;
    }
    assert!(
        provider
            .restore_code_within(&installation, ceiling, quick, NOW)
            .unwrap()
            .is_none()
    );
    assert_eq!(chain.0.lock().unwrap().stale_code_reads, 0);
    // The read before the signature answers at a ledger before the head read just before it:
    // it is taken once more, and the restoration of code that is still lapsed goes on.
    {
        let mut m = chain.0.lock().unwrap();
        m.lapsed_code.insert(installed);
        m.behind_reads_on_restore_simulation = 1;
    }
    chain.step("restore after a read that trails the head");
    assert!(
        provider
            .restore_code_within(&installation, ceiling, Poll::default(), NOW)
            .unwrap()
            .is_some()
    );
    {
        let m = chain.0.lock().unwrap();
        assert_eq!(m.behind_head_code_reads, 0);
        assert!(!m.lapsed_code.contains(&installed));
    }
    // A read taken again may come from a node behind a head that the first read saw: its
    // negative answer does not decide.
    {
        let mut m = chain.0.lock().unwrap();
        m.lapsed_code.insert(installed);
        let head = m.ledger;
        m.heads = [head, head + 1, head, head].into();
    }
    let refused =
        rpc::current_code_state(&*chain, NETWORK, &installed, &Default::default()).unwrap_err();
    assert!(refused.contains("trails"), "{refused}");
    assert!(chain.0.lock().unwrap().heads.is_empty());
    // The first reply trails its own heads (H+1) and the read taken again comes wholly from a
    // replica at H: the heads of the first reply count, so its negative answer does not decide.
    {
        let mut m = chain.0.lock().unwrap();
        let head = m.ledger;
        m.heads = [head + 1, head + 1, head, head].into();
        m.replica_code_reads = [head, head].into();
    }
    let refused =
        rpc::current_code_state(&*chain, NETWORK, &installed, &Default::default()).unwrap_err();
    assert!(refused.contains("trails"), "{refused}");
    // The highest ledger seen holds across the reads of one decision: a later read from a
    // replica behind it does not decide.
    let seen = std::cell::Cell::new(0);
    assert_eq!(
        rpc::current_code_state(&*chain, NETWORK, &installed, &seen).unwrap(),
        rpc::CodeState::Lapsed
    );
    {
        let mut m = chain.0.lock().unwrap();
        let behind = m.ledger - 1;
        m.heads = [behind; 4].into();
        m.replica_code_reads = [behind, behind].into();
    }
    let refused = rpc::current_code_state(&*chain, NETWORK, &installed, &seen).unwrap_err();
    assert!(refused.contains("trails"), "{refused}");
    {
        let mut m = chain.0.lock().unwrap();
        assert!(m.heads.is_empty() && m.replica_code_reads.is_empty());
        m.lapsed_code.remove(&installed);
    }
    // So across the sends of one code transaction: after TRY_AGAIN_LATER another account
    // restores the code, and the check before the repeated send reads from a replica behind
    // the checks before it. Nothing is sent again.
    {
        let mut m = chain.0.lock().unwrap();
        m.lapsed_code.insert(installed);
        m.retry_later_restores = Some(installed);
        let behind = m.ledger - 1;
        m.heads_on_retry_later = vec![behind; 4];
        m.replica_reads_on_retry_later = vec![behind, behind];
    }
    let refused = provider
        .restore_code_within(&installation, ceiling, quick, NOW)
        .unwrap_err();
    assert!(refused.message.contains("trails"), "{}", refused.message);
    {
        let m = chain.0.lock().unwrap();
        assert!(m.heads.is_empty() && m.replica_code_reads.is_empty());
        assert!(!m.lapsed_code.contains(&installed));
    }
    // Another account restores the code while the sending account signs: the restoration is
    // not sent.
    chain.0.lock().unwrap().lapsed_code.insert(installed);
    assert!(
        allowit_stellar::PLUGIN
            .sending_runtime(
                NETWORK,
                Arc::new(Wire(chain.clone())),
                Arc::new(Overtaken(chain.clone(), installed)),
            )
            .unwrap()
            .restore_code_within(&installation, ceiling, Poll::default(), NOW)
            .unwrap()
            .is_none()
    );
    assert!(!chain.0.lock().unwrap().lapsed_code.contains(&installed));
    // Code that the network does not have cannot be restored: it needs an upload.
    chain.0.lock().unwrap().code_bytes.remove(&installed);
    let signed = signatures();
    assert!(
        provider
            .restore_code_within(&installation, ceiling, Poll::default(), NOW)
            .unwrap_err()
            .message
            .contains("not on the network")
    );
    assert_eq!(signatures(), signed);
}
/// A wallet whose instance and `t` lapsed: the ledger still gives their values, so the server
/// reads the wallet and the agent's payment restores both in place; the owner's stop then
/// restores them too and returns everything with one signature.
#[test]
fn a_lapsed_instance_restores_in_the_payment_and_in_the_owners_stop() {
    let wasm = wasm_for(PolicyTier::Common);
    let chain = ModelChain::new(BTreeMap::from([(hash(&wasm), PolicyTier::Common)]));
    let c = create(&chain, PolicyTier::Common, &wasm, [0x37; 32]);
    let lapsed = Lapsed {
        chain: &chain,
        preamble: false,
        instance: true,
    };
    let mut state = rpc::trusted_state(&lapsed, &c, Some(chain.accounting())).unwrap();
    state.source = rpc::get_account(&lapsed, &sender()).unwrap();
    let ledger = chain.ledger();
    let recipient = account_for_seed(&RECIPIENT);
    let transfer = request::transfer(&c, &state, [1; 32], &recipient, 1_000_000).unwrap();
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
    let x::TransactionEnvelope::Tx(envelope) = de(&sealed.transaction_xdr) else {
        panic!()
    };
    let x::TransactionExt::V1(data) = &envelope.tx.ext else {
        panic!()
    };
    assert!(matches!(
        &data.ext,
        x::SorobanTransactionDataExt::V1(ext) if ext.archived_soroban_entries.as_slice() == [0, 1]
    ));
    chain.step("transfer");
    assert_eq!(
        rpc::broadcast(&chain, &sealed, NOW).unwrap(),
        rpc::Broadcast::Submitted
    );
    // The owner alone: the stop reads the lapsed instance and restores it in the same call.
    let mut owner = OwnerAdmin {
        rpc: &lapsed,
        config: &c,
        now: NOW,
    };
    let version = owner.deployment_version().unwrap().0 + 1;
    let stop = owner.stop(DeploymentVersion(version)).unwrap();
    let x::TransactionEnvelope::Tx(envelope) = de(&stop.transaction_xdr) else {
        panic!()
    };
    let x::TransactionExt::V1(data) = &envelope.tx.ext else {
        panic!()
    };
    assert!(matches!(
        &data.ext,
        x::SorobanTransactionDataExt::V1(ext) if ext.archived_soroban_entries.len() == 2
    ));
    owner_submit(&chain, "stop", &stop.transaction_xdr);
    assert_eq!(chain.balance(), 0);
    assert!(chain.config().paused);
}
