//! Stellar RPC protocol, native observations and transaction validity.
//! Common transport owns HTTP bounds; SDK engine owns persistence, polling and retry workflows.
use crate::*;
mod diagnostics;
mod owner_actions;
pub use diagnostics::{
    ContractFault, WalletError, host_policy_denial, simulated_contract, simulation_fault,
    simulation_resource_fee,
};
pub(crate) mod owner_observation;
#[cfg(not(target_arch = "wasm32"))]
use allowit_core::transport::rpc::{EnvelopeValidation, ErrorKind, RpcClient};
pub use owner_actions::{
    CodeState, OwnerSettlement, code_state, code_uploaded, contract_exists, owner_settlement,
    vault_redeemable,
};
pub use owner_observation::{AssetBalance, WalletLifetime, asset_balance, wallet_lifetime};
use serde_json::{Value, json};
#[cfg(not(target_arch = "wasm32"))]
use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

fn transaction_hash_for(network: &str, tx: &Transaction) -> Result<[u8; 32]> {
    super::transaction_hash(network, tx)
}
/// The failure of a Stellar RPC call that got no answer: a timeout or a connection, DNS or TLS
/// failure. Nothing was observed, so a retry with the same request ID is safe.
pub const NETWORK_UNAVAILABLE: &str = "Stellar RPC network unavailable (timeout or connection failure); retry with the same request ID";
/// The failure of a Stellar RPC call that got an answer whose outcome is unknown.
pub const TRANSPORT_UNKNOWN: &str = "Stellar RPC transport result is unknown";
pub trait Rpc: Send + Sync {
    fn call(&self, method: &str, params: Value) -> Result<Value>;
}
/// The RPC method that reads the newest ledger.
#[cfg(not(target_arch = "wasm32"))]
const LATEST_LEDGER: &str = "getLatestLedger";
/// The bound of a `getLatestLedger` reply. The reply holds the close metadata of the newest
/// ledger beside its sequence, so its size follows the content of that ledger and not the
/// request. Testnet ledger 5684062 answered with 1,155,616 characters of metadata, above
/// [`MAX_BYTES`], and every call that read the head during that ledger failed. Callers read
/// only the sequence.
#[cfg(not(target_arch = "wasm32"))]
const LATEST_LEDGER_MAX_BYTES: usize = 16 * MAX_BYTES;
/// Stellar JSON-RPC protocol adapter over the bounded common host transport.
#[cfg(not(target_arch = "wasm32"))]
pub struct HttpRpc {
    client: RpcClient,
    /// The same endpoint with the bound of a `getLatestLedger` reply.
    latest_ledger: RpcClient,
    id: AtomicU64,
}
#[cfg(not(target_arch = "wasm32"))]
impl HttpRpc {
    pub fn new(url: &str) -> Result<Self> {
        Self::with_timeout(url, Duration::from_secs(30))
    }
    fn with_timeout(url: &str, timeout: Duration) -> Result<Self> {
        let client = |max_bytes| {
            RpcClient::new(url, timeout, max_bytes)
                .map(RpcClient::accept_success_statuses)
                .map_err(|_| "RPC requires HTTPS or local HTTP without credentials")
        };
        Ok(Self {
            client: client(MAX_BYTES)?,
            latest_ledger: client(LATEST_LEDGER_MAX_BYTES)?,
            id: AtomicU64::new(1),
        })
    }
}
#[cfg(not(target_arch = "wasm32"))]
impl Rpc for HttpRpc {
    fn call(&self, method: &str, params: Value) -> Result<Value> {
        let client = if method == LATEST_LEDGER {
            &self.latest_ledger
        } else {
            &self.client
        };
        client
            .call_with_id(
                method,
                &params,
                self.id.fetch_add(1, Ordering::Relaxed),
                EnvelopeValidation::StrictIdentity,
                None,
            )
            .map_err(|error| {
                match error.kind {
                    ErrorKind::Timeout | ErrorKind::Connection => NETWORK_UNAVAILABLE,
                    ErrorKind::Http => "Stellar RPC rejected the HTTP request",
                    ErrorKind::Size => "RPC response exceeds limit",
                    ErrorKind::MissingResult => "Missing RPC result",
                    ErrorKind::Json | ErrorKind::Envelope | ErrorKind::Refused => {
                        "Invalid or failed Stellar RPC response"
                    }
                    _ => TRANSPORT_UNKNOWN,
                }
                .into()
            })
    }
}
pub fn get_account(rpc: &dyn Rpc, address: &str) -> Result<AccountState> {
    let key = LedgerKey::Account(LedgerKeyAccount {
        account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(account_key(
            address,
        )?))),
    });
    let value = rpc.call("getLedgerEntries", json!({"keys":[xdr(&key)?]}))?;
    account_from_response(&value, address)
}
/// The account when the ledger holds it, `None` when it does not exist.
pub fn find_account(rpc: &dyn Rpc, address: &str) -> Result<Option<AccountState>> {
    let key = LedgerKey::Account(LedgerKeyAccount {
        account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(account_key(
            address,
        )?))),
    });
    let value = rpc.call("getLedgerEntries", json!({"keys":[xdr(&key)?]}))?;
    if value["entries"].as_array().is_some_and(Vec::is_empty) {
        return Ok(None);
    }
    account_from_response(&value, address).map(Some)
}
/// The XLM of an account as the ledger holds it, in stroops, with what the network locks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeBalance {
    pub balance: i64,
    /// The XLM that open offers of the account hold.
    pub selling: i64,
    /// The entries whose base reserve the account pays: its own signers, trustlines, offers
    /// and data, plus the entries that it sponsors, less the entries that another account
    /// sponsors for it.
    pub reserved_entries: i64,
}
impl NativeBalance {
    /// The XLM that the account can send while it keeps its reserve and `more_entries`
    /// further entries, such as a signer that its owner adds later. Never negative.
    pub fn spendable(&self, more_entries: i64) -> i64 {
        let entries = 2i64
            .saturating_add(self.reserved_entries)
            .saturating_add(more_entries);
        self.balance
            .saturating_sub(self.selling)
            .saturating_sub(entries.saturating_mul(crate::owner::BASE_RESERVE_STROOPS))
            .max(0)
    }
}
/// Read the XLM of an account and the entries that lock its reserve.
pub fn native_balance(rpc: &dyn Rpc, address: &str) -> Result<NativeBalance> {
    let key = LedgerKey::Account(LedgerKeyAccount {
        account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(account_key(
            address,
        )?))),
    });
    let value = rpc.call("getLedgerEntries", json!({"keys":[xdr(&key)?]}))?;
    let entries = value["entries"]
        .as_array()
        .ok_or("Missing account entries")?;
    if entries.len() != 1 {
        return Err("Native account not found".into());
    }
    let LedgerEntryData::Account(account) =
        read(entries[0]["xdr"].as_str().ok_or("Missing account XDR")?)?
    else {
        return Err("Wrong ledger entry type".into());
    };
    let (selling, sponsoring, sponsored) = match &account.ext {
        AccountEntryExt::V0 => (0, 0, 0),
        AccountEntryExt::V1(v1) => {
            let (sponsoring, sponsored) = match &v1.ext {
                AccountEntryExtensionV1Ext::V0 => (0, 0),
                AccountEntryExtensionV1Ext::V2(v2) => {
                    (i64::from(v2.num_sponsoring), i64::from(v2.num_sponsored))
                }
            };
            (v1.liabilities.selling, sponsoring, sponsored)
        }
    };
    Ok(NativeBalance {
        balance: account.balance,
        selling,
        reserved_entries: i64::from(account.num_sub_entries) + sponsoring - sponsored,
    })
}
/// The balance of an issued asset that an account holds, `None` without its trustline.
pub fn trustline_balance(rpc: &dyn Rpc, address: &str, asset: &Asset) -> Result<Option<i64>> {
    let line = match asset {
        Asset::CreditAlphanum4(a) => TrustLineAsset::CreditAlphanum4(a.clone()),
        Asset::CreditAlphanum12(a) => TrustLineAsset::CreditAlphanum12(a.clone()),
        Asset::Native => return Err("XLM has no trustline".into()),
    };
    let key = LedgerKey::Trustline(LedgerKeyTrustLine {
        account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(account_key(
            address,
        )?))),
        asset: line,
    });
    let value = rpc.call("getLedgerEntries", json!({"keys":[xdr(&key)?]}))?;
    let entries = value["entries"]
        .as_array()
        .ok_or("Missing trustline entries")?;
    let Some(entry) = entries.first() else {
        return Ok(None);
    };
    let LedgerEntryData::Trustline(line) =
        read(entry["xdr"].as_str().ok_or("Missing trustline XDR")?)?
    else {
        return Err("Wrong ledger entry type".into());
    };
    Ok(Some(line.balance))
}
/// The units of an issued asset that an account can send: its balance less what its open
/// offers hold. `None` without its trustline.
pub fn trustline_spendable(rpc: &dyn Rpc, address: &str, asset: &Asset) -> Result<Option<i64>> {
    let line = match asset {
        Asset::CreditAlphanum4(a) => TrustLineAsset::CreditAlphanum4(a.clone()),
        Asset::CreditAlphanum12(a) => TrustLineAsset::CreditAlphanum12(a.clone()),
        Asset::Native => return Err("XLM has no trustline".into()),
    };
    let key = LedgerKey::Trustline(LedgerKeyTrustLine {
        account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(account_key(
            address,
        )?))),
        asset: line,
    });
    let value = rpc.call("getLedgerEntries", json!({"keys":[xdr(&key)?]}))?;
    let entries = value["entries"]
        .as_array()
        .ok_or("Missing trustline entries")?;
    let Some(entry) = entries.first() else {
        return Ok(None);
    };
    let LedgerEntryData::Trustline(line) =
        read(entry["xdr"].as_str().ok_or("Missing trustline XDR")?)?
    else {
        return Err("Wrong ledger entry type".into());
    };
    let selling = match &line.ext {
        TrustLineEntryExt::V0 => 0,
        TrustLineEntryExt::V1(v1) => v1.liabilities.selling,
    };
    Ok(Some(line.balance.saturating_sub(selling).max(0)))
}
/// A native source account dated by the entry response and fresh bracketing heads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountObservation {
    pub account: AccountState,
    pub ledger: u32,
}
pub fn observe_account(rpc: &dyn Rpc, network: &str, address: &str) -> Result<AccountObservation> {
    owner_observation::network(rpc, network)?;
    let before = owner_observation::head(rpc)?;
    let observation = read_account_observation(rpc, address)?;
    owner_observation::current(rpc, before, observation.ledger)?;
    Ok(observation)
}

/// Read the exact account entry and its ledger. The caller verifies the network and freshness.
pub(crate) fn read_account_observation(rpc: &dyn Rpc, address: &str) -> Result<AccountObservation> {
    let key = LedgerKey::Account(LedgerKeyAccount {
        account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(account_key(
            address,
        )?))),
    });
    let value = rpc.call("getLedgerEntries", json!({"keys":[xdr(&key)?]}))?;
    let ledger = owner_observation::ledger(&value["latestLedger"])?;
    let account = account_from_response(&value, address)?;
    account.validate_structure()?;
    if value["entries"][0]
        .get("key")
        .is_some_and(|v| v.as_str() != xdr(&key).ok().as_deref())
    {
        return Err("Native account response key differs".into());
    }
    Ok(AccountObservation { account, ledger })
}
fn account_from_response(value: &Value, address: &str) -> Result<AccountState> {
    let entries = value["entries"]
        .as_array()
        .ok_or("Missing account entries")?;
    if entries.len() != 1 {
        return Err("Native account not found".into());
    }
    let raw = entries[0]["xdr"].as_str().ok_or("Missing account XDR")?;
    let LedgerEntryData::Account(account) = read(raw)? else {
        return Err("Wrong ledger entry type".into());
    };
    let PublicKey::PublicKeyTypeEd25519(key) = account.account_id.0;
    let actual = ed25519::PublicKey(key.0).to_string();
    if actual != address {
        return Err("Ledger account identity differs".into());
    }
    let mut signers = Vec::new();
    for s in account.signers.iter() {
        let key = match &s.key {
            SignerKey::Ed25519(key) => ed25519::PublicKey(key.0).to_string(),
            SignerKey::PreAuthTx(key) => stellar_strkey::PreAuthTx(key.0).to_string(),
            SignerKey::HashX(key) => stellar_strkey::HashX(key.0).to_string(),
            SignerKey::Ed25519SignedPayload(key) => ed25519::SignedPayload {
                ed25519: key.ed25519.0,
                payload: key.payload.to_vec(),
            }
            .to_string(),
        };
        signers.push(AccountSigner {
            key,
            weight: s.weight,
        });
    }
    Ok(AccountState {
        address: actual,
        sequence: account.seq_num.0,
        master_weight: u32::from(account.thresholds.0[0]),
        low_threshold: u32::from(account.thresholds.0[1]),
        medium_threshold: u32::from(account.thresholds.0[2]),
        high_threshold: u32::from(account.thresholds.0[3]),
        signers,
    })
}
/// Prepare from authoritative current state and simulate the exact native policy execution.
/// `accounting` is required only for the existing classic/native route. policy wallet property/validation
/// policies receive an ephemeral preflight binding for new signing. Nothing is submitted.
pub fn prepare(
    rpc: &dyn Rpc,
    c: &WalletConfig,
    request: &ExecutionRequest,
    accounting: Option<NativeAccounting>,
    now: u64,
    expires_at: u64,
) -> Result<PreparedOperation> {
    prepare_with(
        rpc,
        c,
        request,
        &ExecutionTerms::default(),
        accounting,
        now,
        expires_at,
    )
}
/// `prepare` with execution args and expense bounds. An operation other than a transfer first
/// checks that the installed code runs it.
pub fn prepare_with(
    rpc: &dyn Rpc,
    c: &WalletConfig,
    request: &ExecutionRequest,
    terms: &ExecutionTerms,
    accounting: Option<NativeAccounting>,
    now: u64,
    expires_at: u64,
) -> Result<PreparedOperation> {
    let mut state = trusted_state(rpc, c, accounting)?;
    if c.route == WalletRoute::Native {
        return super::prepare_with(c, request, terms, &state, now, expires_at);
    }
    // The server's sending account is the source and pays the fee; the wallet repays its gas
    // to that same account.
    state.source = get_account(rpc, &super::gas_repayment(request, terms)?.payee)?;
    let ceiling = terms.expense.as_ref();
    let mut terms = priced_terms(rpc, c, request, terms, &state, now, expires_at)?;
    // The invocation that carries the priced expense is simulated on its own. A policy that
    // reads the gas can need more resources with it than with the provisional expense. Its
    // bound then follows from its own resource fee, within the ceiling, at most
    // `REPRICE_ROUNDS` times. After that the bound decides, and `attach_simulation` refuses a
    // resource fee above it.
    let mut rounds = 0;
    loop {
        let intent = prepare_for_native_preflight(c, request, &terms, &state, now, expires_at)?;
        let encoded = simulated_resources(rpc, &intent)?;
        let repriced = match (ceiling, &terms.expense) {
            (Some(ceiling), Some(signed)) if rounds < REPRICE_ROUNDS => {
                let resources: SorobanTransactionData = read(&encoded)?;
                let bound = fee_bound(resources.resource_fee)?.min(ceiling.max_fee_stroops);
                // The margin of the signed bound absorbs a small change. Only a declared fee
                // above the signed bound prices the operation again, and only upward.
                let declared = resources
                    .resource_fee
                    .saturating_add(i64::from(INCLUSION_FEE_STROOPS));
                (declared > i64::from(signed.max_fee_stroops) && bound > signed.max_fee_stroops)
                    .then(|| bounded(&terms, ceiling, bound, i128::from(c.max_fee_stroops)))
            }
            _ => None,
        };
        let Some(expense) = repriced else {
            let mut prepared = attach_simulation(&intent, &encoded)?;
            record_native_preflight(&mut prepared)?;
            return Ok(prepared);
        };
        // A higher bound leaves less room under the gas cap: the due that fits can only shrink.
        let (expense, gas_due) = expense?;
        terms.expense = Some(expense);
        terms.gas_due = gas_due;
        rounds += 1;
    }
}
/// How often preparation prices an operation again from the simulation of its priced
/// invocation.
const REPRICE_ROUNDS: u8 = 2;
/// `terms` with the expense fee bound lowered from the caller's ceiling to the fee that this
/// operation can be charged: `fee_bound` of its simulated resource fee, at most the ceiling.
///
/// The expense is an argument of the invocation, so the fee is simulated first with a
/// provisional fee bound. The wallet runs its whole policy in that simulation. The lowest bound,
/// the inclusion fee alone, is tried first: a limit that admits the operation at its final bound
/// admits it there. A policy can read the gas of a request and refuse the lowest bound alone, so
/// a refusal there is not final: the ceiling is tried next. When the wallet refuses both, the
/// first refusal is the answer. The caller then simulates the operation again with the returned
/// terms, which decides the policy and the declared fee, and prices it again when that
/// simulation needs a higher bound.
/// The expense of `terms` at the fee bound `fee`: the default repayment follows the bound less
/// the gas carry, and an explicit repayment keeps its gas. It always starts from the caller's
/// `ceiling`, so a price taken again subtracts the carry once.
/// The gas due joins the repayment as far as the wallet's gas cap `gas_cap` allows; the priced terms
/// keep that part.
fn bounded(
    terms: &ExecutionTerms,
    ceiling: &ExpenseBounds,
    fee: u32,
    gas_cap: i128,
) -> Result<(ExpenseBounds, u128)> {
    if terms.gas.is_some() {
        Ok((ceiling.with_fee_bound_only(fee)?, terms.gas_due))
    } else {
        ceiling.with_repayment(fee, terms.gas_carry, terms.gas_due, gas_cap)
    }
}
fn priced_terms(
    rpc: &dyn Rpc,
    c: &WalletConfig,
    request: &ExecutionRequest,
    terms: &ExecutionTerms,
    state: &TrustedState,
    now: u64,
    expires_at: u64,
) -> Result<ExecutionTerms> {
    let Some(ceiling) = terms.expense.as_ref().filter(|e| e.max_fee_stroops > 0) else {
        // An unpriced operation repays nothing: the server charges a gas due to the request.
        return Ok(ExecutionTerms {
            gas_due: 0,
            ..terms.clone()
        });
    };
    // The wallet's gas cap is the installed fee ceiling, which its creation set.
    let gas_cap = i128::from(c.max_fee_stroops);
    let with_bound = |fee: u32| -> Result<ExecutionTerms> {
        let (expense, gas_due) =
            bounded(terms, ceiling, fee.min(ceiling.max_fee_stroops), gas_cap)?;
        Ok(ExecutionTerms {
            args: terms.args.clone(),
            expense: Some(expense),
            gas: terms.gas.clone(),
            sender: terms.sender.clone(),
            gas_carry: terms.gas_carry,
            gas_due,
        })
    };
    let resource_fee = |fee: u32| -> Result<i64> {
        let probe =
            prepare_for_native_preflight(c, request, &with_bound(fee)?, state, now, expires_at)?;
        let resources: SorobanTransactionData = read(&simulated_resources(rpc, &probe)?)?;
        Ok(resources.resource_fee)
    };
    let simulated = match resource_fee(INCLUSION_FEE_STROOPS) {
        Ok(fee) => fee,
        Err(lowest) => resource_fee(ceiling.max_fee_stroops).map_err(|_| lowest)?,
    };
    with_bound(fee_bound(simulated)?)
}
/// Refuse a simulation that needs a separate restoration first, and accept one whose archived
/// entries the transaction restores itself: each named by its index in the read-write
/// footprint. The transaction's fee pays for that restoration. A policy wallet operation and an
/// owner transaction restore a lapsed entry, such as `t` or the instance, in this way.
pub(crate) fn restoring_in_place(value: &Value) -> Result<()> {
    if value
        .get("restorePreamble")
        .is_some_and(|value| !value.is_null())
    {
        return Err("The operation needs a separate restoration first".into());
    }
    if let Some(data) = value.get("transactionData") {
        let data: SorobanTransactionData =
            read(data.as_str().ok_or("Invalid native preflight resources")?)?;
        archived_in_footprint(&data)?;
    }
    Ok(())
}
/// Each archived entry that `data` restores is an entry of its read-write footprint, named once.
pub(crate) fn archived_in_footprint(data: &SorobanTransactionData) -> Result<()> {
    if let SorobanTransactionDataExt::V1(ext) = &data.ext {
        let writable = data.resources.footprint.read_write.len();
        let mut seen = std::collections::BTreeSet::new();
        if !ext
            .archived_soroban_entries
            .iter()
            .all(|index| (*index as usize) < writable && seen.insert(*index))
        {
            return Err("An archived entry is outside the read-write footprint".into());
        }
    }
    Ok(())
}
pub(crate) fn reject_restoration(value: &Value) -> Result<()> {
    if value
        .get("restorePreamble")
        .is_some_and(|value| !value.is_null())
    {
        return Err("Native policy preflight requires restoration".into());
    }
    if let Some(data) = value.get("transactionData") {
        let data: SorobanTransactionData =
            read(data.as_str().ok_or("Invalid native preflight resources")?)?;
        if matches!(data.ext,SorobanTransactionDataExt::V1(ref ext) if !ext.archived_soroban_entries.is_empty())
        {
            return Err("Native policy preflight includes archived entries".into());
        }
    }
    Ok(())
}
/// The sending account's last step of a policy wallet operation that the agent and the server
/// authorized: simulate it in enforce mode, where the wallet's `__check_auth` runs, set the final
/// resources and fee, and sign it as the source with `sign`. Archived entries that it touches,
/// such as a lapsed `t`, are restored in the same transaction. The wallet's authorization stays
/// valid: its payload does not cover the resources.
pub fn seal(
    rpc: &dyn Rpc,
    s: &SignedOperation,
    sign: impl FnOnce(&[u8; 32]) -> Result<[u8; 64]>,
) -> Result<SignedOperation> {
    let p = &s.prepared;
    if p.config.route != WalletRoute::PolicyWallet {
        return Err("Only a policy wallet operation is sealed by its sending account".into());
    }
    crate::validate_retained_signed(s)?;
    let TransactionEnvelope::Tx(mut env) = read(&s.transaction_xdr)? else {
        return Err("Unsupported signed envelope".into());
    };
    if !env.signatures.is_empty() {
        return Err("The operation is sealed already".into());
    }
    if rpc.call("getNetwork", json!({}))?["passphrase"] != passphrase(&p.config.network)? {
        return Err("Simulation network differs from installation".into());
    }
    let v = rpc.call(
        "simulateTransaction",
        json!({"transaction":s.transaction_xdr,"authMode":"enforce"}),
    )?;
    if v.get("error").is_some_and(|value| !value.is_null()) {
        return Err("policy wallet simulation rejected the authorized operation".into());
    }
    restoring_in_place(&v)?;
    if readonly_result(&v)? != ScVal::Void {
        return Err("Native simulation returned a value from execute".into());
    }
    let mut data: SorobanTransactionData = read(
        v["transactionData"]
            .as_str()
            .ok_or("Missing simulated resources")?,
    )?;
    let required = u32::try_from(data.resource_fee)
        .map_err(|_| "Invalid resource fee")?
        .checked_add(crate::INCLUSION_FEE_STROOPS)
        .ok_or("Resource fee overflow")?;
    let bound = p.terms.expense.as_ref().map_or(0, |e| e.max_fee_stroops);
    let declared = required.max(bound.min(p.config.max_fee_stroops));
    if declared > p.config.max_fee_stroops {
        return Err("Simulation resource fee exceeds the installed fee ceiling".into());
    }
    data.resource_fee = i64::from(declared - crate::INCLUSION_FEE_STROOPS);
    env.tx.ext = TransactionExt::V1(data);
    env.tx.fee = declared;
    let hash = crate::transaction_hash(&p.config.network, &env.tx)?;
    let MuxedAccount::Ed25519(Uint256(key)) = env.tx.source_account.clone() else {
        return Err("The sending account is a plain account".into());
    };
    let signature = sign(&hash)?;
    signing::verify_digest(&crate::account_for_public_key(&key), &hash, &signature)?;
    env.signatures = vec![DecoratedSignature {
        hint: SignatureHint(key[28..].try_into().map_err(err)?),
        signature: stellar_xdr::Signature(signature.to_vec().try_into().map_err(err)?),
    }]
    .try_into()
    .map_err(err)?;
    let sealed = SignedOperation {
        prepared: p.clone(),
        transaction_xdr: xdr(&TransactionEnvelope::Tx(env))?,
        transaction_hash: hash,
        role_signatures: Vec::new(),
    };
    crate::validate_retained_signed(&sealed)?;
    Ok(sealed)
}
/// Simulate an original unsigned policy wallet intent and bind successful native validation to it.
/// Supplied resource XDR or JSON booleans alone never create a signing approval.
pub fn simulate(rpc: &dyn Rpc, p: &PreparedOperation) -> Result<PreparedOperation> {
    let encoded = simulated_resources(rpc, p)?;
    let mut prepared = attach_simulation(p, &encoded)?;
    record_native_preflight(&mut prepared)?;
    Ok(prepared)
}
/// Simulate the unchanged intent and return the checked resource requirements as XDR.
/// This does not build a replacement transaction, so it does not check source quorum against a
/// rebuilt hash. `simulate` attaches the result; revalidation compares it with the original.
fn simulated_resources(rpc: &dyn Rpc, p: &PreparedOperation) -> Result<String> {
    validate_retained_prepared(p)?;
    if p.config.route != WalletRoute::PolicyWallet {
        return Err("Native contract simulation requires policy wallet custody".into());
    }
    if rpc.call("getNetwork", json!({}))?["passphrase"] != passphrase(&p.config.network)? {
        return Err("Simulation network differs from installation".into());
    }
    // Stellar RPC rejects recording mode when the transaction already has auth entries.
    // An intent without both signatures is therefore recorded from a copy without them; the
    // recorded scope is compared with the intent's entries below. The wallet's `__check_auth`
    // runs only in enforce mode, so only an entry that the agent and the server both signed is
    // simulated as is; that run gives the final resources, including the wallet's nonce key.
    let (agent, server) = authorization::cosignatures(p)?;
    let recording = agent.is_none() || server.is_none();
    let (transaction, mode) = if recording {
        let TransactionEnvelope::Tx(mut env) = read(&p.transaction_xdr)? else {
            return Err("Unsupported preflight envelope".into());
        };
        let mut operations = env.tx.operations.to_vec();
        let OperationBody::InvokeHostFunction(op) = &mut operations[0].body else {
            return Err("Expected one native policy invocation".into());
        };
        op.auth = VecM::default();
        env.tx.operations = operations.try_into().map_err(err)?;
        (xdr(&TransactionEnvelope::Tx(env))?, "record")
    } else {
        (p.transaction_xdr.clone(), "enforce")
    };
    let v = rpc.call(
        "simulateTransaction",
        json!({"transaction":transaction,"authMode":mode}),
    )?;
    if v.get("error").is_some_and(|value| !value.is_null()) {
        return Err("policy wallet simulation rejected the exact policy operation".into());
    }
    restoring_in_place(&v)?;
    if readonly_result(&v)? != ScVal::Void {
        return Err("Native simulation returned a value from execute".into());
    }
    let TransactionEnvelope::Tx(env) = read(&p.transaction_xdr)? else {
        return Err("Unsupported preflight envelope".into());
    };
    let OperationBody::InvokeHostFunction(op) = &env.tx.operations[0].body else {
        return Err("Expected one native policy invocation".into());
    };
    let observed = v["results"][0]["auth"]
        .as_array()
        .ok_or("Missing native preflight authorization scope")?;
    let auth = observed
        .iter()
        .map(|entry| {
            read(
                entry
                    .as_str()
                    .ok_or("Invalid native preflight authorization")?,
            )
        })
        .collect::<Result<Vec<SorobanAuthorizationEntry>>>()?;
    let same = if recording {
        auth.len() == op.auth.len()
            && auth.iter().zip(op.auth.iter()).all(|(actual, expected)| {
                actual.root_invocation == expected.root_invocation
                    && match (&actual.credentials, &expected.credentials) {
                        (SorobanCredentials::SourceAccount, SorobanCredentials::SourceAccount) => {
                            true
                        }
                        (SorobanCredentials::Address(a), SorobanCredentials::Address(b)) => {
                            a.address == b.address
                        }
                        _ => false,
                    }
            })
    } else {
        auth.as_slice() == op.auth.as_slice()
    };
    if !same {
        return Err("Native preflight authorization differs from the exact intent".into());
    }
    let encoded = v["transactionData"]
        .as_str()
        .ok_or("Missing Soroban resource simulation")?;
    let resources: SorobanTransactionData = read(encoded)?;
    let minimum = v["minResourceFee"]
        .as_str()
        .ok_or("Missing native preflight minimum fee")?
        .parse::<u64>()
        .map_err(err)?;
    if resources.resource_fee < 0 || minimum > resources.resource_fee as u64 {
        return Err("Native preflight fee is below its minimum".into());
    }
    Ok(encoded.into())
}
/// Revalidate an existing unsigned gateway intent through a locally trusted native RPC.
/// The original transaction, hash and operation identity remain unchanged. Current authority,
/// policy configuration and nonce must match the intent; its existing resources must cover
/// fresh simulation. Only the private in-memory signing marker is added. Nothing is submitted.
pub fn revalidate_prepared(
    rpc: &dyn Rpc,
    p: &PreparedOperation,
    now: u64,
) -> Result<PreparedOperation> {
    validate_retained_prepared(p)?;
    if p.config.route != WalletRoute::PolicyWallet
        || p.state.contract_version != Some(CONTRACT_VERSION)
        || p.created_at > now
        || now >= p.expires_at
    {
        return Err(
            "Current unexpired policy wallet intent is required for native revalidation".into(),
        );
    }
    authorization::server_signature(p, true)?;
    // The server's accounting of the figures that the wallet does not keep is the one that the
    // preparation retained; the ledger gives the rest.
    let accounting = (crate::kept_figures(&p.config) != packed::ALL).then_some(NativeAccounting {
        nonce: p.state.nonce,
        deployment_version: p.state.deployment_version,
        spent_daily: p.state.spent_daily,
        spent_total: p.state.spent_total,
        spent_day: p.state.spent_day,
        volume_daily: p.state.volume_daily,
        unpriced_total: p.state.unpriced_total,
        unpriced_daily: p.state.unpriced_daily,
        calls: p.state.calls,
    });
    let mut current = trusted_state(rpc, &p.config, accounting)?;
    current.source = get_account(rpc, &crate::gas_payee(&p.request, &p.terms)?)?;
    // Observation ledgers can advance without changing the transaction's authority or state.
    current.ledger = p.state.ledger;
    if current != p.state {
        return Err("Current native state differs from the existing prepared intent".into());
    }
    let original: SorobanTransactionData = read(
        p.simulation_data
            .as_deref()
            .ok_or("Existing intent has no bounded Soroban resources")?,
    )?;
    archived_in_footprint(&original)?;
    let mut keys = std::collections::BTreeSet::new();
    if !original
        .resources
        .footprint
        .read_only
        .iter()
        .chain(original.resources.footprint.read_write.iter())
        .all(|key| keys.insert(key))
    {
        return Err("Existing resource footprint has duplicate or overlapping keys".into());
    }
    // Fresh requirements can be smaller than the existing resources. Attaching them would change
    // the hash, and an exact-hash preauthorization of the source would no longer match. Compare
    // the requirements only; `validate_prepared` below checks quorum on the unchanged original.
    let required: SorobanTransactionData = read(&simulated_resources(rpc, p)?)?;
    let have = &original.resources;
    let need = &required.resources;
    let footprint_covers = footprint_covers(&p.config.wallet, &have.footprint, &need.footprint)?;
    if !footprint_covers
        || have.instructions < need.instructions
        || have.disk_read_bytes < need.disk_read_bytes
        || have.write_bytes < need.write_bytes
        || declared_resource_fee(p)? < required.resource_fee
    {
        return Err("Existing transaction resources do not cover native revalidation".into());
    }
    let mut validated = p.clone();
    record_native_preflight(&mut validated)?;
    validate_prepared(&validated, now)?;
    Ok(validated)
}
/// Whether the footprint `have` covers `need`: every key that `need` writes, `have` writes, and
/// every key that `need` reads, `have` reads or writes. A recording simulation draws its own nonce
/// for the authorization of `wallet`, so two recordings name different nonce entries of the
/// wallet; the sending account's sealing run sets the exact one. That key alone is not compared.
fn footprint_covers(wallet: &str, have: &LedgerFootprint, need: &LedgerFootprint) -> Result<bool> {
    let wallet = address(wallet)?;
    let nonce = |key: &&LedgerKey| {
        matches!(key, LedgerKey::ContractData(d)
            if d.contract == wallet && matches!(d.key, ScVal::LedgerKeyNonce(_)))
    };
    Ok(need
        .read_write
        .iter()
        .filter(|key| !nonce(key))
        .all(|key| have.read_write.contains(key))
        && need
            .read_only
            .iter()
            .filter(|key| !nonce(key))
            .all(|key| have.read_only.contains(key) || have.read_write.contains(key)))
}
/// The resource fee that the prepared transaction declares. It is the signed bound less the
/// inclusion fee, so it stays above the simulated resource fee by the margin of the bound.
fn declared_resource_fee(p: &PreparedOperation) -> Result<i64> {
    let TransactionEnvelope::Tx(envelope) = read(&p.transaction_xdr)? else {
        return Err("Unsupported transaction envelope".into());
    };
    let TransactionExt::V1(data) = &envelope.tx.ext else {
        return Err("Existing intent declares no Soroban resources".into());
    };
    Ok(data.resource_fee)
}
/// Native outcome of one `sendTransaction` attempt. Persistence and retry policy belong to SDK engine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Broadcast {
    Submitted,
    RetryLater,
    Rejected { error_result_xdr: Option<String> },
    Unknown,
}
/// Validate a new signed operation and send its exact bytes once.
pub fn broadcast(rpc: &dyn Rpc, signed: &SignedOperation, now: u64) -> Result<Broadcast> {
    if signed.prepared.payment_authorization.is_some() {
        return Err("The payer never sends a payment authorization: the seller settles it".into());
    }
    validate_signed(signed, now)?;
    send_transaction(
        rpc,
        &signed.prepared.config.network,
        &signed.transaction_xdr,
    )
}
/// Hash a signed native transaction without rebuilding or authorizing it.
pub fn signed_transaction_hash(network: &str, envelope_xdr: &str) -> Result<[u8; 32]> {
    let TransactionEnvelope::Tx(envelope) = read(envelope_xdr)? else {
        return Err("Expected a signed v1 transaction".into());
    };
    // Exact-hash PreAuthTx quorum can legitimately need zero envelope signatures.
    // This helper establishes transaction identity. The caller validates authority.
    transaction_hash_for(network, &envelope.tx)
}
/// Send an already signed native envelope once and decode only the native response.
/// The caller validates owner/agent authority before passing bytes to this transport operation.
pub fn send_transaction(rpc: &dyn Rpc, network: &str, envelope_xdr: &str) -> Result<Broadcast> {
    let expected = hex(&signed_transaction_hash(network, envelope_xdr)?);
    let value = match rpc.call("sendTransaction", json!({"transaction":envelope_xdr})) {
        Ok(value) => value,
        Err(_) => return Ok(Broadcast::Unknown),
    };
    if value["hash"].as_str() != Some(expected.as_str()) {
        return Ok(Broadcast::Unknown);
    }
    Ok(match value["status"].as_str() {
        Some("PENDING" | "DUPLICATE") => Broadcast::Submitted,
        Some("TRY_AGAIN_LATER") => Broadcast::RetryLater,
        Some("ERROR") => Broadcast::Rejected {
            error_result_xdr: value["errorResultXdr"].as_str().map(String::from),
        },
        _ => Broadcast::Unknown,
    })
}
pub fn status_by_hash(
    rpc: &dyn Rpc,
    network: &str,
    transaction_hash: &[u8; 32],
) -> Result<OperationStatus> {
    let v = rpc.call("getTransaction", json!({"hash":hex(transaction_hash)}))?;
    verify_settlement(&v, network, transaction_hash)
}
/// Whether the owner transaction with hash `hash` lapsed: it never applied and can no longer
/// apply. The server prepared it at ledger `since`, with the time bound `expires_at`. The proof
/// is one `getTransaction` reply: no record of the hash, a searched history that holds `since`,
/// and a ledger that closed after the time bound. `false` means not proven.
pub fn owner_transaction_lapsed(
    rpc: &dyn Rpc,
    hash: &[u8; 32],
    expires_at: u64,
    since: u64,
) -> Result<bool> {
    let reply = rpc.call("getTransaction", json!({ "hash": hex(hash) }))?;
    Ok(owner_never_applied(&reply, &hex(hash), expires_at, since))
}
/// Whether a `getTransaction` reply proves that the transaction with this hash never applied and
/// can no longer apply: see [`owner_transaction_lapsed`].
fn owner_never_applied(reply: &Value, hash: &str, expires_at: u64, since: u64) -> bool {
    let number = |key: &str| {
        reply[key]
            .as_u64()
            .or_else(|| reply[key].as_str()?.parse().ok())
    };
    // The searched history is ledgers `oldest..=latest`, and it must contain `since`.
    let covered = matches!(
        (number("oldestLedger"), number("latestLedger")),
        (Some(oldest), Some(latest)) if 0 < oldest && oldest <= since && since <= latest
    );
    covered
        && reply["status"] == "NOT_FOUND"
        && (reply["txHash"].is_null() || reply["txHash"] == hash)
        && number("latestLedgerCloseTime").is_some_and(|closed| closed > expires_at)
}
/// Whether the policy wallet operation `p` lapsed without executing. Every preparation of the
/// operation carries the same nonce in the wallet's authorization. When the ledger runs one, the
/// host keeps that nonce in a temporary entry of the wallet, and the entry lives at least the
/// network's minimum temporary lifetime from the ledger that ran it, which is no earlier than
/// `WALLET_AUTH_LEDGERS` before the authorization's expiration ledger. The operation lapsed when
/// a ledger closed at or after its `expires_at`, the ledger is past that expiration ledger (no
/// submission of this authorization can run), and inside the lifetime that a spent nonce is sure
/// to have, the wallet holds no such nonce. `false` means not proven: before the expiration
/// ledger, after that lifetime, or when the RPC does not show it.
pub fn operation_lapsed(rpc: &dyn Rpc, p: &PreparedOperation) -> Result<bool> {
    if p.config.route != WalletRoute::PolicyWallet {
        return Ok(false);
    }
    let reply = rpc.call("getTransaction", json!({"hash":hex(&p.transaction_hash)}))?;
    let closed = reply["latestLedgerCloseTime"]
        .as_u64()
        .or_else(|| reply["latestLedgerCloseTime"].as_str()?.parse().ok());
    if reply["status"].as_str() == Some("SUCCESS") || closed.is_none_or(|t| t < p.expires_at) {
        return Ok(false);
    }
    let entry = authorization::wallet_authorization(p)?;
    let SorobanCredentials::Address(credentials) = &entry.credentials else {
        return Ok(false);
    };
    let expiration = u64::from(credentials.signature_expiration_ledger);
    let nonce = LedgerKey::ContractData(LedgerKeyContractData {
        contract: address(&p.config.wallet)?,
        key: ScVal::LedgerKeyNonce(ScNonceKey {
            nonce: credentials.nonce,
        }),
        durability: ContractDataDurability::Temporary,
    });
    let archival = LedgerKey::ConfigSetting(LedgerKeyConfigSetting {
        config_setting_id: ConfigSettingId::StateArchival,
    });
    let entries = rpc.call(
        "getLedgerEntries",
        json!({"keys":[xdr(&nonce)?, xdr(&archival)?]}),
    )?;
    let Some(observed) = entries["latestLedger"].as_u64() else {
        return Ok(false);
    };
    let mut lifetime = None;
    for item in entries["entries"]
        .as_array()
        .ok_or("Missing ledger entries")?
    {
        match read::<LedgerEntryData>(item["xdr"].as_str().ok_or("Missing entry XDR")?)? {
            LedgerEntryData::ConfigSetting(ConfigSettingEntry::StateArchival(settings)) => {
                lifetime = Some(u64::from(settings.min_temporary_ttl));
            }
            // The wallet's nonce entry: the ledger ran the operation.
            _ => return Ok(false),
        }
    }
    let Some(lifetime) = lifetime else {
        return Ok(false);
    };
    // A nonce spent at any ledger that this authorization could run in is live through here.
    let live_through =
        (expiration + lifetime).saturating_sub(u64::from(authorization::WALLET_AUTH_LEDGERS) + 1);
    Ok(observed > expiration && observed <= live_through)
}
/// The settlement of the policy wallet operation `p`, found by the wallet's `allowit` event of
/// its operation id. The settled transaction is the sealed one, so its hash is not the prepared
/// hash: the event names it. The read starts at the ledger of the preparation. `None` when the
/// endpoint holds no such event, or no successful transaction of `p` carries it.
pub fn policy_wallet_settlement(
    rpc: &dyn Rpc,
    p: &PreparedOperation,
) -> Result<Option<(SignedOperation, VerifiedReceipt)>> {
    if p.config.route != WalletRoute::PolicyWallet || p.payment_authorization.is_some() {
        return Err("Only a policy wallet operation settles with its own event".into());
    }
    let topics = [
        xdr(&value_symbol("allowit")?)?,
        xdr(&value_bytes(&p.request.operation.nonce)?)?,
    ];
    let reply = rpc.call(
        "getEvents",
        json!({
            "startLedger": p.state.ledger,
            "filters": [{"type": "contract", "contractIds": [p.config.wallet], "topics": [topics]}],
            "pagination": {"limit": 10},
        }),
    )?;
    for event in reply["events"].as_array().ok_or("Missing ledger events")? {
        let hash = unhex::<32>(
            event["txHash"]
                .as_str()
                .ok_or("Invalid event transaction")?,
        )?;
        let Some(receipt) = receipt_by_hash(rpc, &p.config.network, &hash)? else {
            continue;
        };
        let signed = SignedOperation {
            prepared: p.clone(),
            transaction_xdr: receipt.envelope_xdr.clone(),
            transaction_hash: receipt.transaction_hash,
            role_signatures: Vec::new(),
        };
        if validate_settled_policy_packet(&signed, &receipt).is_ok() {
            return Ok(Some((signed, receipt)));
        }
    }
    Ok(None)
}
/// Verify a terminal CAP-15 wrapper before retaining the original inner transaction.
/// This accepts settlement evidence only; owner intent signing still rejects fee-bump envelopes.
fn settlement_reply<'a>(
    v: &'a Value,
    network: &str,
    expected: &[u8; 32],
) -> Result<std::borrow::Cow<'a, Value>> {
    if !matches!(v["status"].as_str(), Some("SUCCESS" | "FAILED")) {
        return Ok(std::borrow::Cow::Borrowed(v));
    }
    let envelope: TransactionEnvelope = read(
        v["envelopeXdr"]
            .as_str()
            .ok_or("Settlement envelope is required")?,
    )?;
    let TransactionEnvelope::TxFeeBump(outer) = envelope else {
        return Ok(std::borrow::Cow::Borrowed(v));
    };
    let FeeBumpTransactionInnerTx::Tx(inner) = &outer.tx.inner_tx;
    if transaction_hash_for(network, &inner.tx)? != *expected {
        return Err("Fee-bump inner transaction identity differs".into());
    }
    let payload = TransactionSignaturePayload {
        network_id: Hash(network_id(network)?),
        tagged_transaction: TransactionSignaturePayloadTaggedTransaction::TxFeeBump(
            outer.tx.clone(),
        ),
    };
    let outer_hash = hash(payload.to_xdr(limits()).map_err(err)?);
    // RPC versions may echo the requested inner hash or identify the outer wrapper.
    // Neither spelling may identify an unrelated transaction.
    let asserted_hash = if v["txHash"].as_str() == Some(hex(expected).as_str()) {
        expected
    } else {
        &outer_hash
    };
    validate_response_identity(v, asserted_hash)?;
    let result: TransactionResult = read(
        v["resultXdr"]
            .as_str()
            .ok_or("Settlement result is required")?,
    )?;
    let (pair, success) = match result.result {
        TransactionResultResult::TxFeeBumpInnerSuccess(pair) => (pair, true),
        TransactionResultResult::TxFeeBumpInnerFailed(pair) => (pair, false),
        _ => return Err("Fee-bump settlement requires its inner result".into()),
    };
    if pair.transaction_hash.0 != *expected
        || matches!(
            pair.result.result,
            InnerTransactionResultResult::TxSuccess(_)
        ) != success
        || (v["status"] == "SUCCESS") != success
        || pair.result.fee_charged != 0
    {
        return Err("Fee-bump result identity or status differs".into());
    }
    // InnerTransactionResult has the same wire shape as a non-fee-bump TransactionResult.
    let inner_result: TransactionResult = read(&xdr(&pair.result)?)?;
    let mut normalized = v.clone();
    normalized["txHash"] = json!(hex(expected));
    normalized["envelopeXdr"] = json!(xdr(&TransactionEnvelope::Tx(inner.clone()))?);
    normalized["resultXdr"] = json!(xdr(&inner_result)?);
    Ok(std::borrow::Cow::Owned(normalized))
}
fn verify_settlement(
    v: &Value,
    network: &str,
    transaction_hash: &[u8; 32],
) -> Result<OperationStatus> {
    let normalized = settlement_reply(v, network, transaction_hash)?;
    let v = normalized.as_ref();
    validate_response_identity(v, transaction_hash)?;
    if matches!(v["status"].as_str(), Some("SUCCESS" | "FAILED")) {
        let envelope: TransactionEnvelope = read(
            v["envelopeXdr"]
                .as_str()
                .ok_or("Settlement envelope is required")?,
        )?;
        let TransactionEnvelope::Tx(envelope) = envelope else {
            return Err("Unexpected settlement envelope".into());
        };
        if &transaction_hash_for(network, &envelope.tx)? != transaction_hash {
            return Err("Settlement transaction identity differs".into());
        }
        let result: TransactionResult = read(
            v["resultXdr"]
                .as_str()
                .ok_or("Settlement result is required")?,
        )?;
        if v["status"] == "SUCCESS"
            && !matches!(result.result, TransactionResultResult::TxSuccess(_))
        {
            return Err("Settlement success and result differ".into());
        }
        if v["status"] == "FAILED" && matches!(result.result, TransactionResultResult::TxSuccess(_))
        {
            return Err("Settlement failure and result differ".into());
        }
    }
    Ok(match v["status"].as_str() {
        Some("SUCCESS") => OperationStatus::Confirmed,
        Some("FAILED") => OperationStatus::Failed,
        Some("NOT_FOUND") => OperationStatus::SubmissionUnknown,
        _ => return Err("Unknown Stellar settlement state".into()),
    })
}
// Retained receipts can lack RPC range metadata. Every supplied native field must still agree.
fn validate_response_identity(v: &Value, expected_hash: &[u8; 32]) -> Result<()> {
    if let Some(value) = v.get("txHash")
        && unhex::<32>(value.as_str().ok_or("Invalid response transaction hash")?)?
            != *expected_hash
    {
        return Err("Response transaction hash differs from the original".into());
    }
    let ledger = |name: &str| -> Result<Option<u32>> {
        v.get(name)
            .map(|value| {
                value
                    .as_u64()
                    .and_then(|n| u32::try_from(n).ok())
                    .filter(|n| *n > 0)
                    .ok_or_else(|| "Invalid native response ledger".into())
            })
            .transpose()
    };
    let (oldest, latest) = (ledger("oldestLedger")?, ledger("latestLedger")?);
    // A current RPC reports zero as the unset settlement ledger for NOT_FOUND.
    let settled = if v["status"] == "NOT_FOUND" && v["ledger"].as_u64() == Some(0) {
        None
    } else {
        ledger("ledger")?
    };
    if let (Some(oldest), Some(latest)) = (oldest, latest)
        && (oldest > latest || settled.is_some_and(|n| n < oldest || n > latest))
    {
        return Err("Settlement ledger is outside the native response history".into());
    }
    if oldest.is_some() != latest.is_some() {
        return Err("Incomplete native response history interval".into());
    }
    Ok(())
}
/// A chain result bound to the requested network and exact transaction bytes.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerifiedReceipt {
    pub transaction_hash: [u8; 32],
    pub status: OperationStatus,
    pub ledger: u32,
    pub envelope_xdr: String,
    pub result_xdr: String,
    /// Set when this transaction, which another party submitted, settles a payment
    /// authorization: the transaction hash of the operation that prepared it. See
    /// [`crate::seller_settled`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settles: Option<[u8; 32]>,
}
/// Recheck a retained receipt before projecting it through another interface.
pub fn validate_receipt(
    receipt: &VerifiedReceipt,
    network: &str,
    expected_hash: &[u8; 32],
) -> Result<()> {
    if receipt.transaction_hash != *expected_hash
        || receipt.ledger == 0
        || !matches!(
            receipt.status,
            OperationStatus::Confirmed | OperationStatus::Failed
        )
    {
        return Err("Invalid retained Stellar receipt identity".into());
    }
    let value = json!({"status":if receipt.status==OperationStatus::Confirmed {"SUCCESS"} else {"FAILED"},"envelopeXdr":receipt.envelope_xdr,"resultXdr":receipt.result_xdr});
    if verify_settlement(&value, network, expected_hash)? != receipt.status {
        return Err("Retained Stellar receipt result differs".into());
    }
    Ok(())
}
/// Check the receipt of an operation that its own transaction settled. Only the receipt of a
/// payment authorization names what it settles: the mark on any other receipt is refused, so
/// it cannot change how the receipt is read.
pub fn validate_own_receipt(
    receipt: &VerifiedReceipt,
    network: &str,
    expected_hash: &[u8; 32],
) -> Result<()> {
    if receipt.settles.is_some() {
        return Err("The receipt settles a payment authorization, not this operation".into());
    }
    validate_receipt(receipt, network, expected_hash)
}
/// Verify an exact policy-wallet envelope using its chain receipt after key rotation.
/// This checks native identity and the retained server authorization, without current signing admission.
/// A failed enclosing transaction does not revoke its reusable address authorization.
pub fn validate_settled_policy_packet(
    signed: &SignedOperation,
    receipt: &VerifiedReceipt,
) -> Result<()> {
    if signed.prepared.payment_authorization.is_some() {
        return crate::seller_settled::validate_settled(signed, receipt);
    }
    if receipt.settles.is_some() {
        return Err("The receipt settles a payment authorization, not this operation".into());
    }
    let prepared = &signed.prepared;
    if prepared.config.route != WalletRoute::PolicyWallet {
        return Err("Chain-only recovery requires a policy wallet packet".into());
    }
    // The settled transaction is the sealed one: the prepared transaction with both
    // cosignatures, its final resources and the sending account's signature.
    let TransactionEnvelope::Tx(envelope) = read(&signed.transaction_xdr)? else {
        return Err("Unsupported settled envelope".into());
    };
    if envelope.signatures.len() != 1 {
        return Err("The packet is unsigned by its sending account".into());
    }
    crate::validate_retained_signed(signed)?;
    validate_receipt(receipt, &prepared.config.network, &signed.transaction_hash)?;
    if signed.transaction_xdr != receipt.envelope_xdr {
        return Err("The settlement envelope differs from the verified receipt".into());
    }
    Ok(())
}

/// The positional request of the `execute` invocation of a confirmed transaction: `None` for a
/// failed transaction, which counts and repays nothing, and for a transaction that invokes no
/// policy wallet.
fn executed_request(receipt: &VerifiedReceipt) -> Result<Option<Vec<ScVal>>> {
    if receipt.status != OperationStatus::Confirmed {
        return Ok(None);
    }
    let TransactionEnvelope::Tx(envelope) = read(&receipt.envelope_xdr)? else {
        return Ok(None);
    };
    let Some(OperationBody::InvokeHostFunction(op)) =
        envelope.tx.operations.first().map(|op| &op.body)
    else {
        return Ok(None);
    };
    let HostFunction::InvokeContract(call) = &op.host_function else {
        return Ok(None);
    };
    match call
        .args
        .first()
        .filter(|_| call.function_name.0.as_slice() == b"execute")
    {
        Some(ScVal::Vec(Some(request))) => Ok(Some(request.to_vec())),
        _ => Ok(None),
    }
}
/// The gas units that the wallet contract counted against its limits for the transaction of
/// `receipt`: the `gas_units` of the expense that its `execute` invocation carries. Zero for a
/// failed transaction, which counts nothing, for an unpriced request and for a transaction that
/// invokes no policy wallet.
pub fn counted_gas_units(receipt: &VerifiedReceipt) -> Result<i128> {
    let Some(request) = executed_request(receipt)? else {
        return Ok(0);
    };
    // The positional request: its expense is field 4, `Priced(gas, conversion, spent, observed)`.
    match request.get(4) {
        Some(ScVal::Vec(Some(variant))) if variant.len() == 5 => wide(&variant[1]),
        _ => Ok(0),
    }
}
/// The stroops that the wallet repaid to the sending account for the network fee in the
/// transaction of `receipt`: field 5 of its `execute` request. Zero for a failed transaction,
/// which repays nothing, and for a transaction that invokes no policy wallet.
pub fn repaid_gas_stroops(receipt: &VerifiedReceipt) -> Result<u128> {
    let Some(request) = executed_request(receipt)? else {
        return Ok(0);
    };
    match request.get(5) {
        Some(value) => u128::try_from(wide(value)?).map_err(|_| "A negative gas repayment".into()),
        None => Err("The execute request has no gas repayment".into()),
    }
}
/// Read a verified terminal receipt. Absence remains unknown and does not release reservations.
pub fn receipt_by_hash(
    rpc: &dyn Rpc,
    network: &str,
    transaction_hash: &[u8; 32],
) -> Result<Option<VerifiedReceipt>> {
    let v = rpc.call("getTransaction", json!({"hash":hex(transaction_hash)}))?;
    receipt_from_response(&v, network, transaction_hash)
}
/// Read the verified terminal receipt of the transaction that the ledger reports under `reported`,
/// as an event does: the transaction itself, or the fee bump that carries it. A fee bump is
/// verified as a wrapper, and the receipt is that of its inner transaction, under the inner
/// hash. Absence remains unknown.
pub fn receipt_by_reported_hash(
    rpc: &dyn Rpc,
    network: &str,
    reported: &[u8; 32],
) -> Result<Option<VerifiedReceipt>> {
    let v = rpc.call("getTransaction", json!({"hash":hex(reported)}))?;
    let envelope = v["envelopeXdr"]
        .as_str()
        .map(read::<TransactionEnvelope>)
        .transpose()?;
    let Some(TransactionEnvelope::TxFeeBump(outer)) = envelope else {
        return receipt_from_response(&v, network, reported);
    };
    let payload = TransactionSignaturePayload {
        network_id: Hash(network_id(network)?),
        tagged_transaction: TransactionSignaturePayloadTaggedTransaction::TxFeeBump(
            outer.tx.clone(),
        ),
    };
    // The wrapper is the transaction that the ledger reported, and no other.
    if hash(payload.to_xdr(limits()).map_err(err)?) != *reported {
        return Err("The reported transaction differs from its fee bump".into());
    }
    let FeeBumpTransactionInnerTx::Tx(inner) = &outer.tx.inner_tx;
    receipt_from_response(&v, network, &transaction_hash_for(network, &inner.tx)?)
}
fn receipt_from_response(
    v: &Value,
    network: &str,
    transaction_hash: &[u8; 32],
) -> Result<Option<VerifiedReceipt>> {
    let normalized = settlement_reply(v, network, transaction_hash)?;
    let v = normalized.as_ref();
    let status = verify_settlement(v, network, transaction_hash)?;
    if !matches!(status, OperationStatus::Confirmed | OperationStatus::Failed) {
        return Ok(None);
    }
    let ledger = v["ledger"]
        .as_u64()
        .and_then(|v| u32::try_from(v).ok())
        .filter(|v| *v > 0)
        .ok_or("Settlement ledger is required")?;
    Ok(Some(VerifiedReceipt {
        transaction_hash: *transaction_hash,
        status,
        ledger,
        envelope_xdr: v["envelopeXdr"]
            .as_str()
            .ok_or("Settlement envelope is required")?
            .into(),
        result_xdr: v["resultXdr"]
            .as_str()
            .ok_or("Settlement result is required")?
            .into(),
        settles: None,
    }))
}
/// The server's account of a wallet's standard figures: Core's `vendor::runtime::Accounting`.
/// A policy wallet reads the figures that it keeps from the ledger and these for the others.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeAccounting {
    pub nonce: u64,
    #[serde(alias = "revision")]
    pub deployment_version: u64,
    pub spent_daily: i128,
    pub spent_total: i128,
    pub spent_day: u64,
    /// Gross amounts plus separate attributable gas on `spent_day` (`day_total`).
    #[serde(default, skip_serializing_if = "crate::no_amount")]
    pub volume_daily: i128,
    /// An operation lacked price facts in the wallet's lifetime (`unpriced`).
    #[serde(default, skip_serializing_if = "crate::is_false")]
    pub unpriced_total: bool,
    /// An operation on `spent_day` lacked price facts (`day_unpriced`).
    #[serde(default, skip_serializing_if = "crate::is_false")]
    pub unpriced_daily: bool,
    pub calls: u64,
}
pub(crate) fn map_field<'a>(value: &'a ScVal, name: &str) -> Result<&'a ScVal> {
    let ScVal::Map(Some(map)) = value else {
        return Err("Expected contract record".into());
    };
    map.iter()
        .find(|e| matches!(&e.key,ScVal::Symbol(key) if key.0.as_slice()==name.as_bytes()))
        .map(|e| &e.val)
        .ok_or_else(|| format!("Missing contract field {name}"))
}
pub(crate) fn number(value: &ScVal) -> Result<u64> {
    match value {
        ScVal::U32(v) => Ok((*v).into()),
        ScVal::U64(v) => Ok(*v),
        _ => Err("Expected contract unsigned integer".into()),
    }
}
pub(crate) fn wide(value: &ScVal) -> Result<i128> {
    match value {
        ScVal::I128(v) => Ok((i128::from(v.hi) << 64) | i128::from(v.lo)),
        _ => Err("Expected native i128 amount".into()),
    }
}
pub(crate) fn digest_field(value: &ScVal) -> Result<[u8; 32]> {
    match value {
        ScVal::Bytes(v) => {
            v.0.as_slice()
                .try_into()
                .map_err(|_| "Expected bytes32".into())
        }
        _ => Err("Expected bytes32".into()),
    }
}
pub(crate) fn addr(value: &ScVal) -> Result<String> {
    match value {
        ScVal::Address(a) => address_text(a),
        _ => Err("Expected native contract address".into()),
    }
}
pub(crate) fn readonly_call(
    rpc: &dyn Rpc,
    c: &WalletConfig,
    source: &AccountState,
    function: &str,
) -> Result<ScVal> {
    let value = readonly_simulation(rpc, c, source, &c.wallet, function, vec![])?;
    readonly_result(&value)
}
pub(crate) fn readonly_simulation(
    rpc: &dyn Rpc,
    c: &WalletConfig,
    source: &AccountState,
    contract: &str,
    function: &str,
    args: Vec<ScVal>,
) -> Result<Value> {
    validate_config(c)?;
    source.validate_structure()?;
    let call = InvokeContractArgs {
        contract_address: address(contract)?,
        function_name: ScSymbol(function.as_bytes().to_vec().try_into().map_err(err)?),
        args: args.try_into().map_err(err)?,
    };
    let tx = Transaction {
        source_account: muxed(&source.address)?,
        fee: 100,
        seq_num: SequenceNumber(source.sequence.checked_add(1).ok_or("Sequence overflow")?),
        cond: Preconditions::None,
        memo: Memo::None,
        operations: vec![Operation {
            source_account: None,
            body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                host_function: HostFunction::InvokeContract(call),
                auth: VecM::default(),
            }),
        }]
        .try_into()
        .map_err(err)?,
        ext: TransactionExt::V0,
    };
    let value=rpc.call("simulateTransaction",json!({"transaction":xdr(&TransactionEnvelope::Tx(TransactionV1Envelope{tx,signatures:VecM::default()}))?}))?;
    Ok(value)
}
pub(crate) fn readonly_result(value: &Value) -> Result<ScVal> {
    if value.get("error").is_some_and(|value| !value.is_null()) {
        return Err("Contract binding simulation failed".into());
    }
    let results = value["results"]
        .as_array()
        .ok_or("Missing binding result")?;
    if results.len() != 1 {
        return Err("Unexpected binding result count".into());
    }
    read(results[0]["xdr"].as_str().ok_or("Missing binding XDR")?)
}
/// Read an explicitly selected shared checker's executable release metadata without authorizing a call.
/// `None` requires a host diagnostic that the selected engine has no `engine_version` export.
/// Transport failures, unavailable diagnostics and malformed metadata are errors. This query
/// does not attest engine health or code identity and is never required by owner operations.
/// `rpc` must serve the configured network; `checker` selects a contract distinct from the service signer.
/// `source` supplies the native simulation account; this function does not load keys or sign.
pub fn checker_version(
    rpc: &dyn Rpc,
    c: &WalletConfig,
    source: &AccountState,
    checker: &str,
) -> Result<Option<u32>> {
    validate_config(c)?;
    Contract::from_string(checker).map_err(err)?;
    if rpc.call("getNetwork", json!({}))?["passphrase"] != passphrase(&c.network)? {
        return Err("Stellar RPC network differs from installation".into());
    }
    let value = readonly_simulation(rpc, c, source, checker, "engine_version", vec![])?;
    if let Some(error) = value.get("error") {
        if !error
            .as_str()
            .is_some_and(|v| v.contains("Error(WasmVm, MissingValue)"))
        {
            return Err("Engine version simulation failed".into());
        }
        let ScAddress::Contract(engine) = address(checker)? else {
            return Err("Engine is not a contract".into());
        };
        let events = value["events"]
            .as_array()
            .ok_or("Missing engine version diagnostics")?;
        let mut absent = false;
        for encoded in events {
            let event: DiagnosticEvent =
                read(encoded.as_str().ok_or("Invalid engine diagnostic XDR")?)?;
            let ContractEventBody::V0(body) = &event.event.body;
            if !event.in_successful_contract_call
                && event.event.type_ == ContractEventType::Diagnostic
                && event.event.contract_id.as_ref() == Some(&engine)
                && body.topics.as_slice()
                    == [
                        value_symbol("error")?,
                        ScVal::Error(ScError::WasmVm(ScErrorCode::MissingValue)),
                    ]
                && matches!(&body.data, ScVal::Vec(Some(args)) if args.len() == 2
                    && matches!(&args[0], ScVal::String(message) if message.0.as_slice() == b"trying to invoke non-existent contract function")
                    && args[1] == value_symbol("engine_version")?)
            {
                absent = true;
            }
        }
        return if absent {
            Ok(None)
        } else {
            Err("Engine metadata failure is not an absent version export".into())
        };
    }
    match readonly_result(&value)? {
        ScVal::U32(version) if version > 0 => Ok(Some(version)),
        _ => Err("Invalid engine release version".into()),
    }
}
/// Fetch native authority and policy wallet state from the configured chain. Native usage must
/// come from the authoritative durable coordinator, never an implicit zero counter.
pub fn trusted_state(
    rpc: &dyn Rpc,
    c: &WalletConfig,
    accounting: Option<NativeAccounting>,
) -> Result<TrustedState> {
    Ok(trusted_state_inner(rpc, c, accounting, true)?.state)
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiscoveredState {
    pub state: TrustedState,
    pub paused: bool,
}
/// Read public live authority without requiring a previously configured customer key.
/// Discovery reports authority; it does not authorize an execution.
pub fn trusted_state_for_discovery(
    rpc: &dyn Rpc,
    c: &WalletConfig,
    accounting: Option<NativeAccounting>,
) -> Result<DiscoveredState> {
    trusted_state_inner(rpc, c, accounting, false)
}
/// The agent address that the policy wallet of `c` names on the ledger, or `None` while the
/// ledger holds no such wallet. The read reports; it authorizes nothing, and a caller verifies
/// the wallet's whole binding before it relies on the address.
pub fn installed_agent_address(rpc: &dyn Rpc, c: &WalletConfig) -> Result<Option<String>> {
    if c.route != WalletRoute::PolicyWallet {
        return Ok(None);
    }
    let contract = address(&c.wallet)?;
    let key = LedgerKey::ContractData(LedgerKeyContractData {
        contract: contract.clone(),
        key: ScVal::LedgerKeyContractInstance,
        durability: ContractDataDurability::Persistent,
    });
    let entries = rpc.call("getLedgerEntries", json!({"keys":[xdr(&key)?]}))?;
    let list = entries["entries"]
        .as_array()
        .ok_or("Missing policy wallet ledger entry")?;
    let Some(entry) = list.first() else {
        return Ok(None);
    };
    let entry: LedgerEntryData = read(entry["xdr"].as_str().ok_or("Missing instance XDR")?)?;
    let LedgerEntryData::ContractData(data) = entry else {
        return Err("Unexpected policy wallet ledger entry".into());
    };
    if list.len() != 1 || data.contract != contract || data.key != ScVal::LedgerKeyContractInstance
    {
        return Err("policy wallet instance ledger key differs".into());
    }
    let ScVal::ContractInstance(instance) = data.val else {
        return Err("Missing policy wallet instance state".into());
    };
    let storage = instance.storage.ok_or("Missing policy wallet storage")?;
    let Some(ScVal::Bytes(raw)) = storage
        .iter()
        .find(|e| e.key == value_symbol("c").unwrap_or(ScVal::Void))
        .map(|e| &e.val)
    else {
        return Err("Missing policy wallet configuration".into());
    };
    Ok(Some(packed::configuration(raw.as_slice())?.agent))
}
/// The fault of a wallet whose code on the ledger differs from the code of its configuration.
pub const EXECUTABLE_DIFFERS: &str = "policy wallet executable differs from installed code";
fn trusted_state_inner(
    rpc: &dyn Rpc,
    c: &WalletConfig,
    accounting: Option<NativeAccounting>,
    require_customer_quorum: bool,
) -> Result<DiscoveredState> {
    validate_config(c)?;
    if c.route == WalletRoute::Odc && require_customer_quorum {
        return Err("Historical wallet discovery cannot authorize new execution".into());
    }
    let network = rpc.call("getNetwork", json!({}))?;
    if network["passphrase"].as_str() != Some(passphrase(&c.network)?) {
        return Err("Stellar RPC network differs from installation".into());
    }
    let latest = rpc.call("getLatestLedger", json!({}))?;
    let ledger = u32::try_from(
        latest["sequence"]
            .as_u64()
            .ok_or("Missing ledger sequence")?,
    )
    .map_err(err)?;
    if c.route == WalletRoute::Native {
        let source = get_account(rpc, &c.wallet)?;
        // The wallet account holds exactly the roles of its installation. A signer or a
        // threshold that the installation does not name ends every use of the wallet.
        let paused =
            source.wallet_status(&c.owner, &c.agent, &c.server)? == owner::WalletStatus::Paused;
        if require_customer_quorum {
            if paused {
                return Err("This wallet is paused: its owner removed the agent signer".into());
            }
            source.validate_wallet(c)?;
        }
        let a = accounting.ok_or("Native wallet requires authoritative policy accounting")?;
        return Ok(DiscoveredState {
            state: TrustedState {
                contract_version: None,
                policy_state: None,
                source,
                nonce: a.nonce,
                deployment_version: a.deployment_version,
                spent_daily: a.spent_daily,
                spent_total: a.spent_total,
                spent_day: a.spent_day,
                volume_daily: a.volume_daily,
                unpriced_total: a.unpriced_total,
                unpriced_daily: a.unpriced_daily,
                calls: a.calls,
                ledger,
                module_digest: c.module_digest,
                source_hash: c.source_hash,
                owner: c.owner.clone(),
                agent: c.agent.clone(),
                server: c.server.clone(),
                policy_instance: c.policy_instance,
            },
            paused,
        });
    }
    let key = LedgerKey::ContractData(LedgerKeyContractData {
        contract: address(&c.wallet)?,
        key: ScVal::LedgerKeyContractInstance,
        durability: ContractDataDurability::Persistent,
    });
    let entries = rpc.call("getLedgerEntries", json!({"keys":[xdr(&key)?]}))?;
    let list = entries["entries"]
        .as_array()
        .ok_or("Missing policy wallet ledger entry")?;
    if list.len() != 1 {
        return Err("The policy wallet instance is not on the ledger. A lapsed instance is read whatever its lifetime; if the RPC serves no archived entry, restore the wallet's instance first (for example with stellar contract restore).".into());
    }
    let entry: LedgerEntryData = read(list[0]["xdr"].as_str().ok_or("Missing instance XDR")?)?;
    let LedgerEntryData::ContractData(data) = entry else {
        return Err("Unexpected policy wallet ledger entry".into());
    };
    if data.contract != address(&c.wallet)?
        || data.key != ScVal::LedgerKeyContractInstance
        || data.durability != ContractDataDurability::Persistent
    {
        return Err("policy wallet instance ledger key differs".into());
    }
    let ScVal::ContractInstance(instance) = data.val else {
        return Err("Missing policy wallet instance state".into());
    };
    let ContractExecutable::Wasm(module) = instance.executable else {
        return Err("policy wallet must use an owner-selected Wasm executable".into());
    };
    if module.0 != c.module_digest {
        return Err(EXECUTABLE_DIFFERS.into());
    }
    let storage = instance.storage.ok_or("Missing policy wallet storage")?;
    // Layout 5 keeps its packed configuration under `c`; historical wallets keep State under 0.
    let state_key = if c.route == WalletRoute::PolicyWallet {
        value_symbol("c")?
    } else {
        ScVal::U32(0)
    };
    let state = storage
        .iter()
        .find(|e| e.key == state_key)
        .map(|e| &e.val)
        .ok_or("Missing policy wallet custody state")?;
    if c.route == WalletRoute::PolicyWallet {
        return current_wallet_state(
            rpc,
            c,
            state,
            module.0,
            ledger,
            accounting,
            require_customer_quorum,
        );
    }
    historical_wallet_state(rpc, c, state, module.0, ledger, require_customer_quorum)
}
/// Layout 5 discovery: decode the packed configuration, check it against the installation, and
/// read the figures from `t` and an open `d`. The transaction source is the server's sending
/// account, which `prepare_with` reads; discovery leaves it empty.
#[allow(clippy::too_many_arguments)]
fn current_wallet_state(
    rpc: &dyn Rpc,
    c: &WalletConfig,
    raw: &ScVal,
    module: [u8; 32],
    ledger: u32,
    accounting: Option<NativeAccounting>,
    require_customer_quorum: bool,
) -> Result<DiscoveredState> {
    let ScVal::Bytes(bytes) = raw else {
        return Err("Missing the policy wallet configuration".into());
    };
    let config = packed::configuration(bytes.as_slice())?;
    if require_customer_quorum && config.paused {
        return Err("policy wallet automation is paused".into());
    }
    // Discovery reports the installed roles; only an execution requires the configured ones.
    verify_binding(c, &config)?;
    if require_customer_quorum {
        verify_configuration(c, &config)?;
    }
    let figures = figures(rpc, c, ledger)?;
    // A wallet that keeps every figure needs no account of the server's.
    let accounting = accounting.filter(|_| crate::kept_figures(c) != packed::ALL);
    // The server's account of the figures that the wallet does not keep: a Simple wallet keeps
    // none, a Common wallet those of its rules with params. An execution needs it; discovery
    // reports the wallet's own figures without it.
    if require_customer_quorum && accounting.is_none() && crate::kept_figures(c) != packed::ALL {
        return Err(
            "A Simple or Common wallet needs the server's accounting of the figures that it does not keep"
                .into(),
        );
    }
    Ok(DiscoveredState {
        state: TrustedState {
            contract_version: Some(u32::from(config.layout)),
            policy_state: Some(PolicyStateSnapshot {
                params: config.params.clone(),
                rules: config.rules.clone(),
                source_hash: config.source_hash,
                figures: figures.clone(),
                custom: custom_state(rpc, c, ledger)?,
            }),
            source: AccountState {
                address: String::new(),
                sequence: 0,
                master_weight: 0,
                low_threshold: 0,
                medium_threshold: 0,
                high_threshold: 0,
                signers: vec![],
            },
            nonce: 0,
            deployment_version: u64::from(config.deployment_version),
            spent_daily: accounting.as_ref().map_or(
                if figures.day_ends != 0 {
                    figures.day_spent
                } else {
                    0
                },
                |a| a.spent_daily,
            ),
            spent_total: accounting.as_ref().map_or(figures.spent, |a| a.spent_total),
            spent_day: accounting.as_ref().map_or(0, |a| a.spent_day),
            volume_daily: accounting.as_ref().map_or(0, |a| a.volume_daily),
            unpriced_total: accounting.as_ref().is_some_and(|a| a.unpriced_total),
            unpriced_daily: accounting.as_ref().is_some_and(|a| a.unpriced_daily),
            calls: accounting.as_ref().map_or(figures.calls, |a| a.calls),
            ledger,
            module_digest: module,
            source_hash: config.source_hash,
            owner: config.owner,
            agent: config.agent,
            server: config.server,
            policy_instance: c.policy_instance,
        },
        paused: config.paused,
    })
}
/// The figures of the wallet at `ledger`: `t`, and `d` while its window is open.
pub fn figures(rpc: &dyn Rpc, c: &WalletConfig, ledger: u32) -> Result<packed::Figures> {
    let key = |name: &str, durability| -> Result<LedgerKey> {
        Ok(LedgerKey::ContractData(LedgerKeyContractData {
            contract: address(&c.wallet)?,
            key: value_symbol(name)?,
            durability,
        }))
    };
    let mut figures = packed::Figures::default();
    if let Some(ScVal::Bytes(raw)) =
        persistent_entry(rpc, &key("t", ContractDataDurability::Persistent)?)?
    {
        packed::totals(raw.as_slice(), packed::SPENT | packed::CALLS, &mut figures)?;
    }
    if let Some(ScVal::Bytes(raw)) =
        persistent_entry(rpc, &key("d", ContractDataDurability::Temporary)?)?
    {
        packed::daily(raw.as_slice(), ledger, &mut figures)?;
    }
    Ok(figures)
}
/// A Custom policy's own state entries at `ledger`: each key that its build declares, read from
/// its short storage key. A daily entry whose window ended and a persistent entry without a
/// value are absent. Other tiers store none.
pub fn custom_state(
    rpc: &dyn Rpc,
    c: &WalletConfig,
    ledger: u32,
) -> Result<std::collections::BTreeMap<String, crate::PolicyValue>> {
    let mut state = std::collections::BTreeMap::new();
    if c.tier != Some(crate::PolicyTier::Custom) {
        return Ok(state);
    }
    for entry in crate::custom_state_entries(&c.policy_source)? {
        let key = LedgerKey::ContractData(LedgerKeyContractData {
            contract: address(&c.wallet)?,
            key: ScVal::U32(entry.key),
            durability: if entry.daily {
                ContractDataDurability::Temporary
            } else {
                ContractDataDurability::Persistent
            },
        });
        if let Some(ScVal::Bytes(raw)) = persistent_entry(rpc, &key)?
            && let Some(value) = packed::state_value(raw.as_slice(), entry.daily, ledger)?
        {
            state.insert(entry.name, value);
        }
    }
    Ok(state)
}
/// Check the wallet's binding against the installation: its rules, asset and the owner's source
/// hash. The roles may differ.
fn verify_binding(c: &WalletConfig, config: &packed::Configuration) -> Result<()> {
    if config.rules != c.rules || config.asset != c.asset || config.source_hash != c.source_hash {
        return Err("Installed policy rules, asset or source differs".into());
    }
    Ok(())
}
/// Check a decoded configuration against the installation: rules, agent, server, asset and the
/// owner's source hash.
pub(crate) fn verify_configuration(c: &WalletConfig, config: &packed::Configuration) -> Result<()> {
    if config.rules != c.rules
        || config.agent != c.agent
        || config.server != c.server
        || config.asset != c.asset
        || config.source_hash != c.source_hash
    {
        return Err(
            "Installed policy rules, agent, service signer, asset or source differs".into(),
        );
    }
    Ok(())
}
/// Read-only discovery of a historical ODC wallet, for status and recovery of retained bytes.
fn historical_wallet_state(
    rpc: &dyn Rpc,
    c: &WalletConfig,
    state: &ScVal,
    module: [u8; 32],
    ledger: u32,
    require_customer_quorum: bool,
) -> Result<DiscoveredState> {
    if map_field(state, "version")? != &ScVal::U32(1) {
        return Err("Unsupported historical wallet state".into());
    }
    let paused = match map_field(state, "paused")? {
        ScVal::Bool(value) => *value,
        _ => return Err("Invalid policy wallet pause state".into()),
    };
    if require_customer_quorum && paused {
        return Err("policy wallet automation is paused".into());
    }
    let current_agent = addr(map_field(state, "agent")?)?;
    let source = get_account(rpc, &current_agent)?;
    source.validate_structure()?;
    if require_customer_quorum && source.signer_weight(&c.agent)? == 0 {
        return Err("Customer is not a current policy wallet agent account signer".into());
    }
    let binding = readonly_call(rpc, c, &source, "policy_binding")?;
    if digest_field(map_field(&binding, "policy_instance")?)? != c.policy_instance
        || digest_field(map_field(&binding, "module_digest")?)? != c.module_digest
        || digest_field(map_field(&binding, "source_digest")?)? != c.source_hash
        || digest_field(map_field(&binding, "argument_schema_digest")?)?
            != hash(ODC_TRANSFER_SCHEMA)
        || map_field(&binding, "entrypoint")? != &value_symbol("_execute")?
    {
        return Err("Compiled policy binding differs from installation".into());
    }
    if addr(map_field(map_field(state, "grant")?, "asset")?)? != c.asset {
        return Err("policy wallet asset differs from installation".into());
    }
    let out = TrustedState {
        contract_version: None,
        policy_state: None,
        source,
        nonce: number(map_field(state, "nonce")?)?,
        deployment_version: number(map_field(state, "revision")?)?,
        spent_daily: wide(map_field(state, "spent_daily")?)?,
        spent_total: wide(map_field(state, "spent_total")?)?,
        spent_day: number(map_field(state, "spent_day")?)?,
        volume_daily: 0,
        unpriced_total: false,
        unpriced_daily: false,
        calls: number(map_field(state, "calls")?)?,
        ledger,
        module_digest: module,
        source_hash: c.source_hash,
        owner: addr(map_field(state, "owner")?)?,
        agent: addr(map_field(state, "agent")?)?,
        server: addr(map_field(state, "engine")?)?,
        policy_instance: c.policy_instance,
    };
    Ok(DiscoveredState { state: out, paused })
}

fn persistent_entry(rpc: &dyn Rpc, key: &LedgerKey) -> Result<Option<ScVal>> {
    let encoded = xdr(key)?;
    let response = rpc.call("getLedgerEntries", json!({"keys":[encoded]}))?;
    let entries = response["entries"]
        .as_array()
        .ok_or("Missing ledger entries")?;
    let entry = match entries.as_slice() {
        [] => return Ok(None),
        [entry] => entry,
        _ => return Err("Unexpected ledger entry count".into()),
    };
    if entry["key"].as_str().is_some_and(|k| k != encoded) {
        return Err("Ledger entry key differs".into());
    }
    let LedgerEntryData::ContractData(data) =
        read(entry["xdr"].as_str().ok_or("Missing ledger entry XDR")?)?
    else {
        return Err("Unexpected receipt ledger entry".into());
    };
    let LedgerKey::ContractData(expected) = key else {
        unreachable!()
    };
    if data.contract != expected.contract
        || data.key != expected.key
        || data.durability != expected.durability
    {
        return Err("Receipt ledger key differs".into());
    }
    Ok(Some(data.val))
}
#[cfg(all(test, not(target_arch = "wasm32")))]
mod transport_tests {
    use super::*;
    use std::{io::Read, net::TcpListener, thread};

    fn rpc(url: &str, timeout: Duration) -> HttpRpc {
        HttpRpc::with_timeout(url, timeout).unwrap()
    }

    /// A loopback RPC that answers one call with a result of `sequence` and `padding` bytes of
    /// ledger metadata, as `getLatestLedger` does.
    fn serve_ledger(padding: usize) -> (String, thread::JoinHandle<()>) {
        use std::io::Write;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut byte = [0];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
            }
            let header = String::from_utf8(request).unwrap().to_ascii_lowercase();
            let length: usize = header
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .map(|value| value.trim().parse().unwrap())
                .unwrap();
            let mut body = vec![0; length];
            stream.read_exact(&mut body).unwrap();
            let id = serde_json::from_slice::<Value>(&body).unwrap()["id"].clone();
            let reply = json!({"jsonrpc":"2.0","id":id,
                "result":{"sequence":5_684_062,"metadataXdr":"A".repeat(padding)}})
            .to_string();
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
                reply.len()
            );
        });
        (url, server)
    }

    #[test]
    #[cfg_attr(not(feature = "e2e"), ignore = "end-to-end: run with --features e2e")]
    fn the_newest_ledger_reads_with_its_close_metadata_and_other_replies_keep_their_bound() {
        // Testnet ledger 5684062 answered `getLatestLedger` with 1,155,616 characters of
        // metadata: more than the bound of every other reply.
        let (url, server) = serve_ledger(1_155_616);
        let latest = rpc(&url, Duration::from_secs(10))
            .call(LATEST_LEDGER, json!({}))
            .unwrap();
        server.join().unwrap();
        assert_eq!(latest["sequence"], 5_684_062);
        // The same reply to another method is over its bound.
        let (url, server) = serve_ledger(1_155_616);
        let error = rpc(&url, Duration::from_secs(10))
            .call("getLedgerEntries", json!({"keys":[]}))
            .unwrap_err();
        server.join().unwrap();
        assert_eq!(error, "RPC response exceeds limit");
        // The newest ledger has a bound too.
        let (url, server) = serve_ledger(LATEST_LEDGER_MAX_BYTES);
        let error = rpc(&url, Duration::from_secs(10))
            .call(LATEST_LEDGER, json!({}))
            .unwrap_err();
        server.join().unwrap();
        assert_eq!(error, "RPC response exceeds limit");
    }

    #[test]
    #[cfg_attr(not(feature = "e2e"), ignore = "end-to-end: run with --features e2e")]
    fn calls_without_an_answer_are_network_unavailable() {
        // Connection refused: nothing listens on the port.
        let closed = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", closed.local_addr().unwrap());
        drop(closed);
        let error = rpc(&url, Duration::from_secs(5))
            .call("getNetwork", json!({}))
            .unwrap_err();
        assert_eq!(error, NETWORK_UNAVAILABLE);
        // Timeout: the server accepts the request and never answers.
        let silent = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", silent.local_addr().unwrap());
        let held = thread::spawn(move || {
            let (stream, _) = silent.accept().unwrap();
            thread::sleep(Duration::from_millis(1500));
            drop(stream);
        });
        let error = rpc(&url, Duration::from_millis(300))
            .call("getNetwork", json!({}))
            .unwrap_err();
        assert_eq!(error, NETWORK_UNAVAILABLE);
        held.join().unwrap();
        let mapped = crate::provider::failure(error);
        assert_eq!(mapped.code, crate::provider::NETWORK_UNAVAILABLE);
        assert_eq!(crate::provider::failure("Missing RPC result").code, 3);
    }

    #[test]
    #[cfg_attr(not(feature = "e2e"), ignore = "end-to-end: run with --features e2e")]
    fn a_dropped_answer_stays_unknown() {
        // The server reads the request, then closes the connection without a reply.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0; 4096];
            let _ = stream.read(&mut buffer);
        });
        let error = rpc(&url, Duration::from_secs(5))
            .call("getNetwork", json!({}))
            .unwrap_err();
        server.join().unwrap();
        assert_eq!(error, TRANSPORT_UNKNOWN);
        assert_eq!(crate::provider::failure(error).code, 5);
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod footprint_tests {
    use super::*;

    fn nonce(contract: &str, value: i64) -> LedgerKey {
        LedgerKey::ContractData(LedgerKeyContractData {
            contract: address(contract).unwrap(),
            key: ScVal::LedgerKeyNonce(ScNonceKey { nonce: value }),
            durability: ContractDataDurability::Temporary,
        })
    }
    fn entry(contract: &str, name: &str) -> LedgerKey {
        LedgerKey::ContractData(LedgerKeyContractData {
            contract: address(contract).unwrap(),
            key: ScVal::Symbol(ScSymbol(name.try_into().unwrap())),
            durability: ContractDataDurability::Persistent,
        })
    }
    fn footprint(read_write: Vec<LedgerKey>, read_only: Vec<LedgerKey>) -> LedgerFootprint {
        LedgerFootprint {
            read_only: read_only.try_into().unwrap(),
            read_write: read_write.try_into().unwrap(),
        }
    }

    /// Two recordings of one operation draw two nonces for the wallet's authorization: the
    /// prepared footprint still covers the second. Any other key that differs is not covered.
    #[test]
    fn a_recording_nonce_of_the_wallet_alone_may_differ() {
        let wallet = stellar_strkey::Contract([7; 32]).to_string();
        let token = stellar_strkey::Contract([8; 32]).to_string();
        let have = footprint(
            vec![entry(&token, "balance"), nonce(&wallet, 1)],
            vec![entry(&wallet, "c")],
        );
        let again = footprint(
            vec![entry(&token, "balance"), nonce(&wallet, 2)],
            vec![entry(&wallet, "c")],
        );
        assert!(footprint_covers(&wallet, &have, &again).unwrap());
        // Another contract's nonce, another written entry or another read entry is a change.
        for changed in [
            footprint(
                vec![entry(&token, "balance"), nonce(&token, 2)],
                vec![entry(&wallet, "c")],
            ),
            footprint(
                vec![entry(&token, "other"), nonce(&wallet, 2)],
                vec![entry(&wallet, "c")],
            ),
            footprint(
                vec![entry(&token, "balance"), nonce(&wallet, 2)],
                vec![entry(&wallet, "t")],
            ),
        ] {
            assert!(!footprint_covers(&wallet, &have, &changed).unwrap());
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod custom_state_tests {
    use super::*;
    use crate::state_keys::declared;

    const SOURCE: &str = "use allowit::prelude::*;\n/// Count each payment, today and in all.\npub fn execute(ctx: &AllowitContext) -> allowit::Result {\n    // get_state and set_state in a comment are no calls: set_state(ctx, nothing)\n    let note = \"set_state(ctx, \\\"not_a_key\\\", 1)\";\n    let _ = note;\n    let today: u64 = allowit::get_state(ctx, \"day_payments\")?.unwrap_or(0);\n    let all = allowit::get_state::<u64>(ctx, \"payments\")?.unwrap_or(0);\n    let _spent: i128 = allowit::get_state(ctx, \"spent\")?.unwrap_or(0);\n    allowit::r#set_state(ctx, \"day_payments\", today + 1)?;\n    allowit::set_state(ctx, \"payments\", all + 1)?;\n    Ok(())\n}\n";

    #[test]
    fn the_scan_finds_each_literal_key_and_skips_comments_and_strings() {
        let (entries, figures) = declared(SOURCE, |name| crate::hash(name)).unwrap();
        let names: Vec<(&str, bool)> = entries.iter().map(|e| (e.name.as_str(), e.daily)).collect();
        assert_eq!(names, [("day_payments", true), ("payments", false)]);
        assert_eq!(entries[0].key, 0x6df2_15e2);
        // A read of a standard figure keeps that figure: `spent` is figure 1.
        assert_eq!(figures, 1);
        for (source, refused) in [
            ("allowit::set_state(ctx, key, 1)?;", "string literal"),
            ("allowit::set_state(ctx, \"spent\", 1)?;", "standard figure"),
            ("allowit::get_state(ctx, \"a-b\")?;", "not 1 to 32"),
            ("allowit::get_state(ctx, \"\")?;", "not 1 to 32"),
            ("let s = \"unterminated;", "unterminated"),
            // A key is the literal alone: an expression that starts with one is no key.
            (
                "allowit::get_state(ctx, \"day_spent\".max(\"spent\"))?;",
                "string literal",
            ),
            (
                "allowit::set_state(ctx, \"note\".to_owned() + \"x\", 1)?;",
                "string literal",
            ),
        ] {
            let error = declared(source, |name| crate::hash(name)).unwrap_err();
            assert!(error.contains(refused), "{source}: {error}");
        }
        let nine: String = (0..9)
            .map(|i| format!("allowit::set_state(ctx, \"k{i}\", 1)?;\n"))
            .collect();
        assert!(
            declared(&nine, |name| crate::hash(name))
                .unwrap_err()
                .contains("at most 8")
        );
    }

    #[test]
    fn a_state_value_reads_with_its_window_and_its_packing() {
        // A daily entry: end ledger 100, then the packed `Int(1)`.
        let daily = [0, 0, 0, 100, 0, 2];
        assert_eq!(
            packed::state_value(&daily, true, 100).unwrap(),
            Some(crate::PolicyValue::Int(1))
        );
        assert_eq!(packed::state_value(&daily, true, 101).unwrap(), None);
        assert_eq!(
            packed::state_value(&[0, 2], false, 1).unwrap(),
            Some(crate::PolicyValue::Int(1))
        );
        assert_eq!(packed::state_value(&[], false, 1).unwrap(), None);
        assert!(packed::state_value(&[0, 2, 9], false, 1).is_err());
        assert!(packed::state_value(&[0, 0], true, 1).is_err());
    }

    /// An RPC that holds the ledger entries of a test.
    struct Entries(std::collections::BTreeMap<String, LedgerEntryData>);
    impl Rpc for Entries {
        fn call(&self, method: &str, params: Value) -> Result<Value> {
            assert_eq!(method, "getLedgerEntries");
            let key = params["keys"][0].as_str().unwrap().to_owned();
            let entries: Vec<Value> = self
                .0
                .get(&key)
                .map(|data| json!({"key": key, "xdr": xdr(data).unwrap(), "liveUntilLedgerSeq": 1_000}))
                .into_iter()
                .collect();
            Ok(json!({"entries": entries}))
        }
    }

    #[test]
    fn the_snapshot_carries_the_declared_entries_into_the_evaluation() {
        let mut c = crate::test_support::request_config(crate::WalletRoute::PolicyWallet, false);
        c.tier = Some(crate::PolicyTier::Custom);
        c.policy_source = SOURCE.to_owned();
        let entries = crate::custom_state_entries(SOURCE).unwrap();
        let mut ledger = std::collections::BTreeMap::new();
        for (entry, raw) in entries.iter().zip([vec![0, 0, 0, 100, 0, 4], vec![0, 14]]) {
            let key = LedgerKeyContractData {
                contract: address(&c.wallet).unwrap(),
                key: ScVal::U32(entry.key),
                durability: if entry.daily {
                    ContractDataDurability::Temporary
                } else {
                    ContractDataDurability::Persistent
                },
            };
            let data = LedgerEntryData::ContractData(ContractDataEntry {
                ext: ExtensionPoint::V0,
                contract: key.contract.clone(),
                key: key.key.clone(),
                durability: key.durability,
                val: ScVal::Bytes(raw.try_into().unwrap()),
            });
            ledger.insert(xdr(&LedgerKey::ContractData(key)).unwrap(), data);
        }
        let rpc = Entries(ledger);
        // In the window both entries read; after it the daily one is absent.
        let open = custom_state(&rpc, &c, 100).unwrap();
        assert_eq!(open.get("day_payments"), Some(&crate::PolicyValue::Int(2)));
        assert_eq!(open.get("payments"), Some(&crate::PolicyValue::Int(7)));
        let closed = custom_state(&rpc, &c, 101).unwrap();
        assert_eq!(closed.get("day_payments"), None);
        assert_eq!(closed.get("payments"), Some(&crate::PolicyValue::Int(7)));
        // Another tier reads none.
        c.tier = Some(crate::PolicyTier::Common);
        assert!(custom_state(&rpc, &c, 100).unwrap().is_empty());
    }
}
#[cfg(test)]
mod owner_lapse_tests {
    use super::*;

    const HASH: &str = "ab";
    fn reply(status: &str, oldest: u64, latest: u64, closed: u64) -> Value {
        json!({"status":status,"oldestLedger":oldest,"latestLedger":latest,"latestLedgerCloseTime":closed.to_string()})
    }

    /// A sent owner step past its time bound with no ledger record lapsed, so the owner signs a
    /// new step. The proof needs history from the prepared ledger `since` onward.
    #[test]
    fn a_lost_owner_send_lapses_only_when_history_covers_its_prepared_ledger() {
        let (expires_at, since) = (1_000, 500);
        let lapsed = |reply: &Value| owner_never_applied(reply, HASH, expires_at, since);
        assert!(lapsed(&reply("NOT_FOUND", 400, 900, 1_001)));
        assert!(lapsed(&reply("NOT_FOUND", 500, 500, 1_001)));
        // The history starts after the prepared ledger: an earlier inclusion could be missing.
        assert!(!lapsed(&reply("NOT_FOUND", 501, 900, 1_001)));
        // The endpoint has not reached the prepared ledger.
        assert!(!lapsed(&reply("NOT_FOUND", 400, 499, 1_001)));
        // No ledger closed after the time bound yet: the step can still apply.
        assert!(!lapsed(&reply("NOT_FOUND", 400, 900, 1_000)));
        // A ledger record, a reply without history bounds and a reply for another hash prove
        // nothing.
        assert!(!lapsed(&reply("SUCCESS", 400, 900, 1_001)));
        assert!(!lapsed(&reply("FAILED", 400, 900, 1_001)));
        assert!(!lapsed(
            &json!({"status":"NOT_FOUND","latestLedgerCloseTime":"1001"})
        ));
        assert!(!lapsed(&reply("NOT_FOUND", 0, 900, 1_001)));
        let mut other = reply("NOT_FOUND", 400, 900, 1_001);
        other["txHash"] = json!("cd");
        assert!(!lapsed(&other));
        other["txHash"] = json!(HASH);
        assert!(lapsed(&other));
    }

    /// The proof reads the reply for the exact hash.
    #[test]
    fn the_owner_lapse_reads_the_transaction_of_its_hash() {
        struct Reply(std::sync::Mutex<Vec<Value>>);
        impl Rpc for Reply {
            fn call(&self, method: &str, params: Value) -> Result<Value> {
                self.0
                    .lock()
                    .unwrap()
                    .push(json!({"method": method, "params": params}));
                Ok(
                    json!({"status":"NOT_FOUND","oldestLedger":400,"latestLedger":900,"latestLedgerCloseTime":"1001"}),
                )
            }
        }
        let rpc = Reply(std::sync::Mutex::new(Vec::new()));
        assert_eq!(
            owner_transaction_lapsed(&rpc, &[0xab; 32], 1_000, 500),
            Ok(true)
        );
        assert_eq!(
            owner_transaction_lapsed(&rpc, &[0xab; 32], 1_001, 500),
            Ok(false)
        );
        let calls = rpc.0.lock().unwrap();
        assert_eq!(
            calls[0],
            json!({"method":"getTransaction","params":{"hash": hex(&[0xab; 32])}})
        );
    }
}
