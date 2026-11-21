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
    CodeState, OwnerSettlement, code_lifetime, code_state, code_uploaded, contract_exists,
    instance_code, owner_settlement, vault_redeemable,
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
/// only the sequence and the close time.
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
    // A reply that finds no entry gives an empty list, or omits the list beside its ledger.
    if no_entry(&value) {
        return Ok(None);
    }
    account_from_response(&value, address).map(Some)
}
/// Whether the ledger holds the account. A presence is the answer of one read: it never reads
/// as a closed wallet. An absence is confirmed as an observation of the head: after a reply that
/// finds no account, the head is read, then the account again, then the closing head, and the
/// second reply is of the closing head's own ledger, not older than the head before it
/// ([`owner_observation::current`]). The reply of any other ledger does not say that an account
/// is gone now: it is a stale observation, which a caller reads again.
pub fn account_present(rpc: &dyn Rpc, address: &str) -> Result<bool> {
    let key = LedgerKey::Account(LedgerKeyAccount {
        account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(account_key(
            address,
        )?))),
    });
    let read = || rpc.call("getLedgerEntries", json!({"keys":[xdr(&key)?]}));
    let present = |value: &Value| account_from_response(value, address).map(|_| true);
    let value = read()?;
    if !no_entry(&value) {
        return present(&value);
    }
    let before = owner_observation::head(rpc)?;
    let value = read()?;
    if !no_entry(&value) {
        return present(&value);
    }
    let observed = owner_observation::ledger(&value["latestLedger"])?;
    // The absence is of the closing head itself: a ledger that closed after the reply could
    // hold the account again.
    if owner_observation::current(rpc, before, observed)? != observed {
        return Err(owner_observation::STALE_OBSERVATION.into());
    }
    Ok(false)
}
/// Whether a `getLedgerEntries` reply finds no entry: an empty list, or no list beside a valid
/// ledger. Any other reply is read as it is.
fn no_entry(value: &Value) -> bool {
    match value.get("entries") {
        Some(Value::Array(entries)) => entries.is_empty(),
        None | Some(Value::Null) => owner_observation::ledger(&value["latestLedger"]).is_ok(),
        Some(_) => false,
    }
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
/// The trustline of an issued asset that an account holds, `None` without it. A reply that
/// finds no entry is no trustline ([`no_entry`]). The entry that the reply gives must be the one
/// that was asked for, of this account and this asset: the balance of another line is never read.
fn trustline(rpc: &dyn Rpc, address: &str, asset: &Asset) -> Result<Option<TrustLineEntry>> {
    let line = match asset {
        Asset::CreditAlphanum4(a) => TrustLineAsset::CreditAlphanum4(a.clone()),
        Asset::CreditAlphanum12(a) => TrustLineAsset::CreditAlphanum12(a.clone()),
        Asset::Native => return Err("XLM has no trustline".into()),
    };
    let account = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(account_key(
        address,
    )?)));
    let key = LedgerKey::Trustline(LedgerKeyTrustLine {
        account_id: account.clone(),
        asset: line.clone(),
    });
    let value = rpc.call("getLedgerEntries", json!({"keys":[xdr(&key)?]}))?;
    if no_entry(&value) {
        return Ok(None);
    }
    let [entry] = value["entries"]
        .as_array()
        .map(Vec::as_slice)
        .ok_or("Missing trustline entries")?
    else {
        return Err("Expected one trustline entry".into());
    };
    let LedgerEntryData::Trustline(found) =
        read(entry["xdr"].as_str().ok_or("Missing trustline XDR")?)?
    else {
        return Err("Wrong ledger entry type".into());
    };
    if found.account_id != account || found.asset != line {
        return Err("Ledger trustline identity differs".into());
    }
    Ok(Some(found))
}
/// The balance of an issued asset that an account holds, `None` without its trustline.
pub fn trustline_balance(rpc: &dyn Rpc, address: &str, asset: &Asset) -> Result<Option<i64>> {
    Ok(trustline(rpc, address, asset)?.map(|line| line.balance))
}
/// The units of an issued asset that an account can send: its balance less what its open
/// offers hold. `None` without its trustline.
pub fn trustline_spendable(rpc: &dyn Rpc, address: &str, asset: &Asset) -> Result<Option<i64>> {
    Ok(trustline(rpc, address, asset)?.map(|line| {
        let selling = match &line.ext {
            TrustLineEntryExt::V0 => 0,
            TrustLineEntryExt::V1(v1) => v1.liabilities.selling,
        };
        line.balance.saturating_sub(selling).max(0)
    }))
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
    state.source = get_account(rpc, &super::gas_payee(request, terms)?)?;
    let ceiling = terms.expense.as_ref();
    let mut terms = priced_terms(rpc, c, request, terms, &state, now, expires_at)?;
    // The invocation that carries the priced expense is simulated on its own. A policy that
    // reads the gas can need more resources with it than with the provisional expense. Its
    // bound then follows from its own resource fee, within the ceiling and the gas cap, at most
    // `REPRICE_ROUNDS` times. After that the bound decides, and `attach_simulation` refuses a
    // resource fee above it.
    let mut rounds = 0;
    loop {
        let intent = prepare_for_native_preflight(c, request, &terms, &state, now, expires_at)?;
        let encoded = simulated_resources(rpc, &intent)?;
        let repriced = match (ceiling, &terms.expense) {
            (Some(ceiling), Some(signed)) if rounds < REPRICE_ROUNDS => {
                let resources: SorobanTransactionData = read(&encoded)?;
                let bound = fee_bound(resources.resource_fee)?
                    .min(ceiling.max_fee_stroops)
                    .min(c.max_fee_stroops);
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
        terms.expense = Some(expense?);
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
/// The repayment stays within the wallet's gas cap `gas_cap`.
fn bounded(
    terms: &ExecutionTerms,
    ceiling: &ExpenseBounds,
    fee: u32,
    gas_cap: i128,
) -> Result<ExpenseBounds> {
    if terms.gas.is_some() {
        ceiling.with_fee_bound_only(fee)
    } else {
        ceiling.with_repayment(fee, terms.gas_carry, gas_cap)
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
    // An explicit repayment takes no carry, priced or not.
    if terms.gas.is_some() {
        terms.repaid_stroops()?;
    }
    let Some(ceiling) = terms.expense.as_ref().filter(|e| e.max_fee_stroops > 0) else {
        // An unpriced operation repays nothing.
        return Ok(terms.clone());
    };
    // The wallet's gas cap is the installed fee ceiling, which its creation set. The fee bound
    // stays within the quote and within the gas cap: the wallet repays no more than its gas cap, and the
    // sending account declares no fee above it.
    let gas_cap = i128::from(c.max_fee_stroops);
    let limit = ceiling.max_fee_stroops.min(c.max_fee_stroops);
    let with_bound = |fee: u32| -> Result<ExecutionTerms> {
        let expense = bounded(terms, ceiling, fee.min(limit), gas_cap)?;
        Ok(ExecutionTerms {
            args: terms.args.clone(),
            expense: Some(expense),
            gas: terms.gas.clone(),
            sender: terms.sender.clone(),
            gas_carry: terms.gas_carry,
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
        Err(lowest) => resource_fee(limit).map_err(|_| lowest)?,
    };
    with_bound(fee_bound(simulated)?)
}
/// The refusal of a step on a wallet whose instance or code lapsed: nothing restores it (Core's
/// `CONTRACT_EXPIRED`).
pub const CONTRACT_EXPIRED: &str =
    "The wallet's instance or code lapsed on the network: nothing restores it";
/// Refuse the simulation `value` of a step on the wallet `wallet`, whose code is `code`, when it
/// would restore that wallet's instance or code, in place or in a separate restoration first
/// (`CONTRACT_EXPIRED`). A creation names the code of the wallet that it creates and no wallet.
/// An owner step names no code: it calls the wallet alone, whatever code the wallet runs or an
/// upgrade installs, so it refuses any code entry. Other entries, such as `t` or another
/// contract's instance, are left to `restoring_in_place`.
pub(crate) fn refuse_expired(
    value: &Value,
    wallet: Option<&str>,
    code: Option<&[u8; 32]>,
) -> Result<()> {
    let instance = wallet
        .map(|wallet| {
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(LedgerKey::ContractData(
                LedgerKeyContractData {
                    contract: address(wallet)?,
                    key: ScVal::LedgerKeyContractInstance,
                    durability: ContractDataDurability::Persistent,
                },
            ))
        })
        .transpose()
        .map_err(|e| e.to_string())?;
    let expired = |key: &LedgerKey| match key {
        LedgerKey::ContractCode(entry) => code.is_none_or(|code| entry.hash == Hash(*code)),
        key => Some(key) == instance.as_ref(),
    };
    let data = |value: &Value| -> Result<Option<SorobanTransactionData>> {
        value.as_str().map(read).transpose()
    };
    if let Some(preamble) = value.get("restorePreamble").filter(|v| !v.is_null())
        && let Some(restored) = data(&preamble["transactionData"])?
        && restored.resources.footprint.read_write.iter().any(expired)
    {
        return Err(CONTRACT_EXPIRED.into());
    }
    if let Some(data) = data(&value["transactionData"])?
        && let SorobanTransactionDataExt::V1(ext) = &data.ext
    {
        let written = data.resources.footprint.read_write.as_slice();
        if ext
            .archived_soroban_entries
            .iter()
            .any(|index| written.get(*index as usize).is_some_and(expired))
        {
            return Err(CONTRACT_EXPIRED.into());
        }
    }
    Ok(())
}
/// Refuse a simulation that needs a separate restoration first, and accept one whose archived
/// entries the transaction restores itself: each named by its index in the read-write
/// footprint. The transaction's fee pays for that restoration. A policy wallet operation and an
/// owner transaction restore a lapsed data entry, such as `t`, in this way; a wallet whose
/// instance or code lapsed is refused first (`refuse_expired`).
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
    refuse_expired(&v, Some(&p.config.wallet), Some(&p.config.module_digest))?;
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
    refuse_expired(&v, Some(&p.config.wallet), Some(&p.config.module_digest))?;
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
    let accounting = (!crate::wallet_gives_every_figure(&p.config)).then_some(NativeAccounting {
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
/// The network's minimum lifetime of a persistent entry, in ledgers: the lifetime of code that
/// an upload creates, and the lifetime to which a renewal extends shared code.
pub fn minimum_persistent_lifetime(rpc: &dyn Rpc) -> Result<u32> {
    let key = LedgerKey::ConfigSetting(LedgerKeyConfigSetting {
        config_setting_id: ConfigSettingId::StateArchival,
    });
    let value = rpc.call("getLedgerEntries", json!({"keys":[xdr(&key)?]}))?;
    let [entry] = value["entries"]
        .as_array()
        .map(Vec::as_slice)
        .ok_or("Missing state archival settings")?
    else {
        return Err("Unexpected state archival settings".into());
    };
    let data: LedgerEntryData = read(entry["xdr"].as_str().ok_or("Missing settings XDR")?)?;
    let LedgerEntryData::ConfigSetting(ConfigSettingEntry::StateArchival(settings)) = data else {
        return Err("Unexpected state archival settings".into());
    };
    if settings.min_persistent_ttl == 0 {
        return Err("The network names no persistent lifetime".into());
    }
    Ok(settings.min_persistent_ttl)
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
/// Whether the policy wallet operation `p` lapsed: it can no longer execute, and the network's
/// history holds no execution of it. A ledger closed at or after its signed `expires_at`, and the
/// wallet refuses an execution whose expiry is not after the ledger's time, in any envelope that
/// carries its authorization: no execution comes after that ledger. The wallet's events read
/// then, from the preparation's ledger on, hold every execution of the operation, in any envelope,
/// also one whose envelope no receipt of the operation adopts: an event found means that it
/// executed. The time bound alone proves no lapse: once the history no longer holds the
/// preparation's ledger, the operation stays open. `false` before
/// that ledger, when its prepared transaction succeeded, when the RPC does not show the closing
/// time or a history that holds the preparation, when an execution is found, or when the scan of
/// the events does not reach the ledger that showed the expiry; a read that fails
/// is an error, never a lapse.
pub fn operation_lapsed(rpc: &dyn Rpc, p: &PreparedOperation) -> Result<bool> {
    if p.config.route != WalletRoute::PolicyWallet {
        return Ok(false);
    }
    let reply = rpc.call("getTransaction", json!({"hash":hex(&p.transaction_hash)}))?;
    let number = |key: &str| {
        reply[key]
            .as_u64()
            .or_else(|| reply[key].as_str()?.parse().ok())
    };
    let closed = number("latestLedgerCloseTime");
    if reply["status"].as_str() == Some("SUCCESS") || !closed.is_some_and(|t| t >= p.expires_at) {
        return Ok(false);
    }
    // The history starts after the preparation: an execution in it could be gone, so the time
    // bound alone proves nothing. A reply without its history bounds proves nothing either.
    match (number("oldestLedger"), number("latestLedger")) {
        (Some(oldest), Some(latest)) if oldest != 0 && oldest <= u64::from(p.state.ledger) => {
            Ok(executed(rpc, p, latest)? == Some(false))
        }
        _ => Ok(false),
    }
}
/// The most pages of events that one lapse read follows. An RPC scans a bounded range of ledgers
/// for each page (Stellar RPC: 10,000), and its history holds about 120,960 (seven days).
const MAX_EVENT_PAGES: usize = 32;
/// Whether the wallet's events from the ledger of `p`'s preparation on hold an execution of `p`:
/// its `allowit` event of the operation id, in any envelope. Each answer scans a bounded range of
/// ledgers and names where its scan ended (`cursor`); the read follows the cursor until it passed
/// the ledger `through`, which showed the expiry. `None` when no event is found and the scan does
/// not reach that ledger, or an answer names no cursor: an execution in the ledgers that it did
/// not scan could be missing.
fn executed(rpc: &dyn Rpc, p: &PreparedOperation, through: u64) -> Result<Option<bool>> {
    let topics = [
        xdr(&value_symbol("allowit")?)?,
        xdr(&value_bytes(&p.request.operation.nonce)?)?,
    ];
    let filters =
        json!([{"type": "contract", "contractIds": [p.config.wallet], "topics": [topics]}]);
    let mut request = json!({
        "startLedger": p.state.ledger,
        "filters": filters,
        "pagination": {"limit": 1},
    });
    for _ in 0..MAX_EVENT_PAGES {
        let reply = rpc.call("getEvents", request)?;
        if !reply["events"]
            .as_array()
            .ok_or("Missing ledger events")?
            .is_empty()
        {
            return Ok(Some(true));
        }
        let Some((cursor, scanned)) = reply["cursor"]
            .as_str()
            .and_then(|cursor| Some((cursor, cursor_ledger(cursor)?)))
        else {
            return Ok(None);
        };
        if scanned >= through {
            return Ok(Some(false));
        }
        request = json!({"filters": filters, "pagination": {"cursor": cursor, "limit": 1}});
    }
    Ok(None)
}
/// The ledger of an event cursor: the ledger of its TOID, the number before the dash.
fn cursor_ledger(cursor: &str) -> Option<u64> {
    let toid: u64 = cursor.split_once('-')?.0.parse().ok()?;
    Some(toid >> 32)
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
    /// When the ledger that holds the transaction closed, in Unix seconds: the RPC's `createdAt`.
    /// `None` for a receipt that this rail retained before it kept the time, and for an RPC that
    /// does not state it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closed_at: Option<u64>,
}
/// The close time of the settlement ledger in a `getTransaction` reply (`createdAt`, Unix seconds
/// as decimal text or a number), or `None` when the reply does not state it.
fn closed_at(v: &Value) -> Result<Option<u64>> {
    unix_seconds(v, "createdAt", "Invalid settlement time")
}
/// The time that `field` of an RPC reply states, in Unix seconds as decimal text or a number, or
/// `None` when the reply does not state it. Any other value is the error `invalid`.
fn unix_seconds(v: &Value, field: &str, invalid: &'static str) -> Result<Option<u64>> {
    match v.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text))
            if !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) =>
        {
            text.parse().map(Some).map_err(|_| invalid.into())
        }
        Some(Value::Number(number)) => number.as_u64().map(Some).ok_or_else(|| invalid.into()),
        Some(_) => Err(invalid.into()),
    }
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
/// Read the verified terminal receipt of the transaction `envelope`, whose hash is
/// `transaction_hash`, as the ledger holds it: the reply's own envelope is `envelope`, before any
/// fee bump is read. The same transaction in another envelope is no receipt of this one. Absence
/// remains unknown.
pub fn own_receipt_by_hash(
    rpc: &dyn Rpc,
    network: &str,
    transaction_hash: &[u8; 32],
    envelope: &str,
) -> Result<Option<VerifiedReceipt>> {
    let v = rpc.call("getTransaction", json!({"hash":hex(transaction_hash)}))?;
    if matches!(v["status"].as_str(), Some("SUCCESS" | "FAILED"))
        && v["envelopeXdr"].as_str() != Some(envelope)
    {
        return Err("The ledger holds the transaction in another envelope".into());
    }
    receipt_from_response(&v, network, transaction_hash)
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
        closed_at: closed_at(v)?,
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
    /// When the ledger `state.ledger` closed, in Unix seconds: the `closeTime` of the
    /// `getLatestLedger` reply that gave that ledger, at the start of the read. The entries of
    /// the state are read after that reply, so they can be of a later ledger than
    /// `state.ledger`: the time is then earlier than the close of their ledger, never later. It
    /// is a time that the network had reached when the state was read, so an operation that a
    /// caller signs after the read settles in a ledger that closes at or after it. It does not
    /// date the entries themselves. `None` for an observation that this rail retained before it
    /// kept the time, and for an RPC that does not state it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closed_at: Option<u64>,
}
/// The admission read of [`trusted_state`] with the close time of its ledger
/// ([`DiscoveredState::closed_at`]).
pub fn trusted_state_observed(
    rpc: &dyn Rpc,
    c: &WalletConfig,
    accounting: Option<NativeAccounting>,
) -> Result<DiscoveredState> {
    trusted_state_inner(rpc, c, accounting, true)
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
/// The fault of a wallet whose params on the ledger are not the ones that its deployment stores.
pub const PARAMS_DIFFER: &str = "policy wallet params differ from the installation";
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
    // The same reply states when that ledger closed.
    let closed_at = unix_seconds(&latest, "closeTime", "Invalid ledger close time")?;
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
            closed_at,
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
    let mut observed = if c.route == WalletRoute::PolicyWallet {
        current_wallet_state(
            rpc,
            c,
            state,
            module.0,
            ledger,
            accounting,
            require_customer_quorum,
        )?
    } else {
        historical_wallet_state(rpc, c, state, module.0, ledger, require_customer_quorum)?
    };
    observed.closed_at = closed_at;
    Ok(observed)
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
        // The wallet holds exactly the params that its deployment stores: an update outside
        // Allowit that dropped or added one leaves a wallet that admits nothing. Discovery still
        // reports it, so its owner can pause or stop it.
        if config.params != crate::installed_params(c) {
            return Err(PARAMS_DIFFER.into());
        }
        // An operation repays gas under the wallet's current gas cap, which the owner can change
        // on the ledger. An installation with another gas cap would price repayments that the
        // wallet refuses, so it is verified again first. Owner actions do not depend on it.
        if config.gas_cap != i128::from(c.max_fee_stroops) {
            return Err(
                "The wallet's gas cap differs from this installation. Verify the installation first."
                    .into(),
            );
        }
    }
    let figures = figures(rpc, c, ledger)?;
    // A wallet that gives every figure needs no account of the server's.
    let accounting = accounting.filter(|_| !crate::wallet_gives_every_figure(c));
    // The server's account of the figures that the wallet does not give: a Simple wallet gives
    // none, a Common wallet those of its rules with params, and a Custom wallet whose source has
    // a server part the figures that Core names for its on-chain part. The decision is by figure,
    // not by wallet entry: an entry can hold one figure that the wallet gives and one that it
    // does not. An execution needs it; discovery reports the
    // wallet's own figures without it.
    if require_customer_quorum && accounting.is_none() && !crate::wallet_gives_every_figure(c) {
        return Err(
            "This wallet needs the server's accounting of the figures that it does not keep".into(),
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
        closed_at: None,
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
/// A Custom policy's own state entries at `ledger`: each key that the build of its on-chain part
/// declares, read from its short storage key. A daily entry whose window ended and a persistent entry without a
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
    for entry in crate::custom_wallet_state_entries(&c.policy_source)? {
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
    Ok(DiscoveredState {
        state: out,
        paused,
        closed_at: None,
    })
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

    const SOURCE: &str = "use allowit::prelude::*;\n/// Count each payment, today and in all.\npub fn execute(ctx: &AllowitContext) -> allowit::Result {\n    // get_state and set_state in a comment are no calls: set_state(ctx, nothing)\n    let note = \"set_state(ctx, \\\"not_a_key\\\", 1)\";\n    let _ = note;\n    let today: u64 = allowit::get_state(ctx, \"day_payments\")?.unwrap_or(0);\n    let all = allowit::get_state::<u64>(ctx, \"payments\")?.unwrap_or(0);\n    let _spent: i128 = allowit::get_state(ctx, \"spent\")?.unwrap_or(0);\n    allowit::r#set_state(ctx, \"day_payments\", today + 1)?;\n    allowit::set_state(ctx, \"payments\", all + 1)?;\n    Ok(())\n}\n";

    /// Each figure that Core names has its wallet entry; a daily flag alone opens the daily entry.
    #[test]
    fn each_figure_has_its_wallet_entry() {
        use crate::state_keys::packed;
        let all = [
            "calls",
            "spent",
            "unpriced",
            "day_spent",
            "day_total",
            "day_unpriced",
        ];
        assert_eq!(packed(all), Ok(packed::ALL));
        assert_eq!(packed(["unpriced"]), Ok(packed::SPENT));
        assert_eq!(packed(["day_unpriced"]), Ok(packed::DAY_SPENT));
        assert_eq!(packed(["day_total", "day_unpriced"]), Ok(packed::DAY_TOTAL));
        assert_eq!(packed([]), Ok(0));
        assert!(packed(["day"]).unwrap_err().contains("no figure"));
    }

    /// The wallet stores the keys that Core gives the chain, each with Stellar's storage key; a
    /// read of a standard figure stores no entry of the policy's own. Stellar's storage refuses
    /// a key that is no `Symbol`, a standard figure, more than eight keys and a malformed line of
    /// a state file.
    #[test]
    fn the_wallet_stores_the_keys_that_core_gives_the_chain() {
        let entries = crate::custom_wallet_state_entries(SOURCE).unwrap();
        let names: Vec<(&str, bool)> = entries.iter().map(|e| (e.name.as_str(), e.daily)).collect();
        assert_eq!(names, [("day_payments", true), ("payments", false)]);
        assert_eq!(entries[0].key, 0x6df2_15e2);
        let hash = |name: &[u8]| crate::hash(name);
        for (key, refused) in [
            ("spent", "no state key"),
            ("a-b", "no state key"),
            ("", "no state key"),
            ("x".repeat(33).leak() as &str, "no state key"),
        ] {
            let error = crate::state_keys::entries([(key, false)], hash).unwrap_err();
            assert!(error.contains(refused), "{key}: {error}");
        }
        let nine: Vec<String> = (0..9).map(|i| format!("k{i}")).collect();
        assert!(
            crate::state_keys::entries(nine.iter().map(|k| (k.as_str(), false)), hash)
                .unwrap_err()
                .contains("at most 8")
        );
        assert_eq!(
            crate::state_keys::state_file("day_paid daily\nseen lasting\n"),
            Ok(vec![("day_paid", true), ("seen", false)])
        );
        assert!(crate::state_keys::state_file("seen\n").is_err());
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
        // The window is Core's: open through its last ledger, closed one ledger later.
        for ledger in [99, 100, 101] {
            assert_eq!(
                packed::state_value(&daily, true, ledger).unwrap().is_some(),
                allowit_core::daily_window_open(100, u64::from(ledger))
            );
        }
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
        let entries = crate::custom_wallet_state_entries(SOURCE).unwrap();
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
mod owner_read_tests {
    use super::*;
    use std::sync::Mutex;

    /// An endpoint whose head reads answer `heads` in order, the last one again after them, and
    /// whose entry read answers `entries`.
    struct Endpoint {
        heads: Mutex<Vec<u32>>,
        entries: Value,
        calls: Mutex<Vec<String>>,
    }
    impl Rpc for Endpoint {
        fn call(&self, method: &str, _: Value) -> Result<Value> {
            self.calls.lock().unwrap().push(method.into());
            match method {
                "getLatestLedger" => {
                    let mut heads = self.heads.lock().unwrap();
                    let head = if heads.len() > 1 {
                        heads.remove(0)
                    } else {
                        heads[0]
                    };
                    Ok(json!({ "sequence": head }))
                }
                "getLedgerEntries" => Ok(self.entries.clone()),
                _ => Err(format!("Unexpected call {method}")),
            }
        }
    }
    fn endpoint(heads: &[u32], entries: Value) -> Endpoint {
        Endpoint {
            heads: Mutex::new(heads.to_vec()),
            entries,
            calls: Mutex::new(Vec::new()),
        }
    }
    fn address(seed: u8) -> String {
        ed25519::PublicKey([seed; 32]).to_string()
    }
    fn account_id(seed: u8) -> AccountId {
        AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([seed; 32])))
    }

    /// An absent account is an observation of the head: its reply is dated, not older than the
    /// head that was read before it and not ahead of the head that is read after it.
    #[test]
    fn an_absent_account_is_an_observation_of_the_head() {
        let absent = |heads: &[u32], entries: Value| {
            let rpc = endpoint(heads, entries);
            let present = account_present(&rpc, &address(7));
            (present, rpc.calls.into_inner().unwrap())
        };
        // A reply that finds no account, then the head, the account again and the closing head.
        let bracket = [
            "getLedgerEntries",
            "getLatestLedger",
            "getLedgerEntries",
            "getLatestLedger",
        ]
        .map(String::from)
        .to_vec();
        // The three forms of a reply that finds no entry.
        for entries in [
            json!({"latestLedger": 120, "entries": []}),
            json!({"latestLedger": 120}),
            json!({"latestLedger": 120, "entries": null}),
        ] {
            assert_eq!(absent(&[120], entries), (Ok(false), bracket.clone()));
        }
        // A reply of the closing head, which moved since the head before it.
        assert_eq!(
            absent(&[120, 121], json!({"latestLedger": 121, "entries": []})).0,
            Ok(false)
        );
        // The reply of an earlier ledger than the head that was read before it, of a ledger
        // that the head has not reached, of a ledger that the head left one ledger behind (the
        // account could exist again in it), and of one that it left far behind.
        for (heads, dated) in [
            (&[120, 120][..], 119),
            (&[120, 120], 121),
            (&[120, 121], 120),
            (&[120, 127], 121),
        ] {
            assert_eq!(
                absent(heads, json!({"latestLedger": dated, "entries": []})).0,
                Err(owner_observation::STALE_OBSERVATION.to_owned()),
                "{heads:?} {dated}"
            );
        }
        // An absence without its ledger has no date, and a reply that is no list is no answer.
        assert!(absent(&[120], json!({"entries": []})).0.is_err());
        assert!(absent(&[120], json!({"entries": 1})).0.is_err());
    }

    fn usdc(issuer: u8) -> Asset {
        Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4(*b"USDC"),
            issuer: account_id(issuer),
        })
    }
    /// The trustline entry of the account `holder` for USDC of `issuer`: 9 units, 3 of them
    /// held by an open offer.
    fn line(holder: u8, issuer: u8) -> Value {
        let Asset::CreditAlphanum4(asset) = usdc(issuer) else {
            unreachable!()
        };
        let entry = LedgerEntryData::Trustline(TrustLineEntry {
            account_id: account_id(holder),
            asset: TrustLineAsset::CreditAlphanum4(asset),
            balance: 9,
            limit: i64::MAX,
            flags: 1,
            ext: TrustLineEntryExt::V1(TrustLineEntryV1 {
                liabilities: Liabilities {
                    buying: 0,
                    selling: 3,
                },
                ext: TrustLineEntryV1Ext::V0,
            }),
        });
        json!({ "xdr": xdr(&entry).unwrap() })
    }

    /// A trustline read gives the balance of the line that was asked for, and of no other; a
    /// reply that finds no entry is no trustline.
    #[test]
    fn a_trustline_read_is_of_the_line_that_was_asked_for() {
        let read = |entries: Value| {
            let rpc = endpoint(&[120], entries);
            (
                trustline_balance(&rpc, &address(7), &usdc(5)),
                trustline_spendable(&rpc, &address(7), &usdc(5)),
            )
        };
        assert_eq!(
            read(json!({"latestLedger": 120, "entries": [line(7, 5)]})),
            (Ok(Some(9)), Ok(Some(6)))
        );
        // The three forms of a reply that finds no entry.
        for none in [
            json!({"latestLedger": 120, "entries": []}),
            json!({"latestLedger": 120}),
            json!({"latestLedger": 120, "entries": null}),
        ] {
            assert_eq!(read(none), (Ok(None), Ok(None)));
        }
        // The line of another account, the line of another issuer's asset, and two lines.
        for other in [
            json!([line(8, 5)]),
            json!([line(7, 6)]),
            json!([line(7, 5), line(7, 5)]),
        ] {
            let (balance, spendable) = read(json!({"latestLedger": 120, "entries": other}));
            assert!(balance.is_err() && spendable.is_err(), "{other}");
        }
        // A reply with neither a list nor a ledger is no answer.
        let (balance, spendable) = read(json!({}));
        assert!(balance.is_err() && spendable.is_err());
        // XLM has no trustline.
        let rpc = endpoint(&[120], json!({}));
        assert!(trustline_balance(&rpc, &address(7), &Asset::Native).is_err());
        assert!(rpc.calls.lock().unwrap().is_empty());
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
