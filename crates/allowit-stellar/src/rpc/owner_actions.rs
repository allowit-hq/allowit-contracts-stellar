//! Native observations and original-owner-packet settlement. No polling, retries or storage.
use super::*;

/// Whether an exact code entry is currently live. False does not prove it never existed.
pub fn code_uploaded(rpc: &dyn Rpc, network: &str, code: &[u8; 32]) -> Result<bool> {
    if *code == [0; 32] {
        return Err("Missing executable identity".into());
    }
    live_entry(
        rpc,
        network,
        LedgerKey::ContractCode(LedgerKeyContractCode { hash: Hash(*code) }),
    )
}
/// The state of an exact code entry on the network.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodeState {
    /// Live at the closing observation.
    Live,
    /// Past its lifetime, on the ledger or in the network's archive. A restoration of the entry
    /// makes it live again; an upload of the same code can fail once the network archived it.
    Lapsed,
    /// Not on the network. This does not prove that it never existed.
    Absent,
}
/// Whether an exact code entry is live, lapsed or absent.
pub fn code_state(rpc: &dyn Rpc, network: &str, code: &[u8; 32]) -> Result<CodeState> {
    code_observation(rpc, network, code).map(|(state, _)| state)
}
/// As `code_state`, for a decision to pay for a transaction that only code that is not live
/// needs. An RPC node can serve an entry some ledgers behind the closing head, which can miss a
/// transaction that made the code live meanwhile. A negative answer must be dated at the closing
/// head: a read that trails it, or that trails the head read before it, is taken once more, and
/// a second one that trails is refused.
pub fn current_code_state(rpc: &dyn Rpc, network: &str, code: &[u8; 32]) -> Result<CodeState> {
    for attempt in 0..2 {
        match code_observation(rpc, network, code) {
            Ok((CodeState::Live, _)) => return Ok(CodeState::Live),
            Ok((state, true)) => return Ok(state),
            Ok((_, false)) => {}
            Err(stale) if attempt == 0 && stale == owner_observation::STALE_OBSERVATION => {}
            Err(error) => return Err(error),
        }
    }
    Err("The observation of the wallet code trails the network's head".into())
}
/// The state of an exact code entry and whether its observation is dated at the closing head.
fn code_observation(rpc: &dyn Rpc, network: &str, code: &[u8; 32]) -> Result<(CodeState, bool)> {
    if *code == [0; 32] {
        return Err("Missing executable identity".into());
    }
    let key = LedgerKey::ContractCode(LedgerKeyContractCode { hash: Hash(*code) });
    let (live_until, observed, closing) = dated_entry(rpc, network, &key)?;
    let state = match live_until {
        None => CodeState::Absent,
        Some(until) if until >= closing => CodeState::Live,
        Some(_) => CodeState::Lapsed,
    };
    Ok((state, observed == closing))
}
/// Whether a native C-address currently has a live Wasm instance. This grants no trust in its config.
pub fn contract_exists(rpc: &dyn Rpc, network: &str, contract: &str) -> Result<bool> {
    Contract::from_string(contract).map_err(err)?;
    live_entry(
        rpc,
        network,
        LedgerKey::ContractData(LedgerKeyContractData {
            contract: address(contract)?,
            key: ScVal::LedgerKeyContractInstance,
            durability: ContractDataDurability::Persistent,
        }),
    )
}
fn live_entry(rpc: &dyn Rpc, network: &str, key: LedgerKey) -> Result<bool> {
    let (live_until, closing) = observed_entry(rpc, network, &key)?;
    if live_until.is_some_and(|until| until < closing) {
        return Err("Native resource is archived or expired at the closing observation".into());
    }
    Ok(live_until.is_some())
}
/// The live-until ledger of the verified entry of `key`, `None` when the network has no such
/// entry, and the closing head of the observation. An archived entry that the RPC serves without
/// a live-until ledger reads as 0.
fn observed_entry(rpc: &dyn Rpc, network: &str, key: &LedgerKey) -> Result<(Option<u32>, u32)> {
    dated_entry(rpc, network, key).map(|(live_until, _, closing)| (live_until, closing))
}
/// As `observed_entry`, with the ledger that dates the entry between the live-until ledger and
/// the closing head.
fn dated_entry(rpc: &dyn Rpc, network: &str, key: &LedgerKey) -> Result<(Option<u32>, u32, u32)> {
    owner_observation::network(rpc, network)?;
    let before = owner_observation::head(rpc)?;
    let value = rpc.call("getLedgerEntries", json!({"keys":[xdr(key)?]}))?;
    let observed = owner_observation::ledger(&value["latestLedger"])?;
    // A reply that finds no entry can omit the list.
    let none = Vec::new();
    let entries = match value.get("entries") {
        None | Some(Value::Null) => &none,
        Some(entries) => entries.as_array().ok_or("Invalid native entries")?,
    };
    let live_until = match entries.as_slice() {
        [] => None,
        [entry] => {
            if entry
                .get("key")
                .is_some_and(|v| v.as_str() != xdr(key).ok().as_deref())
            {
                return Err("Native observation key differs".into());
            }
            let data: LedgerEntryData =
                read(entry["xdr"].as_str().ok_or("Missing native entry XDR")?)?;
            let matches = match (key, data) {
                (LedgerKey::ContractCode(expected), LedgerEntryData::ContractCode(actual)) => {
                    actual.hash == expected.hash && hash(actual.code.as_slice()) == expected.hash.0
                }
                (LedgerKey::ContractData(expected), LedgerEntryData::ContractData(actual)) => {
                    actual.contract == expected.contract
                        && actual.key == expected.key
                        && actual.durability == expected.durability
                        && matches!(
                            actual.val,
                            ScVal::ContractInstance(ScContractInstance {
                                executable: ContractExecutable::Wasm(_),
                                ..
                            })
                        )
                }
                _ => false,
            };
            if !matches {
                return Err("Native entry differs from the selected resource".into());
            }
            Some(match &entry["liveUntilLedgerSeq"] {
                Value::Null => 0,
                value if value.as_u64() == Some(0) => 0,
                value => owner_observation::ledger(value)?,
            })
        }
        _ => return Err("Unexpected native entry count".into()),
    };
    Ok((
        live_until,
        observed,
        owner_observation::current(rpc, before, observed)?,
    ))
}
/// Only a verified native receipt is terminal. A missing lookup or expiry cannot prove absence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OwnerSettlement {
    Settled(VerifiedReceipt),
    Unknown,
}
pub fn owner_settlement(
    rpc: &dyn Rpc,
    network: &str,
    original_xdr: &str,
) -> Result<OwnerSettlement> {
    owner_observation::network(rpc, network)?;
    let TransactionEnvelope::Tx(envelope) = read(original_xdr)? else {
        return Err("Expected original v1 owner transaction".into());
    };
    let digest = transaction_hash_for(network, &envelope.tx)?;
    let reply = rpc.call("getTransaction", json!({"hash":hex(&digest)}))?;
    match reply["status"].as_str() {
        Some("SUCCESS" | "FAILED") => {
            let receipt = receipt_from_response(&reply, network, &digest)?
                .ok_or("Missing terminal owner receipt")?;
            Ok(OwnerSettlement::Settled(receipt))
        }
        Some("NOT_FOUND") => {
            validate_response_identity(&reply, &digest)?;
            Ok(OwnerSettlement::Unknown)
        }
        _ => Err("Unknown native owner settlement state".into()),
    }
}
/// Read SEP-56 preview_redeem without authorizing a transfer. Missing valuation stays an error.
pub fn vault_redeemable(
    rpc: &dyn Rpc,
    config: &WalletConfig,
    source: &AccountState,
    vault: &str,
    shares: i128,
) -> Result<i128> {
    if shares < 0 {
        return Err("Vault shares must be nonnegative".into());
    }
    Contract::from_string(vault).map_err(err)?;
    owner_observation::network(rpc, &config.network)?;
    let before = owner_observation::head(rpc)?;
    let response = readonly_simulation(
        rpc,
        config,
        source,
        vault,
        "preview_redeem",
        vec![i128_value(shares)],
    )?;
    reject_restoration(&response)?;
    let entries = response["results"][0]["auth"]
        .as_array()
        .ok_or("Missing valuation authorization result")?;
    if !entries.is_empty() {
        return Err("Vault valuation requests authorization".into());
    }
    let value = wide(&readonly_result(&response)?)?;
    if value < 0 {
        return Err("Vault valuation must be nonnegative".into());
    }
    owner_observation::current(
        rpc,
        before,
        owner_observation::ledger(&response["latestLedger"])?,
    )?;
    Ok(value)
}
