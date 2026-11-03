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
    owner_observation::network(rpc, network)?;
    let before = owner_observation::head(rpc)?;
    let value = rpc.call("getLedgerEntries", json!({"keys":[xdr(&key)?]}))?;
    let observed = owner_observation::ledger(&value["latestLedger"])?;
    let entries = value["entries"]
        .as_array()
        .ok_or("Missing native entries")?;
    let result = match entries.as_slice() {
        [] => false,
        [entry] => {
            if entry
                .get("key")
                .is_some_and(|v| v.as_str() != xdr(&key).ok().as_deref())
            {
                return Err("Native observation key differs".into());
            }
            let data: LedgerEntryData =
                read(entry["xdr"].as_str().ok_or("Missing native entry XDR")?)?;
            let matches = match (&key, data) {
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
            if owner_observation::ledger(&entry["liveUntilLedgerSeq"])? < observed {
                return Err("Native resource is archived or expired".into());
            }
            true
        }
        _ => return Err("Unexpected native entry count".into()),
    };
    owner_observation::current(rpc, before, observed)?;
    Ok(result)
}
/// Result of observing the original owner transaction. NeverApplied needs continuous native
/// RPC history from preparation through a ledger closed after the transaction's expiry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OwnerSettlement {
    Settled(VerifiedReceipt),
    NeverApplied,
    Unknown,
}
pub fn owner_settlement(
    rpc: &dyn Rpc,
    network: &str,
    original_xdr: &str,
    prepared_ledger: u32,
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
            let number = |field: &str| {
                reply[field]
                    .as_str()
                    .and_then(|s| s.parse::<u64>().ok())
                    .or_else(|| reply[field].as_u64())
            };
            let bounds = match &envelope.tx.cond {
                Preconditions::Time(b) => Some(b),
                Preconditions::V2(p) => p.time_bounds.as_ref(),
                _ => None,
            };
            Ok(
                match (
                    bounds,
                    number("latestLedgerCloseTime"),
                    number("oldestLedger"),
                    number("latestLedger"),
                ) {
                    (Some(b), Some(close), Some(oldest), Some(latest))
                        if b.max_time.0 > 0
                            && prepared_ledger > 0
                            && close > b.max_time.0
                            && oldest > 0
                            && oldest <= u64::from(prepared_ledger)
                            && latest >= u64::from(prepared_ledger) =>
                    {
                        OwnerSettlement::NeverApplied
                    }
                    _ => OwnerSettlement::Unknown,
                },
            )
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
