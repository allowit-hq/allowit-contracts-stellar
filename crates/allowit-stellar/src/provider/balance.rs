//! The `balance` evidence function of the Stellar rail: what an address holds of an asset now.
//!
//! A client reads a wallet's balance with it, as it reads a price with [`super::price`]: read-only
//! requests to Stellar RPC that need no key, no server and no credit, and move nothing. The
//! balance is what the holder can send now:
//!
//! - a contract wallet holds the asset in the asset's contract: one read-only simulation of that
//!   contract's own `balance`, all of which the wallet can send;
//! - an account (a Native wallet) holds XLM in its account entry and an issued asset in its
//!   trustline: the account's XLM less the reserve of its entries and what its offers sell, or
//!   the trustline less what its offers sell. `total` is the whole holding.
//!
//! Amounts are base units: every Stellar asset has seven decimals.
use super::price::classic;
use crate as native;
use serde_json::{Value, json};

/// The name that hosts look the function up by.
pub const FUNCTION: &str = "balance";
/// The decimals of every Stellar asset contract.
pub const DECIMALS: u32 = 7;
/// The longest that one RPC call of the read waits: a client prints the read beside other
/// output, so a slow RPC delays that output by at most a few of these.
pub const CALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// One balance observation, in the shape that hosts read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Holding {
    /// The contract id of the asset.
    pub asset: String,
    /// The asset's code when this rail lists it, such as `XLM`.
    pub asset_code: Option<String>,
    pub holder: String,
    /// What the holder can send now, in base units.
    pub balance: i128,
    /// What the holder holds, in base units: above `balance` by an account's reserve and what
    /// its offers sell.
    pub total: i128,
    /// The ledger that the read saw.
    pub ledger: u32,
    /// Close time of the newest ledger after the read: at or after `ledger`.
    pub observed_at: u64,
    pub source: String,
}

impl Holding {
    pub fn to_json(&self) -> Value {
        json!({
            "asset": self.asset,
            "assetCode": self.asset_code,
            "holder": self.holder,
            "balance": self.balance.to_string(),
            "total": self.total.to_string(),
            "decimals": DECIMALS,
            "ledger": self.ledger,
            "observedAt": self.observed_at,
            "source": self.source,
        })
    }
}

/// The asset contract that `asset` names on `network`, with its code and classic identity when
/// this rail lists it: `native`, a listed code such as `USDC`, `CODE:ISSUER`, or a contract id.
/// The contract id of an asset that this rail does not list is read as it is: any SEP-41
/// contract answers `balance`.
type Named = (String, Option<String>, Option<native::Asset>);
fn asset_contract(network: &str, asset: &str) -> Result<Named, String> {
    if let Ok(found) = classic(network, asset) {
        let identity = match &found.issuer {
            None => native::Asset::Native,
            Some(issuer) => native::asset_from_identity(&found.code, Some(issuer))?,
        };
        return Ok((
            native::sac_address(network, &identity)?,
            Some(found.code),
            Some(identity),
        ));
    }
    if stellar_strkey::Contract::from_string(asset).is_ok() {
        return Ok((asset.to_owned(), None, None));
    }
    Err(format!(
        "{asset} names no asset of this rail; name it by its code, as CODE:ISSUER or by its contract"
    ))
}

/// Observe what `holder`, an account or a contract, holds of `asset` on `network` now.
pub fn observe(
    rpc: &dyn crate::rpc::Rpc,
    network: &str,
    holder: &str,
    asset: &str,
) -> Result<Holding, String> {
    let holder_address = native::address(holder)?;
    let (contract, asset_code, identity) = asset_contract(network, asset)?;
    let account = stellar_strkey::ed25519::PublicKey::from_string(holder).is_ok();
    let no_balance = |e: String| format!("The asset {contract} gave no balance of {holder}: {e}");
    let (balance, total, ledger) = match (account, identity) {
        // An account's XLM: its account entry, less its reserve and its offers.
        (true, Some(native::Asset::Native)) => {
            crate::rpc::owner_observation::network(rpc, network).map_err(no_balance)?;
            let held = crate::rpc::native_balance(rpc, holder).map_err(no_balance)?;
            let ledger = crate::rpc::owner_observation::head(rpc).map_err(no_balance)?;
            (
                i128::from(held.spendable(0)),
                i128::from(held.balance),
                ledger,
            )
        }
        // An account's issued asset: its trustline, less its offers; none without one.
        (true, Some(issued)) => {
            crate::rpc::owner_observation::network(rpc, network).map_err(no_balance)?;
            let total = crate::rpc::trustline_balance(rpc, holder, &issued).map_err(no_balance)?;
            let spendable =
                crate::rpc::trustline_spendable(rpc, holder, &issued).map_err(no_balance)?;
            let ledger = crate::rpc::owner_observation::head(rpc).map_err(no_balance)?;
            (
                i128::from(spendable.unwrap_or(0)),
                i128::from(total.unwrap_or(0)),
                ledger,
            )
        }
        // A contract wallet, or an asset that this rail does not list: the contract's balance.
        _ => {
            let (value, ledger) = crate::rpc::contract_read(
                rpc,
                network,
                &contract,
                "balance",
                vec![stellar_xdr::ScVal::Address(holder_address)],
            )
            .map_err(no_balance)?;
            let balance = native::rpc::wide(&value)?;
            (balance, balance, ledger)
        }
    };
    if balance < 0 || total < balance {
        return Err(format!(
            "The asset {contract} reports an inconsistent balance of {holder}"
        ));
    }
    let head = rpc
        .call("getLatestLedger", json!({}))
        .map_err(|e| format!("Stellar RPC gave no ledger time: {e}"))?;
    let observed_at = head["closeTime"]
        .as_str()
        .and_then(|t| t.parse().ok())
        .or_else(|| head["closeTime"].as_u64())
        .ok_or("Stellar RPC gave no ledger time")?;
    Ok(Holding {
        source: format!("{contract} balance at ledger {ledger}"),
        asset: contract,
        asset_code,
        holder: holder.to_owned(),
        balance,
        total,
        ledger,
        observed_at,
    })
}

/// The evidence function. `args` are `{"network", "holder", "asset"}`; `facts` are the host's
/// own: its `network` decides, and it may name its Stellar RPC as `rpc`.
#[cfg(not(target_arch = "wasm32"))]
pub fn balance(args: &Value, facts: &Value) -> Result<Value, String> {
    let text = |name: &str| {
        args[name]
            .as_str()
            .ok_or_else(|| format!("A balance observation needs `{name}`"))
    };
    let network = match (facts["network"].as_str(), args["network"].as_str()) {
        (Some(host), Some(asked)) if host != asked => {
            return Err("A balance observation is for the network of its host".into());
        }
        (Some(network), _) | (None, Some(network)) => network,
        (None, None) => return Err("A balance observation needs `network`".into()),
    };
    let (holder, asset) = (text("holder")?, text("asset")?);
    let endpoint = match facts["rpc"].as_str() {
        Some(endpoint) => endpoint,
        None => super::price::public_rpc(network)?,
    };
    let rpc = crate::rpc::HttpRpc::with_timeout(endpoint, CALL_TIMEOUT)?;
    Ok(observe(&rpc, network, holder, asset)?.to_json())
}

#[cfg(test)]
mod tests {
    use super::*;

    const NETWORK: &str = "stellar:testnet";

    /// A Stellar RPC that answers the read-only simulation of an asset contract's `balance`, and
    /// the ledger entries of an account (`entries`).
    struct BalanceRpc {
        held: i128,
        entries: Value,
        asked: std::sync::Mutex<Vec<(String, String)>>,
    }
    impl crate::rpc::Rpc for BalanceRpc {
        fn call(&self, method: &str, params: Value) -> native::Result<Value> {
            use stellar_xdr::{HostFunction, OperationBody, ScVal, TransactionEnvelope};
            match method {
                "getNetwork" => Ok(json!({"passphrase": native::passphrase(NETWORK)?})),
                "getLatestLedger" => Ok(json!({"sequence": 101, "closeTime": "1795003303"})),
                "getLedgerEntries" => {
                    self.asked
                        .lock()
                        .unwrap()
                        .push(("ledger".into(), "entries".into()));
                    Ok(self.entries.clone())
                }
                "simulateTransaction" => {
                    let TransactionEnvelope::Tx(envelope) =
                        native::read(params["transaction"].as_str().unwrap())?
                    else {
                        panic!("a version 1 envelope");
                    };
                    let OperationBody::InvokeHostFunction(op) = &envelope.tx.operations[0].body
                    else {
                        panic!("one contract call");
                    };
                    let HostFunction::InvokeContract(call) = &op.host_function else {
                        panic!("one contract call");
                    };
                    let function = String::from_utf8(call.function_name.0.to_vec()).unwrap();
                    let ScVal::Address(holder) = &call.args[0] else {
                        panic!("the holder's address");
                    };
                    self.asked.lock().unwrap().push((
                        native::address_text(&call.contract_address)?,
                        format!("{function}({})", native::address_text(holder)?),
                    ));
                    Ok(json!({
                        "latestLedger": 100,
                        "results": [{"auth": [], "xdr": native::xdr(&native::i128_value(self.held))?}],
                    }))
                }
                other => panic!("unexpected RPC method {other}"),
            }
        }
    }
    fn rpc(held: i128) -> BalanceRpc {
        BalanceRpc {
            held,
            entries: json!({"entries": []}),
            asked: Default::default(),
        }
    }

    #[test]
    fn a_contract_wallet_balance_is_the_asset_contracts_own_balance() {
        let xlm = native::sac_address(NETWORK, &native::Asset::Native).unwrap();
        let wallet = stellar_strkey::Contract([9; 32]).to_string();
        for asset in ["XLM", "native", &xlm] {
            let rpc = rpc(5_000_000_000);
            let held = observe(&rpc, NETWORK, &wallet, asset).unwrap();
            assert_eq!((held.balance, held.total), (5_000_000_000, 5_000_000_000));
            assert_eq!(held.asset, xlm);
            assert_eq!(held.asset_code.as_deref(), Some("XLM"));
            assert_eq!((held.ledger, held.observed_at), (100, 1_795_003_303));
            assert_eq!(held.source, format!("{xlm} balance at ledger 100"));
            assert_eq!(
                *rpc.asked.lock().unwrap(),
                [(xlm.clone(), format!("balance({wallet})"))]
            );
            let out = held.to_json();
            assert_eq!(out["balance"], "5000000000");
            assert_eq!(out["decimals"], 7);
        }
    }

    #[test]
    fn an_account_can_send_its_xlm_less_its_reserve_and_no_issued_asset_without_a_trustline() {
        let owner = crate::test_support::owner::fresh(crate::rpc::NULL_ACCOUNT);
        let mut accounts = rpc(0);
        accounts.entries = crate::test_support::owner::account_entry(&owner);
        let held = observe(&accounts, NETWORK, crate::rpc::NULL_ACCOUNT, "native").unwrap();
        // 10,000 XLM, of which the two base reserves of an account without entries stay.
        assert_eq!(held.total, 100_000_000_000);
        assert_eq!(
            held.balance,
            100_000_000_000 - 2 * crate::owner::BASE_RESERVE_STROOPS as i128
        );
        assert_eq!(held.ledger, 101);
        assert_eq!(held.to_json()["total"], "100000000000");
        // An issued asset without a trustline: nothing to send.
        let usdc = super::super::tokens_for(NETWORK)
            .iter()
            .find(|t| t.issuer.is_some())
            .expect("an issued token on Testnet")
            .code;
        let held = observe(&rpc(0), NETWORK, crate::rpc::NULL_ACCOUNT, usdc).unwrap();
        assert_eq!((held.balance, held.total), (0, 0));
    }

    #[test]
    fn an_unlisted_contract_is_read_as_it_is() {
        let token = stellar_strkey::Contract([3; 32]).to_string();
        let held = observe(&rpc(0), NETWORK, crate::rpc::NULL_ACCOUNT, &token).unwrap();
        assert_eq!(
            (held.asset.as_str(), held.asset_code),
            (token.as_str(), None)
        );
        assert_eq!(held.balance, 0);
    }

    #[test]
    fn the_function_refuses_bad_arguments_before_any_request() {
        let wallet = stellar_strkey::Contract([9; 32]).to_string();
        for (args, facts) in [
            (json!({"holder": wallet, "asset": "XLM"}), json!({})),
            (json!({"network": NETWORK, "asset": "XLM"}), json!({})),
            (json!({"network": NETWORK, "holder": wallet}), json!({})),
            (
                json!({"network": NETWORK, "holder": wallet, "asset": "XLM"}),
                json!({"network": "stellar:pubnet"}),
            ),
        ] {
            assert!(balance(&args, &facts).is_err(), "{args} {facts}");
        }
        assert!(observe(&rpc(1), NETWORK, "not an address", "XLM").is_err());
        assert!(observe(&rpc(1), NETWORK, &wallet, "NOPE").is_err());
        assert!(observe(&rpc(-1), NETWORK, &wallet, "XLM").is_err());
    }
}
