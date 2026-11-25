//! The `balance` evidence function of the Stellar rail: what an address holds of an asset now.
//!
//! A client reads a wallet's balance with it, as it reads a price with [`super::price`]: one
//! read-only simulation of the asset contract's own `balance` on Stellar RPC. The read needs no
//! key, no server and no credit, and it moves nothing. Every Stellar asset has a contract that
//! answers `balance` for every holder: a contract wallet holds the asset in that contract, and the
//! contract reads an account's XLM or its trustline for a Native wallet. Amounts are base units:
//! every Stellar asset contract has seven decimals.
use super::price::classic;
use crate as native;
use serde_json::{Value, json};

/// The name that hosts look the function up by.
pub const FUNCTION: &str = "balance";
/// The decimals of every Stellar asset contract.
pub const DECIMALS: u32 = 7;

/// One balance observation, in the shape that hosts read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Holding {
    /// The contract id of the asset.
    pub asset: String,
    /// The asset's code when this rail lists it, such as `XLM`.
    pub asset_code: Option<String>,
    pub holder: String,
    /// What the holder holds, in base units.
    pub balance: i128,
    /// Close time of the newest ledger when the balance was read.
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
            "decimals": DECIMALS,
            "observedAt": self.observed_at,
            "source": self.source,
        })
    }
}

/// The asset contract that `asset` names on `network`, with its code when this rail lists it:
/// `native`, a listed code such as `USDC`, `CODE:ISSUER`, or a contract id. The contract id of
/// an asset that this rail does not list is read as it is: any SEP-41 contract answers `balance`.
fn asset_contract(network: &str, asset: &str) -> Result<(String, Option<String>), String> {
    if let Ok(found) = classic(network, asset) {
        let identity = match &found.issuer {
            None => native::Asset::Native,
            Some(issuer) => native::asset_from_identity(&found.code, Some(issuer))?,
        };
        return Ok((native::sac_address(network, &identity)?, Some(found.code)));
    }
    if stellar_strkey::Contract::from_string(asset).is_ok() {
        return Ok((asset.to_owned(), None));
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
    let (contract, asset_code) = asset_contract(network, asset)?;
    let (value, ledger) = crate::rpc::contract_read(
        rpc,
        network,
        &contract,
        "balance",
        vec![stellar_xdr::ScVal::Address(holder_address)],
    )
    .map_err(|e| format!("The asset {contract} gave no balance of {holder}: {e}"))?;
    let balance = native::rpc::wide(&value)?;
    if balance < 0 {
        return Err(format!("The asset {contract} reports a negative balance"));
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
    let rpc = crate::rpc::HttpRpc::new(endpoint)?;
    Ok(observe(&rpc, network, holder, asset)?.to_json())
}

#[cfg(test)]
mod tests {
    use super::*;

    const NETWORK: &str = "stellar:testnet";

    /// A Stellar RPC that answers the read-only simulation of an asset contract's `balance`.
    struct BalanceRpc {
        held: i128,
        asked: std::sync::Mutex<Vec<(String, String)>>,
    }
    impl crate::rpc::Rpc for BalanceRpc {
        fn call(&self, method: &str, params: Value) -> native::Result<Value> {
            use stellar_xdr::{HostFunction, OperationBody, ScVal, TransactionEnvelope};
            match method {
                "getNetwork" => Ok(json!({"passphrase": native::passphrase(NETWORK)?})),
                "getLatestLedger" => Ok(json!({"sequence": 101, "closeTime": "1795003303"})),
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
            asked: Default::default(),
        }
    }

    #[test]
    fn a_wallet_balance_is_the_asset_contracts_own_balance() {
        let xlm = native::sac_address(NETWORK, &native::Asset::Native).unwrap();
        let wallet = stellar_strkey::Contract([9; 32]).to_string();
        let account = crate::rpc::NULL_ACCOUNT;
        for (holder, asset) in [(&*wallet, "XLM"), (&*wallet, "native"), (account, &*xlm)] {
            let rpc = rpc(5_000_000_000);
            let held = observe(&rpc, NETWORK, holder, asset).unwrap();
            assert_eq!(held.balance, 5_000_000_000);
            assert_eq!(held.asset, xlm);
            assert_eq!(held.asset_code.as_deref(), Some("XLM"));
            assert_eq!(held.observed_at, 1_795_003_303);
            assert_eq!(held.source, format!("{xlm} balance at ledger 100"));
            assert_eq!(
                *rpc.asked.lock().unwrap(),
                [(xlm.clone(), format!("balance({holder})"))]
            );
            let out = held.to_json();
            assert_eq!(out["balance"], "5000000000");
            assert_eq!(out["decimals"], 7);
        }
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
