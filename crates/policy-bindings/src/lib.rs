//! Policy-callable metadata for the installed Stellar rail.

pub mod approval;
#[cfg(feature = "horizon-price")]
pub mod horizon;
pub mod networks;

use serde::Deserialize;
use serde_json::{Value, json};

type Invoke = fn(&Value, &Value) -> Result<Value, String>;
type Test = fn() -> Result<(), String>;

/// Register this trusted rail pack with the host's policy engine.
pub fn bindings() -> (&'static str, [(&'static str, Invoke); 1], Test) {
    ("stellar", [("network", network as Invoke)], self_test)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Network<'a> {
    network: &'a str,
}

fn network(args: &Value, _: &Value) -> Result<Value, String> {
    let args = Network::deserialize(args).map_err(|_| "Supply one Stellar network.")?;
    let network = networks::resolve(args.network).ok_or("Unsupported Stellar network.")?;
    Ok(json!({"network": network.id, "testnet": network.testnet}))
}

fn self_test() -> Result<(), String> {
    let pubnet = network(&json!({"network": "stellar:mainnet"}), &Value::Null)?;
    if pubnet != json!({"network": "stellar:pubnet", "testnet": false})
        || network(&json!({"network": "solana:mainnet"}), &Value::Null).is_ok()
    {
        return Err("Stellar policy bindings returned invalid network metadata.".into());
    }
    Ok(())
}

#[cfg(test)]
#[test]
fn exported_binding_test() {
    (bindings().2)().unwrap();
}
