//! Native retained-installation metadata and owner-envelope identity.
use crate::host::{
    error::{Error, Result},
    runtime::{
        Tier,
        owner::{Configuration, ConfigurationInfo, Custody},
    },
};
use crate::{self as native, WalletConfig, WalletRoute};

pub fn configuration(network: &str, document: &[u8]) -> Result<Configuration> {
    let c: WalletConfig = serde_json::from_slice(document)
        .map_err(|_| Error::config("Invalid retained installation"))?;
    if native::network_id(network).map_err(crate::provider::failure)?
        != native::network_id(&c.network).map_err(crate::provider::failure)?
    {
        return Err(Error::config(
            "Retained installation belongs to another network",
        ));
    }
    native::validate_retained_configuration(&c).map_err(crate::provider::failure)?;
    let custody = match c.route {
        WalletRoute::Native => Custody::Owner,
        WalletRoute::PolicyWallet => Custody::Policy,
        WalletRoute::Odc => Custody::Retired,
    };
    let is_native_asset = c.asset_symbol == "XLM" && c.asset_issuer.is_none();
    let custody_encoding =
        serde_json::to_value(&c.route).map_err(|_| Error::config("Cannot describe custody"))?;
    let tier_encoding =
        serde_json::to_value(c.tier).map_err(|_| Error::config("Cannot describe policy tier"))?;
    let info = ConfigurationInfo {
        network: c.network,
        wallet: c.wallet,
        owner: c.owner,
        agent: c.agent,
        server: c.server,
        source: c.policy_source,
        source_hash: c.source_hash,
        binding_hash: c.source_digest,
        rules: c.rules,
        is_retired: c.route == WalletRoute::Odc || c.language != native::PolicyLanguage::Portable,
        module_digest: c.module_digest,
        policy_instance: c.policy_instance,
        asset: c.asset,
        asset_symbol: c.asset_symbol,
        asset_issuer: c.asset_issuer,
        max_fee_units: u64::from(c.max_fee_stroops),
        is_native_asset,
        fee_decimals: 7,
        payment_asset_decimals: 7,
        params: c
            .params
            .0
            .into_iter()
            .map(|(k, v)| {
                v.to_core()
                    .map(|v| (k, v))
                    .map_err(crate::provider::failure)
            })
            .collect::<Result<_>>()?,
        custody,
        custody_encoding,
        tier_encoding,
        tier: c.tier.map(|tier| match tier {
            native::PolicyTier::Simple => Tier::Simple,
            native::PolicyTier::Common => Tier::Standard,
            native::PolicyTier::Custom => Tier::Custom,
        }),
    };
    let raw = serde_json::value::RawValue::from_string(
        std::str::from_utf8(document)
            .map_err(|_| Error::config("Invalid native document encoding"))?
            .into(),
    )
    .map_err(|_| Error::config("Invalid native document"))?;
    Ok(Configuration::new(info, raw))
}
pub fn envelope_hash(network: &str, payload: &[u8], require_signature: bool) -> Result<[u8; 32]> {
    let payload =
        std::str::from_utf8(payload).map_err(|_| Error::usage("Invalid owner signing payload"))?;
    native::owner_intent::owner_envelope_hash(network, payload, require_signature)
        .map_err(crate::provider::failure)
}
pub fn validate_signed(network: &str, original: &[u8], signed: &[u8]) -> Result<[u8; 32]> {
    let original: native::owner_intent::OwnerTransaction = serde_json::from_slice(original)
        .map_err(|_| Error::config("Invalid retained owner packet"))?;
    if native::network_id(network).map_err(crate::provider::failure)?
        != native::network_id(&original.network).map_err(crate::provider::failure)?
    {
        return Err(Error::config(
            "Retained owner packet belongs to another network",
        ));
    }
    let signed =
        std::str::from_utf8(signed).map_err(|_| Error::usage("Invalid signed owner payload"))?;
    native::owner_intent::validate_signed_owner_transaction(&original, signed)
        .map_err(crate::provider::failure)
}
pub fn with_policy(
    config: &Configuration,
    i: crate::host::runtime::owner::PolicyIdentity,
) -> Result<Configuration> {
    let mut c: WalletConfig = serde_json::from_slice(config.bytes())
        .map_err(|_| Error::config("Invalid retained installation"))?;
    if c.route != WalletRoute::Native {
        return Err(Error::config(
            "Installed policy-wallet identity is immutable",
        ));
    }
    let derived = native::sac_address(
        &c.network,
        &native::asset_from_identity(&i.asset_symbol, i.asset_issuer.as_deref())
            .map_err(crate::provider::failure)?,
    )
    .map_err(crate::provider::failure)?;
    if derived != i.asset {
        return Err(Error::config("Admitted asset identity differs"));
    }
    c.policy_instance = i.policy_instance;
    c.module_digest = i.module_digest;
    c.policy_source = i.source;
    c.source_hash = native::hash(&c.policy_source);
    c.params = native::PolicyParams(
        i.params
            .into_iter()
            .map(|(k, v)| {
                native::PolicyValue::from_core(&v)
                    .map(|v| (k, v))
                    .map_err(crate::provider::failure)
            })
            .collect::<Result<_>>()?,
    );
    c.asset = i.asset;
    c.asset_symbol = i.asset_symbol;
    c.asset_issuer = i.asset_issuer;
    c.agent = i.agent;
    c.server = i.server;
    c.max_fee_stroops = u32::try_from(i.max_fee_units)
        .map_err(|_| Error::usage("Fee ceiling exceeds native range"))?;
    c.language = native::PolicyLanguage::Portable;
    c.rules.clear();
    c.tier = None;
    c.source_digest = [0; 32];
    let bytes = serde_json::to_vec(&c)
        .map_err(|_| Error::config("Cannot encode new installation projection"))?;
    configuration(&c.network, &bytes)
}
/// The installation after a confirmed params update of a policy wallet.
pub fn with_params(
    config: &Configuration,
    update: &crate::host::runtime::ParamsUpdate,
) -> Result<Configuration> {
    let c: WalletConfig = serde_json::from_slice(config.bytes())
        .map_err(|_| Error::config("Invalid retained installation"))?;
    let next = super::params_update::updated_config(&c, update)?;
    let bytes = serde_json::to_vec(&next)
        .map_err(|_| Error::config("Cannot encode the updated installation"))?;
    configuration(&next.network, &bytes)
}
pub fn code_hash(wasm: &[u8]) -> Result<[u8; 32]> {
    native::admin::check_wallet_code(wasm).map_err(crate::provider::failure)
}
/// The transport of one RPC `endpoint` of `network`. See [`verified_identity`].
pub fn connect(
    network: &str,
    endpoint: &str,
) -> Result<std::sync::Arc<dyn crate::host::runtime::Transport>> {
    struct Transport(native::rpc::HttpRpc);
    impl crate::host::runtime::Transport for Transport {
        fn call(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
            native::rpc::Rpc::call(&self.0, method, params).map_err(crate::provider::failure)
        }
    }
    verified_identity(
        network,
        std::sync::Arc::new(Transport(
            native::rpc::HttpRpc::new(endpoint).map_err(crate::provider::failure)?,
        )),
    )
}
/// `inner` with the network identity that it verified. Every read and send of the rail first asks
/// the endpoint which network it serves (`getNetwork`), and one call of a host makes several of
/// them, so the transport keeps the first reply that names the passphrase of `network` and
/// answers each later `getNetwork` with it. A reply that names another network or no passphrase,
/// and an error, are returned as they came and kept nowhere: the rail's own check refuses them,
/// and the next call asks the endpoint again. Every other method goes to the endpoint.
fn verified_identity(
    network: &str,
    inner: std::sync::Arc<dyn crate::host::runtime::Transport>,
) -> Result<std::sync::Arc<dyn crate::host::runtime::Transport>> {
    struct Verified {
        inner: std::sync::Arc<dyn crate::host::runtime::Transport>,
        passphrase: &'static str,
        identity: std::sync::OnceLock<serde_json::Value>,
    }
    impl crate::host::runtime::Transport for Verified {
        fn call(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
            if method != "getNetwork" {
                return self.inner.call(method, params);
            }
            if let Some(reply) = self.identity.get() {
                return Ok(reply.clone());
            }
            let reply = self.inner.call(method, params)?;
            if reply["passphrase"].as_str() == Some(self.passphrase) {
                let _ = self.identity.set(reply.clone());
            }
            Ok(reply)
        }
    }
    Ok(std::sync::Arc::new(Verified {
        inner,
        passphrase: native::passphrase(network).map_err(crate::provider::failure)?,
        identity: std::sync::OnceLock::new(),
    }))
}
pub fn fee_bounds() -> crate::host::runtime::owner::FeeBounds {
    crate::host::runtime::owner::FeeBounds {
        minimum: 100,
        maximum_execution: u64::from(native::max_fee_ceiling(&WalletRoute::PolicyWallet)),
        default_execution: 5_000_000,
        default_deployment: 2_000_000_000,
        decimals: 7,
        native_symbol: "XLM".into(),
    }
}
pub fn explorer_link(network: &str, kind: &str, id: &str) -> Option<String> {
    let network = crate::host::routing::normalize(network).ok()?;
    let base = match network {
        "stellar:testnet" => "https://stellar.expert/explorer/testnet",
        "stellar:pubnet" => "https://stellar.expert/explorer/public",
        _ => return None,
    };
    if !matches!(kind, "tx" | "account" | "contract") || id.is_empty() {
        return None;
    }
    Some(format!("{base}/{kind}/{id}"))
}
pub fn wallet_address(network: &str, owner: &str, instance: &[u8; 32]) -> Result<String> {
    native::admin::wallet_address(network, owner, &native::admin::wallet_salt(instance))
        .map_err(crate::provider::failure)
}

pub fn custody_encoding(c: Custody) -> Result<serde_json::Value> {
    serde_json::to_value(match c {
        Custody::Owner => WalletRoute::Native,
        Custody::Policy => WalletRoute::PolicyWallet,
        Custody::Retired => WalletRoute::Odc,
    })
    .map_err(|_| Error::config("Cannot encode custody"))
}
pub fn tier_encoding(t: Option<Tier>) -> Result<serde_json::Value> {
    serde_json::to_value(t.map(|t| match t {
        Tier::Simple => native::PolicyTier::Simple,
        Tier::Standard => native::PolicyTier::Common,
        Tier::Custom => native::PolicyTier::Custom,
    }))
    .map_err(|_| Error::config("Cannot encode tier"))
}

pub fn source_consent<P: serde::Serialize>(
    a: &crate::host::runtime::owner::SourceConsent<'_, P>,
) -> Result<(serde_json::Value, String)> {
    let c: WalletConfig = serde_json::from_slice(a.configuration.bytes())
        .map_err(|_| Error::config("Invalid source-consent configuration"))?;
    let payload = native::signing::source_approval_payload(&native::signing::SourceApproval {
        policy_id: a.policy_id,
        revision: a.revision,
        network: &c.network,
        wallet: &c.wallet,
        route: c.route.encoding(),
        policy_instance: &c.policy_instance,
        source: a.source,
        source_hash: a.source_hash,
        ir_hash: a.ir_hash,
        module_digest: a.module_digest,
        asset: &c.asset,
        asset_symbol: &c.asset_symbol,
        asset_issuer: &c.asset_issuer,
        max_fee_stroops: c.max_fee_stroops,
        language: a.language,
        tier: a.tier,
        rules: a.rules,
        params: a.params,
        params_hash: a.params_hash,
    })
    .map_err(crate::provider::failure)?;
    let message =
        native::signing::source_approval_message(&payload).map_err(crate::provider::failure)?;
    Ok((payload, message))
}

#[cfg(test)]
mod tests {
    use super::{explorer_link, verified_identity};
    use crate::host::{error::Result, runtime::Transport};
    use serde_json::{Value, json};
    use std::sync::{Arc, Mutex};

    /// An endpoint that answers `getNetwork` with each reply of `replies` in turn, then with the
    /// last one, and records every method that it is asked.
    struct Endpoint {
        replies: Mutex<Vec<Result<Value>>>,
        asked: Mutex<Vec<String>>,
    }
    impl Endpoint {
        fn new(replies: Vec<Result<Value>>) -> Arc<Self> {
            Arc::new(Self {
                replies: Mutex::new(replies),
                asked: Mutex::new(Vec::new()),
            })
        }
        fn asked(&self, method: &str) -> usize {
            self.asked
                .lock()
                .unwrap()
                .iter()
                .filter(|m| *m == method)
                .count()
        }
    }
    impl Transport for Endpoint {
        fn call(&self, method: &str, _: Value) -> Result<Value> {
            self.asked.lock().unwrap().push(method.into());
            if method != "getNetwork" {
                return Ok(json!({ "method": method }));
            }
            let mut replies = self.replies.lock().unwrap();
            if replies.len() > 1 {
                replies.remove(0)
            } else {
                replies[0].clone()
            }
        }
    }
    const TESTNET: &str = "Test SDF Network ; September 2015";
    const PUBNET: &str = "Public Global Stellar Network ; September 2015";

    /// The endpoint is asked once for its network: its verified reply answers every later
    /// `getNetwork`, and every other method still reaches the endpoint.
    #[test]
    fn a_verified_network_reply_is_asked_once() {
        let endpoint = Endpoint::new(vec![Ok(json!({ "passphrase": TESTNET }))]);
        let transport = verified_identity("stellar:testnet", endpoint.clone()).unwrap();
        for _ in 0..3 {
            let reply = transport.call("getNetwork", json!({})).unwrap();
            assert_eq!(reply["passphrase"], TESTNET);
            transport.call("getLatestLedger", json!({})).unwrap();
        }
        assert_eq!(endpoint.asked("getNetwork"), 1);
        assert_eq!(endpoint.asked("getLatestLedger"), 3);
    }

    /// A reply that names another network, no passphrase, or an error is returned as it came
    /// and kept nowhere: the next call asks the endpoint again, and the first reply that names
    /// the network is the one that is kept.
    #[test]
    fn a_reply_of_another_network_is_not_kept() {
        let endpoint = Endpoint::new(vec![
            Ok(json!({ "passphrase": PUBNET })),
            Ok(json!({})),
            Err(crate::host::error::Error::uncertain("no answer")),
            Ok(json!({ "passphrase": TESTNET })),
            Ok(json!({ "passphrase": PUBNET })),
        ]);
        let transport = verified_identity("stellar:testnet", endpoint.clone()).unwrap();
        let ask = || transport.call("getNetwork", json!({}));
        assert_eq!(ask().unwrap()["passphrase"], PUBNET);
        assert_eq!(ask().unwrap(), json!({}));
        assert!(ask().is_err());
        assert_eq!(ask().unwrap()["passphrase"], TESTNET);
        // The verified reply is kept: the endpoint's later answer of another network is never read.
        assert_eq!(ask().unwrap()["passphrase"], TESTNET);
        assert_eq!(endpoint.asked("getNetwork"), 4);
    }

    /// Each network keeps its own passphrase, an alias included; a network of another rail has
    /// no transport.
    #[test]
    fn the_kept_identity_is_the_passphrase_of_the_transports_network() {
        for (network, passphrase) in [
            ("stellar:pubnet", PUBNET),
            ("stellar:mainnet", PUBNET),
            ("stellar:testnet", TESTNET),
        ] {
            let endpoint = Endpoint::new(vec![
                Ok(json!({ "passphrase": if passphrase == PUBNET { TESTNET } else { PUBNET } })),
                Ok(json!({ "passphrase": passphrase })),
            ]);
            let transport = verified_identity(network, endpoint.clone()).unwrap();
            transport.call("getNetwork", json!({})).unwrap();
            transport.call("getNetwork", json!({})).unwrap();
            transport.call("getNetwork", json!({})).unwrap();
            assert_eq!(endpoint.asked("getNetwork"), 2, "{network}");
        }
        assert!(verified_identity("solana:devnet", Endpoint::new(vec![Ok(json!({}))])).is_err());
    }

    #[test]
    fn public_explorer_links_accept_canonical_and_historical_networks() {
        let identities = [
            (
                "account",
                "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
            ),
            (
                "contract",
                "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            ),
            (
                "tx",
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            ),
        ];
        for (network, explorer) in [
            ("stellar:pubnet", "public"),
            ("stellar:mainnet", "public"),
            ("stellar:testnet", "testnet"),
        ] {
            for (kind, identity) in identities {
                assert_eq!(
                    explorer_link(network, kind, identity),
                    Some(format!(
                        "https://stellar.expert/explorer/{explorer}/{kind}/{identity}"
                    )),
                    "{network} {kind}",
                );
            }
        }
        assert_eq!(
            explorer_link("stellar:unknown", "account", identities[0].1),
            None
        );
        assert_eq!(
            explorer_link("stellar:pubnet", "unknown", identities[0].1),
            None
        );
        assert_eq!(explorer_link("stellar:pubnet", "account", ""), None);
    }
}
