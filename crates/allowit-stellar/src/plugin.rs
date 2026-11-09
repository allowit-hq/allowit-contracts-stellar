//! The Stellar rail plugin. The SDK registers [`PLUGIN`] with one line and reaches every Stellar
//! capability through the core plugin traits. Each method forwards to `provider::*`.
use crate::host::{
    KeyProvider, Signer,
    error::{Error, Result},
    execution::{Capabilities, Outcome, Recovery, Request},
    generation::{GenerateRequest, GeneratedDraft},
    input::{
        Formats,
        asset::{Amount, Token},
    },
    profiles::{Description, Profile, ProfileBinding},
    request_proof::Protocol,
    routing::{Family, RailInfo},
    runtime::{
        Installation, Kind, OwnerPacket, Packet, PolicyInstallation, ReceiptInfo, Tier, Transport,
        owner::{Configuration, Custody, FeeBounds, PolicyIdentity, SourceConsent},
    },
    vendors::{OwnerProvider, RuntimeProvider},
};
use crate::provider::{self, execution, server, server_owner};
use allowit_core::vendor::plugin::{
    Deadlines, ExecutionProvider, Feature, Fixtures, LinkKind, LiveConfig, OwnerRuntime, OwnerStep,
    ProfileInfo, RailPlugin, ServerHooks, StoreOpener, TestSupport,
};
use serde_json::{Value, value::RawValue};
use std::{sync::Arc, time::Duration};

/// The rail id: store namespaces, element tags and the policy-function namespace.
pub const ID: &str = "stellar";
pub(crate) const FAMILY: Family = Family(ID);

/// The CAIP-2 networks. The second id of each list is a historical spelling.
pub static NETWORKS: &[RailInfo] = &[
    RailInfo {
        id: "stellar:testnet",
        label: "Stellar Testnet",
        aliases: &["stellar-testnet"],
        family: FAMILY,
        testnet: true,
    },
    RailInfo {
        id: "stellar:pubnet",
        label: "Stellar Mainnet",
        aliases: &["stellar:mainnet", "stellar-mainnet"],
        family: FAMILY,
        testnet: false,
    },
];

/// The wallet profiles a server offers. Hosts choose them by custody and tier.
pub static PROFILES: &[ProfileInfo] = &[
    ProfileInfo {
        id: "allowit-stellar-native-v1",
        custody: Custody::Owner,
        tier: None,
        label: "Native multisignature account",
    },
    ProfileInfo {
        id: "allowit-stellar-policy-wallet-v1",
        custody: Custody::Policy,
        tier: Some(Tier::Standard),
        label: "Policy wallet",
    },
    ProfileInfo {
        id: "allowit-stellar-custom-wallet-v1",
        custody: Custody::Policy,
        tier: Some(Tier::Custom),
        label: "Custom policy wallet",
    },
];

pub struct Plugin;
pub static PLUGIN: Plugin = Plugin;
struct Execution;
static EXECUTION: Execution = Execution;
struct Owner;
static OWNER: Owner = Owner;
struct Hooks;
static HOOKS: Hooks = Hooks;

static TEST_SUPPORT: TestSupport = TestSupport {
    network: "stellar:testnet",
    skips: &[(Feature::Swap, "the Stellar plugin has no swap venue")],
    fixtures,
};

fn network(id: &str) -> Result<&'static RailInfo> {
    NETWORKS
        .iter()
        .find(|n| n.id == id || n.aliases.contains(&id))
        .ok_or_else(|| Error::usage(format!("unknown Stellar network {id}")))
}

impl RailPlugin for Plugin {
    fn id(&self) -> &'static str {
        ID
    }
    fn networks(&self) -> &'static [RailInfo] {
        NETWORKS
    }
    fn capabilities(&self, network: &str) -> Capabilities {
        provider::capabilities(network)
    }
    fn test_support(&self) -> &'static TestSupport {
        &TEST_SUPPORT
    }
    fn formats(&self) -> &'static Formats {
        &provider::formats::FORMATS
    }
    fn tokens(&self, network: &str) -> &'static [Token] {
        provider::tokens_for(network)
    }
    fn explorer(&self, network: &str, kind: LinkKind, id: &str) -> Option<String> {
        let kind = match kind {
            LinkKind::Address => "account",
            LinkKind::Transaction => "tx",
            LinkKind::Contract => "contract",
        };
        server_owner::explorer_link(network, kind, id)
    }
    fn deadlines(&self, _network: &str) -> Deadlines {
        Deadlines {
            // An agent request and an owner step are valid for at most one hour of ledgers.
            max_validity_secs: 3_600,
            owner_step_ttl_secs: 300,
            block_time_secs: 5,
        }
    }
    fn keys(&self) -> &'static dyn KeyProvider {
        &provider::KEYS
    }
    fn fund_key(&self, network: &str, address: &str, endpoint: Option<&str>) -> Result<String> {
        provider::fund_key(network, address, endpoint)
    }
    fn decode_profile(
        &self,
        network: &str,
        bytes: &[u8],
    ) -> Result<(Description, Box<dyn ProfileBinding>)> {
        provider::profiles::decode(network, bytes)
    }
    fn generate(
        &self,
        cx: &allowit_core::vendor::plugin::GenerateContext<'_>,
        request: &GenerateRequest,
    ) -> Result<GeneratedDraft> {
        provider::generate(cx.backend, cx.origin, cx.signer, request, &mut || {
            (cx.clock)()
        })
    }
    fn execution(&self) -> &'static dyn ExecutionProvider {
        &EXECUTION
    }
    fn owner(&self) -> &'static dyn OwnerProvider {
        &provider::owner::OWNER
    }
    fn owner_runtime(&self) -> &'static dyn OwnerRuntime {
        &OWNER
    }
    fn connect(&self, network: &str, endpoint: &str) -> Result<Arc<dyn Transport>> {
        self::network(network)?;
        server_owner::connect(endpoint)
    }
    fn runtime(
        &self,
        network: &str,
        transport: Arc<dyn Transport>,
    ) -> Result<Box<dyn RuntimeProvider>> {
        Ok(Box::new(server::Provider::with_transport(
            network, transport,
        )?))
    }
    fn install(&self, installation: PolicyInstallation) -> Result<Installation> {
        server::policy(installation)
    }
    fn restore(&self, kind: Kind, raw: Box<RawValue>) -> Result<Packet> {
        server::restore(kind, raw)
    }
    fn request_proof_protocol(&self) -> Protocol {
        server::request_proof_protocol()
    }
    fn signer_identity(&self, key: &[u8; 32]) -> Result<String> {
        server::signer_identity(key)
    }
    fn request_id(&self, packet: &Packet) -> Result<[u8; 32]> {
        server::request_id(packet)
    }
    fn server(&self) -> &'static dyn ServerHooks {
        &HOOKS
    }
}

impl ExecutionProvider for Execution {
    fn check(
        &self,
        network: &str,
        op: &str,
        to: &str,
        minimum: Option<&Amount>,
        args: bool,
    ) -> Result<()> {
        self::network(network)?;
        provider::request::check(op, to, minimum, args)
    }
    fn build(
        &self,
        profile: &Profile,
        store: StoreOpener<'_>,
        rpc: Option<&str>,
        request: &Request,
    ) -> Result<Value> {
        execution::build(profile, store, rpc, request)
    }
    fn execute(
        &self,
        profile: Profile,
        signer: Arc<dyn Signer>,
        store: StoreOpener<'_>,
        rpc: Option<String>,
        request: &Request,
    ) -> Result<Outcome> {
        execution::execute(profile, signer, store, rpc, request)
    }
    fn status(
        &self,
        profile: Profile,
        signer: Arc<dyn Signer>,
        store: StoreOpener<'_>,
        rpc: Option<String>,
        id: &str,
        wait: Duration,
    ) -> Result<Outcome> {
        execution::status(profile, signer, store, rpc, id, wait)
    }
    fn retained(
        &self,
        store: StoreOpener<'_>,
        network: &str,
        wallet: Option<&str>,
        id: &str,
    ) -> Result<Option<Recovery>> {
        execution::retained(store, network, wallet, id)
    }
    fn recover(
        &self,
        original: Recovery,
        signer: Arc<dyn Signer>,
        backend: &str,
        store: StoreOpener<'_>,
        id: &str,
        wait: Duration,
        request: Option<&Request>,
    ) -> Result<Outcome> {
        execution::recover(original, signer, backend, store, id, wait, request)
    }
}

impl OwnerRuntime for Owner {
    fn configuration(&self, network: &str, document: &[u8]) -> Result<Configuration> {
        server_owner::configuration(network, document)
    }
    fn envelope_hash(
        &self,
        network: &str,
        payload: &[u8],
        require_signature: bool,
    ) -> Result<[u8; 32]> {
        server_owner::envelope_hash(network, payload, require_signature)
    }
    fn validate_signed(&self, network: &str, original: &[u8], signed: &[u8]) -> Result<[u8; 32]> {
        server_owner::validate_signed(network, original, signed)
    }
    fn with_policy(&self, c: &Configuration, identity: PolicyIdentity) -> Result<Configuration> {
        server_owner::with_policy(c, identity)
    }
    fn code_hash(&self, wasm: &[u8]) -> Result<[u8; 32]> {
        server_owner::code_hash(wasm)
    }
    fn fee_bounds(&self) -> FeeBounds {
        server_owner::fee_bounds()
    }
    fn wallet_address(&self, network: &str, owner: &str, instance: &[u8; 32]) -> Result<String> {
        server_owner::wallet_address(network, owner, instance)
    }
    fn custody_encoding(&self, c: Custody) -> Result<Value> {
        server_owner::custody_encoding(c)
    }
    fn tier_encoding(&self, t: Option<Tier>) -> Result<Value> {
        server_owner::tier_encoding(t)
    }
    fn source_consent(&self, input: &SourceConsent<'_, Value>) -> Result<(Value, String)> {
        server_owner::source_consent(input)
    }
    /// The payload is the unsigned base64 transaction envelope; `hash` is its transaction hash.
    fn step(&self, network: &str, packet: &OwnerPacket) -> Result<OwnerStep> {
        let network = self::network(network)?.id;
        if packet.network() != network {
            return Err(Error::config("The owner step belongs to another network"));
        }
        let info = packet.info()?;
        let payload = String::from_utf8(info.signing_payload)
            .map_err(|_| Error::config("Invalid owner transaction encoding"))?;
        let hash = server_owner::envelope_hash(network, payload.as_bytes(), false)?;
        if hash != info.transaction_hash {
            return Err(Error::config("The owner transaction differs from its hash"));
        }
        Ok(OwnerStep {
            explorer: server_owner::explorer_link(network, "tx", &crate::hex(&hash)),
            action: info.action,
            payload,
            hash,
            expires_at: info.expires_at,
        })
    }
}

/// Keys of a network block in the server rail configuration.
const CONFIG_KEYS: &[&str] = &["rpc", "recoveryRpcs", "gasRates", "asset"];

impl ServerHooks for Hooks {
    /// A network block is an object with optional keys: `rpc` (an HTTPS URL), `recoveryRpcs`
    /// (HTTPS URLs), `gasRates` (asset symbol or contract id to a decimal count of asset units
    /// per XLM) and `asset` (the installed asset contract id, set by the engine per receipt).
    fn configure(&self, network: &str, config: &Value) -> Result<()> {
        self::network(network)?;
        let bad = |what: &str| Error::config(format!("Invalid Stellar rail configuration: {what}"));
        let object = config.as_object().ok_or_else(|| bad("not an object"))?;
        if let Some(key) = object.keys().find(|k| !CONFIG_KEYS.contains(&k.as_str())) {
            return Err(bad(&format!("unknown key {key}")));
        }
        let url = |v: &Value| v.as_str().is_some_and(|s| s.starts_with("https://"));
        if object.get("rpc").is_some_and(|v| !url(v)) {
            return Err(bad("rpc must be an HTTPS URL"));
        }
        if object
            .get("recoveryRpcs")
            .is_some_and(|v| !v.as_array().is_some_and(|a| a.iter().all(url)))
        {
            return Err(bad("recoveryRpcs must be HTTPS URLs"));
        }
        if let Some(rates) = object.get("gasRates") {
            let rates = rates.as_object().ok_or_else(|| bad("gasRates"))?;
            if rates.values().any(|v| v.as_str().and_then(rate).is_none()) {
                return Err(bad("gasRates values must be positive decimal strings"));
            }
        }
        Ok(())
    }
    fn profiles(&self) -> &'static [ProfileInfo] {
        PROFILES
    }
    /// A SEP-53 signature over the sign-in message by the account's ed25519 key.
    fn verify_sign_in(
        &self,
        network: &str,
        address: &str,
        message: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        self::network(network)?;
        let message =
            std::str::from_utf8(message).map_err(|_| Error::usage("Invalid sign-in message"))?;
        crate::signing::verify_digest(
            address,
            &crate::signing::signed_message_digest(message),
            signature,
        )
        .map_err(|_| Error::usage("The wallet sign-in signature is invalid"))
    }
    /// The XLM fee in installed-asset units, rounded up. Native XLM is one to one; another
    /// asset needs its `gasRates` entry, keyed by contract id or symbol.
    fn charged_fee(&self, network: &str, config: &Value, receipt: &ReceiptInfo) -> Result<i128> {
        let network = self::network(network)?.id;
        let fee = i128::try_from(receipt.fee.native_units)
            .map_err(|_| Error::config("The receipt fee is out of range"))?;
        let asset = config
            .get("asset")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::config("The fee needs the installed asset"))?;
        let tokens = provider::tokens_for(network);
        let token = tokens
            .iter()
            .find(|t| crate::provider::token_contract(network, t).as_deref() == Some(asset));
        if token.is_some_and(|t| t.native) {
            return Ok(fee);
        }
        let rates = config.get("gasRates").and_then(Value::as_object);
        let rate = rates
            .and_then(|r| r.get(asset).or_else(|| token.and_then(|t| r.get(t.code))))
            .and_then(Value::as_str)
            .and_then(rate)
            .ok_or_else(|| {
                Error::config(format!(
                    "Configure gasRates to price the XLM fee in {asset}"
                ))
            })?;
        // `rate` has 7 decimals, as XLM does, so units = ceil(fee * rate / 10^7).
        fee.checked_mul(rate)
            .and_then(|v| v.checked_add(9_999_999))
            .map(|v| v / 10_000_000)
            .ok_or_else(|| Error::config("The fee is out of range"))
    }
}

/// A positive decimal string with at most 7 fraction digits, scaled by 10^7.
fn rate(text: &str) -> Option<i128> {
    let (whole, fraction) = text.split_once('.').unwrap_or((text, ""));
    if whole.is_empty()
        || fraction.len() > 7
        || !whole
            .bytes()
            .chain(fraction.bytes())
            .all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let value = format!("{whole}{fraction:0<7}").parse::<i128>().ok()?;
    (value > 0).then_some(value)
}

fn fixtures() -> Fixtures {
    let account = |n: u8| crate::account_for_seed(&[n; 32]);
    let wallet = stellar_strkey::Contract([9; 32]).to_string();
    let mut invalid = account(3);
    invalid.replace_range(55.., if invalid.ends_with('A') { "B" } else { "A" });
    Fixtures {
        account: account(1),
        wallet,
        recipient: account(2),
        invalid_address: invalid,
        token: Token {
            code: "USDC",
            decimals: 7,
            native: false,
            issuer: Some("GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5"),
        },
        agent_seed: [7; 32],
        public_profile: include_bytes!("../tests/fixtures/provider/stellar-approval.json").to_vec(),
        owner_generation: serde_json::from_str(include_str!(
            "../tests/fixtures/provider/stellar-owner-generation.json"
        ))
        .expect("owner generation fixture"),
        chain: None,
        live: Some(LiveConfig {
            env: &["ALLOWIT_LIVE_TESTNET"],
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_and_networks_follow_the_plugin_contract() {
        assert_eq!(PLUGIN.id(), "stellar");
        assert!(
            PLUGIN
                .networks()
                .iter()
                .all(|n| n.id.starts_with("stellar:"))
        );
        let support = PLUGIN.test_support();
        assert!(network(support.network).unwrap().testnet);
        assert_eq!(
            support.skip(Feature::Swap),
            Some("the Stellar plugin has no swap venue")
        );
        assert_eq!(support.skip(Feature::Transfer), None);
        assert_eq!(network("stellar:mainnet").unwrap().id, "stellar:pubnet");
        assert!(network("other:testnet").is_err());
    }

    #[test]
    fn fixtures_hold_valid_and_invalid_addresses() {
        let f = (PLUGIN.test_support().fixtures)();
        for address in [&f.account, &f.recipient] {
            assert!(crate::signing::canonical_account_key(address).is_ok());
        }
        assert!(crate::signing::canonical_account_key(&f.invalid_address).is_err());
        assert_ne!(f.account, f.recipient);
    }

    #[test]
    fn explorer_links_name_each_kind() {
        let f = (PLUGIN.test_support().fixtures)();
        assert_eq!(
            PLUGIN.explorer("stellar:testnet", LinkKind::Address, &f.account),
            Some(format!(
                "https://stellar.expert/explorer/testnet/account/{}",
                f.account
            ))
        );
        assert!(
            PLUGIN
                .explorer("stellar:mainnet", LinkKind::Transaction, &"ab".repeat(32))
                .unwrap()
                .starts_with("https://stellar.expert/explorer/public/tx/")
        );
    }

    #[test]
    fn configure_admits_only_known_typed_keys() {
        let hooks = PLUGIN.server();
        hooks
            .configure(
                "stellar:testnet",
                &serde_json::json!({"rpc":"https://rpc.example","gasRates":{"USDC":"0.15"}}),
            )
            .unwrap();
        for bad in [
            serde_json::json!([]),
            serde_json::json!({"rpc":"http://rpc.example"}),
            serde_json::json!({"gasRates":{"USDC":"-1"}}),
            serde_json::json!({"unknown":true}),
        ] {
            assert!(hooks.configure("stellar:testnet", &bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn profiles_cover_owner_and_policy_custody() {
        let profiles = PLUGIN.server().profiles();
        assert!(profiles.iter().any(|p| p.custody == Custody::Owner));
        assert!(profiles.iter().any(|p| p.tier == Some(Tier::Custom)));
    }

    fn receipt(native_units: u128) -> ReceiptInfo {
        ReceiptInfo {
            transaction_hash: [1; 32],
            status: crate::host::runtime::Status::Confirmed,
            observed_height: 1,
            fee: allowit_core::vendor::runtime::Fee {
                native_units,
                charged_units: 0,
            },
            debits: Vec::new(),
        }
    }

    #[test]
    fn fees_count_in_installed_asset_units() {
        let hooks = PLUGIN.server();
        let tokens = provider::tokens_for("stellar:testnet");
        let xlm = provider::token_contract("stellar:testnet", &tokens[0]).unwrap();
        let usdc = provider::token_contract("stellar:testnet", &tokens[1]).unwrap();
        let config = |asset: &str| serde_json::json!({"asset":asset,"gasRates":{"USDC":"0.15"}});
        assert_eq!(
            hooks
                .charged_fee("stellar:testnet", &config(&xlm), &receipt(1_234))
                .unwrap(),
            1_234
        );
        // 1_000 stroops at 0.15 USDC per XLM is 150 USDC units.
        assert_eq!(
            hooks
                .charged_fee("stellar:testnet", &config(&usdc), &receipt(1_000))
                .unwrap(),
            150
        );
        // Rounding is up, so the charge never understates the fee.
        assert_eq!(
            hooks
                .charged_fee("stellar:testnet", &config(&usdc), &receipt(1))
                .unwrap(),
            1
        );
        assert!(
            hooks
                .charged_fee(
                    "stellar:testnet",
                    &serde_json::json!({"asset":usdc}),
                    &receipt(1)
                )
                .is_err()
        );
    }

    #[test]
    fn sign_in_verifies_a_sep53_signature() {
        let seed = [5; 32];
        let address = crate::account_for_seed(&seed);
        let message = "app.example wants you to sign in with your Stellar Testnet account:";
        let signature =
            crate::test_support::sign_digest(seed, &crate::signing::signed_message_digest(message));
        let hooks = PLUGIN.server();
        hooks
            .verify_sign_in("stellar:testnet", &address, message.as_bytes(), &signature)
            .unwrap();
        assert!(
            hooks
                .verify_sign_in("stellar:testnet", &address, b"another message", &signature)
                .is_err()
        );
    }
}
