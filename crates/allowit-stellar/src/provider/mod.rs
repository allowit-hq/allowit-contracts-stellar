//! Stellar adapter registration and native workflow bindings.
pub mod custom_build;
pub mod execution;
pub mod formats;
pub mod message_signature;
pub mod owner;
pub mod paid_service;
pub mod params_update;
pub mod price;
pub mod profiles;
pub mod request;
pub mod runtime;
pub mod server;
pub mod server_owner;
mod typed;
use crate as native;
use crate::host::{KeyProvider, PrivateSigner};
use crate::host::{
    Signer,
    error::{Error, Result},
};
use zeroize::Zeroizing;

/// Stable SDK storage registrations. The caller opens these namespaces.
pub const EXECUTION_STORE_NAMESPACE: &str = "stellar-journal";
pub const OWNER_STORE_NAMESPACE: &str = "stellar-owner-workflows";

/// The exit code of a call that got no answer, in the shared CLI exit table.
pub(crate) const NETWORK_UNAVAILABLE: i32 = 7;
/// The checked shape of a policy's source for its wallet. The server evaluates the source of
/// a classic account, so that source is server policy source: it can read owner text for a
/// server function. A contract compiles the source of a policy wallet, which stays portable.
/// The contract of a Custom wallet (`custom`) compiles the on-chain part of its source, so the
/// one source of such a wallet may have a server part that is server policy source
/// (`policy::custom_parts`). No other policy wallet holds such a source.
pub(crate) fn source_shape(
    classic: bool,
    custom: bool,
    source: &str,
) -> crate::host::error::Result<crate::policy::SourceShape> {
    Ok(checked_shape(classic, custom, source)?.0)
}
/// Whether the server's report of a source's shape binds the wallet: the standard prefix and
/// whether the source writes state. The report states the shape of the whole source. For a
/// Custom source with a server part only the server, which links its host calls, can check that
/// shape, and it binds nothing: a Custom wallet binds no prefix and keeps policy state. Any other
/// report must equal [`source_shape`].
pub(crate) fn report_matches(
    classic: bool,
    custom: bool,
    source: &str,
    prefix: &[String],
    writes_state: bool,
) -> crate::host::error::Result<bool> {
    let (shape, split) = checked_shape(classic, custom, source)?;
    Ok(split || (shape.prefix == prefix && shape.writes_state == writes_state))
}
/// The shape of [`source_shape`], and whether the source is a Custom source with a server part.
fn checked_shape(
    classic: bool,
    custom: bool,
    source: &str,
) -> crate::host::error::Result<(crate::policy::SourceShape, bool)> {
    if classic {
        return Ok((
            crate::policy::classic_shape(source).map_err(Error::usage)?,
            false,
        ));
    }
    // A Custom source is the source that Core derives a part from: its derivation decides the
    // shape and whether a server part exists, also for a source that the portable gate admits.
    if custom {
        let checked = crate::host::authoring::check(source);
        return match crate::policy::custom_parts(source) {
            Ok(parts) => Ok((parts.shape, parts.server_part)),
            Err(derive) => Err(checked.err().unwrap_or_else(|| Error::usage(derive))),
        };
    }
    Ok((crate::host::authoring::check(source)?, false))
}
/// Convert a native failure to a client error. A Stellar RPC call that got no answer keeps the
/// network-unavailable code, and an answer with an unknown outcome stays uncertain, so callers
/// retry both with the same request ID.
pub(crate) fn failure(message: impl Into<String>) -> Error {
    let message = message.into();
    if message.contains(native::rpc::NETWORK_UNAVAILABLE) {
        let mut error = Error::uncertain(message);
        error.code = NETWORK_UNAVAILABLE;
        error
    } else if message.contains(native::rpc::TRANSPORT_UNKNOWN)
        // An invalid lifetime reply decides nothing: it is uncertain for every caller.
        || message.starts_with(native::rpc::owner_observation::INVALID_REPLY)
    {
        Error::uncertain(message)
    } else if message == native::rpc::owner_observation::STALE_OBSERVATION {
        // A caller prepares the owner step once more: the typed code says so, and the text and
        // kind stay those of a plain refusal.
        let mut error = Error::config(message);
        error.api_code = Some(allowit_core::vendor::runtime::STALE_OWNER_OBSERVATION.to_owned());
        error
    } else {
        Error::config(message)
    }
}
#[cfg(test)]
#[test]
fn a_stale_owner_observation_carries_its_code() {
    let error = failure(native::rpc::owner_observation::STALE_OBSERVATION);
    assert_eq!(
        error.api_code.as_deref(),
        Some(allowit_core::vendor::runtime::STALE_OWNER_OBSERVATION)
    );
    assert!(error.config);
    assert_eq!(failure("another refusal").api_code, None);
}
#[cfg(test)]
#[test]
fn an_invalid_lifetime_reply_is_uncertain() {
    let invalid = format!(
        "{}: an entry has no change ledger",
        native::rpc::owner_observation::INVALID_REPLY
    );
    let error = failure(invalid);
    assert_eq!(
        (error.code, error.api_code, error.config),
        (Error::uncertain("").code, None, false)
    );
    assert!(failure("another refusal").config);
}

pub static KEYS: Keys = Keys;
pub struct Keys;
struct Key(native::signing::LocalSigner);

impl KeyProvider for Keys {
    fn entropy_bytes(&self) -> usize {
        native::signing::KEY_ENTROPY_BYTES
    }
    fn derive(&self, entropy: &[u8]) -> Result<Box<dyn PrivateSigner>> {
        native::signing::LocalSigner::from_entropy(entropy)
            .map(|key| Box::new(Key(key)) as Box<dyn PrivateSigner>)
            .map_err(crate::provider::failure)
    }
    fn parse(&self, secret: &str) -> Result<Box<dyn PrivateSigner>> {
        native::signing::LocalSigner::from_encoded(secret)
            .map(|key| Box::new(Key(key)) as Box<dyn PrivateSigner>)
            .map_err(crate::provider::failure)
    }
    fn validate_identity(&self, address: &str, public_key: &str, key_type: &str) -> Result<()> {
        native::signing::validate_key_identity(address, public_key, key_type).map_err(Error::usage)
    }
}

impl PrivateSigner for Key {
    fn address(&self) -> &str {
        self.0.account()
    }
    fn public_key(&self) -> &str {
        self.0.account()
    }
    fn key_type(&self) -> &str {
        native::signing::KEY_TYPE
    }
    fn encoded_secret(&self) -> Zeroizing<String> {
        self.0.encoded_secret()
    }
    fn sign_hash(&self, digest: &[u8]) -> Result<Vec<u8>> {
        self.0.sign_digest(digest).map_err(crate::provider::failure)
    }
}

fn signature(signer: &(impl Signer + ?Sized), digest: &[u8; 32]) -> native::Result<[u8; 64]> {
    if crate::host::routing::family(signer.network()).map_err(|_| "Unknown signing network")?
        != FAMILY
    {
        return Err("Signer does not serve the selected native protocol".into());
    }
    signer
        .sign_hash(digest)
        .map_err(|_| "Local signer failed")?
        .try_into()
        .map_err(|_| "Invalid native signature size".into())
}

impl<T: Signer + ?Sized> crate::provider::runtime::owner_client::OwnerSigner for T {
    fn account(&self) -> &str {
        self.address()
    }
    fn sign_hash(&self, digest: &[u8; 32]) -> native::Result<[u8; 64]> {
        signature(self, digest)
    }
}
impl<T: Signer + ?Sized> crate::provider::runtime::client::AgentSigner for T {
    fn account(&self) -> &str {
        self.address()
    }
    fn sign_hash(&self, digest: &[u8; 32]) -> native::Result<[u8; 64]> {
        signature(self, digest)
    }
}

struct OwnerSignerRef<'a>(&'a dyn Signer);
impl runtime::owner_client::OwnerSigner for OwnerSignerRef<'_> {
    fn account(&self) -> &str {
        self.0.address()
    }
    fn sign_hash(&self, digest: &[u8; 32]) -> native::Result<[u8; 64]> {
        signature(self.0, digest)
    }
}
struct AgentSignerArc(std::sync::Arc<dyn Signer>);
impl runtime::client::AgentSigner for AgentSignerArc {
    fn account(&self) -> &str {
        self.0.address()
    }
    fn sign_hash(&self, digest: &[u8; 32]) -> native::Result<[u8; 64]> {
        signature(self.0.as_ref(), digest)
    }
}

pub fn generate(
    backend: &str,
    origin: &str,
    signer: &dyn Signer,
    request: &crate::host::generation::GenerateRequest,
    clock: &mut dyn FnMut() -> Result<u64>,
) -> Result<crate::host::generation::GeneratedDraft> {
    let mut client = crate::provider::runtime::owner_client::OwnerClient::new(
        backend,
        origin,
        signer.address(),
    )?;
    client.authenticate(&OwnerSignerRef(signer), clock()?)?;
    let policy = client.generate(request, clock()?)?;
    let unresolved = policy.runtime.instance_binding.portable.unresolved.clone();
    let document = serde_json::to_value(policy)
        .map_err(|_| Error::config("Cannot encode generated policy"))?;
    Ok(crate::host::generation::GeneratedDraft {
        document,
        unresolved,
    })
}

/// The params of a rail document and the unit of its installed asset. A draft or policy, as
/// [`generate`] returns it, holds them in `runtime.instanceBinding.portable`. A public wallet
/// profile or an installation holds them in `config`. Each shape is decoded with the type that
/// the rail uses for it, so an absent optional field reads as it does everywhere else. A
/// classic asset that is not listed shows its code through its issuer. An asset without a
/// known unit is an error, so no amount prints with a placeholder unit.
pub fn draft_params(
    network: &str,
    document: &serde_json::Value,
) -> Result<crate::host::plugin::DraftParams> {
    let invalid = || Error::config("The document is not a Stellar policy or wallet document");
    // `stated` is the network of the typed part; a profile also names one at the top level.
    let (stated, params, address, symbol, issuer) =
        if document.pointer("/runtime/instanceBinding").is_some() {
            let policy: runtime::owner_client::GeneratedPolicy =
                serde_json::from_value(document.clone()).map_err(|_| invalid())?;
            let binding = policy.runtime.instance_binding;
            (
                policy.network,
                binding.portable.params,
                binding.portable.asset.address,
                binding.portable.asset.symbol,
                binding.asset_issuer,
            )
        } else if let Some(config) = document.get("config") {
            let config: native::WalletConfig =
                serde_json::from_value(config.clone()).map_err(|_| invalid())?;
            (
                config.network,
                config.params,
                config.asset,
                config.asset_symbol,
                config.asset_issuer,
            )
        } else {
            return Err(invalid());
        };
    let top = match document.get("network") {
        Some(value) => Some(value.as_str().ok_or_else(invalid)?),
        None => None,
    };
    if std::iter::once(stated.as_str())
        .chain(top)
        .any(|named| crate::host::routing::normalize(named).ok() != Some(network))
    {
        return Err(Error::config("The document belongs to another network"));
    }
    let asset = asset_display(network, &address).or_else(|_| {
        let issuer = issuer
            .ok_or_else(|| Error::unsupported("The asset of this document has no known unit"))?;
        asset_display(network, &format!("{symbol}:{issuer}"))
    })?;
    let params = params
        .0
        .iter()
        .map(|(key, value)| {
            serde_json::to_value(allowit_core::policy::PolicyValue(value.allowit()))
                .map(|value| (key.clone(), value))
                .map_err(|_| invalid())
        })
        .collect::<Result<_>>()?;
    Ok(crate::host::plugin::DraftParams { params, asset })
}

use crate::host::input::asset::{AssetDisplay, Token};
const TESTNET: &[Token] = &[
    Token {
        code: "XLM",
        decimals: 7,
        native: true,
        issuer: None,
    },
    Token {
        code: "USDC",
        decimals: 7,
        native: false,
        issuer: Some("GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5"),
    },
];
const PUBNET: &[Token] = &[
    Token {
        code: "XLM",
        decimals: 7,
        native: true,
        issuer: None,
    },
    Token {
        code: "USDC",
        decimals: 7,
        native: false,
        issuer: Some("GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN"),
    },
];

/// The human names of the listed tokens.
fn token_name(code: &str) -> &str {
    match code {
        "XLM" => "Lumens",
        "USDC" => "USD Coin",
        other => other,
    }
}
fn display(token: &Token) -> AssetDisplay {
    AssetDisplay {
        symbol: token.code.into(),
        decimals: token.decimals,
        name: token_name(token.code).into(),
        native: token.native,
    }
}
/// XLM: the native asset and the fee asset of every Stellar network.
pub fn native_display() -> AssetDisplay {
    display(&TESTNET[0])
}
/// Display metadata of an asset reference: `native`, a listed code, `CODE:ISSUER`, an issuer of a
/// listed token, or the Stellar Asset Contract id of a listed token. A classic asset that is not
/// listed shows its code with the seven decimals of every classic asset. A contract that is not
/// listed has no known unit, so it is an error and never a placeholder.
pub fn asset_display(network: &str, asset: &str) -> Result<AssetDisplay> {
    let tokens = tokens_for(network);
    if asset == "native" {
        return Ok(native_display());
    }
    let (code, issuer) = match asset.split_once(':') {
        Some((code, issuer)) => (code, Some(issuer)),
        None => (asset, None),
    };
    if let Some(token) = tokens.iter().find(|t| {
        (t.code == code && (issuer.is_none() || issuer == t.issuer))
            || (issuer.is_none() && t.issuer == Some(asset))
            || (issuer.is_none() && token_contract(network, t).as_deref() == Some(asset))
    }) {
        return Ok(display(token));
    }
    let Some(issuer) = issuer else {
        return Err(Error::usage(format!(
            "unknown Stellar asset {}; name it as CODE:ISSUER",
            crate::host::error::quoted(asset)
        )));
    };
    native::asset_from_identity(code, Some(issuer)).map_err(Error::usage)?;
    Ok(AssetDisplay {
        symbol: code.into(),
        decimals: 7,
        name: code.into(),
        native: false,
    })
}

pub fn tokens_for(rail: &str) -> &'static [Token] {
    if rail == "stellar:testnet" {
        TESTNET
    } else {
        PUBNET
    }
}

/// The Stellar Asset Contract id of a token on a network.
pub fn token_contract(network: &str, token: &Token) -> Option<String> {
    let asset = native::asset_from_identity(token.code, token.issuer).ok()?;
    native::sac_address(network, &asset).ok()
}

pub const FAMILY: crate::host::routing::Family = crate::plugin::FAMILY;
pub fn capabilities(network: &str) -> crate::host::execution::Capabilities {
    crate::host::execution::Capabilities {
        curve: "ed25519",
        address_is_key: true,
        operations: &["transfer", "deposit", "redeem"],
        build_only: true,
        verbs: match crate::host::routing::info(network) {
            Ok(rail) if rail.testnet => &[
                "keys fund",
                "wallet setup",
                "wallet import",
                "policy deploy",
                "policy fund",
                "policy activate",
                "policy export",
                "policy owner-status",
                "wallet show",
                "policy show",
                "policy generate",
                "exec",
                "status",
            ],
            // Every verb of a test network but its faucet.
            Ok(_) => &[
                "wallet setup",
                "wallet import",
                "policy deploy",
                "policy fund",
                "policy activate",
                "policy export",
                "policy owner-status",
                "wallet show",
                "policy show",
                "policy generate",
                "exec",
                "status",
            ],
            // A network outside the rail keeps the list that it had: no setup, which the
            // setup refuses there.
            Err(_) => &[
                "wallet import",
                "policy deploy",
                "policy fund",
                "policy activate",
                "policy export",
                "policy owner-status",
                "wallet show",
                "policy show",
                "policy generate",
                "exec",
                "status",
            ],
        },
    }
}
pub fn fund_key(network: &str, address: &str, endpoint: Option<&str>) -> Result<String> {
    if !crate::host::routing::info(network)?.testnet {
        return Err(Error::unsupported(
            "The selected network has no test faucet",
        ));
    }
    native::owner::fund_testnet_account(address, endpoint).map_err(|message| {
        Error::uncertain(format!("{message}; check the balance before retrying"))
    })
}

pub mod diagnostics;

#[cfg(test)]
mod request_proof_tests;
#[cfg(test)]
mod request_tests;

#[cfg(test)]
mod source_shape_tests {
    use super::{report_matches, source_shape};

    /// The server's report of the whole source's shape binds a Simple, Common or plain Custom
    /// wallet. For a Custom source with a server part that only server policy source can hold
    /// (owner text read with `as_str()`), it binds nothing: a server step writes the state, and
    /// the server's report says so, while the on-chain part writes none.
    #[test]
    fn a_report_binds_the_shape_except_for_a_custom_source_with_a_server_part() {
        const SPLIT: &str = "use allowit::prelude::*;\nuse allowit::AllowitDecision;\npub fn execute(ctx: &AllowitContext) -> allowit::Result {\n    let question: String = allowit::param(ctx, \"question\");\n    let score = allowit::decision(ctx, &AllowitDecision { id: \"research\", query: question.as_str(), deny_below: 3000, allow_above: 8000 })?;\n    allowit::set_state(ctx, \"last_score\", score)?;\n    allowit::payment_limit(ctx, &ctx.params[allowit::PAYMENT_LIMIT])?;\n    Ok(())\n}\n";
        const PLAIN: &str = "use allowit::prelude::*;\npub fn execute(ctx: &AllowitContext) -> allowit::Result {\n    allowit::payment_limit(ctx, &ctx.params[allowit::PAYMENT_LIMIT])?;\n    Ok(())\n}\n";
        let rules = ["payment_limit".to_owned()];
        assert!(report_matches(false, true, SPLIT, &[], true).unwrap());
        assert!(!source_shape(false, true, SPLIT).unwrap().writes_state);
        assert!(report_matches(false, true, PLAIN, &rules, false).unwrap());
        assert!(!report_matches(false, true, PLAIN, &rules, true).unwrap());
        assert!(!report_matches(false, false, PLAIN, &[], false).unwrap());
        assert!(report_matches(false, false, SPLIT, &[], true).is_err());
        // A Custom source that the portable gate admits still goes through Core's derivation: a
        // read of the stored day passes the gate, and Core refuses it.
        let day = PLAIN.replace(
            "    Ok(())",
            "    let day: Option<u64> = allowit::get_state(ctx, \"day\")?;\n    assert!(day.is_some());\n    Ok(())",
        );
        assert!(source_shape(false, false, &day).is_ok());
        assert!(source_shape(false, true, &day).is_err());
    }

    /// Server policy source, with owner text read by `as_str()`, belongs to a classic account
    /// and to a Custom wallet, whose contract compiles the on-chain part. No other policy wallet
    /// holds it. Portable source passes for every wallet.
    #[test]
    fn only_a_classic_account_and_a_custom_wallet_hold_server_policy_source() {
        const SERVER: &str = "use allowit::prelude::*;\nuse allowit::AllowitDecision;\npub fn execute(ctx: &AllowitContext) -> allowit::Result {\n    allowit::payment_limit(ctx, &ctx.params[allowit::PAYMENT_LIMIT])?;\n    let question: String = allowit::param(ctx, \"question\");\n    allowit::decision(ctx, &AllowitDecision { id: \"research\", query: question.as_str(), deny_below: 3000, allow_above: 8000 })?;\n    Ok(())\n}\n";
        const PORTABLE: &str = "use allowit::prelude::*;\npub fn execute(ctx: &AllowitContext) -> allowit::Result {\n    allowit::payment_limit(ctx, &ctx.params[allowit::PAYMENT_LIMIT])?;\n    Ok(())\n}\n";
        assert!(source_shape(true, false, SERVER).is_ok());
        assert!(source_shape(false, true, SERVER).is_ok());
        assert!(source_shape(false, false, SERVER).is_err());
        for (classic, custom) in [(true, false), (false, true), (false, false)] {
            assert!(source_shape(classic, custom, PORTABLE).is_ok());
        }
        // A Custom wallet's source whose on-chain part cannot be derived keeps the portable
        // gate's refusal.
        let dynamic = SERVER.replace(
            "    Ok(())",
            "    allowit::set_state(ctx, question.as_str(), 1u32)?;\n    Ok(())",
        );
        assert!(source_shape(false, true, &dynamic).is_err());
    }
}

#[cfg(test)]
mod capability_tests {
    /// Every network of the rail advertises the wallet setup. Only a test network has a faucet.
    #[test]
    fn each_network_advertises_the_wallet_setup() {
        for network in crate::plugin::NETWORKS {
            let verbs = super::capabilities(network.id).verbs;
            assert!(verbs.contains(&"wallet setup"), "{}", network.id);
            assert_eq!(
                verbs.contains(&"keys fund"),
                network.testnet,
                "{}",
                network.id
            );
        }
    }
    /// A network that the rail does not serve advertises no wallet setup, which the setup
    /// refuses there, and keeps the other verbs that it had.
    #[test]
    fn a_network_outside_the_rail_advertises_no_wallet_setup() {
        for network in ["stellar:futurenet", "example:testnet", ""] {
            assert!(crate::host::routing::info(network).is_err(), "{network}");
            let verbs = super::capabilities(network).verbs;
            assert!(!verbs.contains(&"wallet setup"), "{network}");
            assert!(!verbs.contains(&"keys fund"), "{network}");
            assert_eq!(verbs.len(), 11, "{network}");
            assert!(verbs.contains(&"wallet import") && verbs.contains(&"exec"));
        }
    }
}
