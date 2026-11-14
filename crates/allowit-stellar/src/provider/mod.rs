//! Stellar adapter registration and native workflow bindings.
pub mod execution;
pub mod formats;
pub mod owner;
pub mod paid_service;
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
/// Convert a native failure to a client error. A Stellar RPC call that got no answer keeps the
/// network-unavailable code, and an answer with an unknown outcome stays uncertain, so callers
/// retry both with the same request ID.
pub(crate) fn failure(message: impl Into<String>) -> Error {
    let message = message.into();
    if message.contains(native::rpc::NETWORK_UNAVAILABLE) {
        let mut error = Error::uncertain(message);
        error.code = NETWORK_UNAVAILABLE;
        error
    } else if message.contains(native::rpc::TRANSPORT_UNKNOWN) {
        Error::uncertain(message)
    } else {
        Error::config(message)
    }
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
        verbs: if crate::host::routing::info(network).is_ok_and(|v| v.testnet) {
            &[
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
            ]
        } else {
            &[
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
            ]
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
