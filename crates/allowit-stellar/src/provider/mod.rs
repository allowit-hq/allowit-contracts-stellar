//! Stellar adapter registration and native workflow bindings.
pub mod execution;
pub mod formats;
pub mod owner;
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
            .map_err(Error::config)
    }
    fn parse(&self, secret: &str) -> Result<Box<dyn PrivateSigner>> {
        native::signing::LocalSigner::from_encoded(secret)
            .map(|key| Box::new(Key(key)) as Box<dyn PrivateSigner>)
            .map_err(Error::config)
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
        self.0.sign_digest(digest).map_err(Error::config)
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

use crate::host::input::asset::Token;
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

pub fn tokens_for(rail: &str) -> &'static [Token] {
    if rail == "stellar:testnet" {
        TESTNET
    } else {
        PUBNET
    }
}

pub const FAMILY: crate::host::routing::Family = crate::host::routing::Family("stellar");
pub fn networks() -> Vec<crate::host::routing::RailInfo> {
    // Native owns protocol aliases. The SDK adds only these historical presentation spellings.
    static ALIASES: std::sync::OnceLock<Vec<Vec<&'static str>>> = std::sync::OnceLock::new();
    let aliases = ALIASES.get_or_init(|| {
        native::networks::NETWORKS
            .iter()
            .map(|network| {
                let mut aliases = network.aliases.to_vec();
                aliases.push(if network.testnet {
                    "stellar-testnet"
                } else {
                    "stellar-mainnet"
                });
                aliases
            })
            .collect()
    });
    native::networks::NETWORKS
        .iter()
        .zip(aliases)
        .map(|(n, aliases)| crate::host::routing::RailInfo {
            id: n.id,
            label: if n.testnet {
                "Stellar Testnet"
            } else {
                "Stellar Mainnet"
            },
            aliases,
            family: FAMILY,
            testnet: n.testnet,
        })
        .collect()
}
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
