//! Core contracts used by the native adapter implementation.
pub use allowit_core::client::error;
pub use allowit_core::vendor::request;
pub use allowit_core::vendor::wallet::{KeyProvider, PrivateSigner, Signer};
pub use allowit_core::vendor::{
    authoring, config, execution, generation, input, owner, owner_session, plugin, profiles,
    request_proof, runtime, typed_request,
};
pub mod routing {
    use super::error::{Error, Result};
    pub use allowit_core::vendor::routing::{Family, RailInfo};
    pub fn all() -> &'static [RailInfo] {
        crate::plugin::NETWORKS
    }
    pub fn info(network: &str) -> Result<&'static RailInfo> {
        all()
            .iter()
            .find(|r| r.id == network || r.aliases.contains(&network))
            .ok_or_else(|| {
                Error::usage(format!(
                    "unknown rail {}; run allowit rail ls",
                    allowit_core::client::error::quoted(network)
                ))
            })
    }
    pub fn normalize(network: &str) -> Result<&'static str> {
        info(network).map(|r| r.id)
    }
    pub fn family(network: &str) -> Result<Family> {
        info(network).map(|r| r.family)
    }
}
pub mod vendors {
    pub use allowit_core::vendor::profiles::ProfileBinding;
    pub use allowit_core::vendor::{OwnerProvider, RuntimeProvider};
}
