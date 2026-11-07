//! Core contracts used by the native adapter implementation.
pub use allowit::client::error;
pub use allowit::vendor::request;
pub use allowit::vendor::wallet::{KeyProvider, PrivateSigner, Signer};
pub use allowit::vendor::{
    authoring, config, execution, generation, input, owner, owner_session, profiles, request_proof,
    runtime, typed_request,
};
pub mod routing {
    use super::error::{Error, Result};
    pub use allowit::vendor::routing::{Family, RailInfo};
    pub fn all() -> &'static [RailInfo] {
        static RAILS: std::sync::OnceLock<Vec<RailInfo>> = std::sync::OnceLock::new();
        RAILS.get_or_init(crate::provider::networks)
    }
    pub fn info(network: &str) -> Result<&'static RailInfo> {
        all()
            .iter()
            .find(|r| r.id == network || r.aliases.contains(&network))
            .ok_or_else(|| {
                Error::usage(format!(
                    "unknown rail {}; run allowit rail ls",
                    allowit::client::error::quoted(network)
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
    pub use allowit::vendor::profiles::ProfileBinding;
    pub use allowit::vendor::{OwnerProvider, RuntimeProvider};
}
