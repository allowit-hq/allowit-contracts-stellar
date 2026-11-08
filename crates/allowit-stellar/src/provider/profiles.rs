//! Strict native descriptor decoding and common-value projection.
use crate::host::{
    error::{Error, Result},
    profiles::Description,
    vendors::ProfileBinding,
};
use allowit_core::policy::PolicyValue;
pub fn decode(network: &str, bytes: &[u8]) -> Result<(Description, Box<dyn ProfileBinding>)> {
    let bundle = crate::provider::runtime::client::decode_public_bundle(bytes)?;
    if crate::host::routing::normalize(&bundle.network)? != network {
        return Err(Error::config(
            "Public profile belongs to another selected rail",
        ));
    }
    let c = &bundle.config;
    let d = Description {
        network: network.into(),
        wallet: bundle.wallet.clone(),
        agent: c.agent.clone(),
        policy_id: bundle.policy_id.clone(),
        owner: c.owner.clone(),
        server: c.server.clone(),
        asset: c.asset.clone(),
        asset_symbol: c.asset_symbol.clone(),
        source: c.policy_source.clone(),
        source_hash: crate::hex(&c.source_hash),
        module_digest: bundle.module_digest.clone(),
        params: c
            .params
            .0
            .iter()
            .map(|(k, v)| (k.clone(), PolicyValue(v.allowit())))
            .collect(),
    };
    Ok((d, Box::new(bundle)))
}

impl ProfileBinding for super::runtime::client::Bundle {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn verify_import(&self, endpoint: &str) -> Result<()> {
        self.verify_import(endpoint)
    }
    fn verify_server_role(&self, server: &str) -> Result<()> {
        self.verify_server_role(server)
    }
}
