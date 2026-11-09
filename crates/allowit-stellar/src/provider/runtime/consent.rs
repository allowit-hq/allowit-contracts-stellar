//! One codec for the exact native v1 portable source-consent payload.
use crate::host::error::Result;
use crate::{PolicyParams, WalletConfig};
use serde_json::Value;
pub(super) struct Portable<'a> {
    pub language: &'a str,
    pub tier: &'a str,
    pub rules: &'a [String],
    pub params: &'a PolicyParams,
    pub params_hash: &'a str,
}
pub(super) fn payload(
    policy_id: &str,
    revision: u32,
    c: &WalletConfig,
    source_hash: &str,
    ir_hash: &str,
    module_digest: &str,
    d: Portable<'_>,
) -> Result<Value> {
    crate::signing::source_approval_payload(&crate::signing::SourceApproval {
        policy_id,
        revision,
        network: &c.network,
        wallet: &c.wallet,
        route: c.route.encoding(),
        policy_instance: &c.policy_instance,
        source: &c.policy_source,
        source_hash,
        ir_hash,
        module_digest,
        asset: &c.asset,
        asset_symbol: &c.asset_symbol,
        asset_issuer: &c.asset_issuer,
        max_fee_stroops: c.max_fee_stroops,
        language: d.language,
        tier: d.tier,
        rules: d.rules,
        params: d.params,
        params_hash: d.params_hash,
    })
    .map_err(crate::provider::failure)
}

pub(super) fn message(payload: &Value) -> Result<String> {
    crate::signing::source_approval_message(payload).map_err(crate::provider::failure)
}
