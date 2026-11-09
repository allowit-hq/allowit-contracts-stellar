//! Shared classic-account owner setup continuation. Keys remain with the owner.
use crate::host::error::{Error, Result};
use crate::{
    self as native,
    owner::{NativeSetup, prepare_native_setup, validate_native_setup},
};
use allowit_core::client::store::Store;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

pub struct SetupRequest {
    pub network: String,
    pub owner: String,
    pub agent: String,
    pub server: String,
    pub request_id: String,
    pub fee_per_operation: u32,
}
impl SetupRequest {
    pub fn validate(&self) -> Result<()> {
        if self.network != "stellar:testnet" {
            return Err(Error::unsupported(
                "Native browser setup supports Stellar Testnet only",
            ));
        }
        for account in [&self.owner, &self.agent, &self.server] {
            native::account_key(account).map_err(Error::usage)?;
        }
        if !crate::host::request::request_id_valid(&self.request_id) {
            return Err(Error::usage("Invalid Stellar setup request ID"));
        }
        if !(100..=100_000).contains(&self.fee_per_operation) {
            return Err(Error::usage(
                "Setup fee must be 100..100000 stroops per operation",
            ));
        }
        Ok(())
    }
}
pub fn prepare(store: &Store, request: &SetupRequest, now: u64) -> Result<NativeSetup> {
    request.validate()?;
    if let Some(saved) = store.load::<NativeSetup>(&request.request_id)? {
        if saved.owner != request.owner
            || saved.agent != request.agent
            || saved.engine != request.server
            || saved.network != request.network
            || saved.fee_stroops != request.fee_per_operation * 3
        {
            return Err(Error::config(
                "This Stellar setup request ID already binds another intent",
            ));
        }
        validate_native_setup(&saved).map_err(crate::provider::failure)?;
        return Ok(saved);
    }
    let state = native::owner::fresh_testnet_owner_account(&request.owner, None)
        .map_err(crate::provider::failure)?;
    let prepared = prepare_native_setup(
        &state,
        &request.agent,
        &request.server,
        &request.request_id,
        &request.network,
        request.fee_per_operation,
        now,
    )
    .map_err(crate::provider::failure)?;
    store.save(&request.request_id, &prepared)?;
    Ok(prepared)
}
pub fn signing_url(origin: &str, setup: &NativeSetup) -> Result<String> {
    validate_native_setup(setup).map_err(crate::provider::failure)?;
    let origin = crate::host::config::parse_origin(origin)?;
    let bytes = serde_json::to_vec(setup)
        .map_err(|_| Error::config("Cannot encode Stellar owner intent"))?;
    Ok(format!(
        "{origin}/?chain=stellar&network=stellar%3Atestnet#allowit-stellar-owner={}",
        URL_SAFE_NO_PAD.encode(bytes)
    ))
}
