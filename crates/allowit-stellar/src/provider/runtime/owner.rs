//! The request of one agent's wallet setup. Keys remain with the owner.
use crate::host::error::{Error, Result};
use crate::{self as native};

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
                "Native wallet setup supports Stellar Testnet only",
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
