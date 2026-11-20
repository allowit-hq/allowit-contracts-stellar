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
    /// The issued asset that the wallet holds, from the server's template of the network. The
    /// setup adds its trustline. `None` is a wallet that holds XLM.
    pub asset: Option<native::owner::Trustline>,
    /// The base units of the wallet's asset that the setup moves into the wallet for the
    /// agent's payments: stroops of XLM on top of the account's reserve and its fee float, or
    /// units of the issued asset. The owner's account pays all of it in the setup transaction.
    /// `None` funds the reserve and the float only.
    pub funding: Option<i64>,
}
/// The most that one setup funds a wallet that holds XLM, in stroops: the transaction's
/// ceiling on the starting balance, less the reserve and the fee float that the starting
/// balance also holds. A wallet of an issued asset takes `owner::MAX_ASSET_FUNDING`.
pub const MAX_SETUP_FUNDING: i64 =
    native::owner::MAX_STARTING_BALANCE - native::owner::default_starting_balance(false);
/// The check of a Native wallet's asset that every setup runs, and the asset read of a host
/// before the setup: an issued asset with the code of the network's own asset reads as that
/// asset in every amount, so no wallet holds one. `None` is a wallet that holds XLM.
pub fn check_wallet_asset(asset: Option<&native::owner::Trustline>) -> Result<()> {
    if let Some(asset) = asset
        && (asset.code == "XLM"
            || native::asset_from_identity(&asset.code, Some(&asset.issuer)).is_err())
    {
        return Err(Error::config(
            "The wallet asset of this network is not an issued Stellar asset",
        ));
    }
    Ok(())
}
/// The keys of a setup's roles: each one a Stellar G account and no two the same. The setup
/// checks its owner, agent and server with it, and the asset lookup its owner and server, before
/// the owner signs in.
pub fn check_roles(accounts: &[&str]) -> Result<()> {
    for account in accounts {
        native::account_key(account).map_err(Error::usage)?;
    }
    if (1..accounts.len()).any(|i| accounts[..i].contains(&accounts[i])) {
        return Err(Error::usage(
            "Owner, agent and server must be distinct G accounts",
        ));
    }
    Ok(())
}
impl SetupRequest {
    /// The checks of the caller's own values, which need no asset: the network, the three
    /// roles, the request ID, the fee and the bounds that every funding has. The provider runs
    /// them before it knows the wallet's asset.
    pub fn validate_caller_values(&self) -> Result<()> {
        // A request names its network by the canonical id. An alias would be another request
        // identity for the same ledger; the provider resolves a caller's alias before it builds
        // the request.
        if crate::host::routing::normalize(&self.network).ok() != Some(self.network.as_str()) {
            return Err(Error::unsupported(
                "Native wallet setup needs a Stellar network, named by its network id",
            ));
        }
        check_roles(&[&self.owner, &self.agent, &self.server])?;
        if !crate::host::request::request_id_valid(&self.request_id) {
            return Err(Error::usage("Invalid Stellar setup request ID"));
        }
        if !(100..=100_000).contains(&self.fee_per_operation) {
            return Err(Error::usage(
                "Setup fee must be 100..100000 stroops per operation",
            ));
        }
        self.funding_within(native::owner::MAX_ASSET_FUNDING.max(MAX_SETUP_FUNDING))
    }
    fn funding_within(&self, ceiling: i64) -> Result<()> {
        if self.funding.is_some_and(|f| !(1..=ceiling).contains(&f)) {
            return Err(Error::usage("The setup funding amount is out of range"));
        }
        Ok(())
    }
    pub fn validate(&self) -> Result<()> {
        self.validate_caller_values()?;
        check_wallet_asset(self.asset.as_ref())?;
        // The funding of a wallet that holds XLM is part of the starting balance. The funding
        // of an issued asset is a payment of its own, with the ceiling of the setup builder.
        self.funding_within(if self.asset.is_some() {
            native::owner::MAX_ASSET_FUNDING
        } else {
            MAX_SETUP_FUNDING
        })
    }
}
