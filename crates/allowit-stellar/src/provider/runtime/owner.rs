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
/// The most that one setup funds, in base units: the transaction's ceiling on the starting
/// balance, less the reserve and the fee float that the starting balance also holds.
pub const MAX_SETUP_FUNDING: i64 =
    native::owner::MAX_STARTING_BALANCE - native::owner::default_starting_balance(false);
impl SetupRequest {
    pub fn validate(&self) -> Result<()> {
        native::passphrase(&self.network)
            .map_err(|_| Error::unsupported("Native wallet setup needs a Stellar network"))?;
        // An issued asset with the code of the network's own asset reads as that asset in
        // every amount, so no wallet holds one.
        if let Some(asset) = &self.asset
            && (asset.code == "XLM"
                || native::asset_from_identity(&asset.code, Some(&asset.issuer)).is_err())
        {
            return Err(Error::config(
                "The wallet asset of this network is not an issued Stellar asset",
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
        if self
            .funding
            .is_some_and(|f| !(1..=MAX_SETUP_FUNDING).contains(&f))
        {
            return Err(Error::usage("The setup funding amount is out of range"));
        }
        Ok(())
    }
}
