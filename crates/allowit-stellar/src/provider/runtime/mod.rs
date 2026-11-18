//! Shared Stellar execution workflows. Callers retain keys, authority and durable application state.
pub mod approval;
pub mod client;
mod consent;
pub mod owner;
pub mod owner_client;

use crate::workflow::ExecutionRequest;
use crate::{
    self as native, ExecutionTerms, OperationStatus, PreparedOperation, SignedOperation,
    WalletConfig, WalletRoute, rpc,
};
use std::{sync::Arc, time::Duration};

/// A verified observation of one known policy-wallet authorization envelope.
/// A failed envelope leaves the reusable address authorization unresolved.
pub struct ObservedAuthorization {
    pub signed: SignedOperation,
    pub receipt: rpc::VerifiedReceipt,
}
impl ObservedAuthorization {
    pub fn status(&self) -> OperationStatus {
        projected_status(
            &self.signed.prepared.config.route,
            self.receipt.status.clone(),
        )
    }
}

pub struct Runtime {
    rpc: Arc<dyn rpc::Rpc>,
}
impl Runtime {
    pub fn new(endpoint: &str) -> native::Result<Self> {
        Ok(Self::from_rpc(Arc::new(rpc::HttpRpc::new(endpoint)?)))
    }
    pub fn from_rpc(rpc: Arc<dyn rpc::Rpc>) -> Self {
        Self { rpc }
    }
    pub fn rpc(&self) -> &dyn rpc::Rpc {
        self.rpc.as_ref()
    }

    /// Read native state and perform initial simulation. No authority or store is inferred.
    pub fn prepare(
        &self,
        config: &WalletConfig,
        request: &ExecutionRequest,
        terms: &ExecutionTerms,
        accounting: Option<rpc::NativeAccounting>,
        now: u64,
        expires_at: u64,
    ) -> native::Result<PreparedOperation> {
        rpc::prepare_with(
            self.rpc(),
            config,
            request,
            terms,
            accounting,
            now,
            expires_at,
        )
    }

    /// Authorize, durably retain the complete authorized packet, then perform enforce-mode simulation.
    /// `retain` must commit the original packet before returning success. Its failure prevents further RPC.
    /// A simulation failure leaves that same authorization available through caller-owned recovery state.
    /// The caller durably retains the returned final packet before exposing it to another actor.
    pub fn finalize_authorization(
        &self,
        prepared: &PreparedOperation,
        authorize: impl FnOnce(&PreparedOperation) -> native::Result<PreparedOperation>,
        retain: impl FnOnce(&PreparedOperation) -> native::Result<()>,
    ) -> native::Result<PreparedOperation> {
        if prepared.config.route != WalletRoute::PolicyWallet {
            return Err("Post-authorization simulation requires policy wallet custody".into());
        }
        let authorized = authorize(prepared)?;
        if authorized.config != prepared.config
            || authorized.request != prepared.request
            || authorized.terms != prepared.terms
            || authorized.state != prepared.state
            || authorized.created_at != prepared.created_at
            || authorized.expires_at != prepared.expires_at
        {
            return Err("Authorization changed the original operation identity".into());
        }
        native::validate_retained_prepared(&authorized)?;
        retain(&authorized)?;
        rpc::simulate(self.rpc(), &authorized)
    }

    /// Revalidate unchanged policy-wallet bytes before the caller signs them.
    pub fn revalidate_unsigned(
        &self,
        prepared: &PreparedOperation,
        now: u64,
    ) -> native::Result<PreparedOperation> {
        rpc::revalidate_prepared(self.rpc(), prepared, now)
    }

    /// Observe known envelopes without changing reservations or caller accounting.
    /// Unknown, unavailable or invalid receipts prove no terminal operation state.
    pub fn observe_authorizations<'a>(
        &self,
        packets: impl IntoIterator<Item = &'a PreparedOperation>,
    ) -> Vec<ObservedAuthorization> {
        let mut observed = Vec::new();
        for prepared in packets {
            // A policy wallet operation settles in its sealed transaction, which its event
            // names; another settles under its prepared hash.
            if prepared.config.route == WalletRoute::PolicyWallet
                && prepared.payment_authorization.is_none()
            {
                if let Ok(Some((signed, receipt))) =
                    rpc::policy_wallet_settlement(self.rpc(), prepared)
                {
                    observed.push(ObservedAuthorization { signed, receipt });
                }
                continue;
            }
            let Ok(Some(receipt)) = rpc::receipt_by_hash(
                self.rpc(),
                &prepared.config.network,
                &prepared.transaction_hash,
            ) else {
                continue;
            };
            let signed = SignedOperation {
                prepared: prepared.clone(),
                transaction_xdr: receipt.envelope_xdr.clone(),
                transaction_hash: receipt.transaction_hash,
                role_signatures: Vec::new(),
            };
            if rpc::validate_settled_policy_packet(&signed, &receipt).is_ok() {
                observed.push(ObservedAuthorization { signed, receipt });
            }
        }
        observed
    }

    /// Submit a caller-authorized owner envelope and poll only its original native transaction hash.
    /// An ambiguous send ends this call; the error names the exact hash for later recovery.
    pub fn send_and_poll(
        &self,
        network: &str,
        envelope_xdr: &str,
        poll: Poll,
    ) -> native::Result<rpc::VerifiedReceipt> {
        Self::send_and_poll_while(self.rpc(), network, envelope_xdr, poll, &|| Ok(true))?
            .ok_or_else(|| "A needed transaction was not sent".into())
    }
    /// As `send_and_poll`, for a transaction that another one can make needless before it is
    /// accepted. Each send until the network accepts one, the first included, goes out only
    /// while `needed` answers true; otherwise no send was accepted, and the answer is `None`.
    /// Once a send is accepted, or its outcome is uncertain, only its hash is looked up.
    /// The calls go through `rpc`, so a caller can observe their replies.
    pub fn send_and_poll_while(
        rpc: &dyn rpc::Rpc,
        network: &str,
        envelope_xdr: &str,
        poll: Poll,
        needed: &dyn Fn() -> native::Result<bool>,
    ) -> native::Result<Option<rpc::VerifiedReceipt>> {
        let hash = rpc::signed_transaction_hash(network, envelope_xdr)?;
        let id = native::hex(&hash);
        let unknown = |reason: String| {
            format!(
                "Transaction {id} result is unknown ({reason}); look it up again before any replacement"
            )
        };
        let mut sent = false;
        for attempt in 0..poll.attempts.max(1) {
            if attempt > 0 {
                std::thread::sleep(poll.interval);
            }
            // A send that is not accepted yet, the first one included, goes out only while it is
            // needed: the transaction can become needless while it is signed or waits.
            if !sent && !needed()? {
                return Ok(None);
            }
            if !sent {
                match rpc::send_transaction(rpc, network, envelope_xdr)? {
                    rpc::Broadcast::Submitted => sent = true,
                    rpc::Broadcast::RetryLater => continue,
                    rpc::Broadcast::Unknown => {
                        return Err(unknown("Uncertain native broadcast".into()));
                    }
                    rpc::Broadcast::Rejected { error_result_xdr } => {
                        if let Some(receipt) =
                            rpc::receipt_by_hash(rpc, network, &hash).map_err(unknown)?
                        {
                            return Ok(Some(receipt));
                        }
                        return Err(format!(
                            "Stellar rejected transaction {id}: {}",
                            error_result_xdr.as_deref().unwrap_or("no result")
                        ));
                    }
                }
            }
            if let Some(receipt) = rpc::receipt_by_hash(rpc, network, &hash).map_err(unknown)? {
                return Ok(Some(receipt));
            }
        }
        Err(format!(
            "Transaction {id} has no terminal result yet; look it up again before any replacement"
        ))
    }
}
#[derive(Clone, Copy, Debug)]
pub struct Poll {
    pub attempts: u32,
    pub interval: Duration,
}
impl Default for Poll {
    fn default() -> Self {
        Self {
            attempts: 30,
            interval: Duration::from_secs(2),
        }
    }
}
pub(super) fn projected_status(route: &WalletRoute, status: OperationStatus) -> OperationStatus {
    if *route == WalletRoute::PolicyWallet && status == OperationStatus::Failed {
        OperationStatus::SubmissionUnknown
    } else {
        status
    }
}

#[cfg(test)]
mod tests;
