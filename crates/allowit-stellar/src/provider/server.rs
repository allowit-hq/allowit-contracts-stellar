//! Native bindings for the common local runtime. No HTTP call targets the Allowit server.
use crate::host::{
    config::ServerAuthority,
    error::{Error, Result},
    profiles::Description,
    runtime::*,
};
use crate::{self as native, PreparedOperation, SignedOperation, WalletConfig, WalletRoute, rpc};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::value::RawValue;
use std::collections::BTreeMap;

fn checked<T>(r: native::Result<T>) -> Result<T> {
    r.map_err(crate::provider::failure)
}
fn decode<T: DeserializeOwned>(v: &RawValue) -> Result<T> {
    serde_json::from_str(v.get()).map_err(|_| Error::config("Invalid retained native packet"))
}
/// Every self-identifying native packet crosses the same network and retained-shape boundary.
trait RetainedPacket: DeserializeOwned {
    fn validate_packet(&self, packet: &Packet) -> Result<()>;
}
fn decode_packet<T: RetainedPacket>(packet: &Packet) -> Result<T> {
    let value: T = decode(packet.document())?;
    value.validate_packet(packet)?;
    Ok(value)
}
impl RetainedPacket for PreparedOperation {
    fn validate_packet(&self, packet: &Packet) -> Result<()> {
        packet_network(packet, &self.config.network)?;
        checked(native::validate_retained_prepared(self))
    }
}
impl RetainedPacket for SignedOperation {
    fn validate_packet(&self, packet: &Packet) -> Result<()> {
        packet_network(packet, &self.prepared.config.network)?;
        retained_signed_shape(self)
    }
}
impl RetainedPacket for native::owner_intent::OwnerTransaction {
    fn validate_packet(&self, packet: &Packet) -> Result<()> {
        packet_network(packet, &self.network)?;
        checked(native::owner_intent::validate_retained_owner_transaction(
            self,
        ))
    }
}
impl RetainedPacket for OwnerSignedData {
    fn validate_packet(&self, packet: &Packet) -> Result<()> {
        packet_network(packet, &self.original.network)?;
        checked(native::owner_intent::validate_signed_owner_transaction(
            &self.original,
            owner_payload(self)?,
        ))
        .map(drop)
    }
}
impl RetainedPacket for rpc::VerifiedReceipt {
    fn validate_packet(&self, packet: &Packet) -> Result<()> {
        checked(rpc::validate_receipt(
            self,
            packet.network(),
            &self.transaction_hash,
        ))
    }
}

impl RetainedPacket for native::workflow::ExecutionRequest {
    fn validate_packet(&self, packet: &Packet) -> Result<()> {
        let network = checked(native::network_id(packet.network()))?;
        let matches = |asset: &native::workflow::WorkflowAsset| match asset {
            native::workflow::WorkflowAsset::Native { network: value, .. } => *value == network,
            native::workflow::WorkflowAsset::Token(value) => value.network == network,
        };
        if self
            .effect_bounds
            .iter()
            .any(|bound| !matches(&bound.asset))
            || self
                .fee_bounds
                .iter()
                .flatten()
                .any(|bound| !matches(&bound.asset))
        {
            return Err(Error::config("Request asset and carrier networks differ"));
        }
        Ok(())
    }
}

fn params(v: &BTreeMap<String, allowit_core::policy::PolicyValue>) -> Result<native::PolicyParams> {
    Ok(native::PolicyParams(
        v.iter()
            .map(|(k, v)| checked(native::PolicyValue::from_core(v)).map(|v| (k.clone(), v)))
            .collect::<Result<_>>()?,
    ))
}
fn description(c: &WalletConfig, id: &str) -> Result<Description> {
    Ok(Description {
        network: crate::host::routing::normalize(&c.network)?.into(),
        wallet: c.wallet.clone(),
        agent: c.agent.clone(),
        policy_id: id.into(),
        owner: c.owner.clone(),
        server: c.server.clone(),
        asset: c.asset.clone(),
        asset_symbol: c.asset_symbol.clone(),
        source: c.policy_source.clone(),
        source_hash: native::hex(&c.source_hash),
        module_digest: native::hex(&c.module_digest),
        params: c
            .params
            .0
            .iter()
            .map(|(k, v)| checked(v.to_core()).map(|v| (k.clone(), v)))
            .collect::<Result<_>>()?,
    })
}
pub fn policy(i: PolicyInstallation) -> Result<Installation> {
    let d = i.description;
    let (symbol, issuer) = match i.asset {
        crate::host::input::asset::Asset::Native { code } => (code, None),
        crate::host::input::asset::Asset::Token { code, issuer } => (code, issuer),
        _ => {
            return Err(Error::usage(
                "This vendor needs an explicit named asset identity for installation",
            ));
        }
    };
    if symbol != d.asset_symbol {
        return Err(Error::config(
            "Installation asset differs from its public description",
        ));
    }
    let c = checked(
        native::admin::PolicyInstallation {
            network: d.network.clone(),
            policy_instance: i.policy_instance,
            owner: d.owner.clone(),
            agent: d.agent.clone(),
            server: d.server.clone(),
            tier: match i.tier {
                Tier::Simple => native::PolicyTier::Simple,
                Tier::Standard => native::PolicyTier::Common,
                Tier::Custom => native::PolicyTier::Custom,
            },
            params: params(&d.params)?,
            asset_symbol: symbol,
            asset_issuer: issuer,
            policy_source: d.source.clone(),
            module_digest: checked(native::unhex(&d.module_digest))?,
            max_fee_stroops: fee(i.max_fee_units)?,
        }
        .wallet_config(),
    )?;
    let actual = description(&c, &d.policy_id)?;
    if (!d.wallet.is_empty() && d.wallet != actual.wallet)
        || (!d.asset.is_empty() && d.asset != actual.asset)
        || d.source_hash != actual.source_hash
    {
        return Err(Error::config(
            "Derived installation differs from its admitted public identity",
        ));
    }
    Ok(Installation {
        description: actual,
        config: packet(&c.network, &c)?.document().to_owned(),
        export: None,
        authority: None,
    })
}
fn accounting(a: Option<&Accounting>) -> Option<rpc::NativeAccounting> {
    a.map(|a| rpc::NativeAccounting {
        nonce: a.nonce,
        deployment_version: a.deployment_version,
        spent_daily: a.spent_daily,
        spent_total: a.spent_total,
        spent_day: a.spent_day,
        volume_daily: a.volume_daily,
        unpriced_total: a.unpriced_total,
        unpriced_daily: a.unpriced_daily,
        calls: a.calls,
    })
}
fn fee(v: u64) -> Result<u32> {
    u32::try_from(v).map_err(|_| Error::usage("Fee ceiling exceeds the selected native range"))
}
/// The operation that a request names: an ordinary request, or the transfer of a request for
/// a payment authorization that the seller settles.
fn requested_operation(
    c: &WalletConfig,
    r: &native::workflow::ExecutionRequest,
) -> native::Result<native::StellarOperation> {
    if native::seller_settled::is_request(r) {
        native::seller_settled::transfer(c, r).map(native::StellarOperation::Transfer)
    } else {
        native::operation_from_request(c, r)
    }
}
fn status(v: native::OperationStatus) -> Status {
    match v {
        native::OperationStatus::Prepared => Status::Prepared,
        native::OperationStatus::Submitted => Status::Submitted,
        native::OperationStatus::SubmissionUnknown => Status::SubmissionUnknown,
        native::OperationStatus::Confirmed => Status::Confirmed,
        native::OperationStatus::Failed => Status::Failed,
    }
}
#[derive(Clone, Debug)]
pub struct PreparationCapability(PreparedOperation);

fn prepared(p: &Prepared) -> Result<PreparedOperation> {
    let v = if let Some(capability) = p.0.capability::<PreparationCapability>() {
        let original = &capability.0;
        if crate::host::routing::normalize(&original.config.network)? != p.0.network()
            || serde_json::to_string(original)
                .map_err(|_| Error::config("Cannot bind native preparation"))?
                != p.0.document().get()
        {
            return Err(Error::config(
                "In-memory preparation differs from its exact retained document",
            ));
        }
        original.clone()
    } else {
        decode_packet(&p.0)?
    };
    v.validate_packet(&p.0)?;
    Ok(v)
}
fn signed(p: &Signed) -> Result<SignedOperation> {
    let v: SignedOperation = decode_packet(&p.0)?;
    checked(native::validate_retained_signed(&v))?;
    Ok(v)
}
fn info_of(p: &PreparedOperation, hash: [u8; 32]) -> PacketInfo {
    PacketInfo {
        operation_id: p.request.operation.nonce,
        transaction_hash: hash,
        wallet: p.config.wallet.clone(),
        expires_at: p.expires_at,
    }
}
pub fn info(p: &Packet, k: Kind) -> Result<PacketInfo> {
    match k {
        Kind::Prepared => {
            let value: PreparedOperation = decode_packet(p)?;
            Ok(info_of(&value, value.transaction_hash))
        }
        Kind::Signed => {
            // A code transaction's identity is its transaction hash.
            if let Some(code) = signed_code(p)? {
                return Ok(PacketInfo {
                    operation_id: code.code.transaction_hash,
                    transaction_hash: code.code.transaction_hash,
                    wallet: code.code.source,
                    expires_at: code.code.expires_at,
                });
            }
            let s: SignedOperation = decode_packet(p)?;
            Ok(info_of(&s.prepared, s.transaction_hash))
        }
        _ => Err(Error::usage("This packet has no execution identity")),
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct OwnerSignedData {
    original: native::owner_intent::OwnerTransaction,
    signed_payload: Vec<u8>,
}
fn owner_payload(p: &OwnerSignedData) -> Result<&str> {
    std::str::from_utf8(&p.signed_payload)
        .map_err(|_| Error::usage("Invalid native signed owner payload"))
}
pub fn restore(k: Kind, document: Box<RawValue>) -> Result<Packet> {
    let network = match k {
        Kind::Prepared => decode::<PreparedOperation>(&document)?.config.network,
        Kind::Signed => match decode::<SignedCode>(&document) {
            Ok(code) => code.code.network,
            Err(_) => {
                decode::<SignedOperation>(&document)?
                    .prepared
                    .config
                    .network
            }
        },
        Kind::Owner => decode::<native::owner_intent::OwnerTransaction>(&document)?.network,
        Kind::OwnerSigned => decode::<OwnerSignedData>(&document)?.original.network,
        Kind::Receipt => {
            let receipt: rpc::VerifiedReceipt = decode(&document)?;
            native::networks::NETWORKS
                .iter()
                .find(|n| rpc::validate_receipt(&receipt, n.id, &receipt.transaction_hash).is_ok())
                .ok_or_else(|| Error::config("Receipt has no valid supported network identity"))?
                .id
                .into()
        }
        Kind::Request => {
            return Err(Error::usage(
                "Restore a request through its selected installation",
            ));
        }
    };
    let packet = Packet::from_raw(
        crate::host::routing::normalize(&network)?,
        document,
        &PACKETS,
    );
    match k {
        Kind::Prepared => {
            decode_packet::<PreparedOperation>(&packet)?;
        }
        Kind::Signed => {
            if signed_code(&packet)?.is_none() {
                decode_packet::<SignedOperation>(&packet)?;
            }
        }
        Kind::Owner => {
            decode_packet::<native::owner_intent::OwnerTransaction>(&packet)?;
        }
        Kind::OwnerSigned => {
            decode_packet::<OwnerSignedData>(&packet)?;
        }
        Kind::Receipt => {
            decode_packet::<rpc::VerifiedReceipt>(&packet)?;
        }
        Kind::Request => unreachable!(),
    }
    Ok(packet)
}
pub fn owner_info(p: &Packet) -> Result<OwnerInfo> {
    let original: native::owner_intent::OwnerTransaction = decode_packet(p)?;
    Ok(OwnerInfo {
        action: original.action,
        signing_payload: original.transaction_xdr.into_bytes(),
        transaction_hash: original.transaction_hash,
        expires_at: original.expires_at,
    })
}
// An account observation has no intrinsic network field. It describes caller-supplied
// observed state and never authorizes a transaction or selects an RPC network.
fn decode_observation(packet: &Packet) -> Result<rpc::DiscoveredState> {
    crate::host::routing::normalize(packet.network())?;
    let value: rpc::DiscoveredState = decode(packet.document())?;
    let s = &value.state;
    if s.policy_state.is_some() {
        // A policy wallet has no account: its configuration on chain names its roles. Its owner
        // is an account or a contract; its agent and server are keys.
        checked(native::address(&s.owner))?;
        for key in [&s.agent, &s.server] {
            checked(native::account_key(key))?;
        }
    } else {
        checked(s.source.validate_structure())?;
    }
    Ok(value)
}
pub fn same_snapshot(a: &Snapshot, b: &Snapshot) -> Result<bool> {
    if a.evidence.network() != b.evidence.network() {
        return Ok(false);
    }
    let mut a: rpc::DiscoveredState = decode_observation(&a.evidence)?;
    let mut b: rpc::DiscoveredState = decode_observation(&b.evidence)?;
    // Match the native revalidation rule: only the observation ledger can advance.
    a.state.ledger = 0;
    b.state.ledger = 0;
    Ok(a == b)
}
/// The gas carry of an operation: only a policy wallet operation that repays its gas takes one,
/// and a carry for any other operation is the caller's error.
fn gas_carry(repays_gas: bool, carry: u128) -> Result<u128> {
    match (repays_gas, carry) {
        (true, carry) => Ok(carry),
        (false, 0) => Ok(0),
        (false, _) => Err(Error::usage(
            "Only a policy wallet operation that repays its gas takes a gas carry",
        )),
    }
}
pub fn receipt_info(p: &Packet) -> Result<ReceiptInfo> {
    let r: rpc::VerifiedReceipt = decode_packet(p)?;
    let result: stellar_xdr::TransactionResult = checked(native::read(&r.result_xdr))?;
    // A policy wallet counts the gas units of its signed expense. A keypair account has no
    // counters: the engine prices its fee through ServerHooks::charged_fee.
    let charged_units = checked(rpc::counted_gas_units(&r))?;
    let repaid_native_units = checked(rpc::repaid_gas_stroops(&r))?;
    Ok(ReceiptInfo {
        // The settlement of a payment authorization keeps the identity of the retained
        // operation, and names the transaction that settled it apart.
        transaction_hash: r.settles.unwrap_or(r.transaction_hash),
        status: status(r.status),
        observed_height: u64::from(r.ledger),
        fee: crate::host::runtime::Fee {
            // The party that submitted a payment authorization paid the fee of its
            // transaction. The wallet paid and counted none.
            native_units: if r.settles.is_some() {
                0
            } else {
                u128::try_from(result.fee_charged)
                    .map_err(|_| Error::config("Invalid Stellar receipt fee"))?
            },
            charged_units,
            repaid_native_units,
        },
        // The prepared operation carries its debits; the receipt adds only the fee.
        debits: Vec::new(),
        settlement_hash: r.settles.map(|_| r.transaction_hash),
    })
}
pub struct Provider {
    network: String,
    runtime: crate::provider::runtime::Runtime,
    transport: std::sync::Arc<dyn rpc::Rpc>,
    sender: Option<Sender>,
}
/// The server's sending accounts (Core's `SendingAccounts`): the account that sends the next
/// policy wallet operation or code upload, pays its fee and receives its gas, and the
/// signature of a transaction hash with an account's key.
pub type Sender = std::sync::Arc<dyn SendingAccounts>;
pub use crate::host::runtime::SendingAccounts;
/// The fee that the signed transaction envelope `xdr` declares, in stroops: the most that the
/// ledger charges its source.
fn declared_fee(xdr: &str) -> Result<u32> {
    match checked(native::read::<stellar_xdr::TransactionEnvelope>(xdr))? {
        stellar_xdr::TransactionEnvelope::Tx(envelope) => Ok(envelope.tx.fee),
        _ => Err(Error::config(
            "A wallet code transaction is a plain transaction",
        )),
    }
}
/// The Ed25519 transaction signature of `hash` by the sending account `account`.
fn sending_signature(sender: &Sender, account: &str, hash: &[u8; 32]) -> Result<[u8; 64]> {
    sender
        .sign(account, hash)?
        .try_into()
        .map_err(|_| Error::config("A sending account returned a signature of another size"))
}
/// A wallet code transaction that a sending account signed: the upload of wallet code, or the
/// restoration of lapsed code by its hash (`RuntimeProvider::prepare_code_within`). The rail
/// sends nothing: the caller submits it with `broadcast` and follows it with `status` and
/// `observe`, as any signed operation.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SignedCode {
    /// The transaction, `upload_wasm` or `restore_code`, from the sending account, unsigned.
    pub code: native::admin::PreparedDeployment,
    /// The same transaction with the sending account's signature.
    pub signed_xdr: String,
}
/// The code transaction that the signed packet `p` carries, `None` for any other signed packet.
/// Its bytes are checked: the signed envelope is the prepared transaction with one signature
/// of its source, and the transaction uploads or restores its code alone.
fn signed_code(p: &Packet) -> Result<Option<SignedCode>> {
    let Ok(s) = serde_json::from_str::<SignedCode>(p.document().get()) else {
        return Ok(None);
    };
    if crate::host::routing::normalize(&s.code.network)? != p.network() {
        return Err(Error::config(
            "The code transaction's network differs from its packet",
        ));
    }
    checked(native::admin::check_signed_code(&s.code, &s.signed_xdr))?;
    Ok(Some(s))
}
fn code_of(p: &Signed) -> Result<SignedCode> {
    signed_code(&p.0)?.ok_or_else(|| Error::usage("This packet is not a wallet code transaction"))
}
impl Provider {
    /// The upload of the wallet code `wasm`, from a sending account and signed by it. A simulated
    /// fee above `max_fee_stroops` is refused before anything is signed. `None` when the code is
    /// live. Code that lapsed is refused as `CONTRACT_EXPIRED`: nothing restores it.
    ///
    /// The step trusts the reads and simulations of the one RPC that the server configured (see
    /// the crate README). Another transaction, from another sending account or from the same
    /// one, can make the code live while the step runs: the code is read first, again after
    /// every refusal on the way to the signature, and again just before the signature, and
    /// live code needs nothing.
    fn prepare_code(
        &self,
        i: &Installation,
        wasm: &[u8],
        max_fee_stroops: u32,
        now: u64,
    ) -> Result<Option<SignedCode>> {
        let c = self.config(i)?;
        if c.route != WalletRoute::PolicyWallet {
            return Err(Error::unsupported(
                "A keypair wallet has no code: its owner creates it with the wallet setup",
            ));
        }
        let code_hash = checked(native::admin::check_wallet_code(wasm))?;
        let live = || {
            matches!(
                rpc::code_state(self.rpc(), &c.network, &code_hash),
                Ok(rpc::CodeState::Live)
            )
        };
        match checked(rpc::code_state(self.rpc(), &c.network, &code_hash))? {
            rpc::CodeState::Live => return Ok(None),
            rpc::CodeState::Lapsed => return Err(Error::config(rpc::CONTRACT_EXPIRED)),
            rpc::CodeState::Absent => {}
        }
        // A refusal can come from the transaction that made the code live: a simulated fee above
        // the ceiling for a write that is no longer needed, the sending account's sequence that
        // its own upload advanced, or sending accounts that are all busy with it. Live code
        // needs nothing; otherwise the refusal stands.
        let unless_live = |refused: Error| if live() { Ok(None) } else { Err(refused) };
        let prepare = || -> Result<Option<(&Sender, String, native::admin::PreparedDeployment)>> {
            let sender = self.sender.as_ref().ok_or_else(|| {
                Error::config("This server has no sending account to upload wallet code")
            })?;
            let account = sender.account()?;
            // The server pays the upload, a cost that the ledger consumes; the simulation sets
            // it, within the ceiling.
            let deployer = native::admin::Deployer {
                rpc: self.rpc(),
                network: &c.network,
                now,
                max_fee_stroops,
            };
            Ok(checked(deployer.upload_wasm(&account, wasm))?.map(|p| (sender, account, p)))
        };
        let (sender, account, p) = match prepare() {
            Ok(Some(prepared)) => prepared,
            Ok(None) => return Ok(None),
            Err(refused) => return unless_live(refused),
        };
        if checked(rpc::code_state(self.rpc(), &c.network, &code_hash))? == rpc::CodeState::Live {
            return Ok(None);
        }
        let signed_xdr = match self.code_signature(sender, &account, &c.network, &p) {
            Ok(signed) => signed,
            Err(refused) => return unless_live(refused),
        };
        Ok(Some(SignedCode {
            code: p,
            signed_xdr,
        }))
    }
    /// The extension that the live code `code_hash` needs now: the network's minimum lifetime of a
    /// persistent entry once at most half of it is left, `None` before. Code that lapsed or that is
    /// not on the network is refused: nothing restores it.
    fn renewal_due(&self, code_hash: &[u8; 32]) -> Result<Option<u32>> {
        let Some((live_until, closing)) =
            checked(rpc::code_lifetime(self.rpc(), &self.network, code_hash))?
        else {
            return Err(Error::usage("The wallet code is not on the network"));
        };
        if live_until < closing {
            return Err(Error::usage(
                "The wallet code lapsed on the network: nothing restores it",
            ));
        }
        let minimum = checked(rpc::minimum_persistent_lifetime(self.rpc()))?;
        Ok((live_until - closing <= minimum / 2).then_some(minimum))
    }
    /// Prepare the renewal of the live code `code_hash`, signed by a sending account, once it is
    /// due (`renewal_due`). The code is read again before the signature: a renewal that another
    /// transaction made needless is not signed.
    fn prepare_renewal(
        &self,
        code_hash: &[u8; 32],
        max_fee_stroops: u32,
        now: u64,
    ) -> Result<Option<SignedCode>> {
        let Some(extend_to) = self.renewal_due(code_hash)? else {
            return Ok(None);
        };
        let unless_renewed = |refused: Error| match self.renewal_due(code_hash) {
            Ok(None) => Ok(None),
            _ => Err(refused),
        };
        let sender = self.sender.as_ref().ok_or_else(|| {
            Error::config("This server has no sending account to renew wallet code")
        })?;
        let prepared = sender.account().and_then(|account| {
            let deployer = native::admin::Deployer {
                rpc: self.rpc(),
                network: &self.network,
                now,
                max_fee_stroops,
            };
            Ok((
                checked(deployer.renew_code(&account, *code_hash, extend_to))?,
                account,
            ))
        });
        let (p, account) = match prepared {
            Ok(prepared) => prepared,
            Err(refused) => return unless_renewed(refused),
        };
        if self.renewal_due(code_hash)?.is_none() {
            return Ok(None);
        }
        let signed_xdr = match self.code_signature(sender, &account, &self.network, &p) {
            Ok(signed) => signed,
            Err(refused) => return unless_renewed(refused),
        };
        Ok(Some(SignedCode {
            code: p,
            signed_xdr,
        }))
    }
    /// The envelope of the code transaction `p` with the signature of its source `account`.
    fn code_signature(
        &self,
        sender: &Sender,
        account: &str,
        network: &str,
        p: &native::admin::PreparedDeployment,
    ) -> Result<String> {
        sending_signature(sender, account, &p.transaction_hash).and_then(|signature| {
            checked(native::admin::with_source_signature(
                network,
                &p.transaction_xdr,
                &signature,
            ))
        })
    }
    /// Send the code transaction `s` once. `Prepared` when the network did not accept it:
    /// nothing is pending, and the caller can send the same bytes again while it is needed. A
    /// send never returns a final status: only the receipt (`observe_code`) is final.
    fn broadcast_code(&self, s: &SignedCode, now: u64) -> Result<Status> {
        if now > s.code.expires_at {
            return Err(Error::usage("The code transaction expired"));
        }
        let network = &s.code.network;
        Ok(
            match checked(rpc::send_transaction(self.rpc(), network, &s.signed_xdr))? {
                rpc::Broadcast::Submitted => Status::Submitted,
                rpc::Broadcast::RetryLater => Status::Prepared,
                rpc::Broadcast::Unknown => Status::SubmissionUnknown,
                // A transaction that the network rejected is not pending and cost nothing, unless
                // an earlier send of the same bytes applied: then its receipt decides.
                rpc::Broadcast::Rejected { .. } => {
                    match checked(rpc::receipt_by_hash(
                        self.rpc(),
                        network,
                        &s.code.transaction_hash,
                    ))? {
                        Some(_) => Status::Submitted,
                        None => Status::Prepared,
                    }
                }
            },
        )
    }
    /// The receipt of the code transaction `s`, once the ledger included it. A transaction that
    /// the ledger failed has a receipt too, whose fee its source paid. The ledger charges a
    /// transaction at most the fee that it declares: a receipt that reports more is refused.
    fn observe_code(&self, s: &SignedCode) -> Result<Option<Receipt>> {
        let network = &s.code.network;
        // The ledger's own envelope is the signed transaction, before any fee bump is read.
        let Some(receipt) = checked(rpc::own_receipt_by_hash(
            self.rpc(),
            network,
            &s.code.transaction_hash,
            &s.signed_xdr,
        ))?
        else {
            return Ok(None);
        };
        checked(rpc::validate_own_receipt(
            &receipt,
            network,
            &s.code.transaction_hash,
        ))?;
        if receipt.envelope_xdr != s.signed_xdr {
            return Err(Error::config(
                "The receipt's envelope differs from the code transaction",
            ));
        }
        let packet = packet(network, &receipt)?;
        if receipt_info(&packet)?.fee.native_units > u128::from(declared_fee(&s.signed_xdr)?) {
            return Err(crate::provider::failure(
                "The receipt reports a fee above the fee of its transaction",
            ));
        }
        Ok(Some(Receipt(packet)))
    }
    /// One owner action on a keypair wallet: a transaction from the owner's account whose
    /// operations the owner's signature authorizes alone. `Recover` without an amount closes
    /// the wallet: every signer is removed and the account merges into the owner's account.
    fn prepare_wallet_owner(
        &self,
        c: &WalletConfig,
        a: OwnerAction,
        fee_limit: u64,
        now: u64,
    ) -> Result<OwnerPacket> {
        use native::owner::WalletAction;
        let asset = checked(native::asset_xdr(c))?;
        let units = |units: i128| {
            i64::try_from(units).map_err(|_| Error::usage("The amount exceeds the native range"))
        };
        let action = match a {
            OwnerAction::Fund { units: amount } => WalletAction::Fund {
                units: units(amount)?,
            },
            OwnerAction::SetPause { paused: true } => WalletAction::Pause,
            OwnerAction::SetPause { paused: false } => WalletAction::Resume,
            OwnerAction::Recover {
                units: Some(amount),
                recipient,
            } => WalletAction::Withdraw {
                units: units(amount)?,
                recipient,
            },
            OwnerAction::Recover {
                units: None,
                recipient: None,
            } => WalletAction::Close {
                token_balance: if asset == stellar_xdr::Asset::Native {
                    0
                } else {
                    checked(rpc::trustline_balance(self.rpc(), &c.wallet, &asset))?.unwrap_or(0)
                },
            },
            // Every spendable unit returns and the account stays. It keeps the reserve of the
            // entries that it holds, and of the agent signer that a paused wallet lacks, so
            // its owner can restore that signer and fund the wallet again.
            OwnerAction::Recover {
                units: None,
                recipient: Some(recipient),
            } => {
                let spendable = if asset == stellar_xdr::Asset::Native {
                    let paused = checked(
                        checked(rpc::get_account(self.rpc(), &c.wallet))?
                            .wallet_status(&c.owner, &c.agent, &c.server),
                    )? == native::owner::WalletStatus::Paused;
                    checked(rpc::native_balance(self.rpc(), &c.wallet))?
                        .spendable(i64::from(paused))
                } else {
                    checked(rpc::trustline_spendable(self.rpc(), &c.wallet, &asset))?.unwrap_or(0)
                };
                if spendable <= 0 {
                    return checked(Err(super::diagnostics::NOTHING_TO_RETURN.into()));
                }
                WalletAction::Withdraw {
                    units: spendable,
                    recipient: Some(recipient),
                }
            }
            OwnerAction::Create { .. } | OwnerAction::Extend => {
                return Err(Error::unsupported(
                    "A keypair wallet has no code: its owner creates it with the wallet setup",
                ));
            }
        };
        let owner_state = checked(rpc::get_account(self.rpc(), &c.owner))?;
        let wallet_state = checked(rpc::get_account(self.rpc(), &c.wallet))?;
        // Each operation bids the same share of the caller's fee limit, within the bounds of
        // one classic operation.
        let fee_per_operation = u32::try_from((fee_limit / 6).clamp(100, 10_000))
            .map_err(|_| Error::usage("Invalid owner fee limit"))?;
        let p = checked(native::owner::prepare_wallet_action(
            &owner_state,
            &wallet_state,
            native::owner::WalletRoles {
                wallet: &c.wallet,
                owner: &c.owner,
                agent: &c.agent,
                engine: &c.server,
            },
            &action,
            &asset,
            &c.network,
            fee_per_operation,
            now,
        ))?;
        // A fee limit below the minimum fee of every operation prepares nothing: the declared
        // fee never exceeds the caller's limit.
        let stellar_xdr::TransactionEnvelope::Tx(envelope) = checked(native::read::<
            stellar_xdr::TransactionEnvelope,
        >(&p.transaction_xdr))?
        else {
            return Err(Error::config("Invalid prepared owner transaction"));
        };
        if u64::from(envelope.tx.fee) > fee_limit {
            return Err(Error::usage(format!(
                "The fee limit is below the minimum fee of {} for the {} operations of this action",
                envelope.tx.fee,
                envelope.tx.operations.len()
            )));
        }
        Ok(OwnerPacket(packet(&c.network, &p)?))
    }
    pub fn new(network: &str, endpoint: &str) -> Result<Self> {
        Ok(Self::from_rpc_inner(
            network,
            std::sync::Arc::new(checked(rpc::HttpRpc::new(endpoint))?),
        ))
    }
    fn from_rpc_inner(network: &str, inner: std::sync::Arc<dyn rpc::Rpc>) -> Self {
        Self {
            network: network.into(),
            runtime: super::runtime::Runtime::from_rpc(inner.clone()),
            transport: inner,
            sender: None,
        }
    }
    /// This provider with the signing capability of the server's sending accounts.
    pub fn with_sender(mut self, sender: Sender) -> Self {
        self.sender = Some(sender);
        self
    }
    /// The sending account for the next policy wallet operation.
    fn sending_account(&self) -> Result<String> {
        let sender = self.sender.as_ref().ok_or_else(|| {
            Error::config("This server has no sending account for policy wallet operations")
        })?;
        sender.account()
    }
    #[cfg(test)]
    pub fn from_rpc(network: &str, rpc: std::sync::Arc<dyn rpc::Rpc>) -> Self {
        Self::from_rpc_inner(network, rpc)
    }
    pub fn with_transport(network: &str, transport: std::sync::Arc<dyn Transport>) -> Result<Self> {
        struct Bridge(std::sync::Arc<dyn Transport>);
        impl rpc::Rpc for Bridge {
            fn call(
                &self,
                method: &str,
                params: serde_json::Value,
            ) -> native::Result<serde_json::Value> {
                self.0
                    .call(method, params)
                    .map_err(|error| error.to_string())
            }
        }
        let network = crate::host::routing::normalize(network)?;
        Ok(Self::from_rpc_inner(
            network,
            std::sync::Arc::new(Bridge(transport)),
        ))
    }
    fn rpc(&self) -> &dyn rpc::Rpc {
        self.runtime.rpc()
    }
    fn network(&self, network: &str) -> Result<()> {
        if crate::host::routing::normalize(network)? != self.network {
            Err(Error::config(
                "Runtime and retained packet belong to different rails",
            ))
        } else {
            Ok(())
        }
    }
    fn config(&self, i: &Installation) -> Result<WalletConfig> {
        self.network(&i.description.network)?;
        let c: WalletConfig = decode(&i.config)?;
        self.network(&c.network)?;
        checked(native::validate_config(&c))?;
        Ok(c)
    }
    /// Before the server signs for a policy wallet, require its live instance to run the
    /// installation's code, and that code to be live: a wallet whose instance or code lapsed is
    /// `CONTRACT_EXPIRED`, and one whose owner installed other code, or that is gone, is refused.
    /// The operation's last simulation may precede either.
    fn refuse_lapsed(&self, c: &WalletConfig) -> Result<()> {
        if c.route != WalletRoute::PolicyWallet {
            return Ok(());
        }
        match checked(rpc::instance_code(self.rpc(), &c.network, &c.wallet))? {
            Some(running) if running == c.module_digest => {}
            Some(_) => {
                return Err(Error::config(
                    "The wallet runs other code than its installation names",
                ));
            }
            None => return Err(Error::config("The wallet is not on the network")),
        }
        match checked(rpc::code_state(self.rpc(), &c.network, &c.module_digest))? {
            rpc::CodeState::Live => Ok(()),
            rpc::CodeState::Lapsed => Err(Error::config(rpc::CONTRACT_EXPIRED)),
            rpc::CodeState::Absent => Err(Error::config("The wallet's code is not on the network")),
        }
    }
    fn fresh(&self, i: &Installation) -> Result<WalletConfig> {
        let c = self.config(i)?;
        if c.route == WalletRoute::Native {
            let a = i.authority.as_ref().ok_or_else(|| {
                Error::config("Fresh Native operations require independent public server authority")
            })?;
            self.network(a.network())?;
            let raw = i.export.as_ref().ok_or_else(|| {
                Error::config("Fresh Native operations require actual administrator source consent")
            })?;
            let b = crate::provider::runtime::client::decode_public_bundle(raw.get().as_bytes())?;
            b.verify_server_role(a.public_key())?;
            b.verify_import_with(self.rpc())?;
            if b.config != c {
                return Err(Error::config(
                    "Native installation differs from its source approval",
                ));
            }
        }
        Ok(c)
    }
    fn current(&self, i: &Installation, p: &Prepared, now: u64) -> Result<PreparedOperation> {
        let c = self.fresh(i)?;
        self.network(p.network())?;
        let p = prepared(p)?;
        if c != p.config {
            return Err(Error::config(
                "Prepared packet differs from the admitted installation",
            ));
        }
        checked(native::validate_prepared(&p, now))?;
        if p.payment_authorization.is_some() {
            checked(native::seller_settled::revalidate(self.rpc(), &p, now))?;
            return Ok(p);
        }
        if c.route == WalletRoute::Native {
            let current = checked(rpc::get_account(self.rpc(), &c.wallet))?;
            checked(current.validate_roles(&c.owner, &c.agent, &c.server))?;
            if current != p.state.source {
                return Err(Error::uncertain(
                    "Native source changed before signing. Retain the original packet.",
                ));
            }
            Ok(p)
        } else {
            checked(self.runtime.revalidate_unsigned(&p, now))
        }
    }
    fn packet(&self, p: &PreparedOperation) -> Result<Prepared> {
        Ok(Prepared(
            packet(&p.config.network, p)?.with_capability(PreparationCapability(p.clone())),
        ))
    }
}
/// The terminal contract error of a refused simulation reply and its client-visible problem.
/// The fault belongs to `wallet` only when the simulated transaction invokes `wallet`
/// (`invoked`) and the host events of the reply name it as the one contract that raised the
/// error. Without both proofs the problem is a plain rejection.
fn simulation_problem(
    wallet: &str,
    invoked: Option<&str>,
    reply: &serde_json::Value,
) -> Option<(String, Problem)> {
    let error = reply["error"].as_str()?;
    let mut fault = rpc::simulation_fault(error, &diagnostic_events(reply))?;
    if invoked != Some(wallet) {
        fault.contract = None;
    }
    let problem = super::diagnostics::denial(error, Some(&fault), wallet);
    Some((error.into(), problem))
}
/// The `events` of a simulation reply. An entry that is not a string stays as an empty one,
/// which does not decode, so a malformed list proves nothing.
fn diagnostic_events(reply: &serde_json::Value) -> Vec<String> {
    reply["events"]
        .as_array()
        .map(|events| {
            events
                .iter()
                .map(|event| event.as_str().unwrap_or_default().to_owned())
                .collect()
        })
        .unwrap_or_default()
}
impl crate::host::vendors::RuntimeProvider for Provider {
    fn problem(&self, error: &Error) -> Problem {
        super::diagnostics::denial(&error.to_string(), None, "")
    }
    fn diagnostic_session(&self, installation: &Installation) -> Result<Option<DiagnosticSession>> {
        let config = self.config(installation)?;
        struct Probe {
            inner: std::sync::Arc<dyn rpc::Rpc>,
            wallet: String,
            captured: std::sync::Arc<std::sync::Mutex<Option<(String, Problem)>>>,
        }
        impl rpc::Rpc for Probe {
            fn call(
                &self,
                method: &str,
                params: serde_json::Value,
            ) -> native::Result<serde_json::Value> {
                // The contract that this simulation invokes, read from the request itself.
                let invoked = (method == "simulateTransaction")
                    .then(|| {
                        params["transaction"]
                            .as_str()
                            .and_then(rpc::simulated_contract)
                    })
                    .flatten();
                let value = self.inner.call(method, params)?;
                if method == "simulateTransaction"
                    && let Some((error, problem)) =
                        simulation_problem(&self.wallet, invoked.as_deref(), &value)
                {
                    if let Ok(mut captured) = self.captured.lock() {
                        *captured = Some((error.clone(), problem));
                    }
                    // This terminal contract failure propagates directly to this operation.
                    // Missing-export probes and other native response handling remain unchanged.
                    return Err(error);
                }
                Ok(value)
            }
        }
        let captured = std::sync::Arc::new(std::sync::Mutex::new(None));
        let probe = std::sync::Arc::new(Probe {
            inner: self.transport.clone(),
            wallet: config.wallet,
            captured: captured.clone(),
        });
        // The session sends and signs as this provider does: it keeps the sending accounts.
        let mut provider = Self::from_rpc_inner(&self.network, probe);
        provider.sender = self.sender.clone();
        Ok(Some(DiagnosticSession {
            provider: Box::new(provider),
            classify: Box::new(move |error| {
                captured
                    .lock()
                    .ok()
                    .and_then(|mut capture| capture.take())
                    .filter(|(message, _)| message == &error.message)
                    .map(|(_, problem)| problem)
                    .unwrap_or_else(|| super::diagnostics::denial(&error.to_string(), None, ""))
            }),
        }))
    }

    fn discover_snapshot(
        &self,
        configuration: &crate::host::runtime::owner::Configuration,
        counters: Option<&Accounting>,
    ) -> Result<Snapshot> {
        let c: WalletConfig = serde_json::from_slice(configuration.bytes())
            .map_err(|_| Error::config("Invalid native configuration"))?;
        self.network(&c.network)?;
        checked(native::validate_config(&c))?;
        let live = checked(rpc::trusted_state_for_discovery(
            self.rpc(),
            &c,
            accounting(counters),
        ))?;
        snapshot_from(&c.network, live)
    }
    fn current_height(&self) -> Result<u64> {
        if checked(self.rpc().call("getNetwork", serde_json::json!({})))?["passphrase"].as_str()
            != Some(checked(native::passphrase(&self.network))?)
        {
            return Err(Error::config("Runtime transport network differs"));
        }
        checked(self.rpc().call("getLatestLedger", serde_json::json!({})))?["sequence"]
            .as_u64()
            .filter(|v| *v > 0)
            .ok_or_else(|| Error::config("Missing current height"))
    }
    fn observe_hash(&self, hash: &[u8; 32]) -> Result<Option<Receipt>> {
        self.current_height()?;
        checked(rpc::receipt_by_hash(self.rpc(), &self.network, hash))?
            .map(|r| packet(&self.network, &r).map(Receipt))
            .transpose()
    }

    fn import(&self, a: &ServerAuthority, bytes: &[u8]) -> Result<Installation> {
        self.network(a.network())?;
        let b = crate::provider::runtime::client::decode_public_bundle(bytes)?;
        b.verify_server_role(a.public_key())?;
        b.verify_import_with(self.rpc())?;
        self.network(&b.network)?;
        Ok(Installation {
            description: description(&b.config, &b.policy_id)?,
            config: packet(&b.network, &b.config)?.document().to_owned(),
            export: Some(
                RawValue::from_string(
                    std::str::from_utf8(bytes)
                        .map_err(|_| Error::config("Public export must use UTF-8"))?
                        .into(),
                )
                .map_err(|_| Error::config("Invalid public export"))?,
            ),
            authority: Some(a.clone()),
        })
    }
    fn request(
        &self,
        i: &Installation,
        id: [u8; 32],
        a: Action,
        counters: Option<&Accounting>,
    ) -> Result<RequestPacket> {
        let c = self.fresh(i)?;
        let state = checked(rpc::trusted_state(self.rpc(), &c, accounting(counters)))?;
        let r = checked(match a {
            Action::Transfer { recipient, units } => {
                native::request::transfer(&c, &state, id, &recipient, units)
            }
            Action::Deposit {
                vault,
                assets,
                min_shares,
            } => native::request::deposit(&c, &state, id, &vault, assets, min_shares),
            Action::Redeem {
                vault,
                shares,
                min_assets,
            } => native::request::redeem(&c, &state, id, &vault, shares, min_assets),
        })?;
        Ok(RequestPacket(packet(&c.network, &r)?))
    }
    fn read_request(&self, i: &Installation, bytes: &[u8]) -> Result<RequestPacket> {
        let c = self.config(i)?;
        let r: native::workflow::ExecutionRequest = serde_json::from_slice(bytes)
            .map_err(|_| Error::usage("Invalid native execution request"))?;
        checked(requested_operation(&c, &r))?;
        let document = RawValue::from_string(
            std::str::from_utf8(bytes)
                .map_err(|_| Error::usage("Invalid native request encoding"))?
                .into(),
        )
        .map_err(|_| Error::usage("Invalid native execution request"))?;
        Ok(RequestPacket(Packet::from_raw(
            crate::host::routing::normalize(&c.network)?,
            document,
            &PACKETS,
        )))
    }
    fn snapshot(&self, i: &Installation, a: Option<&Accounting>) -> Result<Snapshot> {
        let c = self.fresh(i)?;
        let state = checked(rpc::trusted_state(self.rpc(), &c, accounting(a)))?;
        // Fresh admission rejects paused automation. Read-only discovery has a separate API.
        snapshot_from(
            &c.network,
            rpc::DiscoveredState {
                state,
                paused: false,
            },
        )
    }
    fn action(&self, i: &Installation, r: &RequestPacket) -> Result<Action> {
        let c = self.config(i)?;
        self.network(r.network())?;
        let r = decode_packet(&r.0)?;
        Ok(match checked(requested_operation(&c, &r))? {
            native::StellarOperation::Transfer(t) => Action::Transfer {
                recipient: t.recipient,
                units: t.amount,
            },
            native::StellarOperation::Deposit(t) => Action::Deposit {
                vault: t.vault,
                assets: t.assets,
                min_shares: t.min_shares,
            },
            native::StellarOperation::Redeem(t) => Action::Redeem {
                vault: t.vault,
                shares: t.shares,
                min_assets: t.min_assets,
            },
        })
    }
    fn resources(&self, i: &Installation) -> Result<Resources> {
        let c = self.config(i)?;
        if c.route == WalletRoute::Native {
            // A keypair wallet has no code and no lifetime: it is present when its account is.
            return Ok(Resources {
                code_present: true,
                wallet_present: checked(rpc::find_account(self.rpc(), &c.wallet))?.is_some(),
                lifetime: None,
            });
        }
        // Nothing restores a lapsed wallet: a wallet whose instance or code lapsed is
        // `CONTRACT_EXPIRED`. Code that is absent, for a wallet not created yet, is not present.
        // The code is the one that the instance runs: a wallet whose owner installed other code
        // outside Allowit did not lapse with the installation's code.
        let code = checked(rpc::code_state(self.rpc(), &c.network, &c.module_digest))?;
        let running = checked(rpc::instance_code(self.rpc(), &c.network, &c.wallet))?;
        if running.is_some_and(|running| running != c.module_digest) {
            return Err(Error::config(
                "The wallet runs other code than its installation names",
            ));
        }
        let wallet_present = running.is_some();
        if wallet_present && code == rpc::CodeState::Lapsed {
            return Err(Error::config(rpc::CONTRACT_EXPIRED));
        }
        let code_present = code == rpc::CodeState::Live;
        // A lifetime reads live entries only: lapsed code has none until it is restored.
        let lifetime = if wallet_present && code_present {
            let l = checked(rpc::wallet_lifetime(
                self.rpc(),
                &c.network,
                &c.wallet,
                &c.module_digest,
            ))?;
            Some(Lifetime {
                observed_height: u64::from(l.ledger),
                instance_until: u64::from(l.instance_live_until),
                code_until: u64::from(l.code_live_until),
                extension_target: u64::from(checked(l.extend_to())?),
                needs_renewal: checked(l.needs_renewal())?,
            })
        } else {
            None
        };
        Ok(Resources {
            code_present,
            wallet_present,
            lifetime,
        })
    }
    fn redeemable(&self, i: &Installation, vault: &str, shares: i128) -> Result<i128> {
        let c = self.fresh(i)?;
        // The read simulates from an account that exists: the sending account of a policy
        // wallet, or the keypair wallet itself.
        let source = if c.route == WalletRoute::PolicyWallet {
            checked(rpc::get_account(self.rpc(), &self.sending_account()?))?
        } else {
            checked(rpc::trusted_state_for_discovery(self.rpc(), &c, None))?
                .state
                .source
        };
        checked(rpc::vault_redeemable(
            self.rpc(),
            &c,
            &source,
            vault,
            shares,
        ))
    }
    fn finish<'a>(
        &self,
        i: &Installation,
        p: &Prepared,
        retain: Box<dyn FnOnce(&Prepared) -> Result<()> + 'a>,
    ) -> Result<Prepared> {
        let c = self.fresh(i)?;
        let p = prepared(p)?;
        if c != p.config {
            return Err(Error::config(
                "Retained authorization differs from selected installation",
            ));
        }
        checked(native::validate_server_authorization(&p))?;
        let out = checked(self.runtime.finalize_authorization(
            &p,
            |p| Ok(p.clone()),
            |p| retain(&self.packet(p).map_err(|e| e.message)?).map_err(|e| e.message),
        ))?;
        self.packet(&out)
    }
    fn prepare(
        &self,
        i: &Installation,
        r: &RequestPacket,
        t: &Terms,
        a: Option<&Accounting>,
        v: Validity,
    ) -> Result<Prepared> {
        let c = self.fresh(i)?;
        self.network(r.network())?;
        let terms = native::ExecutionTerms {
            args: params(&t.args)?,
            expense: t
                .expense
                .as_ref()
                .map(|e| {
                    Ok(native::ExpenseBounds {
                        gas_units: e.gas_units,
                        conversion_units: e.conversion_units,
                        spent_units: e.spent_units,
                        max_fee_stroops: fee(e.max_fee_units)?,
                        observed_ledger: u32::try_from(e.observed_height).map_err(|_| {
                            Error::usage("Observation height exceeds selected native range")
                        })?,
                        day: e.day,
                    })
                })
                .transpose()?,
            gas: None,
            sender: None,
            gas_carry: 0,
        };
        let accounting = accounting(a);
        let request: native::workflow::ExecutionRequest = decode_packet(&r.0)?;
        // A policy wallet operation is sent by one of the server's sending accounts, which pays
        // its fee and receives the gas: the priced expense's fee bound.
        let mut terms = terms;
        let repays_gas =
            c.route == WalletRoute::PolicyWallet && !native::seller_settled::is_request(&request);
        if repays_gas {
            terms.sender = Some(self.sending_account()?);
        }
        terms.gas_carry = gas_carry(repays_gas, t.gas_carry_units)?;
        if native::seller_settled::is_request(&request) {
            return self.packet(&checked(native::seller_settled::prepare(
                self.rpc(),
                &c,
                &request,
                &terms,
                accounting,
                v.now,
                v.expires_at,
            ))?);
        }
        self.packet(&checked(self.runtime.prepare(
            &c,
            &request,
            &terms,
            accounting,
            v.now,
            v.expires_at,
        ))?)
    }
    fn authorize_preparation(
        &self,
        i: &Installation,
        p: &Prepared,
        s: &dyn Signer,
        e: Option<Evaluator<'_>>,
        now: u64,
    ) -> Result<Prepared> {
        let c = self.fresh(i)?;
        let p = prepared(p)?;
        if c != p.config {
            return Err(Error::config(
                "Authorization differs from selected installation",
            ));
        }
        self.refuse_lapsed(&c)?;
        // A classic account has no server authorization entry: the server admits the
        // operation here, with its evaluator, and signs the transaction at execution.
        if c.route == WalletRoute::Native {
            checked(native::admit_classic(&p, s.identity(), now, e))?;
            // A payment authorization can settle after its operation expires, so the whole
            // policy must still allow the payment a margin later.
            if p.payment_authorization.is_some() {
                checked(native::seller_settled::admit_later(&p, e))?;
            }
            return self.packet(&p);
        }
        // A wallet that is no classic account: the rail decides in one place whether its
        // kind signs a payment authorization.
        if p.payment_authorization.is_some() {
            native::seller_settled::signs(&p.config)
                .map_err(|error| Error::unsupported(error.to_string()))?;
        }
        self.packet(&checked(native::authorize_server_using(
            &p,
            s.identity(),
            now,
            e,
            |digest| {
                s.sign_hash(digest)
                    .map_err(|e| e.message)?
                    .try_into()
                    .map_err(|_| "Native signer returned another signature length".into())
            },
        ))?)
    }
    fn finalize<'a>(
        &self,
        i: &Installation,
        p: &Prepared,
        s: &dyn Signer,
        e: Option<Evaluator<'_>>,
        now: u64,
        retain: Box<dyn FnOnce(&Prepared) -> Result<()> + 'a>,
    ) -> Result<Prepared> {
        let c = self.fresh(i)?;
        let p = prepared(p)?;
        if c != p.config {
            return Err(Error::config(
                "Authorization differs from selected installation",
            ));
        }
        self.refuse_lapsed(&c)?;
        let finalized = checked(self.runtime.finalize_authorization(
            &p,
            |p| {
                native::authorize_server_using(p, s.identity(), now, e, |digest| {
                    let v = s.sign_hash(digest).map_err(|e| e.message)?;
                    v.try_into()
                        .map_err(|_| "Native signer returned another signature length".into())
                })
            },
            |p| retain(&self.packet(p).map_err(|e| e.message)?).map_err(|e| e.message),
        ))?;
        self.packet(&finalized)
    }
    fn revalidate(&self, i: &Installation, p: &Prepared, now: u64) -> Result<Prepared> {
        let c = self.fresh(i)?;
        self.network(p.network())?;
        let retained = prepared(p)?;
        if c != retained.config {
            return Err(Error::config(
                "Prepared packet differs from the admitted installation",
            ));
        }
        // Explicit native RPC revalidation establishes a new in-memory preflight only
        // after checking the retained packet, service authorization and current state.
        // Signing still uses `current`, which requires an existing genuine preflight.
        if retained.payment_authorization.is_some() {
            checked(native::seller_settled::revalidate(
                self.rpc(),
                &retained,
                now,
            ))?;
            return self.packet(&retained);
        }
        if c.route == WalletRoute::PolicyWallet {
            self.packet(&checked(self.runtime.revalidate_unsigned(&retained, now))?)
        } else {
            self.packet(&self.current(i, p, now)?)
        }
    }
    fn sign(&self, i: &Installation, p: &Prepared, s: &dyn Signer, now: u64) -> Result<Signature> {
        let p = self.current(i, p, now)?;
        let s = checked(native::sign_with(&p, s.identity(), now, |d| {
            s.sign_hash(d)
                .map_err(|e| e.message)?
                .try_into()
                .map_err(|_| "Native signer returned another signature length".into())
        }))?;
        Ok(Signature {
            identity: s.signer,
            bytes: s.signature,
        })
    }
    fn authorize(
        &self,
        i: &Installation,
        p: &Prepared,
        s: &[Signature],
        now: u64,
    ) -> Result<Signed> {
        let p = self.current(i, p, now)?;
        let s = s
            .iter()
            .map(|s| native::DetachedSignature {
                signer: s.identity.clone(),
                signature: s.bytes.clone(),
            })
            .collect::<Vec<_>>();
        let signed = if p.payment_authorization.is_some() {
            checked(native::seller_settled::authorize(self.rpc(), &p, &s, now))?
        } else {
            checked(native::authorize(&p, &s, now))?
        };
        // A policy wallet operation leaves this step final: the sending account that the request
        // names as its fee payer seals it, so the retained packet is the transaction the network
        // gets.
        let signed =
            if p.config.route == WalletRoute::PolicyWallet && p.payment_authorization.is_none() {
                let sender = self.sender.as_ref().ok_or_else(|| {
                    Error::config("This server has no sending account for policy wallet operations")
                })?;
                let source = checked(native::gas_payee(&p.request, &p.terms))?;
                checked(rpc::seal(self.rpc(), &signed, |hash| {
                    sending_signature(sender, &source, hash).map_err(|e| e.message)
                }))?
            } else {
                signed
            };
        Ok(Signed(packet(&p.config.network, &signed)?))
    }
    fn validate_signed(&self, p: &Signed, now: u64) -> Result<()> {
        self.network(p.network())?;
        if let Some(code) = signed_code(&p.0)? {
            if now > code.code.expires_at {
                return Err(Error::usage("The code transaction expired"));
            }
            return Ok(());
        }
        checked(native::validate_signed(&signed(p)?, now))
    }
    fn broadcast(&self, p: &Signed, now: u64) -> Result<Status> {
        self.network(p.network())?;
        if let Some(code) = signed_code(&p.0)? {
            return self.broadcast_code(&code, now);
        }
        let s = signed(p)?;
        if s.prepared.payment_authorization.is_some() {
            // The seller's facilitator submits a payment authorization. The service releases
            // the signed entry and sends nothing.
            checked(native::validate_signed(&s, now))?;
            return Ok(Status::Submitted);
        }
        let observed = match checked(rpc::broadcast(self.rpc(), &s, now))? {
            rpc::Broadcast::Submitted => native::OperationStatus::Submitted,
            rpc::Broadcast::Rejected { .. } => {
                rpc::status_by_hash(self.rpc(), &s.prepared.config.network, &s.transaction_hash)
                    .unwrap_or(native::OperationStatus::SubmissionUnknown)
            }
            rpc::Broadcast::RetryLater | rpc::Broadcast::Unknown => {
                native::OperationStatus::SubmissionUnknown
            }
        };
        Ok(status(super::runtime::projected_status(
            &s.prepared.config.route,
            observed,
        )))
    }
    fn status(&self, p: &Signed) -> Result<Status> {
        self.network(p.network())?;
        if let Some(code) = signed_code(&p.0)? {
            return Ok(status(checked(rpc::status_by_hash(
                self.rpc(),
                &code.code.network,
                &code.code.transaction_hash,
            ))?));
        }
        let s = signed(p)?;
        if s.prepared.payment_authorization.is_some() {
            // The ledger names the transaction that settled the entry, or shows that no
            // transaction settled it by its expiry ledger. Until then the entry is open.
            return Ok(
                match checked(native::seller_settled::observe(self.rpc(), &s.prepared))? {
                    native::seller_settled::Observed::Settled(_) => Status::Confirmed,
                    // Nothing settled it by its expiry ledger, and nothing can settle it now.
                    native::seller_settled::Observed::Lapsed => Status::Failed,
                    native::seller_settled::Observed::Open => Status::Submitted,
                },
            );
        }
        let observed = checked(rpc::status_by_hash(
            self.rpc(),
            &s.prepared.config.network,
            &s.transaction_hash,
        ))?;
        Ok(status(super::runtime::projected_status(
            &s.prepared.config.route,
            observed,
        )))
    }
    fn observe(&self, p: &Signed) -> Result<Option<Receipt>> {
        self.network(p.network())?;
        if let Some(code) = signed_code(&p.0)? {
            return self.observe_code(&code);
        }
        let s = signed(p)?;
        if s.prepared.payment_authorization.is_some() {
            return checked(native::seller_settled::settlement(self.rpc(), &s.prepared))?
                .map(|settled| {
                    verify_native_receipt(&s, &settled.receipt)?;
                    Ok(Receipt(packet(
                        &s.prepared.config.network,
                        &settled.receipt,
                    )?))
                })
                .transpose();
        }
        let r = checked(rpc::receipt_by_hash(
            self.rpc(),
            &s.prepared.config.network,
            &s.transaction_hash,
        ))?;
        r.map(|r| {
            verify_native_receipt(&s, &r)?;
            Ok(Receipt(packet(&s.prepared.config.network, &r)?))
        })
        .transpose()
    }
    fn observe_authorizations(&self, packets: &[Prepared]) -> Result<Vec<ObservedAuthorization>> {
        let packets = packets
            .iter()
            .map(|p| {
                self.network(p.network())?;
                prepared(p)
            })
            .collect::<Result<Vec<_>>>()?;
        self.runtime
            .observe_authorizations(&packets)
            .into_iter()
            .map(|p| {
                let network = &p.signed.prepared.config.network;
                Ok(ObservedAuthorization {
                    status: status(p.status()),
                    signed: Signed(packet(network, &p.signed)?),
                    receipt: Receipt(packet(network, &p.receipt)?),
                })
            })
            .collect()
    }
    fn lapsed(&self, p: &Prepared) -> Result<bool> {
        self.network(p.network())?;
        let p = prepared(p)?;
        // The same proofs as the agent client's: a payment authorization lapses when no
        // transaction settled it by its expiry ledger, a policy wallet operation when its
        // authorization can no longer run and the history holds no execution of it.
        if p.payment_authorization.is_some() {
            return checked(native::seller_settled::lapsed(self.rpc(), &p));
        }
        checked(rpc::operation_lapsed(self.rpc(), &p))
    }
    fn owner_lapsed(&self, hash: &[u8; 32], expires_at: u64, since: u64) -> Result<bool> {
        self.current_height()?;
        checked(rpc::owner_transaction_lapsed(
            self.rpc(),
            hash,
            expires_at,
            since,
        ))
    }
    fn usage(&self, p: &Prepared) -> Result<Option<Usage>> {
        self.network(p.network())?;
        Ok(
            checked(native::operation_usage(&prepared(p)?))?.map(|u| Usage {
                amount_units: u.amount_units,
                gas_units: u.gas_units,
                spent_units: u.spent_units,
                unpriced: u.unpriced,
            }),
        )
    }
    fn prepare_owner(
        &self,
        i: &Installation,
        a: OwnerAction,
        fee_limit: u64,
        now: u64,
    ) -> Result<OwnerPacket> {
        let c = self.config(i)?;
        if c.route == WalletRoute::Native {
            return self.prepare_wallet_owner(&c, a, fee_limit, now);
        }
        // Renewal preserves the installed fee budget even when deployment has a larger ceiling.
        let fee_limit = if matches!(&a, OwnerAction::Extend) {
            fee_limit.min(u64::from(c.max_fee_stroops))
        } else {
            fee_limit
        };
        let d = native::admin::Deployer {
            rpc: self.rpc(),
            network: &c.network,
            now,
            max_fee_stroops: fee(fee_limit)?,
        };
        let p = match a {
            OwnerAction::Create {
                wasm,
                units,
                fee_asset_units,
            } => {
                let config = checked(native::admin::PolicyConfig::for_policy(&c))?;
                let p = checked(d.deploy_and_fund(
                    &checked(native::admin::deployer_address(&c.network))?,
                    &config,
                    &wasm,
                    native::admin::wallet_salt(&c.policy_instance),
                    &checked(native::admin::creation_funding(&c, units, fee_asset_units))?,
                ))?;
                native::owner_intent::OwnerTransaction {
                    network: p.network,
                    action: p.function,
                    transaction_xdr: p.transaction_xdr,
                    transaction_hash: p.transaction_hash,
                    expires_at: p.expires_at,
                }
            }
            OwnerAction::SetPause { paused } => {
                use allowit_core::admin::{DeploymentVersion, SetPause};
                let mut admin = native::admin::OwnerAdmin {
                    rpc: self.rpc(),
                    config: &c,
                    now,
                };
                let version = checked(admin.deployment_version())?
                    .0
                    .checked_add(1)
                    .ok_or_else(|| Error::config("Deployment version overflow"))?;
                checked(
                    checked(admin.set_pause(paused, DeploymentVersion(version)))?
                        .owner_transaction(),
                )?
            }
            OwnerAction::Recover { units, recipient } => {
                let mut admin = native::admin::OwnerAdmin {
                    rpc: self.rpc(),
                    config: &c,
                    now,
                };
                let prepared = match (units, recipient) {
                    // Everything returns, one balance per call: the asset, then the XLM that a
                    // wallet of another asset holds for its gas.
                    (None, None) => checked(admin.recover_all())?,
                    (Some(units), recipient) => {
                        checked(admin.recover_to(recipient.as_deref().unwrap_or(&c.owner), units))?
                    }
                    _ => return Err(Error::usage("Recovery recipient requires an amount")),
                };
                checked(prepared.owner_transaction())?
            }
            OwnerAction::Fund { units } => {
                checked(
                    native::admin::OwnerAdmin {
                        rpc: self.rpc(),
                        config: &c,
                        now,
                    }
                    .custody(),
                )?;
                // A transfer does not call the wallet: its lifetimes are read first, and a wallet
                // whose instance or code lapsed takes no funds (`CONTRACT_EXPIRED`).
                checked(rpc::wallet_lifetime(
                    self.rpc(),
                    &c.network,
                    &c.wallet,
                    &c.module_digest,
                ))?;
                checked(d.fund(&c, units))?
            }
            OwnerAction::Extend => {
                checked(
                    native::admin::OwnerAdmin {
                        rpc: self.rpc(),
                        config: &c,
                        now,
                    }
                    .custody(),
                )?;
                let l = checked(rpc::wallet_lifetime(
                    self.rpc(),
                    &c.network,
                    &c.wallet,
                    &c.module_digest,
                ))?;
                checked(d.extend_wallet(&c, checked(l.extend_to())?))?
            }
        };
        Ok(OwnerPacket(packet(&c.network, &p)?))
    }
    /// The owner step of a params update: one `deploy_policy` call at the next configuration
    /// revision that replaces the params and keeps the roles, the source binding, the policy
    /// state and the nonce. The simulation prices it within the lower of the caller's fee
    /// limit and the installed fee ceiling.
    fn prepare_params_update(
        &self,
        i: &Installation,
        update: &ParamsUpdate,
        fee_limit: u64,
        now: u64,
    ) -> Result<OwnerPacket> {
        use super::params_update;
        let c = self.config(i)?;
        let installed = params_update::installed(self.rpc(), &c, update)?;
        let deployment = params_update::deployment(&c, update)?;
        // The preparation refuses a simulated fee above its configured ceiling.
        let mut bounded = c.clone();
        bounded.max_fee_stroops = bounded
            .max_fee_stroops
            .min(u32::try_from(fee_limit).unwrap_or(u32::MAX));
        checked(native::validate_config(&bounded))
            .map_err(|_| Error::usage("The fee limit is below the network minimum"))?;
        let mut admin = native::admin::OwnerAdmin {
            rpc: self.rpc(),
            config: &bounded,
            now,
        };
        let mut p = checked(
            checked(admin.deploy_policy_source(
                params_update::next_version(installed.revision)?,
                deployment,
                &c.policy_source,
            ))?
            .owner_transaction(),
        )?;
        p.action = params_update::ACTION.into();
        Ok(OwnerPacket(packet(&c.network, &p)?))
    }
    fn read_owner_signed(&self, p: &OwnerPacket, signed_payload: &[u8]) -> Result<OwnerSigned> {
        self.network(p.network())?;
        let original = decode_packet(&p.0)?;
        checked(native::owner_intent::validate_signed_owner_transaction(
            &original,
            std::str::from_utf8(signed_payload)
                .map_err(|_| Error::usage("Invalid native signed owner payload"))?,
        ))?;
        Ok(OwnerSigned(packet(
            p.network(),
            &OwnerSignedData {
                original,
                signed_payload: signed_payload.into(),
            },
        )?))
    }
    fn prepare_code_within(
        &self,
        i: &Installation,
        wasm: &[u8],
        max_fee: u64,
        now: u64,
    ) -> Result<Option<Signed>> {
        let Some(code) = self.prepare_code(i, wasm, fee(max_fee)?, now)? else {
            return Ok(None);
        };
        Ok(Some(Signed(packet(&code.code.network, &code)?)))
    }
    fn prepare_code_renewal(
        &self,
        code: &[u8; 32],
        max_fee: u64,
        now: u64,
    ) -> Result<Option<Signed>> {
        let Some(code) = self.prepare_renewal(code, fee(max_fee)?, now)? else {
            return Ok(None);
        };
        Ok(Some(Signed(packet(&code.code.network, &code)?)))
    }
    fn code_needed(&self, p: &Signed) -> Result<bool> {
        self.network(p.network())?;
        let code = code_of(p)?;
        match code.code.function.as_str() {
            "renew_code" => Ok(self.renewal_due(&code.code.wasm_hash)?.is_some()),
            _ => Ok(checked(rpc::code_state(
                self.rpc(),
                &code.code.network,
                &code.code.wasm_hash,
            ))? != rpc::CodeState::Live),
        }
    }
    fn submit_owner<'a>(
        &self,
        p: &OwnerSigned,
        retain: Box<dyn FnOnce(&OwnerSigned) -> Result<()> + 'a>,
        poll: Poll,
        now: u64,
    ) -> Result<Receipt> {
        self.network(p.network())?;
        let data: OwnerSignedData = decode_packet(&p.0)?;
        if now >= data.original.expires_at {
            return self.observe_owner(p)?.ok_or_else(|| {
                Error::uncertain(
                    "Original owner result remains unknown. Retain its packet; do not replace it.",
                )
            });
        }
        retain(p)?;
        let receipt = checked(self.runtime.send_and_poll(
            &data.original.network,
            owner_payload(&data)?,
            crate::provider::runtime::Poll {
                attempts: poll.attempts,
                interval: poll.interval,
            },
        ))?;
        checked(rpc::validate_receipt(
            &receipt,
            &data.original.network,
            &data.original.transaction_hash,
        ))?;
        Ok(Receipt(packet(p.network(), &receipt)?))
    }
    fn observe_owner(&self, p: &OwnerSigned) -> Result<Option<Receipt>> {
        self.network(p.network())?;
        let data: OwnerSignedData = decode_packet(&p.0)?;
        checked(rpc::receipt_by_hash(
            self.rpc(),
            &data.original.network,
            &data.original.transaction_hash,
        ))?
        .map(|r| Ok(Receipt(packet(p.network(), &r)?)))
        .transpose()
    }
}

pub fn prepared_metadata(p: &Packet) -> Result<PreparedMetadata> {
    let value: PreparedOperation = decode_packet(p)?;
    let effect = value
        .request
        .effect_bounds
        .first()
        .ok_or_else(|| Error::config("Missing original effect bound"))?;
    let mut amount = [0u8; 16];
    amount.copy_from_slice(&effect.max_debit.0[16..]);
    let operation = native::retained_operation_from_request(&value.config, &value.request)
        .map_err(crate::provider::failure)?;
    let (recipient, units) = operation.debit();
    let token = operation.debit_token(&value.config.asset);
    let redeem = operation.kind() == native::OperationKind::Redeem;
    let kind = serde_json::to_value(operation.kind())
        .map_err(|_| Error::config("Invalid operation kind"))?
        .as_str()
        .ok_or_else(|| Error::config("Invalid operation kind"))?
        .to_owned();
    let debit = Debit {
        units,
        token: token.into(),
        recipient: recipient.into(),
        kind,
        display_amount: if redeem {
            units.to_string()
        } else {
            format!("{}.{:07}", units / 10_000_000, units % 10_000_000)
        },
        display_token: if redeem {
            format!("{token} base units")
        } else {
            value.config.asset_symbol.clone()
        },
    };
    Ok(PreparedMetadata {
        configuration: super::server_owner::configuration(
            &value.config.network,
            packet(&value.config.network, &value.config)?
                .document()
                .get()
                .as_bytes(),
        )?,
        // The request that the agent sent: a payment authorization keeps it apart from the
        // operation that carries the decision.
        request: RequestPacket(packet(
            &value.config.network,
            native::seller_settled::intent(&value),
        )?),
        operation_id: value.request.operation.nonce,
        created_at: value.created_at,
        expires_at: value.expires_at,
        transaction_hash: value.transaction_hash,
        debit_units: i128::from_be_bytes(amount),
        request_hash: value.request_hash,
        debit,
        seller_settles: value.payment_authorization.is_some(),
    })
}
pub fn signed_preparation(p: &Packet) -> Result<Prepared> {
    if signed_code(p)?.is_some() {
        return Err(Error::usage(
            "A wallet code transaction has no wallet operation to prepare",
        ));
    }
    let value: SignedOperation = decode_packet(p)?;
    Ok(Prepared(packet(
        &value.prepared.config.network,
        &value.prepared,
    )?))
}

/// The server's clock in Unix seconds.
fn unix_now() -> Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| Error::config("The server's clock is before 1970"))
}
fn snapshot_from(network: &str, live: rpc::DiscoveredState) -> Result<Snapshot> {
    let s = &live.state;
    let convert = |v: &native::PolicyParams| {
        v.0.iter()
            .map(|(k, v)| checked(v.to_core()).map(|v| (k.clone(), v)))
            .collect::<Result<BTreeMap<_, _>>>()
    };
    Ok(Snapshot {
        accounting: Accounting {
            nonce: s.nonce,
            deployment_version: s.deployment_version,
            spent_daily: s.spent_daily,
            spent_total: s.spent_total,
            spent_day: s.spent_day,
            volume_daily: s.volume_daily,
            unpriced_total: s.unpriced_total,
            unpriced_daily: s.unpriced_daily,
            calls: s.calls,
        },
        observed_height: u64::from(s.ledger),
        paused: live.paused,
        params: s
            .policy_state
            .as_ref()
            .map(|p| convert(&p.params))
            .transpose()?
            .unwrap_or_default(),
        // The wallet's daily figures count while its daily entry's window is open, whatever the
        // UTC day; the snapshot states them as today's, as the wallet feeds its own rules.
        state: s
            .policy_state
            .as_ref()
            .map(|p| convert(&p.standard_state(unix_now()?)))
            .transpose()?
            .unwrap_or_default(),
        evidence: packet(network, &live)?,
    })
}
pub fn verify_consent(s: &Snapshot, message: &str, signatures: &[Signature]) -> Result<()> {
    let live: rpc::DiscoveredState = decode_observation(&s.evidence)?;
    let signatures = signatures
        .iter()
        .map(|s| native::DetachedSignature {
            signer: s.identity.clone(),
            signature: s.bytes.clone(),
        })
        .collect::<Vec<_>>();
    checked(live.state.source.validate_authority_signatures(
        &native::signing::signed_message_digest(message),
        &signatures,
    ))
}
pub fn signer_weight(s: &Snapshot, identity: &str) -> Result<u32> {
    let live: rpc::DiscoveredState = decode_observation(&s.evidence)?;
    // A contract wallet has no account signers: its configuration on chain names its roles.
    if live.state.policy_state.is_some() {
        return checked(live.state.policy_role_weight(identity));
    }
    checked(live.state.source.signer_weight(identity))
}
pub fn authority_document(s: &Snapshot) -> Result<serde_json::Value> {
    let live: rpc::DiscoveredState = decode_observation(&s.evidence)?;
    serde_json::to_value(live.state.source)
        .map_err(|_| Error::config("Cannot describe authority observation"))
}

/// Parse retained signed identity without granting new submission authority. Chain-only recovery
/// can retain an included envelope whose signature roles rotated; broadcast validates signatures again.
/// A retained signed packet: for a policy wallet, the prepared transaction with both
/// cosignatures and, once sealed, its final resources, fee and source signature; the hash is
/// that of the transaction it carries.
fn retained_signed_shape(s: &SignedOperation) -> Result<()> {
    checked(native::validate_retained_prepared(&s.prepared))?;
    checked(native::validate_retained_signed(s))
}
pub fn validate_signed(p: &Packet) -> Result<()> {
    if signed_code(p)?.is_some() {
        return Ok(());
    }
    let signed: SignedOperation = decode_packet(p)?;
    checked(native::validate_retained_signed(&signed))
}
pub fn verify_receipt(r: &Packet, p: &Packet) -> Result<()> {
    let receipt: rpc::VerifiedReceipt = decode_packet(r)?;
    if r.network() != p.network() {
        return Err(Error::config("Receipt network differs from operation"));
    }
    if let Some(code) = signed_code(p)? {
        checked(rpc::validate_own_receipt(
            &receipt,
            &code.code.network,
            &code.code.transaction_hash,
        ))?;
        if receipt.envelope_xdr != code.signed_xdr {
            return Err(Error::config(
                "The receipt's envelope differs from the code transaction",
            ));
        }
        // The ledger charges a transaction at most the fee that it declares.
        if receipt_info(r)?.fee.native_units > u128::from(declared_fee(&code.signed_xdr)?) {
            return Err(Error::config(
                "The receipt reports a fee above the fee of its transaction",
            ));
        }
        return Ok(());
    }
    let signed: SignedOperation = decode_packet(p)?;
    verify_native_receipt(&signed, &receipt)
}
fn verify_native_receipt(signed: &SignedOperation, receipt: &rpc::VerifiedReceipt) -> Result<()> {
    // Another party's transaction settles a payment authorization of either custody form.
    if signed.prepared.payment_authorization.is_some() {
        return checked(native::seller_settled::validate_settled(signed, receipt));
    }
    if receipt.settles.is_some() {
        return Err(Error::config(
            "The receipt settles a payment authorization, not this operation",
        ));
    }
    if signed.prepared.config.route == WalletRoute::PolicyWallet {
        checked(rpc::validate_settled_policy_packet(signed, receipt))
    } else {
        checked(native::validate_retained_signed(signed))?;
        if signed.transaction_xdr != receipt.envelope_xdr {
            return Err(Error::config(
                "The settlement envelope differs from the original packet",
            ));
        }
        checked(rpc::validate_own_receipt(
            receipt,
            &signed.prepared.config.network,
            &signed.transaction_hash,
        ))
    }
}

pub fn request_proof_protocol() -> crate::host::request_proof::Protocol {
    crate::host::request_proof::Protocol {
        domain: native::signing::REQUEST_PROOF_DOMAIN,
        scheme: native::signing::REQUEST_PROOF_SCHEME,
        signature_bytes: native::signing::REQUEST_PROOF_SIGNATURE_BYTES,
        validate_account: |account| {
            checked(native::signing::canonical_account_key(account)).map(|_| ())
        },
        verify: |account, digest, signature| {
            checked(native::signing::verify_digest(account, digest, signature))
        },
    }
}

pub fn signer_identity(key: &[u8; 32]) -> Result<String> {
    Ok(native::account_for_public_key(key))
}

pub fn request_id(p: &Packet) -> Result<[u8; 32]> {
    let request: native::workflow::ExecutionRequest = decode_packet(p)?;
    Ok(request.operation.nonce)
}

/// The owning adapter for every retained native packet.
pub struct Packets;
pub static PACKETS: Packets = Packets;
fn packet(network: &str, value: &impl Serialize) -> Result<Packet> {
    Packet::new(crate::host::routing::normalize(network)?, value, &PACKETS)
}
impl PacketProvider for Packets {
    fn request_id(&self, p: &Packet) -> Result<[u8; 32]> {
        request_id(p)
    }
    fn owner_info(&self, p: &Packet) -> Result<OwnerInfo> {
        owner_info(p)
    }
    fn prepared_metadata(&self, p: &Packet) -> Result<PreparedMetadata> {
        prepared_metadata(p)
    }
    fn info(&self, p: &Packet, k: Kind) -> Result<PacketInfo> {
        info(p, k)
    }
    fn validate_signed(&self, p: &Packet) -> Result<()> {
        validate_signed(p)
    }
    fn signed_preparation(&self, p: &Packet) -> Result<Prepared> {
        signed_preparation(p)
    }
    fn verify_consent(&self, s: &Snapshot, message: &str, signatures: &[Signature]) -> Result<()> {
        verify_consent(s, message, signatures)
    }
    fn signer_weight(&self, s: &Snapshot, identity: &str) -> Result<u32> {
        signer_weight(s, identity)
    }
    fn authority_document(&self, s: &Snapshot) -> Result<serde_json::Value> {
        authority_document(s)
    }
    fn same_snapshot(&self, a: &Snapshot, b: &Snapshot) -> Result<bool> {
        same_snapshot(a, b)
    }
    fn verify_receipt(&self, r: &Packet, p: &Packet) -> Result<()> {
        verify_receipt(r, p)
    }
    fn receipt_info(&self, p: &Packet) -> Result<ReceiptInfo> {
        receipt_info(p)
    }
}

#[cfg(test)]
fn installation(config: &crate::host::runtime::owner::Configuration) -> Installation {
    Installation {
        description: description(
            &serde_json::from_slice(config.bytes()).unwrap(),
            "provider-test",
        )
        .unwrap(),
        config: config.document().to_owned(),
        export: None,
        authority: None,
    }
}
#[cfg(test)]
fn retained(value: &serde_json::Value) -> Prepared {
    Prepared(
        restore(
            Kind::Prepared,
            RawValue::from_string(value.to_string()).unwrap(),
        )
        .unwrap(),
    )
}
#[cfg(test)]
mod role_weight_tests {
    use super::*;

    /// The provider weighs a contract wallet's signers from the roles that its configuration
    /// holds on chain, paused or not: discovery gives such a wallet no account. A keypair
    /// wallet's account still weighs its own signers.
    #[test]
    fn a_contract_wallet_weighs_the_roles_of_its_configuration() {
        let (c, _, keypair, _) = crate::test_support::agent_fixture("policy", "request", 86_401);
        let mut contract = keypair.clone();
        contract.contract_version = Some(native::contract::CONTRACT_VERSION);
        contract.policy_state = Some(native::PolicyStateSnapshot {
            custom: Default::default(),
            params: Default::default(),
            rules: vec![],
            source_hash: contract.source_hash,
            figures: Default::default(),
        });
        // As discovery reports a contract wallet: no source account.
        contract.source = native::AccountState {
            address: String::new(),
            sequence: 0,
            master_weight: 0,
            low_threshold: 0,
            medium_threshold: 0,
            high_threshold: 0,
            signers: vec![],
        };
        let stranger = native::account_for_seed(&[9; 32]);
        for paused in [false, true] {
            let snapshot = snapshot_from(
                &c.network,
                rpc::DiscoveredState {
                    state: contract.clone(),
                    paused,
                },
            )
            .unwrap();
            let weight = |key: &str| signer_weight(&snapshot, key).unwrap();
            assert_eq!(
                (
                    weight(&contract.owner),
                    weight(&contract.agent),
                    weight(&contract.server),
                    weight(&stranger)
                ),
                (3, 1, 1, 0),
                "paused={paused}"
            );
        }
        // An owner that is another contract acts alone, as an owner account does.
        let mut owned = contract.clone();
        owned.owner = stellar_strkey::Contract([5; 32]).to_string();
        let snapshot = snapshot_from(
            &c.network,
            rpc::DiscoveredState {
                state: owned.clone(),
                paused: false,
            },
        )
        .unwrap();
        assert_eq!(
            (
                signer_weight(&snapshot, &owned.owner).unwrap(),
                signer_weight(&snapshot, &owned.agent).unwrap()
            ),
            (3, 1)
        );
        let snapshot = snapshot_from(
            &c.network,
            rpc::DiscoveredState {
                state: keypair.clone(),
                paused: false,
            },
        )
        .unwrap();
        assert_eq!(
            signer_weight(&snapshot, &keypair.agent).unwrap(),
            keypair.source.signer_weight(&keypair.agent).unwrap()
        );
    }
}

#[cfg(test)]
mod receipt_fee_tests {
    use super::*;
    use stellar_xdr::{
        HostFunction, OperationBody, ScVal, TransactionEnvelope, TransactionResult,
        TransactionResultExt, TransactionResultResult,
    };

    /// The receipt facts of `signed` once settled with `fee` paid. `expense` replaces the
    /// expense of a policy wallet invocation.
    fn settled(
        signed: &SignedOperation,
        expense: Option<&native::ExpenseBounds>,
        success: bool,
        fee: i64,
    ) -> ReceiptInfo {
        let TransactionEnvelope::Tx(mut envelope) = native::read(&signed.transaction_xdr).unwrap()
        else {
            panic!()
        };
        if let Some(expense) = expense {
            let mut operations = envelope.tx.operations.to_vec();
            let OperationBody::InvokeHostFunction(op) = &mut operations[0].body else {
                panic!()
            };
            let HostFunction::InvokeContract(call) = &mut op.host_function else {
                panic!()
            };
            let mut args = call.args.to_vec();
            // The positional request holds its expense as field 4 and the repaid stroops as
            // field 5: for XLM, the counted gas.
            let ScVal::Vec(Some(request)) = &args[0] else {
                panic!()
            };
            let mut fields = request.to_vec();
            fields[4] = native::contract::expense(Some(expense)).unwrap();
            fields[5] = native::i128_value(expense.gas_units);
            args[0] = ScVal::Vec(Some(fields.try_into().unwrap()));
            call.args = args.try_into().unwrap();
            envelope.tx.operations = operations.try_into().unwrap();
        }
        let result = TransactionResult {
            fee_charged: fee,
            result: if success {
                TransactionResultResult::TxSuccess(Default::default())
            } else {
                TransactionResultResult::TxFailed(Default::default())
            },
            ext: TransactionResultExt::V0,
        };
        let network = &signed.prepared.config.network;
        let receipt = rpc::VerifiedReceipt {
            transaction_hash: native::transaction_hash(network, &envelope.tx).unwrap(),
            status: if success {
                native::OperationStatus::Confirmed
            } else {
                native::OperationStatus::Failed
            },
            ledger: 9,
            envelope_xdr: native::xdr(&TransactionEnvelope::Tx(envelope)).unwrap(),
            result_xdr: native::xdr(&result).unwrap(),
            settles: None,
        };
        receipt_info(&packet(network, &receipt).unwrap()).unwrap()
    }

    /// Only an operation that repays its gas takes a gas carry.
    #[test]
    fn only_an_operation_that_repays_its_gas_takes_a_gas_carry() {
        assert_eq!(gas_carry(true, 5).unwrap(), 5);
        assert_eq!(gas_carry(true, 0).unwrap(), 0);
        assert_eq!(gas_carry(false, 0).unwrap(), 0);
        assert!(
            gas_carry(false, 1)
                .unwrap_err()
                .message
                .contains("takes a gas carry")
        );
    }

    /// A policy wallet receipt reports the fee paid and, beside it, the gas units that the
    /// wallet counted and the stroops that it repaid: without a carry, the signed expense, never
    /// less than the fee that its bound admits. A failed transaction, an unpriced request and a
    /// keypair account report no counted units, and a failed transaction and a keypair account
    /// no repayment.
    #[test]
    fn a_receipt_reports_the_fee_paid_and_the_gas_that_its_wallet_counted() {
        let wallet = crate::test_support::policy_signed();
        let expense = native::ExpenseBounds::xlm(2_000_000, 0, 5_000_000, 9, 86_401)
            .unwrap()
            .with_fee_bound(2_670_684)
            .unwrap();
        let info = settled(&wallet, Some(&expense), true, 2_202_952);
        assert_eq!(
            (
                info.fee.native_units,
                info.fee.charged_units,
                info.fee.repaid_native_units
            ),
            (2_202_952, 2_670_684, 2_670_684)
        );
        assert!(info.fee.charged_units >= info.fee.native_units as i128);
        // With a carry the wallet repays and counts less than the bound.
        let carried = expense.with_gas_carry(1_000_000).unwrap();
        let info = settled(&wallet, Some(&carried), true, 2_202_952);
        assert_eq!(
            (info.fee.charged_units, info.fee.repaid_native_units),
            (1_670_684, 1_670_684)
        );
        let failed = settled(&wallet, Some(&expense), false, 2_202_952);
        assert_eq!(
            (
                failed.fee.native_units,
                failed.fee.charged_units,
                failed.fee.repaid_native_units
            ),
            (2_202_952, 0, 0)
        );
        assert_eq!(settled(&wallet, None, true, 100).fee.charged_units, 0);
        let account = crate::test_support::native_signed();
        let info = settled(&account, None, true, 100);
        assert_eq!(
            (
                info.fee.native_units,
                info.fee.charged_units,
                info.fee.repaid_native_units
            ),
            (100, 0, 0)
        );
    }
}

#[cfg(test)]
mod capability_tests {
    use super::*;
    use crate::host::vendors::RuntimeProvider;
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
    };

    struct RecordedRpc(Mutex<VecDeque<serde_json::Value>>);
    impl rpc::Rpc for RecordedRpc {
        fn call(
            &self,
            method: &str,
            params: serde_json::Value,
        ) -> native::Result<serde_json::Value> {
            let expected = self
                .0
                .lock()
                .unwrap()
                .pop_front()
                .expect("Unexpected preflight RPC");
            assert_eq!(expected["method"], method);
            assert_eq!(expected["params"], params);
            Ok(expected["result"].clone())
        }
    }
    /// The server reads a lapse as the agent client does (`rpc::operation_lapsed`). Once a ledger
    /// closed at or after the signed time bound, the wallet runs the operation in no envelope, so
    /// the wallet's events read then hold every execution of it, in any envelope: none found, the
    /// operation lapsed. Once the history no longer holds the preparation's ledger, nothing proves
    /// a lapse: the operation stays open. A read that fails proves nothing.
    #[test]
    fn an_operation_lapses_once_its_time_bound_passed_and_no_execution_is_in_the_history() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/provider/stellar-policy-wallet-revalidation-rpc.json"
        ))
        .unwrap();
        let p: PreparedOperation = serde_json::from_value(fixture["prepared"].clone()).unwrap();
        struct Ledger {
            status: &'static str,
            closed: u64,
            oldest: u64,
            /// An execution of the operation, in an envelope that another account sent.
            executed: bool,
            events_fail: bool,
            wallet: String,
            from: u32,
            calls: std::sync::Mutex<Vec<String>>,
        }
        impl rpc::Rpc for Ledger {
            fn call(
                &self,
                method: &str,
                params: serde_json::Value,
            ) -> native::Result<serde_json::Value> {
                self.calls.lock().unwrap().push(method.into());
                match method {
                    "getTransaction" => Ok(serde_json::json!({
                        "status": self.status,
                        "oldestLedger": self.oldest,
                        "latestLedger": 900,
                        "latestLedgerCloseTime": self.closed.to_string(),
                    })),
                    "getEvents" if self.events_fail => Err("The RPC is unreachable".into()),
                    "getEvents" => {
                        assert_eq!(params["startLedger"], self.from);
                        let filter = &params["filters"][0];
                        assert_eq!(filter["contractIds"], serde_json::json!([self.wallet]));
                        assert_eq!(filter["topics"][0].as_array().unwrap().len(), 2);
                        let events = if self.executed {
                            serde_json::json!([{"txHash": native::hex(&[0xee; 32]), "ledger": 130}])
                        } else {
                            serde_json::json!([])
                        };
                        Ok(serde_json::json!({"events": events, "latestLedger": 900}))
                    }
                    other => panic!("unexpected {other}"),
                }
            }
        }
        let read = |status, closed, oldest, executed, events_fail| {
            let ledger = Arc::new(Ledger {
                status,
                closed,
                oldest,
                executed,
                events_fail,
                wallet: p.config.wallet.clone(),
                from: p.state.ledger,
                calls: std::sync::Mutex::new(Vec::new()),
            });
            let provider = Provider::from_rpc("stellar:testnet", ledger.clone());
            let lapsed = provider.lapsed(&provider.packet(&p).unwrap());
            let calls = ledger.calls.lock().unwrap().clone();
            (lapsed, calls)
        };
        let from = u64::from(p.state.ledger);
        // An operation that the agent never submitted: retired once the bound passed, also long
        // after it.
        let (lapsed, calls) = read("NOT_FOUND", p.expires_at, from, false, false);
        assert!(lapsed.unwrap());
        assert_eq!(calls, ["getTransaction", "getEvents"]);
        assert!(
            read("NOT_FOUND", p.expires_at + 86_400, from, false, false)
                .0
                .unwrap()
        );
        // An execution in another envelope, which no receipt of the operation adopts: no lapse.
        assert!(
            !read("NOT_FOUND", p.expires_at, from, true, false)
                .0
                .unwrap()
        );
        // Before the bound the wallet can still run it: the events are not read.
        let (lapsed, calls) = read("NOT_FOUND", p.expires_at - 1, from, false, false);
        assert!(!lapsed.unwrap());
        assert_eq!(calls, ["getTransaction"]);
        // The prepared transaction applied.
        assert!(!read("SUCCESS", p.expires_at, from, false, false).0.unwrap());
        // A read of the events that fails proves nothing.
        assert!(
            read("NOT_FOUND", p.expires_at, from, false, true)
                .0
                .is_err()
        );
        // The history no longer holds the preparation's ledger: an execution could be gone from
        // it, so the time bound alone proves nothing, whether the operation executed or not.
        for executed in [true, false] {
            let (lapsed, calls) = read("NOT_FOUND", p.expires_at, from + 1, executed, false);
            assert!(!lapsed.unwrap());
            assert_eq!(calls, ["getTransaction"]);
        }
        // A reply without its history proves nothing.
        assert!(!read("NOT_FOUND", p.expires_at, 0, false, false).0.unwrap());
    }
    /// The server cosigns no operation of a wallet whose instance lapsed after the operation's
    /// last simulation: the lapse is `contract_expired` before the signer is asked.
    #[test]
    fn the_server_signs_nothing_for_a_wallet_that_lapsed_after_its_simulation() {
        use stellar_xdr::{
            ContractDataDurability, ContractDataEntry, ContractExecutable, ExtensionPoint, Hash,
            LedgerEntryData, Limits, ScContractInstance, ScVal, WriteXdr,
        };
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/provider/stellar-policy-wallet-revalidation-rpc.json"
        ))
        .unwrap();
        let p: PreparedOperation = serde_json::from_value(fixture["prepared"].clone()).unwrap();
        /// The recorded network of the fixture; once `lapsed`, the wallet's instance lapsed, or,
        /// with `running`, it runs that other code, which is live.
        struct Recorded {
            fixture: serde_json::Value,
            config: WalletConfig,
            lapsed: std::sync::atomic::AtomicBool,
            running: std::sync::Mutex<Option<[u8; 32]>>,
        }
        impl rpc::Rpc for Recorded {
            fn call(
                &self,
                method: &str,
                params: serde_json::Value,
            ) -> native::Result<serde_json::Value> {
                let recorded = |method: &str| {
                    self.fixture["calls"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .find(|call| call["method"] == method)
                        .map(|call| call["result"].clone())
                        .unwrap()
                };
                if !self.lapsed.load(std::sync::atomic::Ordering::SeqCst) {
                    return self.fixture["calls"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .find(|call| call["method"] == method && call["params"] == params)
                        .map(|call| call["result"].clone())
                        .ok_or_else(|| format!("Unexpected RPC {method}"));
                }
                Ok(match method {
                    "getNetwork" | "getLatestLedger" => recorded(method),
                    "getLedgerEntries" => {
                        let instance = LedgerEntryData::ContractData(ContractDataEntry {
                            ext: ExtensionPoint::V0,
                            contract: native::address(&self.config.wallet)?,
                            key: ScVal::LedgerKeyContractInstance,
                            durability: ContractDataDurability::Persistent,
                            val: ScVal::ContractInstance(ScContractInstance {
                                executable: ContractExecutable::Wasm(Hash(
                                    self.running
                                        .lock()
                                        .unwrap()
                                        .unwrap_or(self.config.module_digest),
                                )),
                                storage: None,
                            }),
                        });
                        let live = if self.running.lock().unwrap().is_some() {
                            serde_json::json!(4_000_000)
                        } else {
                            serde_json::json!(0)
                        };
                        serde_json::json!({
                            "latestLedger": recorded("getLatestLedger")["sequence"],
                            "entries": [{
                                "xdr": instance.to_xdr_base64(Limits::none()).unwrap(),
                                "liveUntilLedgerSeq": live,
                            }],
                        })
                    }
                    other => panic!("unexpected {other} after the lapse"),
                })
            }
        }
        struct Counting(std::sync::atomic::AtomicUsize, String);
        impl Signer for Counting {
            fn identity(&self) -> &str {
                &self.1
            }
            fn sign_hash(&self, _: &[u8; 32]) -> Result<Vec<u8>> {
                self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(vec![0; 64])
            }
        }
        let configuration = super::super::server_owner::configuration(
            "stellar:testnet",
            &serde_json::to_vec(&p.config).unwrap(),
        )
        .unwrap();
        let installation = installation(&configuration);
        let network = Arc::new(Recorded {
            fixture: fixture.clone(),
            config: p.config.clone(),
            lapsed: std::sync::atomic::AtomicBool::new(false),
            running: std::sync::Mutex::new(None),
        });
        let provider = Provider::from_rpc("stellar:testnet", network.clone());
        let simulated = provider
            .revalidate(&installation, &retained(&fixture["prepared"]), 86_402)
            .unwrap();
        network
            .lapsed
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let signer = Counting(
            std::sync::atomic::AtomicUsize::new(0),
            p.config.server.clone(),
        );
        // The liveness check comes first, before any step that signs.
        let refused = provider
            .authorize_preparation(&installation, &simulated, &signer, None, 86_402)
            .unwrap_err();
        assert_eq!(refused.message, rpc::CONTRACT_EXPIRED);
        let refused = provider
            .finalize(
                &installation,
                &simulated,
                &signer,
                None,
                86_402,
                Box::new(|_| Ok(())),
            )
            .unwrap_err();
        assert_eq!(refused.message, rpc::CONTRACT_EXPIRED);
        // The owner installed other code after the preparation: the server signs nothing for it,
        // whether the installation's code is live or not.
        *network.running.lock().unwrap() = Some([0x42; 32]);
        let refused = provider
            .authorize_preparation(&installation, &simulated, &signer, None, 86_402)
            .unwrap_err();
        assert!(
            refused.message.contains("other code"),
            "{}",
            refused.message
        );
        let refused = provider
            .finalize(
                &installation,
                &simulated,
                &signer,
                None,
                86_402,
                Box::new(|_| Ok(())),
            )
            .unwrap_err();
        assert!(
            refused.message.contains("other code"),
            "{}",
            refused.message
        );
        assert_eq!(signer.0.load(std::sync::atomic::Ordering::SeqCst), 0);
    }
    #[test]
    fn genuine_preflight_survives_carrier_but_not_serialization_or_document_changes() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/provider/stellar-policy-wallet-revalidation-rpc.json"
        ))
        .unwrap();
        let original: PreparedOperation =
            serde_json::from_value(fixture["prepared"].clone()).unwrap();
        let provider = Provider::from_rpc(
            "stellar:testnet",
            Arc::new(RecordedRpc(Mutex::new(
                fixture["calls"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .cloned()
                    .collect(),
            ))),
        );
        let config = super::super::server_owner::configuration(
            "stellar:testnet",
            &serde_json::to_vec(&original.config).unwrap(),
        )
        .unwrap();
        let installation = installation(&config);
        let runtime = provider;
        let restored = retained(&fixture["prepared"]);
        assert!(prepared(&restored).unwrap().native_preflight.is_none());
        let fresh = runtime.revalidate(&installation, &restored, 86402).unwrap();
        let admitted = prepared(&fresh).unwrap();
        assert!(admitted.native_preflight.is_some());
        native::sign(&admitted, &[2; 32], 86402).unwrap();
        let serialized = serde_json::to_vec(&fresh).unwrap();
        let decoded = Prepared(
            restore(
                Kind::Prepared,
                RawValue::from_string(String::from_utf8(serialized).unwrap()).unwrap(),
            )
            .unwrap(),
        );
        assert_eq!(fresh.bytes(), decoded.bytes());
        assert!(prepared(&decoded).unwrap().native_preflight.is_none());
        assert!(native::sign(&prepared(&decoded).unwrap(), &[2; 32], 86402).is_err());
        let changed_document =
            RawValue::from_string(fresh.0.document().get().replacen('{', "{ ", 1)).unwrap();
        let changed = Prepared(
            Packet::from_raw(fresh.network(), changed_document, &PACKETS)
                .with_capability(PreparationCapability(admitted.clone())),
        );
        assert_ne!(changed.bytes(), fresh.bytes());
        assert!(prepared(&changed).is_err());
        let changed = Prepared(
            Packet::from_raw("stellar:mainnet", fresh.0.document().to_owned(), &PACKETS)
                .with_capability(PreparationCapability(admitted)),
        );
        assert!(prepared(&changed).is_err());
    }
}

#[cfg(test)]
mod diagnostic_regressions {
    use super::*;
    use crate::host::vendors::RuntimeProvider;
    use std::sync::Arc;
    struct Refused;
    impl rpc::Rpc for Refused {
        fn call(&self, _: &str, _: serde_json::Value) -> native::Result<serde_json::Value> {
            Ok(serde_json::json!({"error":"HostError: Error(Contract, #18)"}))
        }
    }
    #[test]
    fn diagnosed_operation_returns_owned_fault_without_lending_it_to_later_errors() {
        struct RefusedSimulation(serde_json::Value);
        impl rpc::Rpc for RefusedSimulation {
            fn call(
                &self,
                method: &str,
                params: serde_json::Value,
            ) -> native::Result<serde_json::Value> {
                if method == "simulateTransaction" {
                    return Refused.call(method, params);
                }
                self.0["calls"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|call| call["method"] == method && call["params"] == params)
                    .map(|call| call["result"].clone())
                    .ok_or_else(|| format!("Unexpected RPC {method}"))
            }
        }
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/provider/stellar-policy-wallet-revalidation-rpc.json"
        ))
        .unwrap();
        let original: PreparedOperation =
            serde_json::from_value(fixture["prepared"].clone()).unwrap();
        let configuration = super::super::server_owner::configuration(
            "stellar:testnet",
            &serde_json::to_vec(&original.config).unwrap(),
        )
        .unwrap();
        let installation = installation(&configuration);
        let retained = retained(&fixture["prepared"]);
        let runtime = Provider::from_rpc("stellar:testnet", Arc::new(RefusedSimulation(fixture)));
        let session = runtime.diagnostic_session(&installation).unwrap().unwrap();
        let error = session
            .provider
            .revalidate(&installation, &retained, 86402)
            .unwrap_err();
        let first = (session.classify)(&error);
        assert_eq!(first.code, "wallet_rejected");
        assert_eq!(first.details.as_ref().unwrap()["contractError"], 18);
        assert!(first.details.as_ref().unwrap()["contract"].is_null());
        let later = runtime
            .read_request(&installation, b"not-json")
            .unwrap_err();
        assert!(runtime.problem(&later).details.is_none());
        assert_eq!(first.details.as_ref().unwrap()["contractError"], 18);
    }
    /// A host `error` event of the simulation RPC: `contract` raised or relayed error 18.
    fn error_event(contract: &str) -> serde_json::Value {
        use stellar_xdr as x;
        let id = stellar_strkey::Contract::from_string(contract).unwrap().0;
        let event = x::DiagnosticEvent {
            in_successful_contract_call: false,
            event: x::ContractEvent {
                ext: x::ExtensionPoint::V0,
                contract_id: Some(x::ContractId(x::Hash(id))),
                type_: x::ContractEventType::Diagnostic,
                body: x::ContractEventBody::V0(x::ContractEventV0 {
                    topics: vec![
                        x::ScVal::Symbol(x::ScSymbol(b"error".to_vec().try_into().unwrap())),
                        x::ScVal::Error(x::ScError::Contract(18)),
                    ]
                    .try_into()
                    .unwrap(),
                    data: x::ScVal::Void,
                }),
            },
        };
        native::xdr(&event).unwrap().into()
    }
    /// The diagnostic session reports a refused simulation as a policy denial only when the
    /// simulated transaction invokes the installed wallet and the host events of the reply name
    /// that wallet as the one contract that raised `PolicyDenied`.
    #[test]
    fn a_diagnosed_simulation_is_a_policy_denial_only_with_wallet_provenance() {
        struct Reply {
            fixture: serde_json::Value,
            events: serde_json::Value,
        }
        impl rpc::Rpc for Reply {
            fn call(
                &self,
                method: &str,
                params: serde_json::Value,
            ) -> native::Result<serde_json::Value> {
                if method == "simulateTransaction" {
                    return Ok(serde_json::json!({"error": TERMINAL, "events": self.events}));
                }
                self.fixture["calls"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|call| call["method"] == method && call["params"] == params)
                    .map(|call| call["result"].clone())
                    .ok_or_else(|| format!("Unexpected RPC {method}"))
            }
        }
        const TERMINAL: &str = "HostError: Error(Contract, #18)";
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/provider/stellar-policy-wallet-revalidation-rpc.json"
        ))
        .unwrap();
        let original: PreparedOperation =
            serde_json::from_value(fixture["prepared"].clone()).unwrap();
        let wallet = original.config.wallet.clone();
        let foreign = stellar_strkey::Contract([8; 32]).to_string();
        let configuration = super::super::server_owner::configuration(
            "stellar:testnet",
            &serde_json::to_vec(&original.config).unwrap(),
        )
        .unwrap();
        let installation = installation(&configuration);
        let retained = retained(&fixture["prepared"]);
        // Through the session: the revalidation of the fixture simulates a call of its wallet.
        let diagnose = |events: serde_json::Value| {
            let rpc = Reply {
                fixture: fixture.clone(),
                events,
            };
            let runtime = Provider::from_rpc("stellar:testnet", Arc::new(rpc));
            let session = runtime.diagnostic_session(&installation).unwrap().unwrap();
            let error = session
                .provider
                .revalidate(&installation, &retained, 86402)
                .unwrap_err();
            (session.classify)(&error)
        };
        let denied = diagnose(serde_json::json!([error_event(&wallet)]));
        assert_eq!(denied.code, "policy_denied");
        assert_eq!(denied.status, 409);
        assert_eq!(
            denied.details.unwrap(),
            serde_json::json!({"rule":null,"error":"PolicyDenied","contractError":18})
        );
        for events in [
            // Another contract raised the code and the wallet relayed it.
            serde_json::json!([error_event(&foreign), error_event(&wallet)]),
            serde_json::json!([error_event(&foreign)]),
            // No events, a value that is no list, and an entry that is no string.
            serde_json::json!([]),
            serde_json::Value::Null,
            serde_json::json!([error_event(&wallet), 18]),
        ] {
            let rejected = diagnose(events.clone());
            assert_eq!(rejected.code, "wallet_rejected", "{events}");
            let details = rejected.details.unwrap();
            assert_eq!(details["contractError"], 18);
            assert_eq!(
                details["contract"].is_null(),
                events != serde_json::json!([error_event(&foreign)])
            );
        }
        // The transaction must invoke the wallet too: the same events prove nothing for a
        // simulation of another contract or of no known contract.
        let reply = serde_json::json!({"error": TERMINAL, "events": [error_event(&wallet)]});
        let code = |invoked| simulation_problem(&wallet, invoked, &reply).unwrap().1.code;
        assert_eq!(code(Some(wallet.as_str())), "policy_denied");
        assert_eq!(code(Some(foreign.as_str())), "wallet_rejected");
        assert_eq!(code(None), "wallet_rejected");
        // A reply without a terminal contract error has no fault.
        for reply in [
            serde_json::json!({"results": []}),
            serde_json::json!({"error": "HostError: Error(Budget, ExceededLimit)", "events": [error_event(&wallet)]}),
        ] {
            assert!(simulation_problem(&wallet, Some(&wallet), &reply).is_none());
        }
    }
    #[test]
    fn an_unconsumed_simulation_fault_does_not_classify_a_later_local_error() {
        let provider = Provider::from_rpc("stellar:testnet", Arc::new(Refused));
        let _ = provider
            .rpc()
            .call("simulateTransaction", serde_json::json!({}));
        let local =
            decode::<WalletConfig>(&RawValue::from_string("{}".into()).unwrap()).unwrap_err();
        let runtime = provider;
        let problem = runtime.problem(&local);
        assert!(
            problem.details.is_none(),
            "local decode inherited prior RPC evidence"
        );
        assert!(problem.message.contains("Invalid retained native packet"));
    }
}

fn packet_network(packet: &Packet, network: &str) -> Result<()> {
    if crate::host::routing::normalize(network)? != packet.network() {
        return Err(Error::config("Retained packet and network differ"));
    }
    Ok(())
}

#[cfg(test)]
mod retained_projection_tests {
    use super::*;
    fn owner() -> native::owner_intent::OwnerTransaction {
        let state = native::AccountState {
            address: native::account_for_seed(&[11; 32]),
            sequence: 7,
            master_weight: 1,
            low_threshold: 0,
            medium_threshold: 0,
            high_threshold: 0,
            signers: vec![],
        };
        let setup = native::owner::prepare_native_setup(
            &state,
            &native::owner::SetupTerms {
                wallet: &native::account_for_seed(&[14; 32]),
                agent: &native::account_for_seed(&[12; 32]),
                engine: &native::account_for_seed(&[13; 32]),
                request_id: "setup-history-001",
                network: "stellar:testnet",
                fee_per_operation: 100,
                starting_balance: None,
                trustline: None,
            },
            1,
        )
        .unwrap();
        native::owner_intent::OwnerTransaction {
            network: setup.network,
            action: "native_setup".into(),
            transaction_xdr: setup.transaction_xdr,
            transaction_hash: native::unhex(&setup.transaction_hash).unwrap(),
            expires_at: setup.expires_at,
        }
    }
    fn raw(value: &impl Serialize, network: &str) -> Packet {
        Packet::new(network, value, &PACKETS).unwrap()
    }
    #[test]
    fn retained_owner_projections_reject_corrupted_hash_expiry_action_and_network() {
        let original = owner();
        // Expired history remains readable. No current signing authority is inferred.
        assert_eq!(
            owner_info(&raw(&original, &original.network))
                .unwrap()
                .expires_at,
            301
        );
        for field in ["hash", "expiry", "action", "xdr", "network"] {
            let mut changed = original.clone();
            match field {
                "hash" => changed.transaction_hash[0] ^= 1,
                "expiry" => changed.expires_at += 1,
                "action" => changed.action = "fund".into(),
                "xdr" => changed.transaction_xdr = "invalid".into(),
                "network" => changed.network = "stellar:pubnet".into(),
                _ => unreachable!(),
            }
            let packet = raw(&changed, &changed.network);
            assert!(owner_info(&packet).is_err(), "{field}");
            assert!(
                restore(Kind::Owner, packet.document().to_owned()).is_err(),
                "{field}"
            );
        }
        assert!(owner_info(&raw(&original, "stellar:pubnet")).is_err());
    }
    #[test]
    fn execution_projections_validate_raw_packet_identity_before_exposing_metadata() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/provider/stellar-policy-wallet-revalidation-rpc.json"
        ))
        .unwrap();
        let prepared: PreparedOperation =
            serde_json::from_value(fixture["prepared"].clone()).unwrap();
        let signed: SignedOperation = serde_json::from_value(fixture["signed"].clone()).unwrap();
        assert!(info(&raw(&prepared, &prepared.config.network), Kind::Prepared).is_ok());
        assert!(info(&raw(&signed, &prepared.config.network), Kind::Signed).is_ok());
        let mut changed = prepared.clone();
        changed.transaction_hash[0] ^= 1;
        assert!(info(&raw(&changed, &prepared.config.network), Kind::Prepared).is_err());
        assert!(prepared_metadata(&raw(&changed, &prepared.config.network)).is_err());
        let mut changed = signed.clone();
        changed.transaction_hash[0] ^= 1;
        assert!(info(&raw(&changed, &prepared.config.network), Kind::Signed).is_err());
        assert!(signed_preparation(&raw(&changed, &prepared.config.network)).is_err());
        assert!(info(&raw(&prepared, "stellar:pubnet"), Kind::Prepared).is_err());
        assert!(info(&raw(&signed, "stellar:pubnet"), Kind::Signed).is_err());
        assert!(request_id(&raw(&prepared.request, "stellar:pubnet")).is_err());
        assert_eq!(
            request_id(&raw(&prepared.request, &prepared.config.network)).unwrap(),
            prepared.request.operation.nonce
        );
    }
}

#[cfg(test)]
mod owner_carrier_tests {
    use super::*;
    use crate::host::vendors::RuntimeProvider;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    struct CountRpc(Arc<AtomicUsize>);
    impl rpc::Rpc for CountRpc {
        fn call(&self, _: &str, _: serde_json::Value) -> native::Result<serde_json::Value> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err("unexpected RPC".into())
        }
    }
    #[test]
    fn installation_description_cannot_relabel_embedded_network_before_rpc() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/provider/stellar-policy-wallet-revalidation-rpc.json"
        ))
        .unwrap();
        let prepared: PreparedOperation =
            serde_json::from_value(fixture["prepared"].clone()).unwrap();
        let config = super::super::server_owner::configuration(
            "stellar:testnet",
            &serde_json::to_vec(&prepared.config).unwrap(),
        )
        .unwrap();
        let mut installation = installation(&config);
        installation.description.network = "stellar:pubnet".into();
        let calls = Arc::new(AtomicUsize::new(0));
        let provider = Provider::from_rpc("stellar:pubnet", Arc::new(CountRpc(calls.clone())));
        assert!(provider.snapshot(&installation, None).is_err());
        assert!(provider.resources(&installation).is_err());
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "foreign configuration reached RPC"
        );
    }
    #[test]
    fn raw_owner_carriers_cannot_relabel_network_before_signing_retention_or_rpc() {
        let state = native::AccountState {
            address: native::account_for_seed(&[11; 32]),
            sequence: 7,
            master_weight: 1,
            low_threshold: 0,
            medium_threshold: 0,
            high_threshold: 0,
            signers: vec![],
        };
        let setup = native::owner::prepare_native_setup(
            &state,
            &native::owner::SetupTerms {
                wallet: &native::account_for_seed(&[14; 32]),
                agent: &native::account_for_seed(&[12; 32]),
                engine: &native::account_for_seed(&[13; 32]),
                request_id: "network-test-001",
                network: "stellar:testnet",
                fee_per_operation: 100,
                starting_balance: None,
                trustline: None,
            },
            1,
        )
        .unwrap();
        let original = native::owner_intent::OwnerTransaction {
            network: setup.network,
            action: "native_setup".into(),
            transaction_xdr: setup.transaction_xdr,
            transaction_hash: native::unhex(&setup.transaction_hash).unwrap(),
            expires_at: setup.expires_at,
        };
        let stellar_xdr::TransactionEnvelope::Tx(mut env) =
            native::read(&original.transaction_xdr).unwrap()
        else {
            unreachable!()
        };
        let signature = native::signing::LocalSigner::from_entropy(&[11; 32])
            .unwrap()
            .sign_digest(&original.transaction_hash)
            .unwrap();
        let key = native::account_key(&state.address).unwrap();
        env.signatures = vec![stellar_xdr::DecoratedSignature {
            hint: stellar_xdr::SignatureHint(key[28..].try_into().unwrap()),
            signature: stellar_xdr::Signature(signature.try_into().unwrap()),
        }]
        .try_into()
        .unwrap();
        let signed = native::xdr(&stellar_xdr::TransactionEnvelope::Tx(env)).unwrap();
        native::owner_intent::validate_signed_owner_transaction(&original, &signed).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let provider = Provider::from_rpc("stellar:pubnet", Arc::new(CountRpc(calls.clone())));
        let owner = OwnerPacket(Packet::new("stellar:pubnet", &original, &PACKETS).unwrap());
        let read = provider.read_owner_signed(&owner, signed.as_bytes());
        let data = OwnerSignedData {
            original,
            signed_payload: signed.into_bytes(),
        };
        let owner_signed = OwnerSigned(Packet::new("stellar:pubnet", &data, &PACKETS).unwrap());
        let retained = AtomicUsize::new(0);
        let submitted = provider.submit_owner(
            &owner_signed,
            Box::new(|_| {
                retained.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }),
            Poll {
                attempts: 1,
                interval: std::time::Duration::ZERO,
            },
            1,
        );
        let observed = provider.observe_owner(&owner_signed);
        assert!(
            read.is_err(),
            "read_owner_signed accepted another native network"
        );
        assert!(submitted.is_err());
        assert!(observed.is_err());
        assert_eq!(
            retained.load(Ordering::SeqCst),
            0,
            "foreign network reached durable retention"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "foreign network reached RPC"
        );
    }
}
#[cfg(test)]
mod keypair_wallet_owner_tests {
    use super::*;
    use crate::host::vendors::RuntimeProvider;
    use crate::test_support::owner::{OwnerLedger, configured_source, native_selection};
    use std::sync::{Arc, Mutex};

    /// What the wallet account holds on the test ledger.
    #[derive(Clone, Copy)]
    struct Holdings {
        xlm: i64,
        /// Entries beside its signers whose reserve the account pays, such as a trustline.
        other_entries: u32,
        issued: i64,
        /// The issued units that an open offer of the account holds.
        issued_selling: i64,
    }
    /// A ledger that holds the owner's account and the wallet account `wallet`.
    struct Ledger(OwnerLedger, Mutex<native::AccountState>, Mutex<Holdings>);
    impl rpc::Rpc for Ledger {
        fn call(
            &self,
            method: &str,
            params: serde_json::Value,
        ) -> native::Result<serde_json::Value> {
            use stellar_xdr as x;
            let key = (method == "getLedgerEntries")
                .then(|| native::read::<x::LedgerKey>(params["keys"][0].as_str().unwrap()).ok())
                .flatten();
            match key {
                Some(x::LedgerKey::Account(key)) => {
                    let x::PublicKey::PublicKeyTypeEd25519(key) = key.account_id.0;
                    let wallet = self.1.lock().unwrap().clone();
                    if native::account_for_public_key(&key.0) == wallet.address {
                        let entry = crate::test_support::owner::account_entry(&wallet);
                        let x::LedgerEntryData::Account(mut account) =
                            native::read(entry["entries"][0]["xdr"].as_str().unwrap()).unwrap()
                        else {
                            panic!()
                        };
                        let holdings = *self.2.lock().unwrap();
                        account.balance = holdings.xlm;
                        account.num_sub_entries += holdings.other_entries;
                        let account = x::LedgerEntryData::Account(account);
                        return Ok(
                            serde_json::json!({"entries":[{"xdr":native::xdr(&account).unwrap()}]}),
                        );
                    }
                }
                Some(x::LedgerKey::Trustline(key)) => {
                    let holdings = *self.2.lock().unwrap();
                    let line = x::LedgerEntryData::Trustline(x::TrustLineEntry {
                        account_id: key.account_id,
                        asset: key.asset,
                        balance: holdings.issued,
                        limit: i64::MAX,
                        flags: 1,
                        ext: x::TrustLineEntryExt::V1(x::TrustLineEntryV1 {
                            liabilities: x::Liabilities {
                                buying: 0,
                                selling: holdings.issued_selling,
                            },
                            ext: x::TrustLineEntryV1Ext::V0,
                        }),
                    });
                    return Ok(
                        serde_json::json!({"entries":[{"xdr":native::xdr(&line).unwrap()}]}),
                    );
                }
                _ => {}
            }
            self.0.call(method, params, &[])
        }
    }
    fn fixture() -> (WalletConfig, Arc<Ledger>, Provider, Installation) {
        fixture_for(native_selection().config)
    }
    /// The wallet of `c` with 10,000 XLM and 7 units of its issued asset.
    fn fixture_for(c: WalletConfig) -> (WalletConfig, Arc<Ledger>, Provider, Installation) {
        let ledger = Arc::new(Ledger(
            OwnerLedger::new(c.clone()),
            Mutex::new(configured_source(&c)),
            Mutex::new(Holdings {
                xlm: 100_000_000_000,
                other_entries: 0,
                issued: 7,
                issued_selling: 0,
            }),
        ));
        let configuration =
            super::super::server_owner::configuration(&c.network, &serde_json::to_vec(&c).unwrap())
                .unwrap();
        let provider = Provider::from_rpc(&c.network, ledger.clone());
        (c, ledger, provider, installation(&configuration))
    }
    fn operations(packet: &OwnerPacket, c: &WalletConfig) -> Vec<stellar_xdr::Operation> {
        let info = packet.info().unwrap();
        let payload = String::from_utf8(info.signing_payload).unwrap();
        let stellar_xdr::TransactionEnvelope::Tx(envelope) = native::read(&payload).unwrap() else {
            panic!()
        };
        // The owner's account is the source and pays; the server attaches no signature.
        assert_eq!(
            envelope.tx.source_account,
            stellar_xdr::MuxedAccount::Ed25519(stellar_xdr::Uint256(
                native::account_key(&c.owner).unwrap()
            ))
        );
        assert!(envelope.signatures.is_empty());
        envelope.tx.operations.to_vec()
    }

    /// The one payment of a return of every spendable unit: its amount and its destination.
    fn returned(packet: &OwnerPacket, c: &WalletConfig) -> (i64, stellar_xdr::MuxedAccount) {
        assert_eq!(packet.info().unwrap().action, "withdraw");
        let operations = operations(packet, c);
        let [operation] = operations.as_slice() else {
            panic!("a return is one payment")
        };
        assert_eq!(
            operation.source_account,
            Some(stellar_xdr::MuxedAccount::Ed25519(stellar_xdr::Uint256(
                native::account_key(&c.wallet).unwrap()
            )))
        );
        let stellar_xdr::OperationBody::Payment(payment) = &operation.body else {
            panic!("a return is one payment")
        };
        assert_eq!(payment.asset, native::asset_xdr(c).unwrap());
        (payment.amount, payment.destination.clone())
    }
    #[test]
    fn a_return_of_every_spendable_unit_keeps_the_account_and_the_reserve_of_its_roles() {
        let everything = |recipient: &str| OwnerAction::Recover {
            units: None,
            recipient: Some(recipient.into()),
        };
        let account = |address: &str| {
            stellar_xdr::MuxedAccount::Ed25519(stellar_xdr::Uint256(
                native::account_key(address).unwrap(),
            ))
        };
        let nothing = |provider: &Provider, installation: &Installation, owner: &str| {
            let refused = provider
                .prepare_owner(installation, everything(owner), 100_000, 86_401)
                .unwrap_err();
            let problem = provider.problem(&refused);
            assert_eq!(
                (problem.status, problem.code),
                (409, "nothing_to_return"),
                "{}",
                problem.message
            );
        };
        // An issued asset: the whole balance of the trustline returns, to the named recipient.
        let (c, ledger, provider, installation) = fixture();
        assert!(c.asset_issuer.is_some());
        for recipient in [&c.owner, &c.agent] {
            let packet = provider
                .prepare_owner(&installation, everything(recipient), 100_000, 86_401)
                .unwrap();
            assert_eq!(returned(&packet, &c), (7, account(recipient)));
        }
        // Units that an open offer holds stay: a payment of them would fail.
        ledger.2.lock().unwrap().issued_selling = 3;
        let packet = provider
            .prepare_owner(&installation, everything(&c.owner), 100_000, 86_401)
            .unwrap();
        assert_eq!(returned(&packet, &c), (4, account(&c.owner)));
        for (issued, selling) in [(7, 7), (0, 0)] {
            let mut holdings = ledger.2.lock().unwrap();
            (holdings.issued, holdings.issued_selling) = (issued, selling);
            drop(holdings);
            nothing(&provider, &installation, &c.owner);
        }

        // XLM: everything above the reserve of the account and its three signers returns.
        let mut c = native_selection().config;
        c.asset_symbol = "XLM".into();
        c.asset_issuer = None;
        c.asset = native::sac_address(&c.network, &native::asset_xdr(&c).unwrap()).unwrap();
        let (c, ledger, provider, installation) = fixture_for(c);
        let base = native::owner::BASE_RESERVE_STROOPS;
        let reserve = native::owner::wallet_reserve(false);
        assert_eq!(reserve, 5 * base);
        let packet = provider
            .prepare_owner(&installation, everything(&c.owner), 100_000, 86_401)
            .unwrap();
        assert_eq!(
            returned(&packet, &c),
            (100_000_000_000 - reserve, account(&c.owner))
        );
        // Another entry of the account, such as a trustline, locks one more base reserve.
        ledger.2.lock().unwrap().other_entries = 1;
        let packet = provider
            .prepare_owner(&installation, everything(&c.owner), 100_000, 86_401)
            .unwrap();
        assert_eq!(
            returned(&packet, &c),
            (100_000_000_000 - reserve - base, account(&c.owner))
        );
        ledger.2.lock().unwrap().other_entries = 0;
        // A paused wallet has two signers and a lower network minimum. The return still keeps
        // the reserve of three signers, so the resume that restores the agent signer fits.
        ledger
            .1
            .lock()
            .unwrap()
            .signers
            .retain(|s| s.key != c.agent);
        ledger.2.lock().unwrap().xlm = reserve + 1;
        let packet = provider
            .prepare_owner(&installation, everything(&c.owner), 100_000, 86_401)
            .unwrap();
        assert_eq!(returned(&packet, &c), (1, account(&c.owner)));
        // A wallet at its reserve, or below it, returns nothing: the answer has its own code.
        for balance in [reserve, reserve - base, 0] {
            ledger.2.lock().unwrap().xlm = balance;
            nothing(&provider, &installation, &c.owner);
        }
    }

    #[test]
    fn the_server_prepares_each_owner_action_of_a_keypair_wallet_for_one_owner_signature() {
        let (c, ledger, provider, installation) = fixture();
        let wallet = Some(stellar_xdr::MuxedAccount::Ed25519(stellar_xdr::Uint256(
            native::account_key(&c.wallet).unwrap(),
        )));
        let prepare = |action| provider.prepare_owner(&installation, action, 100_000, 86_401);
        // An issued asset returns to the owner and its trustline closes before the merge.
        let issued = c.asset_issuer.is_some();
        let closing = if issued { 6 } else { 4 };
        for (action, name, count) in [
            (OwnerAction::Fund { units: 5 }, "fund", 1),
            (OwnerAction::SetPause { paused: true }, "pause", 1),
            (
                OwnerAction::Recover {
                    units: Some(5),
                    recipient: None,
                },
                "withdraw",
                1,
            ),
            (
                OwnerAction::Recover {
                    units: None,
                    recipient: None,
                },
                "close",
                closing,
            ),
        ] {
            let packet = prepare(action).unwrap();
            assert_eq!(packet.info().unwrap().action, name);
            let operations = operations(&packet, &c);
            assert_eq!(operations.len(), count, "{name}");
            // Only funding comes from the owner's own balance.
            for operation in &operations {
                assert_eq!(
                    operation.source_account,
                    if name == "fund" { None } else { wallet.clone() },
                    "{name}"
                );
            }
        }
        // The declared fee never exceeds the caller's limit: a limit below the minimum fee of
        // every operation prepares nothing.
        let close = || OwnerAction::Recover {
            units: None,
            recipient: None,
        };
        assert!(
            provider
                .prepare_owner(&installation, close(), 100, 86_401)
                .is_err()
        );
        let minimum = 100 * closing as u64;
        let packet = provider
            .prepare_owner(&installation, close(), minimum, 86_401)
            .unwrap();
        let stellar_xdr::TransactionEnvelope::Tx(envelope) =
            native::read(&String::from_utf8(packet.info().unwrap().signing_payload).unwrap())
                .unwrap()
        else {
            panic!()
        };
        assert_eq!(u64::from(envelope.tx.fee), minimum);
        // A wallet that is not paused takes no resume, and a keypair wallet has no code.
        assert!(prepare(OwnerAction::SetPause { paused: false }).is_err());
        for action in [
            OwnerAction::Create {
                wasm: vec![],
                units: 1,
                fee_asset_units: 0,
            },
            OwnerAction::Extend,
        ] {
            assert!(prepare(action).is_err());
        }
        // The owner paused the wallet: discovery reports it, and only a resume fits.
        ledger
            .1
            .lock()
            .unwrap()
            .signers
            .retain(|s| s.key != c.agent);
        assert!(prepare(OwnerAction::SetPause { paused: true }).is_err());
        let resume = prepare(OwnerAction::SetPause { paused: false }).unwrap();
        assert_eq!(resume.info().unwrap().action, "resume");
        let configuration =
            super::super::server_owner::configuration(&c.network, &serde_json::to_vec(&c).unwrap())
                .unwrap();
        let usage = Accounting {
            deployment_version: 1,
            ..Accounting::default()
        };
        assert!(
            provider
                .discover_snapshot(&configuration, Some(&usage))
                .unwrap()
                .paused
        );
    }
    /// The server signs for a wallet only while the ledger holds exactly the registered roles.
    #[test]
    fn a_wallet_whose_signers_or_thresholds_differ_from_its_registration_is_refused() {
        let (c, ledger, provider, installation) = fixture();
        let configuration =
            super::super::server_owner::configuration(&c.network, &serde_json::to_vec(&c).unwrap())
                .unwrap();
        let usage = Accounting {
            deployment_version: 1,
            ..Accounting::default()
        };
        provider
            .discover_snapshot(&configuration, Some(&usage))
            .unwrap();
        assert!(provider.resources(&installation).unwrap().wallet_present);
        let registered = ledger.1.lock().unwrap().clone();
        let drift: [fn(&mut native::AccountState); 3] = [
            |a| {
                a.signers.push(native::AccountSigner {
                    key: native::account_for_seed(&[99; 32]),
                    weight: 1,
                })
            },
            |a| a.medium_threshold = 1,
            |a| a.master_weight = 1,
        ];
        for change in drift {
            let mut changed = registered.clone();
            change(&mut changed);
            *ledger.1.lock().unwrap() = changed;
            assert!(
                provider
                    .discover_snapshot(&configuration, Some(&usage))
                    .is_err()
            );
            assert!(
                provider
                    .prepare_owner(
                        &installation,
                        OwnerAction::SetPause { paused: true },
                        100_000,
                        86_401
                    )
                    .is_err()
            );
        }
    }
}
