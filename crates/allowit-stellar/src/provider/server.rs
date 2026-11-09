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
    r.map_err(Error::config)
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
        calls: a.calls,
    })
}
fn fee(v: u64) -> Result<u32> {
    u32::try_from(v).map_err(|_| Error::usage("Fee ceiling exceeds the selected native range"))
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
        Kind::Signed => {
            decode::<SignedOperation>(&document)?
                .prepared
                .config
                .network
        }
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
            decode_packet::<SignedOperation>(&packet)?;
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
    checked(value.state.source.validate_structure())?;
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
pub fn receipt_info(p: &Packet) -> Result<ReceiptInfo> {
    let r: rpc::VerifiedReceipt = decode_packet(p)?;
    let result: stellar_xdr::TransactionResult = checked(native::read(&r.result_xdr))?;
    Ok(ReceiptInfo {
        transaction_hash: r.transaction_hash,
        status: status(r.status),
        observed_height: u64::from(r.ledger),
        fee: crate::host::runtime::Fee {
            native_units: u128::try_from(result.fee_charged)
                .map_err(|_| Error::config("Invalid Stellar receipt fee"))?,
            // The engine sets the charge through ServerHooks::charged_fee.
            charged_units: 0,
        },
        // The prepared operation carries its debits; the receipt adds only the fee.
        debits: Vec::new(),
    })
}
pub struct Provider {
    network: String,
    runtime: crate::provider::runtime::Runtime,
    transport: std::sync::Arc<dyn rpc::Rpc>,
}
impl Provider {
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
        }
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
                let value = self.inner.call(method, params)?;
                if method == "simulateTransaction"
                    && let Some(error) = value["error"].as_str()
                    && let Some(fault) = rpc::simulation_fault(error, &[])
                {
                    let problem = super::diagnostics::denial(error, Some(&fault), &self.wallet);
                    if let Ok(mut captured) = self.captured.lock() {
                        *captured = Some((error.into(), problem));
                    }
                    // This terminal contract failure propagates directly to this operation.
                    // Missing-export probes and other native response handling remain unchanged.
                    return Err(error.into());
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
        let provider = Self::from_rpc_inner(&self.network, probe);
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
        checked(native::operation_from_request(&c, &r))?;
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
        Ok(match checked(native::operation_from_request(&c, &r))? {
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
        let code_present = checked(rpc::code_uploaded(self.rpc(), &c.network, &c.module_digest))?;
        let wallet_present = checked(rpc::contract_exists(self.rpc(), &c.network, &c.wallet))?;
        let lifetime = if wallet_present {
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
        let s = checked(rpc::trusted_state_for_discovery(self.rpc(), &c, None))?;
        checked(rpc::vault_redeemable(
            self.rpc(),
            &c,
            &s.state.source,
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
        };
        let accounting = accounting(a);
        self.packet(&checked(self.runtime.prepare(
            &c,
            &decode_packet(&r.0)?,
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
        let signed = checked(native::authorize(&p, &s, now))?;
        Ok(Signed(packet(&p.config.network, &signed)?))
    }
    fn validate_signed(&self, p: &Signed, now: u64) -> Result<()> {
        self.network(p.network())?;
        checked(native::validate_signed(&signed(p)?, now))
    }
    fn broadcast(&self, p: &Signed, now: u64) -> Result<Status> {
        self.network(p.network())?;
        let s = signed(p)?;
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
        let s = signed(p)?;
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
        let s = signed(p)?;
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
    fn prepare_owner(
        &self,
        i: &Installation,
        a: OwnerAction,
        fee_limit: u64,
        now: u64,
    ) -> Result<OwnerPacket> {
        let c = self.config(i)?;
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
            OwnerAction::Upload { wasm } => {
                let p = checked(d.upload_wasm(&c.owner, &wasm))?;
                native::owner_intent::OwnerTransaction {
                    network: p.network,
                    action: p.function,
                    transaction_xdr: p.transaction_xdr,
                    transaction_hash: p.transaction_hash,
                    expires_at: p.expires_at,
                }
            }
            OwnerAction::Create { wasm } => {
                let config = checked(native::admin::PolicyConfig::for_policy(&c, false))?;
                let p = checked(d.create_wallet(
                    &config,
                    &wasm,
                    native::admin::wallet_salt(&c.policy_instance),
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
                use allowit_core::admin::RecoverFunds;
                let mut admin = native::admin::OwnerAdmin {
                    rpc: self.rpc(),
                    config: &c,
                    now,
                };
                let prepared = match (units, recipient) {
                    (None, None) => checked(admin.recover_funds(&c.asset))?,
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
        .map_err(Error::config)?;
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
        request: RequestPacket(packet(&value.config.network, &value.request)?),
        operation_id: value.request.operation.nonce,
        created_at: value.created_at,
        expires_at: value.expires_at,
        transaction_hash: value.transaction_hash,
        debit_units: i128::from_be_bytes(amount),
        request_hash: value.request_hash,
        debit,
    })
}
pub fn signed_preparation(p: &Packet) -> Result<Prepared> {
    let value: SignedOperation = decode_packet(p)?;
    Ok(Prepared(packet(
        &value.prepared.config.network,
        &value.prepared,
    )?))
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
        state: s
            .policy_state
            .as_ref()
            .map(|p| convert(&p.state))
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
    checked(live.state.source.signer_weight(identity))
}
pub fn authority_document(s: &Snapshot) -> Result<serde_json::Value> {
    let live: rpc::DiscoveredState = decode_observation(&s.evidence)?;
    serde_json::to_value(live.state.source)
        .map_err(|_| Error::config("Cannot describe authority observation"))
}

/// Parse retained signed identity without granting new submission authority. Chain-only recovery
/// can retain an included envelope whose signature roles rotated; broadcast validates signatures again.
fn retained_signed_shape(s: &SignedOperation) -> Result<()> {
    checked(native::validate_retained_prepared(&s.prepared))?;
    if s.prepared.config.route != WalletRoute::PolicyWallet {
        return checked(native::validate_retained_signed(s));
    }
    checked(native::validate_server_authorization(&s.prepared))?;
    let hash = checked(rpc::signed_transaction_hash(
        &s.prepared.config.network,
        &s.transaction_xdr,
    ))?;
    if hash != s.transaction_hash || hash != s.prepared.transaction_hash {
        return Err(Error::config("Retained signed identity differs"));
    }
    Ok(())
}
pub fn validate_signed(p: &Packet) -> Result<()> {
    let signed: SignedOperation = decode_packet(p)?;
    checked(native::validate_retained_signed(&signed))
}
pub fn verify_receipt(r: &Packet, p: &Packet) -> Result<()> {
    let signed: SignedOperation = decode_packet(p)?;
    let receipt: rpc::VerifiedReceipt = decode_packet(r)?;
    if r.network() != p.network() {
        return Err(Error::config("Receipt network differs from operation"));
    }
    verify_native_receipt(&signed, &receipt)
}
fn verify_native_receipt(signed: &SignedOperation, receipt: &rpc::VerifiedReceipt) -> Result<()> {
    if signed.prepared.config.route == WalletRoute::PolicyWallet {
        checked(rpc::validate_settled_policy_packet(signed, receipt))
    } else {
        checked(native::validate_retained_signed(signed))?;
        if signed.transaction_xdr != receipt.envelope_xdr {
            return Err(Error::config(
                "The settlement envelope differs from the original packet",
            ));
        }
        checked(rpc::validate_receipt(
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
            &native::account_for_seed(&[12; 32]),
            &native::account_for_seed(&[13; 32]),
            "setup-history-001",
            "stellar:testnet",
            100,
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
            &native::account_for_seed(&[12; 32]),
            &native::account_for_seed(&[13; 32]),
            "network-test-001",
            "stellar:testnet",
            100,
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
