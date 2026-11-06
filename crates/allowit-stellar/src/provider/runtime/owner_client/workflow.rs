//! Retained owner workflows. A session identifies the owner; only checked native intent can request a signature.
use super::*;
use allowit_policy_sdk::client::store::Store;
use native::owner_intent::{self, ExpectedOwnerIntent, OwnerAction, OwnerLimits, OwnerTransaction};
use native::{OperationStatus, WalletConfig, WalletRoute, rpc};

/// Caller-owned capabilities. They do not transfer keys or storage authority to the SDK.
#[derive(Clone, Copy)]
pub struct OwnerCapabilities<'a> {
    pub store: &'a Store,
    pub rpc: &'a dyn rpc::Rpc,
    pub signer: &'a dyn OwnerSigner,
    pub clock: &'a dyn Fn() -> Result<u64>,
}

/// Public policy and the complete installation selected by the caller, independent of a prepared packet.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OwnerPolicy {
    pub policy: GeneratedPolicy,
    pub config: WalletConfig,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Outcome {
    pub request_id: String,
    pub state: String,
    pub selection: OwnerPolicy,
    pub transactions: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
enum Work {
    Deploy,
    Fund { amount: String, units: i128 },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Step {
    network: String,
    action: String,
    transaction_xdr: String,
    transaction_hash: String,
    expires_at: u64,
    // Server explorer links are display-only and are never persisted or trusted.
    #[serde(default, skip_serializing)]
    #[serde(rename = "explorer")]
    _explorer: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RetainedStep {
    packet: Step,
    source: native::AccountState,
    validated_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    extend_to: Option<u32>,
    signed_xdr: Option<String>,
    signature: Option<Vec<u8>>,
    submitted: bool,
    receipt: Option<rpc::VerifiedReceipt>,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Record {
    version: u8,
    request_id: String,
    backend: String,
    origin: String,
    intent_hash: String,
    selection: OwnerPolicy,
    work: Work,
    max_fee_stroops: u32,
    steps: Vec<RetainedStep>,
    complete: bool,
}

fn checked<T>(value: native::Result<T>) -> Result<T> {
    value.map_err(|_| Error::config("Native owner intent or chain observation failed validation"))
}
fn intent_hash(value: &impl Serialize) -> Result<String> {
    serde_json_canonicalizer::to_vec(value)
        .map(|b| allowit_policy_sdk::digest(&b))
        .map_err(|_| Error::config("Cannot encode owner workflow identity"))
}
pub fn wallet_salt(instance: &[u8; 32]) -> [u8; 32] {
    native::admin::wallet_salt(instance)
}

impl OwnerPolicy {
    pub fn validate(&self) -> Result<()> {
        let c = &self.config;
        let p = &self.policy;
        let b = &p.runtime.instance_binding;
        roles(&c.owner, &c.agent, &c.server)?;
        checked(native::validate_config(c))?;
        let target = if b.template == Some(true) {
            Target::NewWallet
        } else {
            Target::Installation(b.deployment_id.clone())
        };
        let request = GenerateRequest {
            prompt: p.original_intent.clone(),
            network: p.network.clone(),
            profile: p.runtime.wallet.profile.clone(),
            target,
        };
        validate_generated(p, &request, &p.network, &p.runtime.wallet.kind)?;
        if c.network != p.network
            || c.policy_instance != checked(native::unhex(&b.policy_instance))?
            || c.policy_source != p.code
            || native::hex(&c.source_hash) != p.source_hash
            || c.asset != b.asset
            || c.asset_symbol != b.asset_symbol
            || c.asset_issuer != b.asset_issuer
            || c.max_fee_stroops != b.max_fee_stroops
            || c.params != b.portable.params
            || c.tier != b.tier
            || (c.route == WalletRoute::Native
                && (c.wallet != b.wallet || native::hex(&c.module_digest) != b.module_digest))
            || (c.route == WalletRoute::Native
                && (c.source_digest != [0; 32]
                    || (!c.rules.is_empty() && c.rules != b.portable.rules)))
            || !b.portable.unresolved.is_empty()
        {
            return Err(Error::config(
                "Public owner selection differs from its source, params or native binding",
            ));
        }
        Ok(())
    }
}
fn roles(owner: &str, agent: &str, server: &str) -> Result<()> {
    for key in [owner, agent, server] {
        checked(native::account_key(key))?;
    }
    if owner == agent || owner == server || agent == server {
        return Err(Error::usage(
            "Owner, agent and server must be distinct G accounts",
        ));
    }
    Ok(())
}
/// Derive every constructor field from the reviewed public draft and reviewed executable.
/// A host compilation report is not a Wasm identity or publication proof.
pub fn deployment_policy(
    policy: GeneratedPolicy,
    owner: &str,
    agent: &str,
    server: &str,
    wasm: &[u8],
) -> Result<OwnerPolicy> {
    roles(owner, agent, server)?;
    let request = GenerateRequest {
        prompt: policy.original_intent.clone(),
        network: policy.network.clone(),
        profile: policy.runtime.wallet.profile.clone(),
        target: Target::NewWallet,
    };
    validate_generated(&policy, &request, &policy.network, "contract-wallet")?;
    let b = &policy.runtime.instance_binding;
    if !b.portable.unresolved.is_empty() {
        return Err(Error::usage(
            "Supply unresolved owner params before deployment",
        ));
    }
    let instance = checked(native::unhex(&b.policy_instance))?;
    let tier = b
        .tier
        .ok_or_else(|| Error::usage("Select the wallet tier"))?;
    let module = checked(native::admin::check_wallet_code(wasm))?;
    let rules = checked(native::policy::tier_rules(tier, &policy.code))?;
    let config = WalletConfig {
        network: policy.network.clone(),
        policy_instance: instance,
        wallet: checked(native::admin::wallet_address(
            &policy.network,
            owner,
            &wallet_salt(&instance),
        ))?,
        owner: owner.into(),
        agent: agent.into(),
        server: server.into(),
        route: WalletRoute::PolicyWallet,
        tier: Some(tier),
        language: native::PolicyLanguage::Portable,
        rules: rules.clone(),
        params: b.portable.params.clone(),
        source_digest: checked(native::policy::installed_source_digest(
            tier,
            &module,
            &b.asset,
            &rules,
            &policy.code,
        ))?,
        asset: b.asset.clone(),
        asset_symbol: b.asset_symbol.clone(),
        asset_issuer: b.asset_issuer.clone(),
        policy_source: policy.code.clone(),
        source_hash: native::hash(policy.code.as_bytes()),
        module_digest: module,
        max_fee_stroops: b.max_fee_stroops,
    };
    checked(native::validate_config(&config))?;
    Ok(OwnerPolicy { policy, config })
}
/// Bind a generated classic policy to explicit operator-provisioned native custody roles.
pub fn native_policy(
    policy: GeneratedPolicy,
    owner: &str,
    agent: &str,
    server: &str,
) -> Result<OwnerPolicy> {
    roles(owner, agent, server)?;
    let b = &policy.runtime.instance_binding;
    let request = GenerateRequest {
        prompt: policy.original_intent.clone(),
        network: policy.network.clone(),
        profile: policy.runtime.wallet.profile.clone(),
        target: Target::Installation(b.deployment_id.clone()),
    };
    validate_generated(&policy, &request, &policy.network, "owner-wallet")?;
    let config = WalletConfig {
        network: policy.network.clone(),
        policy_instance: checked(native::unhex(&b.policy_instance))?,
        wallet: b.wallet.clone(),
        owner: owner.into(),
        agent: agent.into(),
        server: server.into(),
        route: WalletRoute::Native,
        tier: None,
        language: native::PolicyLanguage::Portable,
        rules: Vec::new(),
        params: b.portable.params.clone(),
        source_digest: [0; 32],
        asset: b.asset.clone(),
        asset_symbol: b.asset_symbol.clone(),
        asset_issuer: b.asset_issuer.clone(),
        policy_source: policy.code.clone(),
        source_hash: native::hash(policy.code.as_bytes()),
        module_digest: checked(native::unhex(&b.module_digest))?,
        max_fee_stroops: b.max_fee_stroops,
    };
    checked(native::validate_config(&config))?;
    Ok(OwnerPolicy { policy, config })
}
/// Convert a positive decimal asset amount to exact seven-decimal base units without floating point.
pub fn amount_units(amount: &str) -> Result<i128> {
    let (whole, fraction) = amount.split_once('.').unwrap_or((amount, ""));
    if whole.is_empty()
        || whole.len() > 32
        || fraction.len() > 7
        || !whole
            .bytes()
            .chain(fraction.bytes())
            .all(|b| b.is_ascii_digit())
    {
        return Err(Error::usage(
            "Enter a positive amount with at most seven decimal places",
        ));
    }
    let units = whole
        .parse::<i128>()
        .ok()
        .and_then(|v| v.checked_mul(10_000_000))
        .and_then(|v| {
            fraction
                .parse::<i128>()
                .ok()
                .or(Some(0))
                .and_then(|f| f.checked_mul(10_i128.pow(7 - fraction.len() as u32)))
                .and_then(|f| v.checked_add(f))
        })
        .filter(|v| *v > 0);
    units.ok_or_else(|| Error::usage("Asset amount exceeds the supported positive range"))
}
fn network(rpc: &dyn rpc::Rpc, selected: &str) -> Result<()> {
    if checked(rpc.call("getNetwork", json!({})))?["passphrase"]
        != checked(native::passphrase(selected))?
    {
        return Err(Error::config(
            "Owner RPC network differs from the selected policy",
        ));
    }
    Ok(())
}
fn expected(record: &Record, step: &RetainedStep) -> Result<ExpectedOwnerIntent> {
    let c = &record.selection.config;
    let action = match (&record.work, step.packet.action.as_str()) {
        (Work::Deploy, "upload_wasm") => OwnerAction::UploadWasm {
            wasm_hash: c.module_digest,
        },
        (Work::Deploy, "create_wallet") => OwnerAction::CreateWallet {
            config: Box::new(c.clone()),
            salt: wallet_salt(&c.policy_instance),
            x402_enabled: false,
        },
        (Work::Fund { units, .. }, "fund") => OwnerAction::Fund {
            asset: c.asset.clone(),
            from: c.owner.clone(),
            to: c.wallet.clone(),
            amount: *units,
        },
        (_, "extend") => OwnerAction::Extend {
            wallet: c.wallet.clone(),
            wasm_hash: c.module_digest,
            extend_to: step.extend_to.ok_or_else(|| {
                Error::config("Retained lifetime extension has no independently selected target")
            })?,
        },
        _ => {
            return Err(Error::config(
                "Prepared owner action differs from the retained caller intent",
            ));
        }
    };
    Ok(ExpectedOwnerIntent {
        limits: OwnerLimits {
            network: c.network.clone(),
            owner: c.owner.clone(),
            next_sequence: step
                .source
                .sequence
                .checked_add(1)
                .ok_or_else(|| Error::config("Owner sequence overflow"))?,
            max_fee_stroops: record.max_fee_stroops,
            valid_until: step
                .validated_at
                .checked_add(300)
                .ok_or_else(|| Error::config("Owner validity overflow"))?,
        },
        action,
    })
}
fn packet(step: &Step) -> Result<OwnerTransaction> {
    Ok(OwnerTransaction {
        network: step.network.clone(),
        action: step.action.clone(),
        transaction_xdr: step.transaction_xdr.clone(),
        transaction_hash: checked(native::unhex(&step.transaction_hash))?,
        expires_at: step.expires_at,
    })
}
fn verify_retained(record: &Record, step: &RetainedStep) -> Result<()> {
    let (Some(signed), Some(signature)) = (&step.signed_xdr, &step.signature) else {
        return Err(Error::config("Retained owner signature is incomplete"));
    };
    let signature: [u8; 64] = signature
        .clone()
        .try_into()
        .map_err(|_| Error::config("Invalid retained owner signature"))?;
    let proof = checked(owner_intent::validate_owner_transaction(
        &packet(&step.packet)?,
        &expected(record, step)?,
        step.validated_at,
    ))?;
    let exact = checked(proof.sign_with(step.validated_at, |_| Ok(signature)))?;
    if exact != *signed {
        return Err(Error::config("Retained signed owner bytes changed"));
    }
    Ok(())
}
impl OwnerClient {
    /// Execute the next upload/create steps, retaining every packet and signature before submission.
    pub fn deploy(
        &self,
        caps: OwnerCapabilities<'_>,
        selection: &OwnerPolicy,
        request_id: &str,
        max_fee_stroops: u32,
    ) -> Result<Outcome> {
        self.run_owner(caps, selection, request_id, Work::Deploy, max_fee_stroops)
    }
    pub fn fund(
        &self,
        caps: OwnerCapabilities<'_>,
        selection: &OwnerPolicy,
        request_id: &str,
        amount: &str,
        max_fee_stroops: u32,
    ) -> Result<Outcome> {
        self.run_owner(
            caps,
            selection,
            request_id,
            Work::Fund {
                amount: amount.into(),
                units: amount_units(amount)?,
            },
            max_fee_stroops,
        )
    }
    fn run_owner(
        &self,
        caps: OwnerCapabilities<'_>,
        selection: &OwnerPolicy,
        id: &str,
        work: Work,
        max_fee: u32,
    ) -> Result<Outcome> {
        let OwnerCapabilities {
            store,
            rpc,
            signer,
            clock,
        } = caps;
        if !crate::host::request::request_id_valid(id)
            || max_fee < 100
            || selection.config.route != WalletRoute::PolicyWallet
            || signer.account() != self.session.owner()
            || selection.config.owner != self.session.owner()
        {
            return Err(Error::usage(
                "Select a valid owner request, fee and policy wallet binding",
            ));
        }
        selection.validate()?;
        let identity =
            intent_hash(&json!({"selection":selection,"work":work,"maxFeeStroops":max_fee}))?;
        let mut record = match store.load::<Record>(id)? {
            Some(saved)
                if saved.version == 1
                    && saved.request_id == id
                    && saved.backend == self.session.backend()
                    && saved.origin == self.session.origin()
                    && saved.intent_hash == identity
                    && intent_hash(
                        &json!({"selection":saved.selection,"work":saved.work,"maxFeeStroops":saved.max_fee_stroops}),
                    )? == identity =>
            {
                saved
            }
            Some(_) => {
                return Err(Error::config(
                    "Owner request ID already binds another workflow",
                ));
            }
            None => Record {
                version: 1,
                request_id: id.into(),
                backend: self.session.backend().to_owned(),
                origin: self.session.origin().to_owned(),
                intent_hash: identity,
                selection: selection.clone(),
                work,
                max_fee_stroops: max_fee,
                steps: vec![],
                complete: false,
            },
        };
        for step in &record.steps {
            if step.signed_xdr.is_some() {
                verify_retained(&record, step)?;
            }
            if let Some(receipt) = &step.receipt {
                let hash = checked(native::unhex(&step.packet.transaction_hash))?;
                checked(rpc::validate_receipt(
                    receipt,
                    &selection.config.network,
                    &hash,
                ))?;
                if receipt.status == OperationStatus::Failed {
                    return Err(Error::api(
                        409,
                        "The original owner transaction failed; retain its receipt",
                    ));
                }
            }
        }
        store.save(id, &record)?;
        network(rpc, &selection.config.network)?;
        for _ in 0..4 {
            if record.complete {
                break;
            }
            if record.steps.last().is_none_or(|s| s.receipt.is_some()) {
                if record
                    .steps
                    .last()
                    .is_some_and(|s| s.packet.action == "fund")
                {
                    record.complete = true;
                    store.save(id, &record)?;
                    break;
                }
                #[derive(Deserialize)]
                #[serde(rename_all = "camelCase")]
                struct Prepared {
                    policy_id: String,
                    step: Option<Step>,
                }
                let (path, body) = match &record.work {
                    Work::Deploy => (
                        "/api/native/deploy/prepare",
                        json!({"policyId":selection.policy.id,"agent":selection.config.agent}),
                    ),
                    Work::Fund { amount, .. } => (
                        "/api/native/owner/prepare",
                        json!({"policyId":selection.policy.id,"action":"fund","amount":amount}),
                    ),
                };
                let response: Prepared = self
                    .session
                    .owner_request(Method::Post, path, Some(&body), clock()?, true)
                    .map_err(|_| {
                        Error::uncertain(
                            "Owner preparation is unavailable; retain this workflow ID",
                        )
                    })?;
                if response.policy_id != selection.policy.id {
                    return Err(Error::config("Owner preparation selected another policy"));
                }
                let Some(step) = response.step else {
                    if !matches!(record.work, Work::Deploy) {
                        return Err(Error::uncertain(
                            "Funding preparation omitted its transaction",
                        ));
                    }
                    self.verify_binding(selection, rpc)?;
                    record.complete = true;
                    store.save(id, &record)?;
                    break;
                };
                if record
                    .steps
                    .iter()
                    .any(|saved| saved.packet.action == step.action)
                {
                    return Err(Error::config(
                        "Deployment preparation repeated an already retained action",
                    ));
                }
                let source = checked(rpc::get_account(rpc, self.session.owner()))?;
                checked(source.validate_owner_only())?;
                let extend_to = if step.action == "extend" {
                    let live = checked(rpc::wallet_lifetime(
                        rpc,
                        &selection.config.network,
                        &selection.config.wallet,
                        &selection.config.module_digest,
                    ))?;
                    if !checked(live.needs_renewal())? {
                        return Err(Error::config(
                            "Current wallet lifetime does not require renewal",
                        ));
                    }
                    Some(checked(live.extend_to())?)
                } else {
                    None
                };
                let retained = RetainedStep {
                    extend_to,
                    packet: step,
                    source,
                    validated_at: clock()?,
                    signed_xdr: None,
                    signature: None,
                    submitted: false,
                    receipt: None,
                };
                checked(owner_intent::validate_owner_transaction(
                    &packet(&retained.packet)?,
                    &expected(&record, &retained)?,
                    retained.validated_at,
                ))?;
                record.steps.push(retained);
                store.save(id, &record)?;
            }
            let index = record.steps.len() - 1;
            if record.steps[index].signed_xdr.is_none() {
                let step = &record.steps[index];
                let current = checked(rpc::get_account(rpc, self.session.owner()))?;
                if current != step.source {
                    return Err(Error::config(
                        "Owner account changed before signing; retain the original intent",
                    ));
                }
                if let Some(target) = step.extend_to {
                    let live = checked(rpc::wallet_lifetime(
                        rpc,
                        &selection.config.network,
                        &selection.config.wallet,
                        &selection.config.module_digest,
                    ))?;
                    if checked(live.extend_to())? != target || !checked(live.needs_renewal())? {
                        return Err(Error::config(
                            "Wallet lifetime changed before signing. Retain the original extension intent.",
                        ));
                    }
                }
                if matches!(record.work, Work::Fund { .. }) {
                    self.verify_binding(selection, rpc)?;
                }
                let now = clock()?;
                if now < step.validated_at {
                    return Err(Error::config("Clock moved backwards before owner signing"));
                }
                let proof = checked(owner_intent::validate_owner_transaction(
                    &packet(&step.packet)?,
                    &expected(&record, step)?,
                    now,
                ))?;
                let mut signature = None;
                let signed = checked(proof.sign_with(clock()?, |digest| {
                    let result = signer.sign_hash(digest)?;
                    signature = Some(result.to_vec());
                    Ok(result)
                }))?;
                record.steps[index].signed_xdr = Some(signed);
                record.steps[index].signature = signature;
                store.save(id, &record)?;
            }
            verify_retained(&record, &record.steps[index])?;
            if matches!(record.work, Work::Fund { .. }) && !record.steps[index].submitted {
                self.verify_binding(selection, rpc)?;
            }
            let hash = checked(native::unhex(&record.steps[index].packet.transaction_hash))?;
            let observed =
                rpc::receipt_by_hash(rpc, &selection.config.network, &hash).map_err(|_| {
                    Error::uncertain(
                        "The original owner receipt is unavailable; retain this workflow ID",
                    )
                })?;
            if let Some(receipt) = &observed {
                checked(rpc::validate_receipt(
                    receipt,
                    &selection.config.network,
                    &hash,
                ))?;
                if receipt.status != OperationStatus::Confirmed {
                    record.steps[index].receipt = observed;
                    store.save(id, &record)?;
                    return Err(Error::api(
                        409,
                        "The original owner transaction failed; retain its receipt",
                    ));
                }
            } else if record.steps[index].submitted {
                let current = checked(rpc::get_account(rpc, self.session.owner()))?;
                if clock()? >= record.steps[index].packet.expires_at
                    || current.sequence != record.steps[index].source.sequence
                {
                    return Err(Error::uncertain(
                        "The original owner transaction remains unresolved; no replacement was signed",
                    ));
                }
            }
            if clock()? < record.steps[index].validated_at
                || (observed.is_none() && clock()? >= record.steps[index].packet.expires_at)
            {
                return Err(Error::uncertain(
                    "Owner packet is no longer current; retain its original identity",
                ));
            }
            record.steps[index].submitted = true;
            store.save(id, &record)?;
            let signed = record.steps[index]
                .signed_xdr
                .as_ref()
                .expect("retained signed owner packet");
            let response: Value = self
                .session
                .owner_request(
                    Method::Post,
                    "/api/native/owner/submit",
                    Some(&json!({"policyId":selection.policy.id,"transactionXdr":signed})),
                    clock()?,
                    true,
                )
                .map_err(|_| {
                    Error::uncertain("Owner submission is uncertain; resume this exact workflow ID")
                })?;
            if response["transactionHash"] != native::hex(&hash)
                || response["status"] != "confirmed"
            {
                return Err(Error::uncertain(
                    "Owner submission has no matching confirmed receipt; retain the workflow",
                ));
            }
            let receipt = checked(rpc::receipt_by_hash(rpc, &selection.config.network, &hash))?
                .ok_or_else(|| {
                    Error::uncertain("Owner receipt is not yet independently available")
                })?;
            checked(rpc::validate_receipt(
                &receipt,
                &selection.config.network,
                &hash,
            ))?;
            if receipt.status != OperationStatus::Confirmed
                || record.steps[index].signed_xdr.as_deref() != Some(&receipt.envelope_xdr)
            {
                return Err(Error::api(
                    409,
                    "The original owner transaction failed or its receipt envelope differs",
                ));
            }
            record.steps[index].receipt = Some(receipt);
            store.save(id, &record)?;
        }
        for step in &record.steps {
            verify_retained(&record, step)?;
            if let Some(receipt) = &step.receipt {
                let hash = checked(native::unhex(&step.packet.transaction_hash))?;
                checked(rpc::validate_receipt(
                    receipt,
                    &selection.config.network,
                    &hash,
                ))?;
                if step.signed_xdr.as_deref() != Some(&receipt.envelope_xdr)
                    || receipt.status != OperationStatus::Confirmed
                {
                    return Err(Error::config(
                        "Owner receipt differs from its exact signed packet",
                    ));
                }
            }
        }
        if !record.complete {
            return Err(Error::uncertain(
                "Owner flow retains an unfinished step; resume the same request ID",
            ));
        }
        if matches!(record.work, Work::Deploy) {
            self.verify_binding(selection, rpc)?;
        }
        Ok(Outcome {
            request_id: id.into(),
            state: match record.work {
                Work::Deploy => "installed",
                Work::Fund { .. } => "funded",
            }
            .into(),
            selection: selection.clone(),
            transactions: record
                .steps
                .iter()
                .map(|s| s.packet.transaction_hash.clone())
                .collect(),
        })
    }
    pub fn verify_binding(&self, selection: &OwnerPolicy, rpc: &dyn rpc::Rpc) -> Result<()> {
        selection.validate()?;
        let c = &selection.config;
        let authority = self.authority.as_ref().ok_or_else(|| {
            Error::config("Owner action requires independently configured server authority")
        })?;
        if authority.origin() != self.session.backend()
            || authority.network() != crate::host::routing::normalize(&c.network)?
            || authority.public_key() != c.server
        {
            return Err(Error::config(
                "Owner selection differs from configured server authority",
            ));
        }
        checked(native::validate_config(c))?;
        network(rpc, &c.network)?;
        if c.owner != self.session.owner() {
            return Err(Error::config(
                "Policy owner differs from this owner session",
            ));
        }
        if c.route == WalletRoute::Native {
            return crate::provider::runtime::client::verify_native_members(
                &checked(rpc::get_account(rpc, &c.wallet))?,
                c,
            );
        }
        let live = checked(rpc::trusted_state_for_discovery(rpc, c, None))?;
        if live.paused
            || live.state.owner != c.owner
            || live.state.agent != c.agent
            || live.state.server != c.server
            || live.state.policy_instance != c.policy_instance
            || live.state.module_digest != c.module_digest
            || live.state.policy_state.as_ref().is_none_or(|s| {
                s.params != c.params || s.rules != c.rules || s.source_digest != c.source_digest
            })
        {
            return Err(Error::config(
                "Current native authority or policy binding differs from the selected installation",
            ));
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Activation {
    backend: String,
    origin: String,
    identity: String,
    signature: Option<native::DetachedSignature>,
    completed: bool,
}
fn approval_payload(selection: &OwnerPolicy) -> Result<Value> {
    let c = &selection.config;
    let p = &selection.policy;
    let d = &p.runtime.instance_binding.portable;
    super::super::consent::payload(
        &p.id,
        p.revision,
        c,
        &p.source_hash,
        "",
        &native::hex(&c.module_digest),
        super::super::consent::Portable {
            language: &d.language,
            tier: &d.tier,
            rules: &d.rules,
            params: &d.params,
            params_hash: &d.params_hash,
        },
    )
}
impl OwnerClient {
    /// Check the exact source consent and current native authority before requesting a source signature.
    /// Policy-wallet confirmation requests no source signature; deployment and funding remain separate gates.
    pub fn activate(
        &self,
        caps: OwnerCapabilities<'_>,
        selection: &OwnerPolicy,
        id: &str,
    ) -> Result<Outcome> {
        let OwnerCapabilities {
            store,
            rpc,
            signer,
            clock,
        } = caps;
        if !crate::host::request::request_id_valid(id)
            || signer.account() != self.session.owner()
            || selection.config.owner != self.session.owner()
            || !selection
                .policy
                .runtime
                .instance_binding
                .portable
                .unresolved
                .is_empty()
        {
            return Err(Error::usage(
                "Select a complete owner policy and activation request ID",
            ));
        }
        self.verify_binding(selection, rpc)?;
        let payload = approval_payload(selection)?;
        let message = super::super::consent::message(&payload)?;
        let identity = intent_hash(&json!({"selection":selection,"message":message}))?;
        let mut record = match store.load::<Activation>(id)? {
            Some(saved)
                if saved.backend == self.session.backend()
                    && saved.origin == self.session.origin()
                    && saved.identity == identity =>
            {
                saved
            }
            Some(_) => {
                return Err(Error::config(
                    "Activation request ID already binds another intent",
                ));
            }
            None => Activation {
                backend: self.session.backend().to_owned(),
                origin: self.session.origin().to_owned(),
                identity,
                signature: None,
                completed: false,
            },
        };
        store.save(id, &record)?;
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Consent {
            required: bool,
            payload: Value,
            message: String,
            method: String,
        }
        let consent: Consent = self.session.owner_request(
            Method::Post,
            "/api/native/approval",
            Some(&json!({"policyId":selection.policy.id})),
            clock()?,
            false,
        )?;
        if consent.payload != payload
            || consent.message != message
            || consent.method != "sep53"
            || (selection.config.route == WalletRoute::PolicyWallet && consent.required)
        {
            return Err(Error::config(
                "Source consent differs from the exact locally selected policy",
            ));
        }
        if selection.config.route == WalletRoute::Native && record.signature.is_none() {
            let account = checked(rpc::get_account(rpc, &selection.config.wallet))?;
            crate::provider::runtime::client::verify_native_members(&account, &selection.config)?;
            checked(
                account.validate_signer_quorum(&[self.session.owner()], account.high_threshold),
            )?;
            let digest = native::signing::signed_message_digest(&message);
            let signature = signer
                .sign_hash(&digest)
                .map_err(|_| Error::config("Owner source signer failed"))?;
            checked(native::signing::verify_digest(
                self.session.owner(),
                &digest,
                &signature,
            ))?;
            record.signature = Some(native::DetachedSignature {
                signer: self.session.owner().to_owned(),
                signature: signature.to_vec(),
            });
            store.save(id, &record)?;
        }
        if let Some(signature) = &record.signature {
            let digest = native::signing::signed_message_digest(&message);
            if signature.signer != self.session.owner() {
                return Err(Error::config("Retained source-consent signer differs"));
            }
            checked(native::signing::verify_digest(
                self.session.owner(),
                &digest,
                &signature.signature,
            ))?;
        }
        let response:Value=self.session.owner_request(Method::Post,"/api/micro/allocation/confirm",Some(&json!({"id":selection.policy.id,"revision":selection.policy.revision,"requestId":id,"stellarSourceApproval":record.signature.iter().collect::<Vec<_>>()})),clock()?,true).map_err(|_|Error::uncertain("Owner activation is uncertain; retain this activation ID and source consent"))?;
        if response["active"] != true {
            return Err(Error::uncertain(
                "Activation has not returned a verified active result",
            ));
        }
        self.verify_binding(selection, rpc)?;
        record.completed = true;
        store.save(id, &record)?;
        Ok(Outcome {
            request_id: id.into(),
            state: "active".into(),
            selection: selection.clone(),
            transactions: vec![],
        })
    }
    /// Export a public JSON projection after strict native validation.
    pub fn export(
        &self,
        store: &Store,
        selection: &OwnerPolicy,
        rpc: &dyn rpc::Rpc,
        activation_id: &str,
        now: u64,
    ) -> Result<Value> {
        let raw = self.export_raw(store, selection, rpc, activation_id, now)?;
        serde_json::from_str(raw.get()).map_err(|_| Error::config("Invalid public descriptor"))
    }
    /// Export only the exact current public installation after the retained activation completed.
    pub fn export_raw(
        &self,
        store: &Store,
        selection: &OwnerPolicy,
        rpc: &dyn rpc::Rpc,
        activation_id: &str,
        now: u64,
    ) -> Result<Box<serde_json::value::RawValue>> {
        let activation: Activation = store
            .load(activation_id)?
            .ok_or_else(|| Error::config("Complete the retained owner activation before export"))?;
        let message = super::super::consent::message(&approval_payload(selection)?)?;
        if !activation.completed
            || activation.backend != self.session.backend()
            || activation.origin != self.session.origin()
            || activation.identity
                != intent_hash(&json!({"selection":selection,"message":message}))?
        {
            return Err(Error::config(
                "Export activation does not bind this exact policy",
            ));
        }
        self.verify_binding(selection, rpc)?;
        if selection.config.route == WalletRoute::Native {
            let signature=activation.signature.as_ref().ok_or_else(||Error::config("Native export requires proven owner source consent. Complete source activation on this device."))?;
            if signature.signer != self.session.owner() {
                return Err(Error::config(
                    "Retained source consent belongs to another owner",
                ));
            }
            checked(native::signing::verify_digest(
                &signature.signer,
                &native::signing::signed_message_digest(&message),
                &signature.signature,
            ))?;
            let current = checked(rpc::get_account(rpc, &selection.config.wallet))?;
            checked(current.validate_authority_signatures(
                &native::signing::signed_message_digest(&message),
                std::slice::from_ref(signature),
            ))?;
        }
        let mut value: Box<serde_json::value::RawValue> = self.session.owner_request(
            Method::Post,
            "/api/native/export",
            Some(&json!({"policyId":selection.policy.id})),
            now,
            false,
        )?;
        let bundle =
            crate::provider::runtime::client::decode_public_bundle(value.get().as_bytes())?;
        let mut selected_config = selection.config.clone();
        if selected_config.route == WalletRoute::Native {
            selected_config.rules = bundle.config.rules.clone();
        }
        if bundle.config != selected_config || bundle.policy_id != selection.policy.id {
            return Err(Error::config(
                "Exported descriptor differs from the selected installation",
            ));
        }
        bundle.verify_optional_import_proof(rpc)?;
        if selection.config.route == WalletRoute::Native {
            let mut public: Value = serde_json::from_str(value.get())
                .map_err(|_| Error::config("Invalid checked public descriptor"))?;
            if public.get("sourceApproval").is_none() {
                public["sourceApproval"] = json!({"revision":selection.policy.revision,"signatures":activation.signature.iter().collect::<Vec<_>>()});
                value = serde_json::value::RawValue::from_string(
                    serde_json::to_string(&public)
                        .map_err(|_| Error::config("Cannot encode public source consent"))?,
                )
                .map_err(|_| Error::config("Cannot encode public source consent"))?;
                crate::provider::runtime::client::decode_public_bundle(value.get().as_bytes())?
                    .verify_import_with(rpc)?;
            }
        }
        Ok(value)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NativeSetupRecord {
    identity: String,
    setup: native::owner::NativeSetup,
    source: native::AccountState,
    created_at: u64,
    signed_xdr: Option<String>,
    signature: Option<Vec<u8>>,
    submitted: bool,
    receipt: Option<rpc::VerifiedReceipt>,
}
/// Configure a fresh Native account through SDK Runtime. No server registration is invented.
/// Original unsigned intent and signed bytes are retained before direct native transmission.
pub fn configure_native(
    runtime: &crate::provider::runtime::Runtime,
    store: &Store,
    request: &crate::provider::runtime::owner::SetupRequest,
    signer: &dyn OwnerSigner,
    clock: &dyn Fn() -> Result<u64>,
) -> Result<Value> {
    request.validate()?;
    roles(&request.owner, &request.agent, &request.server)?;
    if signer.account() != request.owner {
        return Err(Error::config("Native setup owner signer differs"));
    }
    network(runtime.rpc(), &request.network)?;
    let identity = intent_hash(
        &json!({"network":request.network,"owner":request.owner,"agent":request.agent,"server":request.server,"requestId":request.request_id,"fee":request.fee_per_operation}),
    )?;
    let mut record = match store.load::<NativeSetupRecord>(&request.request_id)? {
        Some(record) if record.identity == identity => record,
        Some(_) => {
            return Err(Error::config(
                "Native setup request ID already binds another intent",
            ));
        }
        None => {
            let source = checked(rpc::get_account(runtime.rpc(), &request.owner))?;
            let now = clock()?;
            let setup = checked(native::owner::prepare_native_setup(
                &source,
                &request.agent,
                &request.server,
                &request.request_id,
                &request.network,
                request.fee_per_operation,
                now,
            ))?;
            NativeSetupRecord {
                identity,
                setup,
                source,
                created_at: now,
                signed_xdr: None,
                signature: None,
                submitted: false,
                receipt: None,
            }
        }
    };
    store.save(&request.request_id, &record)?;
    let expected = ExpectedOwnerIntent {
        limits: OwnerLimits {
            network: request.network.clone(),
            owner: request.owner.clone(),
            next_sequence: record
                .source
                .sequence
                .checked_add(1)
                .ok_or_else(|| Error::config("Native source sequence overflow"))?,
            max_fee_stroops: record.setup.fee_stroops,
            valid_until: record.setup.expires_at,
        },
        action: OwnerAction::NativeSetup {
            state: record.source.clone(),
            agent: request.agent.clone(),
            engine: request.server.clone(),
            request_id: request.request_id.clone(),
            fee_per_operation: request.fee_per_operation,
            created_at: record.created_at,
        },
    };
    let packet = OwnerTransaction {
        network: record.setup.network.clone(),
        action: "native_setup".into(),
        transaction_xdr: record.setup.transaction_xdr.clone(),
        transaction_hash: checked(native::unhex(&record.setup.transaction_hash))?,
        expires_at: record.setup.expires_at,
    };
    if record.signed_xdr.is_none() {
        let current = checked(rpc::get_account(runtime.rpc(), &request.owner))?;
        if current != record.source || clock()? < record.created_at {
            return Err(Error::config(
                "Native source or clock changed before setup signing",
            ));
        }
        let proof = checked(owner_intent::validate_native_setup(
            &record.setup,
            &expected,
            clock()?,
        ))?;
        record.signed_xdr = Some(checked(proof.sign_with(clock()?, |hash| {
            let signature = signer.sign_hash(hash)?;
            record.signature = Some(signature.to_vec());
            Ok(signature)
        }))?);
        store.save(&request.request_id, &record)?;
    }
    let signature: [u8; 64] = record
        .signature
        .clone()
        .ok_or_else(|| Error::config("Missing retained Native setup signature"))?
        .try_into()
        .map_err(|_| Error::config("Invalid retained Native signature"))?;
    let retained = checked(owner_intent::validate_owner_transaction(
        &packet,
        &expected,
        record.created_at,
    ))?;
    if checked(retained.sign_with(record.created_at, |_| Ok(signature)))?
        != *record.signed_xdr.as_ref().unwrap()
    {
        return Err(Error::config("Retained Native setup bytes changed"));
    }
    if record.receipt.is_none() {
        record.receipt = checked(rpc::receipt_by_hash(
            runtime.rpc(),
            &request.network,
            &packet.transaction_hash,
        ))?;
    }
    if record.receipt.is_none() {
        if clock()? >= record.setup.expires_at {
            return Err(Error::uncertain(
                "Native setup expired without an available original receipt; do not replace it",
            ));
        }
        if record.submitted
            && checked(rpc::get_account(runtime.rpc(), &request.owner))?.sequence
                != record.source.sequence
        {
            return Err(Error::uncertain(
                "Native setup outcome remains unresolved; retain its original hash",
            ));
        }
        record.submitted = true;
        store.save(&request.request_id, &record)?;
        let receipt = runtime
            .send_and_poll(
                &request.network,
                record.signed_xdr.as_ref().unwrap(),
                crate::provider::runtime::Poll::default(),
            )
            .map_err(|_| {
                Error::uncertain(
                    "Native setup outcome is uncertain; resume the original request ID",
                )
            })?;
        record.receipt = Some(receipt);
        store.save(&request.request_id, &record)?;
    }
    let receipt = record.receipt.as_ref().unwrap();
    checked(rpc::validate_receipt(
        receipt,
        &request.network,
        &packet.transaction_hash,
    ))?;
    if receipt.status != OperationStatus::Confirmed
        || record.signed_xdr.as_deref() != Some(&receipt.envelope_xdr)
    {
        return Err(Error::api(
            409,
            "The original Native setup failed or its receipt envelope differs",
        ));
    }
    let account = checked(rpc::get_account(runtime.rpc(), &request.owner))?;
    checked(account.validate_roles(&request.owner, &request.agent, &request.server))?;
    Ok(
        json!({"state":"configured","requestId":request.request_id,"network":request.network,"wallet":request.owner,"owner":request.owner,"agent":request.agent,"server":request.server,"transactionHash":record.setup.transaction_hash,"ledger":receipt.ledger}),
    )
}

/// Read only original transaction receipts. This path requires neither an owner key nor current source admission.
/// It never signs, prepares a replacement or transmits a transaction.
pub fn status(
    store: &Store,
    runtime: &crate::provider::runtime::Runtime,
    id: &str,
    selected_network: &str,
) -> Result<Value> {
    if !crate::host::request::request_id_valid(id) {
        return Err(Error::usage("Invalid owner workflow request ID"));
    }
    let value: Value = store
        .load(id)?
        .ok_or_else(|| Error::config("No retained owner workflow has this ID"))?;
    let (network_name, packets, completed) = if value.get("selection").is_some() {
        let mut record: Record = serde_json::from_value(value)
            .map_err(|_| Error::config("Invalid retained owner workflow"))?;
        if record.version != 1
            || record.request_id != id
            || record.intent_hash
                != intent_hash(
                    &json!({"selection":record.selection,"work":record.work,"maxFeeStroops":record.max_fee_stroops}),
                )?
        {
            return Err(Error::config("Retained owner workflow identity changed"));
        }
        let network_name = record.selection.config.network.clone();
        if crate::host::routing::normalize(&network_name)?
            != crate::host::routing::normalize(selected_network)?
        {
            return Err(Error::config(
                "Owner workflow network differs from selected rail",
            ));
        }
        network(runtime.rpc(), &network_name)?;
        let mut results = vec![];
        for step in &mut record.steps {
            let hash = checked(native::unhex(&step.packet.transaction_hash))?;
            if let (Some(signed), Some(signature)) = (&step.signed_xdr, &step.signature) {
                verify_original_signature(
                    &network_name,
                    &record.selection.config.owner,
                    signed,
                    signature,
                    &hash,
                )?;
            }
            if let Some(receipt) =
                checked(rpc::receipt_by_hash(runtime.rpc(), &network_name, &hash))?
            {
                step.receipt = Some(receipt);
            }
            if let Some(receipt) = &step.receipt {
                checked(rpc::validate_receipt(receipt, &network_name, &hash))?;
                if step.signed_xdr.as_deref() != Some(&receipt.envelope_xdr) {
                    return Err(Error::config("Original owner receipt envelope differs"));
                }
            }
            results.push(json!({"action":step.packet.action,"transactionHash":step.packet.transaction_hash,"status":step.receipt.as_ref().map(|r|&r.status).unwrap_or(&OperationStatus::SubmissionUnknown),"ledger":step.receipt.as_ref().map(|r|r.ledger)}));
        }
        store.save(id, &record)?;
        (network_name, results, record.complete)
    } else {
        let mut record: NativeSetupRecord = serde_json::from_value(value)
            .map_err(|_| Error::config("No native transaction is retained under this ID"))?;
        if record.setup.request_id != id {
            return Err(Error::config("Native setup request ID changed"));
        }
        checked(native::owner::validate_native_setup(&record.setup))?;
        let network_name = record.setup.network.clone();
        if crate::host::routing::normalize(&network_name)?
            != crate::host::routing::normalize(selected_network)?
        {
            return Err(Error::config(
                "Native setup network differs from selected rail",
            ));
        }
        network(runtime.rpc(), &network_name)?;
        let hash = checked(native::unhex(&record.setup.transaction_hash))?;
        if let (Some(signed), Some(signature)) = (&record.signed_xdr, &record.signature) {
            verify_original_signature(
                &network_name,
                &record.setup.owner,
                signed,
                signature,
                &hash,
            )?;
        }
        if let Some(receipt) = checked(rpc::receipt_by_hash(runtime.rpc(), &network_name, &hash))? {
            record.receipt = Some(receipt);
        }
        if let Some(receipt) = &record.receipt {
            checked(rpc::validate_receipt(receipt, &network_name, &hash))?;
            if record.signed_xdr.as_deref() != Some(&receipt.envelope_xdr) {
                return Err(Error::config("Original Native receipt envelope differs"));
            }
        }
        store.save(id, &record)?;
        let confirmed = record
            .receipt
            .as_ref()
            .is_some_and(|r| r.status == OperationStatus::Confirmed);
        let results = vec![
            json!({"action":"native_setup","transactionHash":record.setup.transaction_hash,"status":record.receipt.as_ref().map(|r|&r.status).unwrap_or(&OperationStatus::SubmissionUnknown),"ledger":record.receipt.as_ref().map(|r|r.ledger)}),
        ];
        (network_name, results, confirmed)
    };
    Ok(json!({"requestId":id,"network":network_name,"completed":completed,"transactions":packets}))
}
fn verify_original_signature(
    network: &str,
    owner: &str,
    signed: &str,
    signature: &[u8],
    hash: &[u8; 32],
) -> Result<()> {
    if checked(rpc::signed_transaction_hash(network, signed))? != *hash {
        return Err(Error::config("Original owner transaction hash changed"));
    }
    checked(native::signing::verify_digest(owner, hash, signature))
}
