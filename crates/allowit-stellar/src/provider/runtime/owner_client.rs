//! Owner HTTP authentication and portable generation. This workflow grants no spending authority.
pub mod workflow;
use crate::host::error::{Error, Result};
use crate::{self as native, PolicyParams, PolicyTier};
use allowit_core::transport::http::Method;
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const SOURCE_PROFILE: &str = "allowit-transfer-v1";
const OPERATION: &str = "allowit::transfer";
const LANGUAGE: &str = "allowit-portable-v1";

/// The caller owns this owner key. It is independent of any selected agent key.
pub trait OwnerSigner {
    fn account(&self) -> &str;
    fn sign_hash(&self, digest: &[u8; 32]) -> native::Result<[u8; 64]>;
}

use crate::host::generation::GeneratedDraft;
pub use crate::host::generation::{GenerateRequest, Target};

pub struct OwnerClient {
    session: crate::host::owner_session::Client,
    pub(super) authority: Option<crate::host::config::ServerAuthority>,
}
#[derive(Deserialize)]
struct Discovery {
    wallets: Vec<Advertisement>,
    operations: Vec<OperationAdvertisement>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Advertisement {
    kind: String,
    profile: String,
    source_profiles: Vec<String>,
    networks: Vec<String>,
    operations: Vec<String>,
    capabilities: GenerateCapability,
}
#[derive(Deserialize)]
struct GenerateCapability {
    generate: bool,
}
#[derive(Deserialize)]
struct OperationAdvertisement {
    function: String,
}
#[derive(Deserialize)]
struct Templates {
    templates: Vec<Template>,
}
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Template {
    network: String,
    profiles: Vec<String>,
    asset: String,
    asset_symbol: String,
    asset_issuer: Option<String>,
    #[serde(rename = "maxFeeUnits")]
    max_fee_stroops: u32,
}
#[derive(Deserialize)]
struct Installations {
    installations: Vec<Installation>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Installation {
    policy_id: String,
    config: native::WalletConfig,
    profile: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Generated {
    policies: Vec<Box<serde_json::value::RawValue>>,
    selected_id: String,
}

/// Only public generation fields are returned. Extra server state and credentials are never copied.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeneratedPolicy {
    pub id: String,
    pub revision: u32,
    pub network: String,
    pub language: String,
    pub original_intent: String,
    pub title: String,
    pub explanation: String,
    pub code: String,
    pub source_hash: String,
    pub ir_hash: String,
    pub status: String,
    pub token: String,
    pub mint: String,
    pub runtime: PublicRuntime,
    /// The wallet kind that the server bound to this policy. A server that names none omits it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wallet_kind: Option<allowit_core::vendor::kinds::WalletKind>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicRuntime {
    pub source_profile: String,
    pub wallet: WalletSelection,
    pub operation: String,
    pub instance_binding: PolicyBinding,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletSelection {
    pub kind: String,
    pub profile: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyBinding {
    pub profile: String,
    pub language: String,
    pub deployment_id: String,
    pub policy_instance: String,
    pub module_digest: String,
    pub wallet: String,
    pub route: String,
    pub asset: String,
    pub asset_symbol: String,
    pub asset_issuer: Option<String>,
    #[serde(rename = "maxFeeUnits")]
    pub max_fee_stroops: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier: Option<PolicyTier>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<bool>,
    pub portable: PortableDraft,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PortableDraft {
    pub language: String,
    pub source_hash: String,
    pub tier: String,
    #[serde(default)]
    pub rules: Vec<String>,
    pub params: PolicyParams,
    pub params_hash: String,
    pub asset: PortableAsset,
    pub unresolved: Vec<String>,
    pub build: BuildReport,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub kinds: std::collections::BTreeMap<String, String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableAsset {
    pub symbol: String,
    pub address: String,
    pub decimals: u32,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BuildReport {
    pub prefix: Vec<String>,
    pub writes_state: bool,
    pub library_revision: String,
    pub attempts: usize,
}

fn lower_hash(value: &str) -> Result<()> {
    if value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(())
    } else {
        Err(Error::config("Invalid lowercase Stellar identity"))
    }
}
impl OwnerClient {
    pub fn new(backend: &str, origin: &str, owner: &str) -> Result<Self> {
        native::signing::canonical_account_key(owner)
            .map_err(|_| Error::config("Select a canonical Stellar G owner account"))?;
        Ok(Self {
            session: crate::host::owner_session::Client::new(backend, origin, owner)?,
            authority: None,
        })
    }
    pub fn with_authority(
        authority: &crate::host::config::ServerAuthority,
        origin: &str,
        owner: &str,
    ) -> Result<Self> {
        let mut client = Self::new(authority.origin(), origin, owner)?;
        client.authority = Some(authority.clone());
        Ok(client)
    }
    pub fn authenticate(&mut self, signer: &dyn OwnerSigner, now: u64) -> Result<()> {
        if signer.account() != self.session.owner() {
            return Err(Error::config(
                "Owner signer differs from the selected account",
            ));
        }
        let owner = self.session.owner().to_owned();
        let origin = self.session.origin().to_owned();
        self.session.authenticate("wallet", now, |challenge| {
            let (issued, expiration) = native::signing::sign_in_message_times(
                &challenge.message,
                &owner,
                &origin,
                &challenge.id,
            )
            .map_err(crate::provider::failure)?;
            let issued = crate::host::owner_session::timestamp(issued)?;
            let expiry = crate::host::owner_session::timestamp(&challenge.expires_at)?;
            if expiration != challenge.expires_at
                || expiry.checked_sub(issued) != Some(300)
                || issued > now.saturating_add(30)
                || now.saturating_sub(issued) > 300
            {
                return Err(Error::config(
                    "Owner sign-in challenge is invalid or expired",
                ));
            }
            let digest = native::signing::signed_message_digest(&challenge.message);
            let signature = signer
                .sign_hash(&digest)
                .map_err(|_| Error::config("Owner signing capability failed"))?;
            native::signing::verify_digest(&owner, &digest, &signature)
                .map_err(|_| Error::config("Owner signer returned an invalid signature"))?;
            Ok(STANDARD.encode(signature))
        })
    }
    pub fn generate<'a>(
        &self,
        request: impl Into<std::borrow::Cow<'a, GenerateRequest>>,
        now: u64,
    ) -> Result<GeneratedPolicy> {
        let request = request.into();
        request.validate_with_network(|network| crate::host::routing::info(network).map(|_| ()))?;
        let discovery: Discovery =
            self.session
                .owner_request(Method::Get, "/api/micro/runtime", None, now, false)?;
        let candidates: Vec<_> = discovery
            .wallets
            .iter()
            .filter(|w| {
                w.profile == request.profile
                    && w.capabilities.generate
                    && w.source_profiles.iter().any(|s| s == SOURCE_PROFILE)
                    && w.operations.iter().any(|s| s == OPERATION)
            })
            .collect();
        if candidates.len() != 1 || !discovery.operations.iter().any(|o| o.function == OPERATION) {
            return Err(Error::config(
                "The selected Stellar generation profile is not advertised",
            ));
        }
        let wallet = candidates[0];
        let canonical = crate::host::routing::normalize(&request.network)?;
        let networks: Vec<_> = wallet
            .networks
            .iter()
            .filter(|n| crate::host::routing::normalize(n).ok() == Some(canonical))
            .collect();
        if networks.len() != 1 {
            return Err(Error::config(
                "The selected network is not unambiguously advertised",
            ));
        }
        let network = networks[0];
        let mut selected_template = None;
        let mut selected_config = None;
        let installation = match &request.target {
            Target::NewWallet => {
                if wallet.kind != "contract-wallet" {
                    return Err(Error::usage(
                        "A new wallet requires an advertised contract-wallet template",
                    ));
                }
                let templates: Templates = self.session.owner_request(
                    Method::Post,
                    "/api/native/templates",
                    Some(&json!({})),
                    now,
                    false,
                )?;
                let matching: Vec<_> = templates
                    .templates
                    .into_iter()
                    .filter(|t| t.network == *network && t.profiles.contains(&request.profile))
                    .collect();
                if matching.len() != 1 {
                    return Err(Error::config(
                        "No matching new-wallet template is configured",
                    ));
                }
                let template = matching.into_iter().next().expect("one matching template");
                let asset = native::asset_from_identity(
                    &template.asset_symbol,
                    template.asset_issuer.as_deref(),
                )
                .map_err(|_| Error::config("Invalid advertised template asset"))?;
                if native::sac_address(network, &asset).map_err(crate::provider::failure)?
                    != template.asset
                    || !(super::super::server_owner::fee_bounds().minimum
                        ..=u64::from(native::max_fee_ceiling(&native::WalletRoute::PolicyWallet)))
                        .contains(&u64::from(template.max_fee_stroops))
                {
                    return Err(Error::config("Advertised template asset or fee is invalid"));
                }
                selected_template = Some(template);
                String::new()
            }
            Target::Installation(id) => {
                let all: Installations = self.session.owner_request(
                    Method::Get,
                    "/api/native/policies",
                    None,
                    now,
                    false,
                )?;
                let matching: Vec<_> = all
                    .installations
                    .iter()
                    .filter(|i| {
                        i.policy_id == *id
                            && i.profile == request.profile
                            && i.config.network == *network
                            && i.config.owner == self.session.owner()
                            && native::hex(&i.config.policy_instance) == *id
                    })
                    .collect();
                if matching.len() != 1 {
                    return Err(Error::config(
                        "The selected installation does not belong to this owner, profile and network",
                    ));
                }
                let config = matching[0].config.clone();
                let expected_kind = match config.route {
                    native::WalletRoute::Native => "owner-wallet",
                    native::WalletRoute::PolicyWallet => "contract-wallet",
                    _ => {
                        return Err(Error::config(
                            "Retired installations cannot generate new policy",
                        ));
                    }
                };
                if expected_kind != wallet.kind
                    || config.language != native::PolicyLanguage::Portable
                {
                    return Err(Error::config(
                        "The installation has a different custody profile",
                    ));
                }
                native::validate_config(&config).map_err(|_| {
                    Error::config("The selected installation has invalid portable configuration")
                })?;
                selected_config = Some(config);
                id.clone()
            }
        };
        let mut body = json!({"prompt":request.prompt,"network":network,"runtime":{"sourceProfile":SOURCE_PROFILE,"wallet":{"kind":wallet.kind,"profile":request.profile}},"operation":{"function":OPERATION},"installationId":installation});
        // The owner's choice. The server binds it or refuses with a typed error; without one it
        // proposes a kind.
        if let Some(kind) = request.wallet_kind {
            body[GeneratedDraft::WALLET_KIND_KEY] = json!(kind);
        }
        let result: Generated = self.session.owner_request(
            Method::Post,
            "/api/micro/generate",
            Some(&body),
            now,
            true,
        )?;
        let policy = selected_policy(result)?;
        if policy.revision != 1 {
            return Err(Error::uncertain(
                "Generation returned another revision than the first; inspect the owner workspace before retrying",
            ));
        }
        validate_generated(&policy, &request, network, &wallet.kind).map_err(|_|Error::uncertain("Generated policy failed portable identity validation; inspect the owner workspace before retrying"))?;
        if let (Some(chosen), Some(bound)) = (request.wallet_kind, policy.wallet_kind)
            && chosen != bound
        {
            return Err(Error::uncertain(
                "Generation bound another wallet kind than the selected one; inspect the owner workspace before retrying",
            ));
        }
        let binding = &policy.runtime.instance_binding;
        if let Some(template) = selected_template
            && (binding.asset != template.asset
                || binding.asset_symbol != template.asset_symbol
                || binding.asset_issuer != template.asset_issuer
                || binding.max_fee_stroops != template.max_fee_stroops)
        {
            return Err(Error::uncertain(
                "Generation changed the selected template asset or fee",
            ));
        }
        if let Some(config) = selected_config
            && (binding.wallet != config.wallet
                || binding.route
                    != serde_json::to_value(&config.route)
                        .map_err(|_| Error::config("Cannot encode native custody route"))?
                        .as_str()
                        .unwrap_or("")
                || binding.asset != config.asset
                || binding.asset_symbol != config.asset_symbol
                || binding.asset_issuer != config.asset_issuer
                || binding.max_fee_stroops != config.max_fee_stroops
                || (config.route == native::WalletRoute::PolicyWallet
                    && (binding.module_digest != native::hex(&config.module_digest)
                        || binding.tier != config.tier
                        || policy.code != config.policy_source
                        || binding.portable.params != config.params)))
        {
            return Err(Error::uncertain(
                "Generation changed the explicitly selected installation",
            ));
        }
        Ok(policy)
    }
}
/// The selected policy of a workspace reply, with only its public generation fields.
fn selected_policy(result: Generated) -> Result<GeneratedPolicy> {
    if result.policies.len() > 30 || result.selected_id.is_empty() {
        return Err(Error::uncertain(
            "Generation returned an invalid workspace identity",
        ));
    }
    #[derive(Deserialize)]
    struct Identity {
        id: String,
    }
    let mut selected = None;
    for raw in result.policies {
        let id: Identity = serde_json::from_str(raw.get())
            .map_err(|_| Error::uncertain("Generation returned an invalid policy identity"))?;
        if id.id == result.selected_id {
            if selected.is_some() {
                return Err(Error::uncertain(
                    "Generation returned a duplicate selected identity",
                ));
            }
            selected = Some(
                serde_json::from_str::<GeneratedPolicy>(raw.get()).map_err(|_| {
                    Error::uncertain("Generation returned invalid portable policy fields")
                })?,
            );
        }
    }
    selected.ok_or_else(|| Error::uncertain("Generation omitted the selected policy"))
}
/// The request that a draft itself states: its intent, network, profile and wallet target.
fn request_of(policy: &GeneratedPolicy) -> GenerateRequest {
    let binding = &policy.runtime.instance_binding;
    GenerateRequest {
        prompt: policy.original_intent.clone(),
        network: policy.network.clone(),
        profile: policy.runtime.wallet.profile.clone(),
        target: if binding.template == Some(true) {
            Target::NewWallet
        } else {
            Target::Installation(binding.deployment_id.clone())
        },
        wallet_kind: None,
    }
}
impl OwnerClient {
    /// The next revision of an unsigned draft. It keeps the draft's identity, network, wallet
    /// binding and asset; `source_fixed` also keeps the source bytes.
    fn revised(
        &self,
        draft: &GeneratedPolicy,
        path: &str,
        body: Value,
        source_fixed: bool,
        now: u64,
    ) -> Result<GeneratedPolicy> {
        validate_generated(
            draft,
            &request_of(draft),
            &draft.network,
            &draft.runtime.wallet.kind,
        )
        .map_err(|_| Error::usage("The draft is not a valid owner policy draft"))?;
        if draft.status != "draft" {
            return Err(Error::usage("Only an unsigned draft can be revised"));
        }
        let result: Generated =
            self.session
                .owner_request(Method::Post, path, Some(&body), now, true)?;
        let next = selected_policy(result)?;
        let changed = || {
            Error::uncertain(
                "The revision changed the draft's identity or wallet binding; inspect the owner workspace before retrying",
            )
        };
        validate_generated(
            &next,
            &request_of(&next),
            &draft.network,
            &draft.runtime.wallet.kind,
        )
        .map_err(|_| changed())?;
        let (old, new) = (
            &draft.runtime.instance_binding,
            &next.runtime.instance_binding,
        );
        if next.id != draft.id
            || draft.revision.checked_add(1) != Some(next.revision)
            || next.wallet_kind != draft.wallet_kind
            || next.runtime.wallet.profile != draft.runtime.wallet.profile
            || new.deployment_id != old.deployment_id
            || new.policy_instance != old.policy_instance
            || new.wallet != old.wallet
            || new.route != old.route
            || new.asset != old.asset
            || new.asset_symbol != old.asset_symbol
            || new.asset_issuer != old.asset_issuer
            || new.max_fee_stroops != old.max_fee_stroops
            || new.template != old.template
            || (source_fixed && (next.code != draft.code || new.tier != old.tier))
        {
            return Err(changed());
        }
        Ok(next)
    }
    /// Change typed params of an unsigned draft. The server checks each value against the
    /// param's type and range; the reply holds exactly the values that were sent.
    pub fn edit_params(
        &self,
        draft: &GeneratedPolicy,
        changes: &std::collections::BTreeMap<String, allowit_core::policy::PolicyValue>,
        now: u64,
    ) -> Result<GeneratedPolicy> {
        if changes.is_empty() || changes.len() > 64 {
            return Err(Error::usage("Change one to 64 params"));
        }
        let mut sent = std::collections::BTreeMap::new();
        for (key, value) in changes {
            if !draft
                .runtime
                .instance_binding
                .portable
                .params
                .0
                .contains_key(key)
            {
                return Err(Error::usage(format!(
                    "This policy reads no param named {key}"
                )));
            }
            sent.insert(
                key.clone(),
                native::PolicyValue::from_core(value).map_err(Error::usage)?,
            );
        }
        let next = self.revised(
            draft,
            "/api/micro/params",
            json!({"id":draft.id,"revision":draft.revision,"params":changes}),
            true,
            now,
        )?;
        let saved = &next.runtime.instance_binding.portable.params.0;
        let kept = &draft.runtime.instance_binding.portable.params.0;
        if saved.len() != kept.len()
            || saved
                .iter()
                .any(|(key, value)| sent.get(key).or_else(|| kept.get(key)) != Some(value))
        {
            return Err(Error::uncertain(
                "The saved params differ from the typed edit; inspect the owner workspace before retrying",
            ));
        }
        Ok(next)
    }
    /// Revise an unsigned draft in the owner's words. The source can change; the wallet
    /// binding and the asset stay.
    pub fn revise(
        &self,
        draft: &GeneratedPolicy,
        instruction: &str,
        now: u64,
    ) -> Result<GeneratedPolicy> {
        if !(5..=3000).contains(&instruction.len()) {
            return Err(Error::usage("Describe the change in 5 to 3000 characters"));
        }
        self.revised(
            draft,
            "/api/micro/revise",
            json!({"id":draft.id,"revision":draft.revision,"prompt":instruction}),
            false,
            now,
        )
    }
}
fn validate_generated(
    policy: &GeneratedPolicy,
    request: &GenerateRequest,
    network: &str,
    kind: &str,
) -> Result<()> {
    let b = &policy.runtime.instance_binding;
    let d = &b.portable;
    let shape = crate::host::authoring::check(&policy.code).map_err(|_| {
        Error::uncertain("Returned policy source is outside the portable vocabulary")
    })?;
    if !crate::host::request::request_id_valid(&policy.id)
        || policy.revision == 0
        || policy.network != network
        || policy.language != LANGUAGE
        || policy.original_intent != request.prompt
        || !policy.ir_hash.is_empty()
        || policy.status != "draft"
        || policy.source_hash != allowit_core::digest(policy.code.as_bytes())
        || policy.runtime.source_profile != SOURCE_PROFILE
        || policy.runtime.wallet.kind != kind
        || policy.runtime.wallet.profile != request.profile
        || policy.runtime.operation != OPERATION
        || b.profile != native::PROFILE
        || b.language != LANGUAGE
        || b.asset != policy.mint
        || b.asset_symbol != policy.token
        || d.language != LANGUAGE
        || d.source_hash != policy.source_hash
        || d.params_hash != crate::host::authoring::canonical_digest(&d.params)?
        || d.asset.address != policy.mint
        || d.asset.symbol != policy.token
        || d.asset.decimals != 7
        || d.build.prefix != shape.prefix
        || d.build.writes_state != shape.writes_state
        || d.build.attempts == 0
        || d.build.attempts > 3
    {
        return Err(Error::uncertain(
            "Returned policy changed the exact owner intent or portable binding",
        ));
    }
    lower_hash(&b.policy_instance)?;
    lower_hash(&d.params_hash)?;
    if d.build.library_revision.len() != 40
        || !d
            .build
            .library_revision
            .bytes()
            .all(|v| v.is_ascii_hexdigit())
    {
        return Err(Error::uncertain("Invalid reported policy library revision"));
    }
    let tier = match d.tier.as_str() {
        "standard" => PolicyTier::Common,
        "custom" => PolicyTier::Custom,
        _ => return Err(Error::uncertain("Invalid returned portable tier")),
    };
    if (d.tier == "standard" && (!shape.canonical_only || d.rules != shape.prefix))
        || (d.tier == "custom" && !d.rules.is_empty())
    {
        return Err(Error::uncertain(
            "Returned rules differ from the portable source tier",
        ));
    }
    d.params
        .check(tier)
        .map_err(|_| Error::uncertain("Invalid returned typed params"))?;
    native::policy::parse_rules(&d.rules)
        .map_err(|_| Error::uncertain("Invalid returned canonical rules"))?;
    let asset = native::asset_from_identity(&b.asset_symbol, b.asset_issuer.as_deref())
        .map_err(crate::provider::failure)?;
    if native::sac_address(network, &asset).map_err(crate::provider::failure)? != b.asset
        || !(super::super::server_owner::fee_bounds().minimum
            ..=u64::from(native::max_fee_ceiling(&if kind == "contract-wallet" {
                native::WalletRoute::PolicyWallet
            } else {
                native::WalletRoute::Native
            })))
            .contains(&u64::from(b.max_fee_stroops))
    {
        return Err(Error::uncertain(
            "Returned policy asset or fee binding differs",
        ));
    }
    if kind == "owner-wallet" {
        let identity = crate::host::authoring::portable_identity(
            &d.language,
            &d.tier,
            &d.rules,
            &d.source_hash,
            &d.params_hash,
        )?;
        if b.route != "native"
            || b.tier.is_some()
            || !shape.canonical_only
            || b.module_digest != identity
        {
            return Err(Error::uncertain("Returned native policy identity differs"));
        }
    } else {
        let tier = b
            .tier
            .ok_or_else(|| Error::uncertain("Missing returned contract policy tier"))?;
        let profile_fits = match tier {
            PolicyTier::Custom => request.profile == "allowit-custom-wallet-v1",
            _ => request.profile == "allowit-policy-wallet-v1" && d.tier == "standard",
        };
        if b.route != "policyWallet"
            || !profile_fits
            || b.deployment_id != b.policy_instance
            || (tier.standard() && shape.writes_state)
        {
            return Err(Error::uncertain("Returned contract policy tier differs"));
        }
    }
    match &request.target {
        Target::NewWallet
            if b.template == Some(true)
                && b.route == "policyWallet"
                && b.wallet.is_empty()
                && b.module_digest.is_empty()
                && b.tier.is_some() => {}
        Target::Installation(id)
            if b.template != Some(true) && b.deployment_id == *id && !b.wallet.is_empty() =>
        {
            lower_hash(&b.module_digest)?;
            native::address(&b.wallet).map_err(crate::provider::failure)?;
        }
        _ => {
            return Err(Error::uncertain(
                "Generation changed existing-versus-new wallet selection",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
