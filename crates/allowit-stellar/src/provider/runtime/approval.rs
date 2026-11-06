//! Public continuation for an existing owner-configured Native Stellar policy.
//! Backs the hidden `allowit wallet approve`: prints a source approval link
//! and moves no funds.
use crate::host::error::{Error, Result};
use allowit_policy_sdk::client::store::Store;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
/// Admit the Native approval-link network before reading caller input.
pub fn check_network(network: &str) -> Result<()> {
    if network != "stellar:testnet" {
        return Err(Error::unsupported(
            "Native Stellar approval links support Testnet only",
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyBinding {
    pub wallet: String,
    pub route: String,
    pub policy_instance: String,
    pub module_digest: String,
    pub asset: String,
    pub asset_symbol: String,
    pub asset_issuer: Option<String>,
    pub max_fee_stroops: u32,
    pub deployment_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params_hash: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApprovalIntent {
    pub version: u32,
    pub profile: String,
    pub request_id: String,
    pub network: String,
    pub owner: String,
    pub policy_id: String,
    pub revision: u32,
    pub source: String,
    pub source_hash: String,
    pub ir_hash: String,
    pub binding: PolicyBinding,
    pub intent_digest: String,
}
fn hash(value: impl AsRef<[u8]>) -> String {
    allowit_policy_sdk::digest(value.as_ref())
}
pub fn intent_digest(v: &ApprovalIntent) -> Result<String> {
    let binding = serde_json_canonicalizer::to_vec(&v.binding)
        .map_err(|_| Error::config("Invalid Stellar policy binding"))?;
    Ok(hash(
        serde_json::to_vec(&serde_json::json!([
            v.profile,
            v.request_id,
            v.network,
            v.owner,
            v.policy_id,
            v.revision,
            v.source_hash,
            v.ir_hash,
            hash(binding)
        ]))
        .map_err(|_| Error::config("Cannot encode Stellar approval identity"))?,
    ))
}
fn lower_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn validate_portable(v: &ApprovalIntent) -> Result<()> {
    use allowit_stellar_wallet::{PolicyParams, PolicyTier};
    let b = &v.binding;
    let (Some(language), Some(tier), Some(rules), Some(params), Some(params_hash)) =
        (&b.language, &b.tier, &b.rules, &b.params, &b.params_hash)
    else {
        return Err(Error::config(
            "Portable approval is missing source or params identity",
        ));
    };
    if language != "allowit-portable-v1" || !lower_hash(params_hash) {
        return Err(Error::config(
            "Invalid portable approval language or params hash",
        ));
    }
    let shape = crate::host::authoring::check(&v.source)?;
    let policy_tier = match tier.as_str() {
        "standard" if *rules == shape.prefix => PolicyTier::Common,
        "custom" if rules.is_empty() => PolicyTier::Custom,
        _ => {
            return Err(Error::config(
                "Portable approval tier and rules differ from source",
            ));
        }
    };
    let typed: PolicyParams = serde_json::from_value(params.clone())
        .map_err(|_| Error::config("Invalid typed portable params"))?;
    typed.check(policy_tier).map_err(Error::config)?;
    let canonical = crate::host::authoring::canonical_digest(params)?;
    let canonical_identity = crate::host::authoring::portable_identity(
        language,
        tier,
        rules,
        &v.source_hash,
        params_hash,
    )?;
    if canonical != *params_hash || canonical_identity != b.module_digest {
        return Err(Error::config(
            "Portable source, params or module identity changed",
        ));
    }
    Ok(())
}
pub fn validate(v: &ApprovalIntent) -> Result<()> {
    let b = &v.binding;
    if !matches!(
        (v.version, v.profile.as_str()),
        (1, "allowit-stellar-approval-v1") | (2, "allowit-stellar-approval-v2")
    ) || v.network != "stellar:testnet"
        || !crate::host::request::request_id_valid(&v.request_id)
        || v.policy_id.is_empty()
        || v.policy_id.len() > 128
        || !v
            .policy_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
        || v.revision == 0
        || v.source.len() > 32_768
        || v.source_hash != hash(v.source.as_bytes())
        || (v.version == 1 && !lower_hash(&v.ir_hash))
        || (v.version == 2 && !v.ir_hash.is_empty())
        || b.route != "native"
        || b.asset_symbol.is_empty()
        || b.asset_symbol.len() > 12
        || !b.asset_symbol.bytes().all(|b| b.is_ascii_alphanumeric())
        || u64::from(b.max_fee_stroops) < super::super::server_owner::fee_bounds().minimum
        || b.max_fee_stroops
            > allowit_stellar_wallet::max_fee_ceiling(&allowit_stellar_wallet::WalletRoute::Native)
    {
        return Err(Error::config("Invalid Native Stellar policy approval"));
    }
    if v.version == 1 {
        if b.language.is_some()
            || b.tier.is_some()
            || b.rules.is_some()
            || b.params.is_some()
            || b.params_hash.is_some()
        {
            return Err(Error::config("Historical V1 approval fields changed"));
        }
    } else {
        validate_portable(v)?;
    }
    for a in [&v.owner, &b.wallet] {
        allowit_stellar_wallet::account_key(a).map_err(Error::config)?;
    }
    if let Some(a) = &b.asset_issuer {
        allowit_stellar_wallet::account_key(a).map_err(Error::config)?;
    }
    if !b.asset.starts_with('C') {
        return Err(Error::config(
            "The installed Stellar asset must be its SAC address",
        ));
    }
    allowit_stellar_wallet::address(&b.asset).map_err(Error::config)?;
    let asset =
        allowit_stellar_wallet::asset_from_identity(&b.asset_symbol, b.asset_issuer.as_deref())
            .map_err(Error::config)?;
    if b.asset != allowit_stellar_wallet::sac_address(&v.network, &asset).map_err(Error::config)? {
        return Err(Error::config(
            "The Stellar SAC differs from its asset code, issuer or network",
        ));
    }
    for h in [&b.policy_instance, &b.module_digest] {
        allowit_stellar_wallet::unhex::<32>(h).map_err(Error::config)?;
        if !h
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::config(
                "Stellar policy identities must use lowercase hexadecimal",
            ));
        }
    }
    if let Some(h) = &b.deployment_id {
        allowit_stellar_wallet::unhex::<32>(h).map_err(Error::config)?;
        if !h
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::config(
                "Stellar deployment identity must use lowercase hexadecimal",
            ));
        }
    }
    if intent_digest(v)? != v.intent_digest {
        return Err(Error::config("The Stellar policy approval changed"));
    }
    Ok(())
}
pub fn signing_url(origin: &str, v: &ApprovalIntent) -> Result<String> {
    validate(v)?;
    if v.version != 2 {
        return Err(Error::config(
            "Historical V1 approval is read-only; prepare a portable V2 approval",
        ));
    }
    let origin = crate::host::config::parse_origin(origin)?;
    let bytes =
        serde_json::to_vec(v).map_err(|_| Error::config("Cannot encode Stellar approval"))?;
    let encoded = URL_SAFE_NO_PAD.encode(bytes);
    if encoded.len() > 65_000 {
        return Err(Error::config("Stellar approval exceeds browser bounds"));
    }
    Ok(format!(
        "{origin}/?chain=stellar&network=stellar%3Atestnet#allowit-stellar-approval={encoded}"
    ))
}
/// Select only public approval terms from a stored policy export. Secret or unrelated fields are not copied.
pub fn approval_for_policy(
    policy: &serde_json::Value,
    owner: &str,
    id: &str,
) -> Result<ApprovalIntent> {
    let text = |k| {
        policy[k]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| Error::config("The public Stellar policy is missing source identity"))
    };
    if policy["network"] != "stellar:testnet"
        || policy["runtime"]["wallet"]["profile"] != "allowit-stellar-native-v1"
    {
        return Err(Error::config(
            "Use an existing installed Native Stellar Testnet policy",
        ));
    }
    let raw = &policy["runtime"]["instanceBinding"];
    let optional = |name| match &raw[name] {
        serde_json::Value::Null => Ok(None),
        serde_json::Value::String(value) => Ok(Some(value.clone())),
        _ => Err(Error::config(
            "The Stellar binding contains an invalid optional identity",
        )),
    };
    let portable = &raw["portable"];
    if policy["language"] != "allowit-portable-v1"
        || raw["language"] != "allowit-portable-v1"
        || portable["language"] != "allowit-portable-v1"
        || portable["sourceHash"] != policy["sourceHash"]
        || !portable["unresolved"].as_array().is_some_and(Vec::is_empty)
    {
        return Err(Error::config(
            "Use a resolved portable Stellar policy for fresh approval",
        ));
    }
    let binding = PolicyBinding {
        wallet: raw["wallet"].as_str().unwrap_or("").into(),
        route: raw["route"].as_str().unwrap_or("").into(),
        policy_instance: raw["policyInstance"].as_str().unwrap_or("").into(),
        module_digest: raw["moduleDigest"].as_str().unwrap_or("").into(),
        asset: text("mint")?,
        asset_symbol: text("token")?,
        asset_issuer: optional("assetIssuer")?,
        max_fee_stroops: raw["maxFeeStroops"]
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .unwrap_or(0),
        deployment_id: optional("deploymentId")?,
        language: portable["language"].as_str().map(str::to_owned),
        tier: portable["tier"].as_str().map(str::to_owned),
        rules: serde_json::from_value(
            portable
                .get("rules")
                .cloned()
                .unwrap_or_else(|| serde_json::json!([])),
        )
        .ok(),
        params: portable.get("params").cloned(),
        params_hash: portable["paramsHash"].as_str().map(str::to_owned),
    };
    if raw["asset"] != binding.asset || raw["assetSymbol"] != binding.asset_symbol {
        return Err(Error::config(
            "The policy asset differs from its installation",
        ));
    }
    let mut intent = ApprovalIntent {
        version: 2,
        profile: "allowit-stellar-approval-v2".into(),
        request_id: id.into(),
        network: "stellar:testnet".into(),
        owner: owner.into(),
        policy_id: text("id")?,
        revision: policy["revision"]
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .unwrap_or(0),
        source: text("code")?,
        source_hash: text("sourceHash")?,
        ir_hash: policy.get("irHash").map_or(Ok(String::new()), |value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| Error::config("Invalid policy IR identity"))
        })?,
        binding,
        intent_digest: String::new(),
    };
    intent.intent_digest = intent_digest(&intent)?;
    validate(&intent)?;
    Ok(intent)
}
/// Retain the exact public approval intent before returning it to the calling UI.
pub fn prepare(
    store: &Store,
    policy: &serde_json::Value,
    owner: &str,
    id: &str,
    network: &str,
) -> Result<ApprovalIntent> {
    if network != "stellar:testnet" {
        return Err(Error::unsupported(
            "Native Stellar approval links support Testnet only",
        ));
    }
    let intent = approval_for_policy(policy, owner, id)?;
    if store
        .load::<ApprovalIntent>(id)?
        .as_ref()
        .is_some_and(|old| old != &intent)
    {
        return Err(Error::config(
            "This approval request ID already binds another policy",
        ));
    }
    store.save(id, &intent)?;
    Ok(intent)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> serde_json::Value {
        serde_json::from_str(include_str!(
            "../../../tests/fixtures/provider/stellar-approval.json"
        ))
        .unwrap()
    }
    fn portable_fixture() -> serde_json::Value {
        serde_json::from_str(include_str!(
            "../../../tests/fixtures/provider/stellar-portable-approval.json"
        ))
        .unwrap()
    }
    #[test]
    fn historical_v1_digest_is_unchanged_and_cannot_prepare_fresh_approval() {
        let f = fixture();
        let expected: ApprovalIntent = serde_json::from_value(f["intent"].clone()).unwrap();
        validate(&expected).unwrap();
        assert_eq!(
            intent_digest(&expected).unwrap(),
            "f20ea9a31ad23c3531471c4f2330daf6af011d0cde41d2a1d77b8ba3d886e9fb"
        );
        assert_eq!(serde_json::to_value(&expected).unwrap(), f["intent"]);
        assert!(signing_url("https://app.allowit.xyz", &expected).is_err());
        assert!(approval_for_policy(&f["policy"], &expected.owner, &expected.request_id).is_err());
    }
    #[test]
    fn public_approval_binds_original_source_and_filters_secret_fields() {
        let f = portable_fixture();
        let expected: ApprovalIntent = serde_json::from_value(f["intent"].clone()).unwrap();
        let mut policy = f["policy"].clone();
        policy["signingSeed"] = serde_json::json!("never-export-this-secret");
        let intent = approval_for_policy(&policy, &expected.owner, &expected.request_id).unwrap();
        assert_eq!(intent, expected);
        let url = signing_url("https://app.allowit.xyz", &intent).unwrap();
        assert!(url.contains("?chain=stellar&network=stellar%3Atestnet#allowit-stellar-approval="));
        assert!(
            !serde_json::to_string(&intent)
                .unwrap()
                .contains("never-export")
        );
        policy["code"] = serde_json::json!("substituted source");
        assert!(approval_for_policy(&policy, &expected.owner, &expected.request_id).is_err());
    }
    #[test]
    fn altered_binding_profile_and_network_are_refused() {
        let f = portable_fixture();
        let mut intent: ApprovalIntent = serde_json::from_value(f["intent"].clone()).unwrap();
        intent.binding.module_digest = "11".repeat(32);
        assert!(validate(&intent).is_err());
        let mut policy = f["policy"].clone();
        policy["network"] = serde_json::json!("stellar:mainnet");
        assert!(approval_for_policy(&policy, &intent.owner, &intent.request_id).is_err());
        policy = f["policy"].clone();
        policy["runtime"]["wallet"]["profile"] = serde_json::json!("allowit-stellar-odc-v1");
        assert!(approval_for_policy(&policy, &intent.owner, &intent.request_id).is_err());
    }
    #[test]
    fn native_approval_preserves_separate_owner_authority_and_canonical_asset_identity() {
        let f = portable_fixture();
        let mut intent: ApprovalIntent = serde_json::from_value(f["intent"].clone()).unwrap();
        // Existing installations can give a distinct owner weight-three administration authority.
        intent.owner = allowit_stellar_wallet::account_for_seed(&[9; 32]);
        intent.intent_digest = intent_digest(&intent).unwrap();
        validate(&intent).unwrap();
        let mut issued = intent.clone();
        issued.binding.asset_symbol = "USDC".into();
        issued.binding.asset_issuer = Some(allowit_stellar_wallet::account_for_seed(&[8; 32]));
        issued.intent_digest = intent_digest(&issued).unwrap();
        assert!(validate(&issued).is_err());
        issued.binding.asset = allowit_stellar_wallet::sac_address(
            &issued.network,
            &allowit_stellar_wallet::asset_from_identity(
                "USDC",
                issued.binding.asset_issuer.as_deref(),
            )
            .unwrap(),
        )
        .unwrap();
        issued.intent_digest = intent_digest(&issued).unwrap();
        validate(&issued).unwrap();
        for symbol in ["XLM\n", "USDC\u{202e}", "TOO_LONG_ASSET"] {
            let mut altered = intent.clone();
            altered.binding.asset_symbol = symbol.into();
            altered.intent_digest = intent_digest(&altered).unwrap();
            assert!(validate(&altered).is_err());
        }
        intent.ir_hash = "AB".repeat(32);
        intent.intent_digest = intent_digest(&intent).unwrap();
        assert!(validate(&intent).is_err());
        let mut policy = f["policy"].clone();
        for field in ["assetIssuer", "deploymentId"] {
            policy["runtime"]["instanceBinding"][field] = serde_json::json!(false);
            assert!(approval_for_policy(&policy, &intent.owner, &intent.request_id).is_err());
            policy = f["policy"].clone();
        }
        intent = serde_json::from_value(f["intent"].clone()).unwrap();
        intent.policy_id = "policy\u{202e}".into();
        intent.intent_digest = intent_digest(&intent).unwrap();
        assert!(validate(&intent).is_err());
    }
    #[test]
    fn portable_terms_and_recursive_canonical_values_match_independent_rust_vectors() {
        let f = portable_fixture();
        let original: ApprovalIntent = serde_json::from_value(f["intent"].clone()).unwrap();
        for field in ["language", "tier", "rules", "params", "paramsHash"] {
            let mut value = f["intent"].clone();
            value["binding"][field] = serde_json::Value::Null;
            let mut changed: ApprovalIntent = serde_json::from_value(value).unwrap();
            changed.intent_digest = intent_digest(&changed).unwrap();
            assert!(validate(&changed).is_err(), "{field}");
        }
        let mut changed = original.clone();
        changed.binding.params.as_mut().unwrap()["payment_limit"]["Int"] =
            serde_json::json!("1001");
        changed.intent_digest = intent_digest(&changed).unwrap();
        assert!(validate(&changed).is_err());
        for name in ["canonicalParams", "canonicalValues"] {
            let vector = &f[name];
            let canonical = serde_json_canonicalizer::to_string(&vector["params"]).unwrap();
            assert_eq!(canonical, vector["canonical"]);
            assert_eq!(hash(canonical), vector["hash"]);
        }
    }
}
