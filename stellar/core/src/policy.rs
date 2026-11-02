//! Portable policy: tiers, owner params, the standard prefix and host evaluation.
//!
//! Policy wallets of contract layout 4 run portable authored source. Simple and Common run only
//! the canonical prefix onchain; Custom runs its whole compiled policy. This module derives the
//! prefix from source exactly as `scripts/policy_source.py` does, checks owner params as
//! `scripts/contract_admin.py` does, and evaluates canonical policies with the `allowit` host
//! backend. Retired source languages remain readable only for signed-packet recovery.
use crate::*;
use allowit::{AllowitContext, AllowitRequest, AllowitRule, AllowitTier, AllowitValue};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyEngine {
    SimplePolicyEngine,
    CommonPolicyEngine,
    CustomPolicy,
}

impl PolicyEngine {
    pub fn symbol(self) -> &'static str {
        match self {
            Self::SimplePolicyEngine => "simple_policy_engine",
            Self::CommonPolicyEngine => "common_policy_engine",
            Self::CustomPolicy => "custom_policy",
        }
    }
}

/// Wallet tier: the installed policy engine of a policy wallet.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum PolicyTier {
    /// Fixed minimal engine. No onchain rules; the server evaluates the full policy.
    #[serde(alias = "simple_policy_engine")]
    Simple,
    /// Fixed canonical engine. The owner-approved standard prefix runs onchain.
    #[serde(alias = "common_policy_engine")]
    Common,
    /// Bespoke engine. The whole compiled policy runs onchain.
    #[serde(alias = "custom_policy")]
    Custom,
}
impl PolicyTier {
    /// The engine kind in the policy binding and the standard prefix digest.
    pub fn kind(self) -> &'static str {
        match self {
            Self::Simple => "simple_policy_engine",
            Self::Common => "common_policy_engine",
            Self::Custom => "custom_policy",
        }
    }
    /// Simple and Common store only standard state and admit only canonical params.
    pub fn standard(self) -> bool {
        self != Self::Custom
    }
    /// The `allowit` tier of params and policy state.
    pub fn allowit(self) -> AllowitTier {
        if self.standard() {
            AllowitTier::Standard
        } else {
            AllowitTier::Custom
        }
    }
    /// The legacy SDK name of this engine.
    pub fn engine(self) -> PolicyEngine {
        match self {
            Self::Simple => PolicyEngine::SimplePolicyEngine,
            Self::Common => PolicyEngine::CommonPolicyEngine,
            Self::Custom => PolicyEngine::CustomPolicy,
        }
    }
}
impl From<PolicyEngine> for PolicyTier {
    fn from(engine: PolicyEngine) -> Self {
        match engine {
            PolicyEngine::SimplePolicyEngine => Self::Simple,
            PolicyEngine::CommonPolicyEngine => Self::Common,
            PolicyEngine::CustomPolicy => Self::Custom,
        }
    }
}

/// Language of the installed policy source.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PolicyLanguage {
    /// Historical compiler source, retained only to decode signed packets.
    #[default]
    Legacy,
    /// Portable source that `allowit` compiles on the host and onchain.
    Portable,
}

/// Canonical param keys, which are also the canonical rule names, in `allowit::RULES` order.
pub fn param_keys() -> [&'static str; allowit::RULES.len()] {
    allowit::RULES.map(AllowitRule::key)
}
const MAX_PARAMS: usize = allowit::MAX_PARAMS as usize;
const MAX_ITEMS: usize = allowit::MAX_ITEMS as usize;
const MAX_TEXT: usize = allowit::MAX_TEXT as usize;
const KEY_BYTES: usize = allowit::KEY_BYTES as usize;
const VALUE_BYTES: usize = allowit::VALUE_BYTES as usize;
const MAX_PARAM_BYTES: usize = allowit::MAX_PARAM_BYTES as usize;

/// One owner param, execution arg or policy state value: the JSON form of `AllowitValue`.
/// It serializes as one key naming its type, with `Int` as a decimal string: `{"Int":"5"}`,
/// `{"Bool":true}`, `{"Str":"text"}`, `{"Addr":"G..."}` or `{"List":[...]}`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyValue {
    Int(i128),
    Bool(bool),
    Str(String),
    Addr(String),
    List(Vec<PolicyValue>),
}
impl Serialize for PolicyValue {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = s.serialize_map(Some(1))?;
        match self {
            Self::Int(v) => map.serialize_entry("Int", &v.to_string())?,
            Self::Bool(v) => map.serialize_entry("Bool", v)?,
            Self::Str(v) => map.serialize_entry("Str", v)?,
            Self::Addr(v) => map.serialize_entry("Addr", v)?,
            Self::List(v) => map.serialize_entry("List", v)?,
        }
        map.end()
    }
}
impl<'de> Deserialize<'de> for PolicyValue {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        use serde::de::Error;
        let raw = serde_json::Value::deserialize(d)?;
        let serde_json::Value::Object(map) = raw else {
            return Err(D::Error::custom(
                "A policy value is one key naming its type",
            ));
        };
        let mut entries = map.into_iter();
        let (Some((kind, value)), None) = (entries.next(), entries.next()) else {
            return Err(D::Error::custom(
                "A policy value is one key naming its type",
            ));
        };
        let value = match (kind.as_str(), value) {
            ("Int", serde_json::Value::String(text)) => {
                let n = text.parse::<i128>().map_err(D::Error::custom)?;
                if n.to_string() != text {
                    return Err(D::Error::custom("Int requires a canonical decimal string"));
                }
                Self::Int(n)
            }
            ("Bool", serde_json::Value::Bool(v)) => Self::Bool(v),
            ("Str", serde_json::Value::String(v)) => Self::Str(v),
            ("Addr", serde_json::Value::String(v)) => {
                if !is_address(&v) {
                    return Err(D::Error::custom("Addr requires a canonical G or C address"));
                }
                Self::Addr(v)
            }
            ("List", list @ serde_json::Value::Array(_)) => {
                Self::List(serde_json::from_value(list).map_err(D::Error::custom)?)
            }
            _ => return Err(D::Error::custom("Unsupported policy value")),
        };
        Ok(value)
    }
}

/// Key => value params, args or policy state. Keys are 1 to 32 ASCII letters, digits or
/// underscores. JSON rejects duplicate keys.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PolicyParams(pub BTreeMap<String, PolicyValue>);
impl Serialize for PolicyParams {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        self.0.serialize(s)
    }
}
impl<'de> Deserialize<'de> for PolicyParams {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = PolicyParams;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("unique keys mapped to typed policy values")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut entries: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                use serde::de::Error;
                let mut out = BTreeMap::new();
                while let Some((key, value)) = entries.next_entry::<String, PolicyValue>()? {
                    if !key_ok(&key) {
                        return Err(A::Error::custom(
                            "Param keys are 1 to 32 ASCII letters, digits or underscores",
                        ));
                    }
                    if out.insert(key, value).is_some() {
                        return Err(A::Error::custom("Duplicate policy key"));
                    }
                }
                Ok(PolicyParams(out))
            }
        }
        d.deserialize_map(Visitor)
    }
}
impl PolicyParams {
    pub fn get(&self, key: &str) -> Option<&PolicyValue> {
        self.0.get(key)
    }
    /// Contract encoding: a `Map<Symbol, AllowitValue>`.
    pub fn scval(&self) -> Result<ScVal> {
        let entries = self
            .0
            .iter()
            .map(|(key, value)| {
                Ok(ScMapEntry {
                    key: value_symbol(key)?,
                    val: value.scval()?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(ScVal::Map(Some(entries.try_into().map_err(err)?)))
    }
    /// Decode a contract `Map<Symbol, AllowitValue>` exactly.
    pub fn from_scval(value: &ScVal) -> Result<Self> {
        let ScVal::Map(Some(entries)) = value else {
            return Err("Expected a key => value map".into());
        };
        let mut out = BTreeMap::new();
        let mut previous: Option<&ScVal> = None;
        for entry in entries.iter() {
            let ScVal::Symbol(key) = &entry.key else {
                return Err("Policy map keys must be symbols".into());
            };
            if previous.is_some_and(|p| p >= &entry.key) {
                return Err("Policy map keys must be strictly ordered".into());
            }
            previous = Some(&entry.key);
            let key = String::from_utf8(key.0.to_vec()).map_err(err)?;
            out.insert(key, PolicyValue::from_scval(&entry.val)?);
        }
        Ok(Self(out))
    }
    /// The `allowit` host map.
    pub fn allowit(&self) -> allowit::AllowitMap {
        self.0
            .iter()
            .map(|(k, v)| (k.clone(), v.allowit()))
            .collect()
    }
    /// The params of an `allowit` host map.
    pub fn from_allowit(map: &allowit::AllowitMap) -> Self {
        Self(
            map.iter()
                .map(|(k, v)| (k.clone(), PolicyValue::from_allowit(v)))
                .collect(),
        )
    }
    /// Check owner params as the wallet does for `tier`.
    pub fn check(&self, tier: PolicyTier) -> Result<()> {
        allowit::check_params(&self.allowit(), tier.allowit())
            .map_err(|e| format!("Owner params rejected: {e:?}"))
    }
    /// Check execution args as the wallet does.
    pub fn check_args(&self) -> Result<()> {
        allowit::check_args(&self.allowit()).map_err(|e| format!("Execution args rejected: {e:?}"))
    }
}
impl PolicyValue {
    /// Contract encoding of `AllowitValue`: a vector of its variant symbol and payload.
    pub fn scval(&self) -> Result<ScVal> {
        let (variant, payload) = match self {
            Self::Int(v) => ("Int", i128_value(*v)),
            Self::Bool(v) => ("Bool", ScVal::Bool(*v)),
            Self::Str(v) => (
                "Str",
                ScVal::String(ScString(v.as_bytes().to_vec().try_into().map_err(err)?)),
            ),
            Self::Addr(v) => ("Addr", ScVal::Address(address(v)?)),
            Self::List(v) => (
                "List",
                ScVal::Vec(Some(
                    v.iter()
                        .map(PolicyValue::scval)
                        .collect::<Result<Vec<_>>>()?
                        .try_into()
                        .map_err(err)?,
                )),
            ),
        };
        Ok(ScVal::Vec(Some(
            vec![value_symbol(variant)?, payload]
                .try_into()
                .map_err(err)?,
        )))
    }
    pub fn from_scval(value: &ScVal) -> Result<Self> {
        let ScVal::Vec(Some(items)) = value else {
            return Err("Expected an AllowitValue".into());
        };
        let [ScVal::Symbol(variant), payload] = items.as_slice() else {
            return Err("Expected an AllowitValue variant and payload".into());
        };
        Ok(match (variant.0.as_slice(), payload) {
            (b"Int", ScVal::I128(_)) => Self::Int(rpc::wide(payload)?),
            (b"Bool", ScVal::Bool(v)) => Self::Bool(*v),
            (b"Str", ScVal::String(v)) => Self::Str(String::from_utf8(v.0.to_vec()).map_err(err)?),
            (b"Addr", ScVal::Address(v)) => Self::Addr(address_text(v)?),
            (b"List", ScVal::Vec(Some(v))) => Self::List(
                v.iter()
                    .map(PolicyValue::from_scval)
                    .collect::<Result<Vec<_>>>()?,
            ),
            _ => return Err("Unsupported AllowitValue".into()),
        })
    }
    pub fn allowit(&self) -> AllowitValue {
        match self {
            Self::Int(v) => AllowitValue::Int(*v),
            Self::Bool(v) => AllowitValue::Bool(*v),
            Self::Str(v) => AllowitValue::Str(v.clone()),
            Self::Addr(v) => AllowitValue::Addr(allowit::Address::new(v.clone())),
            Self::List(v) => AllowitValue::List(v.iter().map(PolicyValue::allowit).collect()),
        }
    }
    pub fn from_allowit(value: &AllowitValue) -> Self {
        match value {
            AllowitValue::Int(v) => Self::Int(*v),
            AllowitValue::Bool(v) => Self::Bool(*v),
            AllowitValue::Str(v) => Self::Str(v.clone()),
            AllowitValue::Addr(v) => Self::Addr(v.as_str().into()),
            AllowitValue::List(v) => {
                Self::List(v.as_slice().iter().map(PolicyValue::from_allowit).collect())
            }
        }
    }
}

fn key_ok(key: &str) -> bool {
    (1..=32).contains(&key.len()) && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}
/// A canonical G or C StrKey.
pub fn is_address(value: &str) -> bool {
    matches!(
        Strkey::from_string(value),
        Ok(key @ (Strkey::PublicKeyEd25519(_) | Strkey::Contract(_))) if key.to_string() == value
    )
}
/// Whether `name` is an `operations` entry: a plain op name, `custom.<function>` or
/// `custom:<contract>.<function>`.
fn op_name_ok(name: &str) -> bool {
    let symbol = |s: &str| key_ok(s);
    if let Some(function) = name.strip_prefix("custom.") {
        return symbol(function);
    }
    if let Some(call) = name.strip_prefix("custom:") {
        let b = call.as_bytes();
        return b.len() > 57
            && b[0] == b'C'
            && b[..56]
                .iter()
                .all(|c| c.is_ascii_uppercase() || (b'2'..=b'7').contains(c))
            && b[56] == b'.'
            && symbol(&call[57..]);
    }
    ["transfer", "swap", "deposit", "redeem", "custom"].contains(&name)
}

/// One loose JSON param value: `scripts/contract_admin.py` `param_value`.
fn loose_value(item: &serde_json::Value, count: &mut (usize, usize)) -> Result<PolicyValue> {
    use serde_json::Value;
    let (kind, item) = match item {
        Value::Object(map) => {
            let mut entries = map.iter();
            match (entries.next(), entries.next()) {
                (Some((kind, value)), None)
                    if ["Int", "Bool", "Str", "Addr", "List"].contains(&kind.as_str()) =>
                {
                    (kind.as_str(), value)
                }
                _ => {
                    return Err(
                        "A typed param value is one key of Int, Bool, Str, Addr, List".into(),
                    );
                }
            }
        }
        Value::Bool(_) => ("Bool", item),
        Value::Number(n) if n.is_i64() || n.is_u64() || n.to_string().parse::<i128>().is_ok() => {
            ("Int", item)
        }
        Value::Array(_) => ("List", item),
        Value::String(text) if is_address(text) => ("Addr", item),
        Value::String(_) => ("Str", item),
        _ => ("", item),
    };
    count.1 += VALUE_BYTES;
    let unsupported = || format!("Unsupported param value: {item}");
    match (kind, item) {
        ("Int", Value::Number(n)) => {
            let text = n.to_string();
            let value = text.parse::<i128>().map_err(|_| unsupported())?;
            if text.contains(['.', 'e', 'E']) {
                return Err(unsupported());
            }
            Ok(PolicyValue::Int(value))
        }
        ("Bool", Value::Bool(v)) => Ok(PolicyValue::Bool(*v)),
        ("Addr", Value::String(v)) if is_address(v) => Ok(PolicyValue::Addr(v.clone())),
        ("Str", Value::String(v)) if v.len() <= MAX_TEXT => {
            count.1 += v.len().div_ceil(4) * 4;
            Ok(PolicyValue::Str(v.clone()))
        }
        ("List", Value::Array(items)) => {
            count.0 += items.len();
            if count.0 > MAX_ITEMS {
                return Err(format!("A param value nests at most {MAX_ITEMS} values"));
            }
            Ok(PolicyValue::List(
                items
                    .iter()
                    .map(|entry| loose_value(entry, count))
                    .collect::<Result<_>>()?,
            ))
        }
        _ => Err(unsupported()),
    }
}

/// Validate loose owner params and return their canonical form: `scripts/contract_admin.py`
/// `params`. An integer is `Int`, a boolean `Bool`, a G or C address `Addr`, other text `Str` and
/// a list `List`; a one-key object such as `{"Str": "GA..."}` names the type explicitly. Simple and
/// Common admit only the canonical keys, each with its rule's type. `tier` `None` checks only
/// the Custom bounds.
pub fn params_from_json(
    value: &serde_json::Value,
    tier: Option<PolicyTier>,
) -> Result<PolicyParams> {
    let standard = tier.is_some_and(PolicyTier::standard);
    let limit = if standard {
        allowit::RULES.len()
    } else {
        MAX_PARAMS
    };
    let serde_json::Value::Object(map) = value else {
        return Err(format!("Params must be an object of at most {limit} keys"));
    };
    if map.len() > limit {
        return Err(format!("Params must be an object of at most {limit} keys"));
    }
    let mut out = BTreeMap::new();
    let mut size = 0usize;
    for (key, item) in map {
        if !key_ok(key) {
            return Err("Param keys are 1 to 32 ASCII letters, digits or underscores".into());
        }
        let mut count = (0, 0);
        let encoded = loose_value(item, &mut count)?;
        size += KEY_BYTES + count.1;
        if size > MAX_PARAM_BYTES {
            return Err(format!("Params encode in at most {MAX_PARAM_BYTES} bytes"));
        }
        if standard {
            canonical_param(key, &encoded)?;
        }
        out.insert(key.clone(), encoded);
    }
    Ok(PolicyParams(out))
}
/// Check one canonical param of a standard tier, with the messages of `contract_admin.py`.
fn canonical_param(key: &str, encoded: &PolicyValue) -> Result<()> {
    if !param_keys().contains(&key) {
        return Err(format!(
            "Simple and Common params admit only the canonical keys: {}",
            param_keys().join(", ")
        ));
    }
    match key {
        "destinations" | "tokens" => {
            let ok = matches!(encoded, PolicyValue::List(items)
                if items.iter().all(|i| matches!(i, PolicyValue::Addr(_))));
            if !ok {
                return Err(format!("Param {key} must be a list of addresses"));
            }
        }
        "operations" => {
            let ok = match encoded {
                PolicyValue::Str(text) => text == "*",
                PolicyValue::List(items) => items
                    .iter()
                    .all(|i| matches!(i, PolicyValue::Str(name) if op_name_ok(name))),
                _ => false,
            };
            if !ok {
                return Err("Param operations must be \"*\" or a list of op names".into());
            }
        }
        _ => {
            let bits = if ["call_limit", "expires_at"].contains(&key) {
                64
            } else {
                127
            };
            let ok =
                matches!(encoded, PolicyValue::Int(n) if *n >= 0 && (bits == 127 || *n < 1 << 64));
            if !ok {
                return Err(format!(
                    "Param {key} must be a nonnegative integer in its range"
                ));
            }
        }
    }
    Ok(())
}

/// Parse canonical rule names. The contract admits any ordered list, so only names are checked.
pub fn parse_rules(rules: &[String]) -> Result<Vec<AllowitRule>> {
    rules
        .iter()
        .map(|name| {
            allowit::RULES
                .iter()
                .copied()
                .find(|rule| rule.key() == name)
                .ok_or_else(|| {
                    format!(
                        "Rules must name canonical rules: {}",
                        param_keys().join(", ")
                    )
                })
        })
        .collect()
}
/// Contract encoding of `Vec<AllowitRule>`: each unit variant is a one-symbol vector.
pub fn rules_scval(rules: &[String]) -> Result<ScVal> {
    parse_rules(rules)?;
    let values = rules
        .iter()
        .map(|name| {
            Ok(ScVal::Vec(Some(
                vec![value_symbol(name)?].try_into().map_err(err)?,
            )))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(ScVal::Vec(Some(values.try_into().map_err(err)?)))
}
/// Decode a contract `Vec<AllowitRule>`.
pub fn rules_from_scval(value: &ScVal) -> Result<Vec<String>> {
    let ScVal::Vec(Some(items)) = value else {
        return Err("Expected a rule list".into());
    };
    let rules = items
        .iter()
        .map(|item| match item {
            ScVal::Vec(Some(v)) => match v.as_slice() {
                [ScVal::Symbol(name)] => String::from_utf8(name.0.to_vec()).map_err(err),
                _ => Err("Expected a rule variant".into()),
            },
            _ => Err("Expected a rule variant".into()),
        })
        .collect::<Result<Vec<_>>>()?;
    parse_rules(&rules)?;
    Ok(rules)
}

/// The standard prefix binding of a Simple or Common wallet: `standard_prefix_digest` of the
/// policy wallet crate, the SHA-256 of the canonical XDR of the domain `allowit_std_prefix`, the
/// engine kind, the executable, the asset and the ordered rules. The executable fixes the
/// operations that the code runs. Param values and the offchain suffix are excluded.
pub fn standard_prefix_digest(
    tier: PolicyTier,
    module_digest: &[u8; 32],
    asset: &str,
    rules: &[String],
) -> Result<[u8; 32]> {
    let preimage = ScVal::Vec(Some(
        vec![
            value_symbol("allowit_std_prefix")?,
            value_symbol(tier.kind())?,
            value_bytes(module_digest)?,
            ScVal::Address(address(asset)?),
            rules_scval(rules)?,
        ]
        .try_into()
        .map_err(err)?,
    ));
    Ok(hash(preimage.to_xdr(limits()).map_err(err)?))
}
/// The installed binding digest: the standard prefix digest, or the source digest for Custom.
pub fn installed_source_digest(
    tier: PolicyTier,
    module_digest: &[u8; 32],
    asset: &str,
    rules: &[String],
    source: &str,
) -> Result<[u8; 32]> {
    if tier.standard() {
        standard_prefix_digest(tier, module_digest, asset, rules)
    } else {
        Ok(hash(source.as_bytes()))
    }
}

/// Shared portable source gate from the same released Core dependency as the library.
pub use allowit_policy_sdk::policy_source::{SourceShape, source_shape};
/// The rules a tier installs for `source`: the standard prefix for Common, none otherwise.
pub fn tier_rules(tier: PolicyTier, source: &str) -> Result<Vec<String>> {
    let shape = source_shape(source)?;
    Ok(if tier == PolicyTier::Common {
        shape.prefix
    } else {
        vec![]
    })
}

/// Result of `policy_rules`: warnings for prefix rules whose param is absent.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PolicyCheck {
    pub warnings: Vec<String>,
}
/// Bind an owner packet to its authored source: `scripts/contract_admin.py` `policy_rules`.
/// Common binds the source's standard prefix; Simple and Custom bind none. Custom also binds
/// the source bytes. Simple and Common cannot store `allowit::set_state` writes.
pub fn policy_rules(
    tier: PolicyTier,
    source: &str,
    rules: &[String],
    source_digest: &[u8; 32],
    params: &PolicyParams,
) -> Result<PolicyCheck> {
    let shape = source_shape(source)?;
    let expected = if tier == PolicyTier::Common {
        shape.prefix.clone()
    } else {
        vec![]
    };
    if rules != expected.as_slice() {
        return Err(format!(
            "Rules must be the standard prefix derived from the policy source: {}",
            serde_json::to_string(&expected).map_err(err)?
        ));
    }
    if tier == PolicyTier::Custom && *source_digest != hash(source.as_bytes()) {
        return Err("Custom source_digest must be the SHA-256 of the policy source".into());
    }
    if tier.standard() && shape.writes_state {
        return Err(
            "Simple and Common cannot store allowit::set_state writes; use the custom tier".into(),
        );
    }
    params.check(tier)?;
    let unset: Vec<_> = rules
        .iter()
        .filter(|r| !params.0.contains_key(*r))
        .cloned()
        .collect();
    let mut out = PolicyCheck::default();
    if !unset.is_empty() {
        out.warnings.push(format!(
            "The standard preflight skips prefix rules whose param is absent: {}. The full policy denies them with MissingParam.",
            unset.join(", ")
        ));
    }
    Ok(out)
}

/// Request facts of one native operation, as the wallet builds them for rules.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleRequest {
    pub operation: OperationKind,
    pub asset: String,
    /// The payment recipient or the vault.
    pub recipient: String,
    /// The gross underlying debit, or a redeem's minimum underlying credit.
    pub amount: i128,
    /// Token that leaves the wallet: the asset, or the vault's shares for a redeem.
    pub token_in: String,
    /// Exact units of `token_in` that leave the wallet.
    pub amount_in: i128,
    /// Token that the wallet receives back: the deposit vault's shares, the asset for a redeem,
    /// or none for a transfer.
    pub token_out: Option<String>,
    /// Minimum units of `token_out`, or zero for a transfer.
    pub min_out: i128,
    pub now: u64,
    pub expires_at: u64,
    pub expense: Option<ExpenseBounds>,
    pub args: PolicyParams,
}
impl RuleRequest {
    /// The facts of `operation` on a wallet of `asset`, as the wallet's `facts` builds them.
    pub fn new(
        operation: &StellarOperation,
        asset: &str,
        now: u64,
        expires_at: u64,
        expense: Option<ExpenseBounds>,
        args: PolicyParams,
    ) -> Self {
        let (recipient, amount_in) = operation.debit();
        let (amount, token_out, min_out) = match operation {
            StellarOperation::Transfer(_) => (amount_in, None, 0),
            StellarOperation::Deposit(d) => (amount_in, Some(d.vault.clone()), d.min_shares),
            StellarOperation::Redeem(r) => (r.min_assets, Some(asset.into()), r.min_assets),
        };
        Self {
            operation: operation.kind(),
            asset: asset.into(),
            recipient: recipient.into(),
            amount,
            token_in: operation.debit_token(asset).into(),
            amount_in,
            token_out,
            min_out,
            now,
            expires_at,
            expense,
            args,
        }
    }
}
/// A compiled evaluator of the exact installed source, supplied by a host that compiled it
/// through the server build gate. It is used only when the source is not canonical-only.
pub type PortableEvaluator<'a> = &'a dyn Fn(&AllowitContext) -> allowit::Result;

fn context(params: &PolicyParams, state: &PolicyParams, r: &RuleRequest) -> AllowitContext {
    AllowitContext {
        env: allowit::AllowitEnv::new(),
        params: params.allowit().into(),
        state: state.allowit(),
        request: AllowitRequest {
            operation: r.operation.allowit(),
            asset: allowit::Address::new(r.asset.clone()),
            recipient: allowit::Address::new(r.recipient.clone()),
            amount: r.amount,
            token_in: allowit::Address::new(r.token_in.clone()),
            amount_in: r.amount_in,
            token_out: r.token_out.clone().map(allowit::Address::new),
            min_out: r.min_out,
            now: r.now,
            expires_at: r.expires_at,
            spent_units: r.expense.as_ref().map_or(0, |e| e.spent_units),
            gas_units: r.expense.as_ref().map_or(0, |e| e.gas_units),
            unpriced: r.expense.is_none(),
            args: r.args.allowit().into(),
        },
    }
}
/// Run one canonical rule call `allowit::<rule>(ctx, &ctx.params[allowit::<RULE>])?`. An unset
/// param panics with `MissingParam`, which `allowit::evaluate` returns.
fn run_rule(ctx: &AllowitContext, rule: AllowitRule) -> allowit::Result {
    let value = &ctx.params[rule.key()];
    match rule {
        AllowitRule::payment_limit => allowit::payment_limit(ctx, value).map(drop),
        AllowitRule::lifetime_spending_limit => {
            allowit::lifetime_spending_limit(ctx, value).map(drop)
        }
        AllowitRule::daily_spending_limit => allowit::daily_spending_limit(ctx, value).map(drop),
        AllowitRule::daily_volume_limit => allowit::daily_volume_limit(ctx, value).map(drop),
        AllowitRule::call_limit => allowit::call_limit(ctx, value).map(drop),
        AllowitRule::destinations => allowit::destinations(ctx, value).map(drop),
        AllowitRule::tokens => allowit::tokens(ctx, value).map(drop),
        AllowitRule::expires_at => allowit::expires_at(ctx, value).map(drop),
        AllowitRule::operations => allowit::operations(ctx, value).map(drop),
    }
}
/// What host evaluation established.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Evaluation {
    /// The full policy ran on the host; this is the state the wallet stores.
    Full(PolicyParams),
    /// Only the onchain part ran: the Common prefix, or nothing for Simple. The full policy is
    /// not canonical-only and no evaluator was supplied.
    Prefix,
}
/// Evaluate a policy on the host as the wallet and the server do. The standard preflight of a
/// Common wallet runs first, skipping absent params like the contract. A canonical-only source,
/// or any source with a supplied compiled evaluator, then runs in full through
/// `allowit::evaluate`, where an absent param denies with `MissingParam`.
pub fn evaluate(
    tier: PolicyTier,
    shape: &SourceShape,
    rules: &[String],
    params: &PolicyParams,
    state: &PolicyParams,
    request: &RuleRequest,
    evaluator: Option<PortableEvaluator>,
) -> Result<Evaluation> {
    let ctx = context(params, state, request);
    for rule in parse_rules(rules)? {
        allowit::preflight(&ctx, rule).map_err(|e| format!("Policy prefix denied: {e:?}"))?;
    }
    let full = if let Some(evaluator) = evaluator {
        allowit::evaluate(&ctx, evaluator, tier.allowit())
    } else if shape.canonical_only {
        let prefix = parse_rules(&shape.prefix)?;
        allowit::evaluate(
            &ctx,
            |ctx| {
                for rule in &prefix {
                    run_rule(ctx, *rule)?;
                }
                Ok(())
            },
            tier.allowit(),
        )
    } else {
        // `allowit::evaluate` checks args and standard params; the prefix-only path checks them
        // here. The onchain prefix alone still produces the standard post-flight state.
        request.args.check_args()?;
        if tier.standard() {
            params.check(tier)?;
        }
        allowit::post_flight(&ctx, tier.allowit())
            .map_err(|e| format!("Policy state rejected: {e:?}"))?;
        return Ok(Evaluation::Prefix);
    };
    Ok(Evaluation::Full(PolicyParams::from_allowit(
        &full.map_err(|e| format!("Authored policy denied this exact operation: {e:?}"))?,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    const SOURCE: &str = include_str!("../../../crates/custom-policy/policy/policy.rs");

    #[test]
    fn canonical_source_has_the_full_prefix_and_is_canonical_only() {
        let shape = source_shape(SOURCE).unwrap();
        assert_eq!(shape.prefix, param_keys().map(String::from).to_vec());
        assert!(shape.canonical_only);
        assert!(!shape.writes_state);
    }
    #[test]
    fn only_a_file_of_allowit_uses_and_the_prefix_is_canonical_only() {
        // A local `fn Ok` shadows the prelude constructor, so the compiled policy would deny
        // every operation while the prefix alone allows it.
        let shadowed = format!(
            "{SOURCE}\nfn Ok(_: ()) -> allowit::Result {{ Err(allowit::AllowitError::MissingParam) }}\n"
        );
        let shape = source_shape(&shadowed).unwrap();
        assert_eq!(shape.prefix.len(), allowit::RULES.len());
        assert!(!shape.canonical_only);
        let helper = SOURCE.replace(
            "use allowit::prelude::*;",
            "use allowit::prelude::*;\nconst LIMIT: i128 = 5;",
        );
        assert!(!source_shape(&helper).unwrap().canonical_only);
        let renamed = SOURCE.replace(
            "use allowit::prelude::*;",
            "use allowit::prelude::*;\nuse allowit::{payment_limit as Ok};",
        );
        // `policy_source.py` admits only `use allowit::prelude::*` and plain `allowit` type
        // imports, so a renamed or braced import fails the gate.
        assert!(source_shape(&renamed).is_err());
        let braced = SOURCE.replace(
            "use allowit::prelude::*;",
            "use allowit::{prelude::*, AllowitError};",
        );
        assert!(source_shape(&braced).is_err());
        let attributed = SOURCE.replace("pub fn execute", "#[inline]\npub fn execute");
        assert!(!source_shape(&attributed).unwrap().canonical_only);
    }
    #[test]
    fn macros_and_attributes_follow_the_policy_source_allowlists() {
        for (bad, what) in [
            ("macro_rules! m { () => {} }", "macro `macro_rules!`"),
            ("#[cfg(test)]\nconst A: i128 = 1;", "attribute `cfg`"),
            ("#[doc = \"x\"]\nconst A: i128 = 1;", "attribute `doc`"),
            (
                "const A: () = core::arch::global_asm!(\"\");",
                "macro `global_asm!`",
            ),
            ("const A: &str = concat!(\"a\");", "macro `concat!`"),
        ] {
            let error = source_shape(&format!("{SOURCE}\n{bad}\n")).unwrap_err();
            assert!(error.contains(what), "{bad}: {error}");
        }
        for ok in [
            "#[allow(dead_code)]\nfn helper(a: bool) -> bool { assert!(a != false); !a }",
            "#[inline]\nfn other(a: i128) -> bool { matches!(a, 1) && a != 2 }",
        ] {
            source_shape(&format!("{SOURCE}\n{ok}\n")).unwrap();
        }
    }
    #[test]
    fn standard_prefix_digest_hashes_its_documented_tuple_and_binds_context() {
        // As `standard_prefix_digest_hashes_its_documented_tuple_and_binds_context` in
        // crates/policy-wallet/src/sep56_tests.rs: SHA-256 of the XDR vector (domain, kind,
        // module, asset, rules), where each rule is a one-symbol vector of its name.
        let asset = "CABAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAFNSZ";
        let symbol = |name: &str| ScVal::Symbol(name.try_into().unwrap());
        let list = |items: Vec<ScVal>| ScVal::Vec(Some(items.try_into().unwrap()));
        let tuple = list(vec![
            symbol("allowit_std_prefix"),
            symbol("common_policy_engine"),
            ScVal::Bytes([1u8; 32].to_vec().try_into().unwrap()),
            ScVal::Address(address(asset).unwrap()),
            list(vec![
                list(vec![symbol("lifetime_spending_limit")]),
                list(vec![symbol("destinations")]),
            ]),
        ]);
        let expected = hash(tuple.to_xdr(Limits::none()).unwrap());
        let xlm = sac_address("stellar:testnet", &Asset::Native).unwrap();
        let digest = |tier, module: [u8; 32], asset: &str, rules: [&str; 2]| {
            standard_prefix_digest(tier, &module, asset, &rules.map(String::from)).unwrap()
        };
        let rules = ["lifetime_spending_limit", "destinations"];
        assert_eq!(digest(PolicyTier::Common, [1; 32], asset, rules), expected);
        for other in [
            digest(PolicyTier::Simple, [1; 32], asset, rules),
            digest(PolicyTier::Common, [3; 32], asset, rules),
            digest(PolicyTier::Common, [1; 32], &xlm, rules),
            digest(
                PolicyTier::Common,
                [1; 32],
                asset,
                ["destinations", "lifetime_spending_limit"],
            ),
        ] {
            assert_ne!(other, expected);
        }
    }
    #[test]
    fn values_roundtrip_through_json_and_contract_encoding() {
        let params = params_from_json(
            &serde_json::json!({"payment_limit": 5, "destinations": [account_for_seed(&[3; 32])], "operations": "*"}),
            Some(PolicyTier::Common),
        )
        .unwrap();
        let json = serde_json::to_value(&params).unwrap();
        assert_eq!(json["payment_limit"], serde_json::json!({"Int": "5"}));
        assert_eq!(
            serde_json::from_value::<PolicyParams>(json).unwrap(),
            params
        );
        assert_eq!(
            PolicyParams::from_scval(&params.scval().unwrap()).unwrap(),
            params
        );
        assert!(
            serde_json::from_str::<PolicyParams>(r#"{"a":{"Int":"1"},"a":{"Int":"2"}}"#).is_err()
        );
        assert!(serde_json::from_str::<PolicyParams>(r#"{"a":{"Int":"01"}}"#).is_err());
    }
}
