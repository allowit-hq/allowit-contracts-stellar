//! Portable policy: tiers, owner params, the standard prefix and host evaluation.
//!
//! Policy wallets of contract layout 4 run portable authored source. Simple and Common run only
//! the canonical prefix onchain; Custom runs its whole compiled policy. This module derives the
//! prefix from source exactly as `scripts/policy_source.py` does, checks owner params as
//! `scripts/contract_admin.py` does, and evaluates canonical policies with the `allowit` host
//! backend. The legacy compiler stays only for legacy-language classic installs.
use crate::*;
use allowit::{AllowitContext, AllowitRequest, AllowitRule, AllowitTier, AllowitValue};
use std::collections::BTreeMap;

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
    /// `allowit::v1` source compiled by the legacy SDK compiler. Classic custody only.
    #[default]
    Legacy,
    /// Portable source that `allowit` compiles on the host and onchain.
    Portable,
}

/// Canonical param keys, which are also the canonical rule names, in `allowit::RULES` order.
pub const PARAM_KEYS: [&str; 9] = [
    "transaction_cap",
    "spent_cap",
    "day_spent_cap",
    "day_total_cap",
    "call_cap",
    "recipients",
    "tokens",
    "expiry",
    "operations",
];
const MAX_PARAMS: usize = 32;
const MAX_ITEMS: usize = 64;
const MAX_TEXT: usize = 256;
const KEY_BYTES: usize = 40;
const VALUE_BYTES: usize = 80;
const MAX_PARAM_BYTES: usize = 16 * 1024;

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
            AllowitValue::List(v) => Self::List(v.iter().map(PolicyValue::from_allowit).collect()),
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
        PARAM_KEYS.len()
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
    if !PARAM_KEYS.contains(&key) {
        return Err(format!(
            "Simple and Common params admit only the canonical keys: {}",
            PARAM_KEYS.join(", ")
        ));
    }
    match key {
        "recipients" | "tokens" => {
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
            let bits = if ["call_cap", "expiry"].contains(&key) {
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
                    format!("Rules must name canonical rules: {}", PARAM_KEYS.join(", "))
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

/// SHA-256 of the native transfer argument schema.
pub fn transfer_schema_digest() -> [u8; 32] {
    hash(TRANSFER_SCHEMA)
}
/// SHA-256 of the SEP-56 deposit argument schema.
pub fn deposit_schema_digest() -> [u8; 32] {
    hash(DEPOSIT_SCHEMA)
}
/// The standard prefix binding of a Simple or Common wallet: `standard_prefix_digest` of the
/// policy wallet crate. It binds the engine kind, executable, asset, both native schemas and the
/// ordered rules, not param values or the offchain suffix.
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
            value_bytes(&transfer_schema_digest())?,
            value_bytes(&deposit_schema_digest())?,
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

/// The checked shape of authored source: its standard prefix and whether it writes state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceShape {
    /// Leading canonical prefix statements of `execute`.
    pub prefix: Vec<String>,
    /// The file is only `use allowit::...;` items and an `execute` that is exactly the prefix
    /// followed by `Ok(())`, so the host runs it in full without compiling it.
    pub canonical_only: bool,
    /// The source calls `allowit::set_state`.
    pub writes_state: bool,
}
/// Check portable source and derive its shape: `scripts/policy_source.py` `standard_prefix` and
/// `writes_state`. This applies the structural gate: one self-contained file, `allowit` only as
/// the path root, no file or environment macros, no `#[path]`, `cfg_attr` or raw pointers, only
/// the `MACROS` and `ATTRIBUTES` allowlists and one
/// `pub fn execute(ctx: &AllowitContext) -> allowit::Result`. The identifier allowlist and the
/// std-only compile remain the server build gate (`policy_source.py` `checked_code` and
/// `host_compile`), which needs `rustc`; a source that is not canonical-only needs that compiled
/// evaluator for full host evaluation.
pub fn source_shape(source: &str) -> Result<SourceShape> {
    let code = gate::checked_code(source)?;
    let (prefix, canonical_only) = gate::standard_prefix(&code)?;
    Ok(SourceShape {
        prefix,
        canonical_only,
        writes_state: gate::writes_state(&code),
    })
}
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
    /// The payment recipient or the deposit vault.
    pub recipient: String,
    /// The gross underlying debit.
    pub amount: i128,
    pub now: u64,
    pub expires_at: u64,
    pub expense: Option<ExpenseBounds>,
    pub args: PolicyParams,
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
            operation: match r.operation {
                OperationKind::Transfer => allowit::AllowitOperation::sep41_transfer,
                OperationKind::Deposit => allowit::AllowitOperation::sep56_deposit,
            },
            asset: allowit::Address::new(r.asset.clone()),
            recipient: allowit::Address::new(r.recipient.clone()),
            amount: r.amount,
            now: r.now,
            expires_at: r.expires_at,
            spent_units: r.expense.as_ref().map_or(0, |e| e.spent_units),
            gas_units: r.expense.as_ref().map_or(0, |e| e.gas_units),
            unpriced: r.expense.is_none(),
            args: r.args.allowit().into(),
        },
    }
}
/// Run one canonical rule call `allowit::<rule>(ctx, ctx.params.get(allowit::<RULE>))?`.
fn run_rule(ctx: &AllowitContext, rule: AllowitRule) -> allowit::Result {
    let value = ctx.params.get(rule.key());
    match rule {
        AllowitRule::transaction_cap => allowit::transaction_cap(ctx, value).map(drop),
        AllowitRule::spent_cap => allowit::spent_cap(ctx, value).map(drop),
        AllowitRule::day_spent_cap => allowit::day_spent_cap(ctx, value).map(drop),
        AllowitRule::day_total_cap => allowit::day_total_cap(ctx, value).map(drop),
        AllowitRule::call_cap => allowit::call_cap(ctx, value).map(drop),
        AllowitRule::recipients => allowit::recipients(ctx, value).map(drop),
        AllowitRule::tokens => allowit::tokens(ctx, value).map(drop),
        AllowitRule::expiry => allowit::expiry(ctx, value).map(drop),
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
    request.args.check_args()?;
    if tier.standard() {
        params.check(tier)?;
    }
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
        // The onchain prefix alone still produces the standard post-flight state.
        allowit::post_flight(&ctx, tier.allowit())
            .map_err(|e| format!("Policy state rejected: {e:?}"))?;
        return Ok(Evaluation::Prefix);
    };
    Ok(Evaluation::Full(PolicyParams::from_allowit(
        &full.map_err(|e| format!("Authored policy denied this exact operation: {e:?}"))?,
    )))
}

/// The structural source gate, ported from `scripts/policy_source.py`.
pub(crate) mod gate {
    use super::*;

    /// `policy_source.py` `MACROS`: the macros authored code may invoke.
    const MACROS: [&str; 6] = [
        "assert",
        "assert_eq",
        "assert_ne",
        "panic",
        "matches",
        "unreachable",
    ];
    /// `policy_source.py` `ATTRIBUTES`: the attributes authored code may use.
    const ATTRIBUTES: [&str; 8] = [
        "allow", "expect", "warn", "deny", "forbid", "inline", "cold", "must_use",
    ];
    /// `policy_source.py` `RUST_KEYWORDS`, which may precede a `!` operator.
    const RUST_KEYWORDS: [&str; 53] = [
        "abstract", "as", "async", "await", "become", "box", "break", "const", "continue", "crate",
        "do", "dyn", "else", "enum", "extern", "false", "final", "fn", "for", "gen", "if", "impl",
        "in", "let", "loop", "macro", "match", "mod", "move", "mut", "override", "priv", "pub",
        "ref", "return", "self", "Self", "static", "struct", "super", "trait", "true", "try",
        "type", "typeof", "union", "unsafe", "unsized", "use", "virtual", "where", "while",
        "yield",
    ];
    fn reject(what: &str) -> String {
        format!("Policy source must be one self-contained, portable file; it uses {what}")
    }
    /// The identifier that starts at `k` (`[A-Za-z_]\w*` at a word start) and its end.
    fn ident_at(chars: &[char], k: usize) -> Option<(String, usize)> {
        let first = *chars.get(k)?;
        if !(first.is_ascii_alphabetic() || first == '_') || (k > 0 && word(chars[k - 1])) {
            return None;
        }
        let mut end = k;
        while end < chars.len() && word(chars[end]) {
            end += 1;
        }
        Some((chars[k..end].iter().collect(), end))
    }
    /// The macro and attribute allowlists of `policy_source.py` `portable`: `name!` (not `!=`)
    /// must name an allowed macro or a keyword, and `#[name` an allowed attribute. Every other
    /// macro, such as `macro_rules!` or `asm!`, and every other attribute, such as `cfg` or
    /// `doc`, rejects.
    fn macros_and_attributes(chars: &[char]) -> Result<()> {
        for k in 0..chars.len() {
            if let Some((name, end)) = ident_at(chars, k) {
                let bang = skip_ws(chars, end);
                if chars.get(bang) == Some(&'!')
                    && chars.get(bang + 1) != Some(&'=')
                    && !RUST_KEYWORDS.contains(&name.as_str())
                    && !MACROS.contains(&name.as_str())
                {
                    return Err(reject(&format!(
                        "macro `{name}!`; only assert!, assert_eq!, assert_ne!, matches!, panic!, unreachable! are allowed"
                    )));
                }
            }
            if chars[k] == '#' {
                let open = skip_ws(chars, k + 1);
                if chars.get(open) != Some(&'[') {
                    continue;
                }
                let mut p = skip_ws(chars, open + 1);
                if starts(chars, p, "r#") {
                    p += 2;
                }
                let first = chars.get(p).copied().unwrap_or(' ');
                if !(first.is_ascii_alphabetic() || first == '_') {
                    continue;
                }
                let mut end = p;
                while end < chars.len() && word(chars[end]) {
                    end += 1;
                }
                let name: String = chars[p..end].iter().collect();
                if !ATTRIBUTES.contains(&name.as_str()) {
                    return Err(reject(&format!("attribute `{name}`")));
                }
            }
        }
        Ok(())
    }
    fn word(c: char) -> bool {
        c.is_alphanumeric() || c == '_'
    }
    fn before_ok(chars: &[char], i: usize) -> bool {
        i == 0 || !(chars[i - 1].is_ascii_alphanumeric() || chars[i - 1] == '_')
    }
    fn starts(chars: &[char], i: usize, text: &str) -> bool {
        (i..)
            .zip(text.chars())
            .all(|(k, c)| chars.get(k) == Some(&c))
    }
    /// `[bc]?r(#*)"` at `i`: the index after the opening quote and the number of hashes.
    fn raw_string(chars: &[char], i: usize) -> Option<(usize, usize)> {
        if !before_ok(chars, i) {
            return None;
        }
        let mut k = i;
        if matches!(chars.get(k), Some('b' | 'c')) {
            k += 1;
        }
        if chars.get(k) != Some(&'r') {
            return None;
        }
        k += 1;
        let start = k;
        while chars.get(k) == Some(&'#') {
            k += 1;
        }
        (chars.get(k) == Some(&'"')).then_some((k + 1, k - start))
    }
    /// `[bc]?"(?:\\[\s\S]|[^"\\])*"` at `i`: the index after the closing quote.
    fn string(chars: &[char], i: usize) -> Option<usize> {
        if !before_ok(chars, i) {
            return None;
        }
        let mut k = i;
        if matches!(chars.get(k), Some('b' | 'c')) {
            k += 1;
        }
        if chars.get(k) != Some(&'"') {
            return None;
        }
        k += 1;
        while k < chars.len() {
            match chars[k] {
                '\\' if k + 1 < chars.len() => k += 2,
                '\\' => return None,
                '"' => return Some(k + 1),
                _ => k += 1,
            }
        }
        None
    }
    /// A char literal at `i`: the index after its closing quote.
    fn char_literal(chars: &[char], i: usize) -> Option<usize> {
        if !before_ok(chars, i) {
            return None;
        }
        let mut k = i;
        if chars.get(k) == Some(&'b') {
            k += 1;
        }
        if chars.get(k) != Some(&'\'') {
            return None;
        }
        k += 1;
        match chars.get(k)? {
            '\\' => {
                k += 1;
                match chars.get(k)? {
                    'x' if chars
                        .get(k + 1..k + 3)
                        .is_some_and(|h| h.iter().all(char::is_ascii_hexdigit)) =>
                    {
                        k += 3
                    }
                    'u' if chars.get(k + 1) == Some(&'{') => {
                        let mut j = k + 2;
                        while chars
                            .get(j)
                            .is_some_and(|c| c.is_ascii_hexdigit() || *c == '_')
                        {
                            j += 1;
                        }
                        let len = j - (k + 2);
                        if (1..=8).contains(&len) && chars.get(j) == Some(&'}') {
                            k = j + 1;
                        } else {
                            // `\\u` without a valid escape is the plain `[^\n]` branch.
                            k += 1;
                        }
                    }
                    '\n' => return None,
                    _ => k += 1,
                }
            }
            '\'' | '\n' => return None,
            _ => k += 1,
        }
        (chars.get(k) == Some(&'\'')).then_some(k + 1)
    }
    /// Source with comments blanked and literals replaced by `0`: `rust_code`.
    pub(crate) fn rust_code(source: &str) -> Result<String> {
        let chars: Vec<char> = source.chars().collect();
        let n = chars.len();
        let mut out = String::new();
        let mut i = 0;
        while i < n {
            if starts(&chars, i, "//") {
                i = (i..n).find(|k| chars[*k] == '\n').unwrap_or(n);
                out.push(' ');
            } else if starts(&chars, i, "/*") {
                let mut depth = 1;
                i += 2;
                while depth > 0 {
                    if i >= n {
                        return Err("Policy source has an unterminated block comment".into());
                    }
                    if starts(&chars, i, "/*") {
                        depth += 1;
                        i += 2;
                    } else if starts(&chars, i, "*/") {
                        depth -= 1;
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                out.push(' ');
            } else if let Some((after, hashes)) = raw_string(&chars, i) {
                let close: String = std::iter::once('"')
                    .chain(std::iter::repeat_n('#', hashes))
                    .collect();
                let close: Vec<char> = close.chars().collect();
                let end = (after..=n.saturating_sub(close.len()))
                    .find(|k| chars[*k..*k + close.len()] == close[..])
                    .ok_or("Policy source has an unterminated raw string")?;
                i = end + close.len();
                out.push_str(" 0 ");
            } else if let Some(end) = string(&chars, i) {
                i = end;
                out.push_str(" 0 ");
            } else if let Some(end) = char_literal(&chars, i) {
                i = end;
                out.push_str(" 0 ");
            } else if chars[i] == '"' || starts(&chars, i, "b\"") || starts(&chars, i, "c\"") {
                return Err("Policy source has an unterminated string".into());
            } else {
                out.push(chars[i]);
                i += 1;
            }
        }
        Ok(out)
    }
    /// Each match of the whole word `name` in `code`, as (start, end) char offsets.
    fn words<'a>(
        chars: &'a [char],
        names: &'a [&str],
    ) -> impl Iterator<Item = (usize, usize)> + 'a {
        let mut i = 0;
        std::iter::from_fn(move || {
            while i < chars.len() {
                if word(chars[i]) && (i == 0 || !word(chars[i - 1])) {
                    let start = i;
                    while i < chars.len() && word(chars[i]) {
                        i += 1;
                    }
                    let text: String = chars[start..i].iter().collect();
                    if names.contains(&text.as_str()) {
                        return Some((start, i));
                    }
                } else {
                    i += 1;
                }
            }
            None
        })
    }
    fn trimmed_before(chars: &[char], start: usize) -> String {
        chars[..start]
            .iter()
            .collect::<String>()
            .trim_end()
            .to_string()
    }
    fn trimmed_after(chars: &[char], end: usize) -> String {
        chars[end..]
            .iter()
            .collect::<String>()
            .trim_start()
            .to_string()
    }
    /// `&\s*mut\b[^;,{}]*\.$` on the text before an `env` field.
    fn mut_borrow_before(before: &str) -> bool {
        let b: Vec<char> = before.chars().collect();
        if b.last() != Some(&'.') {
            return false;
        }
        (0..b.len()).any(|i| {
            if b[i] != '&' {
                return false;
            }
            let mut k = i + 1;
            while k < b.len() && b[k].is_whitespace() {
                k += 1;
            }
            if !starts(&b, k, "mut") || b.get(k + 3).is_some_and(|c| word(*c)) {
                return false;
            }
            b[k + 3..b.len() - 1]
                .iter()
                .all(|c| !matches!(c, ';' | ',' | '{' | '}'))
        })
    }
    fn skip_ws(chars: &[char], mut k: usize) -> usize {
        while k < chars.len() && chars[k].is_whitespace() {
            k += 1;
        }
        k
    }
    /// The structural part of `checked_code`; returns the lexed code.
    pub(crate) fn checked_code(source: &str) -> Result<String> {
        let src: Vec<char> = source.chars().collect();
        // `^\s*(//!|/\*!|#\s*!\s*\[)` in multiline mode.
        for start in
            std::iter::once(0).chain((0..src.len()).filter(|k| src[*k] == '\n').map(|k| k + 1))
        {
            let k = skip_ws(&src, start);
            let inner = starts(&src, k, "//!") || starts(&src, k, "/*!") || {
                src.get(k) == Some(&'#') && {
                    let j = skip_ws(&src, k + 1);
                    src.get(j) == Some(&'!') && src.get(skip_ws(&src, j + 1)) == Some(&'[')
                }
            };
            if inner {
                return Err(
                    "Policy source must not use inner attributes or inner doc comments".into(),
                );
            }
        }
        let code = rust_code(source)?;
        let chars: Vec<char> = code.chars().collect();
        for (start, end) in words(&chars, &["allowit"]) {
            if !trimmed_after(&chars, end).starts_with("::")
                || trimmed_before(&chars, start).ends_with("::")
            {
                return Err("Policy source must use `allowit` only as the path root `allowit::`; it must not rebind it".into());
            }
        }
        for (start, end) in words(
            &chars,
            &[
                "include",
                "include_str",
                "include_bytes",
                "env",
                "option_env",
            ],
        ) {
            let before = trimmed_before(&chars, start);
            let after = trimmed_after(&chars, end);
            let field = before.ends_with('.') && !before.ends_with("..");
            if !field
                || after.starts_with(['.', '('])
                || (after.starts_with('!') && !after.starts_with("!="))
            {
                return Err("Policy source must be one self-contained file; it uses file or environment macro".into());
            }
            if (after.starts_with('=') && !after.starts_with("==")) || mut_borrow_before(&before) {
                return Err(reject("a write to the `env` field"));
            }
        }
        // `#\s*\[\s*path\b`
        for k in (0..chars.len()).filter(|k| chars[*k] == '#') {
            let j = skip_ws(&chars, k + 1);
            if chars.get(j) == Some(&'[') {
                let p = skip_ws(&chars, j + 1);
                if starts(&chars, p, "path") && !chars.get(p + 4).is_some_and(|c| word(*c)) {
                    return Err(
                        "Policy source must be one self-contained file; it uses #[path] attribute"
                            .into(),
                    );
                }
            }
        }
        if words(&chars, &["cfg_attr"]).next().is_some() {
            return Err(
                "Policy source must be one self-contained file; it uses cfg_attr attribute".into(),
            );
        }
        // `\*\s*(?:const|mut)\b|\braw\s+(?:const|mut)\b`
        let pointer = (0..chars.len()).any(|k| {
            let after_word = |p: usize, w: &str| {
                starts(&chars, p, w) && !chars.get(p + w.len()).is_some_and(|c| word(*c))
            };
            if chars[k] == '*' {
                let p = skip_ws(&chars, k + 1);
                return after_word(p, "const") || after_word(p, "mut");
            }
            if starts(&chars, k, "raw") && (k == 0 || !word(chars[k - 1])) {
                let p = skip_ws(&chars, k + 3);
                return p > k + 3 && (after_word(p, "const") || after_word(p, "mut"));
            }
            false
        });
        if pointer {
            return Err(
                "Policy source must be one self-contained file; it uses a raw pointer".into(),
            );
        }
        macros_and_attributes(&chars)?;
        Ok(code)
    }
    /// Match `\bpub\s+fn\s+execute\s*\(\s*ctx\s*:\s*&\s*AllowitContext\s*\)\s*->\s*allowit\s*::\s*Result(?:\s*<\s*\(\s*\)\s*>)?\s*\{`
    /// at `k`; the index after `{`.
    fn execute_at(chars: &[char], k: usize) -> Option<usize> {
        if !starts(chars, k, "pub") || (k > 0 && word(chars[k - 1])) {
            return None;
        }
        let mut p = k + 3;
        let ws1 = |p: usize| {
            let q = skip_ws(chars, p);
            (q > p).then_some(q)
        };
        let lit = |p: usize, t: &str| starts(chars, p, t).then_some(p + t.chars().count());
        p = ws1(p)?;
        p = lit(p, "fn")?;
        p = ws1(p)?;
        p = lit(p, "execute")?;
        for t in [
            "(",
            "ctx",
            ":",
            "&",
            "AllowitContext",
            ")",
            "->",
            "allowit",
            "::",
            "Result",
        ] {
            p = lit(skip_ws(chars, p), t)?;
        }
        let generic = (|| {
            let mut q = p;
            for t in ["<", "(", ")", ">"] {
                q = lit(skip_ws(chars, q), t)?;
            }
            Some(q)
        })();
        if let Some(q) = generic {
            p = q;
        }
        lit(skip_ws(chars, p), "{")
    }
    /// `allowit::<rule>(ctx,ctx.params.get(allowit::<RULE>,?),?)?` on a whitespace-free statement.
    fn prefix_call(statement: &str) -> Option<String> {
        let rest = statement.strip_prefix("allowit::")?;
        let name_len = rest
            .bytes()
            .take_while(|b| b.is_ascii_lowercase() || *b == b'_')
            .count();
        if name_len == 0 {
            return None;
        }
        let (name, rest) = rest.split_at(name_len);
        let rest = rest.strip_prefix("(ctx,ctx.params.get(allowit::")?;
        let key_len = rest
            .bytes()
            .take_while(|b| b.is_ascii_uppercase() || *b == b'_')
            .count();
        if key_len == 0 {
            return None;
        }
        let (key, rest) = rest.split_at(key_len);
        let rest = rest.strip_prefix(',').unwrap_or(rest);
        let rest = rest.strip_prefix(')')?;
        let rest = rest.strip_prefix(',').unwrap_or(rest);
        if rest != ")?" || name.to_uppercase() != key || !PARAM_KEYS.contains(&name) {
            return None;
        }
        Some(name.into())
    }
    /// The standard prefix of lexed code and whether the whole file is canonical-only.
    ///
    /// A file is canonical-only when it is nothing but optional `use allowit::...;` items and
    /// one `execute` whose body is exactly the prefix statements followed by `Ok(())`. Only then
    /// does running the prefix rules on the host equal running the compiled file: any other
    /// item, such as a local `fn Ok` that shadows the prelude, could change what `execute` does.
    pub(crate) fn standard_prefix(code: &str) -> Result<(Vec<String>, bool)> {
        let chars: Vec<char> = code.chars().collect();
        let found: Vec<usize> = (0..chars.len())
            .filter_map(|k| execute_at(&chars, k))
            .collect();
        if found.len() != 1 || words(&chars, &["execute"]).count() != 1 {
            return Err("Policy source must define pub fn execute(ctx: &AllowitContext) -> allowit::Result once".into());
        }
        let body: String = chars[found[0]..].iter().collect();
        let mut rules = vec![];
        let mut consumed = 0;
        for statement in body.split(';') {
            let compact: String = statement.chars().filter(|c| !c.is_whitespace()).collect();
            match prefix_call(&compact) {
                Some(rule) => {
                    rules.push(rule);
                    consumed += statement.len() + 1;
                }
                None => break,
            }
        }
        let rest: String = body[consumed.min(body.len())..]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        let canonical_only = rest == "Ok(())}" && only_allowit_uses_before(&chars, found[0]);
        Ok((rules, canonical_only))
    }
    /// True when the code before `execute` (which ends at `body_start`, after its `{`) is only
    /// `use allowit::...;` items: a use tree of path segments, `::`, `*`, `,` and braces,
    /// without renaming.
    fn only_allowit_uses_before(chars: &[char], body_start: usize) -> bool {
        let Some(signature) = (0..body_start)
            .rev()
            .find(|k| starts(chars, *k, "pub") && execute_at(chars, *k) == Some(body_start))
        else {
            return false;
        };
        let mut k = skip_ws(chars, 0);
        while k < signature {
            if !(starts(chars, k, "use") && !chars.get(k + 3).is_some_and(|c| word(*c))) {
                return false;
            }
            let mut p = skip_ws(chars, k + 3);
            if !(starts(chars, p, "allowit") && !chars.get(p + 7).is_some_and(|c| word(*c))) {
                return false;
            }
            p = skip_ws(chars, p + 7);
            if !starts(chars, p, "::") {
                return false;
            }
            p += 2;
            let tree = p;
            while p < signature && chars[p] != ';' {
                let c = chars[p];
                if !(word(c) || c.is_whitespace() || matches!(c, ':' | '*' | ',' | '{' | '}')) {
                    return false;
                }
                p += 1;
            }
            // A renaming import (`use allowit::x as Ok;`) could shadow a prelude name.
            if words(&chars[tree..p], &["as"]).next().is_some() {
                return false;
            }
            if p >= signature {
                return false;
            }
            k = skip_ws(chars, p + 1);
        }
        k == signature
    }
    /// `\ballowit\s*::\s*(?:r#)?set_state\b` on lexed code.
    pub(crate) fn writes_state(code: &str) -> bool {
        let chars: Vec<char> = code.chars().collect();
        words(&chars, &["allowit"]).any(|(_, end)| {
            let p = skip_ws(&chars, end);
            if !starts(&chars, p, "::") {
                return false;
            }
            let mut q = skip_ws(&chars, p + 2);
            if starts(&chars, q, "r#") {
                q += 2;
            }
            starts(&chars, q, "set_state") && !chars.get(q + 9).is_some_and(|c| word(*c))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const SOURCE: &str = include_str!("../../../crates/custom-policy/policy/policy.rs");

    #[test]
    fn canonical_source_has_the_full_prefix_and_is_canonical_only() {
        let shape = source_shape(SOURCE).unwrap();
        assert_eq!(shape.prefix, PARAM_KEYS.map(String::from).to_vec());
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
        assert_eq!(shape.prefix.len(), PARAM_KEYS.len());
        assert!(!shape.canonical_only);
        let helper = SOURCE.replace(
            "use allowit::prelude::*;",
            "use allowit::prelude::*;\nconst LIMIT: i128 = 5;",
        );
        assert!(!source_shape(&helper).unwrap().canonical_only);
        let renamed = SOURCE.replace(
            "use allowit::prelude::*;",
            "use allowit::prelude::*;\nuse allowit::{transaction_cap as Ok};",
        );
        assert!(!source_shape(&renamed).unwrap().canonical_only);
        let braced = SOURCE.replace(
            "use allowit::prelude::*;",
            "use allowit::{prelude::*, AllowitError};",
        );
        assert!(source_shape(&braced).unwrap().canonical_only);
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
    fn standard_prefix_digest_matches_the_contract_vector() {
        // `standard_prefix_digest_matches_independent_xdr_vector_and_binds_context` in
        // crates/policy-wallet/src/sep56_tests.rs.
        let digest = standard_prefix_digest(
            PolicyTier::Common,
            &[1; 32],
            "CABAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAFNSZ",
            &["spent_cap".into(), "recipients".into()],
        )
        .unwrap();
        assert_eq!(
            digest,
            [
                66, 101, 232, 202, 129, 105, 213, 21, 159, 38, 227, 129, 92, 65, 30, 68, 142, 108,
                9, 16, 21, 190, 226, 11, 50, 204, 7, 142, 89, 244, 155, 255,
            ]
        );
    }
    #[test]
    fn values_roundtrip_through_json_and_contract_encoding() {
        let params = params_from_json(
            &serde_json::json!({"transaction_cap": 5, "recipients": [account_for_seed(&[3; 32])], "operations": "*"}),
            Some(PolicyTier::Common),
        )
        .unwrap();
        let json = serde_json::to_value(&params).unwrap();
        assert_eq!(json["transaction_cap"], serde_json::json!({"Int": "5"}));
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
