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
/// Check portable source and derive its shape: `scripts/policy_source.py` `checked_code`,
/// `standard_prefix` and `writes_state`. The gate accepts exactly the sources that
/// `policy_source.py` accepts: one self-contained file, `allowit` only as the path root, no file
/// or environment macros, no `#[path]`, `cfg_attr` or raw pointers, the macro, attribute and
/// identifier allowlists and one `pub fn execute(ctx: &AllowitContext) -> allowit::Result`.
/// The std-only compile (`policy_source.py` `host_compile`) needs `rustc` and stays in the server
/// build gate; a source that is not canonical-only needs that compiled evaluator for full host
/// evaluation. `tests/policy_vectors.rs` replays vectors that the Python gate produced.
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
    use std::collections::{HashMap, HashSet};

    /// `policy_source.py` `MACROS`: the macros authored code may invoke.
    const MACROS: &[&str] = &[
        "assert",
        "assert_eq",
        "assert_ne",
        "panic",
        "matches",
        "unreachable",
    ];
    /// `policy_source.py` `ATTRIBUTES`: the attributes authored code may use.
    const ATTRIBUTES: &[&str] = &[
        "allow", "expect", "warn", "deny", "forbid", "inline", "cold", "must_use",
    ];
    /// `policy_source.py` `RUST_KEYWORDS`, which may precede a `!` operator.
    const RUST_KEYWORDS: &[&str] = &[
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
    /// `unescape` over a string literal's value: the characters its escapes denote. Only the
    /// braces of a macro message matter, so a surrogate becomes U+FFFD. An escape above U+10FFFF
    /// or without digits rejects, as Python `chr` and `int` raise there.
    fn unescape(content: &[char]) -> Result<String> {
        let mut out = String::new();
        let mut k = 0;
        while k < content.len() {
            if content[k] != '\\' {
                out.push(content[k]);
                k += 1;
                continue;
            }
            let hex = |c: &char| c.is_ascii_hexdigit();
            match content.get(k + 1) {
                Some('x') if content.get(k + 2..k + 4).is_some_and(|h| h.iter().all(hex)) => {
                    let text: String = content[k + 2..k + 4].iter().collect();
                    out.push(char::from(u8::from_str_radix(&text, 16).map_err(err)?));
                    k += 4;
                }
                Some('u')
                    if content.get(k + 2) == Some(&'{') && {
                        let run = content[(k + 3).min(content.len())..]
                            .iter()
                            .take_while(|c| hex(c) || **c == '_')
                            .count();
                        (1..=8).contains(&run) && content.get(k + 3 + run) == Some(&'}')
                    } =>
                {
                    let run = content[k + 3..]
                        .iter()
                        .take_while(|c| hex(c) || **c == '_')
                        .count();
                    let digits: String = content[k + 3..k + 3 + run]
                        .iter()
                        .filter(|c| **c != '_')
                        .collect();
                    let value = u32::from_str_radix(&digits, 16)
                        .map_err(|_| "Policy source has an invalid string escape")?;
                    if value > 0x10FFFF {
                        return Err("Policy source has an invalid string escape".into());
                    }
                    out.push(char::from_u32(value).unwrap_or('\u{FFFD}'));
                    k += 4 + run;
                }
                Some('\n') => {
                    k += 2;
                    while k < content.len() && py_space(content[k]) {
                        k += 1;
                    }
                }
                Some(c) => {
                    out.push(match c {
                        'n' => '\n',
                        'r' => '\r',
                        't' => '\t',
                        '0' => '\0',
                        other => *other,
                    });
                    k += 2;
                }
                None => k += 1,
            }
        }
        Ok(out)
    }
    /// Source with comments blanked and literals replaced by `0`: `rust_code`. Also returns the
    /// value of each string literal, keyed by the offset of its `0` in the code.
    pub(crate) fn rust_code(source: &str) -> Result<(String, HashMap<usize, String>)> {
        let chars: Vec<char> = source.chars().collect();
        let n = chars.len();
        let mut out = String::new();
        let mut strings = HashMap::new();
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
                strings.insert(out.chars().count() + 1, chars[after..end].iter().collect());
                i = end + close.len();
                out.push_str(" 0 ");
            } else if let Some(end) = string(&chars, i) {
                let quote = if chars[i] == '"' { i } else { i + 1 };
                strings.insert(
                    out.chars().count() + 1,
                    unescape(&chars[quote + 1..end - 1])?,
                );
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
        Ok((out, strings))
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
            .trim_end_matches(py_space)
            .to_string()
    }
    fn trimmed_after(chars: &[char], end: usize) -> String {
        chars[end..]
            .iter()
            .collect::<String>()
            .trim_start_matches(py_space)
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
            while k < b.len() && py_space(b[k]) {
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
        while k < chars.len() && py_space(chars[k]) {
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
        let (code, strings) = rust_code(source)?;
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
        portable(&code, &strings)?;
        Ok(code)
    }
    // The rest of `policy_source.py` `portable` and `allowlisted`: the code-level allowlist.
    // Code is ASCII here, so byte offsets equal the character offsets of `rust_code`.

    /// `policy_source.py` `MESSAGE`: the argument index of each macro's optional message.
    const MESSAGE: &[(&str, usize)] = &[
        ("panic", 0),
        ("unreachable", 0),
        ("assert", 1),
        ("assert_eq", 2),
        ("assert_ne", 2),
    ];
    const ALLOWED_KEYWORDS: &[&str] = &[
        "break", "const", "continue", "else", "false", "fn", "for", "if", "in", "let", "loop",
        "match", "mut", "pub", "ref", "return", "true", "use", "while",
    ];
    const INTEGERS: &[&str] = &[
        "i8", "i16", "i32", "i64", "i128", "u8", "u16", "u32", "u64", "u128",
    ];
    const NOT_PORTABLE: &[&str] = &["usize", "isize", "f16", "f32", "f64", "f128"];
    const ERRORS: &[&str] = &[
        "MissingParam",
        "TransactionCapExceeded",
        "SpentCapExceeded",
        "DaySpentCapExceeded",
        "DayTotalCapExceeded",
        "CallCapExceeded",
        "RecipientNotAllowed",
        "TokenNotAllowed",
        "Expired",
        "Unpriced",
        "InvalidParam",
        "InvalidState",
        "Overflow",
        "Unsupported",
        "OperationNotAllowed",
        "Panicked",
    ];
    const VALUES: &[&str] = &["Int", "Bool", "Str", "Addr", "List"];
    const SERVER_FUNCTIONS: &[&str] = &[
        "price",
        "fetch",
        "internet_search",
        "marketplace_search",
        "systemone",
        "request_screening",
        "clear_systemone_context",
    ];
    const SERVER_TYPES: &[&str] = &[
        "AllowitPrice",
        "AllowitFetch",
        "AllowitInternetSearch",
        "AllowitMarketplaceSearch",
        "AllowitRequestScreening",
        "AllowitSystemOne",
    ];
    const STRUCT_FIELDS: &[&str] = &[
        "from",
        "to",
        "amount",
        "price",
        "slip",
        "method",
        "url",
        "data",
        "pubkey",
        "query",
        "id",
        "deny_below",
        "allow_above",
    ];
    const PRELUDE_FUNCTIONS: &[&str] =
        &["drop", "size_of", "size_of_val", "align_of", "align_of_val"];
    const FIELDS: &[&str] = &[
        "env",
        "params",
        "request",
        "operation",
        "asset",
        "recipient",
        "amount",
        "now",
        "expires_at",
        "spent_units",
        "gas_units",
        "unpriced",
        "args",
    ];
    /// `FIELD_METHODS`: `get` only on the `params` or `args` field.
    const FIELD_NAMES: &[&str] = &["params", "args"];
    const METHODS: &[&str] = &[
        "clone",
        "eq",
        "ne",
        "lt",
        "le",
        "gt",
        "ge",
        "cmp",
        "partial_cmp",
        "min",
        "max",
        "clamp",
        "is_some",
        "is_none",
        "is_some_and",
        "is_none_or",
        "is_ok",
        "is_err",
        "is_ok_and",
        "is_err_and",
        "ok",
        "err",
        "ok_or",
        "unwrap",
        "expect",
        "unwrap_or",
        "unwrap_or_default",
        "copied",
        "cloned",
        "as_ref",
        "xor",
        "or",
        "and",
        "checked_add",
        "checked_sub",
        "checked_mul",
        "checked_div",
        "checked_rem",
        "checked_neg",
        "checked_abs",
        "checked_pow",
        "saturating_add",
        "saturating_sub",
        "saturating_mul",
        "saturating_pow",
        "pow",
        "abs",
        "abs_diff",
        "unsigned_abs",
        "signum",
        "is_positive",
        "is_negative",
        "div_euclid",
        "rem_euclid",
        "is_lt",
        "is_le",
        "is_gt",
        "is_ge",
        "is_eq",
        "is_ne",
        "reverse",
        "then_some",
        "get",
    ];
    const OPERAND_END: &[&str] = &[")", "]", "?", "true", "false"];

    /// The name lists that `policy_source.py` builds from the constants above.
    struct Names {
        allowit_types: HashSet<String>,
        types: HashSet<String>,
        constructors: HashSet<String>,
        primitives: HashSet<String>,
        function_paths: HashSet<String>,
        paths: HashSet<String>,
    }
    fn lists() -> &'static Names {
        static NAMES: std::sync::OnceLock<Names> = std::sync::OnceLock::new();
        NAMES.get_or_init(|| {
            let set = |items: Vec<String>| items.into_iter().collect::<HashSet<_>>();
            let functions: Vec<String> = PARAM_KEYS
                .iter()
                .chain(["param", "arg", "get_state", "set_state"].iter())
                .chain(SERVER_FUNCTIONS.iter())
                .map(|s| s.to_string())
                .collect();
            let mut allowit_types: Vec<String> = [
                "AllowitContext",
                "AllowitError",
                "AllowitOperation",
                "AllowitRequest",
                "AllowitRule",
                "AllowitValue",
                "Address",
                "Result",
                "String",
                "Vec",
                "DAY",
            ]
            .map(String::from)
            .to_vec();
            allowit_types.extend(PARAM_KEYS.iter().map(|k| k.to_uppercase()));
            allowit_types.extend(SERVER_TYPES.iter().map(|t| t.to_string()));
            let mut types = allowit_types.clone();
            types.extend(["Option", "Some", "None", "Ok", "Err"].map(String::from));
            let mut constructors: Vec<String> = [
                "Some",
                "Ok",
                "Err",
                "Option::Some",
                "Result::Ok",
                "Result::Err",
            ]
            .map(String::from)
            .to_vec();
            for v in VALUES {
                for prefix in ["", "allowit::"] {
                    constructors.push(format!("{prefix}AllowitValue::{v}"));
                }
            }
            let mut primitives: Vec<String> = INTEGERS.iter().map(|t| t.to_string()).collect();
            primitives.extend(["bool", "char", "str", "_"].map(String::from));
            let mut function_paths: Vec<String> =
                functions.iter().map(|f| format!("allowit::{f}")).collect();
            for t in INTEGERS {
                for f in ["from", "try_from"] {
                    function_paths.push(format!("{t}::{f}"));
                }
            }
            function_paths.extend(["core::cmp::min", "core::cmp::max"].map(String::from));
            let mut paths = function_paths.clone();
            paths.extend(allowit_types.iter().map(|t| format!("allowit::{t}")));
            paths.push("allowit::prelude".into());
            let rules: Vec<&str> = PARAM_KEYS.to_vec();
            let enums: [(&str, &[&str]); 4] = [
                ("AllowitOperation", &["sep41_transfer", "sep56_deposit"]),
                ("AllowitError", ERRORS),
                ("AllowitRule", &rules),
                ("AllowitValue", VALUES),
            ];
            for (name, variants) in enums {
                for variant in variants {
                    for prefix in ["", "allowit::"] {
                        paths.push(format!("{prefix}{name}::{variant}"));
                    }
                }
            }
            paths.extend(
                ["Option::Some", "Option::None", "Result::Ok", "Result::Err"].map(String::from),
            );
            for t in INTEGERS {
                for c in ["MAX", "MIN"] {
                    paths.push(format!("{t}::{c}"));
                }
            }
            paths.push("core::cmp::Ordering".into());
            for o in ["Less", "Equal", "Greater"] {
                paths.push(format!("core::cmp::Ordering::{o}"));
            }
            Names {
                allowit_types: set(allowit_types),
                types: set(types),
                constructors: set(constructors),
                primitives: set(primitives),
                function_paths: set(function_paths),
                paths: set(paths),
            }
        })
    }
    /// Python `str.isspace` for one character: Unicode whitespace plus the ASCII separators.
    fn py_space(c: char) -> bool {
        c.is_whitespace() || ('\x1c'..='\x1f').contains(&c)
    }
    fn ascii_word(b: u8) -> bool {
        b.is_ascii_alphanumeric() || b == b'_'
    }
    /// `IDENT` fullmatch: `(?:r#)?[A-Za-z_]\w*`.
    fn is_ident(token: &str) -> bool {
        let t = token.strip_prefix("r#").unwrap_or(token).as_bytes();
        t.first()
            .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_')
            && t.iter().all(|b| ascii_word(*b))
    }
    fn strip_raw(token: &str) -> &str {
        token.strip_prefix("r#").unwrap_or(token)
    }
    fn keyword(token: &str) -> bool {
        RUST_KEYWORDS.contains(&token)
    }
    fn open(token: &str) -> bool {
        matches!(token, "(" | "[" | "{")
    }
    fn close(token: &str) -> bool {
        matches!(token, ")" | "]" | "}")
    }
    /// `NUMBER` fullmatch: an integer literal with an optional fixed-width suffix.
    fn number(token: &str) -> bool {
        let suffix = |rest: &str| rest.is_empty() || INTEGERS.contains(&rest);
        for (prefix, digit) in [
            ("0x", u8::is_ascii_hexdigit as fn(&u8) -> bool),
            ("0o", |b: &u8| (b'0'..=b'7').contains(b)),
            ("0b", |b: &u8| matches!(b, b'0' | b'1')),
        ] {
            if let Some(rest) = token.strip_prefix(prefix) {
                let n = rest.bytes().take_while(|b| digit(b) || *b == b'_').count();
                if n > 0 && suffix(&rest[n..]) {
                    return true;
                }
            }
        }
        let n = token
            .bytes()
            .take_while(|b| b.is_ascii_digit() || *b == b'_')
            .count();
        token.as_bytes().first().is_some_and(u8::is_ascii_digit) && suffix(&token[n..])
    }
    /// `TOKEN.finditer`: each token of ASCII code and its start offset.
    fn tokens(code: &str) -> Vec<(usize, String)> {
        let b = code.as_bytes();
        let word_end = |mut k: usize| {
            while k < b.len() && ascii_word(b[k]) {
                k += 1;
            }
            k
        };
        let mut out = vec![];
        let mut i = 0;
        while i < b.len() {
            let c = b[i];
            let end = if code[i..].starts_with("r#")
                && b.get(i + 2)
                    .is_some_and(|x| x.is_ascii_alphabetic() || *x == b'_')
            {
                word_end(i + 2)
            } else if c.is_ascii_alphabetic() || c == b'_' {
                word_end(i + 1)
            } else if ["::", "=>", "->", "||"]
                .iter()
                .any(|t| code[i..].starts_with(t))
            {
                i + 2
            } else if c == b'$'
                || c.is_ascii_digit()
                || (c == b'\'' && b.get(i + 1).is_some_and(|x| ascii_word(*x)))
            {
                word_end(i + 1)
            } else if py_space(c as char) {
                i += 1;
                continue;
            } else {
                i + 1
            };
            out.push((i, code[i..end].to_string()));
            i = end;
        }
        out
    }
    /// `after_generics`: the index after the generic arguments that open at `tokens[j]`.
    fn after_generics(tokens: &[String], j: usize) -> Result<usize> {
        let mut depth = 0i64;
        for (k, token) in tokens.iter().enumerate().skip(j) {
            depth += i64::from(token == "<") - i64::from(token == ">");
            if depth == 0 {
                return Ok(k + 1);
            }
        }
        Err(reject("unterminated generic arguments"))
    }
    /// `after_brackets`: the index after the bracket group that opens at `tokens[j]`.
    fn after_brackets(tokens: &[String], j: usize) -> Result<usize> {
        let mut depth = 0i64;
        for (k, token) in tokens.iter().enumerate().skip(j) {
            depth += i64::from(open(token)) - i64::from(close(token));
            if depth == 0 {
                return Ok(k + 1);
            }
        }
        Err(reject("an unterminated attribute"))
    }
    /// `operand`: the token ends an operand.
    fn operand(token: &str) -> bool {
        OPERAND_END.contains(&token)
            || token.as_bytes().first().is_some_and(u8::is_ascii_digit)
            || (is_ident(token) && !keyword(token))
    }
    /// Python `tokens[k]`, where a negative index counts from the end.
    fn at(tokens: &[String], k: isize) -> &str {
        let k = if k < 0 { tokens.len() as isize + k } else { k };
        if k < 0 {
            return "";
        }
        tokens.get(k as usize).map_or("", String::as_str)
    }
    /// `declared`: the lowercase names the file declares.
    fn declared(tokens: &[String]) -> HashSet<String> {
        let mut names = HashSet::new();
        let n = tokens.len();
        let bind = |names: &mut HashSet<String>, k: usize| {
            let token = tokens[k].as_str();
            if is_ident(token)
                && !keyword(token)
                && !token.starts_with(|c: char| c.is_ascii_uppercase())
                && at(tokens, k as isize - 1) != "::"
                && !matches!(at(tokens, k as isize + 1), "(" | "::" | "{" | "!")
            {
                names.insert(strip_raw(token).to_string());
            }
        };
        let pattern = |names: &mut HashSet<String>, mut k: usize, stops: &[&str]| {
            let mut depth = 0i64;
            while k < n && !(depth == 0 && stops.contains(&tokens[k].as_str())) {
                depth += i64::from(open(&tokens[k])) - i64::from(close(&tokens[k]));
                if depth < 0 {
                    return;
                }
                bind(names, k);
                k += 1;
            }
        };
        for k in 0..n.saturating_sub(1) {
            let token = tokens[k].as_str();
            if token == "fn" || token == "const" {
                names.insert(strip_raw(&tokens[k + 1]).to_string());
            }
            if token == "let" {
                pattern(&mut names, k + 1, &["=", ";", ":"]);
            } else if token == "for" {
                pattern(&mut names, k + 1, &["in"]);
            } else if token == "fn" {
                let Some(start) = (k..n).find(|j| tokens[*j] == "(") else {
                    continue;
                };
                let mut depth = 0i64;
                for (j, t) in tokens.iter().enumerate().take(n).skip(start) {
                    depth += i64::from(open(t)) - i64::from(close(t));
                    if depth == 0 {
                        break;
                    }
                    if depth == 1 && (t == "(" || t == ",") {
                        pattern(&mut names, j + 1, &[":", ",", ")"]);
                    }
                }
            } else if token == "=>" {
                let mut depth = 0i64;
                let mut found = vec![];
                for j in (0..k).rev() {
                    let t = tokens[j].as_str();
                    depth += i64::from(matches!(t, ")" | "]")) - i64::from(matches!(t, "(" | "["));
                    if depth == 0 && matches!(t, "," | "{" | "}") {
                        break;
                    }
                    if depth == 0 && t == "if" {
                        found.clear();
                    }
                    found.push(j);
                }
                for j in found {
                    bind(&mut names, j);
                }
            }
        }
        names
    }
    /// `uses`: check the `use` declaration at `tokens[i]`; its imported names and the next index.
    fn uses(tokens: &[String], i: usize) -> Result<(Vec<String>, usize)> {
        let end = (i..tokens.len())
            .find(|k| tokens[*k] == ";")
            .unwrap_or(tokens.len());
        let tree: String = tokens[(i + 1).min(end)..end].concat();
        if tree == "allowit::prelude::*" {
            return Ok((vec![], end + 1));
        }
        let names: Vec<String> = if let Some(inner) = tree
            .strip_prefix("allowit::{")
            .and_then(|t| t.strip_suffix('}'))
        {
            inner.split(',').map(String::from).collect()
        } else if let Some(name) = tree.strip_prefix("allowit::") {
            vec![name.to_string()]
        } else {
            vec![]
        };
        let names: Vec<String> = names.into_iter().filter(|n| !n.is_empty()).collect();
        if names.is_empty() || names.iter().any(|n| !lists().allowit_types.contains(n)) {
            return Err(reject(&format!(
                "`use {tree}`; only `use allowit::prelude::*` and `allowit` types may be imported"
            )));
        }
        Ok((names, end + 1))
    }
    /// `allowlisted`: every identifier, path, method, field and literal is on the allowlist.
    fn allowlisted(code: &str) -> Result<()> {
        if !code.is_ascii() {
            return Err(reject("a non-ASCII identifier"));
        }
        let lists = lists();
        let tokens: Vec<String> = tokens(code).into_iter().map(|(_, t)| t).collect();
        let n = tokens.len();
        let tok = |k: usize| tokens.get(k).map_or("", String::as_str);
        let local_fns: HashSet<&str> = (0..n.saturating_sub(1))
            .filter(|k| tokens[*k] == "fn")
            .map(|k| strip_raw(&tokens[k + 1]))
            .collect();
        let local_names = declared(&tokens);
        let mut reserved: Vec<&&str> = FIELD_NAMES
            .iter()
            .filter(|f| local_names.contains(**f))
            .collect();
        reserved.sort();
        if let Some(name) = reserved.first() {
            return Err(reject(&format!(
                "the name `{name}` for a binding or function; it is reserved for the context field"
            )));
        }
        let mut defined: HashSet<String> = (0..n.saturating_sub(1))
            .filter(|k| tokens[*k] == "const" && is_ident(&tokens[k + 1]))
            .map(|k| tokens[k + 1].clone())
            .collect();
        let mut i = 0;
        while i < n {
            let token = tokens[i].as_str();
            let before = if i > 0 { tokens[i - 1].as_str() } else { "" };
            let after = tok(i + 1);
            if token == "#" && after == "[" {
                i = after_brackets(&tokens, i + 1)?;
                continue;
            }
            if token == "use" {
                let (imported, next) = uses(&tokens, i)?;
                defined.extend(imported);
                i = next;
                continue;
            }
            if token.as_bytes()[0].is_ascii_digit() {
                if before != "."
                    && (!number(token)
                        || (after == "." && tok(i + 2) != "." && !is_ident(tok(i + 2))))
                {
                    return Err(reject(&format!(
                        "the literal `{token}`; only integer literals with fixed-width suffixes are portable"
                    )));
                }
                i += 1;
                continue;
            }
            if token == "::" {
                return Err(reject("a path that does not start at an allowed name"));
            }
            if token == "|" || token == "||" {
                if !operand(before) {
                    return Err(reject(
                        "a closure, which can become a function pointer whose address differs between the backends",
                    ));
                }
                i += 1;
                continue;
            }
            if !is_ident(token) {
                i += 1;
                continue;
            }
            let name = strip_raw(token);
            if token == name && keyword(name) {
                if !ALLOWED_KEYWORDS.contains(&name) {
                    return Err(reject(&format!("the keyword `{name}`")));
                }
                if name == "fn" && !is_ident(after) {
                    return Err(reject(
                        "a function pointer type, whose address differs between the backends",
                    ));
                }
                i += 1;
                continue;
            }
            if after == "!" && tok(i + 2) != "=" {
                i += 1;
                continue;
            }
            if before == "." && (i < 2 || tokens[i - 2] != ".") {
                if after == "(" || after == "::" {
                    if !METHODS.contains(&name) {
                        return Err(reject(&format!(
                            "the method `{name}`, which is not on the portable allowlist"
                        )));
                    }
                    if name == "get"
                        && (i < 3
                            || !FIELD_NAMES.contains(&tokens[i - 2].as_str())
                            || tokens[i - 3] != ".")
                    {
                        return Err(reject(
                            "the method `get` other than on the field `.params` or `.args`",
                        ));
                    }
                } else if !FIELDS.contains(&name) {
                    return Err(reject(&format!(
                        "the field `{name}`, which is not on the portable allowlist"
                    )));
                }
                i += 1;
                continue;
            }
            let mut segments = vec![name.to_string()];
            let mut j = i + 1;
            while tok(j) == "::" && j + 1 < n && is_ident(&tokens[j + 1]) {
                segments.push(strip_raw(&tokens[j + 1]).to_string());
                j += 2;
            }
            let turbofish = tok(j) == "::" && tok(j + 1) == "<";
            if segments.len() > 1 || turbofish {
                let path = segments.join("::");
                if !lists.paths.contains(&path) {
                    return Err(reject(&format!(
                        "the path `{path}`, which is not on the portable allowlist"
                    )));
                }
                let call = if turbofish {
                    after_generics(&tokens, j + 1)?
                } else {
                    j
                };
                if (lists.function_paths.contains(&path) || lists.constructors.contains(&path))
                    && tok(call) != "("
                {
                    return Err(reject(&format!(
                        "the function `{path}` as a value, whose address differs between the backends"
                    )));
                }
                i = if turbofish { j + 1 } else { j };
                continue;
            }
            if STRUCT_FIELDS.contains(&name) && after == ":" && tok(i + 2) != ":" {
                i += 1;
                continue;
            }
            if local_fns.contains(name) && after != "(" && before != "fn" {
                return Err(reject(&format!(
                    "the function `{name}` as a value, whose address differs between the backends"
                )));
            } else if name.starts_with(|c: char| c.is_ascii_uppercase()) {
                if !lists.types.contains(name) && !defined.contains(name) {
                    return Err(reject(&format!(
                        "the name `{name}`, which is not on the portable allowlist"
                    )));
                }
                if lists.constructors.contains(name) && after != "(" {
                    return Err(reject(&format!(
                        "the constructor `{name}` as a value, whose address differs between the backends"
                    )));
                }
            } else if NOT_PORTABLE.contains(&name) {
                return Err(reject(&format!(
                    "the type `{name}`, whose width or representation differs between the backends"
                )));
            } else if PRELUDE_FUNCTIONS.contains(&name) {
                return Err(reject(&format!(
                    "the prelude function `{name}`, which can observe a pointer width or layout"
                )));
            } else if !local_names.contains(name) && !lists.primitives.contains(name) {
                return Err(reject(&format!(
                    "the name `{name}`, which the file does not declare"
                )));
            }
            i += 1;
        }
        Ok(())
    }
    /// `macro_args`: the top-level comma-separated token groups of the macro arguments at `i`.
    fn macro_args(tokens: &[String], i: usize) -> Result<Vec<Vec<String>>> {
        let end = after_brackets(tokens, i)?;
        let mut groups: Vec<Vec<String>> = vec![vec![]];
        let mut depth = 0i64;
        for token in &tokens[i + 1..end - 1] {
            depth += i64::from(open(token)) - i64::from(close(token));
            if depth == 0 && token == "," {
                groups.push(vec![]);
            } else {
                groups.last_mut().unwrap().push(token.clone());
            }
        }
        Ok(groups)
    }
    /// `plain_braces`: a macro message admits only `{}`, `{:?}`, `{{` and `}}`.
    fn plain_braces(value: &str) -> Result<()> {
        let v: Vec<char> = value.chars().collect();
        let mut i = 0;
        while i < v.len() {
            let start = i;
            if (v[i] == '{' && v.get(i + 1) == Some(&'{'))
                || (v[i] == '}' && v.get(i + 1) == Some(&'}'))
            {
                i += 2;
            } else if v[i] == '{' {
                i += 1;
                while i < v.len() && v[i] != '{' && v[i] != '}' {
                    i += 1;
                }
                if v.get(i) == Some(&'}') {
                    i += 1;
                }
            } else if v[i] == '}' {
                i += 1;
            } else {
                i += 1;
                continue;
            }
            let brace: String = v[start..i].iter().collect();
            if !["{{", "}}", "{}", "{:?}"].contains(&brace.as_str()) {
                return Err(reject(&format!(
                    "the format placeholder `{brace}`; only `{{}}` and `{{:?}}` are portable"
                )));
            }
        }
        Ok(())
    }
    /// `[{,]\s*\.\.(?![=.])\s*[^\s}\]),]`: struct update syntax.
    fn struct_update(b: &[u8]) -> bool {
        let skip = |mut k: usize| {
            while k < b.len() && py_space(b[k] as char) {
                k += 1;
            }
            k
        };
        (0..b.len()).any(|p| {
            if !matches!(b[p], b'{' | b',') {
                return false;
            }
            let q = skip(p + 1);
            if b.get(q) != Some(&b'.') || b.get(q + 1) != Some(&b'.') {
                return false;
            }
            if matches!(b.get(q + 2), Some(b'=' | b'.')) {
                return false;
            }
            let r = skip(q + 2);
            b.get(r)
                .is_some_and(|c| !py_space(*c as char) && !matches!(c, b'}' | b']' | b')' | b','))
        })
    }
    /// The ends of one `&\s*(?:'\w+\s*)?(?:mut\s+)?` unit that starts at `p`.
    fn borrow_unit_ends(b: &[u8], p: usize) -> Vec<usize> {
        let mut ends = vec![];
        if b.get(p) != Some(&b'&') {
            return ends;
        }
        let spaces = |k: usize| {
            let mut out = vec![k];
            let mut k = k;
            while k < b.len() && py_space(b[k] as char) {
                k += 1;
                out.push(k);
            }
            out
        };
        for q in spaces(p + 1) {
            let mut lifetimes = vec![q];
            if b.get(q) == Some(&b'\'') {
                let mut w = q + 1;
                while w < b.len() && ascii_word(b[w]) {
                    w += 1;
                    lifetimes.extend(spaces(w));
                }
            }
            for l in lifetimes {
                ends.push(l);
                if b[l.min(b.len())..].starts_with(b"mut") {
                    let after: Vec<usize> = spaces(l + 3).into_iter().skip(1).collect();
                    ends.extend(after);
                }
            }
        }
        ends.sort_unstable();
        ends.dedup();
        ends
    }
    /// `re.sub(r"(?:&\s*(?:'\w+\s*)?(?:mut\s+)?)+$", "", text)`.
    fn strip_borrows(text: &str) -> &str {
        let b = text.as_bytes();
        for s in 0..b.len() {
            let mut frontier = vec![s];
            while !frontier.is_empty() {
                let mut next: Vec<usize> = frontier
                    .iter()
                    .flat_map(|p| borrow_unit_ends(b, *p))
                    .collect();
                if next.contains(&b.len()) {
                    return &text[..s];
                }
                next.sort_unstable();
                next.dedup();
                frontier = next;
            }
        }
        text
    }
    fn py_rstrip(text: &str) -> &str {
        text.trim_end_matches(py_space)
    }
    /// `\bAllowitContext\s*\{` outside a return type: a context struct expression or pattern.
    fn context_struct(code: &str) -> bool {
        let chars: Vec<char> = code.chars().collect();
        words(&chars, &["AllowitContext"]).any(|(start, end)| {
            if chars.get(skip_ws(&chars, end)) != Some(&'{') {
                return false;
            }
            let before = py_rstrip(strip_borrows(py_rstrip(&code[..start])));
            !before.ends_with("->")
        })
    }
    /// `\.\s*(?:params|args)\s*\.\s*\d`: a tuple field of params or args.
    fn map_field(b: &[u8]) -> bool {
        let skip = |mut k: usize| {
            while k < b.len() && py_space(b[k] as char) {
                k += 1;
            }
            k
        };
        (0..b.len()).any(|p| {
            if b[p] != b'.' {
                return false;
            }
            let q = skip(p + 1);
            let Some(len) = ["params", "args"]
                .iter()
                .find(|f| b[q..].starts_with(f.as_bytes()))
                .map(|f| f.len())
            else {
                return false;
            };
            let r = skip(q + len);
            if b.get(r) != Some(&b'.') {
                return false;
            }
            b.get(skip(r + 1)).is_some_and(u8::is_ascii_digit)
        })
    }
    /// `portable` after its macro and attribute checks, then `allowlisted`.
    pub(crate) fn portable(code: &str, strings: &HashMap<usize, String>) -> Result<()> {
        // Every non-ASCII code character rejects in `allowlisted`; checking first keeps the
        // byte and character offsets equal below.
        if !code.is_ascii() {
            return Err(reject("a non-ASCII identifier"));
        }
        let b = code.as_bytes();
        if struct_update(b) {
            return Err(reject("struct update syntax `..`"));
        }
        if context_struct(code) {
            return Err(reject("a struct expression or pattern of `AllowitContext`"));
        }
        if map_field(b) {
            return Err(reject(
                "the map inside params or args; read them with `.get(key)`",
            ));
        }
        let spans = tokens(code);
        let toks: Vec<String> = spans.iter().map(|(_, t)| t.clone()).collect();
        for k in 0..toks.len().saturating_sub(2) {
            let name = strip_raw(&toks[k]);
            let Some((_, index)) = MESSAGE.iter().find(|(m, _)| *m == name) else {
                continue;
            };
            if toks[k + 1] != "!" || !open(&toks[k + 2]) {
                continue;
            }
            let args = macro_args(&toks, k + 2)?;
            let message: &[String] = args.get(*index).map_or(&[], Vec::as_slice);
            if !(message.is_empty() || message == ["0"]) {
                return Err(reject(&format!(
                    "a `{name}!` message that is not one string literal"
                )));
            }
            if !message.is_empty() {
                let at = k + 3 + args[..*index].iter().map(|g| g.len() + 1).sum::<usize>();
                plain_braces(strings.get(&spans[at].0).map_or("", String::as_str))?;
            }
        }
        for pair in toks.windows(2) {
            let (before, token) = (pair[0].as_str(), pair[1].as_str());
            if token == "["
                && (matches!(before, ")" | "]" | "?")
                    || before.as_bytes()[0].is_ascii_digit()
                    || (is_ident(before) && !keyword(before)))
            {
                return Err(reject("indexing, whose index is a pointer-width `usize`"));
            }
        }
        allowlisted(code)
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
            let compact: String = statement.chars().filter(|c| !py_space(*c)).collect();
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
            .filter(|c| !py_space(*c))
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
                if !(word(c) || py_space(c) || matches!(c, ':' | '*' | ',' | '{' | '}')) {
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
