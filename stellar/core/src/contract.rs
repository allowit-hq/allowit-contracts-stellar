//! Exact native encodings of the policy wallet interface, custody layout 4.
//!
//! Each encoder emits the `ScVal` that the contract type of `crates/protocol` and
//! `crates/policy-wallet` decodes: structs are symbol-keyed maps in key order, unit enum variants
//! are one-symbol vectors and `Option` is `Void` or the value.
use crate::*;

/// Custody layout this crate reads and writes.
pub const CONTRACT_VERSION: u32 = 4;
/// Most canonical bytes of the native operation arguments.
pub const MAX_ARGUMENT_BYTES: usize = 1024;
/// Most canonical bytes of the expense bounds.
pub const MAX_EXPENSE_BYTES: usize = 1024;

pub(crate) fn struct_value(entries: Vec<(&str, ScVal)>) -> Result<ScVal> {
    value_map(entries)
}
fn bytes_of(value: &ScVal) -> Result<Vec<u8>> {
    value.to_xdr(limits()).map_err(err)
}
fn option<T>(value: Option<T>, f: impl FnOnce(T) -> Result<ScVal>) -> Result<ScVal> {
    value.map(f).transpose().map(|v| v.unwrap_or(ScVal::Void))
}
fn string(value: &ScVal) -> Result<String> {
    match value {
        ScVal::String(v) => String::from_utf8(v.0.to_vec()).map_err(err),
        _ => Err("Expected contract string".into()),
    }
}
fn boolean(value: &ScVal) -> Result<bool> {
    match value {
        ScVal::Bool(v) => Ok(*v),
        _ => Err("Expected contract boolean".into()),
    }
}
fn u32_field(value: &ScVal) -> Result<u32> {
    match value {
        ScVal::U32(v) => Ok(*v),
        _ => Err("Expected contract u32".into()),
    }
}
fn u64_field(value: &ScVal) -> Result<u64> {
    match value {
        ScVal::U64(v) => Ok(*v),
        _ => Err("Expected contract u64".into()),
    }
}
fn symbol_text(value: &ScVal) -> Result<String> {
    match value {
        ScVal::Symbol(v) => String::from_utf8(v.0.to_vec()).map_err(err),
        _ => Err("Expected contract symbol".into()),
    }
}
/// Require exactly these struct keys, so a value of another layout cannot decode.
fn exact_keys(value: &ScVal, keys: &[&str]) -> Result<()> {
    let ScVal::Map(Some(map)) = value else {
        return Err("Expected contract record".into());
    };
    let mut sorted: Vec<&str> = keys.to_vec();
    sorted.sort_unstable();
    let actual: Vec<_> = map
        .iter()
        .map(|e| match &e.key {
            ScVal::Symbol(k) => Ok(k.0.as_slice()),
            _ => Err("Contract record keys must be symbols".to_string()),
        })
        .collect::<Result<_>>()?;
    if actual.len() != sorted.len() || actual.iter().zip(&sorted).any(|(a, b)| *a != b.as_bytes()) {
        return Err("Contract record fields differ from layout 4".into());
    }
    Ok(())
}

/// `AllowitSep41TransferArgs` canonical XDR.
pub fn transfer_args(token: &str, from: &str, to: &str, amount: i128) -> Result<Vec<u8>> {
    bytes_of(&struct_value(vec![
        ("amount", i128_value(amount)),
        ("from", ScVal::Address(address(from)?)),
        ("to", ScVal::Address(address(to)?)),
        ("token", ScVal::Address(address(token)?)),
    ])?)
}
/// `AllowitSep56DepositArgs` canonical XDR.
pub fn deposit_args(d: &Deposit) -> Result<Vec<u8>> {
    bytes_of(&struct_value(vec![
        ("assets", i128_value(d.assets)),
        ("from", ScVal::Address(address(&d.from)?)),
        ("min_shares", i128_value(d.min_shares)),
        ("operator", ScVal::Address(address(&d.operator)?)),
        ("receiver", ScVal::Address(address(&d.receiver)?)),
        ("vault", ScVal::Address(address(&d.vault)?)),
    ])?)
}
/// `AllowitExpenseBounds` canonical XDR for the wallet asset.
pub fn expense_bounds(asset: &str, e: &ExpenseBounds) -> Result<Vec<u8>> {
    bytes_of(&struct_value(vec![
        ("asset", ScVal::Address(address(asset)?)),
        ("conversion_units", i128_value(e.conversion_units)),
        ("day", ScVal::U64(e.day)),
        ("decimals", ScVal::U32(7)),
        ("gas_units", i128_value(e.gas_units)),
        ("max_fee_stroops", ScVal::U32(e.max_fee_stroops)),
        ("observed_ledger", ScVal::U32(e.observed_ledger)),
        ("spent_units", i128_value(e.spent_units)),
    ])?)
}
/// `AllowitPolicyInvocation` for one native operation.
pub fn invocation(module_digest: &[u8; 32], schema: &[u8; 32], arguments: &[u8]) -> Result<ScVal> {
    if arguments.len() > MAX_ARGUMENT_BYTES {
        return Err("Native operation arguments exceed the contract bound".into());
    }
    struct_value(vec![
        ("argument_schema_digest", value_bytes(schema)?),
        ("arguments", value_bytes(arguments)?),
        ("entrypoint", value_symbol("execute")?),
        ("module_digest", value_bytes(module_digest)?),
    ])
}
/// Every field of one `AllowitExecutionRequest`.
pub struct ExecutionPacket<'a> {
    pub policy_instance: &'a [u8; 32],
    pub source_hash: &'a [u8; 32],
    pub operation_id: &'a [u8; 32],
    pub nonce: u64,
    pub deployment_version: u64,
    pub expires_at: u64,
    pub invocation: ScVal,
    pub expense: Option<Vec<u8>>,
    pub args: &'a PolicyParams,
}
/// `AllowitExecutionRequest`.
pub fn execution_request(p: ExecutionPacket) -> Result<ScVal> {
    if p.expense
        .as_ref()
        .is_some_and(|e| e.len() > MAX_EXPENSE_BYTES)
    {
        return Err("Expense bounds exceed the contract bound".into());
    }
    struct_value(vec![
        ("args", p.args.scval()?),
        ("deployment_version", ScVal::U64(p.deployment_version)),
        ("expense", option(p.expense, |e| value_bytes(&e))?),
        ("expires_at", ScVal::U64(p.expires_at)),
        ("invocation", p.invocation),
        ("nonce", ScVal::U64(p.nonce)),
        ("operation_id", value_bytes(p.operation_id)?),
        ("policy_instance", value_bytes(p.policy_instance)?),
        ("source_hash", value_bytes(p.source_hash)?),
    ])
}

/// `AllowitTransferReceipt`, returned by `execute` for both operations. A deposit reports its
/// underlying debit to the vault.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransferReceipt {
    pub operation_id: [u8; 32],
    pub token: String,
    pub from: String,
    pub to: String,
    pub amount: i128,
    pub nonce: u64,
    pub deployment_version: u64,
}
impl TransferReceipt {
    pub fn scval(&self) -> Result<ScVal> {
        struct_value(vec![
            ("amount", i128_value(self.amount)),
            ("deployment_version", ScVal::U64(self.deployment_version)),
            ("from", ScVal::Address(address(&self.from)?)),
            ("nonce", ScVal::U64(self.nonce)),
            ("operation_id", value_bytes(&self.operation_id)?),
            ("to", ScVal::Address(address(&self.to)?)),
            ("token", ScVal::Address(address(&self.token)?)),
        ])
    }
    pub fn from_scval(value: &ScVal) -> Result<Self> {
        use rpc::{addr, digest_field, map_field, wide};
        exact_keys(
            value,
            &[
                "amount",
                "deployment_version",
                "from",
                "nonce",
                "operation_id",
                "to",
                "token",
            ],
        )?;
        Ok(Self {
            operation_id: digest_field(map_field(value, "operation_id")?)?,
            token: addr(map_field(value, "token")?)?,
            from: addr(map_field(value, "from")?)?,
            to: addr(map_field(value, "to")?)?,
            amount: wide(map_field(value, "amount")?)?,
            nonce: u64_field(map_field(value, "nonce")?)?,
            deployment_version: u64_field(map_field(value, "deployment_version")?)?,
        })
    }
}
/// `AllowitSep56DepositReceipt`: the settled share credit of one deposit.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DepositReceipt {
    pub operation_id: [u8; 32],
    pub vault: String,
    pub asset: String,
    pub from: String,
    pub receiver: String,
    pub operator: String,
    pub assets: i128,
    pub shares: i128,
    pub nonce: u64,
    pub deployment_version: u64,
}
impl DepositReceipt {
    pub fn scval(&self) -> Result<ScVal> {
        struct_value(vec![
            ("asset", ScVal::Address(address(&self.asset)?)),
            ("assets", i128_value(self.assets)),
            ("deployment_version", ScVal::U64(self.deployment_version)),
            ("from", ScVal::Address(address(&self.from)?)),
            ("nonce", ScVal::U64(self.nonce)),
            ("operation_id", value_bytes(&self.operation_id)?),
            ("operator", ScVal::Address(address(&self.operator)?)),
            ("receiver", ScVal::Address(address(&self.receiver)?)),
            ("shares", i128_value(self.shares)),
            ("vault", ScVal::Address(address(&self.vault)?)),
        ])
    }
    pub fn from_scval(value: &ScVal) -> Result<Self> {
        use rpc::{addr, digest_field, map_field, wide};
        exact_keys(
            value,
            &[
                "asset",
                "assets",
                "deployment_version",
                "from",
                "nonce",
                "operation_id",
                "operator",
                "receiver",
                "shares",
                "vault",
            ],
        )?;
        Ok(Self {
            operation_id: digest_field(map_field(value, "operation_id")?)?,
            vault: addr(map_field(value, "vault")?)?,
            asset: addr(map_field(value, "asset")?)?,
            from: addr(map_field(value, "from")?)?,
            receiver: addr(map_field(value, "receiver")?)?,
            operator: addr(map_field(value, "operator")?)?,
            assets: wide(map_field(value, "assets")?)?,
            shares: wide(map_field(value, "shares")?)?,
            nonce: u64_field(map_field(value, "nonce")?)?,
            deployment_version: u64_field(map_field(value, "deployment_version")?)?,
        })
    }
}

/// Decoded `AllowitState` of layout 4.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CustodyState {
    pub policy_state: PolicyParams,
    pub contract_version: u32,
    pub owner: String,
    pub agent: String,
    pub server: String,
    pub asset: String,
    pub policy_instance: [u8; 32],
    pub source_digest: [u8; 32],
    pub rules: Vec<String>,
    pub params: PolicyParams,
    pub x402_enabled: bool,
    pub token: String,
    pub deployment_version: u64,
    pub nonce: u64,
    pub paused: bool,
}
const STATE_KEYS: [&str; 15] = [
    "agent",
    "asset",
    "contract_version",
    "deployment_version",
    "nonce",
    "owner",
    "params",
    "paused",
    "policy_instance",
    "policy_state",
    "rules",
    "server",
    "source_digest",
    "token",
    "x402_enabled",
];
impl CustodyState {
    /// Decode stored State exactly. Other layouts, also ones that add or drop a field, reject.
    pub fn from_scval(value: &ScVal) -> Result<Self> {
        use rpc::{addr, digest_field, map_field};
        let version = u32_field(map_field(value, "contract_version")?)?;
        if version != CONTRACT_VERSION {
            return Err(format!(
                "Unsupported policy contract version {version}; this crate reads layout {CONTRACT_VERSION}"
            ));
        }
        exact_keys(value, &STATE_KEYS)?;
        let state = Self {
            policy_state: PolicyParams::from_scval(map_field(value, "policy_state")?)?,
            contract_version: version,
            owner: addr(map_field(value, "owner")?)?,
            agent: addr(map_field(value, "agent")?)?,
            server: addr(map_field(value, "server")?)?,
            asset: addr(map_field(value, "asset")?)?,
            policy_instance: digest_field(map_field(value, "policy_instance")?)?,
            source_digest: digest_field(map_field(value, "source_digest")?)?,
            rules: policy::rules_from_scval(map_field(value, "rules")?)?,
            params: PolicyParams::from_scval(map_field(value, "params")?)?,
            x402_enabled: boolean(map_field(value, "x402_enabled")?)?,
            token: string(map_field(value, "token")?)?,
            deployment_version: u64_field(map_field(value, "deployment_version")?)?,
            nonce: u64_field(map_field(value, "nonce")?)?,
            paused: boolean(map_field(value, "paused")?)?,
        };
        // Only the canonical encoding of the decoded State is accepted, as the contract does.
        if &state.scval()? != value {
            return Err("Stored State is not the canonical layout 4 encoding".into());
        }
        Ok(state)
    }
    pub fn scval(&self) -> Result<ScVal> {
        struct_value(vec![
            ("agent", ScVal::Address(address(&self.agent)?)),
            ("asset", ScVal::Address(address(&self.asset)?)),
            ("contract_version", ScVal::U32(self.contract_version)),
            ("deployment_version", ScVal::U64(self.deployment_version)),
            ("nonce", ScVal::U64(self.nonce)),
            ("owner", ScVal::Address(address(&self.owner)?)),
            ("params", self.params.scval()?),
            ("paused", ScVal::Bool(self.paused)),
            ("policy_instance", value_bytes(&self.policy_instance)?),
            ("policy_state", self.policy_state.scval()?),
            ("rules", policy::rules_scval(&self.rules)?),
            ("server", ScVal::Address(address(&self.server)?)),
            ("source_digest", value_bytes(&self.source_digest)?),
            (
                "token",
                ScVal::String(ScString(
                    self.token.as_bytes().to_vec().try_into().map_err(err)?,
                )),
            ),
            ("x402_enabled", ScVal::Bool(self.x402_enabled)),
        ])
    }
}
/// The stored fields that every readable custody layout keeps: the contract's `KeptState`.
/// Owner `recover` reads only these, so recovery needs no exact layout 4 State or policy binding.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KeptState {
    pub contract_version: u32,
    pub owner: String,
    pub asset: String,
    pub policy_instance: [u8; 32],
    pub token: String,
    pub deployment_version: u64,
    pub nonce: u64,
    pub paused: bool,
}
impl KeptState {
    /// Decode the kept fields of any layout from 1 to [`CONTRACT_VERSION`], ignoring the other
    /// State keys as the contract's struct decoding does.
    pub fn from_scval(value: &ScVal) -> Result<Self> {
        use rpc::{addr, digest_field, map_field};
        let version = u32_field(map_field(value, "contract_version")?)?;
        if version == 0 || version > CONTRACT_VERSION {
            return Err(format!(
                "Unsupported policy contract version {version}; this crate reads layouts 1 to {CONTRACT_VERSION}"
            ));
        }
        Ok(Self {
            contract_version: version,
            owner: addr(map_field(value, "owner")?)?,
            asset: addr(map_field(value, "asset")?)?,
            policy_instance: digest_field(map_field(value, "policy_instance")?)?,
            token: string(map_field(value, "token")?)?,
            deployment_version: u64_field(map_field(value, "deployment_version")?)?,
            nonce: u64_field(map_field(value, "nonce")?)?,
            paused: boolean(map_field(value, "paused")?)?,
        })
    }
}
/// Decoded `AllowitPolicyBinding`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyBinding {
    pub engine_kind: String,
    pub contract_version: u32,
    pub policy_instance: [u8; 32],
    pub module_digest: [u8; 32],
    pub source_digest: [u8; 32],
    pub argument_schema_digest: [u8; 32],
    pub entrypoint: String,
}
impl PolicyBinding {
    pub fn from_scval(value: &ScVal) -> Result<Self> {
        use rpc::{digest_field, map_field};
        exact_keys(
            value,
            &[
                "argument_schema_digest",
                "contract_version",
                "engine_kind",
                "entrypoint",
                "module_digest",
                "policy_instance",
                "source_digest",
            ],
        )?;
        Ok(Self {
            engine_kind: symbol_text(map_field(value, "engine_kind")?)?,
            contract_version: u32_field(map_field(value, "contract_version")?)?,
            policy_instance: digest_field(map_field(value, "policy_instance")?)?,
            module_digest: digest_field(map_field(value, "module_digest")?)?,
            source_digest: digest_field(map_field(value, "source_digest")?)?,
            argument_schema_digest: digest_field(map_field(value, "argument_schema_digest")?)?,
            entrypoint: symbol_text(map_field(value, "entrypoint")?)?,
        })
    }
    pub fn scval(&self) -> Result<ScVal> {
        struct_value(vec![
            (
                "argument_schema_digest",
                value_bytes(&self.argument_schema_digest)?,
            ),
            ("contract_version", ScVal::U32(self.contract_version)),
            ("engine_kind", value_symbol(&self.engine_kind)?),
            ("entrypoint", value_symbol(&self.entrypoint)?),
            ("module_digest", value_bytes(&self.module_digest)?),
            ("policy_instance", value_bytes(&self.policy_instance)?),
            ("source_digest", value_bytes(&self.source_digest)?),
        ])
    }
    /// Check this binding against the installation for one argument schema.
    pub fn verify(&self, c: &WalletConfig, schema: &[u8; 32]) -> Result<()> {
        let tier = c.tier.ok_or("Selected policy tier is required")?;
        if self.engine_kind != tier.kind()
            || self.contract_version != CONTRACT_VERSION
            || self.policy_instance != c.policy_instance
            || self.module_digest != c.module_digest
            || self.source_digest != c.source_digest
            || self.argument_schema_digest != *schema
            || self.entrypoint != "execute"
        {
            return Err("Installed policy binding differs from the installation".into());
        }
        Ok(())
    }
}

/// Persistent ledger key of the replay marker, which holds the transfer receipt.
pub fn operation_key(wallet: &str, operation_id: &[u8; 32]) -> Result<LedgerKey> {
    persistent_key(wallet, "Operation", operation_id)
}
/// Persistent ledger key of a deposit receipt.
pub fn deposit_key(wallet: &str, operation_id: &[u8; 32]) -> Result<LedgerKey> {
    persistent_key(wallet, "Deposit", operation_id)
}
fn persistent_key(wallet: &str, variant: &str, operation_id: &[u8; 32]) -> Result<LedgerKey> {
    Ok(LedgerKey::ContractData(LedgerKeyContractData {
        contract: address(wallet)?,
        key: ScVal::Vec(Some(
            vec![value_symbol(variant)?, value_bytes(operation_id)?]
                .try_into()
                .map_err(err)?,
        )),
        durability: ContractDataDurability::Persistent,
    }))
}
