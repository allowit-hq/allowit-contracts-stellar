//! Exact native encodings of the policy wallet interface, custody layout 5.
//!
//! Each encoder emits the `ScVal` that the contract type of `crates/protocol` and
//! `crates/policy-wallet` decodes: named structs are symbol-keyed maps in key order, tuple structs
//! and enum variants are vectors (a variant's symbol first), and `Option` is `Void` or the value.
//! The agent's request is positional, so it carries no field names: it travels twice in a
//! transaction, as the call's argument and in the wallet's authorization entry.
use crate::*;

/// Custody layout this crate reads and writes.
pub const CONTRACT_VERSION: u32 = packed::LAYOUT as u32;

pub(crate) fn struct_value(entries: Vec<(&str, ScVal)>) -> Result<ScVal> {
    value_map(entries)
}
/// One enum variant with its fields: `[Symbol(variant), field, ...]`.
fn variant(name: &str, fields: Vec<ScVal>) -> Result<ScVal> {
    let mut items = vec![value_symbol(name)?];
    items.extend(fields);
    Ok(ScVal::Vec(Some(items.try_into().map_err(err)?)))
}
/// `AllowitStellarOperation` of one native operation, positional. The wallet is every source,
/// receiver and operator, so no argument names it.
pub fn operation(asset: &str, operation: &StellarOperation) -> Result<ScVal> {
    match operation {
        StellarOperation::Transfer(t) => variant(
            "Transfer",
            vec![
                ScVal::Address(address(asset)?),
                ScVal::Address(address(&t.recipient)?),
                i128_value(t.amount),
            ],
        ),
        StellarOperation::Deposit(d) => variant(
            "Deposit",
            vec![
                ScVal::Address(address(&d.vault)?),
                i128_value(d.assets),
                i128_value(d.min_shares),
            ],
        ),
        StellarOperation::Redeem(r) => variant(
            "Redeem",
            vec![
                ScVal::Address(address(&r.vault)?),
                i128_value(r.shares),
                i128_value(r.min_assets),
            ],
        ),
    }
}
/// `AllowitExpense`: `Unpriced`, or `Priced(gas units, conversion units, spent units, observed
/// ledger)`.
pub fn expense(expense: Option<&ExpenseBounds>) -> Result<ScVal> {
    let Some(e) = expense else {
        return variant("Unpriced", vec![]);
    };
    variant(
        "Priced",
        vec![
            i128_value(e.gas_units),
            i128_value(e.conversion_units),
            i128_value(e.spent_units),
            ScVal::U32(e.observed_ledger),
        ],
    )
}
/// Every field of one `AllowitExecutionRequest`.
pub struct ExecutionPacket<'a> {
    pub operation_id: &'a [u8; 32],
    pub deployment_version: u32,
    pub expires_at: u64,
    pub operation: ScVal,
    pub expense: ScVal,
    /// XLM stroops that the wallet repays for the network fee.
    pub gas_stroops: i128,
    /// The account that receives the repayment: the server's sending account.
    pub gas_payee: &'a str,
    pub args: &'a PolicyParams,
}
/// `AllowitExecutionRequest`, positional: operation id, deployment version, expiry, operation,
/// expense, gas, gas payee, args.
pub fn execution_request(p: ExecutionPacket) -> Result<ScVal> {
    Ok(ScVal::Vec(Some(
        vec![
            value_bytes(p.operation_id)?,
            ScVal::U32(p.deployment_version),
            ScVal::U64(p.expires_at),
            p.operation,
            p.expense,
            i128_value(p.gas_stroops),
            ScVal::Address(address(p.gas_payee)?),
            p.args.scval()?,
        ]
        .try_into()
        .map_err(err)?,
    )))
}
/// `AllowitCosignatures`: the agent's and then the server's signature of the wallet's
/// authorization payload.
pub fn cosignatures(agent: &[u8; 64], server: &[u8; 64]) -> Result<ScVal> {
    Ok(ScVal::Vec(Some(
        vec![value_bytes(agent)?, value_bytes(server)?]
            .try_into()
            .map_err(err)?,
    )))
}
/// The raw Ed25519 key of an account address, as the wallet stores its agent and server.
fn raw_key(account: &str) -> Result<ScVal> {
    value_bytes(&account_key(account)?)
}
/// `AllowitPolicyConfig`: the owner-signed configuration of a new wallet.
pub struct PolicyConfig<'a> {
    pub owner: &'a str,
    pub agent: &'a str,
    pub server: &'a str,
    pub asset: &'a str,
    pub source_hash: &'a [u8; 32],
    pub gas_cap: i128,
    pub rules: &'a [String],
    pub params: &'a PolicyParams,
}
pub fn policy_config(c: PolicyConfig) -> Result<ScVal> {
    struct_value(vec![
        ("agent", raw_key(c.agent)?),
        ("asset", ScVal::Address(address(c.asset)?)),
        ("gas_cap", i128_value(c.gas_cap)),
        ("owner", ScVal::Address(address(c.owner)?)),
        ("params", c.params.scval()?),
        ("rules", policy::rules_scval(c.rules)?),
        ("server", raw_key(c.server)?),
        ("source_hash", value_bytes(c.source_hash)?),
    ])
}
/// `AllowitPolicyUpdate`: a complete owner update at `deployment_version`.
pub struct PolicyUpdate<'a> {
    pub deployment_version: u32,
    pub owner: &'a str,
    pub agent: &'a str,
    pub server: &'a str,
    pub source_hash: &'a [u8; 32],
    pub gas_cap: i128,
    pub rules: &'a [String],
    pub params: &'a PolicyParams,
    pub wasm_hash: Option<&'a [u8; 32]>,
}
pub fn policy_update(u: PolicyUpdate) -> Result<ScVal> {
    struct_value(vec![
        ("agent", raw_key(u.agent)?),
        ("deployment_version", ScVal::U32(u.deployment_version)),
        ("gas_cap", i128_value(u.gas_cap)),
        ("owner", ScVal::Address(address(u.owner)?)),
        ("params", u.params.scval()?),
        ("rules", policy::rules_scval(u.rules)?),
        ("server", raw_key(u.server)?),
        ("source_hash", value_bytes(u.source_hash)?),
        (
            "wasm_hash",
            match u.wasm_hash {
                Some(hash) => value_bytes(hash)?,
                None => ScVal::Void,
            },
        ),
    ])
}
