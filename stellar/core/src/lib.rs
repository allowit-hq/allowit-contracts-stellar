//! Stellar adapters for the existing typed execution request and operation lifecycle.
//! Native and policy wallet custody use the same authored policy and exact operation identity.
use crate::workflow::{
    AbiValue, AccountId as WorkflowAccount, AccountKind, Amount256, Chain, ExecutionInput,
    ExecutionRequest, NativeInstruction, WorkflowAsset,
};
use ed25519_dalek::{Signature as EdSignature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use stellar_strkey::{Contract, Strkey, ed25519};
use stellar_xdr::*;

pub mod admin;
mod authorization;
pub mod contract;
pub mod owner;
pub mod policy;
pub mod request;
pub mod workflow;
pub use authorization::{authorize_server, authorize_server_with, sign_account_entry};
pub use contract::{CONTRACT_VERSION, DepositReceipt, RedeemReceipt, TransferReceipt};
pub use policy::{PolicyEngine, PolicyLanguage, PolicyParams, PolicyTier, PolicyValue};
pub mod rpc;
pub mod x402;
pub type Result<T> = std::result::Result<T, String>;

pub const PROFILE: &str = "allowit-stellar-wallet-v1";
const MAX_BYTES: usize = 1_048_576;

pub fn hash(bytes: impl AsRef<[u8]>) -> [u8; 32] {
    Sha256::digest(bytes.as_ref()).into()
}
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub fn unhex<const N: usize>(s: &str) -> Result<[u8; N]> {
    if s.len() != N * 2 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("Invalid hexadecimal identity".into());
    }
    let mut out = [0; N];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(err)?;
    }
    Ok(out)
}
fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}
fn limits() -> Limits {
    Limits {
        depth: 64,
        len: MAX_BYTES,
    }
}
/// Canonical base64 XDR of a native value.
pub fn xdr<T: WriteXdr>(value: &T) -> Result<String> {
    value.to_xdr_base64(limits()).map_err(err)
}
/// Decode bounded base64 XDR.
pub fn read<T: ReadXdr>(value: &str) -> Result<T> {
    if value.len() > MAX_BYTES * 2 {
        return Err("XDR exceeds limit".into());
    }
    T::from_xdr_base64(value, limits()).map_err(err)
}
pub fn passphrase(network: &str) -> Result<&'static str> {
    match network {
        "stellar:mainnet" => Ok("Public Global Stellar Network ; September 2015"),
        "stellar:testnet" => Ok("Test SDF Network ; September 2015"),
        _ => Err("Unsupported Stellar network".into()),
    }
}
pub fn network_id(network: &str) -> Result<[u8; 32]> {
    Ok(hash(passphrase(network)?))
}
/// Decode a canonical local Ed25519 seed. Never include this value in an export bundle.
pub fn decode_seed(value: &str) -> Result<[u8; 32]> {
    ed25519::PrivateKey::from_string(value)
        .map(|v| v.0)
        .map_err(|_| "Expected a canonical Stellar S seed".into())
}
pub fn account_for_seed(seed: &[u8; 32]) -> String {
    ed25519::PublicKey(SigningKey::from_bytes(seed).verifying_key().to_bytes()).to_string()
}
pub fn account_key(address: &str) -> Result<[u8; 32]> {
    ed25519::PublicKey::from_string(address)
        .map(|v| v.0)
        .map_err(|_| "Expected canonical Stellar G account".into())
}
pub fn address(value: &str) -> Result<ScAddress> {
    match Strkey::from_string(value).map_err(err)? {
        Strkey::PublicKeyEd25519(v) => Ok(ScAddress::Account(AccountId(
            PublicKey::PublicKeyTypeEd25519(Uint256(v.0)),
        ))),
        Strkey::Contract(v) => Ok(ScAddress::Contract(ContractId(Hash(v.0)))),
        _ => Err("Only canonical G and C addresses are admitted".into()),
    }
}
pub fn address_text(value: &ScAddress) -> Result<String> {
    match value {
        ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(v))) => {
            Ok(ed25519::PublicKey(v.0).to_string())
        }
        ScAddress::Contract(v) => Ok(Contract(v.0.0).to_string()),
        _ => Err("Unsupported address".into()),
    }
}
fn workflow_address(value: &WorkflowAccount) -> Result<String> {
    match value.kind {
        AccountKind::Wallet => Ok(ed25519::PublicKey(value.address).to_string()),
        AccountKind::Contract => Ok(Contract(value.address).to_string()),
    }
}
fn value_symbol(v: &str) -> Result<ScVal> {
    Ok(ScVal::Symbol(ScSymbol(
        v.as_bytes().to_vec().try_into().map_err(err)?,
    )))
}
fn value_bytes(v: &[u8]) -> Result<ScVal> {
    Ok(ScVal::Bytes(ScBytes(v.to_vec().try_into().map_err(err)?)))
}
fn value_map(entries: Vec<(&str, ScVal)>) -> Result<ScVal> {
    let mut out = entries
        .into_iter()
        .map(|(k, val)| {
            Ok(ScMapEntry {
                key: value_symbol(k)?,
                val,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    out.sort_by(|a, b| a.key.cmp(&b.key));
    Ok(ScVal::Map(Some(ScMap(out.try_into().map_err(err)?))))
}
fn i128_value(v: i128) -> ScVal {
    ScVal::I128(Int128Parts {
        hi: (v >> 64) as i64,
        lo: v as u64,
    })
}
fn amount(v: &Amount256) -> Result<i128> {
    if v.0[..16].iter().any(|b| *b != 0) {
        return Err("Amount exceeds native i128".into());
    }
    i128::try_from(u128::from_be_bytes(v.0[16..].try_into().unwrap())).map_err(err)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum WalletRoute {
    Native,
    PolicyWallet,
    /// Historical signed packets only. New preparation rejects this route.
    #[doc(hidden)]
    Odc,
}
fn is_zero(v: &[u8; 32]) -> bool {
    *v == [0; 32]
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WalletConfig {
    pub network: String,
    pub policy_instance: [u8; 32],
    pub wallet: String,
    pub owner: String,
    pub agent: String,
    #[serde(alias = "engine")]
    pub server: String,
    pub route: WalletRoute,
    /// Installed policy wallet tier: simple, common or custom. Classic custody has none.
    #[serde(
        default,
        alias = "policyEngine",
        skip_serializing_if = "Option::is_none"
    )]
    pub tier: Option<PolicyTier>,
    /// Source language. Policy wallets require portable source.
    #[serde(default, skip_serializing_if = "is_legacy")]
    pub language: PolicyLanguage,
    /// Ordered canonical rules installed onchain: the standard prefix for Common, none otherwise.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<String>,
    /// Owner params at installation, canonical keys plus Custom keys. Live params are read from
    /// the wallet; owner updates change them without a new installation record.
    #[serde(default, skip_serializing_if = "policy_params_empty")]
    pub params: PolicyParams,
    /// Installed binding digest: the standard prefix digest for Simple and Common, the source
    /// digest for Custom.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub source_digest: [u8; 32],
    pub asset: String,
    pub asset_symbol: String,
    #[serde(default)]
    pub asset_issuer: Option<String>,
    pub policy_source: String,
    /// SHA-256 of the complete policy source, which agent and server authorization cover.
    pub source_hash: [u8; 32],
    pub module_digest: [u8; 32],
    pub max_fee_stroops: u32,
}
fn is_legacy(language: &PolicyLanguage) -> bool {
    *language == PolicyLanguage::Legacy
}
fn policy_params_empty(params: &PolicyParams) -> bool {
    params.0.is_empty()
}
impl WalletConfig {
    /// The legacy SDK engine name of the installed tier.
    pub fn policy_engine(&self) -> Option<PolicyEngine> {
        self.tier.map(PolicyTier::engine)
    }
}
/// The general operations of the policy core, which policy wallet bindings list and rules read.
/// This crate prepares transfers, deposits and redeems.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum OperationKind {
    /// Token transfer to a recipient.
    Transfer,
    /// Exact-input swap through an exchange.
    Swap,
    /// Deposit of the asset into a vault, which is also the share token.
    Deposit,
    /// Redeem of vault shares for the asset.
    Redeem,
}
impl OperationKind {
    /// The op name: the `AllowitOperation` variant and the `operations` entry.
    pub fn name(self) -> &'static str {
        match self {
            Self::Transfer => "transfer",
            Self::Swap => "swap",
            Self::Deposit => "deposit",
            Self::Redeem => "redeem",
        }
    }
    /// The `AllowitOperation` of the policy core.
    pub fn allowit(self) -> allowit::AllowitOperation {
        match self {
            Self::Transfer => allowit::AllowitOperation::transfer,
            Self::Swap => allowit::AllowitOperation::swap,
            Self::Deposit => allowit::AllowitOperation::deposit,
            Self::Redeem => allowit::AllowitOperation::redeem,
        }
    }
    /// Contract encoding of the unit `AllowitOperation` variant: a one-symbol vector.
    pub fn scval(self) -> Result<ScVal> {
        Ok(ScVal::Vec(Some(
            vec![value_symbol(self.name())?].try_into().map_err(err)?,
        )))
    }
    /// Decode a unit `AllowitOperation` variant.
    pub fn from_scval(value: &ScVal) -> Result<Self> {
        let ScVal::Vec(Some(items)) = value else {
            return Err("Expected an operation variant".into());
        };
        let [ScVal::Symbol(name)] = items.as_slice() else {
            return Err("Expected an operation variant".into());
        };
        [Self::Transfer, Self::Swap, Self::Deposit, Self::Redeem]
            .into_iter()
            .find(|op| op.name().as_bytes() == name.0.as_slice())
            .ok_or_else(|| "Unknown policy wallet operation".into())
    }
}
/// Request-bound conservative economic ceilings in the wallet asset, attested by the server
/// signer with its authorization: `AllowitExpenseBounds`. Amounts use the wallet asset's seven
/// decimals. For XLM, gas equals the fee bound in stroops.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExpenseBounds {
    /// Attributable gas ceiling in wallet-asset units.
    pub gas_units: i128,
    /// Deposit fee or slippage ceiling in wallet-asset units. Transfers use zero.
    pub conversion_units: i128,
    /// Transfer principal plus gas, or deposit conversion plus gas.
    pub spent_units: i128,
    /// Signed outer transaction fee bound in stroops. The final fee must not exceed it.
    pub max_fee_stroops: u32,
    /// Nonzero ledger at which the server observed the economic inputs.
    pub observed_ledger: u32,
    /// UTC execution day (Unix seconds / 86400).
    pub day: u64,
}
impl ExpenseBounds {
    /// Bounds of one operation in native XLM, where gas is the fee bound itself.
    pub fn xlm(
        principal: i128,
        conversion_units: i128,
        max_fee_stroops: u32,
        observed_ledger: u32,
        now: u64,
    ) -> Result<Self> {
        let gas = i128::from(max_fee_stroops);
        Ok(Self {
            gas_units: gas,
            conversion_units,
            spent_units: principal.checked_add(gas).ok_or("Expense overflow")?,
            max_fee_stroops,
            observed_ledger,
            day: now / allowit::DAY,
        })
    }
}
/// Execution terms beyond the canonical request: the agent's execution args and the server's
/// expense bounds. Agent and server sign them with the request.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutionTerms {
    #[serde(default, skip_serializing_if = "policy_params_empty")]
    pub args: PolicyParams,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expense: Option<ExpenseBounds>,
}
impl ExecutionTerms {
    pub fn is_empty(&self) -> bool {
        self.args.0.is_empty() && self.expense.is_none()
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountSigner {
    pub key: String,
    pub weight: u32,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountState {
    pub address: String,
    pub sequence: i64,
    pub master_weight: u32,
    pub low_threshold: u32,
    pub medium_threshold: u32,
    pub high_threshold: u32,
    pub signers: Vec<AccountSigner>,
}
fn automated_roles(c: &WalletConfig) -> Vec<&str> {
    let mut roles = vec![c.agent.as_str()];
    if c.route == WalletRoute::Native && c.server != c.agent {
        roles.push(c.server.as_str());
    }
    roles
}
impl AccountState {
    pub fn validate_structure(&self) -> Result<()> {
        account_key(&self.address)?;
        if self.sequence < 0
            || self.master_weight > 255
            || [
                self.low_threshold,
                self.medium_threshold,
                self.high_threshold,
            ]
            .iter()
            .any(|v| *v > 255)
            || self.signers.len() > 20
        {
            return Err("Invalid live account structure".into());
        }
        let mut seen = std::collections::BTreeSet::new();
        for signer in &self.signers {
            let key = Strkey::from_string(&signer.key).map_err(err)?;
            if !matches!(
                key,
                Strkey::PublicKeyEd25519(_)
                    | Strkey::PreAuthTx(_)
                    | Strkey::HashX(_)
                    | Strkey::SignedPayloadEd25519(_)
            ) || key.to_string() != signer.key
                || signer.key == self.address
                || !seen.insert(signer.key.clone())
            {
                return Err("Invalid or duplicate live account signer".into());
            }
        }
        Ok(())
    }
    pub fn signer_weight(&self, signer: &str) -> Result<u32> {
        self.validate_structure()?;
        account_key(signer)?;
        Ok(if signer == self.address {
            self.master_weight
        } else {
            self.signers
                .iter()
                .find(|s| s.key == signer)
                .map_or(0, |s| s.weight.min(255))
        })
    }
    pub fn validate_signer_quorum(&self, signers: &[&str], threshold: u32) -> Result<()> {
        self.validate_structure()?;
        if threshold > 255 {
            return Err("Invalid account threshold".into());
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut weight = 0u32;
        for signer in signers {
            if !seen.insert(*signer) {
                return Err("Duplicate quorum signer".into());
            }
            weight = weight
                .checked_add(self.signer_weight(signer)?)
                .ok_or("Signer weight overflow")?;
        }
        if weight == 0 || weight < threshold {
            return Err("Current account signer quorum is insufficient".into());
        }
        Ok(())
    }
    pub fn validate_wallet(&self, c: &WalletConfig) -> Result<()> {
        if self.address != c.wallet {
            return Err("Native wallet identity differs".into());
        }
        if self.signer_weight(&c.agent)? == 0 {
            return Err("Customer is not a current account signer".into());
        }
        Ok(())
    }
}
/// Chain-observed policy inputs of a layout 4 policy wallet.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyStateSnapshot {
    /// Current owner params.
    pub params: PolicyParams,
    /// Current free-form policy state before this operation.
    pub state: PolicyParams,
    /// Installed ordered canonical rules.
    pub rules: Vec<String>,
    /// Installed binding digest.
    pub source_digest: [u8; 32],
    /// Owner opt-in to x402.
    pub x402_enabled: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrustedState {
    /// Executable release metadata. Legacy code has no advertised release version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract_version: Option<u32>,
    /// Full chain-observed policy wallet maps; classic usage fields below are not policy wallet accounting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_state: Option<PolicyStateSnapshot>,
    pub source: AccountState,
    pub nonce: u64,
    /// Current ordered owner configuration. Historical spellings identify this same counter.
    #[serde(alias = "revision")]
    pub deployment_version: u64,
    pub spent_daily: i128,
    pub spent_total: i128,
    pub spent_day: u64,
    pub calls: u64,
    pub ledger: u32,
    pub module_digest: [u8; 32],
    pub source_hash: [u8; 32],
    pub owner: String,
    pub agent: String,
    #[serde(alias = "engine")]
    pub server: String,
    pub policy_instance: [u8; 32],
}
/// Ephemeral proof that the exact native operation passed trusted RPC preflight.
/// It grants no authority against later chain changes and cannot be deserialized.
#[derive(Clone, Debug)]
pub struct NativePreflight {
    binding: [u8; 32],
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedOperation {
    pub version: u32,
    pub config: WalletConfig,
    pub request: ExecutionRequest,
    /// Execution args and expense bounds that the request packet carries.
    #[serde(default, skip_serializing_if = "ExecutionTerms::is_empty")]
    pub terms: ExecutionTerms,
    pub state: TrustedState,
    pub transaction_xdr: String,
    pub transaction_hash: [u8; 32],
    pub request_hash: [u8; 32],
    pub simulation_data: Option<String>,
    pub created_at: u64,
    pub expires_at: u64,
    #[serde(skip)]
    pub native_preflight: Option<NativePreflight>,
}
// The ephemeral preflight is new-signing admission, not durable signed-record identity.
impl PartialEq for PreparedOperation {
    fn eq(&self, other: &Self) -> bool {
        self.version == other.version
            && self.config == other.config
            && self.request == other.request
            && self.terms == other.terms
            && self.state == other.state
            && self.transaction_xdr == other.transaction_xdr
            && self.transaction_hash == other.transaction_hash
            && self.request_hash == other.request_hash
            && self.simulation_data == other.simulation_data
            && self.created_at == other.created_at
            && self.expires_at == other.expires_at
    }
}
impl Eq for PreparedOperation {}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DetachedSignature {
    pub signer: String,
    pub signature: Vec<u8>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedOperation {
    pub prepared: PreparedOperation,
    pub transaction_xdr: String,
    pub transaction_hash: [u8; 32],
    /// Classic custody only: one verified proof over `transaction_hash` per automated role key,
    /// in role order (agent, then service). The envelope keeps only the signatures that current
    /// chain thresholds select, so these proofs keep service approval checkable at submission.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub role_signatures: Vec<DetachedSignature>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum OperationStatus {
    Prepared,
    Submitted,
    SubmissionUnknown,
    Confirmed,
    Failed,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transfer {
    pub token: String,
    pub source: String,
    pub recipient: String,
    pub amount: i128,
    pub native: bool,
}
/// One SEP-56 deposit of the wallet asset into `vault`. The wallet is its source, receiver and
/// operator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Deposit {
    pub vault: String,
    pub assets: i128,
    pub min_shares: i128,
}
/// One SEP-56 redeem of `shares` of `vault` for at least `min_assets` of the wallet asset. The
/// wallet is its owner, receiver and operator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Redeem {
    pub vault: String,
    pub shares: i128,
    pub min_assets: i128,
}
/// The admitted native operation of one request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StellarOperation {
    Transfer(Transfer),
    Deposit(Deposit),
    Redeem(Redeem),
}
impl StellarOperation {
    pub fn kind(&self) -> OperationKind {
        match self {
            Self::Transfer(_) => OperationKind::Transfer,
            Self::Deposit(_) => OperationKind::Deposit,
            Self::Redeem(_) => OperationKind::Redeem,
        }
    }
    /// The one debit's beneficiary and units: deposits move `assets` to the vault, and redeems
    /// burn `shares` at the vault.
    pub fn debit(&self) -> (&str, i128) {
        match self {
            Self::Transfer(t) => (&t.recipient, t.amount),
            Self::Deposit(d) => (&d.vault, d.assets),
            Self::Redeem(r) => (&r.vault, r.shares),
        }
    }
    /// The token of the debit on a wallet of `asset`: the asset, or the vault's shares for a
    /// redeem.
    pub fn debit_token<'a>(&'a self, asset: &'a str) -> &'a str {
        match self {
            Self::Redeem(r) => &r.vault,
            Self::Transfer(_) | Self::Deposit(_) => asset,
        }
    }
}

/// The highest fee ceiling of one native custody operation, in stroops (0.1 XLM).
pub const NATIVE_MAX_FEE_STROOPS: u32 = 1_000_000;
/// The highest fee ceiling of one policy wallet operation, in stroops (1 XLM). Each wallet
/// operation writes a persistent replay entry and extends it to the network's longest lifetime;
/// on testnet on 2026-10-31 that rent made a Common wallet transfer cost 2645894 stroops.
pub const POLICY_WALLET_MAX_FEE_STROOPS: u32 = 10_000_000;
/// The highest installed fee ceiling of a custody route.
pub fn max_fee_ceiling(route: &WalletRoute) -> u32 {
    match route {
        WalletRoute::Native => NATIVE_MAX_FEE_STROOPS,
        WalletRoute::PolicyWallet | WalletRoute::Odc => POLICY_WALLET_MAX_FEE_STROOPS,
    }
}

pub fn validate_config(c: &WalletConfig) -> Result<()> {
    validate_config_for(c, true)
}
// Retained packets prove transport/effect identity. Their original owner-approved source
// binding belongs to the caller's durable record; current source admission cannot replace it.
fn validate_config_for(c: &WalletConfig, admit_source: bool) -> Result<()> {
    passphrase(&c.network)?;
    if c.policy_instance == [0; 32]
        || c.source_hash != hash(c.policy_source.as_bytes())
        || c.max_fee_stroops < 100
        || c.max_fee_stroops > max_fee_ceiling(&c.route)
    {
        return Err("Invalid installed policy or fee binding".into());
    }
    address(&c.owner)?;
    account_key(&c.agent)?;
    match c.route {
        WalletRoute::Native => {
            account_key(&c.wallet)?;
            account_key(&c.server)?;
        }
        WalletRoute::PolicyWallet | WalletRoute::Odc => {
            if c.route == WalletRoute::PolicyWallet {
                account_key(&c.server)?;
                if c.server == c.agent || c.tier.is_none() {
                    return Err(
                        "Distinct agent and service signer and selected policy tier are required"
                            .into(),
                    );
                }
            } else {
                Contract::from_string(&c.server).map_err(err)?;
            }
            Contract::from_string(&c.wallet).map_err(err)?;
            if c.module_digest == [0; 32] {
                return Err("Missing installed policy wallet code identity".into());
            }
        }
    }
    address(&c.asset)?;
    if c.asset != sac_address(&c.network, &asset_xdr(c)?)? {
        return Err("SAC does not match installed native asset identity".into());
    }
    if admit_source && c.route == WalletRoute::PolicyWallet {
        validate_portable_install(c)?;
    }
    if admit_source && c.route == WalletRoute::Native && c.language == PolicyLanguage::Portable {
        validate_classic_portable_install(c)?;
    }
    Ok(())
}
/// Classic custody enforces nothing onchain and its prepare and sign paths take no compiled
/// evaluator, so the host must run the whole portable policy itself. Only a canonical-only
/// source allows that: one `execute` of canonical rule calls over canonical params.
fn validate_classic_portable_install(c: &WalletConfig) -> Result<()> {
    if !policy::source_shape(&c.policy_source)?.canonical_only {
        return Err("Portable classic custody supports only canonical-only sources: `use allowit::...;` items and one execute of canonical rule calls followed by Ok(()). Use a policy wallet for other sources".into());
    }
    c.params
        .check(PolicyTier::Simple)
        .map_err(|e| format!("Portable classic custody reads only canonical params: {e}"))
}
/// Bind a layout 4 policy wallet installation to its portable source: tier rules, binding
/// digest, owner params and standard-state writes.
fn validate_portable_install(c: &WalletConfig) -> Result<()> {
    let tier = c.tier.ok_or("Selected policy tier is required")?;
    if c.language != PolicyLanguage::Portable {
        return Err("Policy wallets of layout 4 run portable policy source".into());
    }
    let shape = policy::source_shape(&c.policy_source)?;
    let expected = if tier == PolicyTier::Common {
        shape.prefix.clone()
    } else {
        vec![]
    };
    if c.rules != expected {
        return Err("Installed rules differ from the standard prefix of the policy source".into());
    }
    if tier.standard() && shape.writes_state {
        return Err("Simple and Common cannot store allowit::set_state writes".into());
    }
    let digest = policy::installed_source_digest(
        tier,
        &c.module_digest,
        &c.asset,
        &c.rules,
        &c.policy_source,
    )?;
    if c.source_digest != digest {
        return Err("Installed source digest differs from the tier binding".into());
    }
    c.params.check(tier)
}
/// Decode only the admitted catalog transfer profile, with exact effect and fee bounds.
pub fn transfer_from_request(c: &WalletConfig, r: &ExecutionRequest) -> Result<Transfer> {
    match decode_operation(c, r, false)? {
        StellarOperation::Transfer(t) => Ok(t),
        _ => Err("This profile admits only a transfer".into()),
    }
}
/// Decode one admitted native operation: a SEP-41 transfer, or a SEP-56 deposit or redeem for
/// policy wallets, with exact effect and fee bounds.
pub fn operation_from_request(c: &WalletConfig, r: &ExecutionRequest) -> Result<StellarOperation> {
    decode_operation(c, r, false)
}
fn decode_operation(
    c: &WalletConfig,
    r: &ExecutionRequest,
    retained: bool,
) -> Result<StellarOperation> {
    validate_config_for(c, !retained)?;
    if r.operation.policy_instance != c.policy_instance || r.operation.nonce == [0; 32] {
        return Err("Operation installation or identity differs".into());
    }
    let ExecutionInput::Instructions(instructions) = &r.input else {
        return Err("Stellar execution requires typed instructions".into());
    };
    if instructions.len() != 1 || r.effect_bounds.len() != 1 || !r.evidence.is_empty() {
        return Err("Only one admitted operation without unresolved evidence is supported".into());
    }
    let operation = match &instructions[0] {
        NativeInstruction::StellarNativeTransfer {
            source,
            destination,
            stroops,
        } => StellarOperation::Transfer(Transfer {
            token: c.asset.clone(),
            source: workflow_address(source)?,
            recipient: workflow_address(destination)?,
            amount: i128::from(*stroops),
            native: true,
        }),
        // The contract, function and typed arguments identify a Stellar call. Its schema digest
        // names no contract schema, so this crate does not read it.
        NativeInstruction::StellarCall {
            contract,
            function,
            arguments,
            ..
        } => match (function.as_str(), arguments.as_slice()) {
            (
                "transfer",
                [
                    AbiValue::Account(from),
                    AbiValue::Account(to),
                    AbiValue::Signed128(units),
                ],
            ) if workflow_address(contract)? == c.asset => StellarOperation::Transfer(Transfer {
                token: c.asset.clone(),
                source: workflow_address(from)?,
                recipient: workflow_address(to)?,
                amount: *units,
                native: false,
            }),
            // SEP-56 `deposit(assets, receiver, from, operator)` and `redeem(shares, receiver,
            // owner, operator)`, then the wallet's minimum output.
            (
                function @ ("deposit" | "redeem"),
                [
                    AbiValue::Signed128(amount),
                    AbiValue::Account(receiver),
                    AbiValue::Account(holder),
                    AbiValue::Account(operator),
                    AbiValue::Signed128(minimum),
                ],
            ) => {
                if c.route != WalletRoute::PolicyWallet || contract.kind != AccountKind::Contract {
                    return Err(
                        "SEP-56 operations require a policy wallet and a vault contract".into(),
                    );
                }
                for party in [receiver, holder, operator] {
                    if workflow_address(party)? != c.wallet {
                        return Err(
                            "SEP-56 receiver, holder and operator must be the wallet".into()
                        );
                    }
                }
                let vault = workflow_address(contract)?;
                if function == "deposit" {
                    StellarOperation::Deposit(Deposit {
                        vault,
                        assets: *amount,
                        min_shares: *minimum,
                    })
                } else {
                    StellarOperation::Redeem(Redeem {
                        vault,
                        shares: *amount,
                        min_assets: *minimum,
                    })
                }
            }
            _ => return Err("Unknown Stellar contract, method or arguments".into()),
        },
    };
    let native = match &operation {
        StellarOperation::Transfer(transfer) => {
            if transfer.native && asset_xdr(c)? != Asset::Native {
                return Err("Native XLM request differs from installed asset".into());
            }
            if transfer.amount <= 0 || transfer.source != c.wallet || transfer.recipient == c.wallet
            {
                return Err("Invalid transfer source, amount or recipient".into());
            }
            if !retained && c.asset_issuer.as_deref() == Some(transfer.recipient.as_str()) {
                return Err("Issued-asset payments to the issuer burn units instead of crediting the required recipient balance".into());
            }
            transfer.native
        }
        StellarOperation::Deposit(Deposit {
            vault,
            assets: amount,
            min_shares: minimum,
        })
        | StellarOperation::Redeem(Redeem {
            vault,
            shares: amount,
            min_assets: minimum,
        }) => {
            if *vault == c.wallet || *vault == c.asset {
                return Err("The vault must be another contract".into());
            }
            if *amount <= 0 || *minimum <= 0 {
                return Err("SEP-56 amounts and minimum outputs must be positive".into());
            }
            false
        }
    };
    // The effect bound is the one debit: the asset, or the vault's shares for a redeem.
    let (beneficiary, units) = operation.debit();
    let effect = &r.effect_bounds[0];
    let asset = match &effect.asset {
        WorkflowAsset::Native { chain, network } => {
            *chain == Chain::Stellar && *network == network_id(&c.network)? && native
        }
        WorkflowAsset::Token(a) => {
            a.network == network_id(&c.network)?
                && workflow_address(&a.token)? == operation.debit_token(&c.asset)
                && !native
        }
    };
    if !asset
        || workflow_address(&effect.source)? != c.wallet
        || workflow_address(&effect.beneficiary)? != beneficiary
        || amount(&effect.max_debit)? != units
        || amount(&effect.min_credit)? != units
        || amount(&effect.max_burn)? != 0
    {
        return Err("Operation effects differ from approved bounds".into());
    }
    let fees = r
        .fee_bounds
        .as_ref()
        .ok_or("Resolved native fee bounds are required")?;
    if fees.len() != 1 {
        return Err("One native fee bound is required".into());
    }
    let fee = &fees[0];
    let payer = workflow_address(&fee.payer)?;
    account_key(&payer)?;
    if (c.route == WalletRoute::Native && payer != c.wallet)
        || !matches!(&fee.asset,WorkflowAsset::Native{chain:Chain::Stellar,network} if *network==network_id(&c.network)?)
        || amount(&fee.max_fee)? < i128::from(c.max_fee_stroops)
    {
        return Err("Native fee payer or fee bound differs".into());
    }
    Ok(operation)
}
pub fn asset_xdr(c: &WalletConfig) -> Result<Asset> {
    asset_from_identity(&c.asset_symbol, c.asset_issuer.as_deref())
}
/// Construct the exact classic asset before deriving its network-bound SAC address.
pub fn asset_from_identity(symbol: &str, issuer: Option<&str>) -> Result<Asset> {
    if symbol == "XLM" && issuer.is_none() {
        return Ok(Asset::Native);
    }
    let issuer = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(account_key(
        issuer.ok_or("Issued asset needs exact issuer")?,
    )?)));
    let code = symbol.as_bytes();
    if code.is_empty() || code.len() > 12 || !code.iter().all(|v| v.is_ascii_alphanumeric()) {
        return Err("Invalid issued asset code".into());
    }
    if code.len() <= 4 {
        let mut v = [0; 4];
        v[..code.len()].copy_from_slice(code);
        Ok(Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4(v),
            issuer,
        }))
    } else {
        let mut v = [0; 12];
        v[..code.len()].copy_from_slice(code);
        Ok(Asset::CreditAlphanum12(AlphaNum12 {
            asset_code: AssetCode12(v),
            issuer,
        }))
    }
}
pub fn sac_address(network: &str, asset: &Asset) -> Result<String> {
    let preimage = HashIdPreimage::ContractId(HashIdPreimageContractId {
        network_id: Hash(network_id(network)?),
        contract_id_preimage: ContractIdPreimage::Asset(asset.clone()),
    });
    Ok(Contract(hash(preimage.to_xdr(limits()).map_err(err)?)).to_string())
}
/// Check one exact transfer against the portable installed policy before signing.
pub fn verify_policy(
    c: &WalletConfig,
    r: &ExecutionRequest,
    state: &TrustedState,
    now: u64,
) -> Result<()> {
    let expires = now.saturating_add(300);
    verify_operation(c, r, &ExecutionTerms::default(), state, now, expires, None).map(drop)
}
/// Check one exact operation and its terms against the installed policy before signing.
///
/// Retired source languages cannot authorize execution. Portable installs check the tier
/// binding, owner params, execution args and expense bounds, run the Common prefix as the
/// contract does and evaluate the full policy on the host when the source is canonical-only or
/// `evaluator` compiles it. `Evaluation::Prefix` means only the onchain part ran: a Custom wallet
/// runs the rest in native preflight, and the server evaluates the rest of a Simple or Common
/// policy with `authorize_server_with`.
pub fn verify_operation(
    c: &WalletConfig,
    r: &ExecutionRequest,
    terms: &ExecutionTerms,
    state: &TrustedState,
    now: u64,
    expires_at: u64,
    evaluator: Option<policy::PortableEvaluator>,
) -> Result<policy::Evaluation> {
    let operation = operation_from_request(c, r)?;
    match (&c.route, c.language) {
        (WalletRoute::Native, PolicyLanguage::Legacy) => {
            Err("Retired policy language cannot authorize new execution".into())
        }
        (WalletRoute::Native, PolicyLanguage::Portable) => {
            let StellarOperation::Transfer(t) = operation else {
                unreachable!()
            };
            verify_classic_portable(c, &t, terms, state, now, expires_at, evaluator)
        }
        (WalletRoute::PolicyWallet, _) => {
            verify_wallet_portable(c, &operation, terms, state, now, expires_at, evaluator)
        }
        (WalletRoute::Odc, _) => Err("Historical wallet packets are read-only".into()),
    }
}
/// Classic custody enforces nothing onchain, so the full portable policy must run on the host.
/// Params come from the owner-approved installation and standard state from the durable
/// coordinator's accounting. The payment principal is the exact spend; classic fees are paid in
/// XLM by the account and bounded separately by the fee ceiling.
fn verify_classic_portable(
    c: &WalletConfig,
    t: &Transfer,
    terms: &ExecutionTerms,
    state: &TrustedState,
    now: u64,
    expires_at: u64,
    evaluator: Option<policy::PortableEvaluator>,
) -> Result<policy::Evaluation> {
    if terms.expense.is_some() {
        return Err("Classic custody derives its expense from the exact payment".into());
    }
    let shape = policy::source_shape(&c.policy_source)?;
    if shape.writes_state {
        return Err("Classic custody cannot store allowit::set_state writes".into());
    }
    let mut standard = PolicyParams::default();
    for (key, value) in [
        ("calls", PolicyValue::Int(i128::from(state.calls))),
        ("spent", PolicyValue::Int(state.spent_total)),
        ("day", PolicyValue::Int(i128::from(state.spent_day))),
        ("day_spent", PolicyValue::Int(state.spent_daily)),
        ("day_total", PolicyValue::Int(state.spent_daily)),
    ] {
        standard.0.insert(key.into(), value);
    }
    let request = policy::RuleRequest::new(
        &StellarOperation::Transfer(t.clone()),
        &c.asset,
        now,
        expires_at,
        Some(ExpenseBounds {
            gas_units: 0,
            conversion_units: 0,
            spent_units: t.amount,
            max_fee_stroops: 0,
            observed_ledger: state.ledger,
            day: now / allowit::DAY,
        }),
        terms.args.clone(),
    );
    let evaluation = policy::evaluate(
        PolicyTier::Simple,
        &shape,
        &[],
        &c.params,
        &standard,
        &request,
        evaluator,
    )?;
    if evaluation == policy::Evaluation::Prefix {
        return Err(
            "Classic custody needs full host evaluation: supply a compiled evaluator".into(),
        );
    }
    Ok(evaluation)
}
/// Check expense bounds as the kernel does, from the signer's trusted observations.
fn validate_expense(
    c: &WalletConfig,
    expense: &ExpenseBounds,
    operation: &StellarOperation,
    state: &TrustedState,
    now: u64,
) -> Result<()> {
    if expense.gas_units < 0
        || expense.conversion_units < 0
        || expense.spent_units < 0
        || expense.observed_ledger == 0
        || expense.observed_ledger > state.ledger
        || expense.day != now / allowit::DAY
    {
        return Err(
            "Expense bounds have negative units, a future observation or another day".into(),
        );
    }
    if (expense.max_fee_stroops == 0 && expense.gas_units != 0)
        || (expense.max_fee_stroops > 0 && expense.gas_units <= 0)
        || (asset_xdr(c)? == Asset::Native
            && expense.gas_units != i128::from(expense.max_fee_stroops))
    {
        return Err("Expense gas differs from its signed fee bound".into());
    }
    let principal = match operation {
        StellarOperation::Transfer(t) => {
            if expense.conversion_units != 0 {
                return Err("Transfers carry no conversion units".into());
            }
            t.amount
        }
        StellarOperation::Deposit(d) => {
            if expense.conversion_units > d.assets {
                return Err("Deposit conversion exceeds its assets".into());
            }
            expense.conversion_units
        }
        StellarOperation::Redeem(_) => expense.conversion_units,
    };
    if Some(expense.spent_units) != principal.checked_add(expense.gas_units) {
        return Err("Expense spent units must be principal plus gas".into());
    }
    Ok(())
}
fn verify_wallet_portable(
    c: &WalletConfig,
    operation: &StellarOperation,
    terms: &ExecutionTerms,
    state: &TrustedState,
    now: u64,
    expires_at: u64,
    evaluator: Option<policy::PortableEvaluator>,
) -> Result<policy::Evaluation> {
    let tier = c.tier.ok_or("Selected policy tier is required")?;
    let snapshot = state
        .policy_state
        .as_ref()
        .ok_or("Trusted layout 4 params and policy state are required")?;
    if state.contract_version != Some(CONTRACT_VERSION)
        || snapshot.source_digest != c.source_digest
        || snapshot.rules != c.rules
    {
        return Err("Installed policy wallet binding differs from the installation".into());
    }
    if let Some(expense) = &terms.expense {
        validate_expense(c, expense, operation, state, now)?;
    }
    let shape = policy::source_shape(&c.policy_source)?;
    let request = policy::RuleRequest::new(
        operation,
        &c.asset,
        now,
        expires_at,
        terms.expense.clone(),
        terms.args.clone(),
    );
    policy::evaluate(
        tier,
        &shape,
        &c.rules,
        &snapshot.params,
        &snapshot.state,
        &request,
        evaluator,
    )
}
fn muxed(value: &str) -> Result<MuxedAccount> {
    Ok(MuxedAccount::Ed25519(Uint256(account_key(value)?)))
}
fn transaction_hash(network: &str, tx: &Transaction) -> Result<[u8; 32]> {
    Ok(hash(
        TransactionSignaturePayload {
            network_id: Hash(network_id(network)?),
            tagged_transaction: TransactionSignaturePayloadTaggedTransaction::Tx(tx.clone()),
        }
        .to_xdr(limits())
        .map_err(err)?,
    ))
}
/// The transfer argument schema that historical ODC packets and bindings name. Retained ODC
/// bytes are rebuilt exactly, so this one historical descriptor stays.
pub(crate) const ODC_TRANSFER_SCHEMA: &[u8] =
    b"allowit.stellar.sep41_transfer.v1:ScValMap(amount:i128,from:Address,to:Address,token:Address)";
/// Historical transfer arguments of retained ODC packets.
fn legacy_transfer_args(c: &WalletConfig, t: &Transfer) -> Result<ScVal> {
    value_map(vec![
        ("amount", i128_value(t.amount)),
        ("from", ScVal::Address(address(&c.wallet)?)),
        ("to", ScVal::Address(address(&t.recipient)?)),
        ("token", ScVal::Address(address(&c.asset)?)),
    ])
}
/// The historical execution packet, kept only to verify retained ODC bytes.
fn legacy_wallet_request(
    c: &WalletConfig,
    r: &ExecutionRequest,
    state: &TrustedState,
    t: &Transfer,
    expires: u64,
    legacy_revision: bool,
) -> Result<ScVal> {
    let args = legacy_transfer_args(c, t)?.to_xdr(limits()).map_err(err)?;
    let invocation = value_map(vec![
        ("module_digest", value_bytes(&c.module_digest)?),
        ("entrypoint", value_symbol("_execute")?),
        (
            "argument_schema_digest",
            value_bytes(&hash(ODC_TRANSFER_SCHEMA))?,
        ),
        ("arguments", value_bytes(&args)?),
    ])?;
    value_map(vec![
        ("policy_instance", value_bytes(&c.policy_instance)?),
        ("operation_id", value_bytes(&r.operation.nonce)?),
        ("nonce", ScVal::U64(state.nonce)),
        (
            if legacy_revision {
                "revision"
            } else {
                "deployment_version"
            },
            ScVal::U64(state.deployment_version),
        ),
        ("expires_at", ScVal::U64(expires)),
        ("invocation", invocation),
    ])
}
/// The layout 4 `AllowitExecutionRequest` of one operation: the full source identity, the
/// executable, the typed native operation, the expense and the execution args.
pub(crate) fn policy_wallet_request(
    c: &WalletConfig,
    r: &ExecutionRequest,
    terms: &ExecutionTerms,
    state: &TrustedState,
    operation: &StellarOperation,
    expires: u64,
) -> Result<ScVal> {
    contract::execution_request(contract::ExecutionPacket {
        policy_instance: &c.policy_instance,
        source_hash: &c.source_hash,
        operation_id: &r.operation.nonce,
        nonce: state.nonce,
        deployment_version: state.deployment_version,
        expires_at: expires,
        module_digest: &c.module_digest,
        operation: contract::operation(&c.asset, operation)?,
        expense: contract::expense(terms.expense.as_ref())?,
        args: &terms.args,
    })
}
#[derive(Clone, Copy)]
enum PacketUse {
    Current,
    Retained,
    RetainedRevision,
    NativePreflight,
}
#[allow(clippy::too_many_arguments)]
fn build(
    c: &WalletConfig,
    r: &ExecutionRequest,
    terms: &ExecutionTerms,
    state: &TrustedState,
    now: u64,
    expires: u64,
    bounds: PacketBounds,
    packet: PacketUse,
) -> Result<Transaction> {
    let admit_policy = matches!(packet, PacketUse::Current);
    let legacy_revision = matches!(packet, PacketUse::RetainedRevision);
    if c.route == WalletRoute::Odc
        && matches!(packet, PacketUse::Current | PacketUse::NativePreflight)
    {
        return Err("Historical wallet packets are read-only".into());
    }
    match c.route {
        WalletRoute::Odc => {
            if legacy_revision {
                if state.contract_version.is_some() {
                    return Err("Legacy policy wallet packets are read-only".into());
                }
            } else if state.contract_version != Some(1) {
                return Err("Unsupported policy contract version".into());
            }
        }
        WalletRoute::PolicyWallet => {
            if legacy_revision || state.contract_version != Some(CONTRACT_VERSION) {
                return Err("Unsupported policy contract version".into());
            }
        }
        WalletRoute::Native => {
            if !terms.is_empty() {
                return Err("Classic custody carries no execution args or expense bounds".into());
            }
        }
    }
    if c.route != WalletRoute::PolicyWallet && !terms.is_empty() {
        return Err("Only policy wallet packets carry execution terms".into());
    }
    let operation = decode_operation(
        c,
        r,
        matches!(packet, PacketUse::Retained | PacketUse::RetainedRevision),
    )?;
    if admit_policy {
        verify_operation(c, r, terms, state, now, expires, None)?;
    }
    let day_end = (now / allowit::DAY)
        .checked_add(1)
        .and_then(|day| day.checked_mul(allowit::DAY))
        .ok_or("UTC boundary overflow")?;
    if terms.expense.is_some() && expires > day_end {
        return Err("Priced execution cannot cross its UTC expense day".into());
    }
    if c.route == WalletRoute::Native && expires > day_end {
        return Err("Native approval cannot cross its UTC budget day".into());
    }
    if expires <= now || expires > now.checked_add(300).ok_or("Expiry overflow")? {
        return Err("Operation expiry must be within 300 seconds".into());
    }
    if state.source_hash != c.source_hash {
        return Err("Installed authored source identity differs".into());
    }
    if state.policy_instance != c.policy_instance
        || (c.route == WalletRoute::Native && state.agent != c.agent)
        || (c.route != WalletRoute::Odc && state.server != c.server)
    {
        return Err("Trusted wallet identity differs".into());
    }
    let mut body = match c.route {
        WalletRoute::Native => {
            state.source.validate_wallet(c)?;
            let StellarOperation::Transfer(t) = &operation else {
                return Err("Classic custody admits only a transfer".into());
            };
            OperationBody::Payment(PaymentOp {
                destination: muxed(&t.recipient)?,
                asset: asset_xdr(c)?,
                amount: i64::try_from(t.amount).map_err(|_| "Classic payment exceeds i64")?,
            })
        }
        WalletRoute::PolicyWallet | WalletRoute::Odc => {
            state.source.validate_structure()?;
            if state.source.signer_weight(&c.agent)? == 0 {
                return Err("Customer is not a current policy wallet agent account signer".into());
            }
            if state.module_digest != c.module_digest || state.source.address != state.agent {
                return Err(
                    "policy wallet executable or current agent transaction source differs".into(),
                );
            }
            let fee = &r.fee_bounds.as_ref().ok_or("Native fee bound required")?[0];
            if workflow_address(&fee.payer)? != state.source.address {
                return Err(
                    "policy wallet fee payer differs from its current agent account".into(),
                );
            }
            let request = if c.route == WalletRoute::Odc {
                let StellarOperation::Transfer(t) = &operation else {
                    return Err("Historical wallet packets hold only transfers".into());
                };
                legacy_wallet_request(c, r, state, t, expires, legacy_revision)?
            } else {
                policy_wallet_request(c, r, terms, state, &operation, expires)?
            };
            let call = InvokeContractArgs {
                contract_address: address(&c.wallet)?,
                function_name: ScSymbol(b"execute".to_vec().try_into().map_err(err)?),
                args: vec![request].try_into().map_err(err)?,
            };
            OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                host_function: HostFunction::InvokeContract(call.clone()),
                auth: vec![SorobanAuthorizationEntry {
                    credentials: SorobanCredentials::SourceAccount,
                    root_invocation: SorobanAuthorizedInvocation {
                        function: SorobanAuthorizedFunction::ContractFn(call),
                        sub_invocations: VecM::default(),
                    },
                }]
                .try_into()
                .map_err(err)?,
            })
        }
    };
    if c.route == WalletRoute::PolicyWallet {
        let OperationBody::InvokeHostFunction(op) = &mut body else {
            unreachable!()
        };
        let mut auth = op.auth.to_vec();
        auth.push(authorization::server_entry(
            c,
            r,
            state,
            auth[0].root_invocation.clone(),
        )?);
        op.auth = auth.try_into().map_err(err)?;
    }
    let tx = Transaction {
        source_account: muxed(&state.source.address)?,
        fee: c.max_fee_stroops,
        seq_num: SequenceNumber(
            state
                .source
                .sequence
                .checked_add(1)
                .ok_or("Sequence overflow")?,
        ),
        cond: Preconditions::Time(transaction_bounds(c, now, expires, bounds)?),
        memo: if c.route == WalletRoute::Native {
            Memo::Hash(Hash(r.operation.nonce))
        } else {
            Memo::None
        },
        operations: vec![Operation {
            source_account: None,
            body,
        }]
        .try_into()
        .map_err(err)?,
        ext: TransactionExt::V0,
    };
    if c.route == WalletRoute::Native {
        account_transaction_signers(
            &state.source,
            &transaction_hash(&c.network, &tx)?,
            &automated_roles(c),
        )?;
    }
    Ok(tx)
}
/// The time bounds a packet carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PacketBounds {
    /// A new packet: `[0, expires_at - 1]`.
    Current,
    /// A retained classic packet: `[created_at, expires_at]`. Historical wallet packets always
    /// carry it.
    Original,
    /// A retained classic packet: `[0, expires_at]`.
    UnboundedStart,
}
/// Time bounds of a packet. A new packet has no lower bound, so a transaction that is signed
/// before the next ledger closes is never `txTOO_EARLY`. Its upper bound excludes the expiry
/// second, because Stellar's `maxTime` is inclusive while the request expiry, the policy
/// wallet's `expires_at <= now` check and the portable `expires_at` rule are exclusive: a
/// transaction that the network includes is never past its expiry. Retained packets keep their
/// original bounds.
fn transaction_bounds(
    c: &WalletConfig,
    now: u64,
    expires: u64,
    bounds: PacketBounds,
) -> Result<TimeBounds> {
    let (min_time, max_time) = match (&c.route, bounds) {
        (WalletRoute::Odc, _) | (_, PacketBounds::Original) => (now, expires),
        (_, PacketBounds::UnboundedStart) => (0, expires),
        (_, PacketBounds::Current) => (
            0,
            expires
                .checked_sub(1)
                .filter(|max| *max > 0)
                .ok_or("Invalid operation expiry")?,
        ),
    };
    Ok(TimeBounds {
        min_time: TimePoint(min_time),
        max_time: TimePoint(max_time),
    })
}
pub fn prepare(
    c: &WalletConfig,
    r: &ExecutionRequest,
    state: &TrustedState,
    now: u64,
    expires_at: u64,
) -> Result<PreparedOperation> {
    prepare_with(c, r, &ExecutionTerms::default(), state, now, expires_at)
}
/// Prepare one operation with its execution args and expense bounds.
pub fn prepare_with(
    c: &WalletConfig,
    r: &ExecutionRequest,
    terms: &ExecutionTerms,
    state: &TrustedState,
    now: u64,
    expires_at: u64,
) -> Result<PreparedOperation> {
    prepare_with_bounds(
        c,
        r,
        terms,
        state,
        now,
        expires_at,
        PacketBounds::Current,
        PacketUse::Current,
    )
}
#[allow(clippy::too_many_arguments)]
fn prepare_with_bounds(
    c: &WalletConfig,
    r: &ExecutionRequest,
    terms: &ExecutionTerms,
    state: &TrustedState,
    now: u64,
    expires_at: u64,
    bounds: PacketBounds,
    packet: PacketUse,
) -> Result<PreparedOperation> {
    let tx = build(c, r, terms, state, now, expires_at, bounds, packet)?;
    Ok(PreparedOperation {
        version: 1,
        config: c.clone(),
        request: r.clone(),
        terms: terms.clone(),
        state: state.clone(),
        transaction_xdr: xdr(&TransactionEnvelope::Tx(TransactionV1Envelope {
            tx: tx.clone(),
            signatures: VecM::default(),
        }))?,
        transaction_hash: transaction_hash(&c.network, &tx)?,
        request_hash: hash(serde_json::to_vec(r).map_err(err)?),
        simulation_data: None,
        created_at: now,
        expires_at,
        native_preflight: None,
    })
}
fn needs_native_preflight(c: &WalletConfig) -> Result<bool> {
    Ok(c.route == WalletRoute::PolicyWallet)
}
fn preflight_binding(p: &PreparedOperation) -> Result<[u8; 32]> {
    Ok(hash(serde_json::to_vec(p).map_err(err)?))
}
pub(crate) fn record_native_preflight(p: &mut PreparedOperation) -> Result<()> {
    p.native_preflight = Some(NativePreflight {
        binding: preflight_binding(p)?,
    });
    Ok(())
}
/// The unsigned policy wallet intent for native preflight. Portable verification runs first,
/// so a host-denied operation never reaches simulation.
pub(crate) fn prepare_for_native_preflight(
    c: &WalletConfig,
    r: &ExecutionRequest,
    terms: &ExecutionTerms,
    state: &TrustedState,
    now: u64,
    expires_at: u64,
) -> Result<PreparedOperation> {
    if c.route != WalletRoute::PolicyWallet {
        return prepare_with(c, r, terms, state, now, expires_at);
    }
    if state.policy_state.is_none() {
        return Err("Trusted layout 4 params and policy state are required".into());
    }
    verify_operation(c, r, terms, state, now, expires_at, None)?;
    prepare_with_bounds(
        c,
        r,
        terms,
        state,
        now,
        expires_at,
        PacketBounds::Current,
        PacketUse::NativePreflight,
    )
}
/// Policy wallets need the in-memory native preflight marker of this exact packet; every route
/// then checks the installed policy on the host.
fn validate_signing_policy(p: &PreparedOperation, now: u64) -> Result<()> {
    if needs_native_preflight(&p.config)? {
        let marker = p
            .native_preflight
            .as_ref()
            .ok_or("Native policy preflight is required before new signing")?;
        if marker.binding != preflight_binding(p)? {
            return Err("Native preflight no longer binds this exact operation".into());
        }
    }
    verify_operation(
        &p.config,
        &p.request,
        &p.terms,
        &p.state,
        now,
        p.expires_at,
        None,
    )
    .map(drop)
}
/// Rebuild every authorization field before signing. Caller-supplied prepared metadata is not trusted.
pub fn validate_prepared(p: &PreparedOperation, now: u64) -> Result<()> {
    if p.config.route == WalletRoute::Odc
        || (p.config.route == WalletRoute::PolicyWallet
            && p.state.contract_version != Some(CONTRACT_VERSION))
    {
        return Err(
            "Legacy or unsupported policy wallet packets cannot authorize execution".into(),
        );
    }
    if p.version != 1 || p.created_at > now || now >= p.expires_at {
        return Err("Prepared operation is stale".into());
    }
    validate_signing_policy(p, p.created_at)?;
    validate_retained_prepared(p)
}
/// Verify retained transport and effect identity for read-only history or recovery.
/// This does not compile source, grant authorization, or permit a broadcast.
/// Native signatures do not prove source metadata. Bind it to the durable owner-approved record first.
pub fn validate_retained_prepared(p: &PreparedOperation) -> Result<()> {
    if p.version != 1 {
        return Err("Unsupported retained operation version".into());
    }
    let bounds = packet_bounds(p)?;
    let mut expected = prepare_with_bounds(
        &p.config,
        &p.request,
        &p.terms,
        &p.state,
        p.created_at,
        p.expires_at,
        bounds,
        if retained_revision_packet(p)? {
            PacketUse::RetainedRevision
        } else {
            PacketUse::Retained
        },
    )?;
    if p.config.route == WalletRoute::PolicyWallet {
        expected = authorization::attach(&expected, authorization::server_signature(p, false)?)?;
    }
    if let Some(data) = &p.simulation_data {
        expected = attach_simulation(&expected, data)?;
    }
    if &expected != p {
        return Err("Prepared operation changed".into());
    }
    Ok(())
}
// Canonical main emitted revision packets before contract release metadata existed.
// This private decoder permits only original-byte status/recovery verification.
fn retained_revision_packet(p: &PreparedOperation) -> Result<bool> {
    if p.config.route != WalletRoute::Odc {
        return Ok(false);
    }
    let TransactionEnvelope::Tx(env) = read(&p.transaction_xdr)? else {
        return Err("Invalid retained envelope".into());
    };
    let Some(Operation {
        body: OperationBody::InvokeHostFunction(op),
        ..
    }) = env.tx.operations.first()
    else {
        return Err("Invalid retained policy wallet operation".into());
    };
    let HostFunction::InvokeContract(call) = &op.host_function else {
        return Err("Invalid retained policy wallet call".into());
    };
    let Some(ScVal::Map(Some(fields))) = call.args.first() else {
        return Err("Invalid retained policy wallet request".into());
    };
    let keys: Vec<_> = fields
        .iter()
        .filter_map(|f| match &f.key {
            ScVal::Symbol(k) => Some(k.0.as_slice()),
            _ => None,
        })
        .collect();
    match (
        p.state.contract_version,
        keys.contains(&b"revision".as_slice()),
        keys.contains(&b"deployment_version".as_slice()),
    ) {
        (None, true, false) => Ok(true),
        (Some(1), false, true) => Ok(false),
        _ => Err("Unsupported retained policy wallet contract format".into()),
    }
}
/// The bounds a packet carries. Historical wallet packets always carry their original bounds.
fn packet_bounds(p: &PreparedOperation) -> Result<PacketBounds> {
    if p.config.route == WalletRoute::Odc {
        return Ok(PacketBounds::Original);
    }
    let TransactionEnvelope::Tx(envelope) = read(&p.transaction_xdr)? else {
        return Err("Unsupported transaction envelope".into());
    };
    let Preconditions::Time(bounds) = envelope.tx.cond else {
        return Err("Transaction time bounds are required".into());
    };
    // Every policy wallet packet of the typed request carries the current bounds.
    let kinds: &[PacketBounds] = if p.config.route == WalletRoute::Native {
        &[
            PacketBounds::Current,
            PacketBounds::UnboundedStart,
            PacketBounds::Original,
        ]
    } else {
        &[PacketBounds::Current]
    };
    for kind in kinds {
        if bounds == transaction_bounds(&p.config, p.created_at, p.expires_at, *kind)? {
            return Ok(*kind);
        }
    }
    Err("Transaction time bounds changed".into())
}
fn current_authorization_bounds(p: &PreparedOperation) -> Result<()> {
    if packet_bounds(p)? != PacketBounds::Current {
        return Err("Retained transaction time bounds are read-only".into());
    }
    Ok(())
}
pub fn sign(p: &PreparedOperation, seed: &[u8; 32], now: u64) -> Result<DetachedSignature> {
    sign_with(p, &account_for_seed(seed), now, |digest| {
        Ok(SigningKey::from_bytes(seed).sign(digest).to_bytes())
    })
}
/// Sign through a caller-owned key capability after native admission checks.
/// The capability receives only the exact transaction hash and must return its Ed25519 signature.
pub fn sign_with(
    p: &PreparedOperation,
    signer: &str,
    now: u64,
    sign_hash: impl FnOnce(&[u8; 32]) -> Result<[u8; 64]>,
) -> Result<DetachedSignature> {
    validate_prepared(p, now)?;
    current_authorization_bounds(p)?;
    validate_signing_policy(p, now)?;
    if p.config.route == WalletRoute::PolicyWallet && p.simulation_data.is_none() {
        return Err("policy wallet resource simulation is required before signing".into());
    }
    if p.config.route == WalletRoute::PolicyWallet {
        authorization::server_signature(p, true)?;
    }
    let allowed = if p.config.route == WalletRoute::Native {
        signer == p.config.agent || signer == p.config.server
    } else {
        signer == p.config.agent
    };
    if !allowed {
        return Err("Signer has no automated role".into());
    }
    let signature = sign_hash(&p.transaction_hash)?;
    VerifyingKey::from_bytes(&account_key(signer)?)
        .map_err(err)?
        .verify_strict(&p.transaction_hash, &EdSignature::from_bytes(&signature))
        .map_err(|_| "Signing capability returned an invalid signature")?;
    Ok(DetachedSignature {
        signer: signer.into(),
        signature: signature.to_vec(),
    })
}
fn transaction_signers(p: &PreparedOperation, candidates: &[&str]) -> Result<Vec<String>> {
    account_transaction_signers(&p.state.source, &p.transaction_hash, candidates)
}
fn account_transaction_signers(
    source: &AccountState,
    transaction_hash: &[u8; 32],
    candidates: &[&str],
) -> Result<Vec<String>> {
    source.validate_structure()?;
    let automatic: Vec<_> = source.signers.iter().filter(|s| matches!(Strkey::from_string(&s.key), Ok(Strkey::PreAuthTx(key)) if key.0 == *transaction_hash)).collect();
    let automatic_weight = automatic.iter().map(|s| s.weight.min(255)).sum::<u32>();
    let mut masks: Vec<_> = (0usize..(1usize << candidates.len())).collect();
    masks.sort_by_key(|mask| (mask.count_ones(), *mask));
    for mask in masks {
        let chosen: Vec<_> = candidates
            .iter()
            .enumerate()
            .filter(|(n, _)| mask & (1 << n) != 0)
            .map(|(_, key)| *key)
            .collect();
        let mut used = std::collections::BTreeSet::new();
        let mut satisfies = |threshold: u32| -> Result<bool> {
            if !automatic.is_empty() && automatic_weight >= threshold {
                return Ok(true);
            }
            let mut weight = automatic_weight;
            for key in &chosen {
                let current = source.signer_weight(key)?;
                if current > 0 {
                    weight = weight
                        .checked_add(current)
                        .ok_or("Signer weight overflow")?;
                    used.insert(*key);
                    if weight >= threshold {
                        return Ok(true);
                    }
                }
            }
            Ok(false)
        };
        // The source authorizes the transaction at LOW; Payment and InvokeHostFunction
        // then authorize this same account at MEDIUM. Neither check uses HIGH.
        if satisfies(source.low_threshold)?
            && satisfies(source.medium_threshold)?
            && used.len() == chosen.len()
        {
            return Ok(chosen.into_iter().map(str::to_owned).collect());
        }
    }
    Err("Current account cannot authorize this exact transaction with the supplied keys".into())
}
pub fn authorize(
    p: &PreparedOperation,
    signatures: &[DetachedSignature],
    now: u64,
) -> Result<SignedOperation> {
    validate_prepared(p, now)?;
    current_authorization_bounds(p)?;
    if p.config.route == WalletRoute::PolicyWallet {
        authorization::server_signature(p, true)?;
    }
    let required = automated_roles(&p.config);
    let aliased_roles = p.config.route == WalletRoute::Native && p.config.agent == p.config.server;
    if signatures.len() != required.len() && !(aliased_roles && signatures.len() == 2) {
        return Err("Exact automated signature quorum required".into());
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut verified = std::collections::BTreeMap::new();
    let mut proofs = std::collections::BTreeMap::new();
    for s in signatures {
        if !required.contains(&s.signer.as_str())
            || (!seen.insert(s.signer.clone()) && !aliased_roles)
        {
            return Err("Unexpected or duplicate signature".into());
        }
        let key = account_key(&s.signer)?;
        let sig: [u8; 64] = s
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| "Invalid signature length")?;
        VerifyingKey::from_bytes(&key)
            .map_err(err)?
            .verify_strict(&p.transaction_hash, &EdSignature::from_bytes(&sig))
            .map_err(err)?;
        proofs.entry(s.signer.clone()).or_insert_with(|| s.clone());
        verified.insert(
            s.signer.clone(),
            DecoratedSignature {
                hint: SignatureHint(key[28..].try_into().unwrap()),
                signature: stellar_xdr::Signature(sig.to_vec().try_into().map_err(err)?),
            },
        );
    }
    let role_signatures = if p.config.route == WalletRoute::Native {
        required
            .iter()
            .map(|role| {
                proofs
                    .get(*role)
                    .cloned()
                    .ok_or("Missing automated role signature".to_string())
            })
            .collect::<Result<Vec<_>>>()?
    } else {
        Vec::new()
    };
    let candidates = required;
    let selected = transaction_signers(p, &candidates)?;
    let out: Vec<_> = selected
        .iter()
        .map(|key| {
            verified
                .get(key)
                .cloned()
                .ok_or("Missing selected role signature".to_string())
        })
        .collect::<Result<_>>()?;
    let TransactionEnvelope::Tx(mut env) = read(&p.transaction_xdr)? else {
        return Err("Unsupported transaction envelope".into());
    };
    env.signatures = out.try_into().map_err(err)?;
    Ok(SignedOperation {
        prepared: p.clone(),
        transaction_xdr: xdr(&TransactionEnvelope::Tx(env))?,
        transaction_hash: p.transaction_hash,
        role_signatures,
    })
}
/// Check the classic automated role proofs. `required` demands one proof per role key; a
/// retained record from before role proofs existed may carry none.
fn validate_role_signatures(s: &SignedOperation, required: bool) -> Result<()> {
    if s.prepared.config.route != WalletRoute::Native {
        if !s.role_signatures.is_empty() {
            return Err("Role proofs are only valid for classic custody".into());
        }
        return Ok(());
    }
    if s.role_signatures.is_empty() && !required {
        return Ok(());
    }
    let roles = automated_roles(&s.prepared.config);
    if s.role_signatures.len() != roles.len() {
        return Err("Every automated role must approve the exact transaction".into());
    }
    for (role, proof) in roles.iter().zip(&s.role_signatures) {
        if proof.signer != *role {
            return Err("Automated role proof order or signer differs".into());
        }
        let key = account_key(&proof.signer)?;
        let sig: [u8; 64] = proof
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| "Invalid role proof length")?;
        VerifyingKey::from_bytes(&key)
            .map_err(err)?
            .verify_strict(&s.transaction_hash, &EdSignature::from_bytes(&sig))
            .map_err(|_| "Invalid automated role proof")?;
    }
    Ok(())
}
pub fn validate_signed(s: &SignedOperation, now: u64) -> Result<()> {
    operation_from_request(&s.prepared.config, &s.prepared.request)?;
    if s.prepared.state.contract_version == Some(CONTRACT_VERSION)
        && needs_native_preflight(&s.prepared.config)?
    {
        if s.prepared.created_at > now || now >= s.prepared.expires_at {
            return Err("Signed operation is stale".into());
        }
    } else {
        validate_prepared(&s.prepared, now)?;
    }
    validate_retained_signed(s)?;
    // Broadcast needs both role approvals even when the agent alone meets the thresholds.
    validate_role_signatures(s, true)
}
/// Verify an original signed packet without reauthorizing retired policy source.
/// Callers must compare their durable original identity and use it only for status/recovery.
pub fn validate_retained_signed(s: &SignedOperation) -> Result<()> {
    validate_retained_prepared(&s.prepared)?;
    if s.prepared.config.route == WalletRoute::PolicyWallet {
        authorization::server_signature(&s.prepared, true)?;
    }
    if s.transaction_hash != s.prepared.transaction_hash {
        return Err("Signed transaction identity differs".into());
    }
    validate_role_signatures(s, false)?;
    let TransactionEnvelope::Tx(env) = read(&s.transaction_xdr)? else {
        return Err("Unsupported signed envelope".into());
    };
    let TransactionEnvelope::Tx(unsigned) = read(&s.prepared.transaction_xdr)? else {
        return Err("Unsupported unsigned envelope".into());
    };
    if env.tx != unsigned.tx {
        return Err("Signed transaction bytes differ".into());
    }
    let candidates = automated_roles(&s.prepared.config);
    let expected = transaction_signers(&s.prepared, &candidates)?;
    if env.signatures.len() != expected.len() {
        return Err("Signed transaction quorum differs".into());
    }
    let mut used = std::collections::BTreeSet::new();
    for sig in env.signatures.iter() {
        let mut matched = None;
        for signer in &expected {
            let key = account_key(signer)?;
            if sig.hint.0 == key[28..]
                && VerifyingKey::from_bytes(&key)
                    .map_err(err)?
                    .verify_strict(
                        &s.transaction_hash,
                        &EdSignature::from_slice(sig.signature.as_slice()).map_err(err)?,
                    )
                    .is_ok()
            {
                matched = Some((*signer).clone());
                break;
            }
        }
        let signer = matched.ok_or("Invalid transaction signature")?;
        if !used.insert(signer) {
            return Err("Duplicate transaction signer".into());
        }
    }
    Ok(())
}

/// Attach only RPC resource data. The exact invocation and authorization remain unchanged.
pub fn attach_simulation(p: &PreparedOperation, data: &str) -> Result<PreparedOperation> {
    if !matches!(p.config.route, WalletRoute::PolicyWallet | WalletRoute::Odc) {
        return Err("Resource data is only valid for policy wallet execution".into());
    }
    let resource: SorobanTransactionData = read(data)?;
    let required = u32::try_from(resource.resource_fee)
        .map_err(|_| "Invalid resource fee")?
        .checked_add(100)
        .ok_or("Resource fee overflow")?;
    if required > p.config.max_fee_stroops
        || p.terms
            .expense
            .as_ref()
            .is_some_and(|e| required > e.max_fee_stroops)
    {
        return Err("Simulation resource fee exceeds approved fee bound".into());
    }
    let TransactionEnvelope::Tx(mut env) = read(&p.transaction_xdr)? else {
        return Err("Unsupported transaction envelope".into());
    };
    env.tx.ext = TransactionExt::V1(resource);
    env.tx.fee = required;
    let mut out = p.clone();
    out.transaction_hash = transaction_hash(&p.config.network, &env.tx)?;
    out.transaction_xdr = xdr(&TransactionEnvelope::Tx(env))?;
    out.simulation_data = Some(data.into());
    // An unsigned service entry has not established the final transaction hash.
    // Exact source-account quorum is checked after that entry is signed.
    if out.config.route != WalletRoute::PolicyWallet
        || authorization::server_signature(&out, false)? != ScVal::Void
    {
        transaction_signers(&out, &automated_roles(&out.config))?;
    }
    Ok(out)
}
