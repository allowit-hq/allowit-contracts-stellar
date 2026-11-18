//! Stellar adapters for the existing typed execution request and operation lifecycle.
//! Native and policy wallet custody use the same authored policy and exact operation identity.

#[cfg(not(target_arch = "wasm32"))]
mod host;
#[cfg(not(target_arch = "wasm32"))]
pub mod plugin;
#[cfg(not(target_arch = "wasm32"))]
pub use plugin::PLUGIN;
#[cfg(not(target_arch = "wasm32"))]
pub mod provider;
#[cfg(all(not(target_arch = "wasm32"), any(test, feature = "test-support")))]
pub mod test_support;

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
// The bridge is built for the browser. Native test builds compile it to test its checks.
#[cfg(any(
    all(target_arch = "wasm32", feature = "browser-owner-verifier"),
    all(test, not(target_arch = "wasm32"))
))]
mod browser_owner;
pub mod contract;
pub mod networks;
pub mod owner;
pub mod owner_intent;
pub mod policy;
pub mod request;
pub mod workflow;
pub use authorization::{
    authorize_server, authorize_server_using, authorize_server_with, sign_account_entry,
    validate_server_authorization,
};
pub use contract::CONTRACT_VERSION;
pub use policy::{PolicyEngine, PolicyLanguage, PolicyParams, PolicyTier, PolicyValue};
pub mod packed;
pub mod rpc;
pub mod seller_settled;
#[cfg(not(target_arch = "wasm32"))]
pub mod settlement_service;
pub mod signing;
pub type Result<T> = std::result::Result<T, String>;

pub const PROFILE: &str = "allowit-wallet-v1";
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
        "stellar:pubnet" | "stellar:mainnet" => {
            Ok("Public Global Stellar Network ; September 2015")
        }
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
/// Encode an already derived public key using the native account address format.
pub fn account_for_public_key(key: &[u8; 32]) -> String {
    ed25519::PublicKey(*key).to_string()
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
impl WalletRoute {
    /// Existing native route spelling in owner approval and retained packet codecs.
    pub fn encoding(&self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::PolicyWallet => "policyWallet",
            Self::Odc => "odc",
        }
    }
}
pub(crate) fn no_amount(v: &i128) -> bool {
    *v == 0
}
pub(crate) fn is_false(v: &bool) -> bool {
    !*v
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
    /// The owner's fee ceiling of one operation, in stroops. For a policy wallet it is also the
    /// owner-signed gas cap: the most that the wallet repays for one request's network fee.
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
    pub fn allowit(self) -> allowit_core::AllowitOperation {
        match self {
            Self::Transfer => allowit_core::AllowitOperation::transfer,
            Self::Swap => allowit_core::AllowitOperation::swap,
            Self::Deposit => allowit_core::AllowitOperation::deposit,
            Self::Redeem => allowit_core::AllowitOperation::redeem,
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
/// The inclusion fee that a policy wallet transaction declares on top of its resource fee, in
/// stroops: the network's minimum base fee.
pub const INCLUSION_FEE_STROOPS: u32 = 100;
/// The margin of a fee bound is the simulated resource fee divided by this, rounded up: 1%.
const FEE_BOUND_MARGIN_DIVISOR: u32 = 100;
/// The fee bound that a policy wallet operation signs and its wallet counts as gas, from the
/// resource fee of a recording simulation of the same operation: the resource fee, the
/// inclusion fee and a 1% margin, rounded up.
///
/// The network charges a transaction at most its declared fee. It refunds the unused part of
/// the refundable resource fee (rent, events and the return value); the wallet contract cannot
/// observe that refund. The declared fee of the operation is its signed bound, and
/// `attach_simulation` refuses a simulation that needs more, so the counted gas is never below
/// the fee charged. The declared resource fee is the bound less the inclusion fee: it has the
/// margin of the bound above the simulated resource fee, so a resource fee that rises between
/// preparation and execution stays covered. A recording simulation
/// prices the server's authorization nonce at the longest entry lifetime, so its resource fee
/// covers the final enforce-mode simulation of the signed entry. The margin covers the change of
/// the resource fee between the two simulations: rent grows with each closed ledger, and the
/// rent rate follows the ledger state size.
pub fn fee_bound(resource_fee: i64) -> Result<u32> {
    let resource = u32::try_from(resource_fee).map_err(|_| "Invalid resource fee")?;
    resource
        .checked_add(INCLUSION_FEE_STROOPS)
        .and_then(|fee| fee.checked_add(resource.div_ceil(FEE_BOUND_MARGIN_DIVISOR)))
        .ok_or_else(|| "Resource fee overflow".into())
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
            day: now / allowit_core::DAY,
        })
    }
    /// These bounds with the fee bound lowered to `fee_stroops`. Gas falls pro rata and rounds
    /// up, so it never counts less than the gas rate of these bounds prices `fee_stroops`; for
    /// XLM it is `fee_stroops` itself. Spent units fall by the same gas.
    /// The bound of a transaction fee for terms whose gas repayment the server set itself, such
    /// as the gas that it repays after a carry: only the fee bound moves, and the gas that the
    /// wallet repays and counts stays.
    pub fn with_fee_bound_only(&self, fee_stroops: u32) -> Result<Self> {
        if fee_stroops == 0 || fee_stroops > self.max_fee_stroops {
            return Err("A fee bound lowers a positive fee ceiling".into());
        }
        Ok(Self {
            max_fee_stroops: fee_stroops,
            ..self.clone()
        })
    }
    /// The stroops that the wallet repays at these bounds after `carry`: the fee bound less the
    /// carry, at least zero.
    pub fn repaid_after_carry(&self, carry: u128) -> i128 {
        let bound = i128::from(self.max_fee_stroops);
        bound - i128::try_from(carry).unwrap_or(i128::MAX).min(bound)
    }
    /// These bounds when the wallet repays the fee bound less `carry`, at least zero: the gas
    /// that the server's account holds from earlier repayments above the fee that the ledger
    /// charged. The gas falls in proportion and rounds up, as for a lower fee bound, so an XLM
    /// wallet counts exactly what it repays and any wallet counts gas exactly when it repays
    /// some. Spent units fall by the same gas. The fee bound stays: the transaction can still be
    /// charged that much.
    pub fn with_gas_carry(&self, carry: u128) -> Result<Self> {
        if carry == 0 || self.max_fee_stroops == 0 {
            return Ok(self.clone());
        }
        if self.gas_units < 0 {
            return Err("A gas carry lowers nonnegative gas".into());
        }
        let bound = i128::from(self.max_fee_stroops);
        let repaid = self.repaid_after_carry(carry);
        let gas_units = self
            .gas_units
            .checked_mul(repaid)
            .and_then(|units| units.checked_add(bound - 1))
            .map(|units| units / bound)
            .ok_or("Expense overflow")?;
        Ok(Self {
            gas_units,
            spent_units: self
                .spent_units
                .checked_sub(self.gas_units)
                .and_then(|principal| principal.checked_add(gas_units))
                .ok_or("Expense overflow")?,
            ..self.clone()
        })
    }
    pub fn with_fee_bound(&self, fee_stroops: u32) -> Result<Self> {
        if fee_stroops == 0 || fee_stroops > self.max_fee_stroops || self.gas_units < 0 {
            return Err("A fee bound lowers a positive fee ceiling".into());
        }
        let ceiling = i128::from(self.max_fee_stroops);
        let gas_units = self
            .gas_units
            .checked_mul(i128::from(fee_stroops))
            .and_then(|units| units.checked_add(ceiling - 1))
            .map(|units| units / ceiling)
            .ok_or("Expense overflow")?;
        Ok(Self {
            gas_units,
            spent_units: self
                .spent_units
                .checked_sub(self.gas_units)
                .and_then(|principal| principal.checked_add(gas_units))
                .ok_or("Expense overflow")?,
            max_fee_stroops: fee_stroops,
            ..self.clone()
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
    /// The XLM that a policy wallet repays for the network fee, and its payee, when the server
    /// sets them; by default the expense's fee bound to the sending account.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gas: Option<GasRepayment>,
    /// The server's sending account of a policy wallet operation: its source, which pays the
    /// fee and receives the gas.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender: Option<String>,
    /// The stroops that the wallet repaid above the network fees of its earlier confirmed
    /// operations, as the server's account holds them. The default repayment is the fee bound
    /// less this carry, at least zero. An explicit `gas` takes no carry.
    #[serde(default, skip_serializing_if = "is_zero_carry")]
    pub gas_carry: u128,
}
fn is_zero_carry(carry: &u128) -> bool {
    *carry == 0
}
impl ExecutionTerms {
    pub fn is_empty(&self) -> bool {
        self.args.0.is_empty()
            && self.expense.is_none()
            && self.gas.is_none()
            && self.sender.is_none()
            && self.gas_carry == 0
    }
    /// The stroops that a policy wallet repays under these terms: the explicit repayment, else
    /// the fee bound of the expense less the gas carry, at least zero; nothing when unpriced.
    /// An explicit repayment takes no carry.
    pub fn repaid_stroops(&self) -> Result<i128> {
        match &self.gas {
            Some(_) if self.gas_carry != 0 => {
                Err("An explicit gas repayment takes no gas carry".into())
            }
            Some(gas) => Ok(gas.stroops),
            None => Ok(self
                .expense
                .as_ref()
                .map_or(0, |e| e.repaid_after_carry(self.gas_carry))),
        }
    }
}
/// The gas that a policy wallet repays in the transaction: `stroops` of XLM to `payee`, the
/// server's sending account, at most the owner-signed gas cap. The server signs it with the
/// request; a repayment above the fee is carried to the wallet's next request.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GasRepayment {
    pub stroops: i128,
    pub payee: String,
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
    /// Check the exact wallet account against independently selected public roles: this
    /// account is the wallet, its own key has weight 0, and its only signers are the owner
    /// (weight 3), the agent (weight 1) and the server (weight 1) under thresholds 2/2/3.
    /// A paused wallet, which has no agent signer, is refused: see [`Self::wallet_status`].
    /// This is current admission, not validation of a retained transaction after key rotation.
    pub fn validate_roles(&self, owner: &str, agent: &str, trusted_server: &str) -> Result<()> {
        match self.wallet_status(owner, agent, trusted_server)? {
            owner::WalletStatus::Active => Ok(()),
            owner::WalletStatus::Paused => {
                Err("This wallet is paused: its owner removed the agent signer".into())
            }
        }
    }
    /// The wallet account's exact roles, active or paused. Any other signer, a hash or
    /// pre-authorized signer, a threshold other than 2/2/3 or a weight on the account's own
    /// key is refused.
    pub fn wallet_status(
        &self,
        owner: &str,
        agent: &str,
        trusted_server: &str,
    ) -> Result<owner::WalletStatus> {
        self.validate_structure()?;
        for role in [owner, agent, trusted_server] {
            signing::canonical_account_key(role)?;
        }
        let differs = || -> Result<owner::WalletStatus> {
            Err("Current native account differs from the independently selected roles".into())
        };
        if [owner, agent, trusted_server].contains(&self.address.as_str())
            || owner == agent
            || owner == trusted_server
            || agent == trusted_server
            || self.master_weight != 0
            || self.low_threshold != owner::PAYMENT_THRESHOLD
            || self.medium_threshold != owner::PAYMENT_THRESHOLD
            || self.high_threshold != owner::OWNER_THRESHOLD
        {
            return differs();
        }
        let weight = |key: &str| self.signers.iter().find(|s| s.key == key).map(|s| s.weight);
        if weight(owner) != Some(owner::OWNER_WEIGHT)
            || weight(trusted_server) != Some(owner::AUTOMATED_WEIGHT)
        {
            return differs();
        }
        match (weight(agent), self.signers.len()) {
            (Some(owner::AUTOMATED_WEIGHT), 3) => Ok(owner::WalletStatus::Active),
            (None, 2) => Ok(owner::WalletStatus::Paused),
            _ => differs(),
        }
    }
    /// Verify every administrator signature and the current high-threshold quorum.
    /// Zero-weight and nonmember signatures are errors even beside a sufficient quorum.
    pub fn validate_authority_signatures(
        &self,
        digest: &[u8; 32],
        signatures: &[DetachedSignature],
    ) -> Result<()> {
        self.validate_structure()?;
        if signatures.is_empty()
            || signatures.len() > 20
            || self.signers.iter().any(|s| s.weight > 255)
        {
            return Err("Invalid current administrator signatures or weights".into());
        }
        let mut signers = std::collections::BTreeSet::new();
        for signature in signatures {
            if !signers.insert(signature.signer.as_str())
                || self.signer_weight(&signature.signer)? == 0
            {
                return Err("Repeated or inactive administrator signer".into());
            }
            signing::verify_digest(&signature.signer, digest, &signature.signature)?;
        }
        self.validate_signer_quorum(
            &signers.into_iter().collect::<Vec<_>>(),
            self.high_threshold,
        )
    }
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
/// The state entries of a Custom policy source: the same scan as the contract's build.
#[path = "../../../contracts/allowit-custom-policy/state_keys.rs"]
pub mod state_keys;
/// The declared state entries of a Custom policy source, as its build declares them.
pub fn custom_state_entries(source: &str) -> Result<Vec<state_keys::StateEntry>> {
    state_keys::declared(source, |name| hash(name)).map(|(entries, _)| entries)
}
/// Chain-observed policy inputs of a layout 4 policy wallet.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyStateSnapshot {
    /// A Custom policy's own state entries at the snapshot's ledger, by key name.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub custom: std::collections::BTreeMap<String, PolicyValue>,
    /// Current owner params.
    pub params: PolicyParams,
    /// Installed ordered canonical rules.
    pub rules: Vec<String>,
    /// The owner-signed hash of the owner's full policy source.
    pub source_hash: [u8; 32],
    /// The cumulated figures that the wallet keeps, read at the snapshot's ledger.
    pub figures: packed::Figures,
}
impl PolicyStateSnapshot {
    /// Core's standard state before an operation at `now`: the totals, and the daily figures of
    /// an open window as the figures of today. The wallet's day is the life of its daily entry,
    /// not a UTC day, and it feeds its rules the same way.
    pub fn standard_state(&self, now: u64) -> PolicyParams {
        let f = &self.figures;
        let open = f.day_ends != 0;
        let mut state = std::collections::BTreeMap::new();
        state.insert("calls".to_owned(), PolicyValue::Int(i128::from(f.calls)));
        state.insert("spent".to_owned(), PolicyValue::Int(f.spent));
        state.insert("unpriced".to_owned(), PolicyValue::Bool(f.unpriced));
        state.insert(
            "day".to_owned(),
            PolicyValue::Int(i128::from(now / allowit_core::DAY)),
        );
        state.insert(
            "day_spent".to_owned(),
            PolicyValue::Int(if open { f.day_spent } else { 0 }),
        );
        state.insert(
            "day_total".to_owned(),
            PolicyValue::Int(if open { f.day_total } else { 0 }),
        );
        state.insert(
            "day_unpriced".to_owned(),
            PolicyValue::Bool(open && f.day_unpriced),
        );
        // A Custom policy reads its own state beside the figures.
        state.extend(self.custom.clone());
        PolicyParams(state)
    }
}
impl TrustedState {
    /// Core's standard state of a policy wallet before an operation at `now`: each figure that
    /// the wallet keeps comes from the wallet, and the server's accounting in this state gives
    /// every other one, as for a keypair wallet.
    pub fn policy_wallet_state(&self, c: &WalletConfig, now: u64) -> Result<PolicyParams> {
        let snapshot = self
            .policy_state
            .as_ref()
            .ok_or("Trusted layout 5 params and figures are required")?;
        let kept = kept_figures(c);
        let wallet = &snapshot.figures;
        let open = wallet.day_ends != 0;
        let today = now / allowit_core::DAY;
        let server_today = self.spent_day == today;
        let pick =
            |figure: u8, own: i128, server: i128| if kept & figure != 0 { own } else { server };
        let mut state = std::collections::BTreeMap::new();
        state.insert(
            "calls".to_owned(),
            PolicyValue::Int(pick(
                packed::CALLS,
                i128::from(wallet.calls),
                i128::from(self.calls),
            )),
        );
        state.insert(
            "spent".to_owned(),
            PolicyValue::Int(pick(packed::SPENT, wallet.spent, self.spent_total)),
        );
        state.insert(
            "unpriced".to_owned(),
            PolicyValue::Bool(if kept & packed::SPENT != 0 {
                wallet.unpriced
            } else {
                self.unpriced_total
            }),
        );
        state.insert("day".to_owned(), PolicyValue::Int(i128::from(today)));
        let server_daily = if server_today { self.spent_daily } else { 0 };
        let server_volume = if server_today { self.volume_daily } else { 0 };
        let own_daily = |value: i128| if open { value } else { 0 };
        state.insert(
            "day_spent".to_owned(),
            PolicyValue::Int(pick(
                packed::DAY_SPENT,
                own_daily(wallet.day_spent),
                server_daily,
            )),
        );
        state.insert(
            "day_total".to_owned(),
            PolicyValue::Int(pick(
                packed::DAY_TOTAL,
                own_daily(wallet.day_total),
                server_volume,
            )),
        );
        state.insert(
            "day_unpriced".to_owned(),
            PolicyValue::Bool(if kept & (packed::DAY_SPENT | packed::DAY_TOTAL) != 0 {
                open && wallet.day_unpriced
            } else {
                server_today && self.unpriced_daily
            }),
        );
        state.extend(snapshot.custom.clone());
        Ok(PolicyParams(state))
    }
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
    /// The server's gross volume on `spent_day`, and its unpriced flags: figures that a policy
    /// wallet which does not keep them reads from the server's accounting.
    #[serde(default, skip_serializing_if = "no_amount")]
    pub volume_daily: i128,
    #[serde(default, skip_serializing_if = "is_false")]
    pub unpriced_total: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub unpriced_daily: bool,
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
impl TrustedState {
    /// The weight of `signer` in a policy wallet, as a keypair wallet's account weighs its
    /// signers: the owner acts alone (3), the agent and the server only together (1 each), and
    /// any other key has none. A policy wallet has no account signers; the configuration that
    /// it holds on chain names its owner, agent and server, which this state carries.
    pub fn policy_role_weight(&self, signer: &str) -> Result<u32> {
        if self.policy_state.is_none() {
            return Err("Only a policy wallet weighs its configured roles".into());
        }
        account_key(signer)?;
        Ok(if signer == self.owner {
            3
        } else if signer == self.agent || signer == self.server {
            1
        } else {
            0
        })
    }
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
    /// Set when the seller settles the payment: the operation is a payment authorization for
    /// the seller's facilitator, and nobody signs or sends `transaction_xdr`. See
    /// [`seller_settled`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment_authorization: Option<Box<seller_settled::PaymentAuthorization>>,
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
            && self.payment_authorization == other.payment_authorization
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

/// The figures that a policy wallet keeps for its checks: a Simple or Common wallet those of its
/// rules with params; a Custom wallet every figure that its compiled source reads, which are the
/// only ones that the source can read on the server too.
pub fn kept_figures(c: &WalletConfig) -> u8 {
    if c.tier == Some(PolicyTier::Custom) {
        return packed::ALL;
    }
    packed::standard_kept(&c.rules, &installed_params(c))
}
/// The params that a policy wallet stores: a Simple or Common wallet keeps only the params of its
/// on-chain rules, and the server keeps the rest of the owner's params; a Custom wallet keeps all.
pub fn installed_params(c: &WalletConfig) -> PolicyParams {
    if c.tier == Some(PolicyTier::Custom) {
        return c.params.clone();
    }
    PolicyParams(
        c.params
            .0
            .iter()
            .filter(|(key, _)| c.rules.contains(key))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
    )
}
pub fn validate_config(c: &WalletConfig) -> Result<()> {
    validate_config_for(c, true)
}
// Retained packets prove transport/effect identity. Their original owner-approved source
// binding belongs to the caller's durable record; current source admission cannot replace it.
/// Validate a retained configuration's immutable structure without admitting source for new actions.
pub fn validate_retained_configuration(c: &WalletConfig) -> Result<()> {
    validate_config_for(c, false)
}
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
/// Classic custody enforces nothing onchain, so the host runs the whole portable policy. A
/// canonical-only source is one `execute` of canonical rule calls over canonical params: every
/// prepare and sign path runs it in full. Any other source needs the compiled evaluator of
/// the server, which admits each operation of it with [`admit_classic`] before it signs. Such
/// a source takes the bounded params of a Custom policy, so it can read owner text.
fn validate_classic_portable_install(c: &WalletConfig) -> Result<()> {
    let shape = policy::classic_shape(&c.policy_source)?;
    if shape.writes_state {
        return Err(CLASSIC_WRITES_STATE.into());
    }
    let tier = classic_tier(&shape);
    c.params.check(tier).map_err(|e| {
        if tier == PolicyTier::Simple {
            format!("Portable classic custody reads only canonical params for a canonical-only source: {e}")
        } else {
            e
        }
    })
}
/// A classic account stores no policy state, so no source of it writes any.
const CLASSIC_WRITES_STATE: &str = "Classic custody cannot store allowit::set_state writes";
/// The param and evaluation rules of a classic account's source: those of a Simple policy for
/// a canonical-only source, and those of a Custom policy for any other.
fn classic_tier(shape: &policy::SourceShape) -> PolicyTier {
    if shape.canonical_only {
        PolicyTier::Simple
    } else {
        PolicyTier::Custom
    }
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
    // Only a Custom wallet stores its policy's own state: the entries that its build declares.
    if shape.writes_state && tier != PolicyTier::Custom {
        return Err(policy::WRITES_STATE.into());
    }
    if tier == PolicyTier::Custom {
        custom_state_entries(&c.policy_source)?;
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
/// Read the effect of an original retained request. This grants no fresh execution authority.
pub fn retained_operation_from_request(
    c: &WalletConfig,
    r: &ExecutionRequest,
) -> Result<StellarOperation> {
    decode_operation(c, r, true)
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
    // A policy wallet's request may name no fee payer: the server's sending account pays and
    // the preparation names it as the gas payee.
    if c.route == WalletRoute::PolicyWallet && r.fee_bounds.is_none() {
        return Ok(operation);
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
/// A canonical-only source runs in full here. Any other source runs in full only with
/// `evaluator`. Without one the result is `Evaluation::Prefix`: the execution terms are
/// checked and nothing of the policy ran. The agent's client prepares and signs so, because it
/// has no evaluator and its signature alone moves nothing. The server admits the operation
/// with [`admit_classic`], which requires the full evaluation.
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
    let shape = policy::classic_shape(&c.policy_source)?;
    if shape.writes_state {
        return Err(CLASSIC_WRITES_STATE.into());
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
            day: now / allowit_core::DAY,
        }),
        terms.args.clone(),
    );
    policy::evaluate(
        classic_tier(&shape),
        &shape,
        &[],
        &c.params,
        &standard,
        &request,
        evaluator,
        None,
    )
}
/// The server's admission of one prepared operation of a classic account: the whole installed
/// policy on the policy context of that exact operation. A source that is not canonical-only
/// needs `evaluator`, the compiled evaluator that the server's policy build gate made from
/// `config.policy_source`. The server calls this before it stores the operation, and it signs
/// only an operation that it stored: [`sign_with`] cannot tell whether this ran.
pub fn admit_classic(
    p: &PreparedOperation,
    signer_account: &str,
    now: u64,
    evaluator: Option<policy::PortableEvaluator>,
) -> Result<()> {
    if p.config.route != WalletRoute::Native || signer_account != p.config.server {
        return Err("Configured classic account server signer required".into());
    }
    validate_prepared(p, now)?;
    let evaluation = verify_operation(
        &p.config,
        &p.request,
        &p.terms,
        &p.state,
        now,
        p.expires_at,
        evaluator,
    )?;
    if evaluation == policy::Evaluation::Prefix {
        return Err(
            "The server must evaluate the full policy of a classic account; supply its compiled evaluator"
                .into(),
        );
    }
    Ok(())
}
/// Check expense bounds as the kernel does, from the signer's trusted observations.
fn validate_expense(
    c: &WalletConfig,
    expense: &ExpenseBounds,
    repaid: i128,
    operation: &StellarOperation,
    state: &TrustedState,
    now: u64,
) -> Result<()> {
    if expense.gas_units < 0
        || expense.conversion_units < 0
        || expense.spent_units < 0
        || expense.observed_ledger == 0
        || expense.observed_ledger > state.ledger
        || expense.day != now / allowit_core::DAY
    {
        return Err(
            "Expense bounds have negative units, a future observation or another day".into(),
        );
    }
    // As the kernel checks: the wallet counts gas exactly when it repays some, and an XLM
    // wallet counts the repaid stroops.
    if (repaid == 0) != (expense.gas_units == 0)
        || (asset_xdr(c)? == Asset::Native && expense.gas_units != repaid)
    {
        return Err("Expense gas differs from the gas that the wallet repays".into());
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
        .ok_or("Trusted layout 5 params and figures are required")?;
    // The wallet stores the params of its on-chain rules; the server holds the rest of the
    // owner's params, and the source runs over all of them.
    if state.contract_version != Some(CONTRACT_VERSION)
        || snapshot.source_hash != c.source_hash
        || snapshot.rules != c.rules
        || snapshot.params != installed_params(c)
    {
        return Err("Installed policy wallet binding differs from the installation".into());
    }
    if let Some(expense) = &terms.expense {
        validate_expense(c, expense, terms.repaid_stroops()?, operation, state, now)?;
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
    let declared: Vec<String> = if tier == PolicyTier::Custom {
        custom_state_entries(&c.policy_source)?
            .into_iter()
            .map(|entry| entry.name)
            .collect()
    } else {
        vec![]
    };
    policy::evaluate(
        tier,
        &shape,
        &c.rules,
        &c.params,
        &state.policy_wallet_state(c, now)?,
        &request,
        evaluator,
        Some(&declared),
    )
}
fn muxed(value: &str) -> Result<MuxedAccount> {
    Ok(MuxedAccount::Ed25519(Uint256(account_key(value)?)))
}
/// Native signature-payload digest, without admitting or signing the transaction.
pub fn transaction_hash(network: &str, tx: &Transaction) -> Result<[u8; 32]> {
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
/// The gas that a policy wallet repays for `r`: the explicit repayment of `terms`, else the fee
/// bound of its expense less the server's gas carry, at least zero, in stroops. The payee is the
/// server's sending account, which `terms` or the request's fee payer names; when both name one,
/// they agree. An unpriced request repays nothing.
pub(crate) fn gas_repayment(r: &ExecutionRequest, terms: &ExecutionTerms) -> Result<GasRepayment> {
    let payer = match &r.fee_bounds {
        Some(fees) => Some(workflow_address(
            &fees.first().ok_or("Native fee bound required")?.payer,
        )?),
        None => None,
    };
    let named = [
        payer,
        terms.sender.clone(),
        terms.gas.as_ref().map(|g| g.payee.clone()),
    ];
    let mut sender: Option<String> = None;
    for account in named.into_iter().flatten() {
        if sender.as_ref().is_some_and(|s| *s != account) {
            return Err(
                "The request, the sending account and the gas payee name other accounts".into(),
            );
        }
        sender = Some(account);
    }
    let stroops = terms.repaid_stroops()?;
    if let Some(gas) = &terms.gas {
        return Ok(gas.clone());
    }
    Ok(GasRepayment {
        stroops,
        payee: sender.ok_or(
            "A policy wallet operation needs the server's sending account as its gas payee",
        )?,
    })
}
/// The sending account that a policy wallet operation names: the payee of its gas repayment and
/// the fee payer of its request.
pub fn gas_payee(r: &ExecutionRequest, terms: &ExecutionTerms) -> Result<String> {
    Ok(gas_repayment(r, terms)?.payee)
}
/// The layout 5 `AllowitExecutionRequest` of one operation: its id, the wallet's deployment
/// version, the expiry, the typed native operation, the expense, the gas repayment and the
/// execution args.
pub(crate) fn policy_wallet_request(
    c: &WalletConfig,
    r: &ExecutionRequest,
    terms: &ExecutionTerms,
    state: &TrustedState,
    operation: &StellarOperation,
    expires: u64,
) -> Result<ScVal> {
    let gas = gas_repayment(r, terms)?;
    contract::execution_request(contract::ExecutionPacket {
        operation_id: &r.operation.nonce,
        deployment_version: u32::try_from(state.deployment_version)
            .map_err(|_| "Deployment version exceeds u32")?,
        expires_at: expires,
        operation: contract::operation(&c.asset, operation)?,
        expense: contract::expense(terms.expense.as_ref())?,
        gas_stroops: gas.stroops,
        gas_payee: &gas.payee,
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
    let day_end = (now / allowit_core::DAY)
        .checked_add(1)
        .and_then(|day| day.checked_mul(allowit_core::DAY))
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
    let body = match c.route {
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
        WalletRoute::Odc => {
            state.source.validate_structure()?;
            if state.source.signer_weight(&c.agent)? == 0 {
                return Err("Customer is not a current policy wallet agent account signer".into());
            }
            if state.module_digest != c.module_digest || state.source.address != state.agent {
                return Err(
                    "policy wallet executable or current agent transaction source differs".into(),
                );
            }
            let StellarOperation::Transfer(t) = &operation else {
                return Err("Historical wallet packets hold only transfers".into());
            };
            let request = legacy_wallet_request(c, r, state, t, expires, legacy_revision)?;
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
        WalletRoute::PolicyWallet => {
            // The server's sending account is the source and pays the fee. The agent holds a key
            // and no account: it signs the wallet's own authorization with the server.
            state.source.validate_structure()?;
            if state.module_digest != c.module_digest {
                return Err("policy wallet executable differs".into());
            }
            if gas_payee(r, terms)? != state.source.address {
                return Err("policy wallet gas payee differs from the sending account".into());
            }
            let request = policy_wallet_request(c, r, terms, state, &operation, expires)?;
            let call = InvokeContractArgs {
                contract_address: address(&c.wallet)?,
                function_name: ScSymbol(b"execute".to_vec().try_into().map_err(err)?),
                args: vec![request].try_into().map_err(err)?,
            };
            OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                host_function: HostFunction::InvokeContract(call.clone()),
                auth: vec![authorization::wallet_entry(c, r, state, call)?]
                    .try_into()
                    .map_err(err)?,
            })
        }
    };
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
        payment_authorization: None,
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
        return Err("Trusted layout 5 params and figures are required".into());
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
    if p.payment_authorization.is_some() {
        // A payment authorization is admitted on the terms that its signers sign.
        return seller_settled::admit(p, now).map(drop);
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
    // The authorization part is checked against the operation around it, not rebuilt here.
    expected
        .payment_authorization
        .clone_from(&p.payment_authorization);
    if p.config.route == WalletRoute::PolicyWallet {
        expected = authorization::attach(&expected, authorization::wallet_signature(p)?)?;
    }
    if let Some(data) = &p.simulation_data {
        let current = attach_simulation(&expected, data)?;
        // A packet of an earlier release declares the simulated resource fee itself.
        expected = if &current == p {
            current
        } else {
            attach_resources(&expected, data, false)?
        };
    }
    if &expected != p {
        return Err("Prepared operation changed".into());
    }
    if p.payment_authorization.is_some() {
        seller_settled::validate(p)?;
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
/// The digest that the agent signs: for a policy wallet, the payload of the wallet's own
/// authorization entry, which the server has signed too; else the transaction hash.
pub fn signing_digest(p: &PreparedOperation) -> Result<[u8; 32]> {
    if p.config.route == WalletRoute::PolicyWallet {
        authorization::wallet_payload(p)
    } else {
        Ok(p.transaction_hash)
    }
}
pub fn sign_with(
    p: &PreparedOperation,
    signer: &str,
    now: u64,
    sign_hash: impl FnOnce(&[u8; 32]) -> Result<[u8; 64]>,
) -> Result<DetachedSignature> {
    if p.payment_authorization.is_some() {
        return seller_settled::sign(p, signer, now, sign_hash);
    }
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
    let digest = signing_digest(p)?;
    let signature = sign_hash(&digest)?;
    VerifyingKey::from_bytes(&account_key(signer)?)
        .map_err(err)?
        .verify_strict(&digest, &EdSignature::from_bytes(&signature))
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
    if p.payment_authorization.is_some() {
        // The assembly of a payment authorization checks it against the ledger.
        return Err("Assemble a payment authorization with seller_settled::authorize".into());
    }
    validate_prepared(p, now)?;
    current_authorization_bounds(p)?;
    if p.config.route == WalletRoute::PolicyWallet {
        return authorize_wallet(p, signatures);
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
/// A signed policy wallet operation: the prepared transaction with both cosignatures in the
/// wallet's entry and, once the sending account sealed it, the final resources and fee and that
/// account's one signature. Nothing else differs from the prepared transaction.
fn validate_wallet_signed(s: &SignedOperation) -> Result<()> {
    let p = &s.prepared;
    if !s.role_signatures.is_empty() {
        return Err("A policy wallet operation carries no role signatures".into());
    }
    let TransactionEnvelope::Tx(env) = read(&s.transaction_xdr)? else {
        return Err("Unsupported signed envelope".into());
    };
    let TransactionEnvelope::Tx(unsigned) = read(&p.transaction_xdr)? else {
        return Err("Unsupported unsigned envelope".into());
    };
    let mut assembled = p.clone();
    assembled.transaction_xdr = xdr(&TransactionEnvelope::Tx(TransactionV1Envelope {
        tx: env.tx.clone(),
        signatures: VecM::default(),
    }))?;
    let (Some(_), Some(_)) = authorization::cosignatures(&assembled)? else {
        return Err("The wallet's authorization lacks a cosignature".into());
    };
    let mut normalized = env.tx.clone();
    normalized.fee = unsigned.tx.fee;
    normalized.ext = unsigned.tx.ext.clone();
    let mut operations = normalized.operations.to_vec();
    let mut original = unsigned.tx.operations.to_vec();
    if let (
        Some(OperationBody::InvokeHostFunction(op)),
        Some(OperationBody::InvokeHostFunction(prepared_op)),
    ) = (
        operations.first_mut().map(|o| &mut o.body),
        original.first_mut().map(|o| &mut o.body),
    ) {
        op.auth = prepared_op.auth.clone();
    }
    normalized.operations = operations.try_into().map_err(err)?;
    if normalized != unsigned.tx {
        return Err("Signed transaction bytes differ".into());
    }
    if env.tx.fee > p.config.max_fee_stroops {
        return Err("The sealed fee exceeds the installed fee ceiling".into());
    }
    if s.transaction_hash != transaction_hash(&p.config.network, &env.tx)? {
        return Err("Signed transaction identity differs".into());
    }
    match env.signatures.as_slice() {
        [] => Ok(()),
        [signature] => {
            let MuxedAccount::Ed25519(Uint256(key)) = &env.tx.source_account else {
                return Err("The sending account is a plain account".into());
            };
            if signature.hint.0 != key[28..] {
                return Err("The source signature is not the sending account's".into());
            }
            VerifyingKey::from_bytes(key)
                .map_err(err)?
                .verify_strict(
                    &s.transaction_hash,
                    &EdSignature::from_slice(signature.signature.as_slice()).map_err(err)?,
                )
                .map_err(|_| "Invalid sending account signature".into())
        }
        _ => Err("The sending account signs alone".into()),
    }
}
/// The agent's step of a policy wallet operation: its one signature of the wallet's payload joins
/// the server's in the wallet's entry. The envelope stays unsigned: the server's sending account
/// simulates it for its final resources, signs it as the source and sends it (`rpc::seal`).
fn authorize_wallet(
    p: &PreparedOperation,
    signatures: &[DetachedSignature],
) -> Result<SignedOperation> {
    let server =
        authorization::server_signature(p, true)?.ok_or("Service authorization is unsigned")?;
    let [s] = signatures else {
        return Err("The agent's one signature of the wallet's authorization is required".into());
    };
    if s.signer != p.config.agent {
        return Err("Unexpected or duplicate signature".into());
    }
    let agent: [u8; 64] = s
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| "Invalid signature length")?;
    signing::verify_digest(&p.config.agent, &authorization::wallet_payload(p)?, &agent)?;
    let out = authorization::attach(p, contract::cosignatures(&agent, &server)?)?;
    Ok(SignedOperation {
        prepared: p.clone(),
        transaction_xdr: out.transaction_xdr,
        transaction_hash: out.transaction_hash,
        role_signatures: Vec::new(),
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
    if s.prepared.payment_authorization.is_some() {
        seller_settled::admit(&s.prepared, now)?;
        return seller_settled::validate_signed(s);
    }
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
    if s.prepared.payment_authorization.is_some() {
        return seller_settled::validate_signed(s);
    }
    validate_retained_prepared(&s.prepared)?;
    if s.prepared.config.route == WalletRoute::PolicyWallet {
        return validate_wallet_signed(s);
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
///
/// An operation with a signed expense bound declares that bound as its fee, and the bound less
/// the inclusion fee as its resource fee. The network charges the resources that the
/// transaction uses and refunds the rest, so the declared headroom costs nothing, and the fee
/// charged stays at or below the gas that the wallet counts. Without it, a resource fee that
/// rises between this simulation and the server's simulation at execution refuses the
/// operation.
pub fn attach_simulation(p: &PreparedOperation, data: &str) -> Result<PreparedOperation> {
    attach_resources(p, data, true)
}
/// `attach_simulation`, or with `headroom` false the rule of earlier releases, which declared
/// the simulated resource fee itself. Retained packets of those releases stay verifiable.
fn attach_resources(
    p: &PreparedOperation,
    data: &str,
    headroom: bool,
) -> Result<PreparedOperation> {
    if !matches!(p.config.route, WalletRoute::PolicyWallet | WalletRoute::Odc) {
        return Err("Resource data is only valid for policy wallet execution".into());
    }
    let mut resource: SorobanTransactionData = read(data)?;
    let required = u32::try_from(resource.resource_fee)
        .map_err(|_| "Invalid resource fee")?
        .checked_add(INCLUSION_FEE_STROOPS)
        .ok_or("Resource fee overflow")?;
    if required > p.config.max_fee_stroops
        || p.terms
            .expense
            .as_ref()
            .is_some_and(|e| required > e.max_fee_stroops)
    {
        return Err("Simulation resource fee exceeds approved fee bound".into());
    }
    // The signed bound is at least the simulated fee here, and never above the installed
    // ceiling, so the declared fee is within both.
    let declared = match &p.terms.expense {
        Some(expense) if headroom => expense.max_fee_stroops.min(p.config.max_fee_stroops),
        _ => required,
    };
    resource.resource_fee = i64::from(declared - INCLUSION_FEE_STROOPS);
    let TransactionEnvelope::Tx(mut env) = read(&p.transaction_xdr)? else {
        return Err("Unsupported transaction envelope".into());
    };
    env.tx.ext = TransactionExt::V1(resource);
    env.tx.fee = declared;
    let mut out = p.clone();
    out.transaction_hash = transaction_hash(&p.config.network, &env.tx)?;
    out.transaction_xdr = xdr(&TransactionEnvelope::Tx(env))?;
    out.simulation_data = Some(data.into());
    // A policy wallet's source is the server's sending account, which signs last; the agent and
    // the server sign the wallet's own authorization instead.
    if out.config.route != WalletRoute::PolicyWallet {
        transaction_signers(&out, &automated_roles(&out.config))?;
    }
    Ok(out)
}
