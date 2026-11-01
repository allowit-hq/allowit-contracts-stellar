#![no_std]
use soroban_sdk::{Address, BytesN, Map, Symbol, contractevent, contracttype};

/// The general operation that policy rules read.
pub use allowit::AllowitOperation;
/// The one value type of owner params, execution params and policy state.
pub use allowit::AllowitValue;

/// Most tokens in one swap path: the paid token, up to two intermediate tokens and the received token.
pub const MAX_SWAP_PATH: u32 = 4;

/// One native operation of `execute` or an intercepted call, with its named arguments. The wallet
/// is the token source, share owner, receiver and operator of each one, so no argument names it.
/// `to_core` gives the general operation that policy rules read.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AllowitStellarOperation {
    /// SEP-41 `token.transfer(wallet, to, amount)`.
    Transfer(AllowitTransferArgs),
    /// Exact-input `router.swap_exact_tokens_for_tokens(amount_in, amount_out_min, path, wallet,
    /// deadline)`, in the Soroswap router shape.
    Swap(AllowitSwapArgs),
    /// SEP-56 `vault.deposit(assets, wallet, wallet, wallet)`.
    Deposit(AllowitDepositArgs),
    /// SEP-56 `vault.redeem(shares, wallet, wallet, wallet)`.
    Redeem(AllowitRedeemArgs),
}

impl AllowitStellarOperation {
    /// The general operation that policy rules read.
    pub fn to_core(&self) -> AllowitOperation {
        match self {
            Self::Transfer(_) => AllowitOperation::transfer,
            Self::Swap(_) => AllowitOperation::swap,
            Self::Deposit(_) => AllowitOperation::deposit,
            Self::Redeem(_) => AllowitOperation::redeem,
        }
    }
}

/// Arguments of a SEP-41 transfer from the wallet.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllowitTransferArgs {
    /// Exact installed SAC address, distinct from the human-readable asset label.
    pub token: Address,
    /// Exact token destination, bound to the approved recipient.
    pub to: Address,
    /// Positive exact transfer amount in the installed asset's native i128 base units.
    pub amount: i128,
}

/// Arguments of an exact-input router swap. The router pays `amount_in` of `path[0]` from the
/// wallet to its first pair and returns at least `amount_out_min` of the last path token to the
/// wallet. One path endpoint is the wallet asset.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllowitSwapArgs {
    /// Router contract selected by the request and constrained by authored policy as the recipient.
    pub router: Address,
    /// Positive exact units of `path[0]` that leave the wallet.
    pub amount_in: i128,
    /// Positive minimum units of the last path token that the router must return.
    pub amount_out_min: i128,
    /// Two to `MAX_SWAP_PATH` token contracts. Exactly one endpoint is the wallet asset, and both
    /// endpoints are Stellar Asset Contracts.
    pub path: soroban_sdk::Vec<Address>,
    /// Router deadline in Unix seconds, no later than the request expiry.
    pub deadline: u64,
}

/// Arguments of a SEP-56 deposit of the wallet asset.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllowitDepositArgs {
    /// Vault and share-token contract selected by the request and constrained by authored policy.
    pub vault: Address,
    /// Positive underlying SAC units supplied. The immutable wallet asset fixes their scale.
    pub assets: i128,
    /// Positive minimum minted share units in the vault share token's native scale.
    pub min_shares: i128,
}

/// Arguments of a SEP-56 redeem of vault shares for the wallet asset.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllowitRedeemArgs {
    /// Vault and share-token contract selected by the request and constrained by authored policy.
    pub vault: Address,
    /// Positive share units burned, in the vault share token's native scale.
    pub shares: i128,
    /// Positive minimum underlying units. `execute` checks the observed credit against it.
    pub min_assets: i128,
}

/// Settled deposit effects, stored atomically with custody nonce and underlying transfer receipt.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllowitSep56DepositReceipt {
    /// Single-use logical operation identifier retained across re-preparation.
    pub operation_id: BytesN<32>,
    /// Admitted vault, also the share-token contract.
    pub vault: Address,
    /// Immutable underlying SAC address.
    pub asset: Address,
    /// Underlying source, equal to this wallet.
    pub from: Address,
    /// Share receiver, equal to this wallet.
    pub receiver: Address,
    /// Authorized operator, equal to this wallet.
    pub operator: Address,
    /// Exact observed underlying debit in native units.
    pub assets: i128,
    /// Observed share credit, equal to returned minted units. External vault code defines share behavior.
    pub shares: i128,
    /// Consumed execution sequence, distinct from native authorization nonces.
    pub nonce: u64,
    /// Owner configuration sequence used for this deposit.
    pub deployment_version: u64,
}

/// Confirmed underlying-to-share exchange. The complete receipt remains available by operation identity.
#[contractevent(topics = ["sep56_deposit"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllowitSep56DepositEvent {
    #[topic]
    pub operation_id: BytesN<32>,
    #[topic]
    pub vault: Address,
    pub assets: i128,
    pub shares: i128,
}

/// Settled swap effects of an `execute` swap, stored atomically with the custody nonce.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllowitSwapReceipt {
    /// Single-use logical operation identifier retained across re-preparation.
    pub operation_id: BytesN<32>,
    /// Admitted router.
    pub router: Address,
    /// Paid token, `path[0]`.
    pub token_in: Address,
    /// Received token, the last path token.
    pub token_out: Address,
    /// Exact observed debit of `token_in`.
    pub amount_in: i128,
    /// Observed credit of `token_out`, equal to the router's last returned amount.
    pub amount_out: i128,
    /// Consumed execution sequence, distinct from native authorization nonces.
    pub nonce: u64,
    /// Owner configuration sequence used for this swap.
    pub deployment_version: u64,
}

/// Settled redeem effects of an `execute` redeem, stored atomically with the custody nonce.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllowitSep56RedeemReceipt {
    /// Single-use logical operation identifier retained across re-preparation.
    pub operation_id: BytesN<32>,
    /// Admitted vault, also the share-token contract.
    pub vault: Address,
    /// Immutable underlying SAC address.
    pub asset: Address,
    /// Share owner, equal to this wallet.
    pub owner: Address,
    /// Underlying receiver, equal to this wallet.
    pub receiver: Address,
    /// Authorized operator, equal to this wallet.
    pub operator: Address,
    /// Exact observed share debit.
    pub shares: i128,
    /// Observed underlying credit, equal to the returned assets.
    pub assets: i128,
    /// Consumed execution sequence, distinct from native authorization nonces.
    pub nonce: u64,
    /// Owner configuration sequence used for this redeem.
    pub deployment_version: u64,
}

/// Confirmed `execute` swap. The complete receipt remains available by operation identity.
#[contractevent(topics = ["swap"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllowitSwapEvent {
    #[topic]
    pub operation_id: BytesN<32>,
    #[topic]
    pub router: Address,
    pub amount_in: i128,
    pub amount_out: i128,
}

/// Confirmed `execute` share-to-underlying exchange. The complete receipt remains available by
/// operation identity.
#[contractevent(topics = ["sep56_redeem"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllowitSep56RedeemEvent {
    #[topic]
    pub operation_id: BytesN<32>,
    #[topic]
    pub vault: Address,
    pub shares: i128,
    pub assets: i128,
}

/// Request-bound conservative economic ceilings, approved by the configured server signer.
/// These are not a proof of final gas or external vault valuation. Amounts use the immutable underlying asset.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllowitExpenseBounds {
    /// Conservative attributable gas ceiling in underlying units. Native XLM identity conversion is supported.
    pub gas_units: i128,
    /// Deposit, swap or redeem fee/slippage ceiling in underlying units. Transfers require zero.
    pub conversion_units: i128,
    /// Full payment principal plus gas, or conversion loss plus gas. The kernel checks the operation class.
    pub spent_units: i128,
    /// Signed outer transaction fee bound in stroops, checked by the SDK/server; the contract cannot observe final fees.
    pub max_fee_stroops: u32,
    /// Nonzero ledger at which the server observed the economic inputs. It cannot exceed execution ledger.
    pub observed_ledger: u32,
    /// UTC execution day (Unix seconds / 86400). Cross-day use rejects.
    pub day: u64,
}

/// The expense facts of a request.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AllowitExpense {
    /// No expense bounds: the operation is unpriced, which cost rules deny.
    Unpriced,
    /// Server-approved expense bounds.
    Priced(AllowitExpenseBounds),
}

impl AllowitExpense {
    /// The bounds of a priced request.
    pub fn bounds(&self) -> Option<&AllowitExpenseBounds> {
        match self {
            Self::Unpriced => None,
            Self::Priced(bounds) => Some(bounds),
        }
    }
}

/// The SDK maps OperationRef.policy_instance and OperationRef.nonce without changing them.
/// The monotonic execution nonce and deployment version come from authenticated custody state.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllowitExecutionRequest {
    /// Stable nonzero logical policy identifier. Upgrades and configuration changes preserve this identity.
    pub policy_instance: BytesN<32>,
    /// Exact full offchain source identity covered by agent/server authorization. Std binds its prefix separately.
    pub source_hash: BytesN<32>,
    /// Nonzero logical operation identifier consumed once with successful effects; replacement preparations retain it.
    pub operation_id: BytesN<32>,
    /// Strict next execution sequence shared by delegated spending paths. It is distinct from the native authorization nonce.
    pub nonce: u64,
    /// Active owner configuration counter. Executions use the current value; configuration changes target exactly the next value.
    pub deployment_version: u64,
    /// Exclusive Unix timestamp expiry in ledger seconds. Authored policy may add a stricter bound.
    pub expires_at: u64,
    /// Actual wallet Wasm SHA-256 identity that agent and server approve. It differs from both
    /// release metadata and the authored-source digest.
    pub module_digest: BytesN<32>,
    /// The native operation and its named arguments.
    pub operation: AllowitStellarOperation,
    /// Server-approved expense bounds, or none.
    pub expense: AllowitExpense,
    /// The agent's execution params of this call, at most `allowit::MAX_ARGS` keys with bounded
    /// values. Agent and server sign them with the request; the wallet never stores them, and
    /// only authored policy reads them, as `ctx.request.args`.
    pub args: Map<Symbol, AllowitValue>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllowitPolicyBinding {
    /// Exact installed wallet tier, independently bound by its executable hash.
    pub engine_kind: Symbol,
    /// Compiled kernel release metadata. Exact executable identity remains module_digest.
    pub contract_version: u32,
    /// Stable nonzero logical policy identifier. Upgrades and configuration changes preserve this identity.
    pub policy_instance: BytesN<32>,
    /// Actual wallet Wasm SHA-256 identity. It differs from both release metadata and the authored-source digest.
    pub module_digest: BytesN<32>,
    /// Fixed standard prefix binding, or the complete compiled source digest for Custom.
    /// Standard offchain source authorization is separate and does not change this binding.
    pub source_digest: BytesN<32>,
    /// The general operations that this wallet runs. The owner's `operations` param selects among
    /// them.
    pub operations: soroban_sdk::Vec<AllowitOperation>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllowitTransferReceipt {
    /// Nonzero logical operation identifier consumed once with successful effects; replacement preparations retain it.
    pub operation_id: BytesN<32>,
    /// Exact installed SAC address, distinct from the human-readable asset label.
    pub token: Address,
    /// Token source: this wallet.
    pub from: Address,
    /// Exact token destination, bound to the approved recipient.
    pub to: Address,
    /// Positive exact transfer amount in the installed asset's native i128 base units.
    pub amount: i128,
    /// Execution sequence consumed by this transfer. It is distinct from the native authorization nonce.
    pub nonce: u64,
    /// Owner configuration version used to authorize this transfer.
    pub deployment_version: u64,
}
