#![no_std]
use soroban_sdk::{Address, BytesN, Map, Symbol, contractevent, contracttype};

/// The general operation that policy rules read.
pub use allowit::AllowitOperation;
/// The one value type of owner params, execution params and policy state.
pub use allowit::AllowitValue;

/// Most tokens in one swap path: the paid token, up to two intermediate tokens and the received token.
pub const MAX_SWAP_PATH: u32 = 4;

/// One native operation of `execute`, with its named arguments. The wallet
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

/// Request-bound conservative economic ceilings, approved by the configured server signer.
/// These are not a proof of final gas or external vault valuation. Amounts use the immutable underlying asset.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllowitExpenseBounds {
    /// Gas that the wallet repays, in underlying units. For an XLM wallet it equals the repaid
    /// stroops; for another asset the agent and server attest the conversion. Zero when the
    /// wallet repays nothing.
    pub gas_units: i128,
    /// Deposit, swap or redeem fee/slippage ceiling in underlying units. Transfers require zero.
    pub conversion_units: i128,
    /// Full payment principal plus gas, or conversion loss plus gas. The kernel checks the operation class.
    pub spent_units: i128,
    /// Nonzero ledger at which the server observed the economic inputs. It cannot exceed execution ledger.
    pub observed_ledger: u32,
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

/// One agent operation. The agent and the server sign the ledger's authorization payload of
/// `execute(request)`, which binds the wallet, this request, a ledger nonce and an expiration
/// ledger; the ledger keeps the nonce until that ledger, so the wallet stores nothing for replay.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllowitExecutionRequest {
    /// Nonzero logical operation identifier. The wallet never stores it; its one event names it.
    pub operation_id: BytesN<32>,
    /// The owner configuration counter that the request was prepared under. An owner update,
    /// pause or stop moves it, which voids every request signed before.
    pub deployment_version: u32,
    /// The owner-signed hash of the owner's full policy source, as the wallet stores it.
    pub source_hash: BytesN<32>,
    /// The wallet Wasm SHA-256 that agent and server approve.
    pub module_digest: BytesN<32>,
    /// Exclusive Unix timestamp expiry in ledger seconds. Authored policy may add a stricter bound.
    pub expires_at: u64,
    /// The native operation and its named arguments.
    pub operation: AllowitStellarOperation,
    /// Server-approved expense bounds, or none.
    pub expense: AllowitExpense,
    /// XLM stroops that the wallet repays to `gas_payee` for the network fee, at most the
    /// owner-signed gas cap. Zero repays nothing.
    pub gas_stroops: i128,
    /// The account that receives the gas repayment: the server's sending account.
    pub gas_payee: Address,
    /// The agent's execution params of this call, at most `allowit::MAX_ARGS` keys with bounded
    /// values. Agent and server sign them with the request; the wallet never stores them, and
    /// only authored policy reads them, as `ctx.request.args`.
    pub args: Map<Symbol, AllowitValue>,
}

/// The wallet's own authorization of `execute`: the agent's and the server's raw Ed25519
/// signatures of the ledger's authorization payload.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllowitCosignatures {
    pub agent: BytesN<64>,
    pub server: BytesN<64>,
}

/// The one event of an `execute`: the operation and what the wallet received back. A transfer
/// reports its amount, a swap its observed output, a deposit its minted shares and a redeem its
/// paid assets. The request, with its gas repayment, is in the transaction.
#[contractevent(topics = ["allowit"], data_format = "single-value")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllowitExecuted {
    #[topic]
    pub operation_id: BytesN<32>,
    pub output: i128,
}
