#![no_std]
use soroban_sdk::{Address, BytesN, Map, Symbol, contractevent, contracttype};

/// The general operation that policy rules read.
pub use allowit::AllowitOperation;
/// The one value type of owner params, execution params and policy state.
pub use allowit::AllowitValue;

/// Most tokens in one swap path: the paid token, up to two intermediate tokens and the received token.
pub const MAX_SWAP_PATH: u32 = 4;

/// One native operation of `execute`. The wallet is the token source, share owner, receiver and
/// operator of each one, so no argument names it. The arguments are positional, so the request
/// carries no field names; `args` gives them named.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AllowitStellarOperation {
    /// SEP-41 `token.transfer(wallet, to, amount)`: token, to, amount.
    Transfer(Address, Address, i128),
    /// Exact-input `router.swap_exact_tokens_for_tokens(amount_in, amount_out_min, path, wallet,
    /// deadline)`, in the Soroswap router shape: router, amount_in, amount_out_min, path, deadline.
    Swap(Address, i128, i128, soroban_sdk::Vec<Address>, u64),
    /// SEP-56 `vault.deposit(assets, wallet, wallet, wallet)`: vault, assets, min_shares.
    Deposit(Address, i128, i128),
    /// SEP-56 `vault.redeem(shares, wallet, wallet, wallet)`: vault, shares, min_assets.
    Redeem(Address, i128, i128),
}

impl AllowitStellarOperation {
    /// The general operation that policy rules read.
    pub fn to_core(&self) -> AllowitOperation {
        match self {
            Self::Transfer(..) => AllowitOperation::transfer,
            Self::Swap(..) => AllowitOperation::swap,
            Self::Deposit(..) => AllowitOperation::deposit,
            Self::Redeem(..) => AllowitOperation::redeem,
        }
    }
    /// The operation with named arguments.
    pub fn args(&self) -> AllowitOperationArgs {
        match self.clone() {
            Self::Transfer(token, to, amount) => {
                AllowitOperationArgs::Transfer(AllowitTransferArgs { token, to, amount })
            }
            Self::Swap(router, amount_in, amount_out_min, path, deadline) => {
                AllowitOperationArgs::Swap(AllowitSwapArgs {
                    router,
                    amount_in,
                    amount_out_min,
                    path,
                    deadline,
                })
            }
            Self::Deposit(vault, assets, min_shares) => {
                AllowitOperationArgs::Deposit(AllowitDepositArgs {
                    vault,
                    assets,
                    min_shares,
                })
            }
            Self::Redeem(vault, shares, min_assets) => {
                AllowitOperationArgs::Redeem(AllowitRedeemArgs {
                    vault,
                    shares,
                    min_assets,
                })
            }
        }
    }
}

/// An operation with named arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AllowitOperationArgs {
    Transfer(AllowitTransferArgs),
    Swap(AllowitSwapArgs),
    Deposit(AllowitDepositArgs),
    Redeem(AllowitRedeemArgs),
}

/// Arguments of a SEP-41 transfer from the wallet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllowitTransferArgs {
    /// Exact installed SAC address.
    pub token: Address,
    /// Exact token destination, bound to the approved recipient.
    pub to: Address,
    /// Positive exact transfer amount in the installed asset's native i128 base units.
    pub amount: i128,
}

/// Arguments of an exact-input router swap. The router pays `amount_in` of `path[0]` from the
/// wallet to its first pair and returns at least `amount_out_min` of the last path token to the
/// wallet. One path endpoint is the wallet asset.
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
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllowitDepositArgs {
    /// Vault and share-token contract selected by the request and constrained by authored policy.
    pub vault: Address,
    /// Positive underlying SAC units supplied.
    pub assets: i128,
    /// Positive minimum minted share units in the vault share token's native scale.
    pub min_shares: i128,
}

/// Arguments of a SEP-56 redeem of vault shares for the wallet asset.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllowitRedeemArgs {
    /// Vault and share-token contract selected by the request and constrained by authored policy.
    pub vault: Address,
    /// Positive share units burned, in the vault share token's native scale.
    pub shares: i128,
    /// Positive minimum underlying units. `execute` checks the observed credit against it.
    pub min_assets: i128,
}

/// The request's expense facts.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AllowitExpense {
    /// No expense bounds: the operation is unpriced, which cost rules deny.
    Unpriced,
    /// Server-approved conservative ceilings, positional: gas units, conversion units, spent
    /// units, observed ledger. They are not a proof of final gas or external vault valuation.
    /// Amounts use the immutable underlying asset.
    ///
    /// - Gas units: the gas that the wallet repays, in asset units. For an XLM wallet they equal
    ///   the repaid stroops; for another asset the agent and server attest the conversion. Zero
    ///   when the wallet repays nothing.
    /// - Conversion units: the deposit, swap or redeem fee and slippage ceiling. Transfers
    ///   require zero.
    /// - Spent units: the payment principal plus gas, or the conversion loss plus gas.
    /// - Observed ledger: the nonzero ledger at which the server observed the economic inputs; it
    ///   cannot exceed the execution ledger.
    Priced(i128, i128, i128, u32),
}

/// Named view of priced expense facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AllowitExpenseBounds {
    pub gas_units: i128,
    pub conversion_units: i128,
    pub spent_units: i128,
    pub observed_ledger: u32,
}

impl AllowitExpense {
    /// The bounds of a priced request.
    pub fn bounds(&self) -> Option<AllowitExpenseBounds> {
        match *self {
            Self::Unpriced => None,
            Self::Priced(gas_units, conversion_units, spent_units, observed_ledger) => {
                Some(AllowitExpenseBounds {
                    gas_units,
                    conversion_units,
                    spent_units,
                    observed_ledger,
                })
            }
        }
    }
}

/// One agent operation, positional. The agent and the server sign the ledger's authorization
/// payload of `execute(request)`, which binds the wallet, this request, a ledger nonce and an
/// expiration ledger; the ledger keeps the nonce until that ledger, so the wallet stores nothing
/// for replay. Positional fields keep the request small: it travels twice in a transaction, as
/// the call's argument and in the authorization entry.
///
/// 0. Operation id: nonzero and logical. The wallet never stores it; its one event names it.
/// 1. Deployment version: the owner configuration counter that the request was prepared under.
///    Every owner update, code change, pause and stop moves it, which voids each request signed
///    before; so the request needs no code or source hash of its own.
/// 2. Expiry: exclusive Unix timestamp in ledger seconds. Authored policy may add a stricter bound.
/// 3. The native operation.
/// 4. Expense: server-approved bounds, or `Unpriced`, which cost rules deny.
/// 5. Gas: XLM stroops that the wallet repays to the payee for the network fee, at most the
///    owner-signed gas cap. Zero repays nothing.
/// 6. Gas payee: the account that receives the repayment, the server's sending account.
/// 7. Args: the agent's execution params of this call, at most `allowit::MAX_ARGS` keys with
///    bounded values. The wallet never stores them; only authored policy reads them, as
///    `ctx.request.args`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllowitExecutionRequest(
    pub BytesN<32>,
    pub u32,
    pub u64,
    pub AllowitStellarOperation,
    pub AllowitExpense,
    pub i128,
    pub Address,
    pub Map<Symbol, AllowitValue>,
);

impl AllowitExecutionRequest {
    pub fn operation_id(&self) -> &BytesN<32> {
        &self.0
    }
    pub fn deployment_version(&self) -> u32 {
        self.1
    }
    pub fn expires_at(&self) -> u64 {
        self.2
    }
    pub fn operation(&self) -> &AllowitStellarOperation {
        &self.3
    }
    pub fn expense(&self) -> Option<AllowitExpenseBounds> {
        self.4.bounds()
    }
    pub fn gas_stroops(&self) -> i128 {
        self.5
    }
    pub fn gas_payee(&self) -> &Address {
        &self.6
    }
    pub fn args(&self) -> &Map<Symbol, AllowitValue> {
        &self.7
    }
}

/// The wallet's own authorization of `execute`: the agent's and then the server's raw Ed25519
/// signature of the ledger's authorization payload.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllowitCosignatures(pub BytesN<64>, pub BytesN<64>);

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
