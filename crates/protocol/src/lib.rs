#![no_std]
use soroban_sdk::{Address, Bytes, BytesN, Map, Symbol, contractevent, contracttype};

/// The one value type of owner params, execution params and policy state.
pub use allowit::AllowitValue;

/// Native transfer-profile argument encoding, fixed independently of policy source.
pub const ARGUMENT_SCHEMA_DESCRIPTOR: &[u8] = b"allowit.stellar.sep41_transfer.v1:ScValMap(amount:i128,from:Address,to:Address,token:Address)";
/// Exact SEP-56 deposit encoding. The vault is also its SEP-41 share-token contract.
pub const SEP56_DEPOSIT_SCHEMA_DESCRIPTOR: &[u8] = b"allowit.stellar.sep56_deposit.v1:ScValMap(assets:i128,from:Address,min_shares:i128,operator:Address,receiver:Address,vault:Address)";
/// Exact exact-input router swap encoding: the arguments of a Soroswap-style
/// `swap_exact_tokens_for_tokens(amount_in, amount_out_min, path, to, deadline)` and its router.
pub const ROUTER_SWAP_SCHEMA_DESCRIPTOR: &[u8] = b"allowit.stellar.router_swap_exact_in.v1:ScValMap(amount_in:i128,amount_out_min:i128,deadline:u64,path:Vec<Address>,router:Address,to:Address)";
/// Exact SEP-56 redeem encoding, with the wallet's minimum underlying output.
pub const SEP56_REDEEM_SCHEMA_DESCRIPTOR: &[u8] = b"allowit.stellar.sep56_redeem.v1:ScValMap(min_assets:i128,operator:Address,owner:Address,receiver:Address,shares:i128,vault:Address)";
pub const MAX_ARGUMENT_BYTES: u32 = 1024;
pub const MAX_EXPENSE_BYTES: u32 = 1024;
/// Most tokens in one swap path: the paid token, up to two intermediate tokens and the received token.
pub const MAX_SWAP_PATH: u32 = 4;

/// Exact arguments of the admitted stellar::sep41_transfer operation.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllowitSep41TransferArgs {
    /// Exact installed SAC address, distinct from the human-readable asset label.
    pub token: Address,
    /// Exact token source address; delegated spending requires the current wallet address.
    pub from: Address,
    /// Exact token destination, bound to the approved recipient.
    pub to: Address,
    /// Positive exact transfer amount in the installed asset's native i128 base units.
    pub amount: i128,
}

/// Exact arguments of the admitted stellar::sep56_deposit operation.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllowitSep56DepositArgs {
    /// Vault and share-token contract selected by the request and constrained by authored policy.
    pub vault: Address,
    /// Positive underlying SAC units supplied. The immutable wallet asset fixes their scale.
    pub assets: i128,
    /// Share receiver. Delegated deposits require the current wallet address.
    pub receiver: Address,
    /// Underlying source. Delegated deposits require the current wallet address.
    pub from: Address,
    /// Deposit operator. Delegated deposits require the current wallet address.
    pub operator: Address,
    /// Positive minimum minted share units in the vault share token's native scale.
    pub min_shares: i128,
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

/// Exact arguments of the admitted stellar::router_swap_exact_in operation. The router pays
/// `amount_in` of `path[0]` from the wallet to its first pair and returns at least
/// `amount_out_min` of the last path token to `to`. One path endpoint is the wallet asset.
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
    /// Output receiver and debit source. Delegated swaps require the current wallet address.
    pub to: Address,
    /// Router deadline in Unix seconds, no later than the request expiry.
    pub deadline: u64,
}

/// Exact arguments of the admitted stellar::sep56_redeem operation.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllowitSep56RedeemArgs {
    /// Vault and share-token contract selected by the request and constrained by authored policy.
    pub vault: Address,
    /// Positive share units burned, in the vault share token's native scale.
    pub shares: i128,
    /// Underlying receiver. Delegated redeems require the current wallet address.
    pub receiver: Address,
    /// Share owner. Delegated redeems require the current wallet address.
    pub owner: Address,
    /// Redeem operator. Delegated redeems require the current wallet address.
    pub operator: Address,
    /// Positive minimum underlying units. `execute` checks the observed credit against it.
    pub min_assets: i128,
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

/// The native profile of the canonical signed module-selection record.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllowitPolicyInvocation {
    /// Actual wallet Wasm SHA-256 identity. It differs from both release metadata and the authored-source digest.
    pub module_digest: BytesN<32>,
    /// Authored policy entrypoint, `execute`. Only the installed selector is admitted.
    pub entrypoint: Symbol,
    /// SHA-256 of the admitted native argument schema. Unknown schemas reject.
    pub argument_schema_digest: BytesN<32>,
    /// Canonical bounded XDR of the selected native operation; alternative encodings and extra data reject.
    pub arguments: Bytes,
}

/// Request-bound conservative economic ceilings, approved by the configured server signer.
/// These are not a proof of final gas or external vault valuation. Amounts use the immutable underlying asset.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllowitExpenseBounds {
    /// Immutable underlying SAC denomination, distinct from the share token.
    pub asset: Address,
    /// Exact underlying scale. This native custody profile requires seven.
    pub decimals: u32,
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
    /// Installed module selection and exact canonical arguments, bound before compiled policy execution.
    pub invocation: AllowitPolicyInvocation,
    /// Optional canonical XDR of `AllowitExpenseBounds`, bounded by MAX_EXPENSE_BYTES. New cost rules require Some.
    pub expense: Option<Bytes>,
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
    /// SHA-256 of the admitted native argument schema. Unknown schemas reject.
    pub argument_schema_digest: BytesN<32>,
    /// Authored policy entrypoint, `execute`. Only the installed selector is admitted.
    pub entrypoint: Symbol,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllowitTransferReceipt {
    /// Nonzero logical operation identifier consumed once with successful effects; replacement preparations retain it.
    pub operation_id: BytesN<32>,
    /// Exact installed SAC address, distinct from the human-readable asset label.
    pub token: Address,
    /// Exact token source address; delegated spending requires the current wallet address.
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
