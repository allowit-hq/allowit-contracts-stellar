#![no_std]
//! Owner-controlled custody mixins shared by fixed and bespoke policy wallets.
use allowit::{
    AllowitContext, AllowitOperation, AllowitParams, AllowitRequest, AllowitRule, AllowitTier,
    AllowitValue,
};
use allowit_wallet_protocol::{
    AllowitDepositArgs, AllowitExecutionRequest, AllowitExpenseBounds, AllowitPolicyBinding,
    AllowitRedeemArgs, AllowitSep56DepositEvent, AllowitSep56DepositReceipt,
    AllowitSep56RedeemEvent, AllowitSep56RedeemReceipt, AllowitStellarOperation, AllowitSwapArgs,
    AllowitSwapEvent, AllowitSwapReceipt, AllowitTransferReceipt, MAX_SWAP_PATH,
};
use soroban_sdk::{
    Address, Bytes, BytesN, Env, Executable, IntoVal, Map, String, Symbol, TryFromVal, Val, Vec,
    address_payload::AddressPayload,
    auth::{Context, ContractContext, InvokerContractAuthEntry, SubContractInvocation},
    contracterror, contracttype,
    crypto::Hash,
    token,
    xdr::ToXdr,
};
mod persistent;
/// Instance-storage key of the custody State.
const STATE_KEY: u32 = 0;
/// Version 4: owner `params` and `policy_state` are key => `AllowitValue` maps. Version 3 stored the
/// canonical params as a typed struct and a policy state of raw values, version 2 a typed accounting
/// history struct and version 1 a text-keyed params map. No layout migrates implicitly: the owner
/// recovers funds.
pub const CONTRACT_VERSION: u32 = 4;
// Wasm metadata equal to CONTRACT_VERSION. Release tooling refuses a code change to Wasm that
// declares another custody layout, or none (version 1), because that code cannot read State.
soroban_sdk::contractmeta!(key = "allowit_custody_layout", val = "4");

/// Initial owner-signed configuration. Asset and policy_instance stay fixed after creation.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllowitPolicyConfig {
    pub owner: Address,
    pub agent: Address,
    /// Independent service signer, never a parent-controlled checker address.
    pub server: Address,
    pub asset: Address,
    pub policy_instance: BytesN<32>,
    /// Fixed standard prefix digest; Custom uses its complete compiled source digest.
    pub source_digest: BytesN<32>,
    /// Ordered owner-approved standard prefix. Simple and Custom use an empty list.
    pub rules: Vec<AllowitRule>,
    /// Owner constructor params, key => value. Standard tiers admit only the canonical keys.
    pub params: Map<Symbol, AllowitValue>,
    pub x402_enabled: bool,
}

/// Complete owner update. It preserves asset, logical identity, nonce, pause and policy state.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllowitPolicyDeployment {
    pub deployment_version: u64,
    pub owner: Address,
    pub agent: Address,
    pub server: Address,
    /// Fixed standard prefix digest; Custom uses its complete compiled source digest.
    pub source_digest: BytesN<32>,
    pub rules: Vec<AllowitRule>,
    /// Replacement owner params, key => value; changing only them needs no code redeployment.
    pub params: Map<Symbol, AllowitValue>,
    pub x402_enabled: bool,
    pub wasm_hash: Option<BytesN<32>>,
}

/// Stored custody State: owner configuration, policy state, nonce and pause.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllowitState {
    /// Free-form policy state after the last operation: standard and policy-defined keys.
    pub policy_state: Map<Symbol, AllowitValue>,
    pub contract_version: u32,
    pub owner: Address,
    pub agent: Address,
    pub server: Address,
    pub asset: Address,
    pub policy_instance: BytesN<32>,
    /// Fixed standard prefix digest; Custom uses its complete compiled source digest.
    pub source_digest: BytesN<32>,
    pub rules: Vec<AllowitRule>,
    /// Owner constructor params, key => value.
    pub params: Map<Symbol, AllowitValue>,
    pub x402_enabled: bool,
    /// Authenticated SAC label cached before any active-token authorization callback.
    pub token: String,
    pub deployment_version: u64,
    pub nonce: u64,
    pub paused: bool,
}

/// Custom-account signature of an intercepted transfer, swap or redeem: the signed execution
/// request and the agent and server signatures over it and the host payload.
#[contracttype]
#[derive(Clone)]
pub struct AllowitPolicyAuthorization {
    pub execution: AllowitExecutionRequest,
    pub agent_signature: BytesN<64>,
    pub server_signature: BytesN<64>,
}

/// Wallet error codes, all below 100; `AllowitError` codes start at 101. Rule denials collapse to
/// `PolicyDenied`.
#[contracterror]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum AllowitWalletError {
    InvalidState = 1,
    /// Invalid owner params or rules, or a param that a rule cannot decode.
    InvalidParam = 2,
    UnsupportedAsset = 3,
    InvalidActor = 4,
    StaleRequest = 5,
    Paused = 6,
    Expired = 7,
    InvalidAmount = 8,
    InvalidRecipient = 9,
    Overflow = 11,
    InsufficientFunds = 14,
    InvalidEffects = 15,
    UnsupportedOperation = 16,
    InvalidInvocation = 17,
    PolicyDenied = 18,
    Replay = 19,
}

/// Persistent keys: the replay marker of an operation and the output receipt of an `execute`
/// deposit, swap or redeem.
#[contracttype]
#[derive(Clone)]
enum Key {
    Operation(BytesN<32>),
    Deposit(BytesN<32>),
    Swap(BytesN<32>),
    Redeem(BytesN<32>),
}

/// Compile-time policy mixin. No runtime fallback or system-controlled executable reference exists.
pub trait AllowitPolicy {
    /// Implementation kind in bindings and the standard prefix digest.
    const KIND: &'static str;
    /// Fixed standard implementations bind only their owner-approved initial preflight prefix.
    const STANDARD_PREFIX: bool = false;
    /// The general operations that this implementation runs; transfers only unless it selects
    /// more. The owner's `operations` param selects among them.
    const OPERATIONS: &'static [AllowitOperation] = &[AllowitOperation::transfer];
    /// A bespoke implementation binds its compiled source. Fixed tiers use the owner's source digest.
    fn source_digest(_env: &Env) -> Option<BytesN<32>> {
        None
    }
    /// Check the owner-approved standard prefix. Only Common admits a nonempty list.
    fn validate(rules: &Vec<AllowitRule>) -> Result<(), AllowitWalletError> {
        if rules.is_empty() {
            Ok(())
        } else {
            Err(AllowitWalletError::InvalidParam)
        }
    }
    /// Evaluate the compiled checks on the kernel-built rule input. Pass values are discarded.
    /// Custom runs its own `execute`; the standard tiers run the owner's prefix.
    fn check(ctx: &AllowitContext, rules: &Vec<AllowitRule>) -> Result<(), AllowitWalletError>;
}

/// The params a tier admits and the policy state it stores. Simple and Common run only the
/// canonical prefix onchain; Custom runs its whole compiled policy.
fn tier<P: AllowitPolicy>() -> AllowitTier {
    if P::STANDARD_PREFIX {
        AllowitTier::Standard
    } else {
        AllowitTier::Custom
    }
}
/// Check owner params for the tier of `P`.
fn checked_params<P: AllowitPolicy>(
    params: &Map<Symbol, AllowitValue>,
) -> Result<(), AllowitWalletError> {
    allowit::check_params(params, tier::<P>()).map_err(|_| AllowitWalletError::InvalidParam)
}
/// A checked arithmetic result, or `Overflow`.
fn checked<T>(value: Option<T>) -> Result<T, AllowitWalletError> {
    value.ok_or(AllowitWalletError::Overflow)
}
/// Read initialized state and maintain its instance and code lifetime. Constructor initialization is explicit.
fn load(env: &Env, initial: Option<AllowitState>) -> Result<AllowitState, AllowitWalletError> {
    if let Some(state) = initial {
        store(env, &state);
    }
    let raw = stored(env)?;
    let state =
        AllowitState::try_from_val(env, &raw).map_err(|_| AllowitWalletError::InvalidState)?;
    // Struct decoding ignores extra keys and reads absent Option keys as None. Only the exact
    // canonical encoding of this layout is accepted, including the params map.
    if state.contract_version != CONTRACT_VERSION || state.clone().to_xdr(env) != raw.to_xdr(env) {
        return Err(AllowitWalletError::InvalidState);
    }
    extend(env);
    Ok(state)
}
/// Renew the instance and code lifetime of this wallet.
fn extend(env: &Env) {
    let ttl = env.storage().max_ttl();
    env.deployer()
        .extend_ttl(env.current_contract_address(), ttl / 2, ttl);
}
/// Write the custody State.
fn store(env: &Env, state: &AllowitState) {
    env.storage().instance().set(&STATE_KEY, state);
}
/// Stored fields that owner entrypoints keep. Struct decoding ignores the other State keys, so
/// stored params or a rule list that no longer decodes never block recovery, passthrough or their
/// replacement by an owner packet. Policy state is read separately, only where it is carried over.
#[contracttype]
struct KeptState {
    contract_version: u32,
    owner: Address,
    asset: Address,
    policy_instance: BytesN<32>,
    token: String,
    deployment_version: u64,
    nonce: u64,
    paused: bool,
}
/// Read the kept fields. Callers require the owner's authorization.
fn kept(env: &Env) -> Result<KeptState, AllowitWalletError> {
    let kept = KeptState::try_from_val(env, &stored(env)?)
        .map_err(|_| AllowitWalletError::InvalidState)?;
    // A later layout may change the meaning of kept fields.
    if kept.contract_version == 0 || kept.contract_version > CONTRACT_VERSION {
        return Err(AllowitWalletError::InvalidState);
    }
    extend(env);
    Ok(kept)
}
/// Policy state carried into a new State. Earlier layouts store none, or store other values, so
/// they do not migrate.
fn kept_policy_state(
    env: &Env,
    kept: &KeptState,
) -> Result<Map<Symbol, AllowitValue>, AllowitWalletError> {
    if kept.contract_version != CONTRACT_VERSION {
        return Err(AllowitWalletError::InvalidState);
    }
    let fields = Map::<Symbol, Val>::try_from_val(env, &stored(env)?)
        .map_err(|_| AllowitWalletError::InvalidState)?;
    let raw = fields
        .get(Symbol::new(env, "policy_state"))
        .ok_or(AllowitWalletError::InvalidState)?;
    Map::try_from_val(env, &raw).map_err(|_| AllowitWalletError::InvalidState)
}
/// The raw stored State, before layout decoding.
fn stored(env: &Env) -> Result<Val, AllowitWalletError> {
    env.storage()
        .instance()
        .get(&STATE_KEY)
        .ok_or(AllowitWalletError::InvalidState)
}
/// The ed25519 master key of a G-account address; any other address is `InvalidActor`. The
/// wallet's agent and server sign with their master keys.
fn public_key(address: &Address) -> Result<BytesN<32>, AllowitWalletError> {
    match address.to_payload() {
        Some(AddressPayload::AccountIdPublicKeyEd25519(key)) => Ok(key),
        _ => Err(AllowitWalletError::InvalidActor),
    }
}
/// Pure standard-prefix binding: SHA-256 of the canonical XDR of the domain `allowit_std_prefix`,
/// the implementation kind, the module hash, the asset and the ordered rules. The module hash fixes
/// the operations that the code runs. Param values and the owner-signed offchain suffix are
/// excluded.
pub fn standard_prefix_digest(
    env: &Env,
    kind: &Symbol,
    module: &BytesN<32>,
    asset: &Address,
    rules: &Vec<AllowitRule>,
) -> BytesN<32> {
    env.crypto()
        .sha256(
            &(
                Symbol::new(env, "allowit_std_prefix"),
                kind.clone(),
                module.clone(),
                asset.clone(),
                rules.clone(),
            )
                .to_xdr(env),
        )
        .to_bytes()
}
/// The standard prefix digest of this executable, asset and rules.
fn checked_prefix<P: AllowitPolicy>(
    env: &Env,
    asset: &Address,
    rules: &Vec<AllowitRule>,
) -> Result<BytesN<32>, AllowitWalletError> {
    let Some(Executable::Wasm(module)) = env.current_contract_address().executable() else {
        return Err(AllowitWalletError::InvalidState);
    };
    Ok(standard_prefix_digest(
        env,
        &Symbol::new(env, P::KIND),
        &module,
        asset,
        rules,
    ))
}
/// Check owner configuration: distinct roles, identities, source binding, params, rules and x402 keys.
fn validate<P: AllowitPolicy>(
    env: &Env,
    config: &AllowitPolicyConfig,
) -> Result<(), AllowitWalletError> {
    let roles = [&config.owner, &config.agent, &config.server];
    for (i, role) in roles.iter().enumerate() {
        if **role == env.current_contract_address() || roles[..i].contains(role) {
            return Err(AllowitWalletError::InvalidActor);
        }
    }
    if config.policy_instance == BytesN::from_array(env, &[0; 32])
        || config.source_digest == BytesN::from_array(env, &[0; 32])
    {
        return Err(AllowitWalletError::InvalidState);
    }
    if P::source_digest(env).is_some_and(|digest| digest != config.source_digest) {
        return Err(AllowitWalletError::InvalidState);
    }
    checked_params::<P>(&config.params)?;
    decoded(&config.rules)?;
    P::validate(&config.rules)?;
    if P::STANDARD_PREFIX
        && config.source_digest != checked_prefix::<P>(env, &config.asset, &config.rules)?
    {
        return Err(AllowitWalletError::InvalidState);
    }
    if config.x402_enabled {
        public_key(&config.agent)?;
        public_key(&config.server)?;
    }
    Ok(())
}
/// Soroban decodes vector elements when read. Owner configuration decodes each rule before storing
/// it, so an element that later fails to decode cannot be stored. An unknown `AllowitRule` symbol
/// aborts. `allowit::check_params` decodes every param value the same way.
fn decoded<T: IntoVal<Env, Val> + TryFromVal<Env, Val>>(
    list: &Vec<T>,
) -> Result<(), AllowitWalletError> {
    for i in 0..list.len() {
        list.try_get(i)
            .map_err(|_| AllowitWalletError::InvalidParam)?;
    }
    Ok(())
}
/// The installed binding: executable, source binding and the operations that this code runs.
fn binding<P: AllowitPolicy>(
    env: &Env,
    state: &AllowitState,
) -> Result<AllowitPolicyBinding, AllowitWalletError> {
    let Some(Executable::Wasm(module_digest)) = env.current_contract_address().executable() else {
        return Err(AllowitWalletError::InvalidState);
    };
    if P::source_digest(env).is_some_and(|digest| digest != state.source_digest) {
        return Err(AllowitWalletError::InvalidState);
    }
    if P::STANDARD_PREFIX
        && state.source_digest != checked_prefix::<P>(env, &state.asset, &state.rules)?
    {
        return Err(AllowitWalletError::InvalidState);
    }
    let mut operations = Vec::new(env);
    for operation in P::OPERATIONS {
        operations.push_back(operation.clone());
    }
    Ok(AllowitPolicyBinding {
        engine_kind: Symbol::new(env, P::KIND),
        contract_version: CONTRACT_VERSION,
        policy_instance: state.policy_instance.clone(),
        module_digest,
        source_digest: state.source_digest.clone(),
        operations,
    })
}

/// The one debit of an operation: `amount` of `token` leaves the wallet toward `to`. Deposits move
/// `assets` to the vault, swaps move `amount_in` of the first path token toward the router, and
/// redeems burn `shares` of the vault's share token.
struct Debit {
    token: Address,
    to: Address,
    amount: i128,
}
/// The debit of `operation` on a wallet of `asset`.
fn debit(operation: &AllowitStellarOperation, asset: &Address) -> Debit {
    match operation {
        AllowitStellarOperation::Transfer(args) => Debit {
            token: args.token.clone(),
            to: args.to.clone(),
            amount: args.amount,
        },
        AllowitStellarOperation::Swap(args) => Debit {
            token: args.path.get_unchecked(0),
            to: args.router.clone(),
            amount: args.amount_in,
        },
        AllowitStellarOperation::Deposit(args) => Debit {
            token: asset.clone(),
            to: args.vault.clone(),
            amount: args.assets,
        },
        AllowitStellarOperation::Redeem(args) => Debit {
            token: args.vault.clone(),
            to: args.vault.clone(),
            amount: args.shares,
        },
    }
}
/// Request facts of one native operation, which rules read.
struct Facts {
    recipient: Address,
    amount: i128,
    token_in: Address,
    amount_in: i128,
    token_out: Option<Address>,
    min_out: i128,
}
/// The request facts of `operation`. A forward swap counts its asset input as the gross amount; a
/// reverse swap and a redeem count their minimum asset output, a floor.
fn facts(operation: &AllowitStellarOperation, asset: &Address) -> Facts {
    let debit = debit(operation, asset);
    let (recipient, amount, token_out, min_out) = match operation {
        AllowitStellarOperation::Transfer(args) => (args.to.clone(), args.amount, None, 0),
        AllowitStellarOperation::Swap(args) => {
            let last = args.path.get_unchecked(args.path.len() - 1);
            let amount = if debit.token == *asset {
                args.amount_in
            } else {
                args.amount_out_min
            };
            let router = args.router.clone();
            (router, amount, Some(last), args.amount_out_min)
        }
        AllowitStellarOperation::Deposit(args) => (
            args.vault.clone(),
            args.assets,
            Some(args.vault.clone()),
            args.min_shares,
        ),
        AllowitStellarOperation::Redeem(args) => (
            args.vault.clone(),
            args.min_assets,
            Some(asset.clone()),
            args.min_assets,
        ),
    };
    Facts {
        recipient,
        amount,
        token_in: debit.token,
        amount_in: debit.amount,
        token_out,
        min_out,
    }
}
/// Whether `address` is a contract, not an account. A contract address never burns a classic asset.
fn is_contract(address: &Address) -> bool {
    matches!(
        address.to_payload(),
        Some(AddressPayload::ContractIdHash(_))
    )
}
/// Check the native operation of a request: a transfer moves the installed asset, a vault or
/// router is neither the wallet nor the asset, and amounts are positive. The wallet supplies itself
/// as every source, owner, receiver and operator.
fn validate_operation(
    env: &Env,
    execution: &AllowitExecutionRequest,
    state: &AllowitState,
) -> Result<(), AllowitWalletError> {
    let wallet = env.current_contract_address();
    let (vault, amount, minimum) = match &execution.operation {
        AllowitStellarOperation::Transfer(args) => {
            return if args.token == state.asset {
                Ok(())
            } else {
                Err(AllowitWalletError::InvalidInvocation)
            };
        }
        AllowitStellarOperation::Swap(args) => return validate_swap(env, execution, state, args),
        AllowitStellarOperation::Deposit(args) => (&args.vault, args.assets, args.min_shares),
        AllowitStellarOperation::Redeem(args) => (&args.vault, args.shares, args.min_assets),
    };
    if *vault == wallet || *vault == state.asset {
        return Err(AllowitWalletError::InvalidInvocation);
    }
    if amount <= 0 || minimum <= 0 {
        return Err(AllowitWalletError::InvalidAmount);
    }
    Ok(())
}
/// Check a router swap: the path holds two to `MAX_SWAP_PATH` tokens without the wallet, exactly
/// one endpoint is the asset, both endpoints are Stellar Asset Contracts, and the router deadline
/// falls within the request expiry.
fn validate_swap(
    env: &Env,
    execution: &AllowitExecutionRequest,
    state: &AllowitState,
    args: &AllowitSwapArgs,
) -> Result<(), AllowitWalletError> {
    let wallet = env.current_contract_address();
    let n = args.path.len();
    if args.router == wallet
        || args.router == state.asset
        || !(2..=MAX_SWAP_PATH).contains(&n)
        || args.deadline > execution.expires_at
    {
        return Err(AllowitWalletError::InvalidInvocation);
    }
    // Soroban decodes vector elements when read: check every element before any use.
    for i in 0..n {
        let token = args
            .path
            .try_get(i)
            .map_err(|_| AllowitWalletError::InvalidInvocation)?;
        if token.as_ref() == Some(&wallet) {
            return Err(AllowitWalletError::InvalidInvocation);
        }
    }
    let first = args.path.get_unchecked(0);
    let last = args.path.get_unchecked(n - 1);
    if (first == state.asset) == (last == state.asset) {
        return Err(AllowitWalletError::InvalidInvocation);
    }
    // A host lookup of the executable, not a contract call.
    let other = if first == state.asset { last } else { first };
    if other.executable() != Some(Executable::StellarAsset) {
        return Err(AllowitWalletError::UnsupportedAsset);
    }
    if args.amount_in <= 0 || args.amount_out_min <= 0 {
        return Err(AllowitWalletError::InvalidAmount);
    }
    Ok(())
}

/// The SAC symbol of the asset, cached at construction for issuer checks.
fn token_label(env: &Env, asset: &Address) -> String {
    let native = env
        .deployer()
        .with_stellar_asset(Bytes::from_array(env, &[0; 4]))
        .deployed_address();
    if asset == &native {
        String::from_str(env, "XLM")
    } else {
        token::Client::new(env, asset).symbol()
    }
}
// A transfer to a classic issuer burns its asset. Derive the immutable SAC identity
// from the cached symbol and candidate issuer without reentering the active SAC.
/// Whether `to` is the classic issuer of the asset, where a transfer burns it.
fn issuer_destination(
    env: &Env,
    token: &String,
    asset: &Address,
    to: &Address,
) -> Result<bool, AllowitWalletError> {
    let len = token.len() as usize;
    if len == 0 || len > 48 {
        return Err(AllowitWalletError::InvalidState);
    }
    let mut encoded = [0u8; 48];
    token.copy_into_slice(&mut encoded[..len]);
    let mut code = [0u8; 12];
    let mut cursor = 0;
    let mut size = 0;
    while cursor < len {
        if size == 12 {
            return Err(AllowitWalletError::InvalidState);
        }
        code[size] = if encoded[cursor] == b'\\' {
            if cursor + 3 >= len || encoded[cursor + 1] != b'x' {
                return Err(AllowitWalletError::InvalidState);
            }
            let hex = |b| match b {
                b'0'..=b'9' => Some(b - b'0'),
                b'a'..=b'f' => Some(b - b'a' + 10),
                _ => None,
            };
            let (Some(high), Some(low)) = (hex(encoded[cursor + 2]), hex(encoded[cursor + 3]))
            else {
                return Err(AllowitWalletError::InvalidState);
            };
            cursor += 4;
            high * 16 + low
        } else {
            let b = encoded[cursor];
            cursor += 1;
            b
        };
        size += 1;
    }
    // SEP-11 keeps at least five bytes for AlphaNum12, including escaped zeros.
    let (kind, width) = if size <= 4 { (1u32, 4) } else { (2u32, 12) };
    let Ok(issuer) = public_key(to) else {
        return Ok(false);
    };
    let mut preimage = Bytes::from_array(env, &kind.to_be_bytes());
    preimage.append(&Bytes::from_slice(env, &code[..width]));
    preimage.append(&Bytes::from_array(env, &[0; 4]));
    preimage.append(&issuer.into());
    Ok(env
        .deployer()
        .with_stellar_asset(preimage)
        .deployed_address()
        == *asset)
}
/// Transfer `amount` from this wallet and check both exact balance effects.
fn move_tokens(
    env: &Env,
    asset: &Address,
    to: &Address,
    amount: i128,
) -> Result<(), AllowitWalletError> {
    let client = token::Client::new(env, asset);
    let from = env.current_contract_address();
    let before = client.balance(&from);
    if before < amount {
        return Err(AllowitWalletError::InsufficientFunds);
    }
    let after_from = checked(before.checked_sub(amount))?;
    let after_to = checked(client.balance(to).checked_add(amount))?;
    client.transfer(&from, to, &amount);
    if client.balance(&from) != after_from || client.balance(to) != after_to {
        return Err(AllowitWalletError::InvalidEffects);
    }
    Ok(())
}
/// Check denomination, operation class and conservative signed cost identities. External facts remain server-attested.
fn validate_expense(
    env: &Env,
    state: &AllowitState,
    expense: Option<&AllowitExpenseBounds>,
    operation: &AllowitStellarOperation,
) -> Result<(), AllowitWalletError> {
    let Some(expense) = expense else {
        return Ok(());
    };
    if expense.asset != state.asset
        || expense.decimals != 7
        || expense.gas_units < 0
        || expense.conversion_units < 0
        || expense.spent_units < 0
        || expense.observed_ledger == 0
        || expense.observed_ledger > env.ledger().sequence()
        || expense.day != env.ledger().timestamp() / 86_400
    {
        return Err(AllowitWalletError::InvalidInvocation);
    }
    let native_asset = env
        .deployer()
        .with_stellar_asset(Bytes::from_array(env, &[0; 4]))
        .deployed_address();
    // Both authenticated actors attest normalized gas for non-XLM accounting assets.
    // The kernel cannot verify a cross-asset price. XLM remains exact stroop identity.
    if (expense.max_fee_stroops == 0 && expense.gas_units != 0)
        || (expense.max_fee_stroops > 0 && expense.gas_units <= 0)
        || (state.asset == native_asset && expense.gas_units != i128::from(expense.max_fee_stroops))
    {
        return Err(AllowitWalletError::InvalidInvocation);
    }
    let principal = match operation {
        AllowitStellarOperation::Transfer(args) => {
            if expense.conversion_units != 0 {
                return Err(AllowitWalletError::InvalidInvocation);
            }
            args.amount
        }
        AllowitStellarOperation::Deposit(args) => {
            if expense.conversion_units > args.assets {
                return Err(AllowitWalletError::InvalidInvocation);
            }
            expense.conversion_units
        }
        // A forward swap pays the asset: its loss cannot exceed the input.
        AllowitStellarOperation::Swap(args) => {
            if args.path.get_unchecked(0) == state.asset
                && expense.conversion_units > args.amount_in
            {
                return Err(AllowitWalletError::InvalidInvocation);
            }
            expense.conversion_units
        }
        AllowitStellarOperation::Redeem(_) => expense.conversion_units,
    };
    if expense.spent_units != checked(principal.checked_add(expense.gas_units))? {
        return Err(AllowitWalletError::InvalidInvocation);
    }
    Ok(())
}

/// Deposit into a SEP-56 vault with exactly one delegated transfer, then check share and asset effects.
fn deposit_tokens(
    env: &Env,
    asset: &Address,
    args: &AllowitDepositArgs,
    expense: Option<&AllowitExpenseBounds>,
) -> Result<i128, AllowitWalletError> {
    use soroban_sdk::IntoVal;
    let underlying: Address =
        env.invoke_contract(&args.vault, &Symbol::new(env, "query_asset"), Vec::new(env));
    if underlying != *asset {
        return Err(AllowitWalletError::UnsupportedAsset);
    }
    let wallet = env.current_contract_address();
    let asset_client = token::Client::new(env, asset);
    let shares_client = token::Client::new(env, &args.vault);
    let before_assets = asset_client.balance(&wallet);
    let before_shares = shares_client.balance(&wallet);
    if before_assets < args.assets {
        return Err(AllowitWalletError::InsufficientFunds);
    }
    if before_shares < 0 {
        return Err(AllowitWalletError::InvalidEffects);
    }
    // The direct vault call is authorized by this invoking contract. Only this exact deeper transfer is delegated.
    env.authorize_as_current_contract(soroban_sdk::vec![
        env,
        InvokerContractAuthEntry::Contract(SubContractInvocation {
            context: ContractContext {
                contract: asset.clone(),
                fn_name: Symbol::new(env, "transfer"),
                args: (wallet.clone(), args.vault.clone(), args.assets).into_val(env),
            },
            sub_invocations: Vec::new(env),
        })
    ]);
    // SEP-56 `deposit(assets, receiver, from, operator)`: the wallet is all three parties.
    let shares: i128 = env.invoke_contract(
        &args.vault,
        &Symbol::new(env, "deposit"),
        (args.assets, wallet.clone(), wallet.clone(), wallet.clone()).into_val(env),
    );
    if let Some(expense) = expense {
        // The selected vault supplies this valuation. It is not a proof of future redemption or economic honesty.
        let redeemable: i128 = env.invoke_contract(
            &args.vault,
            &Symbol::new(env, "preview_redeem"),
            (shares,).into_val(env),
        );
        if redeemable < 0 || args.assets - args.assets.min(redeemable) > expense.conversion_units {
            return Err(AllowitWalletError::InvalidEffects);
        }
    }
    // Finish foreign metadata reads before measuring final effects. A vault getter is not trusted to be pure.
    let after_asset: Address =
        env.invoke_contract(&args.vault, &Symbol::new(env, "query_asset"), Vec::new(env));
    if after_asset != *asset {
        return Err(AllowitWalletError::InvalidEffects);
    }
    let expected_assets = checked(before_assets.checked_sub(args.assets))?;
    let expected_shares = checked(before_shares.checked_add(shares))?;
    let after_shares = shares_client.balance(&wallet);
    // The immutable SAC read is last: no untrusted vault code runs after these final observations.
    let after_assets = asset_client.balance(&wallet);
    if shares < args.min_shares
        || shares <= 0
        || after_assets != expected_assets
        || after_shares != expected_shares
    {
        return Err(AllowitWalletError::InvalidEffects);
    }
    Ok(shares)
}
/// Swap through the router with exactly one delegated transfer of `amount_in` to the router's
/// first pair, then check both endpoint balances. Returns the observed output.
fn swap_tokens(env: &Env, args: &AllowitSwapArgs) -> Result<i128, AllowitWalletError> {
    let wallet = env.current_contract_address();
    let n = args.path.len();
    let token_in = args.path.get_unchecked(0);
    let token_out = args.path.get_unchecked(n - 1);
    let pair: Address = env.invoke_contract(
        &args.router,
        &Symbol::new(env, "router_pair_for"),
        (token_in.clone(), args.path.get_unchecked(1)).into_val(env),
    );
    if pair == wallet || pair == args.router || !is_contract(&pair) {
        return Err(AllowitWalletError::InvalidEffects);
    }
    let in_client = token::Client::new(env, &token_in);
    let out_client = token::Client::new(env, &token_out);
    let before_in = in_client.balance(&wallet);
    let before_out = out_client.balance(&wallet);
    if before_in < args.amount_in {
        return Err(AllowitWalletError::InsufficientFunds);
    }
    // The router call itself is authorized by this invoking contract. Only this exact deeper
    // transfer to the pair is delegated.
    env.authorize_as_current_contract(soroban_sdk::vec![
        env,
        InvokerContractAuthEntry::Contract(SubContractInvocation {
            context: ContractContext {
                contract: token_in.clone(),
                fn_name: Symbol::new(env, "transfer"),
                args: (wallet.clone(), pair, args.amount_in).into_val(env),
            },
            sub_invocations: Vec::new(env),
        })
    ]);
    let amounts: Vec<i128> = env.invoke_contract(
        &args.router,
        &Symbol::new(env, "swap_exact_tokens_for_tokens"),
        (
            args.amount_in,
            args.amount_out_min,
            args.path.clone(),
            wallet.clone(),
            args.deadline,
        )
            .into_val(env),
    );
    let reported = |i| amounts.try_get(i).ok().flatten();
    let (Some(first), Some(out)) = (reported(0), reported(n - 1)) else {
        return Err(AllowitWalletError::InvalidEffects);
    };
    let expected_in = checked(before_in.checked_sub(args.amount_in))?;
    let expected_out = checked(before_out.checked_add(out))?;
    // Both endpoints are Stellar Asset Contracts: no untrusted code runs after the router returns.
    let after_out = out_client.balance(&wallet);
    let after_in = in_client.balance(&wallet);
    if amounts.len() != n
        || first != args.amount_in
        || out < args.amount_out_min
        || after_in != expected_in
        || after_out != expected_out
    {
        return Err(AllowitWalletError::InvalidEffects);
    }
    Ok(out)
}
/// Redeem vault shares for the asset, then check the share debit, the asset credit and the
/// conversion loss against the vault's own preview. The vault authorizes against this invoking
/// contract; the wallet delegates no token authorization.
fn redeem_shares(
    env: &Env,
    asset: &Address,
    args: &AllowitRedeemArgs,
    expense: Option<&AllowitExpenseBounds>,
) -> Result<i128, AllowitWalletError> {
    let underlying: Address =
        env.invoke_contract(&args.vault, &Symbol::new(env, "query_asset"), Vec::new(env));
    if underlying != *asset {
        return Err(AllowitWalletError::UnsupportedAsset);
    }
    // The selected vault values the shares before it acts. As for a deposit, this bounds the loss
    // against the vault's own valuation; it is not a proof of economic honesty.
    let previewed = match expense {
        Some(_) => {
            let value: i128 = env.invoke_contract(
                &args.vault,
                &Symbol::new(env, "preview_redeem"),
                (args.shares,).into_val(env),
            );
            if value < 0 {
                return Err(AllowitWalletError::InvalidEffects);
            }
            Some(value)
        }
        None => None,
    };
    let wallet = env.current_contract_address();
    let asset_client = token::Client::new(env, asset);
    let shares_client = token::Client::new(env, &args.vault);
    let before_assets = asset_client.balance(&wallet);
    let before_shares = shares_client.balance(&wallet);
    if before_shares < args.shares {
        return Err(AllowitWalletError::InsufficientFunds);
    }
    // SEP-56 `redeem(shares, receiver, owner, operator)`: the wallet is all three parties.
    let assets: i128 = env.invoke_contract(
        &args.vault,
        &Symbol::new(env, "redeem"),
        (args.shares, wallet.clone(), wallet.clone(), wallet.clone()).into_val(env),
    );
    // Finish foreign reads before the final asset balance. A vault getter is not trusted to be pure.
    let after_asset: Address =
        env.invoke_contract(&args.vault, &Symbol::new(env, "query_asset"), Vec::new(env));
    if after_asset != *asset {
        return Err(AllowitWalletError::InvalidEffects);
    }
    let expected_shares = checked(before_shares.checked_sub(args.shares))?;
    let expected_assets = checked(before_assets.checked_add(assets))?;
    let after_shares = shares_client.balance(&wallet);
    // The immutable SAC read is last: no untrusted vault code runs after these final observations.
    let after_assets = asset_client.balance(&wallet);
    let loss_exceeded = match (previewed, expense) {
        (Some(value), Some(expense)) => value - value.min(assets) > expense.conversion_units,
        _ => false,
    };
    if assets < args.min_assets
        || assets <= 0
        || loss_exceeded
        || after_shares != expected_shares
        || after_assets != expected_assets
    {
        return Err(AllowitWalletError::InvalidEffects);
    }
    Ok(assets)
}
/// Rule input: contract environment, owner params, current policy state, authenticated request
/// facts and the agent's execution params. Deposits and redeems name their vault, and swaps their
/// router, as the recipient. A request without expense bounds is unpriced.
fn rule_input(
    env: &Env,
    state: &AllowitState,
    execution: &AllowitExecutionRequest,
) -> AllowitContext {
    let facts = facts(&execution.operation, &state.asset);
    let expense = execution.expense.bounds();
    AllowitContext {
        env: env.clone(),
        params: AllowitParams(state.params.clone()),
        state: state.policy_state.clone(),
        request: AllowitRequest {
            operation: execution.operation.to_core(),
            asset: state.asset.clone(),
            recipient: facts.recipient,
            amount: facts.amount,
            token_in: facts.token_in,
            amount_in: facts.amount_in,
            token_out: facts.token_out,
            min_out: facts.min_out,
            now: env.ledger().timestamp(),
            expires_at: execution.expires_at,
            spent_units: expense.map_or(0, |e| e.spent_units),
            gas_units: expense.map_or(0, |e| e.gas_units),
            unpriced: expense.is_none(),
            args: AllowitParams(execution.args.clone()),
        },
    }
}
/// Admit one delegated operation: check bindings, replay, pause, nonce and expense, run the
/// policy, then write post-flight state, nonce and replay marker before any external call.
fn admit<P: AllowitPolicy>(
    env: &Env,
    execution: &AllowitExecutionRequest,
    mut state: AllowitState,
) -> Result<AllowitTransferReceipt, AllowitWalletError> {
    if !P::OPERATIONS.contains(&execution.operation.to_core()) {
        return Err(AllowitWalletError::UnsupportedOperation);
    }
    let installed = binding::<P>(env, &state)?;
    if execution.policy_instance != installed.policy_instance
        || execution.source_hash == BytesN::from_array(env, &[0; 32])
        || (!P::STANDARD_PREFIX && execution.source_hash != installed.source_digest)
        || execution.operation_id == BytesN::from_array(env, &[0; 32])
        || execution.module_digest != installed.module_digest
        || allowit::check_args(&execution.args).is_err()
    {
        return Err(AllowitWalletError::InvalidInvocation);
    }
    let expense = execution.expense.bounds();
    let args = debit(&execution.operation, &state.asset);
    let replay_key = Key::Operation(execution.operation_id.clone());
    if env.storage().persistent().has(&replay_key) {
        return Err(AllowitWalletError::Replay);
    }
    if state.paused {
        return Err(AllowitWalletError::Paused);
    }
    if execution.nonce != state.nonce || execution.deployment_version != state.deployment_version {
        return Err(AllowitWalletError::StaleRequest);
    }
    let now = env.ledger().timestamp();
    if execution.expires_at <= now {
        return Err(AllowitWalletError::Expired);
    }
    if args.amount <= 0 {
        return Err(AllowitWalletError::InvalidAmount);
    }
    if args.to == env.current_contract_address()
        || issuer_destination(env, &state.token, &state.asset, &args.to)?
    {
        return Err(AllowitWalletError::InvalidRecipient);
    }
    validate_expense(env, &state, expense, &execution.operation)?;
    let nonce = checked(state.nonce.checked_add(1))?;
    // Code changes defer tier validation of the kept rules and params to this admission.
    P::validate(&state.rules)?;
    if P::STANDARD_PREFIX {
        checked_params::<P>(&state.params)?;
    }
    let ctx = rule_input(env, &state, execution);
    P::check(&ctx, &state.rules)?;
    // The shared post-flight, then storage, precede token, router and vault calls. A later
    // failure in this transaction rolls all of it back.
    state.policy_state = allowit::post_flight(&ctx, tier::<P>())?;
    state.nonce = nonce;
    store(env, &state);
    let receipt = AllowitTransferReceipt {
        operation_id: execution.operation_id.clone(),
        token: args.token,
        from: env.current_contract_address(),
        to: args.to,
        amount: args.amount,
        nonce: execution.nonce,
        deployment_version: execution.deployment_version,
    };
    Ok(persistent::load(env, &replay_key, Some(&receipt)).unwrap())
}

/// Initialize custody from an owner-signed configuration.
pub fn construct<P: AllowitPolicy>(
    env: &Env,
    config: AllowitPolicyConfig,
) -> Result<(), AllowitWalletError> {
    // Decoding ignores extra keys and reads absent Option keys as None. The owner signs the
    // canonical encoding of the decoded packet, so a packet whose meaning differs fails auth.
    config
        .owner
        .require_auth_for_args((config.clone(),).into_val(env));
    validate::<P>(env, &config)?;
    if config.asset.executable() != Some(Executable::StellarAsset) {
        return Err(AllowitWalletError::UnsupportedAsset);
    }
    let token = token_label(env, &config.asset);
    load(
        env,
        Some(AllowitState {
            policy_state: Map::new(env),
            contract_version: CONTRACT_VERSION,
            owner: config.owner,
            agent: config.agent,
            server: config.server,
            asset: config.asset,
            policy_instance: config.policy_instance,
            source_digest: config.source_digest,
            rules: config.rules,
            params: config.params,
            x402_enabled: config.x402_enabled,
            token,
            deployment_version: 0,
            nonce: 0,
            paused: false,
        }),
    )?;
    Ok(())
}
/// Read the custody State.
pub fn state(env: &Env) -> Result<AllowitState, AllowitWalletError> {
    load(env, None)
}
/// Read the current free-form policy state: standard and policy-defined keys.
pub fn policy_state(env: &Env) -> Result<Map<Symbol, AllowitValue>, AllowitWalletError> {
    Ok(load(env, None)?.policy_state)
}
/// Read the installed binding: executable, source binding and the operations that this code runs.
pub fn policy_binding<P: AllowitPolicy>(
    env: &Env,
) -> Result<AllowitPolicyBinding, AllowitWalletError> {
    binding::<P>(env, &load(env, None)?)
}
/// Read the atomically retained actual share credit for a successful deposit operation.
pub fn deposit_receipt(
    env: &Env,
    operation_id: BytesN<32>,
) -> Result<Option<AllowitSep56DepositReceipt>, AllowitWalletError> {
    load(env, None)?;
    Ok(persistent::load(env, &Key::Deposit(operation_id), None))
}
/// Read the atomically retained observed output of a successful `execute` swap.
pub fn swap_receipt(
    env: &Env,
    operation_id: BytesN<32>,
) -> Result<Option<AllowitSwapReceipt>, AllowitWalletError> {
    load(env, None)?;
    Ok(persistent::load(env, &Key::Swap(operation_id), None))
}
/// Read the atomically retained observed output of a successful `execute` redeem.
pub fn redeem_receipt(
    env: &Env,
    operation_id: BytesN<32>,
) -> Result<Option<AllowitSep56RedeemReceipt>, AllowitWalletError> {
    load(env, None)?;
    Ok(persistent::load(env, &Key::Redeem(operation_id), None))
}
/// Run one agent- and server-authorized native operation under the installed policy.
pub fn execute<P: AllowitPolicy>(
    env: &Env,
    execution: AllowitExecutionRequest,
) -> Result<AllowitTransferReceipt, AllowitWalletError> {
    let state = load(env, None)?;
    // Decoding ignores extra keys. Agent and server sign the canonical encoding of the decoded
    // request, so a request whose meaning differs from what they signed fails auth.
    let signed: Vec<Val> = (execution.clone(),).into_val(env);
    state.agent.require_auth_for_args(signed.clone());
    state.server.require_auth_for_args(signed);
    validate_operation(env, &execution, &state)?;
    let asset = state.asset.clone();
    let receipt = admit::<P>(env, &execution, state)?;
    let expense = execution.expense.bounds();
    let wallet = env.current_contract_address();
    match execution.operation {
        AllowitStellarOperation::Swap(args) => {
            let amount_out = swap_tokens(env, &args)?;
            let swapped = AllowitSwapReceipt {
                operation_id: receipt.operation_id.clone(),
                router: args.router,
                token_in: args.path.get_unchecked(0),
                token_out: args.path.get_unchecked(args.path.len() - 1),
                amount_in: args.amount_in,
                amount_out,
                nonce: receipt.nonce,
                deployment_version: receipt.deployment_version,
            };
            persistent::load(
                env,
                &Key::Swap(receipt.operation_id.clone()),
                Some(&swapped),
            );
            AllowitSwapEvent {
                operation_id: receipt.operation_id.clone(),
                router: swapped.router,
                amount_in: swapped.amount_in,
                amount_out,
            }
            .publish(env);
        }
        AllowitStellarOperation::Redeem(args) => {
            let assets = redeem_shares(env, &asset, &args, expense)?;
            let redeemed = AllowitSep56RedeemReceipt {
                operation_id: receipt.operation_id.clone(),
                vault: args.vault,
                asset,
                owner: wallet.clone(),
                receiver: wallet.clone(),
                operator: wallet,
                shares: args.shares,
                assets,
                nonce: receipt.nonce,
                deployment_version: receipt.deployment_version,
            };
            persistent::load(
                env,
                &Key::Redeem(receipt.operation_id.clone()),
                Some(&redeemed),
            );
            AllowitSep56RedeemEvent {
                operation_id: receipt.operation_id.clone(),
                vault: redeemed.vault,
                shares: redeemed.shares,
                assets,
            }
            .publish(env);
        }
        AllowitStellarOperation::Transfer(_) => {
            move_tokens(env, &receipt.token, &receipt.to, receipt.amount)?
        }
        AllowitStellarOperation::Deposit(args) => {
            let shares = deposit_tokens(env, &receipt.token, &args, expense)?;
            let deposited = AllowitSep56DepositReceipt {
                operation_id: receipt.operation_id.clone(),
                vault: args.vault,
                asset: receipt.token.clone(),
                from: wallet.clone(),
                receiver: wallet.clone(),
                operator: wallet,
                assets: args.assets,
                shares,
                nonce: receipt.nonce,
                deployment_version: receipt.deployment_version,
            };
            persistent::load(
                env,
                &Key::Deposit(receipt.operation_id.clone()),
                Some(&deposited),
            );
            AllowitSep56DepositEvent {
                operation_id: receipt.operation_id.clone(),
                vault: deposited.vault,
                assets: deposited.assets,
                shares: deposited.shares,
            }
            .publish(env);
        }
    }
    Ok(receipt)
}
/// Apply a complete owner update; kept fields and policy state carry over.
pub fn deploy_policy<P: AllowitPolicy>(
    env: &Env,
    deployment: AllowitPolicyDeployment,
) -> Result<(), AllowitWalletError> {
    let kept = kept(env)?;
    // The current and any new owner sign the canonical encoding of the decoded packet.
    let signed: Vec<Val> = (deployment.clone(),).into_val(env);
    kept.owner.require_auth_for_args(signed.clone());
    if checked(kept.deployment_version.checked_add(1))? != deployment.deployment_version {
        return Err(AllowitWalletError::StaleRequest);
    }
    let policy_state = kept_policy_state(env, &kept)?;
    let config = AllowitPolicyConfig {
        owner: deployment.owner,
        agent: deployment.agent,
        server: deployment.server,
        asset: kept.asset,
        policy_instance: kept.policy_instance,
        source_digest: deployment.source_digest,
        rules: deployment.rules,
        params: deployment.params,
        x402_enabled: deployment.x402_enabled,
    };
    // A new bespoke executable validates its source on its next call. The owner binds its exact hash.
    if deployment.wasm_hash.as_ref().is_none_or(|hash| {
        env.current_contract_address().executable() == Some(Executable::Wasm(hash.clone()))
    }) {
        validate::<P>(env, &config)?;
    } else {
        validate::<UpgradeConfig>(env, &config)?;
    }
    if config.owner != kept.owner {
        config.owner.require_auth_for_args(signed);
    }
    // Kept fields carry over. The packet replaces the rest and writes the current layout.
    store(
        env,
        &AllowitState {
            policy_state,
            contract_version: CONTRACT_VERSION,
            owner: config.owner,
            agent: config.agent,
            server: config.server,
            asset: config.asset,
            policy_instance: config.policy_instance,
            source_digest: config.source_digest,
            rules: config.rules,
            params: config.params,
            x402_enabled: config.x402_enabled,
            token: kept.token,
            deployment_version: deployment.deployment_version,
            nonce: kept.nonce,
            paused: kept.paused,
        },
    );
    if let Some(hash) = deployment.wasm_hash {
        env.deployer()
            .update_current_contract(soroban_sdk::ContractExecutable::Wasm(hash));
    }
    Ok(())
}
/// Validation of a packet that installs new code: the new code checks its own rules on its next call.
struct UpgradeConfig;
impl AllowitPolicy for UpgradeConfig {
    const KIND: &'static str = "upgrade";
    /// The new code validates its rules itself.
    fn validate(_rules: &Vec<AllowitRule>) -> Result<(), AllowitWalletError> {
        Ok(())
    }
    /// Never used to execute.
    fn check(_ctx: &AllowitContext, _rules: &Vec<AllowitRule>) -> Result<(), AllowitWalletError> {
        Err(AllowitWalletError::PolicyDenied)
    }
}
/// Pause or resume delegated execution; the owner targets the next deployment version.
pub fn set_pause(
    env: &Env,
    paused: bool,
    deployment_version: u64,
) -> Result<(), AllowitWalletError> {
    let mut state = load(env, None)?;
    state.owner.require_auth();
    if checked(state.deployment_version.checked_add(1))? != deployment_version {
        return Err(AllowitWalletError::StaleRequest);
    }
    state.paused = paused;
    state.deployment_version = deployment_version;
    store(env, &state);
    Ok(())
}
/// Owner recovery of funds under any readable layout.
pub fn recover(env: &Env, recipient: Address, amount: i128) -> Result<(), AllowitWalletError> {
    let kept = kept(env)?;
    kept.owner.require_auth();
    if amount <= 0 {
        return Err(AllowitWalletError::InvalidAmount);
    }
    if recipient == env.current_contract_address()
        || issuer_destination(env, &kept.token, &kept.asset, &recipient)?
    {
        return Err(AllowitWalletError::InvalidRecipient);
    }
    move_tokens(env, &kept.asset, &recipient, amount)
}
/// Owner-signed passthrough. Native authorization binds target, arguments and every nested scope.
pub fn invoke(
    env: &Env,
    contract: Address,
    function: Symbol,
    args: Vec<Val>,
    auth: Vec<InvokerContractAuthEntry>,
) -> Result<Val, AllowitWalletError> {
    kept(env)?.owner.require_auth();
    env.authorize_as_current_contract(auth);
    Ok(env.invoke_contract(&contract, &function, args))
}
/// The contract context of an authorization context; any other context is `UnsupportedOperation`.
fn contract_context(
    contexts: &Vec<Context>,
    index: u32,
) -> Result<ContractContext, AllowitWalletError> {
    match contexts.get(index) {
        Some(Context::Contract(context)) => Ok(context),
        Some(_) => Err(AllowitWalletError::UnsupportedOperation),
        None => Err(AllowitWalletError::InvalidInvocation),
    }
}
/// Require a context of `function` on `contract`; another call is `UnsupportedOperation`.
fn require_call(
    env: &Env,
    context: &ContractContext,
    contract: &Address,
    function: &str,
) -> Result<(), AllowitWalletError> {
    if context.contract != *contract || context.fn_name != Symbol::new(env, function) {
        return Err(AllowitWalletError::UnsupportedOperation);
    }
    Ok(())
}
/// Require that the signed authorization tree, in host preorder, is exactly the native call of
/// `operation` as a plain wallet would sign it: a token `transfer`; a router
/// `swap_exact_tokens_for_tokens` with its one `transfer` of the first path token to a pair; or a
/// vault `redeem`. Deposits have no intercepted form.
fn match_contexts(
    env: &Env,
    state: &AllowitState,
    operation: &AllowitStellarOperation,
    contexts: &Vec<Context>,
) -> Result<(), AllowitWalletError> {
    let wallet = env.current_contract_address();
    let nodes = match operation {
        AllowitStellarOperation::Swap(_) => 2,
        _ => 1,
    };
    if contexts.len() != nodes {
        return Err(AllowitWalletError::InvalidInvocation);
    }
    let root = contract_context(contexts, 0)?;
    let args: Vec<Val> = match operation {
        AllowitStellarOperation::Deposit(_) => {
            return Err(AllowitWalletError::UnsupportedOperation);
        }
        AllowitStellarOperation::Transfer(a) => {
            require_call(env, &root, &state.asset, "transfer")?;
            (wallet.clone(), a.to.clone(), a.amount).into_val(env)
        }
        AllowitStellarOperation::Redeem(a) => {
            require_call(env, &root, &a.vault, "redeem")?;
            (a.shares, wallet.clone(), wallet.clone(), wallet.clone()).into_val(env)
        }
        AllowitStellarOperation::Swap(a) => {
            require_call(env, &root, &a.router, "swap_exact_tokens_for_tokens")?;
            let debit = contract_context(contexts, 1)?;
            require_call(env, &debit, &a.path.get_unchecked(0), "transfer")?;
            // The router pays its own pair; the signed tree names it. It is a contract other
            // than the wallet and the router, so the debit never burns a classic asset.
            let pair = debit
                .args
                .get(1)
                .and_then(|raw| Address::try_from_val(env, &raw).ok())
                .ok_or(AllowitWalletError::InvalidInvocation)?;
            let paid: Vec<Val> = (wallet.clone(), pair.clone(), a.amount_in).into_val(env);
            if pair == wallet || pair == a.router || !is_contract(&pair) || debit.args != paid {
                return Err(AllowitWalletError::InvalidInvocation);
            }
            let path = a.path.clone();
            (
                a.amount_in,
                a.amount_out_min,
                path,
                wallet.clone(),
                a.deadline,
            )
                .into_val(env)
        }
    };
    if root.args != args {
        return Err(AllowitWalletError::InvalidInvocation);
    }
    Ok(())
}
/// Verify the agent's and the server's raw ed25519 signatures over the host payload and the
/// execution request. A bad signature aborts.
fn verify_cosigners(
    env: &Env,
    state: &AllowitState,
    payload: &Hash<32>,
    authorization: &AllowitPolicyAuthorization,
) -> Result<(), AllowitWalletError> {
    let digest = env
        .crypto()
        .sha256(
            &(
                Symbol::new(env, "allowit_wallet_v1"),
                payload.to_bytes(),
                authorization.execution.clone(),
            )
                .to_xdr(env),
        )
        .to_bytes();
    env.crypto().ed25519_verify(
        &public_key(&state.agent)?,
        &digest.clone().into(),
        &authorization.agent_signature,
    );
    env.crypto().ed25519_verify(
        &public_key(&state.server)?,
        &digest.into(),
        &authorization.server_signature,
    );
    Ok(())
}
/// Custom-account authorization: admit one transfer, swap or redeem that a plain wallet would
/// sign, intercepted here, with the agent's and server's signatures, as `execute` does. The host
/// calls this while the token, router or vault, not the wallet, is on the call stack, and it
/// makes no contract call.
pub fn check_auth<P: AllowitPolicy>(
    env: &Env,
    payload: Hash<32>,
    authorization: AllowitPolicyAuthorization,
    contexts: Vec<Context>,
) -> Result<(), AllowitWalletError> {
    let state = load(env, None)?;
    if !state.x402_enabled {
        return Err(AllowitWalletError::UnsupportedOperation);
    }
    // The same typed operation and kernel invariants as execute.
    let execution = &authorization.execution;
    validate_operation(env, execution, &state)?;
    match_contexts(env, &state, &execution.operation, &contexts)?;
    verify_cosigners(env, &state, &payload, &authorization)?;
    admit::<P>(env, execution, state)?;
    Ok(())
}

/// Every native operation: the SEP-41 transfer, the router swap and the SEP-56 deposit and redeem.
pub const NATIVE_OPERATIONS: &[AllowitOperation] = &[
    AllowitOperation::transfer,
    AllowitOperation::swap,
    AllowitOperation::deposit,
    AllowitOperation::redeem,
];
/// Fixed minimal policy: server approval is mandatory, with no onchain business predicates.
pub struct AllowitSimple;
impl AllowitPolicy for AllowitSimple {
    const KIND: &'static str = "simple_policy_engine";
    const STANDARD_PREFIX: bool = true;
    const OPERATIONS: &'static [AllowitOperation] = NATIVE_OPERATIONS;
    /// No onchain rules: the kernel and the shared post-flight only.
    fn check(_ctx: &AllowitContext, _rules: &Vec<AllowitRule>) -> Result<(), AllowitWalletError> {
        Ok(())
    }
}
/// Fixed canonical rule set. The owner chooses every enforced rule explicitly.
pub struct AllowitCommon;
impl AllowitPolicy for AllowitCommon {
    const KIND: &'static str = "common_policy_engine";
    const STANDARD_PREFIX: bool = true;
    const OPERATIONS: &'static [AllowitOperation] = NATIVE_OPERATIONS;
    /// Any ordered list of typed rules. The kernel decodes each element before storing it.
    fn validate(_rules: &Vec<AllowitRule>) -> Result<(), AllowitWalletError> {
        Ok(())
    }
    /// Run each prefix call `allowit::<rule>(ctx, ctx.params.get(allowit::<RULE>))?;` in owner
    /// order. An absent param skips its rule here only; the full offchain policy denies it.
    fn check(ctx: &AllowitContext, rules: &Vec<AllowitRule>) -> Result<(), AllowitWalletError> {
        for rule in rules.iter() {
            allowit::preflight(ctx, rule)?;
        }
        Ok(())
    }
}
/// Rule denials collapse to PolicyDenied. Invalid owner configuration, state and overflow stay distinct.
impl From<allowit::AllowitError> for AllowitWalletError {
    fn from(error: allowit::AllowitError) -> Self {
        match error {
            allowit::AllowitError::MissingParam | allowit::AllowitError::InvalidParam => {
                AllowitWalletError::InvalidParam
            }
            allowit::AllowitError::InvalidState => AllowitWalletError::InvalidState,
            allowit::AllowitError::Overflow => AllowitWalletError::Overflow,
            allowit::AllowitError::Unsupported => AllowitWalletError::UnsupportedOperation,
            _ => AllowitWalletError::PolicyDenied,
        }
    }
}

/// Attach the complete owner and delegated-execution interface to a policy implementation.
#[macro_export]
macro_rules! policy_wallet {
    ($name:ident, $policy:ty) => {
        /// Policy wallet contract of one compiled policy.
        #[soroban_sdk::contract]
        pub struct $name;
        #[soroban_sdk::contractimpl]
        impl $name {
            /// Initialize custody from an owner-signed configuration.
            pub fn __constructor(env: soroban_sdk::Env, config: $crate::AllowitPolicyConfig) {
                $crate::construct::<$policy>(&env, config).unwrap();
            }
            /// Read the custody State.
            pub fn state(
                env: soroban_sdk::Env,
            ) -> Result<$crate::AllowitState, $crate::AllowitWalletError> {
                $crate::state(&env)
            }
            /// Read the current free-form policy state: standard and policy-defined keys.
            pub fn policy_state(
                env: soroban_sdk::Env,
            ) -> Result<
                soroban_sdk::Map<soroban_sdk::Symbol, allowit_wallet_protocol::AllowitValue>,
                $crate::AllowitWalletError,
            > {
                $crate::policy_state(&env)
            }
            /// Read the installed binding: executable, source binding and the operations it runs.
            pub fn policy_binding(
                env: soroban_sdk::Env,
            ) -> Result<allowit_wallet_protocol::AllowitPolicyBinding, $crate::AllowitWalletError>
            {
                $crate::policy_binding::<$policy>(&env)
            }
            /// Read the retained share credit of a successful deposit operation.
            pub fn deposit_receipt(
                env: soroban_sdk::Env,
                operation_id: soroban_sdk::BytesN<32>,
            ) -> Result<
                Option<allowit_wallet_protocol::AllowitSep56DepositReceipt>,
                $crate::AllowitWalletError,
            > {
                $crate::deposit_receipt(&env, operation_id)
            }
            /// Read the retained observed output of a successful `execute` swap.
            pub fn swap_receipt(
                env: soroban_sdk::Env,
                operation_id: soroban_sdk::BytesN<32>,
            ) -> Result<
                Option<allowit_wallet_protocol::AllowitSwapReceipt>,
                $crate::AllowitWalletError,
            > {
                $crate::swap_receipt(&env, operation_id)
            }
            /// Read the retained observed output of a successful `execute` redeem.
            pub fn redeem_receipt(
                env: soroban_sdk::Env,
                operation_id: soroban_sdk::BytesN<32>,
            ) -> Result<
                Option<allowit_wallet_protocol::AllowitSep56RedeemReceipt>,
                $crate::AllowitWalletError,
            > {
                $crate::redeem_receipt(&env, operation_id)
            }
            /// Run one agent- and server-authorized native operation under the installed policy.
            pub fn execute(
                env: soroban_sdk::Env,
                execution: allowit_wallet_protocol::AllowitExecutionRequest,
            ) -> Result<allowit_wallet_protocol::AllowitTransferReceipt, $crate::AllowitWalletError>
            {
                $crate::execute::<$policy>(&env, execution)
            }
            /// Apply a complete owner update at the next deployment version.
            pub fn deploy_policy(
                env: soroban_sdk::Env,
                deployment: $crate::AllowitPolicyDeployment,
            ) -> Result<(), $crate::AllowitWalletError> {
                $crate::deploy_policy::<$policy>(&env, deployment)
            }
            /// Pause or resume delegated execution at the next deployment version.
            pub fn set_pause(
                env: soroban_sdk::Env,
                paused: bool,
                deployment_version: u64,
            ) -> Result<(), $crate::AllowitWalletError> {
                $crate::set_pause(&env, paused, deployment_version)
            }
            /// Owner recovery of funds under any readable layout.
            pub fn recover(
                env: soroban_sdk::Env,
                recipient: soroban_sdk::Address,
                amount: i128,
            ) -> Result<(), $crate::AllowitWalletError> {
                $crate::recover(&env, recipient, amount)
            }
            /// Owner-signed passthrough call with explicit nested authorization.
            pub fn invoke(
                env: soroban_sdk::Env,
                contract: soroban_sdk::Address,
                function: soroban_sdk::Symbol,
                args: soroban_sdk::Vec<soroban_sdk::Val>,
                auth: soroban_sdk::Vec<soroban_sdk::auth::InvokerContractAuthEntry>,
            ) -> Result<soroban_sdk::Val, $crate::AllowitWalletError> {
                $crate::invoke(&env, contract, function, args, auth)
            }
        }
        #[soroban_sdk::contractimpl]
        impl soroban_sdk::auth::CustomAccountInterface for $name {
            type Signature = $crate::AllowitPolicyAuthorization;
            type Error = $crate::AllowitWalletError;
            /// Admit one intercepted transfer, swap or redeem that the agent and server signed.
            fn __check_auth(
                env: soroban_sdk::Env,
                signature_payload: soroban_sdk::crypto::Hash<32>,
                authorization: $crate::AllowitPolicyAuthorization,
                contexts: soroban_sdk::Vec<soroban_sdk::auth::Context>,
            ) -> Result<(), $crate::AllowitWalletError> {
                $crate::check_auth::<$policy>(&env, signature_payload, authorization, contexts)
            }
        }
    };
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod sep56_tests;

#[cfg(test)]
mod portability_tests;

#[cfg(test)]
mod swap_redeem_tests;
