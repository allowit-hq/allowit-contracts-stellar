//! The native operations and their effect checks: SEP-41 transfers, router swaps and SEP-56
//! deposits and redeems. The wallet is every source, owner, receiver and operator.
use crate::{AllowitWalletError, checked, public_key};
use allowit_wallet_protocol::{
    AllowitDepositArgs, AllowitExecutionRequest, AllowitExpenseBounds, AllowitRedeemArgs,
    AllowitStellarOperation, AllowitSwapArgs, MAX_SWAP_PATH,
};
use soroban_sdk::{
    Address, Bytes, Env, Executable, IntoVal, Symbol, Vec,
    address_payload::AddressPayload,
    auth::{ContractContext, InvokerContractAuthEntry, SubContractInvocation},
    token,
};

/// The one debit of an operation: `amount` of `token` leaves the wallet. Deposits move
/// `assets` to the vault, swaps move `amount_in` of the first path token toward the router, and
/// redeems burn `shares` of the vault's share token.
pub(crate) struct Debit {
    pub(crate) token: Address,
    pub(crate) amount: i128,
}
/// The debit of `operation` on a wallet of `asset`.
pub(crate) fn debit(operation: &AllowitStellarOperation, asset: &Address) -> Debit {
    match operation {
        AllowitStellarOperation::Transfer(args) => Debit {
            token: args.token.clone(),
            amount: args.amount,
        },
        AllowitStellarOperation::Swap(args) => Debit {
            token: args.path.get_unchecked(0),
            amount: args.amount_in,
        },
        AllowitStellarOperation::Deposit(args) => Debit {
            token: asset.clone(),
            amount: args.assets,
        },
        AllowitStellarOperation::Redeem(args) => Debit {
            token: args.vault.clone(),
            amount: args.shares,
        },
    }
}
/// Request facts of one native operation, which rules read.
pub(crate) struct Facts {
    pub(crate) recipient: Address,
    pub(crate) amount: i128,
    pub(crate) token_in: Address,
    pub(crate) amount_in: i128,
    pub(crate) token_out: Option<Address>,
    pub(crate) min_out: i128,
}
/// The request facts of `operation`. A forward swap counts its asset input as the gross amount; a
/// reverse swap and a redeem count their minimum asset output, a floor.
pub(crate) fn facts(operation: &AllowitStellarOperation, asset: &Address) -> Facts {
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
pub(crate) fn is_contract(address: &Address) -> bool {
    matches!(
        address.to_payload(),
        Some(AddressPayload::ContractIdHash(_))
    )
}
/// Check the native operation of a request: a transfer moves a positive amount of the installed
/// asset to neither the wallet nor the asset's classic issuer, a vault or router is neither the
/// wallet nor the asset, and amounts are positive. The wallet supplies itself as every source,
/// owner, receiver and operator.
pub(crate) fn validate_operation(
    env: &Env,
    execution: &AllowitExecutionRequest,
    asset: &Address,
) -> Result<(), AllowitWalletError> {
    let wallet = env.current_contract_address();
    let (vault, amount, minimum) = match &execution.operation {
        AllowitStellarOperation::Transfer(args) => {
            if args.token != *asset {
                return Err(AllowitWalletError::InvalidInvocation);
            }
            if args.amount <= 0 {
                return Err(AllowitWalletError::InvalidAmount);
            }
            if args.to == wallet || issuer_destination(env, asset, &args.to)? {
                return Err(AllowitWalletError::InvalidRecipient);
            }
            return Ok(());
        }
        AllowitStellarOperation::Swap(args) => return validate_swap(env, execution, asset, args),
        AllowitStellarOperation::Deposit(args) => (&args.vault, args.assets, args.min_shares),
        AllowitStellarOperation::Redeem(args) => (&args.vault, args.shares, args.min_assets),
    };
    if *vault == wallet || vault == asset {
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
    asset: &Address,
    args: &AllowitSwapArgs,
) -> Result<(), AllowitWalletError> {
    let wallet = env.current_contract_address();
    let n = args.path.len();
    if args.router == wallet
        || args.router == *asset
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
    if (first == *asset) == (last == *asset) {
        return Err(AllowitWalletError::InvalidInvocation);
    }
    // A host lookup of the executable, not a contract call.
    let other = if first == *asset { last } else { first };
    if other.executable() != Some(Executable::StellarAsset) {
        return Err(AllowitWalletError::UnsupportedAsset);
    }
    if args.amount_in <= 0 || args.amount_out_min <= 0 {
        return Err(AllowitWalletError::InvalidAmount);
    }
    Ok(())
}

/// The native XLM Stellar Asset Contract address.
pub(crate) fn native_asset(env: &Env) -> Address {
    env.deployer()
        .with_stellar_asset(Bytes::from_array(env, &[0; 4]))
        .deployed_address()
}
// A transfer to a classic issuer burns its asset. The SAC's symbol gives the asset code; the
// SAC address of that code and the candidate issuer is compared with the asset.
/// Whether `to` is the classic issuer of the asset, where a transfer burns it. XLM has no issuer,
/// and a contract never burns a classic asset.
pub(crate) fn issuer_destination(
    env: &Env,
    asset: &Address,
    to: &Address,
) -> Result<bool, AllowitWalletError> {
    let Ok(issuer) = public_key(to) else {
        return Ok(false);
    };
    if *asset == native_asset(env) {
        return Ok(false);
    }
    let token = token::Client::new(env, asset).symbol();
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
pub(crate) fn move_tokens(
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
/// Deposit into a SEP-56 vault with exactly one delegated transfer, then check share and asset effects.
pub(crate) fn deposit_tokens(
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
        // An overflowing loss saturates above the bound, which never exceeds the assets.
        if args.assets.saturating_sub(args.assets.min(redeemable)) > expense.conversion_units {
            return Err(AllowitWalletError::InvalidEffects);
        }
    }
    let expected_assets = checked(before_assets.checked_sub(args.assets))?;
    let expected_shares = checked(before_shares.checked_add(shares))?;
    let after_shares = shares_client.balance(&wallet);
    // The immutable SAC read is last: no untrusted vault code runs after these final observations.
    let after_assets = asset_client.balance(&wallet);
    // `min_shares` is positive, so this also rejects a nonpositive mint.
    if shares < args.min_shares
        || after_assets != expected_assets
        || after_shares != expected_shares
    {
        return Err(AllowitWalletError::InvalidEffects);
    }
    Ok(shares)
}
/// Swap through the router with exactly one delegated transfer of `amount_in` to the router's
/// first pair, then check both endpoint balances. Returns the observed output.
pub(crate) fn swap_tokens(env: &Env, args: &AllowitSwapArgs) -> Result<i128, AllowitWalletError> {
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
pub(crate) fn redeem_shares(
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
    // A nonpositive preview bounds no loss, as the vault can always report zero.
    let previewed: Option<i128> = expense.map(|_| {
        env.invoke_contract(
            &args.vault,
            &Symbol::new(env, "preview_redeem"),
            (args.shares,).into_val(env),
        )
    });
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
    let expected_shares = checked(before_shares.checked_sub(args.shares))?;
    let expected_assets = checked(before_assets.checked_add(assets))?;
    let after_shares = shares_client.balance(&wallet);
    // The immutable SAC read is last: no untrusted vault code runs after these final observations.
    let after_assets = asset_client.balance(&wallet);
    let loss_exceeded = match (previewed, expense) {
        (Some(value), Some(expense)) => {
            value.saturating_sub(value.min(assets)) > expense.conversion_units
        }
        _ => false,
    };
    // `min_assets` is positive, so this also rejects a nonpositive payout.
    if assets < args.min_assets
        || loss_exceeded
        || after_shares != expected_shares
        || after_assets != expected_assets
    {
        return Err(AllowitWalletError::InvalidEffects);
    }
    Ok(assets)
}
