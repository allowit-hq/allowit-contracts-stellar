#![no_std]
//! Test-only SEP-56 vault with a share price that its admin sets. Never use this fixture as a
//! deployed asset vault.
//!
//! The vault behaves as a SEP-56 vault should: a deposit takes exactly the assets it is asked to
//! take and mints the shares that `preview_deposit` names; a redeem burns exactly the shares it
//! is asked to burn and pays the assets that `preview_redeem` names. Its share token is a SEP-41
//! token. Unlike a real vault, it earns nothing: its admin sets the price of one share
//! (`set_share_price`), and every conversion uses that price. Tests and Testnet evals use it to
//! give a wallet an honest vault and to move a share price on purpose.
//!
//! The price is the asset amount, in base units, for [`SHARE`] share base units (one share at
//! seven decimals). `SHARE` itself is a price of one asset per share. Conversions round toward
//! the vault, as ERC-4626 does: a deposit and a redeem round down, a mint and a withdraw round
//! up. The admin keeps the vault solvent: a redeem fails when the vault holds fewer assets than
//! it pays, so raise the price only after moving the difference to the vault with a plain
//! asset transfer.
use soroban_sdk::{
    Address, Env, MuxedAddress, String, contract, contracterror, contractevent, contractimpl,
    contracttype, panic_with_error, token,
};

/// One share in base units, and the price of one asset per share.
pub const SHARE: i128 = 10_000_000;
/// Share decimals.
pub const DECIMALS: u32 = 7;
/// Below this many ledgers of remaining life, a call extends an entry (about 3.5 days).
const EXTEND_BELOW: u32 = 60_480;
/// The life that a call extends an entry to (about 7 days, the Testnet minimum).
const EXTEND_TO: u32 = 120_960;

#[contracttype]
#[derive(Clone)]
enum Key {
    Asset,
    Admin,
    Name,
    Price,
    Supply,
    Balance(Address),
    Allowance(Address, Address),
}

#[contracttype]
#[derive(Clone)]
struct Allowance {
    amount: i128,
    expiration_ledger: u32,
}

#[contracterror]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum VaultError {
    /// An amount or a price is not positive.
    NotPositive = 1,
    /// The conversion gives no share or no asset.
    ZeroResult = 2,
    /// The owner holds fewer shares than the call moves.
    InsufficientShares = 3,
    /// The operator's allowance is smaller than the call moves, or it expired.
    InsufficientAllowance = 4,
    /// An amount overflows.
    Overflow = 5,
    /// The expiration ledger of an allowance is in the past.
    InvalidExpiration = 6,
}

/// SEP-56: assets came in and shares went out.
#[contractevent(topics = ["deposit"])]
pub struct Deposit {
    #[topic]
    pub operator: Address,
    #[topic]
    pub from: Address,
    #[topic]
    pub receiver: Address,
    pub assets: i128,
    pub shares: i128,
}
/// SEP-56: shares were burned and assets went out.
#[contractevent(topics = ["withdraw"])]
pub struct Withdraw {
    #[topic]
    pub operator: Address,
    #[topic]
    pub receiver: Address,
    #[topic]
    pub owner: Address,
    pub assets: i128,
    pub shares: i128,
}
/// The admin set a new share price.
#[contractevent(topics = ["share_price"])]
pub struct SharePrice {
    pub old: i128,
    pub new: i128,
}
/// SEP-41: shares minted.
#[contractevent(topics = ["mint"])]
pub struct Mint {
    #[topic]
    pub to: Address,
    pub amount: i128,
}
/// SEP-41: shares burned.
#[contractevent(topics = ["burn"])]
pub struct Burn {
    #[topic]
    pub from: Address,
    pub amount: i128,
}
/// SEP-41: shares moved between holders.
#[contractevent(topics = ["transfer"])]
pub struct Transfer {
    #[topic]
    pub from: Address,
    #[topic]
    pub to: Address,
    pub amount: i128,
}
/// SEP-41: an allowance was set.
#[contractevent(topics = ["approve"])]
pub struct Approve {
    #[topic]
    pub from: Address,
    #[topic]
    pub spender: Address,
    pub amount: i128,
    pub expiration_ledger: u32,
}

#[contract]
pub struct AllowitSep56PricedTestVault;

fn get<V: soroban_sdk::TryFromVal<Env, soroban_sdk::Val>>(env: &Env, key: &Key) -> V {
    env.storage().instance().get(key).unwrap()
}
fn touch(env: &Env) {
    env.storage().instance().extend_ttl(EXTEND_BELOW, EXTEND_TO);
}
fn positive(env: &Env, amount: i128) {
    if amount <= 0 {
        panic_with_error!(env, VaultError::NotPositive);
    }
}
fn ratio(env: &Env, value: i128, times: i128, over: i128, up: bool) -> i128 {
    let product = value
        .checked_mul(times)
        .unwrap_or_else(|| panic_with_error!(env, VaultError::Overflow));
    let quotient = product / over;
    if up && product % over != 0 {
        quotient + 1
    } else {
        quotient
    }
}
fn price(env: &Env) -> i128 {
    get(env, &Key::Price)
}
fn balance_of(env: &Env, holder: &Address) -> i128 {
    let key = Key::Balance(holder.clone());
    let balance = env.storage().persistent().get(&key).unwrap_or(0);
    if balance != 0 {
        env.storage()
            .persistent()
            .extend_ttl(&key, EXTEND_BELOW, EXTEND_TO);
    }
    balance
}
fn set_balance(env: &Env, holder: &Address, amount: i128) {
    let key = Key::Balance(holder.clone());
    if amount == 0 {
        env.storage().persistent().remove(&key);
    } else {
        env.storage().persistent().set(&key, &amount);
        env.storage()
            .persistent()
            .extend_ttl(&key, EXTEND_BELOW, EXTEND_TO);
    }
}
fn mint_shares(env: &Env, to: &Address, shares: i128) {
    let after = balance_of(env, to)
        .checked_add(shares)
        .unwrap_or_else(|| panic_with_error!(env, VaultError::Overflow));
    set_balance(env, to, after);
    let supply: i128 = get(env, &Key::Supply);
    env.storage().instance().set(
        &Key::Supply,
        &supply
            .checked_add(shares)
            .unwrap_or_else(|| panic_with_error!(env, VaultError::Overflow)),
    );
    Mint {
        to: to.clone(),
        amount: shares,
    }
    .publish(env);
}
fn burn_shares(env: &Env, from: &Address, shares: i128) {
    let before = balance_of(env, from);
    if before < shares {
        panic_with_error!(env, VaultError::InsufficientShares);
    }
    set_balance(env, from, before - shares);
    let supply: i128 = get(env, &Key::Supply);
    env.storage()
        .instance()
        .set(&Key::Supply, &(supply - shares));
    Burn {
        from: from.clone(),
        amount: shares,
    }
    .publish(env);
}
fn allowance_of(env: &Env, from: &Address, spender: &Address) -> i128 {
    let key = Key::Allowance(from.clone(), spender.clone());
    match env.storage().temporary().get::<_, Allowance>(&key) {
        Some(a) if a.expiration_ledger >= env.ledger().sequence() => a.amount,
        _ => 0,
    }
}
fn spend_allowance(env: &Env, from: &Address, spender: &Address, amount: i128) {
    let key = Key::Allowance(from.clone(), spender.clone());
    let current = allowance_of(env, from, spender);
    if current < amount {
        panic_with_error!(env, VaultError::InsufficientAllowance);
    }
    let a: Allowance = env.storage().temporary().get(&key).unwrap();
    env.storage().temporary().set(
        &key,
        &Allowance {
            amount: current - amount,
            expiration_ledger: a.expiration_ledger,
        },
    );
}
/// The operator acts for `holder`: either it is the holder, or it spends the holder's
/// allowance of `shares`.
fn act_for(env: &Env, operator: &Address, holder: &Address, shares: i128) {
    operator.require_auth();
    if operator != holder {
        spend_allowance(env, holder, operator, shares);
    }
}
fn move_shares(env: &Env, from: &Address, to: &Address, amount: i128) {
    let before = balance_of(env, from);
    if before < amount {
        panic_with_error!(env, VaultError::InsufficientShares);
    }
    set_balance(env, from, before - amount);
    let after = balance_of(env, to)
        .checked_add(amount)
        .unwrap_or_else(|| panic_with_error!(env, VaultError::Overflow));
    set_balance(env, to, after);
}

#[contractimpl]
impl AllowitSep56PricedTestVault {
    /// Fix the underlying asset, the admin that sets the price, the share token's name and the
    /// starting price of one share in asset base units.
    pub fn __constructor(
        env: Env,
        asset: Address,
        admin: Address,
        name: String,
        share_price: i128,
    ) {
        positive(&env, share_price);
        let storage = env.storage().instance();
        storage.set(&Key::Asset, &asset);
        storage.set(&Key::Admin, &admin);
        storage.set(&Key::Name, &name);
        storage.set(&Key::Price, &share_price);
        storage.set(&Key::Supply, &0i128);
    }

    // --- Price administration ---

    /// The admin that sets the price.
    pub fn admin(env: Env) -> Address {
        get(&env, &Key::Admin)
    }
    /// The asset base units that one share ([`SHARE`] share base units) converts to.
    pub fn share_price(env: Env) -> i128 {
        price(&env)
    }
    /// Admin only: set the price of one share.
    pub fn set_share_price(env: Env, share_price: i128) {
        let admin: Address = get(&env, &Key::Admin);
        admin.require_auth();
        positive(&env, share_price);
        let old = price(&env);
        env.storage().instance().set(&Key::Price, &share_price);
        touch(&env);
        SharePrice {
            old,
            new: share_price,
        }
        .publish(&env);
    }

    // --- SEP-56 ---

    /// The underlying asset.
    pub fn query_asset(env: Env) -> Address {
        get(&env, &Key::Asset)
    }
    /// The assets that all shares are worth at the current price.
    pub fn total_assets(env: Env) -> i128 {
        let supply: i128 = get(&env, &Key::Supply);
        ratio(&env, supply, price(&env), SHARE, false)
    }
    /// Shares for `assets`, rounded down.
    pub fn convert_to_shares(env: Env, assets: i128) -> i128 {
        ratio(&env, assets, SHARE, price(&env), false)
    }
    /// Assets for `shares`, rounded down.
    pub fn convert_to_assets(env: Env, shares: i128) -> i128 {
        ratio(&env, shares, price(&env), SHARE, false)
    }
    /// The vault takes any deposit.
    pub fn max_deposit(_env: Env, _receiver: Address) -> i128 {
        i128::MAX
    }
    /// Shares that a deposit of `assets` mints.
    pub fn preview_deposit(env: Env, assets: i128) -> i128 {
        Self::convert_to_shares(env, assets)
    }
    /// Take exactly `assets` from `from` and mint shares to `receiver`. The operator authorizes;
    /// when it is not `from`, it spends its allowance of the asset from `from`.
    pub fn deposit(
        env: Env,
        assets: i128,
        receiver: Address,
        from: Address,
        operator: Address,
    ) -> i128 {
        operator.require_auth();
        positive(&env, assets);
        let shares = Self::preview_deposit(env.clone(), assets);
        if shares <= 0 {
            panic_with_error!(&env, VaultError::ZeroResult);
        }
        Self::take(&env, &operator, &from, assets);
        mint_shares(&env, &receiver, shares);
        touch(&env);
        Deposit {
            operator,
            from,
            receiver,
            assets,
            shares,
        }
        .publish(&env);
        shares
    }
    /// The vault mints any number of shares.
    pub fn max_mint(_env: Env, _receiver: Address) -> i128 {
        i128::MAX
    }
    /// Assets that minting `shares` takes, rounded up.
    pub fn preview_mint(env: Env, shares: i128) -> i128 {
        ratio(&env, shares, price(&env), SHARE, true)
    }
    /// Mint exactly `shares` to `receiver` for the assets that `preview_mint` names.
    pub fn mint(
        env: Env,
        shares: i128,
        receiver: Address,
        from: Address,
        operator: Address,
    ) -> i128 {
        operator.require_auth();
        positive(&env, shares);
        let assets = Self::preview_mint(env.clone(), shares);
        Self::take(&env, &operator, &from, assets);
        mint_shares(&env, &receiver, shares);
        touch(&env);
        Deposit {
            operator,
            from,
            receiver,
            assets,
            shares,
        }
        .publish(&env);
        assets
    }
    /// The assets that `owner` can withdraw: its shares' worth, within what the vault holds.
    pub fn max_withdraw(env: Env, owner: Address) -> i128 {
        let worth = Self::convert_to_assets(env.clone(), balance_of(&env, &owner));
        worth.min(Self::held(&env))
    }
    /// Shares that withdrawing `assets` burns, rounded up.
    pub fn preview_withdraw(env: Env, assets: i128) -> i128 {
        ratio(&env, assets, SHARE, price(&env), true)
    }
    /// Pay exactly `assets` to `receiver` and burn the shares that `preview_withdraw` names.
    pub fn withdraw(
        env: Env,
        assets: i128,
        receiver: Address,
        owner: Address,
        operator: Address,
    ) -> i128 {
        positive(&env, assets);
        let shares = Self::preview_withdraw(env.clone(), assets);
        act_for(&env, &operator, &owner, shares);
        burn_shares(&env, &owner, shares);
        Self::pay(&env, &receiver, assets);
        touch(&env);
        Withdraw {
            operator,
            receiver,
            owner,
            assets,
            shares,
        }
        .publish(&env);
        shares
    }
    /// The shares that `owner` can redeem: its shares, within what the vault can pay.
    pub fn max_redeem(env: Env, owner: Address) -> i128 {
        let payable = ratio(&env, Self::held(&env), SHARE, price(&env), false);
        balance_of(&env, &owner).min(payable)
    }
    /// Assets that redeeming `shares` pays.
    pub fn preview_redeem(env: Env, shares: i128) -> i128 {
        Self::convert_to_assets(env, shares)
    }
    /// Burn exactly `shares` of `owner` and pay the assets that `preview_redeem` names to
    /// `receiver`. The operator authorizes; when it is not `owner`, it spends its allowance of
    /// the shares from `owner`.
    pub fn redeem(
        env: Env,
        shares: i128,
        receiver: Address,
        owner: Address,
        operator: Address,
    ) -> i128 {
        positive(&env, shares);
        let assets = Self::preview_redeem(env.clone(), shares);
        if assets <= 0 {
            panic_with_error!(&env, VaultError::ZeroResult);
        }
        act_for(&env, &operator, &owner, shares);
        burn_shares(&env, &owner, shares);
        Self::pay(&env, &receiver, assets);
        touch(&env);
        Withdraw {
            operator,
            receiver,
            owner,
            assets,
            shares,
        }
        .publish(&env);
        assets
    }

    // --- SEP-41 share token ---

    /// Shares of `id`.
    pub fn balance(env: Env, id: Address) -> i128 {
        balance_of(&env, &id)
    }
    /// All shares.
    pub fn total_supply(env: Env) -> i128 {
        get(&env, &Key::Supply)
    }
    /// Share decimals.
    pub fn decimals(_env: Env) -> u32 {
        DECIMALS
    }
    /// The share token's name.
    pub fn name(env: Env) -> String {
        get(&env, &Key::Name)
    }
    /// The share token's symbol.
    pub fn symbol(env: Env) -> String {
        String::from_str(&env, "SHARE")
    }
    /// The shares that `spender` may move for `from`.
    pub fn allowance(env: Env, from: Address, spender: Address) -> i128 {
        allowance_of(&env, &from, &spender)
    }
    /// Let `spender` move `amount` shares of `from` until `expiration_ledger`.
    pub fn approve(
        env: Env,
        from: Address,
        spender: Address,
        amount: i128,
        expiration_ledger: u32,
    ) {
        from.require_auth();
        if amount < 0 {
            panic_with_error!(&env, VaultError::NotPositive);
        }
        if amount > 0 && expiration_ledger < env.ledger().sequence() {
            panic_with_error!(&env, VaultError::InvalidExpiration);
        }
        let key = Key::Allowance(from.clone(), spender.clone());
        env.storage().temporary().set(
            &key,
            &Allowance {
                amount,
                expiration_ledger,
            },
        );
        if amount > 0 {
            let live = expiration_ledger - env.ledger().sequence();
            env.storage().temporary().extend_ttl(&key, live, live);
        }
        Approve {
            from,
            spender,
            amount,
            expiration_ledger,
        }
        .publish(&env);
    }
    /// Move `amount` shares from `from` to `to`.
    pub fn transfer(env: Env, from: Address, to: MuxedAddress, amount: i128) {
        from.require_auth();
        positive(&env, amount);
        let to = to.address();
        move_shares(&env, &from, &to, amount);
        Transfer { from, to, amount }.publish(&env);
    }
    /// Move `amount` shares from `from` to `to` with the allowance of `spender`.
    pub fn transfer_from(env: Env, spender: Address, from: Address, to: Address, amount: i128) {
        spender.require_auth();
        positive(&env, amount);
        spend_allowance(&env, &from, &spender, amount);
        move_shares(&env, &from, &to, amount);
        Transfer { from, to, amount }.publish(&env);
    }
    /// Burn `amount` of `from`'s shares without paying assets.
    pub fn burn(env: Env, from: Address, amount: i128) {
        from.require_auth();
        positive(&env, amount);
        burn_shares(&env, &from, amount);
    }
    /// Burn `amount` of `from`'s shares with the allowance of `spender`.
    pub fn burn_from(env: Env, spender: Address, from: Address, amount: i128) {
        spender.require_auth();
        positive(&env, amount);
        spend_allowance(&env, &from, &spender, amount);
        burn_shares(&env, &from, amount);
    }
}

impl AllowitSep56PricedTestVault {
    /// The assets that the vault holds.
    fn held(env: &Env) -> i128 {
        let asset: Address = get(env, &Key::Asset);
        token::Client::new(env, &asset).balance(&env.current_contract_address())
    }
    /// Take `assets` from `from` into the vault: one `transfer(from, vault, assets)` when the
    /// operator is `from`, the exact call that a policy wallet authorizes; otherwise one
    /// `transfer_from` with the operator's allowance.
    fn take(env: &Env, operator: &Address, from: &Address, assets: i128) {
        let asset: Address = get(env, &Key::Asset);
        let client = token::Client::new(env, &asset);
        let vault = env.current_contract_address();
        if operator == from {
            client.transfer(from, &vault, &assets);
        } else {
            client.transfer_from(operator, from, &vault, &assets);
        }
    }
    /// Pay `assets` from the vault to `receiver`.
    fn pay(env: &Env, receiver: &Address, assets: i128) {
        let asset: Address = get(env, &Key::Asset);
        token::Client::new(env, &asset).transfer(
            &env.current_contract_address(),
            receiver,
            &assets,
        );
    }
}

#[cfg(test)]
mod tests;
