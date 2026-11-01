#![no_std]
//! Test-only hostile SEP-56 vault. Never use this fixture as a deployed asset vault.
use soroban_sdk::{
    Address, BytesN, ContractExecutable, Env, Symbol, Val, Vec, contract, contractevent,
    contractimpl, token,
};
#[contractevent(topics=["mint"])]
pub struct AllowitShareMint {
    #[topic]
    pub to: Address,
    pub amount: i128,
}
#[contract]
pub struct AllowitSep56TestVault;
#[contractimpl]
impl AllowitSep56TestVault {
    /// Fix the underlying asset and the hostile behavior code.
    pub fn __constructor(env: Env, asset: Address, behavior: u32) {
        env.storage().instance().set(&0u32, &asset);
        env.storage().instance().set(&1u32, &behavior);
    }
    /// The underlying asset.
    pub fn query_asset(env: Env) -> Address {
        env.storage().instance().get(&0u32).unwrap()
    }
    /// Underlying value of `shares`; behavior 11 undervalues by two, 12 destroys shares, 14
    /// reports `i128::MIN`.
    pub fn preview_redeem(env: Env, shares: i128) -> i128 {
        let behavior: u32 = env.storage().instance().get(&1u32).unwrap();
        if behavior == 12
            && let Some(receiver) = env.storage().instance().get::<_, Address>(&3u32)
        {
            env.storage().persistent().set(&receiver, &0i128);
        }
        match behavior {
            11 => shares - 2,
            14 => i128::MIN,
            _ => shares,
        }
    }
    /// Share decimals.
    pub fn decimals(_env: Env) -> u32 {
        7
    }
    /// Code that behavior 8 installs during a deposit.
    pub fn set_upgrade(env: Env, hash: BytesN<32>) {
        env.storage().instance().set(&2u32, &hash);
    }
    /// Behavior 13 makes this call from inside `deposit`, after the vault pulls the assets.
    pub fn set_callback(env: Env, contract: Address, function: Symbol, args: Vec<Val>) {
        env.storage()
            .instance()
            .set(&5u32, &(contract, function, args));
    }
    /// Share balance of `owner`.
    pub fn balance(env: Env, owner: Address) -> i128 {
        env.storage().persistent().get(&owner).unwrap_or(0)
    }
    /// Test setup only: credit `shares` to `to` without assets.
    pub fn mint_shares(env: Env, to: Address, shares: i128) {
        let before = Self::balance(env.clone(), to.clone());
        env.storage().persistent().set(&to, &(before + shares));
    }
    /// Burn `shares` of `owner` and pay as many underlying units to `receiver`, as an
    /// OpenZeppelin SEP-56 vault does with `operator.require_auth()` only. Hostile behaviors: 20
    /// also authorizes the owner in the same frame, 21 pays one unit less than it returns, 22
    /// returns one unit more than it pays, 23 burns one share more, 25 keeps a
    /// three-unit fee that `preview_redeem` does not show, 26 returns `i128::MIN`, and 13 makes
    /// the configured callback.
    pub fn redeem(
        env: Env,
        shares: i128,
        receiver: Address,
        owner: Address,
        operator: Address,
    ) -> i128 {
        operator.require_auth();
        let behavior: u32 = env.storage().instance().get(&1u32).unwrap();
        if behavior == 20 {
            owner.require_auth();
        }
        let asset: Address = env.storage().instance().get(&0u32).unwrap();
        let burned = if behavior == 23 { shares + 1 } else { shares };
        let before = Self::balance(env.clone(), owner.clone());
        env.storage().persistent().set(&owner, &(before - burned));
        let paid = match behavior {
            21 => shares - 1,
            25 => shares - 3,
            _ => shares,
        };
        token::Client::new(&env, &asset).transfer(
            &env.current_contract_address(),
            &receiver,
            &paid,
        );
        if behavior == 13 {
            let (contract, function, args): (Address, Symbol, Vec<Val>) =
                env.storage().instance().get(&5u32).unwrap();
            env.invoke_contract::<Val>(&contract, &function, args);
        }
        match behavior {
            22 => shares + 1,
            25 => shares - 3,
            26 => i128::MIN,
            _ => shares,
        }
    }
    /// Pull `assets` and mint shares, with the configured hostile behavior.
    pub fn deposit(
        env: Env,
        assets: i128,
        receiver: Address,
        from: Address,
        operator: Address,
    ) -> i128 {
        operator.require_auth();
        from.require_auth();
        let asset: Address = env.storage().instance().get(&0u32).unwrap();
        let behavior: u32 = env.storage().instance().get(&1u32).unwrap();
        let vault = env.current_contract_address();
        let token = token::Client::new(&env, &asset);
        let debit = if behavior == 3 {
            assets + 1
        } else if behavior == 4 {
            assets - 1
        } else {
            assets
        };
        token.transfer(&from, &vault, &debit);
        if behavior == 7 {
            // A second gross debit followed by a refund must fail even though net balance would match.
            token.transfer(&from, &vault, &assets);
            token.transfer(&vault, &from, &assets);
        }
        if behavior == 13 {
            // A vault can call back into the wallet, or into a token that asks the wallet to
            // authorize, while the wallet's operation runs.
            let (contract, function, args): (Address, Symbol, Vec<Val>) =
                env.storage().instance().get(&5u32).unwrap();
            env.invoke_contract::<Val>(&contract, &function, args);
        }
        if behavior == 8 {
            let hash: BytesN<32> = env.storage().instance().get(&2u32).unwrap();
            env.deployer()
                .update_current_contract(ContractExecutable::Wasm(hash));
        }
        if behavior == 5 {
            // A persistent approval must never inherit the exact deeper transfer authorization.
            token.approve(&from, &vault, &1, &1_000_000);
        }
        let shares = if behavior == 1 { assets - 1 } else { assets };
        let credit = if behavior == 2 { shares - 1 } else { shares };
        let before = Self::balance(env.clone(), receiver.clone());
        env.storage()
            .persistent()
            .set(&receiver, &(before + credit));
        AllowitShareMint {
            to: receiver.clone(),
            amount: credit,
        }
        .publish(&env);
        env.storage().instance().set(&3u32, &receiver);
        shares
    }
}
