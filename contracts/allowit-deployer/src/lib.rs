#![no_std]
//! One owner signature creates a policy wallet and funds it.
//!
//! The deployer holds no state, no funds and no authority. The owner's authorization of `deploy`
//! covers the whole tree: the creation of the wallet at the owner's own address and salt, with the
//! exact code hash and constructor arguments, the wallet constructor's owner check and every
//! transfer from the owner into the wallet. A contract holds any Stellar asset with no trustline.
//! The wallet's address is the address of the owner's own creation: it depends on the owner and
//! the salt only.
use soroban_sdk::{
    Address, BytesN, ContractExecutable, Env, Val, Vec, contract, contractimpl, token,
};

#[contract]
pub struct AllowitDeployer;

#[contractimpl]
impl AllowitDeployer {
    /// Create the wallet of `wasm_hash` at the owner's address and `salt` with `constructor_args`,
    /// then move each `(asset, amount)` of `funding` from the owner into it. Returns the wallet.
    pub fn deploy(
        env: Env,
        owner: Address,
        wasm_hash: BytesN<32>,
        salt: BytesN<32>,
        constructor_args: Vec<Val>,
        funding: Vec<(Address, i128)>,
    ) -> Address {
        owner.require_auth();
        let wallet = env
            .deployer()
            .with_address(owner.clone(), salt)
            .deploy_contract(ContractExecutable::Wasm(wasm_hash), constructor_args);
        for (asset, amount) in funding.iter() {
            token::Client::new(&env, &asset).transfer(&owner, &wallet, &amount);
        }
        wallet
    }
}

#[cfg(test)]
mod tests;
