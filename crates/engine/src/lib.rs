#![no_std]
//! Shared stateless checker. Each method runs the canonical rule on its canonical param.
//! It holds no custody, params or accounting. No policy wallet or tool here calls it.
//! `AllowitContext` carries the contract `Env`, so it is not a contract value. Each method takes
//! the other context fields and builds the context with its own `Env`.
use allowit::{AllowitContext, AllowitError, AllowitParams, AllowitRequest, AllowitValue};
use soroban_sdk::{Address, Env, Map, String, Symbol, contract, contractimpl, panic_with_error};
#[contract]
pub struct AllowitEngine;
/// Engine executable release, independent of parent administration. Version 5 takes the context
/// fields `params` (the owner's key => value params), `state` (the free-form current policy state)
/// and `request` as separate arguments, because the context carries the contract `Env`; its
/// `AllowitRequest` names general operations and carries the swap and redeem facts `token_in`,
/// `amount_in`, `token_out` and `min_out`. Its methods carry the canonical rule names, such as
/// `payment_limit` and `destinations`. Version 4 took the same arguments under the earlier rule
/// names. Version 3 took the same arguments with a request that named Stellar operations and
/// lacked those facts. It replaces the
/// release 1 ABI, `(request: EngineRequest, state: EngineState)`; release 2 was never released.
const ENGINE_VERSION: u32 = 5;
/// Contract error code of the test fixture veto. It is outside `allowit::AllowitError`.
pub const TEST_DENY: u32 = 1000;
/// Test fixture veto: every rule aborts with `TEST_DENY`. Used only to prove reference upgrades
/// change behavior.
fn vetoed(env: &Env) {
    if cfg!(feature = "test-deny") {
        panic_with_error!(env, soroban_sdk::Error::from_contract_error(TEST_DENY));
    }
}
/// Rule input with this contract's `Env`, after the test fixture veto.
fn context(
    env: Env,
    params: Map<Symbol, AllowitValue>,
    state: Map<Symbol, AllowitValue>,
    request: AllowitRequest,
) -> AllowitContext {
    vetoed(&env);
    AllowitContext {
        env,
        params: AllowitParams(params),
        state,
        request,
    }
}
#[contractimpl]
impl AllowitEngine {
    /// Read the engine executable release without changing data or requiring authorization.
    pub fn engine_version(env: Env) -> u32 {
        let _ = env;
        ENGINE_VERSION
    }
    /// Run `allowit::payment_limit(&ctx, ctx.params.get(allowit::PAYMENT_LIMIT))`; returns the headroom left for this operation.
    pub fn payment_limit(
        env: Env,
        params: Map<Symbol, AllowitValue>,
        state: Map<Symbol, AllowitValue>,
        request: AllowitRequest,
    ) -> Result<i128, AllowitError> {
        let ctx = context(env, params, state, request);
        allowit::payment_limit(&ctx, ctx.params.get(allowit::PAYMENT_LIMIT))
    }
    /// Run `allowit::lifetime_spending_limit(&ctx, ctx.params.get(allowit::LIFETIME_SPENDING_LIMIT))`; returns the cumulative expense headroom.
    pub fn lifetime_spending_limit(
        env: Env,
        params: Map<Symbol, AllowitValue>,
        state: Map<Symbol, AllowitValue>,
        request: AllowitRequest,
    ) -> Result<i128, AllowitError> {
        let ctx = context(env, params, state, request);
        allowit::lifetime_spending_limit(&ctx, ctx.params.get(allowit::LIFETIME_SPENDING_LIMIT))
    }
    /// Run `allowit::daily_spending_limit(&ctx, ctx.params.get(allowit::DAILY_SPENDING_LIMIT))`; returns the UTC-day expense headroom.
    pub fn daily_spending_limit(
        env: Env,
        params: Map<Symbol, AllowitValue>,
        state: Map<Symbol, AllowitValue>,
        request: AllowitRequest,
    ) -> Result<i128, AllowitError> {
        let ctx = context(env, params, state, request);
        allowit::daily_spending_limit(&ctx, ctx.params.get(allowit::DAILY_SPENDING_LIMIT))
    }
    /// Run `allowit::daily_volume_limit(&ctx, ctx.params.get(allowit::DAILY_VOLUME_LIMIT))`; returns the UTC-day gross headroom.
    pub fn daily_volume_limit(
        env: Env,
        params: Map<Symbol, AllowitValue>,
        state: Map<Symbol, AllowitValue>,
        request: AllowitRequest,
    ) -> Result<i128, AllowitError> {
        let ctx = context(env, params, state, request);
        allowit::daily_volume_limit(&ctx, ctx.params.get(allowit::DAILY_VOLUME_LIMIT))
    }
    /// Run `allowit::call_limit(&ctx, ctx.params.get(allowit::CALL_LIMIT))`; returns the operations left.
    pub fn call_limit(
        env: Env,
        params: Map<Symbol, AllowitValue>,
        state: Map<Symbol, AllowitValue>,
        request: AllowitRequest,
    ) -> Result<u64, AllowitError> {
        let ctx = context(env, params, state, request);
        allowit::call_limit(&ctx, ctx.params.get(allowit::CALL_LIMIT))
    }
    /// Run `allowit::destinations(&ctx, ctx.params.get(allowit::DESTINATIONS))`; returns the matched recipient.
    pub fn destinations(
        env: Env,
        params: Map<Symbol, AllowitValue>,
        state: Map<Symbol, AllowitValue>,
        request: AllowitRequest,
    ) -> Result<Address, AllowitError> {
        let ctx = context(env, params, state, request);
        allowit::destinations(&ctx, ctx.params.get(allowit::DESTINATIONS))
    }
    /// Run `allowit::tokens(&ctx, ctx.params.get(allowit::TOKENS))`; returns the matched asset.
    pub fn tokens(
        env: Env,
        params: Map<Symbol, AllowitValue>,
        state: Map<Symbol, AllowitValue>,
        request: AllowitRequest,
    ) -> Result<Address, AllowitError> {
        let ctx = context(env, params, state, request);
        allowit::tokens(&ctx, ctx.params.get(allowit::TOKENS))
    }
    /// Run `allowit::expires_at(&ctx, ctx.params.get(allowit::EXPIRES_AT))`; returns the seconds left.
    pub fn expires_at(
        env: Env,
        params: Map<Symbol, AllowitValue>,
        state: Map<Symbol, AllowitValue>,
        request: AllowitRequest,
    ) -> Result<u64, AllowitError> {
        let ctx = context(env, params, state, request);
        allowit::expires_at(&ctx, ctx.params.get(allowit::EXPIRES_AT))
    }
    /// Run `allowit::operations(&ctx, ctx.params.get(allowit::OPERATIONS))`; returns the request's op name.
    pub fn operations(
        env: Env,
        params: Map<Symbol, AllowitValue>,
        state: Map<Symbol, AllowitValue>,
        request: AllowitRequest,
    ) -> Result<String, AllowitError> {
        let ctx = context(env.clone(), params, state, request);
        let op = allowit::operations(&ctx, ctx.params.get(allowit::OPERATIONS))?;
        Ok(String::from_str(&env, op))
    }
}
#[cfg(test)]
mod tests;
