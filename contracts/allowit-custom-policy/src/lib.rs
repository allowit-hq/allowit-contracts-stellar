#![no_std]
//! The on-chain part of the owner's policy, compiled verbatim from `policy/policy.rs`. See `build.rs`.
use allowit::{AllowitContext, AllowitOperation, AllowitRule};
use allowit_policy_wallet::{AllowitPolicy, AllowitWalletError};
use soroban_sdk::{BytesN, Env, Vec};

/// The on-chain part of the authored policy, compiled unchanged. The server evaluates the whole source.
#[cfg(not(feature = "test-catching"))]
#[path = "../policy/policy.rs"]
mod policy;
/// Test fixture only: a policy that catches a rule error, continues and writes its own state.
#[cfg(feature = "test-catching")]
#[path = "catching_policy.rs"]
mod policy;

/// SHA-256 of the exact bytes of the owner's policy source, computed by `build.rs`.
pub const SOURCE_HASH: [u8; 32] = include!(concat!(env!("OUT_DIR"), "/source_hash.rs"));

/// The bespoke policy tier: its compiled source decides every operation.
pub struct AllowitCustom;
impl AllowitPolicy for AllowitCustom {
    const KIND: &'static str = "custom_policy";
    /// Transfers, router swaps and SEP-56 redeems; no deposits. The compiled policy's `operations`
    /// rule selects among them.
    const OPERATIONS: &'static [AllowitOperation] = &[
        AllowitOperation::transfer,
        AllowitOperation::swap,
        AllowitOperation::redeem,
    ];
    /// The digest of the owner's policy source.
    fn source_digest(env: &Env) -> Option<BytesN<32>> {
        Some(BytesN::from_array(env, &SOURCE_HASH))
    }
    /// Run the complete authored policy. Only an error it returns denies. A rule denial fails the
    /// call with the policy's own `AllowitError` code, so the caller learns which rule denied; the
    /// standard tiers report `PolicyDenied`. Invalid configuration, state, overflow and an
    /// unsupported function keep their wallet codes.
    fn check(ctx: &AllowitContext, _rules: &Vec<AllowitRule>) -> Result<(), AllowitWalletError> {
        let Err(error) = policy::execute(ctx) else {
            return Ok(());
        };
        match AllowitWalletError::from(error) {
            AllowitWalletError::PolicyDenied => ctx.env.panic_with_error(error),
            other => Err(other),
        }
    }
}
allowit_policy_wallet::policy_wallet!(AllowitCustomPolicy, AllowitCustom);
