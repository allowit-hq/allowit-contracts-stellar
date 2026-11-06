#![no_std]
//! Bespoke policy compiled verbatim from `policy/policy.rs` into the shared custody mixins.
use allowit::{AllowitContext, AllowitOperation, AllowitRule};
use allowit_policy_wallet::{AllowitPolicy, AllowitWalletError};
use soroban_sdk::{BytesN, Env, Vec};

/// Authored policy source, compiled unchanged as a module. The offchain server compiles the same file.
#[cfg(not(feature = "test-catching"))]
#[path = "../policy/policy.rs"]
mod policy;
/// Test fixture only: a policy that catches a rule error, continues and writes its own state.
#[cfg(feature = "test-catching")]
#[path = "catching_policy.rs"]
mod policy;

/// SHA-256 of the exact bytes of the compiled policy source, computed by `build.rs`.
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
    /// The digest of the compiled policy source.
    fn source_digest(env: &Env) -> Option<BytesN<32>> {
        Some(BytesN::from_array(env, &SOURCE_HASH))
    }
    /// Run the complete authored policy. Only an error it returns denies.
    fn check(ctx: &AllowitContext, _rules: &Vec<AllowitRule>) -> Result<(), AllowitWalletError> {
        Ok(policy::execute(ctx)?)
    }
}
allowit_policy_wallet::policy_wallet!(AllowitCustomPolicy, AllowitCustom);
