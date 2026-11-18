#![no_std]
//! Bespoke policy compiled verbatim from `policy/policy.rs` into the shared custody mixins.
use allowit::{AllowitContext, AllowitOperation, AllowitRule};
use allowit_policy_wallet::{AllowitPolicy, AllowitStateKey, AllowitWalletError};
use soroban_sdk::{BytesN, Env, Vec};

/// Authored policy source, compiled unchanged as a module. The offchain server compiles the same file.
#[cfg(not(any(feature = "test-catching", feature = "test-daily")))]
#[path = "../policy/policy.rs"]
mod policy;
/// Test fixture only: a policy that catches a rule error, continues and writes its own state.
#[cfg(feature = "test-catching")]
#[path = "catching_policy.rs"]
mod policy;
/// Test fixture only: a policy with one daily state entry.
#[cfg(feature = "test-daily")]
#[path = "daily_policy.rs"]
mod policy;

/// SHA-256 of the owner's full policy source, computed by `build.rs`.
pub const SOURCE_HASH: [u8; 32] = include!(concat!(env!("OUT_DIR"), "/source_hash.rs"));
/// The figures that the compiled policy's checks read, found by `build.rs`.
pub const FIGURES: u8 = include!(concat!(env!("OUT_DIR"), "/figures.rs"));
/// The policy's own state entries, declared by `build.rs` from its `get_state` and `set_state`
/// calls.
pub const STATE: &[AllowitStateKey] = include!(concat!(env!("OUT_DIR"), "/state.rs"));

/// The bespoke policy tier: its compiled source decides every operation.
pub struct AllowitCustom;
impl AllowitPolicy for AllowitCustom {
    const KIND: &'static str = "custom_policy";
    /// Every native operation. The compiled policy's `operations` rule selects among them.
    const OPERATIONS: &'static [AllowitOperation] = &[
        AllowitOperation::transfer,
        AllowitOperation::swap,
        AllowitOperation::deposit,
        AllowitOperation::redeem,
    ];
    const FIGURES: Option<u8> = Some(FIGURES);
    const STATE: &'static [AllowitStateKey] = STATE;
    /// The hash of the owner's full policy source.
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
