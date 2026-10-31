#![no_std]
//! Bespoke policy compiled verbatim from `policy/policy.rs` into the shared custody mixins.
use allowit::{AllowitContext, AllowitRule};
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
/// The native operations this policy admits, enforced through their schema hashes. The compiled
/// policy's `operations` rule selects among them.
pub const ADMITTED_OPERATIONS: [&str; 3] = [
    "stellar::sep41_transfer",
    "stellar::router_swap_exact_in",
    "stellar::sep56_redeem",
];
/// SHA-256 of the default SEP-41 transfer argument schema descriptor.
pub const ARGUMENT_SCHEMA_HASH: [u8; 32] = [
    216, 0, 105, 227, 91, 242, 126, 112, 2, 254, 161, 21, 191, 170, 167, 44, 147, 71, 240, 150,
    126, 226, 36, 246, 86, 136, 223, 200, 250, 20, 126, 139,
];
/// SHA-256 of the admitted router swap argument schema descriptor.
pub const SWAP_SCHEMA_HASH: [u8; 32] = [
    239, 93, 217, 8, 25, 175, 69, 191, 45, 85, 182, 32, 203, 219, 162, 236, 84, 207, 48, 193, 137,
    86, 126, 64, 110, 201, 246, 190, 236, 245, 221, 247,
];
/// SHA-256 of the admitted SEP-56 redeem argument schema descriptor.
pub const REDEEM_SCHEMA_HASH: [u8; 32] = [
    206, 99, 14, 28, 97, 209, 2, 119, 174, 153, 2, 202, 112, 159, 93, 50, 109, 48, 46, 128, 190, 1,
    15, 188, 101, 160, 37, 234, 127, 21, 38, 97,
];

pub struct AllowitCustom;
impl AllowitPolicy for AllowitCustom {
    const KIND: &'static str = "custom_policy";
    /// The digest of the compiled policy source.
    fn source_digest(env: &Env) -> Option<BytesN<32>> {
        Some(BytesN::from_array(env, &SOURCE_HASH))
    }
    /// Transfers by default.
    fn argument_schema_digest(env: &Env) -> BytesN<32> {
        BytesN::from_array(env, &ARGUMENT_SCHEMA_HASH)
    }
    /// Transfers, router swaps and SEP-56 redeems; no deposits.
    fn admits_schema(env: &Env, digest: &BytesN<32>) -> bool {
        [ARGUMENT_SCHEMA_HASH, SWAP_SCHEMA_HASH, REDEEM_SCHEMA_HASH]
            .iter()
            .any(|hash| *digest == BytesN::from_array(env, hash))
    }
    /// Run the complete authored policy. Only an error it returns denies.
    fn check(ctx: &AllowitContext, _rules: &Vec<AllowitRule>) -> Result<(), AllowitWalletError> {
        Ok(policy::execute(ctx)?)
    }
}
allowit_policy_wallet::policy_wallet!(AllowitCustomPolicy, AllowitCustom);

#[cfg(test)]
mod tests;
