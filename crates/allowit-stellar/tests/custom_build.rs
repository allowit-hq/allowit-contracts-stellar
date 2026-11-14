//! The build of the Custom wallet Wasm from a policy source. These tests run the Stellar CLI and
//! the Rust toolchain and fetch crates, so they are ignored by default:
//!
//!   cargo test --locked --manifest-path crates/allowit-stellar/Cargo.toml --test custom_build -- --ignored
use allowit_core::vendor::{
    custom_build::{attest, check_code_hash, code, presign},
    plugin::RailPlugin,
    wallet::Signer,
};
use allowit_stellar::{plugin::PLUGIN, signing::LocalSigner};

const NETWORK: &str = "stellar:testnet";
const SOURCE: &str = include_str!("../../../contracts/allowit-custom-policy/policy/policy.rs");

struct Key(LocalSigner);
impl Signer for Key {
    fn network(&self) -> &str {
        NETWORK
    }
    fn address(&self) -> &str {
        self.0.account()
    }
    fn sign_hash(&self, digest: &[u8]) -> allowit_core::client::error::Result<Vec<u8>> {
        self.0
            .sign_digest(digest)
            .map_err(allowit_core::client::error::Error::config)
    }
}

#[test]
#[ignore = "runs the Stellar CLI and fetches crates"]
fn the_same_source_builds_the_same_code_and_altered_source_builds_other_code() {
    let hook = PLUGIN.custom_wallet_build().unwrap();
    let work = tempfile::tempdir().unwrap();
    let first = hook.build(NETWORK, SOURCE, &work.path().join("a")).unwrap();
    // Another folder and a warm compiler cache give the same Wasm.
    let again = hook.build(NETWORK, SOURCE, &work.path().join("b")).unwrap();
    assert_eq!(first.code, again.code);
    assert_eq!(
        hook.code_hash(NETWORK, &first.code).unwrap(),
        first.code_hash
    );
    assert!(
        first.toolchain.starts_with("stellar 28.1.0"),
        "{}",
        first.toolchain
    );
    // `scripts/build-custom-policy.sh` builds the same Wasm from a checkout of this revision.
    if let Ok(expected) = std::env::var("ALLOWIT_EXPECTED_CUSTOM_WASM_HASH") {
        assert_eq!(
            allowit_core::vendor::custom_build::hex(&first.code_hash),
            expected
        );
    }
    // The owner attests the code of the admitted source. A build from altered source has
    // another hash, so it is not the attested code.
    let server = Key(LocalSigner::from_entropy(&[1; 32]).unwrap());
    let owner = Key(LocalSigner::from_entropy(&[2; 32]).unwrap());
    let presignature = presign(hook, &server, NETWORK, "policy-1", SOURCE).unwrap();
    let attestation = attest(hook, &owner, &presignature, &first.code_hash).unwrap();
    let altered = SOURCE.replace("pub fn execute", "/// Altered.\npub fn execute");
    assert_ne!(altered, SOURCE);
    let other = hook
        .build(NETWORK, &altered, &work.path().join("a"))
        .unwrap();
    assert_ne!(other.code_hash, first.code_hash);
    let error = check_code_hash(&attestation, &other.code_hash).unwrap_err();
    assert_eq!(error.api_code.as_deref(), Some(code::CODE_HASH_MISMATCH));
}
