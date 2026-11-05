//! Public deterministic approval fixture. No test seed is exported.
use allowit_stellar_wallet as stellar;
use allowit_stellar_wallet::provider::runtime::approval::approval_for_policy;
use sha2::{Digest, Sha256};
fn main() {
    let source =
        "use allowit::v1::prelude::*; async fn _execute(ctx: &Context) -> PolicyResult { Ok(()) }";
    let source_hash = Sha256::digest(source)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let asset = stellar::sac_address("stellar:testnet", &stellar_xdr::Asset::Native).unwrap();
    let owner = stellar::account_for_seed(&[1; 32]);
    let policy = serde_json::json!({"id":"existing-native-policy","revision":1,"network":"stellar:testnet","code":source,"sourceHash":source_hash,"irHash":"05".repeat(32),"mint":asset,"token":"XLM","runtime":{"wallet":{"profile":"allowit-stellar-native-v1"},"instanceBinding":{"wallet":owner,"route":"native","policyInstance":"07".repeat(32),"moduleDigest":"05".repeat(32),"asset":asset,"assetSymbol":"XLM","assetIssuer":null,"maxFeeStroops":100,"deploymentId":"09".repeat(32)}}});
    let intent = approval_for_policy(&policy, &owner, "stellar-approval-001").unwrap();
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({"policy":policy,"intent":intent}))
            .unwrap()
    );
}
