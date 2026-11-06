//! Deterministic portable approval fixture. No private key or signing seed is exported.
use allowit_stellar_wallet::provider::runtime::approval::approval_for_policy;
fn main() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../tests/fixtures/provider/stellar-portable-approval.json"
    ))
    .unwrap();
    let policy = &fixture["policy"];
    let expected = &fixture["intent"];
    let intent = approval_for_policy(
        policy,
        expected["owner"].as_str().unwrap(),
        expected["requestId"].as_str().unwrap(),
    )
    .unwrap();
    assert_eq!(serde_json::to_value(&intent).unwrap(), *expected);
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({"policy":policy,"intent":intent}))
            .unwrap()
    );
}
