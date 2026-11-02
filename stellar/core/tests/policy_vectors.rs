//! Native owner-param vectors and binding integration with the shared Core source gate.
use allowit_stellar_wallet::PolicyTier;
use allowit_stellar_wallet::policy::params_from_json;
use serde_json::Value;

const CANONICAL: &str = include_str!("../../../crates/custom-policy/policy/policy.rs");

fn vectors(text: &str) -> Vec<Value> {
    serde_json::from_str(text).expect("vector file is JSON")
}

#[test]
fn params_from_json_matches_contract_admin_params() {
    let vectors = vectors(include_str!("fixtures/params-vectors.json"));
    assert!(vectors.len() > 1000);
    for v in &vectors {
        let tier = match v["tier"].as_str() {
            None => None,
            Some("simple") => Some(PolicyTier::Simple),
            Some("common") => Some(PolicyTier::Common),
            Some("custom") => Some(PolicyTier::Custom),
            Some(other) => panic!("unknown tier {other}"),
        };
        let result = params_from_json(&v["input"], tier);
        match (&v["params"], result) {
            (Value::Null, Ok(params)) => panic!(
                "Python rejects ({}), Rust accepts {params:?}: {}",
                v["error"], v["input"]
            ),
            (Value::Null, Err(_)) => {}
            (expected, Ok(params)) => {
                assert_eq!(
                    &serde_json::to_value(&params).unwrap(),
                    expected,
                    "{}",
                    v["input"]
                );
            }
            (_, Err(error)) => panic!("Python accepts, Rust rejects: {error}: {}", v["input"]),
        }
    }
}

#[test]
fn owner_builders_reject_sources_the_python_gate_rejects() {
    // Every owner builder binds its source through `policy_rules` and `tier_rules`, so a source
    // the server build gate can never compile cannot reach a create or deploy packet.
    use allowit_stellar_wallet::policy::{PolicyParams, policy_rules, tier_rules};
    for extra in [
        "use std::fs;",
        "fn helper(a: &[i128]) -> bool { a.len() > 0 }",
    ] {
        let source = format!("{CANONICAL}\n{extra}\n");
        for tier in [PolicyTier::Simple, PolicyTier::Common, PolicyTier::Custom] {
            assert!(tier_rules(tier, &source).is_err(), "{tier:?} {extra}");
            let digest = [0; 32];
            let check = policy_rules(tier, &source, &[], &digest, &PolicyParams::default());
            assert!(check.is_err(), "{tier:?} {extra}");
        }
    }
}
