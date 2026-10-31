//! Replay the vectors that `scripts/policy-core-vectors.py` records from the Python admin tools.
//! The Rust source gate and `params_from_json` must decide exactly as `policy_source.py` and
//! `contract_admin.py` do, so an owner packet that one side accepts the other side accepts too.
use allowit_stellar_wallet::PolicyTier;
use allowit_stellar_wallet::policy::{params_from_json, source_shape};
use serde_json::Value;

const CANONICAL: &str = include_str!("../../../crates/custom-policy/policy/policy.rs");

fn vectors(text: &str) -> Vec<Value> {
    serde_json::from_str(text).expect("vector file is JSON")
}

#[test]
fn source_gate_matches_policy_source_py() {
    let vectors = vectors(include_str!("fixtures/policy-gate-vectors.json"));
    assert!(vectors.len() > 300);
    let mut accepted = 0;
    for v in &vectors {
        let head = v["head"].as_u64().unwrap() as usize;
        let tail = v["tail"].as_u64().unwrap() as usize;
        let source = format!(
            "{}{}{}",
            &CANONICAL[..head],
            v["middle"].as_str().unwrap(),
            &CANONICAL[CANONICAL.len() - tail..]
        );
        let shape = source_shape(&source);
        if v["accepted"].as_bool().unwrap() {
            accepted += 1;
            let shape =
                shape.unwrap_or_else(|e| panic!("Python accepts, Rust rejects: {e}\n{source}"));
            let prefix: Vec<String> = serde_json::from_value(v["prefix"].clone()).unwrap();
            assert_eq!(shape.prefix, prefix, "{source}");
            assert_eq!(
                shape.writes_state,
                v["writes_state"].as_bool().unwrap(),
                "{source}"
            );
        } else {
            assert!(
                shape.is_err(),
                "Python rejects ({}), Rust accepts:\n{source}",
                v["error"]
            );
        }
    }
    assert!(accepted > 100 && accepted < vectors.len());
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
