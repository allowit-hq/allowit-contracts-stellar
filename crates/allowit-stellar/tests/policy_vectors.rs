//! Native owner-param vectors and binding integration with the shared Core source gate.
use allowit_stellar::PolicyTier;
use allowit_stellar::policy::params_from_json;
use serde_json::Value;

const CANONICAL: &str = include_str!("../../../contracts/allowit-custom-policy/policy/policy.rs");

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
    use allowit_stellar::policy::{PolicyParams, policy_rules, tier_rules};
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

/// `fixtures/policy-source-cases.json` records the verdict of the Core Python gate
/// (`scripts/policy_source.py` at Core `22aa2b6`) for each source of this repository's earlier
/// gate tests: rebinding `allowit`, a file that is not self-contained, code that diverges between
/// backends, pointer-width, layout, closure and function-value probes, macro placeholders,
/// param and arg reads outside their context fields, and prefix derivation through comments and
/// literals. The Rust gate that owner builders and the admin binary use gives the same verdict,
/// prefix and state-write flag.
#[test]
fn source_gate_matches_the_recorded_policy_source_cases() {
    use allowit_stellar::policy::source_shape;
    let cases = vectors(include_str!("fixtures/policy-source-cases.json"));
    assert_eq!(cases.len(), 393);
    let (mut accepted, mut writers) = (0, 0);
    for case in &cases {
        let source = case["source"].as_str().unwrap();
        match (case["accepted"].as_bool().unwrap(), source_shape(source)) {
            (true, Ok(shape)) => {
                let prefix: Vec<String> = serde_json::from_value(case["prefix"].clone()).unwrap();
                assert_eq!(shape.prefix, prefix, "{source}");
                assert_eq!(case["writes_state"], shape.writes_state, "{source}");
                accepted += 1;
                writers += usize::from(shape.writes_state);
            }
            (false, Err(_)) => {}
            (true, Err(error)) => panic!("Python accepts, Rust rejects: {error}: {source}"),
            (false, Ok(_)) => panic!("Python rejects, Rust accepts: {source}"),
        }
    }
    assert_eq!(accepted, 36);
    assert!(writers > 0);
}
