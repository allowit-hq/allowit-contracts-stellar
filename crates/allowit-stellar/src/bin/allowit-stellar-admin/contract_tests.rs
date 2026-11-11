//! Guards of contract administration. `tests/fixtures/contract_admin_vectors.json` records what
//! the Python command line `scripts/contract_admin.py` returned at revision `d0cf4e0` for each
//! case: argument checks, Stellar CLI commands, assembly checks and complete runs with every
//! CLI call.
use super::contract::*;
use super::{Result, public};
use base64::Engine;
use serde_json::{Map, Value, json};
use std::cell::RefCell;
use std::path::Path;

fn resolve(value: &mut Value, blobs: &[Value]) {
    match value {
        Value::Object(map) if map.len() == 1 && map.contains_key("$") => {
            *value = blobs[map["$"].as_u64().unwrap() as usize].clone();
        }
        Value::Object(map) => map.values_mut().for_each(|item| resolve(item, blobs)),
        Value::Array(items) => items.iter_mut().for_each(|item| resolve(item, blobs)),
        _ => {}
    }
}
fn vectors() -> Value {
    let mut vectors: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/contract_admin_vectors.json"
    ))
    .unwrap();
    let blobs = vectors["blobs"].as_array().unwrap().clone();
    resolve(&mut vectors, &blobs);
    vectors
}
/// The fixture files in a fresh directory. A vector names one as `@name`.
fn files(vectors: &Value) -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    for (name, data) in vectors["files"].as_object().unwrap() {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(data.as_str().unwrap())
            .unwrap();
        std::fs::write(directory.path().join(name), bytes).unwrap();
    }
    directory
}
fn real(directory: &Path, value: &str) -> String {
    match value.strip_prefix('@') {
        Some(name) => directory.join(name).to_str().unwrap().to_string(),
        None => value.to_string(),
    }
}
fn named(directory: &Path, value: &str) -> String {
    value.replace(&format!("{}/", directory.to_str().unwrap()), "@")
}
/// A command as the vectors record it: the arguments before `--`, the method and the named
/// values, each parsed as JSON when it is JSON. Argument order after `--` has no meaning.
fn normalized(directory: &Path, command: &[String]) -> Value {
    let command: Vec<String> = command.iter().map(|arg| named(directory, arg)).collect();
    let Some(at) = command.iter().position(|arg| arg == "--") else {
        return json!({"head": command, "method": null, "pairs": {}});
    };
    let mut tail = &command[at + 1..];
    let mut method = Value::Null;
    if tail.len() % 2 == 1 {
        method = json!(tail[0]);
        tail = &tail[1..];
    }
    let mut pairs = Map::new();
    for pair in tail.chunks(2) {
        let loose = serde_json::from_str(&pair[1]).unwrap_or_else(|_| json!(pair[1]));
        pairs.insert(pair[0].clone(), loose);
    }
    json!({"head": command[..at], "method": method, "pairs": pairs})
}
fn no_compile(_: &str) -> Result<()> {
    Ok(())
}
fn option(case: &Value, key: &str, directory: &Path) -> Option<String> {
    case[key].as_str().map(|text| real(directory, text))
}
fn arguments(case: &Value, directory: &Path) -> Arguments {
    Arguments {
        action: case["action"].as_str().unwrap().into(),
        network: case["network"].as_str().unwrap().into(),
        allow_mainnet: case["allow_mainnet"].as_bool().unwrap(),
        source: case["source"].as_str().unwrap().into(),
        wasm: option(case, "wasm", directory),
        wasm_hash: option(case, "wasm_hash", directory),
        engine_wasm: option(case, "engine_wasm", directory),
        owner: option(case, "owner", directory),
        config: option(case, "config", directory),
        contract: option(case, "contract", directory),
        method: option(case, "method", directory),
        family: case["family"].as_str().unwrap().into(),
        tier: option(case, "tier", directory),
        policy_source: option(case, "policy_source", directory),
        members: vec![],
        candidate_members: vec![],
        max_fee: 10_000_000,
        arguments: case["arguments"].as_str().unwrap().into(),
    }
}
/// A Stellar CLI that replays the recorded calls in order and checks each call's arguments and
/// standard input against the record.
struct Replay<'a> {
    calls: &'a [Value],
    next: RefCell<usize>,
    directory: &'a Path,
    normalize: bool,
}
impl Replay<'_> {
    fn call(&self, args: &[String], input: Option<&str>) -> Result<String> {
        let index = self.next.replace_with(|next| *next + 1);
        let call = self
            .calls
            .get(index)
            .unwrap_or_else(|| panic!("unrecorded CLI call {args:?}"));
        if self.normalize {
            assert_eq!(normalized(self.directory, args), call["args"]);
        } else {
            assert_eq!(json!(args), call["args"]);
        }
        assert_eq!(json!(input), call["stdin"], "standard input of {args:?}");
        call["stdout"]
            .as_str()
            .map(String::from)
            .ok_or_else(|| "Stellar CLI failed".to_string())
    }
    fn finish(&self, case: &Value) {
        assert_eq!(*self.next.borrow(), self.calls.len(), "CLI calls of {case}");
    }
}

#[test]
fn argument_checks_match_the_recorded_vectors() {
    let vectors = vectors();
    let cases = vectors["arguments"].as_array().unwrap();
    assert_eq!(cases.len(), 49);
    for case in cases {
        let values = public_json(case["values"].as_str().unwrap()).unwrap();
        let (method, family) = (
            case["method"].as_str().unwrap(),
            case["family"].as_str().unwrap(),
        );
        let admitted = checked_args(method, &values, family).is_ok();
        assert_eq!(admitted, case["ok"] == true, "{case}");
    }
    assert_eq!(cases.iter().filter(|case| case["ok"] == true).count(), 13);
}

#[test]
fn commands_match_the_recorded_vectors_and_never_submit() {
    let vectors = vectors();
    let directory = files(&vectors);
    let cases = vectors["commands"].as_array().unwrap();
    assert_eq!(cases.len(), 83);
    let mut prepared = 0;
    for case in cases {
        let args = arguments(&case["options"], directory.path());
        let result = command(&args, &no_compile);
        let Ok((command, warning)) = result else {
            assert!(
                case["command"].is_null(),
                "{} for {case}",
                result.unwrap_err()
            );
            continue;
        };
        assert_eq!(
            normalized(directory.path(), &command),
            case["command"],
            "{case}"
        );
        assert_eq!(json!(warning), case["warning"], "{case}");
        // Every command only builds or only reads; none can sign or send.
        let read = args.action == "read";
        assert_eq!(command.iter().any(|arg| arg == "--send=no"), read);
        assert_eq!(command.iter().any(|arg| arg == "--build-only"), !read);
        for forbidden in ["--send=yes", "--sign-with-key", "--secret-key", "--source"] {
            assert!(!command.iter().any(|arg| arg == forbidden));
        }
        prepared += 1;
    }
    assert_eq!(prepared, 24);
}

#[test]
fn assembly_admits_only_resources_fees_and_the_expected_authorization() {
    let vectors = vectors();
    let directory = files(&vectors);
    let cases = vectors["assemblies"].as_array().unwrap();
    assert_eq!(cases.len(), 47);
    let mut assembled = 0;
    for case in cases {
        let replay = Replay {
            calls: case["calls"].as_array().unwrap(),
            next: RefCell::new(0),
            directory: directory.path(),
            normalize: false,
        };
        let result = prepare_xdr(
            &|args, input| replay.call(args, input),
            case["raw"].as_str().unwrap(),
            &Assembly {
                source: case["source"].as_str().unwrap(),
                network: case["network"].as_str().unwrap(),
                now: 1000,
                max_fee: case["max_fee"].as_u64().unwrap() as u32,
                candidate: case["candidate"].as_str(),
                expected_wasm: case["expected_wasm"].as_str(),
            },
        );
        assert_eq!(
            json!(result.as_ref().ok()),
            case["output"],
            "{result:?} for {case}"
        );
        replay.finish(case);
        assembled += usize::from(result.is_ok());
    }
    assert_eq!(assembled, 9);
}

#[test]
fn complete_runs_match_the_recorded_vectors() {
    let vectors = vectors();
    let directory = files(&vectors);
    let cases = vectors["runs"].as_array().unwrap();
    assert_eq!(cases.len(), 58);
    let mut completed = 0;
    for case in cases {
        let argv: Vec<String> = case["argv"]
            .as_array()
            .unwrap()
            .iter()
            .map(|arg| real(directory.path(), arg.as_str().unwrap()))
            .collect();
        let replay = Replay {
            calls: case["calls"].as_array().unwrap(),
            next: RefCell::new(0),
            directory: directory.path(),
            normalize: true,
        };
        let get = |url: &str| -> Result<Value> {
            let account = url.rsplit('/').next().unwrap();
            assert_eq!(
                url,
                format!("https://horizon-testnet.stellar.org/accounts/{account}")
            );
            case["accounts"]
                .get(account)
                .cloned()
                .ok_or_else(|| "unknown account".to_string())
        };
        let result = parse(&argv).and_then(|args| {
            run(
                &args,
                &get,
                &|args, input| replay.call(args, input),
                &no_compile,
                1000,
            )
        });
        let Ok((output, warning)) = result else {
            assert!(
                case["stdout"].is_null(),
                "{} for {case}",
                result.unwrap_err()
            );
            replay.finish(case);
            continue;
        };
        assert_eq!(json!(output), case["stdout"], "{case}");
        assert_eq!(json!(warning), case["warning"], "{case}");
        replay.finish(case);
        completed += 1;
    }
    assert_eq!(completed, 17);
}

#[test]
fn owner_packets_pass_the_std_only_compile_of_the_offchain_server() {
    let vectors = vectors();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("policy.rs");
    let cases = vectors["compiles"].as_array().unwrap();
    assert_eq!(cases.len(), 4);
    for case in cases {
        std::fs::write(&path, case["source"].as_str().unwrap()).unwrap();
        let result = host_compile(path.to_str().unwrap());
        assert_eq!(result.is_ok(), case["ok"] == true, "{result:?} for {case}");
        if let Err(error) = result {
            assert!(error.contains("std-only compile"), "{error}");
        }
    }
    // The owner packet path of every tier runs the compile and stops on its failure.
    let failing = |_: &str| -> Result<()> { Err("std-only compile".into()) };
    std::fs::write(&path, cases[0]["source"].as_str().unwrap()).unwrap();
    let digest = allowit_stellar::hex(&allowit_stellar::hash(std::fs::read(&path).unwrap()));
    for (tier, rules, source_digest) in [
        (
            "common",
            json!(["destinations", "expires_at"]),
            "22".repeat(32),
        ),
        ("custom", json!([]), digest),
        ("simple", json!([]), "22".repeat(32)),
    ] {
        let packet = json!({"rules": rules, "source_digest": source_digest});
        let source = path.to_str();
        assert!(policy_rules(&packet, Some(tier), source, &no_compile).is_ok());
        assert!(policy_rules(&packet, Some(tier), source, &failing).is_err());
        assert!(policy_rules(&packet, None, source, &no_compile).is_err());
        assert!(policy_rules(&packet, Some(tier), None, &no_compile).is_err());
    }
}

/// `tests/fixtures/policy-source-cases.json` records the std-only compile verdict of the Core
/// Python helper for sources that the gate tests compiled. Some pass the lexical gate and fail
/// the compile, such as an address order; the compile is the second guard of an owner packet.
#[test]
fn the_std_only_compile_matches_the_recorded_policy_source_cases() {
    let cases: Vec<Value> = serde_json::from_str(include_str!(
        "../../../tests/fixtures/policy-source-cases.json"
    ))
    .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let lib = host_allowit(directory.path()).unwrap();
    let path = directory.path().join("policy.rs");
    let (mut compiled, mut refused) = (0, 0);
    for case in cases.iter().filter(|case| case["compiles"].is_boolean()) {
        std::fs::write(&path, case["source"].as_str().unwrap()).unwrap();
        let result = compile_policy(&lib, directory.path(), path.to_str().unwrap());
        assert_eq!(
            json!(result.is_ok()),
            case["compiles"],
            "{result:?} for {case}"
        );
        match result {
            Ok(()) => compiled += 1,
            Err(error) => {
                assert!(error.contains("std-only compile"), "{error}");
                refused += 1;
            }
        }
    }
    assert_eq!((compiled, refused), (17, 10));
}

#[test]
fn public_json_rejects_duplicate_keys_at_every_depth() {
    assert!(public_json(r#"{"custom":1,"other":{"a":[{"b":1}]}}"#).is_ok());
    for duplicate in [
        r#"{"custom":1,"custom":2}"#,
        r#"{"a":{"paused":true,"paused":false}}"#,
        r#"{"a":[{"b":1,"b":1}]}"#,
    ] {
        assert_eq!(
            public_json(duplicate).unwrap_err(),
            "Duplicate public JSON key"
        );
    }
    assert!(public_json("not json").is_err());
}

#[test]
fn only_the_pinned_stellar_cli_runs() {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    let stub = |name: &str, version: &str| {
        let path = directory.path().join(name);
        let script = format!(
            "#!/bin/sh\nif [ \"$1\" = --version ]; then echo '{version}'; exit 0; fi\nif [ \"$1\" = fail ]; then echo refused >&2; exit 1; fi\necho \"ran $*\"; cat\n"
        );
        std::fs::write(&path, script).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    };
    let pinned = stub("pinned", "stellar 28.1.0 (c0f4d0da)");
    let args = ["tx".to_string(), "simulate".to_string()];
    assert_eq!(
        run_cli(pinned.as_os_str(), &args, Some("input")).unwrap(),
        "ran tx simulate\ninput"
    );
    let failure = run_cli(pinned.as_os_str(), &["fail".to_string()], None);
    assert_eq!(failure.unwrap_err(), "Stellar CLI failed: refused");
    for version in [
        "stellar 28.1.1 (abc)",
        "stellar 28.1.0",
        "stellar 27.0.0 (abc)",
    ] {
        let other = stub("other", version);
        assert_eq!(
            run_cli(other.as_os_str(), &args, None).unwrap_err(),
            "Stellar CLI 28.1.0 is required"
        );
    }
    let missing = directory.path().join("missing");
    assert!(run_cli(missing.as_os_str(), &args, None).is_err());
}

#[test]
fn the_command_line_takes_only_public_values() {
    let key = |n: u8| super::tests::key(n);
    let parse_args = |args: &[&str]| parse(&args.iter().map(|a| a.to_string()).collect::<Vec<_>>());
    let invalid = "invalid-private-input-for-test";
    let seed = stellar_strkey::ed25519::PrivateKey([7; 32]).to_string();
    for input in [invalid, seed.as_str()] {
        for args in [
            vec!["read", "--source", input],
            vec!["deploy-parent", "--source", &key(1), "--member", input],
            vec!["admin", "--source", &key(1), "--candidate-member", input],
        ] {
            let error = parse_args(&args).unwrap_err();
            assert_eq!(error, super::BAD_ADDRESS);
            assert!(public(input).is_err());
        }
    }
    assert!(parse_args(&["read"]).is_err());
    for flag in ["--secret", "--seed", "--sign", "--send", "--identity"] {
        assert!(parse_args(&["read", "--source", &key(1), flag, "x"]).is_err());
    }
    for (flag, value) in [
        ("--network", "futurenet"),
        ("--family", "token"),
        ("--tier", "native"),
    ] {
        assert!(parse_args(&["read", "--source", &key(1), flag, value]).is_err());
    }
    assert!(parse_args(&["read", "--source", &key(1), "--max-fee", "-1"]).is_err());
    let parsed = parse_args(&["read", "--source", &key(1)]).unwrap();
    assert_eq!(
        (parsed.network.as_str(), parsed.max_fee),
        ("testnet", 10_000_000)
    );
}
