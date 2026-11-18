//! Guards of contract administration. `tests/fixtures/contract_admin_vectors.json` records what
//! the Python module `scripts/contract_admin.py` returns for each case: argument checks and
//! Stellar CLI commands (re-recorded for the wallet ABI of custody layout 5), assembly checks
//! and complete runs of uploads and of the parent family with every CLI call (recorded at
//! revision `d0cf4e0`). The wallet runs are the tests at the end of this file.
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
    assert_eq!(cases.iter().filter(|case| case["ok"] == true).count(), 12);
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
    assert_eq!(prepared, 27);
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
    assert_eq!(cases.len(), 19);
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
    assert_eq!(completed, 5);
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
    for (tier, rules) in [
        ("common", json!(["destinations", "expires_at"])),
        ("custom", json!([])),
        ("simple", json!([])),
    ] {
        // Every tier stores the SHA-256 of the whole source.
        let packet = json!({"rules": rules, "source_hash": digest});
        assert!(
            policy_rules(
                &json!({"rules": rules, "source_hash": "22".repeat(32)}),
                Some(tier),
                path.to_str(),
                &no_compile
            )
            .is_err()
        );
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

/// A Stellar CLI and RPC for a policy wallet of layout 5: it reads the wallet's `state` view,
/// builds the exact invocation or creation of the named arguments, and simulates it with the
/// owner's source authorization, and a new owner's address authorization, as the pinned CLI and
/// RPC record them.
struct WalletCli {
    state: Value,
    candidate: Option<String>,
    calls: RefCell<Vec<Vec<String>>>,
}
impl WalletCli {
    fn new(state: Value) -> Self {
        Self {
            state,
            candidate: None,
            calls: RefCell::new(vec![]),
        }
    }
    fn call(&self, args: &[String], input: Option<&str>) -> Result<String> {
        self.calls.borrow_mut().push(args.to_vec());
        if args.iter().any(|arg| arg == "--send=no") {
            assert_eq!(args.last().map(String::as_str), Some("state"));
            return Ok(self.state.to_string());
        }
        if args[..2] == ["tx", "simulate"] {
            return self.simulate(input.unwrap());
        }
        self.build(args)
    }
    fn build(&self, args: &[String]) -> Result<String> {
        use stellar_xdr::*;
        let at = |flag: &str| args[args.iter().position(|arg| arg == flag).unwrap() + 1].clone();
        let source = at("--source-account");
        let tail = &args[args.iter().position(|arg| arg == "--").unwrap() + 1..];
        let named = |flag: &str| {
            tail.iter()
                .position(|arg| arg == flag)
                .map(|i| tail[i + 1].clone())
                .unwrap()
        };
        let update = |text: &str| -> ScVal {
            let u: serde_json::Value = serde_json::from_str(text).unwrap();
            let raw = |role: &str| {
                allowit_stellar::account_for_public_key(
                    &allowit_stellar::unhex::<32>(u[role].as_str().unwrap()).unwrap(),
                )
            };
            let rules: Vec<String> = serde_json::from_value(u["rules"].clone()).unwrap();
            let params = serde_json::from_value(u["params"].clone()).unwrap();
            let source_hash =
                allowit_stellar::unhex::<32>(u["source_hash"].as_str().unwrap()).unwrap();
            let gas_cap = u["gas_cap"].as_str().unwrap().parse().unwrap();
            if u.get("asset").is_some() {
                return allowit_stellar::contract::policy_config(
                    allowit_stellar::contract::PolicyConfig {
                        owner: u["owner"].as_str().unwrap(),
                        agent: &raw("agent"),
                        server: &raw("server"),
                        asset: u["asset"].as_str().unwrap(),
                        source_hash: &source_hash,
                        gas_cap,
                        rules: &rules,
                        params: &params,
                    },
                )
                .unwrap();
            }
            let wasm = u["wasm_hash"]
                .as_str()
                .map(|h| allowit_stellar::unhex::<32>(h).unwrap());
            allowit_stellar::contract::policy_update(allowit_stellar::contract::PolicyUpdate {
                deployment_version: u["deployment_version"].as_u64().unwrap() as u32,
                owner: u["owner"].as_str().unwrap(),
                agent: &raw("agent"),
                server: &raw("server"),
                source_hash: &source_hash,
                gas_cap,
                rules: &rules,
                params: &params,
                wasm_hash: wasm.as_ref(),
            })
            .unwrap()
        };
        let address = |text: &str| allowit_stellar::address(text).unwrap();
        let host_function = if args[1] == "deploy" {
            let wasm = std::fs::read(at("--wasm")).unwrap();
            HostFunction::CreateContractV2(CreateContractArgsV2 {
                contract_id_preimage: ContractIdPreimage::Address(ContractIdPreimageFromAddress {
                    address: address(&source),
                    salt: Uint256([5; 32]),
                }),
                executable: ContractExecutable::Wasm(Hash(allowit_stellar::hash(&wasm))),
                constructor_args: vec![update(&named("--config"))].try_into().unwrap(),
            })
        } else {
            let method = tail[0].clone();
            let call_args = match method.as_str() {
                "set_pause" => vec![
                    ScVal::Bool(named("--paused") == "true"),
                    ScVal::U32(named("--deployment-version").parse().unwrap()),
                ],
                "stop" => vec![ScVal::U32(named("--deployment-version").parse().unwrap())],
                "recover" => vec![
                    ScVal::Address(address(&named("--token"))),
                    ScVal::Address(address(&named("--recipient"))),
                    {
                        let amount: i128 = named("--amount").parse().unwrap();
                        ScVal::I128(Int128Parts {
                            hi: (amount >> 64) as i64,
                            lo: amount as u64,
                        })
                    },
                ],
                "deploy_policy" => vec![update(&named("--update"))],
                other => panic!("unexpected method {other}"),
            };
            HostFunction::InvokeContract(InvokeContractArgs {
                contract_address: address(&at("--id")),
                function_name: ScSymbol(method.as_bytes().to_vec().try_into().unwrap()),
                args: call_args.try_into().unwrap(),
            })
        };
        let tx = Transaction {
            source_account: MuxedAccount::Ed25519(Uint256(public(&source).unwrap())),
            fee: 100,
            seq_num: SequenceNumber(43),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: vec![Operation {
                source_account: None,
                body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                    host_function,
                    auth: VecM::default(),
                }),
            }]
            .try_into()
            .unwrap(),
            ext: TransactionExt::V0,
        };
        allowit_stellar::xdr(&TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: VecM::default(),
        }))
    }
    fn simulate(&self, input: &str) -> Result<String> {
        use stellar_xdr::*;
        let TransactionEnvelope::Tx(mut envelope) = allowit_stellar::read(input).unwrap() else {
            panic!()
        };
        let mut operations = envelope.tx.operations.to_vec();
        let OperationBody::InvokeHostFunction(op) = &mut operations[0].body else {
            panic!()
        };
        let root = match &op.host_function {
            HostFunction::InvokeContract(call) => SorobanAuthorizedInvocation {
                function: SorobanAuthorizedFunction::ContractFn(call.clone()),
                sub_invocations: VecM::default(),
            },
            HostFunction::CreateContractV2(create) => {
                let wallet = admin_wallet(create);
                SorobanAuthorizedInvocation {
                    function: SorobanAuthorizedFunction::CreateContractV2HostFn(create.clone()),
                    sub_invocations: vec![SorobanAuthorizedInvocation {
                        function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                            contract_address: allowit_stellar::address(&wallet).unwrap(),
                            function_name: ScSymbol(b"__constructor".to_vec().try_into().unwrap()),
                            args: create.constructor_args.clone(),
                        }),
                        sub_invocations: VecM::default(),
                    }]
                    .try_into()
                    .unwrap(),
                }
            }
            _ => panic!(),
        };
        let mut auth = vec![SorobanAuthorizationEntry {
            credentials: SorobanCredentials::SourceAccount,
            root_invocation: root.clone(),
        }];
        if let Some(candidate) = &self.candidate {
            auth.push(SorobanAuthorizationEntry {
                credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                    address: allowit_stellar::address(candidate).unwrap(),
                    nonce: 7,
                    signature_expiration_ledger: 0,
                    signature: ScVal::Void,
                }),
                root_invocation: root,
            });
        }
        op.auth = auth.try_into().unwrap();
        envelope.tx.operations = operations.try_into().unwrap();
        envelope.tx.ext = TransactionExt::V1(SorobanTransactionData {
            resource_fee: 1000,
            ..Default::default()
        });
        envelope.tx.fee += 1000;
        allowit_stellar::xdr(&TransactionEnvelope::Tx(envelope))
    }
}
/// The wallet that a creation's preimage derives on Testnet.
fn admin_wallet(create: &stellar_xdr::CreateContractArgsV2) -> String {
    let stellar_xdr::ContractIdPreimage::Address(from) = &create.contract_id_preimage else {
        panic!()
    };
    allowit_stellar::admin::wallet_address(
        "stellar:testnet",
        &allowit_stellar::address_text(&from.address).unwrap(),
        &from.salt.0,
    )
    .unwrap()
}
const WALLET: &str = "CAEQSCIJBEEQSCIJBEEQSCIJBEEQSCIJBEEQSCIJBEEQSCIJBEEQTD2L";
const COMMON: &str = "use allowit::prelude::*;\npub fn execute(ctx: &AllowitContext) -> allowit::Result {\n    allowit::destinations(ctx, &ctx.params[allowit::DESTINATIONS])?;\n    allowit::expires_at(ctx, &ctx.params[allowit::EXPIRES_AT])?;\n    Ok(())\n}\n";
fn owner_account(account: &str) -> Value {
    json!({"account_id": account, "sequence": "42",
        "signers": [{"key": account, "weight": 1, "type": "ed25519_public_key"}],
        "thresholds": {"low_threshold": 0, "med_threshold": 0, "high_threshold": 0}})
}
/// One run of `argv` against `cli`, with every named account an owner-only account.
fn wallet_run(cli: &WalletCli, argv: &[String]) -> Result<String> {
    let get = |url: &str| -> Result<Value> { Ok(owner_account(url.rsplit('/').next().unwrap())) };
    let args = parse(argv)?;
    run(&args, &get, &|a, i| cli.call(a, i), &no_compile, 1000).map(|(out, _)| out)
}
fn assembled_auth(output: &str) -> Vec<stellar_xdr::SorobanAuthorizationEntry> {
    let stellar_xdr::TransactionEnvelope::Tx(envelope) = allowit_stellar::read(output).unwrap()
    else {
        panic!()
    };
    let stellar_xdr::OperationBody::InvokeHostFunction(op) = &envelope.tx.operations[0].body else {
        panic!()
    };
    op.auth.to_vec()
}

#[test]
fn the_owner_pauses_stops_and_recovers_a_wallet_at_its_next_version() {
    let owner = super::tests::key(1);
    let argv = |method: &str, arguments: Value, source: &str| -> Vec<String> {
        [
            "admin",
            "--contract",
            WALLET,
            "--method",
            method,
            "--arguments",
            &arguments.to_string(),
            "--source",
            source,
        ]
        .map(String::from)
        .to_vec()
    };
    let state = json!({"owner": owner, "deployment_version": 2, "contract_version": 5});
    for (method, arguments) in [
        (
            "set_pause",
            json!({"paused": true, "deployment_version": 3}),
        ),
        ("stop", json!({"deployment_version": 3})),
    ] {
        let cli = WalletCli::new(state.clone());
        let output = wallet_run(&cli, &argv(method, arguments.clone(), &owner)).unwrap();
        // The state read, the build and the simulation; only the owner authorizes.
        assert_eq!(cli.calls.borrow().len(), 3, "{method}");
        let auth = assembled_auth(&output);
        assert_eq!(auth.len(), 1);
        assert_eq!(
            auth[0].credentials,
            stellar_xdr::SorobanCredentials::SourceAccount
        );
        // Another version than the next one, or another source than the owner, prepares nothing.
        let mut stale = arguments.clone();
        stale["deployment_version"] = json!(4);
        assert!(wallet_run(&WalletCli::new(state.clone()), &argv(method, stale, &owner)).is_err());
        let other = super::tests::key(9);
        assert!(
            wallet_run(
                &WalletCli::new(state.clone()),
                &argv(method, arguments, &other)
            )
            .unwrap_err()
            .contains("current owner")
        );
    }
    // A recovery reads no state: it runs under any layout that keeps the owner's header.
    let token = "CABQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGCK3";
    let recover = json!({"token": token, "recipient": owner, "amount": 5});
    let cli = WalletCli::new(json!({}));
    wallet_run(&cli, &argv("recover", recover.clone(), &owner)).unwrap();
    assert_eq!(cli.calls.borrow().len(), 2);
    let mut account_token = recover.clone();
    account_token["token"] = json!(owner);
    assert!(
        wallet_run(
            &WalletCli::new(json!({})),
            &argv("recover", account_token, &owner)
        )
        .is_err()
    );
}

#[test]
fn an_owner_update_binds_the_source_and_a_new_owner_cosigns() {
    let directory = tempfile::tempdir().unwrap();
    let policy = directory.path().join("policy.rs");
    std::fs::write(&policy, COMMON).unwrap();
    let source_hash = allowit_stellar::hex(&allowit_stellar::hash(COMMON.as_bytes()));
    let (owner, agent, server) = (
        super::tests::key(1),
        super::tests::key(2),
        super::tests::key(3),
    );
    let update = |next_owner: &str| {
        json!({"update": {"deployment_version": 3, "owner": next_owner, "agent": agent, "server": server,
            "source_hash": source_hash, "gas_cap": 1000000, "rules": ["destinations", "expires_at"],
            "params": {"destinations": [super::tests::key(4)], "expires_at": 2000000000}, "wasm_hash": null}})
    };
    let argv = |arguments: Value| -> Vec<String> {
        [
            "admin",
            "--contract",
            WALLET,
            "--method",
            "deploy_policy",
            "--tier",
            "common",
            "--policy-source",
            policy.to_str().unwrap(),
            "--arguments",
            &arguments.to_string(),
            "--source",
            &owner,
        ]
        .map(String::from)
        .to_vec()
    };
    let state = json!({"owner": owner, "deployment_version": 2, "contract_version": 5});
    let cli = WalletCli::new(state.clone());
    let output = wallet_run(&cli, &argv(update(&owner))).unwrap();
    assert_eq!(assembled_auth(&output).len(), 1);
    // The CLI receives the agent and the server as raw keys and the gas cap as decimal text.
    let build = cli.calls.borrow()[1].clone();
    let sent: Value =
        serde_json::from_str(&build[build.iter().position(|a| a == "--update").unwrap() + 1])
            .unwrap();
    assert_eq!(
        sent["agent"],
        json!(allowit_stellar::hex(&public(&agent).unwrap()))
    );
    assert_eq!(sent["gas_cap"], json!("1000000"));
    // A new owner authorizes the update too, by its own address entry.
    let next = super::tests::key(5);
    let mut cli = WalletCli::new(state.clone());
    cli.candidate = Some(next.clone());
    let output = wallet_run(&cli, &argv(update(&next))).unwrap();
    let auth = assembled_auth(&output);
    assert_eq!(auth.len(), 2);
    assert!(
        matches!(&auth[1].credentials, stellar_xdr::SorobanCredentials::Address(c)
        if c.address == allowit_stellar::address(&next).unwrap())
    );
    // An earlier layout, another source hash, roles that repeat or name the wallet prepare nothing.
    let earlier = json!({"owner": owner, "deployment_version": 2, "contract_version": 4});
    assert!(
        wallet_run(&WalletCli::new(earlier), &argv(update(&owner)))
            .unwrap_err()
            .contains("layout version 5")
    );
    let mut other = update(&owner);
    other["update"]["source_hash"] = json!("22".repeat(32));
    assert!(wallet_run(&WalletCli::new(state.clone()), &argv(other)).is_err());
    let mut repeated = update(&owner);
    repeated["update"]["server"] = json!(agent);
    assert!(wallet_run(&WalletCli::new(state.clone()), &argv(repeated)).is_err());
    let mut wallet_owner = update(&owner);
    wallet_owner["update"]["owner"] = json!(WALLET);
    assert!(wallet_run(&WalletCli::new(state), &argv(wallet_owner)).is_err());
}

#[test]
fn the_owner_creates_a_wallet_with_its_config_and_constructor_authorization() {
    let directory = tempfile::tempdir().unwrap();
    let policy = directory.path().join("policy.rs");
    std::fs::write(&policy, COMMON).unwrap();
    let wasm = directory.path().join("wallet.wasm");
    // A module that declares custody layout 5.
    let mut meta = 0u32.to_be_bytes().to_vec();
    for text in [b"allowit_custody_layout".as_slice(), b"5"] {
        meta.extend((text.len() as u32).to_be_bytes());
        meta.extend(text);
        meta.resize(meta.len().div_ceil(4) * 4, 0);
    }
    let mut module = b"\0asm\x01\0\0\0".to_vec();
    let mut payload = vec![14u8];
    payload.extend(b"contractmetav0");
    payload.extend(&meta);
    module.extend([0, payload.len() as u8]);
    module.extend(payload);
    std::fs::write(&wasm, &module).unwrap();
    let owner = super::tests::key(1);
    let config = json!({"owner": owner, "agent": super::tests::key(2), "server": super::tests::key(3),
        "asset": "CABQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGCK3",
        "source_hash": allowit_stellar::hex(&allowit_stellar::hash(COMMON.as_bytes())), "gas_cap": 1000000,
        "rules": ["destinations", "expires_at"], "params": {"destinations": [super::tests::key(4)], "expires_at": 2000000000}});
    let argv = |config: &Value| -> Vec<String> {
        [
            "deploy-wallet",
            "--wasm",
            wasm.to_str().unwrap(),
            "--wasm-hash",
            &allowit_stellar::hex(&allowit_stellar::hash(&module)),
            "--config",
            &config.to_string(),
            "--tier",
            "common",
            "--policy-source",
            policy.to_str().unwrap(),
            "--source",
            &owner,
        ]
        .map(String::from)
        .to_vec()
    };
    let cli = WalletCli::new(json!({}));
    let output = wallet_run(&cli, &argv(&config)).unwrap();
    let auth = assembled_auth(&output);
    assert_eq!(auth.len(), 1);
    assert!(matches!(
        auth[0].root_invocation.function,
        stellar_xdr::SorobanAuthorizedFunction::CreateContractV2HostFn(_)
    ));
    for (field, value) in [
        ("policy_instance", json!("11".repeat(32))),
        ("gas_cap", json!(-1)),
        ("agent", json!(owner)),
    ] {
        let mut changed = config.clone();
        changed[field] = value;
        assert!(
            wallet_run(&WalletCli::new(json!({})), &argv(&changed)).is_err(),
            "{field}"
        );
    }
}
