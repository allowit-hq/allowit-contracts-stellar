//! Guards of native account administration: admission of exact profiles, atomic unsigned
//! preparation and the command-line refusals.
use super::*;
use stellar_xdr::ReadXdr;

pub fn key(n: u8) -> String {
    let public = ed25519_dalek::SigningKey::from_bytes(&[n; 32]).verifying_key();
    AccountKey(public.to_bytes()).to_string()
}
fn signer_entry(key: &str, weight: u64, kind: &str) -> Value {
    json!({"key": key, "weight": weight, "type": kind})
}
fn set_thresholds(state: &mut Value, low: u64, med: u64, high: u64) {
    state["thresholds"] =
        json!({"low_threshold": low, "med_threshold": med, "high_threshold": high});
}
/// A fresh account: master weight 1, no other signer and default thresholds.
fn state() -> Value {
    let mut state = json!({"account_id": key(1), "sequence": "42",
        "signers": [signer_entry(&key(1), 1, "ed25519_public_key")]});
    set_thresholds(&mut state, 0, 0, 0);
    state
}
/// The exact native wallet profile of owner `key(1)`, agent `key(2)` and engine `key(3)`.
fn wallet_state() -> Value {
    let mut value = state();
    value["signers"] = json!([
        signer_entry(&key(1), 3, "ed25519_public_key"),
        signer_entry(&key(2), 1, "ed25519_public_key"),
        signer_entry(&key(3), 1, "ed25519_public_key"),
    ]);
    set_thresholds(&mut value, 2, 2, 3);
    value
}
fn preparation<'a>(action: &'a str, agent: &'a str, engine: &'a str) -> Preparation<'a> {
    Preparation {
        action,
        network: "testnet",
        agent: Some(agent),
        engine: Some(engine),
        members: &[],
        fee: 100,
        now: 1000,
        source_state: None,
    }
}
fn decode(xdr: &str) -> TransactionV1Envelope {
    match TransactionEnvelope::from_xdr_base64(xdr, Limits::none()).unwrap() {
        TransactionEnvelope::Tx(envelope) => envelope,
        _ => panic!("expected a v1 envelope"),
    }
}
fn options(operation: &Operation) -> &SetOptionsOp {
    match &operation.body {
        OperationBody::SetOptions(body) => body,
        _ => panic!("expected set options"),
    }
}
fn signer_of(operation: &Operation) -> (String, u32) {
    let signer = options(operation).signer.as_ref().unwrap();
    let SignerKey::Ed25519(Uint256(bytes)) = &signer.key else {
        panic!("expected an Ed25519 signer");
    };
    (AccountKey(*bytes).to_string(), signer.weight)
}
fn weights_of(operation: &Operation) -> [Option<u32>; 4] {
    let body = options(operation);
    [
        body.master_weight,
        body.low_threshold,
        body.med_threshold,
        body.high_threshold,
    ]
}
fn arguments(args: &[&str]) -> Result<Arguments> {
    parse(&args.iter().map(|arg| arg.to_string()).collect::<Vec<_>>())
}

#[test]
fn an_owner_has_only_its_master_key_active() {
    owner_only(&state()).unwrap();
    let mut value = state();
    value["signers"][0]["weight"] = json!(3);
    set_thresholds(&mut value, 2, 2, 3);
    owner_only(&value).unwrap();
    // A delegated agent and engine quorum is not an owner.
    assert!(owner_only(&wallet_state()).is_err());
    let mut zero = state();
    zero["signers"][0]["weight"] = json!(0);
    assert!(owner_only(&zero).is_err());
    // A threshold above the master weight locks the owner out.
    let mut drift = state();
    drift["thresholds"]["high_threshold"] = json!(2);
    assert!(owner_only(&drift).is_err());
    let mut hash = state();
    hash["signers"]
        .as_array_mut()
        .unwrap()
        .push(signer_entry("hash", 1, "sha256_hash"));
    assert!(owner_only(&hash).is_err());
    for weight in [json!(256), json!(-1), json!(1.5), json!("1"), json!(true)] {
        let mut invalid = state();
        invalid["signers"][0]["weight"] = weight;
        assert!(owner_only(&invalid).is_err());
    }
}

#[test]
fn wallet_setup_is_one_unsigned_transaction_of_the_exact_profile() {
    let (agent, engine) = (key(2), key(3));
    let xdr = prepare(&state(), &preparation("setup-wallet", &agent, &engine)).unwrap();
    let envelope = decode(&xdr);
    assert!(envelope.signatures.is_empty());
    let tx = &envelope.tx;
    assert_eq!(
        tx.source_account,
        MuxedAccount::Ed25519(Uint256(public(&key(1)).unwrap()))
    );
    assert_eq!((tx.seq_num.0, tx.fee), (43, 300));
    assert_eq!(
        tx.cond,
        Preconditions::Time(TimeBounds {
            min_time: TimePoint(0),
            max_time: TimePoint(1300)
        })
    );
    let operations = tx.operations.as_slice();
    assert_eq!(operations.len(), 3);
    assert_eq!(signer_of(&operations[0]), (agent, 1));
    assert_eq!(signer_of(&operations[1]), (engine, 1));
    assert_eq!(
        weights_of(&operations[2]),
        [Some(3), Some(2), Some(2), Some(3)]
    );
    assert!(operations.iter().all(|op| op.source_account.is_none()));
}

#[test]
fn setup_never_replaces_existing_authority() {
    let (agent, engine) = (key(2), key(3));
    for malformed in ["threshold", "signer", "preauth", "duplicate"] {
        let mut value = state();
        if malformed == "threshold" {
            value["thresholds"]["high_threshold"] = json!(1);
        } else {
            let extra = match malformed {
                "preauth" => signer_entry(&key(4), 1, "preauth_tx"),
                "duplicate" => signer_entry(&key(1), 1, "ed25519_public_key"),
                _ => signer_entry(&key(4), 1, "ed25519_public_key"),
            };
            value["signers"].as_array_mut().unwrap().push(extra);
        }
        for action in ["setup-wallet", "setup-admin"] {
            let members = [key(2), key(3), key(4)];
            let mut p = preparation(action, &agent, &engine);
            p.members = &members;
            assert!(prepare(&value, &p).is_err(), "{malformed} {action}");
        }
    }
}

#[test]
fn shutdown_removes_both_signers_and_raises_every_threshold() {
    let (agent, engine) = (key(2), key(3));
    let mut value = wallet_state();
    wallet(&value, &agent, &engine).unwrap();
    let xdr = prepare(&value, &preparation("shutdown-wallet", &agent, &engine)).unwrap();
    let envelope = decode(&xdr);
    let operations = envelope.tx.operations.as_slice();
    assert_eq!(signer_of(&operations[0]), (agent.clone(), 0));
    assert_eq!(signer_of(&operations[1]), (engine.clone(), 0));
    assert_eq!(
        weights_of(&operations[2]),
        [Some(3), Some(3), Some(3), Some(3)]
    );
    // An unexpected extra signer is not the exact profile.
    value["signers"]
        .as_array_mut()
        .unwrap()
        .push(signer_entry(&key(5), 1, "ed25519_public_key"));
    assert!(wallet(&value, &agent, &engine).is_err());
    assert!(prepare(&value, &preparation("shutdown-wallet", &agent, &engine)).is_err());
    // Swapped roles and threshold drift are not the exact profile either.
    let mut drift = wallet_state();
    drift["thresholds"]["med_threshold"] = json!(1);
    assert!(wallet(&drift, &agent, &engine).is_err());
    assert!(wallet(&wallet_state(), &agent, &key(4)).is_err());
}

#[test]
fn shutdown_takes_a_separate_owner_only_fee_source() {
    let (agent, engine) = (key(2), key(3));
    let value = wallet_state();
    let mut fee_source = state();
    fee_source["account_id"] = json!(key(5));
    fee_source["sequence"] = json!("100");
    fee_source["signers"][0]["key"] = json!(key(5));
    let mut p = preparation("shutdown-wallet", &agent, &engine);
    p.source_state = Some(&fee_source);
    let envelope = decode(&prepare(&value, &p).unwrap());
    let wallet_account = MuxedAccount::Ed25519(Uint256(public(&key(1)).unwrap()));
    assert_eq!(
        envelope.tx.source_account,
        MuxedAccount::Ed25519(Uint256(public(&key(5)).unwrap()))
    );
    assert_eq!(envelope.tx.seq_num.0, 101);
    assert!(
        envelope
            .tx
            .operations
            .iter()
            .all(|op| op.source_account.as_ref() == Some(&wallet_account))
    );
    // The agent, the engine or the wallet itself cannot be the separate source.
    for delegated in [key(1), key(2), key(3)] {
        let mut source = fee_source.clone();
        source["account_id"] = json!(delegated);
        source["signers"][0]["key"] = json!(delegated);
        let mut p = preparation("shutdown-wallet", &agent, &engine);
        p.source_state = Some(&source);
        assert!(prepare(&value, &p).is_err());
    }
    // A source that a quorum controls is refused, and so is a source for setup.
    let quorum = wallet_state();
    let mut p = preparation("shutdown-wallet", &agent, &engine);
    p.source_state = Some(&quorum);
    assert!(prepare(&value, &p).is_err());
    let mut p = preparation("setup-wallet", &agent, &engine);
    p.source_state = Some(&fee_source);
    assert!(prepare(&state(), &p).is_err());
}

#[test]
fn open_offers_refuse_verification_and_only_warn_for_shutdown() {
    let offers = |records: Value| move |_: &str| Ok(json!({"_embedded": {"records": records}}));
    let none = offers(json!([]));
    assert_eq!(no_offers(&none, "testnet", &key(1), true), Ok(None));
    let open = offers(json!([{"id": "1"}]));
    assert!(no_offers(&open, "testnet", &key(1), true).is_err());
    let warning = no_offers(&open, "testnet", &key(1), false).unwrap();
    assert!(warning.unwrap().contains("Revoke signers first"));
    let malformed = |_: &str| Ok(json!({}));
    assert!(no_offers(&malformed, "testnet", &key(1), true).is_err());
}

#[test]
fn admin_setup_gives_three_distinct_members_a_two_of_three_quorum() {
    let members = [key(2), key(3), key(4)];
    let mut p = preparation("setup-admin", "", "");
    p.members = &members;
    let envelope = decode(&prepare(&state(), &p).unwrap());
    let operations = envelope.tx.operations.as_slice();
    assert_eq!(operations.len(), 4);
    for (operation, member) in operations.iter().zip(&members) {
        assert_eq!(signer_of(operation), (member.clone(), 1));
    }
    assert_eq!(
        weights_of(&operations[3]),
        [Some(0), Some(2), Some(2), Some(2)]
    );
    // A master key that is a member keeps weight 1.
    let with_master = [key(1), key(2), key(3)];
    p.members = &with_master;
    let envelope = decode(&prepare(&state(), &p).unwrap());
    assert_eq!(envelope.tx.operations.len(), 3);
    assert_eq!(
        weights_of(envelope.tx.operations.last().unwrap()),
        [Some(1), Some(2), Some(2), Some(2)]
    );
    let invalid = [
        vec![key(2), key(2), key(2)],
        vec![key(2), key(3)],
        vec![key(2), key(3), key(4), key(5)],
    ];
    for members in &invalid {
        p.members = members;
        assert!(prepare(&state(), &p).is_err());
    }
}

#[test]
fn admin_verification_admits_only_the_exact_quorum() {
    let members = [key(2), key(3), key(4)];
    let mut value = state();
    assert!(admin(&value, &members).is_err());
    value["signers"][0]["weight"] = json!(0);
    for member in &members {
        value["signers"].as_array_mut().unwrap().push(signer_entry(
            member,
            1,
            "ed25519_public_key",
        ));
    }
    set_thresholds(&mut value, 2, 2, 2);
    admin(&value, &members).unwrap();
    assert!(admin(&value, &[key(2), key(3), key(5)]).is_err());
    assert!(admin(&value, &[key(2), key(3)]).is_err());
    value["signers"][1]["weight"] = json!(2);
    assert!(admin(&value, &members).is_err());
}

#[test]
fn roles_must_differ_and_the_fee_and_network_are_bounded() {
    let (owner, agent, engine) = (key(1), key(2), key(3));
    assert!(prepare(&state(), &preparation("setup-wallet", &owner, &engine)).is_err());
    assert!(prepare(&state(), &preparation("setup-wallet", &engine, &engine)).is_err());
    for fee in [99, 100_001, 1_000_000] {
        let mut p = preparation("setup-wallet", &agent, &engine);
        p.fee = fee;
        assert!(prepare(&state(), &p).is_err());
    }
    let mut p = preparation("setup-wallet", &agent, &engine);
    p.network = "futurenet";
    assert!(prepare(&state(), &p).is_err());
    assert!(prepare(&state(), &preparation("inspect", &agent, &engine)).is_err());
    let mut negative = state();
    negative["sequence"] = json!("-1");
    assert!(prepare(&negative, &preparation("setup-wallet", &agent, &engine)).is_err());
}

#[test]
fn address_errors_never_echo_the_input() {
    let invalid = "invalid-private-input-for-test";
    // A secret seed is a valid StrKey of another type; it is refused like any other text.
    let seed = stellar_strkey::ed25519::PrivateKey([7; 32]).to_string();
    for input in [invalid, seed.as_str()] {
        for args in [
            vec!["inspect", "--account", input],
            vec!["setup-wallet", "--account", &key(1), "--agent", input],
            vec!["setup-admin", "--account", &key(1), "--member", input],
            vec![
                "shutdown-wallet",
                "--account",
                &key(1),
                "--transaction-source",
                input,
            ],
        ] {
            let error = arguments(&args).unwrap_err();
            assert_eq!(error, BAD_ADDRESS);
            assert!(!error.contains(input));
        }
    }
}

#[test]
fn the_command_line_refuses_unsafe_or_incomplete_requests() {
    let (owner, agent, engine) = (key(1), key(2), key(3));
    let with = |action: &str, extra: &[&str]| {
        let mut args = vec![action, "--account", &owner, "--agent", &agent];
        args.extend(["--engine", &engine]);
        args.extend(extra);
        arguments(&args)
    };
    // Mainnet preparation needs the explicit flag; a mainnet read does not.
    for action in ["setup-wallet", "shutdown-wallet", "setup-admin"] {
        assert!(with(action, &["--network", "mainnet"]).is_err());
        assert!(with(action, &["--network", "mainnet", "--allow-mainnet"]).is_ok());
    }
    assert!(with("verify-wallet", &["--network", "mainnet"]).is_ok());
    assert_eq!(with("setup-wallet", &[]).unwrap().network, "testnet");
    assert!(with("setup-wallet", &["--network", "futurenet"]).is_err());
    // No action signs or submits, and no flag takes a secret.
    for action in ["sign", "submit", "send"] {
        assert!(with(action, &[]).is_err());
    }
    for flag in ["--secret", "--seed", "--sign", "--send"] {
        assert!(with("setup-wallet", &[flag, "x"]).is_err());
    }
    for action in ["setup-wallet", "shutdown-wallet", "verify-wallet"] {
        assert!(arguments(&[action, "--account", &owner, "--agent", &agent]).is_err());
    }
    assert!(arguments(&["inspect"]).is_err());
    let source = key(5);
    assert!(with("shutdown-wallet", &["--transaction-source", &source]).is_ok());
    for action in ["setup-wallet", "verify-wallet", "inspect"] {
        assert!(with(action, &["--transaction-source", &source]).is_err());
    }
}

/// `tests/fixtures/native_admin_vectors.json` records what the Python command line
/// `scripts/wallet_admin.py` returned at revision `d0cf4e0` for each case: every admission check
/// and every prepared XDR.
#[test]
fn checks_and_prepared_xdr_match_the_recorded_vectors() {
    let vectors: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/native_admin_vectors.json"
    ))
    .unwrap();
    let keys: Vec<String> = serde_json::from_value(vectors["keys"].clone()).unwrap();
    assert_eq!(keys, (1..=6).map(key).collect::<Vec<_>>());
    let key_at = |index: &Value| keys[index.as_u64().unwrap() as usize].clone();
    let members = |case: &Value| -> Vec<String> {
        case["members"]
            .as_array()
            .unwrap()
            .iter()
            .map(key_at)
            .collect()
    };
    let states = &vectors["states"];
    let checks = vectors["checks"].as_array().unwrap();
    assert_eq!(checks.len(), 132);
    for case in checks {
        let state = &states[case["state"].as_str().unwrap()];
        let admitted = match case["check"].as_str().unwrap() {
            "owner_only" => owner_only(state).is_ok(),
            "wallet" => wallet(state, &keys[1], &keys[2]).is_ok(),
            "admin" => admin(state, &members(case)).is_ok(),
            other => panic!("unknown check {other}"),
        };
        assert_eq!(admitted, case["ok"] == true, "{case}");
    }
    let prepares = vectors["prepares"].as_array().unwrap();
    assert_eq!(prepares.len(), 272);
    let mut prepared = 0;
    for case in prepares {
        let (agent, engine) = (key_at(&case["agent"]), key_at(&case["engine"]));
        let members = members(case);
        let result = prepare(
            &states[case["state"].as_str().unwrap()],
            &Preparation {
                action: case["action"].as_str().unwrap(),
                network: "testnet",
                agent: Some(&agent),
                engine: Some(&engine),
                members: &members,
                fee: case["fee"].as_u64().unwrap() as u32,
                now: 1000,
                source_state: case["source"].as_str().map(|name| &states[name]),
            },
        );
        assert_eq!(
            result.ok().map(Value::String),
            case["xdr"].as_str().map(|xdr| json!(xdr)),
            "{case}"
        );
        prepared += usize::from(case["xdr"].is_string());
    }
    assert_eq!(prepared, 17);
    // Both networks prepare the same bytes: a transaction names no network until it is signed.
    let (agent, engine) = (key(2), key(3));
    let mut mainnet = preparation("setup-wallet", &agent, &engine);
    mainnet.network = "mainnet";
    assert_eq!(
        json!(prepare(&states["fresh"], &mainnet).unwrap()),
        vectors["mainnet_setup"]
    );
}

#[test]
fn help_is_a_flag_and_never_the_value_of_another_flag() {
    let args = |args: &[&str]| args.iter().map(|arg| arg.to_string()).collect::<Vec<_>>();
    for help in [
        &["--help"][..],
        &["-h"],
        &["inspect", "-h"],
        &["--network", "testnet", "--help"],
        &["admin", "--allow-mainnet", "--help"],
        &["read", "--network=mainnet", "-h"],
    ] {
        assert!(help_requested(&args(help)), "{help:?}");
    }
    for other in [
        &[][..],
        &["inspect", "--account", "-h"],
        &["admin", "--arguments", "--help"],
        &["read", "--method", "state"],
    ] {
        assert!(!help_requested(&args(other)), "{other:?}");
    }
    assert_eq!(
        action_of(&args(&["--network", "testnet", "read"])),
        Some("read")
    );
    assert_eq!(
        action_of(&args(&["--allow-mainnet", "admin"])),
        Some("admin")
    );
    assert_eq!(action_of(&args(&["--network", "inspect"])), None);
}

#[test]
fn every_action_reads_live_state_and_prints_only_public_output() {
    let (owner, agent, engine) = (key(1), key(2), key(3));
    let roles = ["--account", &owner, "--agent", &agent, "--engine", &engine];
    let get = |url: &str| -> Result<Value> {
        assert!(url.starts_with("https://horizon-testnet.stellar.org/accounts/"));
        if url.ends_with("/offers?limit=1") {
            return Ok(json!({"_embedded": {"records": [{"id": "1"}]}}));
        }
        let mut value = wallet_state();
        value["balances"] = json!([{"balance": "1.0"}]);
        Ok(value)
    };
    let run_action = |action: &str| {
        let mut args = vec![action];
        args.extend(roles);
        run(&arguments(&args).unwrap(), &get, 1000)
    };
    let (inspected, _) = run_action("inspect").unwrap();
    let inspected: Value = serde_json::from_str(&inspected).unwrap();
    let keys: Vec<_> = inspected.as_object().unwrap().keys().collect();
    assert_eq!(keys, ["account_id", "sequence", "signers", "thresholds"]);
    // Open offers refuse verification; shutdown still prepares and warns.
    assert!(run_action("verify-wallet").is_err());
    let (xdr, warning) = run_action("shutdown-wallet").unwrap();
    assert!(warning.is_some());
    assert!(decode(&xdr).signatures.is_empty());
    // A response for another account is refused.
    let other = |_: &str| Ok(json!({"account_id": key(4)}));
    let args = arguments(&["inspect", "--account", &owner]).unwrap();
    assert!(run(&args, &other, 1000).is_err());
}
