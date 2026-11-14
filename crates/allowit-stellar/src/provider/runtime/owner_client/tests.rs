//! Synthetic protocol/native fixtures verify orchestration; no model, Wasm execution or chain run is claimed.
#[path = "../../../../tests/support/provider/owner_chain.rs"]
mod chain;
#[path = "../../../../tests/support/provider/owner_server.rs"]
mod wire;
use crate::provider::runtime::{
    Runtime,
    owner::SetupRequest,
    owner_client::{
        OwnerClient,
        workflow::{self, OwnerCapabilities},
    },
};
use allowit_core::client::store::Store;
use chain::*;
fn authority(origin: &str) -> crate::host::config::ServerAuthority {
    crate::host::config::ServerAuthority::validated("stellar:testnet", origin, &account(13))
        .unwrap()
}

use serde_json::{Value, json};
use std::{
    cell::Cell,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
#[test]
fn native_setup_retains_before_sign_and_recovers_lost_reply_without_another_signature() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().canonicalize().unwrap().join("proof");
    let store = Store::open(&path).unwrap();
    let c = selection().config;
    let mut chain = Chain::new(c.clone());
    chain.lose_direct = true;
    let chain = Arc::new(chain);
    let runtime = Runtime::from_rpc(chain.clone());
    let request = SetupRequest {
        network: c.network.clone(),
        owner: c.owner.clone(),
        agent: c.agent.clone(),
        server: c.server.clone(),
        request_id: "setup-test-001".into(),
        fee_per_operation: 100,
    };
    let clock = Cell::new(wire::now());
    let before = || {
        let saved: Value = store.load(&request.request_id).unwrap().unwrap();
        assert!(saved["setup"]["transactionXdr"].is_string());
        assert!(saved["signedXdr"].is_null());
    };
    let signer = Key {
        calls: AtomicUsize::new(0),
        bad: false,
        before: Some(&before),
    };
    let error =
        workflow::configure_native(&runtime, &store, &request, &signer, &|| Ok(clock.get()))
            .unwrap_err();
    assert_eq!(error.code, 5);
    assert_eq!(signer.calls.load(Ordering::SeqCst), 1);
    let original: Value = store.load(&request.request_id).unwrap().unwrap();
    assert_eq!(original["submitted"], true);
    assert_eq!(
        original["signedXdr"],
        chain.direct_signed.lock().unwrap().clone().unwrap()
    );
    drop(store);
    clock.set(clock.get() + 301);
    let reopened = Store::open(&path).unwrap();
    let signer = key();
    let out =
        workflow::configure_native(&runtime, &reopened, &request, &signer, &|| Ok(clock.get()))
            .unwrap();
    assert_eq!(out["state"], "configured");
    assert_eq!(signer.calls.load(Ordering::SeqCst), 0);
    let recovered: Value = reopened.load(&request.request_id).unwrap().unwrap();
    assert_eq!(recovered["signedXdr"], original["signedXdr"]);
    assert_eq!(
        chain
            .events
            .lock()
            .unwrap()
            .iter()
            .filter(|s| s.as_str() == "sendTransaction")
            .count(),
        1
    );
}
#[test]
fn changed_fund_packets_never_reach_the_signer_and_rebound_records_are_not_signing_authority() {
    for tamper_retained in [false, true] {
        let selected = selection();
        let now = wire::now();
        let mut plan = wire::Plan::new(&account(11));
        let step = fund_step(
            &selected.config,
            if tamper_retained {
                10_000_000
            } else {
                20_000_000
            },
            now,
        );
        plan.owner_prepare = Some(json!({"policyId":selected.policy.id,"step":step}));
        let server = wire::Server::new(plan);
        let mut client = OwnerClient::with_authority(
            &authority(&server.url),
            "http://localhost:5173",
            &account(11),
        )
        .unwrap();
        let auth = key();
        client.authenticate(&auth, now).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().canonicalize().unwrap().join("proof")).unwrap();
        let mut chain = Chain::new(selected.config.clone());
        chain.server = Some(server.state.clone());
        let bad = Key {
            calls: AtomicUsize::new(0),
            bad: true,
            before: None,
        };
        let capabilities = OwnerCapabilities {
            store: &store,
            rpc: &chain,
            signer: &bad,
            clock: &|| Ok(now),
        };
        assert!(
            client
                .fund(capabilities, &selected, "fund-test-001", "1", 10_000)
                .is_err()
        );
        assert_eq!(
            bad.calls.load(Ordering::SeqCst),
            usize::from(tamper_retained)
        );
        assert_eq!(server.calls("/api/native/owner/submit"), 0);
        if tamper_retained {
            let mut saved: Value = store.load("fund-test-001").unwrap().unwrap();
            saved["work"]["fund"]["amount"] = json!("2");
            saved["work"]["fund"]["units"] = json!(20_000_000);
            saved["steps"][0]["packet"] = fund_step(&selected.config, 20_000_000, now);
            store.save("fund-test-001", &saved).unwrap();
            let signer = Key {
                calls: AtomicUsize::new(0),
                bad: true,
                before: None,
            };
            let capabilities = OwnerCapabilities {
                store: &store,
                rpc: &chain,
                signer: &signer,
                clock: &|| Ok(now),
            };
            assert!(
                client
                    .fund(capabilities, &selected, "fund-test-001", "1", 10_000)
                    .is_err()
            );
            assert_eq!(
                signer.calls.load(Ordering::SeqCst),
                0,
                "modified retained business fields reached the owner signer"
            );
        }
    }
}
#[test]
fn funded_wallet_receipt_and_restart_preserve_exact_signed_bytes_and_single_owner_authorization() {
    let selected = selection();
    let now = wire::now();
    let mut plan = wire::Plan::new(&account(11));
    plan.owner_prepare = Some(
        json!({"policyId":selected.policy.id,"step":fund_step(&selected.config,10_000_000,now)}),
    );
    plan.lose_owner_reply = true;
    let server = wire::Server::new(plan);
    let mut client = OwnerClient::with_authority(
        &authority(&server.url),
        "http://localhost:5173",
        &account(11),
    )
    .unwrap();
    let signer = key();
    client.authenticate(&signer, now).unwrap();
    let prior = signer.calls.load(Ordering::SeqCst);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().canonicalize().unwrap().join("proof");
    let store = Store::open(&path).unwrap();
    let mut chain = Chain::new(selected.config.clone());
    chain.server = Some(server.state.clone());
    let capabilities = OwnerCapabilities {
        store: &store,
        rpc: &chain,
        signer: &signer,
        clock: &|| Ok(now),
    };
    assert_eq!(
        client
            .fund(capabilities, &selected, "fund-lost-001", "1", 10_000)
            .unwrap_err()
            .code,
        5
    );
    assert_eq!(signer.calls.load(Ordering::SeqCst), prior + 1);
    let saved: Value = store.load("fund-lost-001").unwrap().unwrap();
    assert_eq!(saved["submitted"], Value::Null);
    assert_eq!(saved["steps"][0]["submitted"], true);
    let signed = saved["steps"][0]["signedXdr"].clone();
    drop(store);
    let reopened = Store::open(&path).unwrap();
    let capabilities = OwnerCapabilities {
        store: &reopened,
        rpc: &chain,
        signer: &signer,
        clock: &|| Ok(now + 301),
    };
    let out = client
        .fund(capabilities, &selected, "fund-lost-001", "1", 10_000)
        .unwrap();
    assert_eq!(out.state, "funded");
    assert_eq!(signer.calls.load(Ordering::SeqCst), prior + 1);
    let state = server.state.lock().unwrap();
    assert_eq!(state.owner_submissions.len(), 2);
    assert!(
        state
            .owner_submissions
            .iter()
            .all(|s| s["payload"] == signed)
    );
}

#[cfg(unix)]
#[test]
fn failed_signed_retention_prevents_native_transmission() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().canonicalize().unwrap().join("proof");
    let store = Store::open(&path).unwrap();
    let c = selection().config;
    let chain = Arc::new(Chain::new(c.clone()));
    let runtime = Runtime::from_rpc(chain.clone());
    let now = wire::now();
    let request = SetupRequest {
        network: c.network,
        owner: c.owner,
        agent: c.agent,
        server: c.server,
        request_id: "native-retain-001".into(),
        fee_per_operation: 100,
    };
    let fail_retention =
        || std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o500)).unwrap();
    let signer = Key {
        calls: AtomicUsize::new(0),
        bad: false,
        before: Some(&fail_retention),
    };
    let result = workflow::configure_native(&runtime, &store, &request, &signer, &|| Ok(now));
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(result.is_err());
    assert_eq!(signer.calls.load(Ordering::SeqCst), 1);
    assert!(
        !chain
            .events
            .lock()
            .unwrap()
            .iter()
            .any(|s| s == "sendTransaction")
    );
    let saved: Value = store.load(&request.request_id).unwrap().unwrap();
    assert!(saved["signedXdr"].is_null());
    assert_eq!(saved["submitted"], false);
}

#[test]
fn owner_funding_renews_only_the_independently_observed_relative_lifetime_target() {
    for target in [999, 1119] {
        let selected = selection();
        let now = wire::now();
        let mut plan = wire::Plan::new(&account(11));
        plan.owner_prepare = Some(
            json!({"policyId":selected.policy.id,"step":extend_step(&selected.config,target,now)}),
        );
        let mut fund = fund_step(&selected.config, 10_000_000, now);
        change_step(&mut fund, |tx| tx.seq_num.0 = 43);
        plan.owner_next_prepare = Some(json!({"policyId":selected.policy.id,"step":fund}));
        let server = wire::Server::new(plan);
        let mut client = OwnerClient::with_authority(
            &authority(&server.url),
            "http://localhost:5173",
            &account(11),
        )
        .unwrap();
        let signer = key();
        client.authenticate(&signer, now).unwrap();
        let before = signer.calls.load(Ordering::SeqCst);
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().canonicalize().unwrap().join("proof")).unwrap();
        let mut chain = Chain::new(selected.config.clone());
        chain.server = Some(server.state.clone());
        let out = client.fund(
            OwnerCapabilities {
                store: &store,
                rpc: &chain,
                signer: &signer,
                clock: &|| Ok(now),
            },
            &selected,
            "fund-renew-001",
            "1",
            10_000,
        );
        if target == 1119 {
            assert!(out.is_err());
            assert_eq!(signer.calls.load(Ordering::SeqCst), before);
            assert!(server.state.lock().unwrap().owner_submissions.is_empty());
        } else {
            assert_eq!(out.unwrap().state, "funded");
            assert_eq!(signer.calls.load(Ordering::SeqCst), before + 2);
            let saved: Value = store.load("fund-renew-001").unwrap().unwrap();
            assert_eq!(saved["steps"][0]["extendTo"], 999);
            assert_eq!(saved["steps"][1]["packet"]["action"], "fund");
            let bytes = saved["steps"][0]["signedXdr"].clone();
            client
                .fund(
                    OwnerCapabilities {
                        store: &store,
                        rpc: &chain,
                        signer: &signer,
                        clock: &|| Ok(now + 301),
                    },
                    &selected,
                    "fund-renew-001",
                    "1",
                    10_000,
                )
                .unwrap();
            assert_eq!(signer.calls.load(Ordering::SeqCst), before + 2);
            let retained: Value = store.load("fund-renew-001").unwrap().unwrap();
            assert_eq!(retained["steps"][0]["signedXdr"], bytes);
        }
    }
}

#[test]
fn stale_funding_destination_never_receives_an_owner_signature_or_submission() {
    let p = selection();
    let now = wire::now();
    let mut plan = wire::Plan::new(&account(11));
    plan.owner_prepare =
        Some(json!({"policyId":p.policy.id,"step":fund_step(&p.config,10_000_000,now)}));
    let server = wire::Server::new(plan);
    let mut client = OwnerClient::with_authority(
        &authority(&server.url),
        "http://localhost:5173",
        &account(11),
    )
    .unwrap();
    let signer = key();
    client.authenticate(&signer, now).unwrap();
    let before = signer.calls.load(Ordering::SeqCst);
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().canonicalize().unwrap().join("proof")).unwrap();
    let mut chain = Chain::new(p.config.clone());
    chain.config.agent = account(14);
    chain.server = Some(server.state.clone());
    assert!(
        client
            .fund(
                OwnerCapabilities {
                    store: &store,
                    rpc: &chain,
                    signer: &signer,
                    clock: &|| Ok(now)
                },
                &p,
                "fund-stale-001",
                "1",
                10_000
            )
            .is_err()
    );
    assert_eq!(signer.calls.load(Ordering::SeqCst), before);
    assert!(server.state.lock().unwrap().owner_submissions.is_empty());
}

#[test]
fn generation_validates_prompt_network_and_profile_before_authenticated_http() {
    use super::{GenerateRequest, Target};
    let server = wire::Server::new(wire::Plan::new(&account(11)));
    let now = wire::now();
    let mut client = OwnerClient::with_authority(
        &authority(&server.url),
        "http://localhost:5173",
        &account(11),
    )
    .unwrap();
    client.authenticate(&key(), now).unwrap();
    let mut request = GenerateRequest {
        prompt: "Allow a small payment".into(),
        network: "stellar:unsupported".into(),
        profile: "allowit-policy-wallet-v1".into(),
        target: Target::NewWallet,
        wallet_kind: None,
    };
    let error = client.generate(&request, now).unwrap_err();
    assert!(error.message.starts_with("unknown rail"));
    assert_eq!(
        server.calls("/api/micro/runtime"),
        0,
        "invalid network reached authenticated discovery"
    );
    request.prompt = "x".into();
    request.profile.clear();
    assert_eq!(
        client.generate(&request, now).unwrap_err().message,
        "Describe the policy in 5–3000 UTF-8 bytes"
    );
    request.prompt = "Allow a small payment".into();
    assert!(
        client
            .generate(&request, now)
            .unwrap_err()
            .message
            .starts_with("unknown rail"),
        "network must precede profile validation"
    );
    request.network = "stellar:testnet".into();
    assert_eq!(
        client.generate(&request, now).unwrap_err().message,
        "Select an advertised wallet profile"
    );
    assert_eq!(server.calls("/api/micro/runtime"), 0);
}

#[test]
fn generation_sends_the_chosen_wallet_kind_keeps_the_bound_one_and_reports_a_typed_refusal() {
    use super::{GenerateRequest, Target};
    use allowit_core::vendor::kinds::WalletKind;
    let now = wire::now();
    let generate = |plan: wire::Plan, kind: Option<WalletKind>| {
        let profile = plan.discovery["wallets"][0]["profile"]
            .as_str()
            .unwrap()
            .to_owned();
        let server = wire::Server::new(plan);
        let mut client = OwnerClient::with_authority(
            &authority(&server.url),
            "http://localhost:5173",
            &account(11),
        )
        .unwrap();
        client.authenticate(&key(), now).unwrap();
        let request = GenerateRequest {
            prompt: "Allow a small payment".into(),
            network: "stellar:testnet".into(),
            profile,
            target: Target::NewWallet,
            wallet_kind: kind,
        };
        let result = client.generate(&request, now);
        let sent = server.state.lock().unwrap().generated.clone();
        (result, sent)
    };
    let plan = || {
        let mut plan = wire::Plan::new(&account(11));
        // The stub advertises the profile of its fixture policy.
        let profile = plan.policy["runtime"]["wallet"]["profile"].clone();
        plan.discovery["wallets"][0]["profile"] = profile.clone();
        plan.templates["templates"][0]["profiles"] = json!([profile]);
        plan
    };
    // Without a choice the request names no kind, and a reply without one binds none.
    let (policy, sent) = generate(plan(), None);
    let policy = policy.map_err(|e| e.message).unwrap();
    assert_eq!(policy.wallet_kind, None);
    assert_eq!(sent.len(), 1);
    assert!(sent[0].get("walletKind").is_none());
    assert!(
        serde_json::to_value(&policy)
            .unwrap()
            .get("walletKind")
            .is_none()
    );
    // The choice is the top-level `walletKind`, and the bound kind stays on the document.
    let mut bound = plan();
    bound.policy["walletKind"] = json!("standard");
    let (policy, sent) = generate(bound, Some(WalletKind::Standard));
    let policy = policy.map_err(|e| e.message).unwrap();
    assert_eq!(sent[0]["walletKind"], "standard");
    assert_eq!(policy.wallet_kind, Some(WalletKind::Standard));
    let draft = crate::host::generation::GeneratedDraft {
        document: serde_json::to_value(&policy).unwrap(),
        unresolved: Vec::new(),
    };
    assert_eq!(draft.wallet_kind(), Some(WalletKind::Standard));
    // A reply that binds another kind than the chosen one is not returned as the draft.
    let mut other = plan();
    other.policy["walletKind"] = json!("custom");
    let (result, _) = generate(other, Some(WalletKind::Standard));
    assert_eq!(result.unwrap_err().code, 5);
    // An unknown kind id in a reply is invalid; ids have no alias.
    let mut alias = plan();
    alias.policy["walletKind"] = json!("common");
    assert!(generate(alias, None).0.is_err());
    // The typed refusal keeps its code and details.
    for code in ["wallet_kind_unsupported", "wallet_kind_unknown"] {
        let mut refused = plan();
        refused.generation_refusal = Some((
            400,
            json!({"error":"This network does not offer the wallet kind","code":code,
                "details":{"walletKind":"custom","network":"stellar:testnet","reason":"No Custom template is configured"}}),
        ));
        let (result, sent) = generate(refused, Some(WalletKind::Custom));
        let error = result.unwrap_err();
        assert_eq!(sent[0]["walletKind"], "custom");
        assert_eq!(error.api_code.as_deref(), Some(code));
        assert_eq!((error.code, error.status), (4, Some(400)));
        assert_eq!(
            error.detail("reason"),
            Some("No Custom template is configured")
        );
        assert_eq!(error.details.as_ref().unwrap()["walletKind"], "custom");
        assert_eq!(
            error.details.as_ref().unwrap()["network"],
            "stellar:testnet"
        );
    }
}

fn limit_update(
    selected: &workflow::OwnerPolicy,
    units: i128,
) -> crate::host::runtime::ParamsUpdate {
    crate::host::runtime::ParamsUpdate {
        policy_id: selected.policy.id.clone(),
        expected_revision: None,
        changes: [(
            "payment_limit".to_owned(),
            allowit_core::policy::PolicyValue(allowit_core::AllowitValue::Int(units)),
        )]
        .into(),
    }
}
/// The step that a server prepares for `update` over revision 1.
fn prepared_update(
    selected: &workflow::OwnerPolicy,
    update: &crate::host::runtime::ParamsUpdate,
    now: u64,
) -> Value {
    let deployment =
        crate::provider::params_update::deployment(&selected.config, update, false).unwrap();
    update_step(&selected.config, &deployment, 2, now)
}
#[test]
fn params_update_signs_one_exact_policy_packet_and_resumes_without_another_signature() {
    let selected = selection();
    let update = limit_update(&selected, 20_000_000);
    let now = wire::now();
    let mut plan = wire::Plan::new(&account(11));
    plan.owner_prepare = Some(
        json!({"policyId":selected.policy.id,"step":prepared_update(&selected, &update, now)}),
    );
    plan.lose_owner_reply = true;
    let server = wire::Server::new(plan);
    let mut client = OwnerClient::with_authority(
        &authority(&server.url),
        "http://localhost:5173",
        &account(11),
    )
    .unwrap();
    let signer = key();
    client.authenticate(&signer, now).unwrap();
    let prior = signer.calls.load(Ordering::SeqCst);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().canonicalize().unwrap().join("proof");
    let store = Store::open(&path).unwrap();
    let mut chain = Chain::new(selected.config.clone());
    chain.server = Some(server.state.clone());
    let usage = crate::policy::params_from_json(
        &json!({"spent": 7_000_000, "day_spent": 7_000_000, "day": 20_000, "calls": 1}),
        None,
    )
    .unwrap();
    *chain.installed.lock().unwrap() = Some((selected.config.params.clone(), 1, usage.clone()));
    let before =
        crate::provider::params_update::verify(&chain, &selected.policy.id, &selected.config)
            .unwrap();
    assert!(before.matches);
    assert_eq!(before.state.revision, 1);
    // The reply of the submission is lost: the signed step stays saved and unresolved.
    let capabilities = OwnerCapabilities {
        store: &store,
        rpc: &chain,
        signer: &signer,
        clock: &|| Ok(now),
    };
    assert_eq!(
        client
            .update_params(capabilities, &selected, "update-lost-001", &update, 10_000)
            .unwrap_err()
            .code,
        5
    );
    assert_eq!(signer.calls.load(Ordering::SeqCst), prior + 1);
    let saved: Value = store.load("update-lost-001").unwrap().unwrap();
    assert_eq!(
        saved["work"]["updateParams"]["update"]["expectedRevision"],
        1
    );
    assert_eq!(saved["steps"][0]["packet"]["action"], "update_params");
    let signed = saved["steps"][0]["signedXdr"].clone();
    // The update settled: the wallet holds the new params at the next revision, and it kept
    // its recorded usage.
    let next = crate::provider::params_update::updated_config(&selected.config, &update).unwrap();
    *chain.installed.lock().unwrap() = Some((next.params.clone(), 2, usage));
    drop(store);
    let reopened = Store::open(&path).unwrap();
    let capabilities = OwnerCapabilities {
        store: &reopened,
        rpc: &chain,
        signer: &signer,
        clock: &|| Ok(now + 301),
    };
    let out = client
        .update_params(capabilities, &selected, "update-lost-001", &update, 10_000)
        .unwrap();
    assert_eq!(out.state, "updated");
    assert_eq!(out.selection.config, next);
    assert_eq!(
        out.selection
            .policy
            .runtime
            .instance_binding
            .portable
            .params,
        next.params
    );
    assert_eq!(out.receipts.len(), 1);
    assert_eq!(out.receipts[0].action, "update_params");
    // The resumed request asked for no other signature and sent the same signed bytes.
    assert_eq!(signer.calls.load(Ordering::SeqCst), prior + 1);
    {
        let state = server.state.lock().unwrap();
        assert_eq!(state.owner_submissions.len(), 2);
        assert!(
            state
                .owner_submissions
                .iter()
                .all(|s| s["payload"] == signed)
        );
    }
    // The outcome is the owner's new document: the ledger matches it and no longer matches
    // the earlier one. The counters are those from before the update.
    let after =
        crate::provider::params_update::verify(&chain, &out.selection.policy.id, &next).unwrap();
    assert!(after.matches);
    assert_eq!(after.state.revision, 2);
    assert_eq!(after.state.counters, before.state.counters);
    assert_eq!(
        after.state.counters.as_ref().unwrap().spent_total,
        7_000_000
    );
    let stale =
        crate::provider::params_update::verify(&chain, &selected.policy.id, &selected.config)
            .unwrap();
    assert!(!stale.matches);
    assert_eq!(
        stale
            .comparisons
            .iter()
            .filter(|c| !c.matches)
            .map(|c| c.field.as_str())
            .collect::<Vec<_>>(),
        ["params"]
    );
    // A completed update exports the updated installation, and only that one.
    let other = limit_update(&selected, 30_000_000);
    let capabilities = OwnerCapabilities {
        store: &reopened,
        rpc: &chain,
        signer: &signer,
        clock: &|| Ok(now + 301),
    };
    assert!(
        client
            .update_params(capabilities, &selected, "update-lost-001", &other, 10_000)
            .is_err(),
        "a request ID binds one update"
    );
    assert_eq!(signer.calls.load(Ordering::SeqCst), prior + 1);
}
#[test]
fn changed_update_packets_and_invalid_updates_never_reach_the_signer() {
    let selected = selection();
    let update = limit_update(&selected, 20_000_000);
    let now = wire::now();
    let tampered = {
        // Another value than the owner selected.
        let other = limit_update(&selected, 90_000_000);
        let value = prepared_update(&selected, &other, now);
        // Another target revision.
        let deployment =
            crate::provider::params_update::deployment(&selected.config, &update, false).unwrap();
        let version = update_step(&selected.config, &deployment, 3, now);
        // A new owner in the packet.
        let mut handoff = deployment.clone();
        handoff.owner = account(51);
        let owner = update_step(&selected.config, &handoff, 2, now);
        // A funding transfer under the update action.
        let mut transfer = fund_step(&selected.config, 10_000_000, now);
        transfer["action"] = json!("update_params");
        [value, version, owner, transfer]
    };
    for step in tampered {
        let mut plan = wire::Plan::new(&account(11));
        plan.owner_prepare = Some(json!({"policyId":selected.policy.id,"step":step}));
        let server = wire::Server::new(plan);
        let mut client = OwnerClient::with_authority(
            &authority(&server.url),
            "http://localhost:5173",
            &account(11),
        )
        .unwrap();
        let signer = key();
        client.authenticate(&signer, now).unwrap();
        let prior = signer.calls.load(Ordering::SeqCst);
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().canonicalize().unwrap().join("proof")).unwrap();
        let mut chain = Chain::new(selected.config.clone());
        chain.server = Some(server.state.clone());
        let capabilities = OwnerCapabilities {
            store: &store,
            rpc: &chain,
            signer: &signer,
            clock: &|| Ok(now),
        };
        assert!(
            client
                .update_params(capabilities, &selected, "update-test-001", &update, 10_000)
                .is_err()
        );
        assert_eq!(signer.calls.load(Ordering::SeqCst), prior);
        assert_eq!(server.calls("/api/native/owner/submit"), 0);
    }
    // An update that the installation cannot take is refused before the server is asked.
    let mut plan = wire::Plan::new(&account(11));
    plan.owner_prepare = Some(json!({"policyId":selected.policy.id,"step":Value::Null}));
    let server = wire::Server::new(plan);
    let mut client = OwnerClient::with_authority(
        &authority(&server.url),
        "http://localhost:5173",
        &account(11),
    )
    .unwrap();
    let signer = key();
    client.authenticate(&signer, now).unwrap();
    let prior = signer.calls.load(Ordering::SeqCst);
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().canonicalize().unwrap().join("proof")).unwrap();
    let mut chain = Chain::new(selected.config.clone());
    chain.server = Some(server.state.clone());
    let value = |v| allowit_core::policy::PolicyValue(v);
    use allowit_core::AllowitValue as V;
    let invalid = [
        // No installed param of this name.
        ("call_limit", value(V::Int(5)), None),
        // Another type than the installed value.
        ("payment_limit", value(V::Bool(true)), None),
        // Outside the range of the rule.
        ("payment_limit", value(V::Int(-1)), None),
        // The value that is installed already.
        ("payment_limit", value(V::Int(10_000_000)), None),
        // Another configuration revision than the wallet holds.
        ("payment_limit", value(V::Int(20_000_000)), Some(7)),
    ];
    for (key, value, expected_revision) in invalid {
        let update = crate::host::runtime::ParamsUpdate {
            policy_id: selected.policy.id.clone(),
            expected_revision,
            changes: [(key.to_owned(), value)].into(),
        };
        let capabilities = OwnerCapabilities {
            store: &store,
            rpc: &chain,
            signer: &signer,
            clock: &|| Ok(now),
        };
        assert!(
            client
                .update_params(capabilities, &selected, "update-test-002", &update, 10_000)
                .is_err(),
            "{key}"
        );
        assert_eq!(server.calls("/api/native/owner/prepare"), 0, "{key}");
        assert_eq!(signer.calls.load(Ordering::SeqCst), prior, "{key}");
    }
    // Another policy's update is refused for this installation.
    let mut foreign = limit_update(&selected, 20_000_000);
    foreign.policy_id = "0".repeat(64);
    let capabilities = OwnerCapabilities {
        store: &store,
        rpc: &chain,
        signer: &signer,
        clock: &|| Ok(now),
    };
    assert!(
        client
            .update_params(capabilities, &selected, "update-test-003", &foreign, 10_000)
            .is_err()
    );
    assert_eq!(server.calls("/api/native/owner/prepare"), 0);
    // A keypair account holds no installed params to update.
    let native = native_selection();
    let update = limit_update(&native, 20_000_000);
    assert!(crate::provider::params_update::next_params(&native.config, &update).is_err());
}
