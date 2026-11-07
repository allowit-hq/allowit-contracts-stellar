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
use allowit::client::store::Store;
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
fn server_policy_uses_installed_prefix_and_retains_exact_overlay_consent() {
    use allowit_stellar_wallet as native;

    let base = selection();
    let mut draft = base.policy.clone();
    let prefix = draft.code.clone();
    let prefix_hash = draft.source_hash.clone();
    draft.code = prefix.replace(
        "    Ok(())",
        "    let _network = stellar::network(ctx)?;\n    Ok(())",
    );
    assert_ne!(draft.code, prefix);
    draft.source_hash = allowit::digest(draft.code.as_bytes());
    let binding = &mut draft.runtime.instance_binding;
    binding.installed_source = Some(prefix.clone());
    binding.installed_source_hash = Some(prefix_hash.clone());
    binding.portable.tier = "server".into();
    binding.portable.source_hash = draft.source_hash.clone();
    binding.portable.build.server_bindings = Some("44".repeat(32));

    let selected = workflow::deployment_policy(
        draft.clone(),
        &account(11),
        &account(12),
        &account(13),
        &wasm(),
    )
    .unwrap();
    assert_eq!(selected.config, base.config);
    assert_eq!(selected.config.policy_source, prefix);
    assert_ne!(selected.policy.code, selected.config.policy_source);
    selected.validate().unwrap();
    let mut mismatched = selected.clone();
    mismatched
        .policy
        .runtime
        .instance_binding
        .installed_source_hash = Some("55".repeat(32));
    assert!(mismatched.validate().is_err());
    let mut mismatched = selected.clone();
    mismatched.policy.runtime.instance_binding.portable.tier = "standard".into();
    assert!(mismatched.validate().is_err());

    let c = &selected.config;
    let p = &selected.policy;
    let payload = json!({
        "profile":"allowit-stellar-server-policy-approval-v1", "network":c.network,
        "wallet":c.wallet, "owner":c.owner, "policyId":p.id, "revision":p.revision,
        "policyInstance":native::hex(&c.policy_instance), "moduleDigest":native::hex(&c.module_digest),
        "installedSourceHash":prefix_hash, "source":p.code, "sourceHash":p.source_hash,
        "paramsHash":p.runtime.instance_binding.portable.params_hash, "serverBindings":"44".repeat(32),
    });
    let message = format!(
        "AllowIt Stellar server policy approval v1\n{}",
        serde_json_canonicalizer::to_string(&payload).unwrap()
    );
    let digest = native::signing::signed_message_digest(&message);
    let expected_signature = native::test_support::sign_digest([11; 32], &digest);
    let descriptor = native::test_support::public_profile(c, &p.id);
    let now = wire::now();

    for substitute in [true, false] {
        let mut returned = payload.clone();
        if substitute {
            returned["serverBindings"] = json!("55".repeat(32));
        }
        let returned_message = format!(
            "AllowIt Stellar server policy approval v1\n{}",
            serde_json_canonicalizer::to_string(&returned).unwrap()
        );
        let mut plan = wire::Plan::new(&account(11));
        plan.policy = serde_json::to_value(&draft).unwrap();
        plan.approval = Some(
            json!({"required":true,"payload":returned,"message":returned_message,"method":"sep53"}),
        );
        plan.activation = Some(json!({"active":true}));
        plan.export = Some(descriptor.clone());
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
        let chain = Chain::new(c.clone());
        let caps = OwnerCapabilities {
            store: &store,
            rpc: &chain,
            signer: &signer,
            clock: &|| Ok(now),
        };
        let id = "server-activate-001";
        if substitute {
            assert!(client.activate(caps, &selected, id).is_err());
            assert_eq!(signer.calls.load(Ordering::SeqCst), prior);
            assert_eq!(server.calls("/api/micro/allocation/confirm"), 0);
        } else {
            let request = super::GenerateRequest {
                prompt: p.original_intent.clone(),
                network: p.network.clone(),
                profile: p.runtime.wallet.profile.clone(),
                target: super::Target::NewWallet,
            };
            let generated = client.generate(&request, now).unwrap();
            assert_eq!(generated.code, p.code);
            assert_eq!(
                generated
                    .runtime
                    .instance_binding
                    .installed_source
                    .as_deref(),
                Some(prefix.as_str())
            );
            let out = client.activate(caps, &selected, id).unwrap();
            assert_eq!(out.state, "active");
            assert_eq!(out.selection.policy.code, p.code);
            assert_eq!(
                client.activate(caps, &selected, id).unwrap().state,
                "active"
            );
            assert_eq!(signer.calls.load(Ordering::SeqCst), prior + 1);
            let submitted = server.state.lock().unwrap().owner_activations.clone();
            assert_eq!(submitted.len(), 2);
            for request in submitted {
                assert_eq!(
                    request["stellarSourceApproval"],
                    json!([{"signer":c.owner,"signature":expected_signature.to_vec()}])
                );
            }
            assert_eq!(
                client.export(&store, &selected, &chain, id, now).unwrap(),
                descriptor
            );
            let mut saved: Value = store.load(id).unwrap().unwrap();
            saved["signature"]["signature"][0] = json!(expected_signature[0] ^ 1);
            store.save(id, &saved).unwrap();
            assert!(client.export(&store, &selected, &chain, id, now).is_err());
            assert_eq!(server.calls("/api/native/export"), 1);
        }
    }
}

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
        let caps = OwnerCapabilities {
            store: &store,
            rpc: &chain,
            signer: &bad,
            clock: &|| Ok(now),
        };
        assert!(
            client
                .fund(caps, &selected, "fund-test-001", "1", 10_000)
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
            let caps = OwnerCapabilities {
                store: &store,
                rpc: &chain,
                signer: &signer,
                clock: &|| Ok(now),
            };
            assert!(
                client
                    .fund(caps, &selected, "fund-test-001", "1", 10_000)
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
    let caps = OwnerCapabilities {
        store: &store,
        rpc: &chain,
        signer: &signer,
        clock: &|| Ok(now),
    };
    assert_eq!(
        client
            .fund(caps, &selected, "fund-lost-001", "1", 10_000)
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
    let caps = OwnerCapabilities {
        store: &reopened,
        rpc: &chain,
        signer: &signer,
        clock: &|| Ok(now + 301),
    };
    let out = client
        .fund(caps, &selected, "fund-lost-001", "1", 10_000)
        .unwrap();
    assert_eq!(out.state, "funded");
    assert_eq!(signer.calls.load(Ordering::SeqCst), prior + 1);
    let state = server.state.lock().unwrap();
    assert_eq!(state.owner_submissions.len(), 2);
    assert!(
        state
            .owner_submissions
            .iter()
            .all(|s| s["transactionXdr"] == signed)
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
        profile: "allowit-stellar-policy-wallet-v1".into(),
        target: Target::NewWallet,
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
