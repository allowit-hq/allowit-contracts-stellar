use allowit_stellar_wallet::{self as native, signing};
use ed25519_dalek::{Signer as _, SigningKey};

#[test]
fn classic_roles_and_admin_quorum_bind_current_independent_identities() {
    let owner = native::account_for_seed(&[1; 32]);
    let agent = native::account_for_seed(&[2; 32]);
    let server = native::account_for_seed(&[3; 32]);
    let stranger = native::account_for_seed(&[4; 32]);
    let state = native::AccountState {
        address: owner.clone(),
        sequence: 42,
        master_weight: 3,
        low_threshold: 2,
        medium_threshold: 2,
        high_threshold: 3,
        signers: vec![
            native::AccountSigner {
                key: agent.clone(),
                weight: 1,
            },
            native::AccountSigner {
                key: server.clone(),
                weight: 1,
            },
        ],
    };
    state.validate_roles(&owner, &agent, &server).unwrap();
    let mut reordered = state.clone();
    reordered.signers.reverse();
    reordered.validate_roles(&owner, &agent, &server).unwrap();
    for (o, a, s) in [
        (&stranger, &agent, &server),
        (&owner, &owner, &server),
        (&owner, &agent, &agent),
        (&owner, &agent, &stranger),
    ] {
        assert!(state.validate_roles(o, a, s).is_err());
    }
    for field in 0..7 {
        let mut changed = state.clone();
        match field {
            0 => changed.master_weight = 2,
            1 => changed.low_threshold = 1,
            2 => changed.medium_threshold = 1,
            3 => changed.high_threshold = 2,
            4 => changed.signers[0].weight = 0,
            5 => changed.signers[0].key = stranger.clone(),
            _ => changed.signers.push(native::AccountSigner {
                key: stranger.clone(),
                weight: 0,
            }),
        }
        assert!(changed.validate_roles(&owner, &agent, &server).is_err());
    }
    let digest = signing::signed_message_digest("unchanged source approval v1 bytes");
    let signature = |n| native::DetachedSignature {
        signer: native::account_for_seed(&[n; 32]),
        signature: SigningKey::from_bytes(&[n; 32])
            .sign(&digest)
            .to_bytes()
            .to_vec(),
    };
    state
        .validate_authority_signatures(&digest, &[signature(1)])
        .unwrap();
    assert!(
        state
            .validate_authority_signatures(&digest, &[signature(2), signature(3)])
            .is_err()
    );
    assert!(
        state
            .validate_authority_signatures(&digest, &[signature(1), signature(4)])
            .is_err()
    );
    assert!(
        state
            .validate_authority_signatures(&digest, &[signature(1), signature(1)])
            .is_err()
    );
    assert!(
        state
            .validate_authority_signatures(&native::hash(b"other"), &[signature(1)])
            .is_err()
    );
    let mut inactive = state.clone();
    inactive.signers[0].weight = 0;
    assert!(
        inactive
            .validate_authority_signatures(&digest, &[signature(1), signature(2)])
            .is_err()
    );
    let mut rotated = state;
    rotated.master_weight = 0;
    rotated.signers[0].weight = 3;
    assert!(
        rotated
            .validate_authority_signatures(&digest, &[signature(1)])
            .is_err()
    );
    rotated
        .validate_authority_signatures(&digest, &[signature(2)])
        .unwrap();
}

#[test]
fn native_key_codec_preserves_existing_files_and_signatures() {
    assert_eq!(
        signing::canonical_account_key("GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF")
            .unwrap(),
        [0; 32]
    );
    for seed in [[0; 32], [7; 32], [255; 32]] {
        let signer = signing::LocalSigner::from_entropy(&seed).unwrap();
        let encoded = signer.encoded_secret();
        assert_eq!(native::decode_seed(&encoded).unwrap(), seed);
        let restored = signing::LocalSigner::from_encoded(&encoded).unwrap();
        assert_eq!(restored.account(), native::account_for_seed(&seed));
        signing::validate_key_identity(restored.account(), restored.account(), "ed25519").unwrap();
        let digest = native::hash(b"exact caller-approved intent");
        let actual = restored.sign_digest(&digest).unwrap();
        assert_eq!(
            actual,
            SigningKey::from_bytes(&seed).sign(&digest).to_bytes()
        );
        signing::verify_digest(restored.account(), &digest, &actual).unwrap();
    }
    assert!(signing::LocalSigner::from_entropy(&[0; 31]).is_err());
    assert!(signing::LocalSigner::from_encoded("not a key").is_err());
}

#[test]
fn signatures_bind_exact_domains_bytes_and_public_identity() {
    let signer = signing::LocalSigner::from_entropy(&[7; 32]).unwrap();
    let message = "exact UTF-8 policy consent: £5\n";
    let digest = signing::signed_message_digest(message);
    let mut old = b"Stellar Signed Message:\n".to_vec();
    old.extend_from_slice(message.as_bytes());
    assert_eq!(digest, native::hash(old));
    let signature = signer.sign_digest(&digest).unwrap();
    signing::verify_digest(signer.account(), &digest, &signature).unwrap();
    for changed in [
        native::hash(message),
        signing::signed_message_digest("changed"),
    ] {
        assert!(signing::verify_digest(signer.account(), &changed, &signature).is_err());
    }
    assert!(
        signing::verify_digest(&native::account_for_seed(&[8; 32]), &digest, &signature).is_err()
    );
    assert!(signing::verify_digest(signer.account(), &digest, &signature[..63]).is_err());
    assert!(signing::verify_digest(signer.account(), &digest, &[0; 64]).is_err());
    assert!(signer.sign_digest(&digest[..31]).is_err());
    assert!(signing::canonical_account_key(&signer.account().to_lowercase()).is_err());
    assert!(signing::validate_key_identity("different", signer.account(), "ed25519").is_err());
    assert!(signing::validate_key_identity(signer.account(), signer.account(), "other").is_err());
}

#[test]
fn sign_in_message_binds_canonical_account_origin_and_nonce() {
    let owner = native::account_for_seed(&[7; 32]);
    let origin = "http://localhost:5173";
    let nonce = "a".repeat(64);
    let message = format!(
        "localhost:5173 wants you to sign in with your Stellar account:\n{owner}\n\nSign in to AllowIt. This does not authorize spending or move funds.\n\nURI: {origin}\nVersion: 1\nNonce: {nonce}\nIssued At: 2026-11-02T00:00:00Z\nExpiration Time: 2026-11-02T00:05:00Z"
    );
    assert_eq!(
        signing::sign_in_message_times(&message, &owner, origin, &nonce).unwrap(),
        ("2026-11-02T00:00:00Z", "2026-11-02T00:05:00Z")
    );
    for (account, uri, challenge) in [
        (
            native::account_for_seed(&[8; 32]),
            origin.to_owned(),
            nonce.clone(),
        ),
        (owner.clone(), "http://localhost:5174".into(), nonce.clone()),
        (owner.clone(), origin.into(), "b".repeat(64)),
        (owner.clone(), origin.into(), "A".repeat(64)),
        (
            owner.clone(),
            "https://example.com/path".into(),
            nonce.clone(),
        ),
    ] {
        assert!(signing::sign_in_message_times(&message, &account, &uri, &challenge).is_err());
    }
    assert!(
        signing::sign_in_message_times(
            &message.replace("Stellar account", "Solana account"),
            &owner,
            origin,
            &nonce
        )
        .is_err()
    );
}

#[test]
fn service_proofs_bind_request_path_time_and_exact_body() {
    let owner = native::account_for_seed(&[7; 32]);
    let body = br#"{"network":"stellar:testnet","requestId":"one"}"#;
    let digest = signing::request_digest(42, "/api/native/execute", body);
    let mut old = b"allowit-stellar-request-v1\n42\n/api/native/execute\n".to_vec();
    old.extend_from_slice(body);
    assert_eq!(digest, native::hash(old));
    assert_ne!(
        digest,
        signing::request_digest(43, "/api/native/execute", body)
    );
    assert_ne!(
        digest,
        signing::request_digest(42, "/api/native/status", body)
    );
    assert_ne!(
        digest,
        signing::request_digest(42, "/api/native/execute", b"changed")
    );
    assert_eq!(
        signing::request_proof(&owner, 42, &[1; 64]).unwrap(),
        format!("Bearer stellar-proof.{owner}.42.{}", native::hex(&[1; 64]))
    );
    assert!(signing::request_proof(&owner, 42, &[1; 63]).is_err());
    assert!(signing::request_proof("untrusted\nheader", 42, &[1; 64]).is_err());
}

#[test]
fn network_inventory_owns_unique_canonical_and_alias_names() {
    let mut names = std::collections::BTreeSet::new();
    let descriptors = native::networks::NETWORKS;
    assert_eq!(descriptors.len(), 2);
    for network in descriptors {
        assert!(names.insert(network.id));
        assert_eq!(network.testnet, network.id == "stellar:testnet");
        for alias in network.aliases {
            assert!(names.insert(alias));
            assert_eq!(native::passphrase(alias), native::passphrase(network.id));
            assert_eq!(native::network_id(alias), native::network_id(network.id));
        }
    }
    assert_eq!(
        names,
        std::collections::BTreeSet::from(["stellar:testnet", "stellar:pubnet", "stellar:mainnet",])
    );
}

#[test]
fn canonical_networks_preserve_existing_native_passphrase_and_identity_bytes() {
    for (id, passphrase, network_id) in [
        (
            "stellar:testnet",
            "Test SDF Network ; September 2015",
            "cee0302d59844d32bdca915c8203dd44b33fbb7edc19051ea37abedf28ecd472",
        ),
        (
            "stellar:pubnet",
            "Public Global Stellar Network ; September 2015",
            "7ac33997544e3175d266bd022439b22cdb16508c01163f26e5cb2a3e1045a979",
        ),
        (
            "stellar:mainnet",
            "Public Global Stellar Network ; September 2015",
            "7ac33997544e3175d266bd022439b22cdb16508c01163f26e5cb2a3e1045a979",
        ),
    ] {
        assert_eq!(native::passphrase(id).unwrap(), passphrase);
        assert_eq!(native::hex(&native::network_id(id).unwrap()), network_id);
    }
    assert_ne!(
        native::network_id("stellar:testnet"),
        native::network_id("stellar:pubnet")
    );
    assert!(native::passphrase("stellar:futurenet").is_err());
}

#[test]
fn request_proof_verification_preserves_server_domain_and_exact_input() {
    let signer = signing::LocalSigner::from_entropy(&[7; 32]).unwrap();
    let now = 1_800_000_000;
    let path = "/api/native/prepare";
    let body = br#"{"requestId":"original","amount":"5"}"#;
    let digest = signing::request_digest(now, path, body);
    let proof =
        signing::request_proof(signer.account(), now, &signer.sign_digest(&digest).unwrap())
            .unwrap();
    let token = proof.strip_prefix("Bearer ").unwrap();
    assert_eq!(
        signing::verify_request_proof(token, now, path, body).unwrap(),
        signer.account()
    );
    for (time, route, data) in [
        (now + 121, path, body.as_slice()),
        (now - 121, path, body.as_slice()),
        (now, "/api/native/submit", body.as_slice()),
        (now, path, b"{}".as_slice()),
    ] {
        assert!(signing::verify_request_proof(token, time, route, data).is_err());
    }
    assert!(signing::verify_request_proof(&proof, now, path, body).is_err());
}
