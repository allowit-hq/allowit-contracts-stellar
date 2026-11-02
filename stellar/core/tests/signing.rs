use allowit_stellar_wallet::{self as native, signing};
use ed25519_dalek::{Signer as _, SigningKey};

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
