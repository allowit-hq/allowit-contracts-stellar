use crate::host::{
    error::Error,
    request_proof::{Protocol, authorize, verify},
};
use crate::{self as native, signing};
fn protocol() -> Protocol {
    super::server::request_proof_protocol()
}
fn signer() -> signing::LocalSigner {
    signing::LocalSigner::from_entropy(&[7; 32]).unwrap()
}
fn proof(at: u64, path: &str, body: &[u8]) -> String {
    let signer = signer();
    authorize(protocol(), signer.account(), at, path, body, |digest| {
        signer.sign_digest(digest).map_err(Error::config)
    })
    .unwrap()
}
#[test]
fn wire_bytes_preserve_the_original_native_service_protocol() {
    let signer = signer();
    let body = br#"{"network":"stellar:testnet","requestId":"one"}"#;
    let mut old = b"allowit-stellar-request-v1\n42\n/api/native/execute\n".to_vec();
    old.extend_from_slice(body);
    let digest = native::hash(old);
    let original = format!(
        "Bearer stellar-proof.{}.42.{}",
        signer.account(),
        native::hex(&signer.sign_digest(&digest).unwrap())
    );
    assert_eq!(proof(42, "/api/native/execute", body), original);
}
#[test]
fn verification_binds_exact_body_path_identity_and_inclusive_time_window() {
    let now = 1_800_000_000;
    let path = "/api/native/prepare";
    let body = br#"{"requestId":"original","amount":"5"}"#;
    let bearer = proof(now, path, body);
    let token = bearer.strip_prefix("Bearer ").unwrap();
    for at in [now - 120, now, now + 120] {
        assert_eq!(
            verify(protocol(), token, at, path, body).unwrap(),
            signer().account()
        );
    }
    for (at, route, data) in [
        (now - 121, path, body.as_slice()),
        (now + 121, path, body.as_slice()),
        (now, "/api/native/submit", body.as_slice()),
        (now, path, b"{}".as_slice()),
        (
            now,
            path,
            br#"{ "requestId":"original","amount":"5"}"#.as_slice(),
        ),
    ] {
        assert!(verify(protocol(), token, at, route, data).is_err());
    }
    assert!(verify(protocol(), &bearer, now, path, body).is_err());
    for malformed in [
        "",
        "stellar-proof",
        "other.account.1.ab",
        "stellar-proof.a.not-time.ab",
        "stellar-proof.a.1800000000.zz",
        &"a".repeat(513),
    ] {
        assert!(verify(protocol(), malformed, now, path, body).is_err());
    }
    let wrong = token.replacen(signer().account(), &native::account_for_seed(&[8; 32]), 1);
    assert!(verify(protocol(), &wrong, now, path, body).is_err());
}
#[test]
fn signing_capability_must_return_a_valid_signature_before_header_encoding() {
    assert!(
        authorize(
            protocol(),
            signer().account(),
            42,
            "/api/native/execute",
            b"{}",
            |_| Ok(vec![0; 64])
        )
        .is_err()
    );
}
