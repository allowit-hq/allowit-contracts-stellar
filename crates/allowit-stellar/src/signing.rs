//! Native local keys and message-signing semantics. None of these primitives grants authority.
use crate::{Result, account_for_seed, account_key, hash};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use zeroize::{Zeroize, Zeroizing};

pub const KEY_ENTROPY_BYTES: usize = 32;
pub const KEY_TYPE: &str = "ed25519";

/// A private native key. It is deliberately neither serializable nor printable.
pub struct LocalSigner {
    seed: Zeroizing<[u8; 32]>,
    account: String,
}
impl LocalSigner {
    /// Derive a native key from caller-supplied operating-system entropy.
    pub fn from_entropy(entropy: &[u8]) -> Result<Self> {
        let seed: &[u8; 32] = entropy.try_into().map_err(|_| "Invalid key entropy size")?;
        Ok(Self {
            seed: Zeroizing::new(*seed),
            account: account_for_seed(seed),
        })
    }
    /// Decode the canonical private-file representation without exposing its value in errors.
    pub fn from_encoded(value: &str) -> Result<Self> {
        let mut private = stellar_strkey::ed25519::PrivateKey::from_string(value)
            .map_err(|_| "Invalid local Stellar signer")?;
        let result = Self::from_entropy(&private.0);
        private.0.zeroize();
        result
    }
    pub fn account(&self) -> &str {
        &self.account
    }
    /// Encode only for an explicitly requested private-file write or export.
    pub fn encoded_secret(&self) -> Zeroizing<String> {
        let mut private = stellar_strkey::ed25519::PrivateKey(*self.seed);
        let encoded = Zeroizing::new(private.to_string());
        private.0.zeroize();
        encoded
    }
    /// Low-level signing. The caller must independently authorize this exact digest.
    pub fn sign_digest(&self, digest: &[u8]) -> Result<Vec<u8>> {
        let digest: &[u8; 32] = digest
            .try_into()
            .map_err(|_| "Invalid signing digest size")?;
        Ok(SigningKey::from_bytes(&self.seed)
            .sign(digest)
            .to_bytes()
            .to_vec())
    }
}

/// A canonical account identity, without interpreting a valid address as signing authority.
pub fn canonical_account_key(account: &str) -> Result<[u8; 32]> {
    let key = account_key(account)?;
    if stellar_strkey::ed25519::PublicKey(key).to_string() != account {
        return Err("Expected a canonical Stellar G account".into());
    }
    Ok(key)
}

/// Check the public metadata that accompanies a local native key.
pub fn validate_key_identity(address: &str, public_key: &str, key_type: &str) -> Result<()> {
    if key_type != KEY_TYPE {
        return Err("Invalid public key type".into());
    }
    let key = canonical_account_key(public_key)?;
    VerifyingKey::from_bytes(&key).map_err(|_| "Invalid public point")?;
    if address != stellar_strkey::ed25519::PublicKey(key).to_string() {
        return Err("Address differs from public key".into());
    }
    Ok(())
}

/// Verify the exact native digest. Length, key and weak-signature checks fail closed.
pub fn verify_digest(account: &str, digest: &[u8; 32], signature: &[u8]) -> Result<()> {
    let signature = Signature::from_slice(signature).map_err(|_| "Invalid signature size")?;
    VerifyingKey::from_bytes(&canonical_account_key(account)?)
        .map_err(|_| "Invalid signing account")?
        .verify_strict(digest, &signature)
        .map_err(|_| "Signing capability returned an invalid signature".into())
}

/// SEP-53 domain separation, shared by sign-in and explicit source consent.
pub fn signed_message_digest(message: &str) -> [u8; 32] {
    let mut bytes = b"Stellar Signed Message:\n".to_vec();
    bytes.extend_from_slice(message.as_bytes());
    hash(bytes)
}

/// Native signing domain and wire identifier selected by common request-proof coordination.
pub const REQUEST_PROOF_DOMAIN: &str = "allowit-stellar-request-v1";
pub const REQUEST_PROOF_SCHEME: &str = "stellar-proof";
pub const REQUEST_PROOF_SIGNATURE_BYTES: usize = 64;

/// Parse the exact native sign-in message selected by the caller.
/// The caller checks the returned timestamps, expiry field and challenge freshness.
pub fn sign_in_message_times<'a>(
    message: &'a str,
    owner: &str,
    origin: &str,
    nonce: &str,
) -> Result<(&'a str, &'a str)> {
    canonical_account_key(owner)?;
    if allowit_policy_sdk::client::config::parse_origin(origin)
        .map_err(|_| "Invalid sign-in Origin")?
        != origin
        || nonce.len() != 64
        || !nonce
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("Invalid sign-in identity or Origin".into());
    }
    let host = origin.split_once("://").ok_or("Invalid sign-in Origin")?.1;
    let prefix = format!(
        "{host} wants you to sign in with your Stellar account:\n{owner}\n\nSign in to AllowIt. This does not authorize spending or move funds.\n\nURI: {origin}\nVersion: 1\nNonce: {nonce}\nIssued At: "
    );
    message
        .strip_prefix(&prefix)
        .and_then(|s| s.split_once("\nExpiration Time: "))
        .ok_or_else(|| "Owner sign-in message differs from its exact account and Origin".into())
}

/// Borrowed inputs of the existing native v1 owner source-consent protocol.
/// Encoding binds bytes only. The caller independently checks authority and approved identity.
pub struct SourceApproval<'a, P: serde::Serialize> {
    pub policy_id: &'a str,
    pub revision: u32,
    pub network: &'a str,
    pub wallet: &'a str,
    pub route: &'a str,
    pub policy_instance: &'a [u8; 32],
    pub source: &'a str,
    pub source_hash: &'a str,
    pub ir_hash: &'a str,
    pub module_digest: &'a str,
    pub asset: &'a str,
    pub asset_symbol: &'a str,
    pub asset_issuer: &'a Option<String>,
    pub max_fee_stroops: u32,
    pub language: &'a str,
    pub tier: &'a str,
    pub rules: &'a [String],
    pub params: &'a P,
    pub params_hash: &'a str,
}
/// Encode all fields of the existing native v1 source-consent payload.
pub fn source_approval_payload<P: serde::Serialize>(
    a: &SourceApproval<'_, P>,
) -> Result<serde_json::Value> {
    let params =
        serde_json::to_value(a.params).map_err(|_| "Cannot encode exact source consent")?;
    Ok(
        serde_json::json!({"version":1,"policyId":a.policy_id,"revision":a.revision,
        "network":a.network,"wallet":a.wallet,"route":a.route,
        "policyInstance":crate::hex(a.policy_instance),"source":a.source,
        "sourceHash":a.source_hash,"irHash":a.ir_hash,"moduleDigest":a.module_digest,
        "asset":a.asset,"assetSymbol":a.asset_symbol,"assetIssuer":a.asset_issuer,
        "maxFeeStroops":a.max_fee_stroops,"language":a.language,"tier":a.tier,
        "rules":a.rules,"params":params,"paramsHash":a.params_hash}),
    )
}
/// Canonical native consent text. Signing or decoding this text does not establish authority.
pub fn source_approval_message(payload: &serde_json::Value) -> Result<String> {
    serde_json_canonicalizer::to_string(payload)
        .map(|json| format!("AllowIt Native policy approval v1\n{json}"))
        .map_err(|_| "Cannot encode exact source consent".into())
}
