//! Stellar owner consent for a server policy on an installed policy wallet.

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use stellar_strkey::{Contract, ed25519::PublicKey};

pub const SERVER_POLICY_APPROVAL_PROFILE: &str = "allowit-stellar-server-policy-approval-v1";
const MESSAGE_PREFIX: &str = "AllowIt Stellar server policy approval v1\n";

/// Exact source and installation identity. The host must independently check the live wallet
/// owner, installed source, module, params and binding registry before it accepts this proof.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServerPolicyApproval {
    pub profile: String,
    pub network: String,
    pub wallet: String,
    pub owner: String,
    pub policy_id: String,
    pub revision: u32,
    pub policy_instance: String,
    pub module_digest: String,
    pub installed_source_hash: String,
    pub source: String,
    pub source_hash: String,
    pub params_hash: String,
    pub server_bindings: String,
}

impl ServerPolicyApproval {
    /// Encode the distinct server consent domain. Native consent messages keep their own codec.
    pub fn message(&self) -> Result<String, String> {
        self.owner_key()?;
        self.message_with_checked_owner()
    }

    /// Verify the SEP-53 signature from the independently established policy wallet owner.
    pub fn verify(&self, expected_owner: &str, signature: &[u8]) -> Result<(), String> {
        if self.owner != expected_owner {
            return Err("The server policy approval names another owner.".into());
        }
        let owner = self.owner_key()?;
        let message = self.message_with_checked_owner()?;
        let signature = Signature::from_slice(signature)
            .map_err(|_| "Invalid server policy approval signature size.")?;
        owner
            .verify_strict(&message_digest(&message), &signature)
            .map_err(|_| "Invalid server policy approval signature.".into())
    }

    fn owner_key(&self) -> Result<VerifyingKey, String> {
        let owner = PublicKey::from_string(&self.owner)
            .map_err(|_| "Invalid server policy approval owner.")?;
        if owner.to_string() != self.owner {
            return Err("Invalid server policy approval owner.".into());
        }
        VerifyingKey::from_bytes(&owner.0)
            .map_err(|_| "Invalid server policy approval owner.".into())
    }

    fn message_with_checked_owner(&self) -> Result<String, String> {
        if self.profile != SERVER_POLICY_APPROVAL_PROFILE
            || crate::networks::resolve(&self.network).is_none()
            || Contract::from_string(&self.wallet)
                .ok()
                .is_none_or(|wallet| wallet.to_string() != self.wallet)
            || !(1..=128).contains(&self.policy_id.len())
            || !self
                .policy_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
            || self.revision == 0
            || !(1..=32_768).contains(&self.source.len())
            || self.source_hash != format!("{:x}", Sha256::digest(self.source.as_bytes()))
            || ![
                &self.policy_instance,
                &self.module_digest,
                &self.installed_source_hash,
                &self.params_hash,
                &self.server_bindings,
            ]
            .into_iter()
            .all(|value| lower_hash(value))
        {
            return Err("Invalid Stellar server policy approval identity.".into());
        }
        serde_json_canonicalizer::to_string(self)
            .map(|payload| format!("{MESSAGE_PREFIX}{payload}"))
            .map_err(|_| "Cannot encode exact server policy approval.".into())
    }
}

fn lower_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn message_digest(message: &str) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"Stellar Signed Message:\n");
    digest.update(message.as_bytes());
    digest.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::{Value, json};

    fn fixture() -> Value {
        serde_json::from_str(include_str!(
            "../tests/fixtures/server-policy-approval.json"
        ))
        .unwrap()
    }

    #[test]
    fn exact_browser_message_and_owner_signature_match() {
        let fixture = fixture();
        let approval: ServerPolicyApproval =
            serde_json::from_value(fixture["payload"].clone()).unwrap();
        let message = approval.message().unwrap();
        assert_eq!(message, fixture["message"]);
        let digest = message_digest(&message);
        assert_eq!(
            digest
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
            fixture["digest"]
        );
        let owner = SigningKey::from_bytes(&[7; 32]);
        let signature = owner.sign(&digest).to_bytes();
        approval.verify(&approval.owner, &signature).unwrap();
        let wrong_owner = PublicKey(SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes());
        assert!(
            approval
                .verify(&wrong_owner.to_string(), &signature)
                .is_err()
        );
        let native = message.replacen(MESSAGE_PREFIX, "AllowIt Native policy approval v1\n", 1);
        assert!(
            approval
                .verify(
                    &approval.owner,
                    &owner.sign(&message_digest(&native)).to_bytes()
                )
                .is_err()
        );
    }

    #[test]
    fn signature_rejects_source_and_installation_substitution() {
        let fixture = fixture();
        let payload = &fixture["payload"];
        let approval: ServerPolicyApproval = serde_json::from_value(payload.clone()).unwrap();
        let signature = SigningKey::from_bytes(&[7; 32])
            .sign(&message_digest(&approval.message().unwrap()))
            .to_bytes();
        for (field, value) in [
            ("source", json!("changed source")),
            ("sourceHash", json!("55".repeat(32))),
            ("network", json!("stellar:pubnet")),
            ("wallet", json!(Contract([3; 32]).to_string())),
            ("policyId", json!("other-policy")),
            ("revision", json!(3)),
            ("policyInstance", json!("55".repeat(32))),
            ("moduleDigest", json!("55".repeat(32))),
            ("installedSourceHash", json!("55".repeat(32))),
            ("paramsHash", json!("55".repeat(32))),
            ("serverBindings", json!("55".repeat(32))),
        ] {
            let mut changed = payload.clone();
            changed[field] = value;
            let changed: ServerPolicyApproval = serde_json::from_value(changed).unwrap();
            assert!(
                changed.verify(&approval.owner, &signature).is_err(),
                "{field}"
            );
        }
        let mut extra = payload.clone();
        extra["route"] = json!("native");
        assert!(serde_json::from_value::<ServerPolicyApproval>(extra).is_err());
    }
}
