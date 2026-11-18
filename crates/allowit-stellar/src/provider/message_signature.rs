//! The rail's text-message signature: SEP-53, the signature that a Stellar browser wallet makes
//! with `signMessage`. A server signs its own statements with it, such as the request of a signed
//! fetch, and anyone verifies them with the server's public identity.
use crate::host::{
    Signer,
    error::{Error, Result},
};
use allowit_core::vendor::wallet::MessageSignature;

pub struct MessageSigning;
pub static MESSAGE_SIGNING: MessageSigning = MessageSigning;

impl MessageSignature for MessageSigning {
    /// A SEP-53 message signature: the one that a browser wallet makes with `signMessage`.
    fn sign_message(&self, signer: &dyn Signer, message: &str) -> Result<Vec<u8>> {
        signer.sign_hash(&crate::signing::signed_message_digest(message))
    }
    fn verify_message(
        &self,
        network: &str,
        address: &str,
        message: &str,
        signature: &[u8],
    ) -> Result<()> {
        crate::host::routing::normalize(network)?;
        crate::signing::verify_digest(
            address,
            &crate::signing::signed_message_digest(message),
            signature,
        )
        .map_err(|_| Error::usage("The message signature is invalid"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NETWORK: &str = "stellar:testnet";

    struct Key(crate::signing::LocalSigner);
    fn key(seed: u8) -> Key {
        Key(crate::signing::LocalSigner::from_entropy(&[seed; 32]).unwrap())
    }
    impl Signer for Key {
        fn network(&self) -> &str {
            NETWORK
        }
        fn address(&self) -> &str {
            self.0.account()
        }
        fn sign_hash(&self, digest: &[u8]) -> Result<Vec<u8>> {
            self.0.sign_digest(digest).map_err(Error::config)
        }
    }

    #[test]
    fn a_message_signature_is_the_wallet_message_signature_of_its_text() {
        let server = key(1);
        let message = "Allowit signed request v1\nexample";
        let signature = MESSAGE_SIGNING.sign_message(&server, message).unwrap();
        // The signature is the SEP-53 signature of the message text, as a wallet makes it.
        let wallet = server
            .0
            .sign_digest(&crate::signing::signed_message_digest(message))
            .unwrap();
        assert_eq!(signature, wallet);
        MESSAGE_SIGNING
            .verify_message(NETWORK, server.address(), message, &signature)
            .unwrap();
        // Another key, another text and another network spelling that is no network.
        assert!(
            MESSAGE_SIGNING
                .verify_message(NETWORK, key(2).address(), message, &signature)
                .is_err()
        );
        assert!(
            MESSAGE_SIGNING
                .verify_message(NETWORK, server.address(), "another text", &signature)
                .is_err()
        );
        assert!(
            MESSAGE_SIGNING
                .verify_message("unknown:network", server.address(), message, &signature)
                .is_err()
        );
    }

    #[test]
    fn a_raw_signature_of_the_text_is_not_a_message_signature() {
        // A signature of the message bytes without the SEP-53 prefix is refused.
        let server = key(1);
        let message = "Allowit signed request v1\nexample";
        let raw = server
            .0
            .sign_digest(&crate::hash(message.as_bytes()))
            .unwrap();
        assert!(
            MESSAGE_SIGNING
                .verify_message(NETWORK, server.address(), message, &raw)
                .is_err()
        );
    }
}
