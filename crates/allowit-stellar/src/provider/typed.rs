//! Typed agent requests. A rail adapter builds the canonical SDK
//! `ExecutionRequest` from the `exec` flags; the engine receives only typed
//! requests. The envelope is `{"requestId", "input": {"kind", "request"}}`.
use crate::host::{
    error::{Error, Result},
    typed_request::operation_nonce,
};
use crate::workflow::ExecutionRequest;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq)]
pub struct TypedRequest {
    pub request_id: String,
    pub request: ExecutionRequest,
}

#[derive(Serialize)]
struct Wire<'a> {
    #[serde(rename = "requestId")]
    request_id: &'a str,
    input: WireInput<'a>,
}
#[derive(Serialize)]
#[serde(tag = "kind", content = "request")]
enum WireInput<'a> {
    #[serde(rename = "execution-request")]
    Execution(&'a ExecutionRequest),
}

impl TypedRequest {
    /// Binds a request to its policy and request ID through the version 1
    /// operation nonce.
    pub fn new(policy_id: &str, request_id: &str, request: ExecutionRequest) -> Result<Self> {
        if request.operation.nonce != operation_nonce(policy_id, request_id) {
            return Err(Error::usage(
                "operation.nonce is not the version 1 nonce for this policy ID and requestId",
            ));
        }
        Ok(Self {
            request_id: request_id.into(),
            request,
        })
    }
    /// The canonical envelope of the validated values.
    pub fn wire(&self) -> Result<serde_json::Value> {
        serde_json::to_value(Wire {
            request_id: &self.request_id,
            input: WireInput::Execution(&self.request),
        })
        .map_err(|_| Error::usage("the typed request cannot be encoded"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    const ENVELOPE: &str =
        include_str!("../../tests/fixtures/provider/typed/execution-envelope-v1.json");
    const VECTOR: &str =
        include_str!("../../tests/fixtures/provider/typed/operation-vector-v1.json");
    const POLICY: &str = "owner-policy_Example-A";
    const ID: &str = "cli-native-transfer-01";

    fn fixture() -> (Value, ExecutionRequest) {
        let envelope: Value = serde_json::from_str(ENVELOPE).unwrap();
        let request = serde_json::from_value(envelope["input"]["request"].clone()).unwrap();
        (envelope, request)
    }
    #[test]
    fn canonical_envelope_round_trips_through_the_typed_request() {
        let (envelope, request) = fixture();
        let typed = TypedRequest::new(POLICY, ID, request).unwrap();
        assert_eq!(typed.wire().unwrap(), envelope);
        let vector: Value = serde_json::from_str(VECTOR).unwrap();
        let nonce: Vec<u8> = serde_json::from_value(vector["nonce"].clone()).unwrap();
        assert_eq!(operation_nonce(POLICY, ID).to_vec(), nonce);
    }
    #[test]
    fn amount256_bytes_survive_canonical_wire_encoding() {
        let (_, request) = fixture();
        let mut expected = [0u8; 32];
        expected[30..].copy_from_slice(&1000u16.to_be_bytes());
        assert_eq!(request.effect_bounds[0].max_debit.0, expected);
    }
    #[test]
    fn nonce_binds_the_exact_policy_and_request_id() {
        let (_, request) = fixture();
        for (policy, id) in [
            ("owner-policy_example-a", ID),
            ("owner-policy_Example-A ", ID),
            (POLICY, "cli-native-transfer-02"),
        ] {
            assert!(
                TypedRequest::new(policy, id, request.clone())
                    .unwrap_err()
                    .message
                    .contains("nonce")
            );
        }
    }
}
