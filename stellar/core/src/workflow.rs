//! Native Stellar request records. The host authenticates inputs and installed profiles.
//! These results establish facts, never spending authorization or settlement.
use serde::{Deserialize, Serialize};
use std::{string::String, vec::Vec};

pub type Digest = [u8; 32];
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Amount256(pub [u8; 32]);
impl From<u64> for Amount256 {
    fn from(value: u64) -> Self {
        let mut bytes = [0; 32];
        bytes[24..].copy_from_slice(&value.to_be_bytes());
        Self(bytes)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Chain {
    Stellar,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccountKind {
    Wallet,
    Contract,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountId {
    pub chain: Chain,
    pub kind: AccountKind,
    pub address: Digest,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssetId {
    pub network: Digest,
    pub token: AccountId,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum WorkflowAsset {
    Native { chain: Chain, network: Digest },
    Token(AssetId),
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationRef {
    pub policy_instance: Digest,
    pub nonce: Digest,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceKind {
    Quote,
    PaymentChallenge,
    ExternalClaim,
    ServiceMessage,
    PreferenceAssessment,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRef {
    pub namespace_id: u32,
    pub schema: u16,
    pub kind: EvidenceKind,
    pub digest: Digest,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowEffectBound {
    pub asset: WorkflowAsset,
    pub source: AccountId,
    pub beneficiary: AccountId,
    pub max_debit: Amount256,
    pub min_credit: Amount256,
    pub max_burn: Amount256,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowFeeBound {
    pub payer: AccountId,
    pub asset: WorkflowAsset,
    pub max_fee: Amount256,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AbiValue {
    Bool(bool),
    Unsigned(Amount256),
    Signed128(i128),
    Account(AccountId),
    Bytes(Vec<u8>),
    Text(String),
    Tuple(Vec<AbiValue>),
    Array(Vec<AbiValue>),
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum NativeInstruction {
    StellarNativeTransfer {
        source: AccountId,
        destination: AccountId,
        stroops: u64,
    },
    StellarCall {
        contract: AccountId,
        schema_digest: Digest,
        function: String,
        arguments: Vec<AbiValue>,
    },
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ExecutionInput {
    Instructions(Vec<NativeInstruction>),
    Message(Vec<u8>),
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionRequest {
    pub operation: OperationRef,
    pub input: ExecutionInput,
    pub effect_bounds: Vec<WorkflowEffectBound>,
    pub fee_bounds: Option<Vec<WorkflowFeeBound>>,
    pub evidence: Vec<EvidenceRef>,
}
