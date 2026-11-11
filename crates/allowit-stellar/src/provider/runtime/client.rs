//! Agent requests for an installed Stellar wallet profile. The public wallet
//! profile names the wallet, its roles and the engine endpoints; the agent
//! key signs. Requests go to the profile's `/api/native/execute` endpoints and
//! are journaled in caller-supplied private storage before they leave the process.
use crate::host::{
    config::parse_origin,
    error::{Error, Result},
    execution::{LimitReport, Quantity},
    input::asset::AssetDisplay,
    typed_request::operation_nonce,
};
use crate::rpc::Rpc;
use crate::workflow::ExecutionRequest;
use crate::{
    self as sdk, DetachedSignature, OperationStatus, PreparedOperation, SignedOperation,
    WalletConfig, WalletRoute,
};
use allowit_core::{
    client::{progress, store::Store},
    transport::{
        http::{HttpClient, Method, Request},
        rpc::Options,
    },
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    path::Path,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

/// The query that asks the engine for the fee that the limits count and for the spending limits
/// of the policy. It is outside the request proof and changes only the reply.
const REPORTS: &str = "?include=limits";

/// Every engine call waits up to this long. Prepare, submit and status each run tens of
/// sequential ledger reads and simulations on the server, and submit also broadcasts and
/// polls for the receipt. At public RPC latency (about 5 s per call) these took up to 138 s.
const ENGINE_TIMEOUT: Duration = Duration::from_secs(180);

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Bundle {
    version: u8,
    profile: String,
    pub network: String,
    pub policy_id: String,
    #[serde(default)]
    language: Option<String>,
    #[serde(default)]
    portable: Option<PortableProfile>,
    source_hash: String,
    #[serde(default)]
    ir_hash: String,
    pub module_digest: String,
    pub wallet: String,
    route: WalletRoute,
    pub config: WalletConfig,
    endpoints: Endpoints,
    #[serde(default)]
    source_approval: Option<SourceApproval>,
    /// The wallet kind that a server names at the top level of a wallet document. It is
    /// optional; when present it must be the kind that `config` binds.
    #[serde(default)]
    wallet_kind: Option<allowit_core::vendor::kinds::WalletKind>,
    /// A public profile never holds this; reading refuses a file that does.
    #[serde(default, deserialize_with = "local_secret")]
    signing_seed: Option<Zeroizing<String>>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SourceApproval {
    revision: u32,
    signatures: Vec<DetachedSignature>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PortableProfile {
    language: String,
    source_hash: String,
    tier: String,
    #[serde(default)]
    rules: Vec<String>,
    params: sdk::PolicyParams,
    params_hash: String,
    asset: PortableAsset,
    unresolved: Vec<String>,
    build: PortableBuild,
    #[serde(default)]
    kinds: std::collections::BTreeMap<String, String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PortableAsset {
    symbol: String,
    address: String,
    decimals: u32,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PortableBuild {
    prefix: Vec<String>,
    writes_state: bool,
    library_revision: String,
    attempts: usize,
}
fn validate_portable_profile(bundle: &Bundle) -> Result<()> {
    let Some(portable) = &bundle.portable else {
        return Err(Error::config(
            "The portable Stellar profile is missing its source binding",
        ));
    };
    let shape = crate::host::authoring::check(&bundle.config.policy_source)?;
    let params_hash = crate::host::authoring::canonical_digest(&portable.params)?;
    if bundle.language.as_deref() != Some("allowit-portable-v1")
        || portable.language != "allowit-portable-v1"
        || portable.source_hash != bundle.source_hash
        || portable.params != bundle.config.params
        || portable.params_hash != params_hash
        || portable.asset.address != bundle.config.asset
        || portable.asset.symbol != bundle.config.asset_symbol
        || portable.asset.decimals != 7
        || !portable.unresolved.is_empty()
        || portable.build.prefix != shape.prefix
        || portable.build.writes_state != shape.writes_state
    {
        return Err(Error::config(
            "The portable Stellar descriptor differs from its installed configuration",
        ));
    }
    let tier = match portable.tier.as_str() {
        "standard" => sdk::PolicyTier::Common,
        "custom" => sdk::PolicyTier::Custom,
        _ => return Err(Error::config("Invalid portable Stellar policy tier")),
    };
    checked(portable.params.check(tier))?;
    checked(sdk::policy::parse_rules(&portable.rules))?;
    // Library revision, attempts and param kinds describe authoring. They are never
    // publication proof or signing authority supplied by the public descriptor.
    let _ = (
        &portable.build.library_revision,
        portable.build.attempts,
        &portable.kinds,
    );
    if bundle.route == WalletRoute::Native {
        if bundle.config.tier.is_some()
            || bundle.config.source_digest != [0; 32]
            || (!bundle.config.rules.is_empty() && bundle.config.rules != portable.rules)
        {
            return Err(Error::config(
                "Native configuration contradicts its signed portable binding",
            ));
        }
        let identity = crate::host::authoring::portable_identity(
            &portable.language,
            &portable.tier,
            &portable.rules,
            &portable.source_hash,
            &portable.params_hash,
        )?;
        if identity != bundle.module_digest {
            return Err(Error::config(
                "The Native Stellar module identity differs from its portable source",
            ));
        }
    }
    Ok(())
}
fn local_secret<'de, D: serde::Deserializer<'de>>(
    decoder: D,
) -> std::result::Result<Option<Zeroizing<String>>, D::Error> {
    String::deserialize(decoder).map(|value| Some(Zeroizing::new(value)))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Endpoints {
    execute: String,
    status: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Response {
    prepared: PreparedOperation,
    operation: Operation,
    signed_operation: Option<SignedOperation>,
    receipt: Option<sdk::rpc::VerifiedReceipt>,
    /// The engine's own settlement report. This client reports the settlement of the receipt
    /// that it verified, so the value is accepted and not read.
    #[serde(default, rename = "settlement")]
    _settlement: Option<serde::de::IgnoredAny>,
    /// The fee that the spending limits count for this operation, in the installed asset. The
    /// engine sends it and `limits` for [`REPORTS`]. Both are engine statements with no chain
    /// proof; [`reported`] and [`reported_limits`] admit them as display data.
    #[serde(default)]
    fee_charged: Option<serde_json::Value>,
    #[serde(default)]
    limits: Option<serde_json::Value>,
    /// Engine links and the wallet kind are accepted and not read: the rail builds its own
    /// explorer link, and the profile binds the kind.
    #[serde(default, rename = "explorer")]
    _explorer: Option<serde::de::IgnoredAny>,
    #[serde(default, rename = "walletKind")]
    _wallet_kind: Option<serde::de::IgnoredAny>,
    /// The engine reported this policy wallet operation `failed` without a chain receipt: it
    /// released the operation. The status stays `submissionUnknown` until the client proves
    /// the release itself.
    #[serde(skip)]
    released: bool,
    /// This client proved, or its journal retains its proof, that the packet lapsed without
    /// executing.
    #[serde(skip)]
    lapsed: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Operation {
    id: String,
    status: OperationStatus,
    transaction_hash: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Record {
    /// Original service identity for new records. Old records rely on caller-retained bindings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    backend_origin: Option<String>,
    policy_id: String,
    request_id: String,
    config: WalletConfig,
    request: ExecutionRequest,
    prepared: Option<PreparedOperation>,
    agent_signature: Option<DetachedSignature>,
    status: Option<OperationStatus>,
    /// This client's own RPC proved that the retained preparation lapsed without executing.
    /// The proof is final, so the operation stays `failed` when the wallet nonce later moves
    /// or RPC is unavailable. An engine `failed` report alone never sets it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    lapsed: bool,
}
struct ExecutionProfile {
    policy_id: String,
    config: WalletConfig,
    endpoints: Endpoints,
}
pub struct Client {
    http: HttpClient,
    origin: String,
    bundle: ExecutionProfile,
    signer: Arc<dyn AgentSigner>,
    account: String,
    rpc_url: String,
}
fn revalidate_with_rpc_url(
    p: &PreparedOperation,
    now: u64,
    value: &str,
) -> Result<PreparedOperation> {
    if p.config.route == WalletRoute::Native {
        let rpc = checked(sdk::rpc::HttpRpc::new(value))?;
        if checked(rpc.call("getNetwork", json!({})))?["passphrase"]
            != checked(sdk::passphrase(&p.config.network))?
        {
            return Err(Error::config("Signing RPC belongs to another network"));
        }
        let current = checked(sdk::rpc::get_account(&rpc, &p.config.wallet))?;
        verify_native_members(&current, &p.config)?;
        if current != p.state.source {
            return Err(Error::uncertain(
                "Native source account changed before signing. Retain the original packet.",
            ));
        }
        return Ok(p.clone());
    }
    if value.is_empty() {
        return Err(Error::config(
            "policy wallet signing revalidates through Stellar RPC; pass --rpc-url URL or set rpc_url for this rail",
        ));
    }
    let runtime = checked(super::Runtime::new(value))?;
    checked(runtime.revalidate_unsigned(p, now))
}
fn clock() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|v| v.as_secs())
        .map_err(|_| Error::config("System clock precedes the Unix epoch"))
}
fn checked<T>(v: sdk::Result<T>) -> Result<T> {
    v.map_err(crate::provider::failure)
}
fn journal_error(_: Error) -> Error {
    Error::config("Stellar operation journal is unsafe or unreadable; retain the original journal")
}
fn same_policy_config(expected: &WalletConfig, actual: &WalletConfig) -> bool {
    expected == actual
}
fn same_retained_policy_config(expected: &WalletConfig, actual: &WalletConfig) -> bool {
    let mut original = actual.clone();
    original.agent = expected.agent.clone();
    original.server = expected.server.clone();
    &original == expected
}
fn validate_bundle(policy: &str, bundle: &Bundle) -> Result<()> {
    if bundle.version != 1
        || bundle.profile != sdk::PROFILE
        || bundle.policy_id != policy
        || bundle.network != bundle.config.network
        || bundle.wallet != bundle.config.wallet
        || bundle.route != bundle.config.route
        || checked(sdk::unhex::<32>(&bundle.source_hash))? != bundle.config.source_hash
        || checked(sdk::unhex::<32>(&bundle.module_digest))? != bundle.config.module_digest
        || (!bundle.ir_hash.is_empty() && sdk::unhex::<32>(&bundle.ir_hash).is_err())
        || (bundle.ir_hash.is_empty() && bundle.config.language != sdk::PolicyLanguage::Portable)
        || bundle.endpoints.execute != "/api/native/execute"
        || bundle.endpoints.status != "/api/native/execute/status"
    {
        return Err(Error::config(
            "The Stellar bundle does not match the installed policy profile",
        ));
    }
    checked(sdk::validate_config(&bundle.config))?;
    if bundle.config.language == sdk::PolicyLanguage::Portable {
        validate_portable_profile(bundle)?;
    } else if bundle.language.is_some() || bundle.portable.is_some() {
        return Err(Error::config(
            "A retained legacy profile cannot claim portable source",
        ));
    }
    Ok(())
}
pub fn read_public_bundle(path: &Path) -> Result<Bundle> {
    // The file reader reports request-file errors; name the profile instead.
    let bundle: Bundle = crate::host::typed_request::read_request_file(path).map_err(|_| {
        Error::config(format!(
            "{} is not a readable public Stellar wallet profile",
            path.display()
        ))
    })?;
    validate_public_bundle(bundle)
}
/// Decode a strict public descriptor before any JSON value projection.
pub fn decode_public_bundle(bytes: &[u8]) -> Result<Bundle> {
    if bytes.len() > 1_048_576 {
        return Err(Error::config("Public wallet profile exceeds its limit"));
    }
    crate::host::typed_request::validate_json(bytes, 1_048_576)?;
    let bundle = serde_json::from_slice(bytes)
        .map_err(|_| Error::config("Invalid public wallet profile"))?;
    validate_public_bundle(bundle)
}
fn validate_public_bundle(mut bundle: Bundle) -> Result<Bundle> {
    if let Some(_private) = bundle.signing_seed.take() {
        return Err(Error::config(
            "The public Stellar bundle must not contain signing material",
        ));
    }
    validate_bundle(&bundle.policy_id, &bundle)?;
    if bundle
        .wallet_kind
        .is_some_and(|named| crate::provider::profiles::wallet_kind(&bundle.config) != Some(named))
    {
        return Err(Error::config(
            "The public Stellar wallet names another wallet kind than its configuration binds",
        ));
    }
    if bundle.config.owner == bundle.config.agent
        || bundle.config.owner == bundle.config.server
        || bundle.config.agent == bundle.config.server
    {
        return Err(Error::config(
            "The public Stellar wallet must use distinct owner, agent and server identities",
        ));
    }
    Ok(bundle)
}
pub fn public_description(bundle: &Bundle, source: bool) -> serde_json::Value {
    let mut value = json!({
        "policyId":bundle.policy_id,"profile":bundle.profile,"network":bundle.network,
        "wallet":bundle.wallet,"route":bundle.route,"owner":bundle.config.owner,
        "agent":bundle.config.agent,"server":bundle.config.server,
        "sourceHash":bundle.source_hash,"irHash":bundle.ir_hash,"moduleDigest":bundle.module_digest,
        "asset":bundle.config.asset,"assetSymbol":bundle.config.asset_symbol,"assetIssuer":bundle.config.asset_issuer,
        "maxFeeStroops":bundle.config.max_fee_stroops
    });
    if source {
        value["policy"] = json!(bundle.config.policy_source);
    }
    value
}
/// A Stellar key capability. Its implementation owns key custody outside this workflow.
pub trait AgentSigner: Send + Sync {
    fn account(&self) -> &str;
    fn sign_hash(&self, digest: &[u8; 32]) -> sdk::Result<[u8; 64]>;
}
/// The exit code of a policy denial in the shared CLI exit table.
const POLICY_DENIED: i32 = 20;
/// The text that starts the message of an engine reply that left the operation unresolved.
const UNRESOLVED: &str = "Stellar operation was not resolved";
/// An engine refusal `{error, code, details}`. See `provider::diagnostics`.
#[derive(Default, Deserialize)]
struct Refusal {
    #[serde(default)]
    code: String,
    #[serde(default)]
    error: String,
    #[serde(default)]
    details: RefusalDetails,
}
/// An engine message as terminal text: its printable ASCII characters, at most 200, without
/// the final period. Engine text reaches the terminal only through this function.
fn plain(text: &str) -> Option<String> {
    let text: String = text
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(200)
        .collect();
    let text = text.trim().trim_end_matches('.');
    (!text.is_empty()).then(|| text.to_owned())
}
/// Whether `error` is an engine reply that neither resolved nor typed the operation: a 409
/// without a stable code. The engine sends it, for example, while the receipt of a settled
/// transaction is not yet readable, so the status of the same request ID can still resolve.
fn unresolved(error: &Error) -> bool {
    error.status == Some(409) && error.api_code.is_none() && error.message.contains(UNRESOLVED)
}
/// The unresolved reply `error` as an uncertain outcome: the caller reads the same request ID
/// again with status.
fn uncertain(error: Error) -> Error {
    Error {
        code: Error::uncertain("").code,
        ..error
    }
}
#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RefusalDetails {
    rule: Option<String>,
    error: Option<String>,
    contract_error: Option<u32>,
}
/// The client error for a non-2xx engine reply. A 409 `policy_denied` names the denying rule
/// and error and uses the policy-denial exit code. A 409 `wallet_rejected` is a contract
/// rejection: the wallet, its asset or a vault refused the operation, and it names the contract
/// error. Every other reply leaves the operation unresolved: its message keeps the engine's
/// message, and the error keeps the engine's stable code when the reply has one.
fn refusal(status: u16, body: &[u8]) -> Error {
    let refusal = serde_json::from_slice::<Refusal>(body).unwrap_or_default();
    // The engine got no answer from the rail network. The request ID stays valid for a retry.
    if matches!(status, 503 | 504) && refusal.code == "network_unavailable" {
        let mut error = Error::api(
            status,
            "network unavailable; retry with the same request ID",
        );
        error.code = crate::provider::NETWORK_UNAVAILABLE;
        return error;
    }
    // Engine names reach the terminal only as plain identifiers.
    let name = |v: &Option<String>| {
        v.clone().filter(|v| {
            (1..=64).contains(&v.len()) && v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        })
    };
    let Refusal {
        code,
        error: reason,
        details: d,
    } = refusal;
    match code.as_str() {
        "policy_denied" if status == 409 => {
            let reason = match (name(&d.rule), name(&d.error), d.contract_error) {
                (Some(rule), Some(error), _) => format!("`{rule}` ({error})"),
                (Some(rule), None, _) => format!("`{rule}`"),
                (None, Some(error), Some(code)) => format!("{error} (contract error {code})"),
                (None, Some(error), None) => error,
                (None, None, Some(code)) => format!("contract error {code}"),
                (None, None, None) => "no rule named".into(),
            };
            let mut error = Error::api(
                status,
                format!("The policy denied this operation: {reason}"),
            );
            error.code = POLICY_DENIED;
            error
        }
        "wallet_rejected" if status == 409 => Error::api(
            status,
            match (name(&d.error), d.contract_error) {
                (Some(error), Some(code)) => format!(
                    "The operation was rejected in simulation: {error} (contract error {code})"
                ),
                (None, Some(code)) => {
                    format!("The operation was rejected in simulation: contract error {code}")
                }
                (_, None) => "The operation was rejected in simulation".into(),
            },
        ),
        _ => {
            let message = match plain(&reason) {
                Some(reason) => {
                    format!("{UNRESOLVED}: {reason}; retain the original request ID")
                }
                None => format!("{UNRESOLVED}; retain the original request ID"),
            };
            match name(&Some(code)) {
                Some(code) => Error::refused(status, code, message),
                None => Error::api(status, message),
            }
        }
    }
}
fn validate_response_receipt(r: &Response) -> Result<()> {
    let p = &r.prepared;
    if let Some(receipt) = &r.receipt {
        checked(sdk::rpc::validate_receipt(
            receipt,
            &p.config.network,
            &p.transaction_hash,
        ))?;
        if super::projected_status(&p.config.route, receipt.status.clone()) != r.operation.status
            || r.signed_operation
                .as_ref()
                .is_none_or(|v| v.transaction_xdr != receipt.envelope_xdr)
        {
            return Err(Error::uncertain(
                "Stellar receipt differs from its retained signed operation",
            ));
        }
    }
    Ok(())
}
impl Client {
    pub fn new(
        bundle: Bundle,
        signer: Arc<dyn AgentSigner>,
        authority: &crate::host::config::ServerAuthority,
        rpc_url: Option<String>,
    ) -> Result<Self> {
        if authority.network() != crate::host::routing::normalize(&bundle.network)? {
            return Err(Error::config("Server authority belongs to another rail"));
        }
        bundle.verify_server_role(authority.public_key())?;
        let origin = authority.origin();
        let account = signer.account().to_owned();
        if account != bundle.config.agent {
            return Err(Error::config(
                "the agent key differs from the wallet profile agent",
            ));
        }
        validate_bundle(&bundle.policy_id, &bundle)?;
        if bundle.config.route == WalletRoute::Native {
            let endpoint=rpc_url.as_deref().filter(|v|!v.is_empty()).ok_or_else(||Error::config("Fresh Native execution requires independent RPC to verify source consent and current roles"))?;
            bundle.verify_import(endpoint)?;
        }
        Self::from_context(
            ExecutionProfile {
                policy_id: bundle.policy_id,
                config: bundle.config,
                endpoints: bundle.endpoints,
            },
            signer,
            origin,
            rpc_url,
        )
    }
    fn from_context(
        bundle: ExecutionProfile,
        signer: Arc<dyn AgentSigner>,
        origin: &str,
        rpc_url: Option<String>,
    ) -> Result<Self> {
        let account = signer.account().to_owned();
        Ok(Self {
            http: HttpClient::new(Options {
                timeout: ENGINE_TIMEOUT,
                max_response_bytes: 1_048_576,
                no_proxy: false,
                connect_timeout: None,
            })
            .map_err(|_| Error::config("Cannot initialize Stellar transport"))?,
            origin: parse_origin(origin)?,
            bundle,
            signer,
            account,
            rpc_url: rpc_url.unwrap_or_default(),
        })
    }
    fn post(&self, path: &str, body: serde_json::Value) -> Result<Response> {
        self.post_within(path, body, None)?.ok_or_else(|| {
            Error::uncertain(
                "Stellar transport is uncertain; recover the original request ID with status",
            )
        })
    }
    /// One engine call that ends at `deadline`. `None` in the result means that the deadline
    /// ended the call before an answer arrived. Only a read may take a deadline: a state-changing
    /// call that stops early leaves its outcome unknown.
    fn post_within(
        &self,
        path: &str,
        body: serde_json::Value,
        deadline: Option<Instant>,
    ) -> Result<Option<Response>> {
        let issued_at = clock()?;
        let canonical = serde_json_canonicalizer::to_vec(&body)
            .map_err(|_| Error::config("Cannot encode Stellar request"))?;
        let proof = crate::host::request_proof::authorize(
            crate::provider::server::request_proof_protocol(),
            &self.account,
            issued_at,
            path,
            &canonical,
            |digest| checked(self.signer.sign_hash(digest)).map(|signature| signature.to_vec()),
        )?;
        let bytes = serde_json::to_vec(&body)
            .map_err(|_| Error::config("Cannot encode Stellar request"))?;
        let headers = [
            ("Authorization".into(), proof),
            ("Content-Type".into(), "application/json".into()),
        ];
        let response = self.http.send(
            Request {
                method: Method::Post,
                url: &format!("{}{path}{REPORTS}", self.origin),
                headers: &headers,
                body: Some(&bytes),
            },
            deadline,
        );
        let response = match response {
            Ok(response) => response,
            Err(_) if deadline.is_some_and(|end| Instant::now() >= end) => return Ok(None),
            Err(_) => {
                return Err(Error::uncertain(
                    "Stellar transport is uncertain; recover the original request ID with status",
                ));
            }
        };
        if !(200..300).contains(&response.status) {
            return Err(refusal(response.status, &response.body));
        }
        let mut parsed: Response = serde_json::from_slice(&response.body).map_err(|_| {
            Error::uncertain("Invalid Stellar response; recover the original request ID")
        })?;
        parsed.released = parsed.prepared.config.route == WalletRoute::PolicyWallet
            && parsed.operation.status == OperationStatus::Failed
            && parsed.receipt.is_none();
        parsed.operation.status =
            super::projected_status(&parsed.prepared.config.route, parsed.operation.status);
        Ok(Some(parsed))
    }
    fn validate(
        &self,
        r: &Response,
        id: &str,
        record: Option<&Record>,
        read_only: bool,
    ) -> Result<()> {
        let config_matches = if read_only {
            same_retained_policy_config
        } else {
            same_policy_config
        };
        let p = &r.prepared;
        if r.operation.id != id
            || !config_matches(&self.bundle.config, &p.config)
            || p.request.operation.nonce != operation_nonce(&self.bundle.policy_id, id)
            || r.operation.transaction_hash != sdk::hex(&p.transaction_hash)
            || record.is_some_and(|old| {
                p.request != old.request
                    || !config_matches(&old.config, &p.config)
                    || old.prepared.as_ref().is_some_and(|v| v != p)
            })
        {
            return Err(Error::uncertain(
                "Stellar response changed the original operation identity",
            ));
        }
        if terminal(&r.operation.status) && r.receipt.is_none() {
            return Err(Error::uncertain(
                "Terminal Stellar status requires a verified chain receipt",
            ));
        }
        validate_response_receipt(r)?;
        // Status verifies retained bytes at their preparation time, including after expiry.
        checked(sdk::validate_retained_prepared(p))?;
        if let Some(s) = &r.signed_operation {
            if s.prepared != *p {
                return Err(Error::uncertain(
                    "Stellar signed packet differs from the original operation",
                ));
            }
            if s.prepared.config.route == WalletRoute::PolicyWallet {
                if let Some(receipt) = &r.receipt {
                    checked(sdk::rpc::validate_settled_policy_packet(s, receipt))?;
                } else {
                    checked(sdk::validate_retained_signed(s))?;
                }
            } else {
                checked(sdk::validate_retained_signed(s))?;
            }
        }
        if matches!(
            r.operation.status,
            OperationStatus::Submitted | OperationStatus::Confirmed | OperationStatus::Failed
        ) && r.signed_operation.is_none()
        {
            return Err(Error::uncertain(
                "Stellar settlement omitted its signed packet",
            ));
        }
        if let Some(old) = record.and_then(|v| v.status.as_ref())
            && terminal(&super::projected_status(&p.config.route, old.clone()))
            && super::projected_status(&p.config.route, old.clone()) != r.operation.status
        {
            return Err(Error::uncertain("A terminal Stellar receipt changed"));
        }
        Ok(())
    }
    fn status(&self, id: &str, record: Option<&Record>) -> Result<Response> {
        self.status_within(id, record, None)?.ok_or_else(|| {
            Error::uncertain(
                "Stellar transport is uncertain; recover the original request ID with status",
            )
        })
    }
    /// A status read whose engine call ends at `deadline`; `None` means that the deadline ended
    /// it. The lapse proof of an answer runs after the call and is not bounded by `deadline`.
    fn status_within(
        &self,
        id: &str,
        record: Option<&Record>,
        deadline: Option<Instant>,
    ) -> Result<Option<Response>> {
        let Some(mut r) = self.post_within(
            &self.bundle.endpoints.status,
            json!({"policyId":self.bundle.policy_id,"requestId":id}),
            deadline,
        )?
        else {
            return Ok(None);
        };
        self.validate(&r, id, record, true)?;
        self.settle(&mut r, record)?;
        Ok(Some(r))
    }
    /// Report `failed` for a policy wallet operation that this client proved lapsed, now or in
    /// an earlier query that the journal retains for the same preparation.
    fn settle(&self, r: &mut Response, record: Option<&Record>) -> Result<()> {
        let retained = record.is_some_and(|v| v.lapsed && v.prepared.as_ref() == Some(&r.prepared));
        if retained && r.operation.status == OperationStatus::Confirmed {
            return Err(Error::uncertain("A terminal Stellar receipt changed"));
        }
        r.lapsed = retained || self.proven_release(r, record);
        if r.lapsed {
            r.operation.status = OperationStatus::Failed;
        }
        Ok(())
    }
    /// Whether the engine released the retained policy wallet operation and this client's own
    /// RPC proves that it lapsed without executing. Without independent RPC, a retained
    /// preparation or the proof, the operation stays `submissionUnknown`.
    fn proven_release(&self, r: &Response, record: Option<&Record>) -> bool {
        r.released
            && record.and_then(|v| v.prepared.as_ref()) == Some(&r.prepared)
            && !self.rpc_url.is_empty()
            && sdk::rpc::HttpRpc::new(&self.rpc_url)
                .and_then(|rpc| sdk::rpc::operation_lapsed(&rpc, &r.prepared))
                .unwrap_or(false)
    }
}
/// The request retained under this policy and request ID, if any. `exec`
/// checks the rest of the record.
pub fn retained_request(
    journal: &Store,
    policy: &str,
    id: &str,
) -> Result<Option<ExecutionRequest>> {
    let name = sdk::hex(&operation_nonce(policy, id));
    let old: Option<Record> = journal.load(&name).map_err(journal_error)?;
    Ok(old.map(|r| r.request))
}
/// Reads one request by its ID without creating another.
pub fn status(c: &Client, journal: &Store, id: &str, wait: Duration) -> Result<ExecutionOutcome> {
    validate_wait_and_id(id, wait)?;
    let policy = c.bundle.policy_id.clone();
    let name = sdk::hex(&operation_nonce(&policy, id));
    let old: Option<Record> = journal.load(&name).map_err(journal_error)?;
    if old.as_ref().is_some_and(|v| {
        v.policy_id != policy
            || v.backend_origin
                .as_ref()
                .is_some_and(|origin| origin != &c.origin)
            || v.request_id != *id
            || !same_retained_policy_config(&c.bundle.config, &v.config)
    }) {
        return Err(Error::config(
            "The journal does not bind this installed Stellar policy",
        ));
    }
    poll(c, id, old, journal, &name, wait, None)
}
/// Prepares, signs and submits one typed request, then polls within `wait`.
///
/// `wait` bounds only the engine status reads after the submit answer. Prepare and submit each
/// wait up to [`ENGINE_TIMEOUT`] for the engine: a submit that stops early leaves its outcome
/// unknown, so no caller bound ends it. A status answer that reports a released policy wallet
/// operation also starts the lapse proof on the caller's RPC, which keeps its own timeouts and
/// runs to its end, because a half-read proof decides nothing.
pub fn exec(
    c: &Client,
    journal: &Store,
    request_id: &str,
    request: ExecutionRequest,
    wait: Duration,
) -> Result<ExecutionOutcome> {
    validate_wait_and_id(request_id, wait)?;
    let policy = c.bundle.policy_id.clone();
    let id = request_id.to_owned();
    if request.operation.nonce != operation_nonce(&policy, &id) {
        return Err(Error::usage(
            "The operation nonce does not bind this policy and request ID",
        ));
    }
    checked(sdk::operation_from_request(&c.bundle.config, &request))?;
    let name = sdk::hex(&request.operation.nonce);
    let old = journal.load::<Record>(&name).map_err(journal_error)?;
    if c.bundle.config.language != sdk::PolicyLanguage::Portable
        && old.as_ref().is_none_or(|record| {
            record.agent_signature.is_none()
                && matches!(record.status, None | Some(OperationStatus::Prepared))
        })
    {
        return Err(Error::unsupported(
            "Retired policy source supports original signed-operation status only",
        ));
    }
    let (mut record, resumed) = if let Some(old) = old {
        if old.policy_id != policy
            || old
                .backend_origin
                .as_ref()
                .is_some_and(|origin| origin != &c.origin)
            || old.request_id != id
            || !same_retained_policy_config(&c.bundle.config, &old.config)
            || old.request != request
        {
            return Err(Error::config(
                "The original request ID already binds different input",
            ));
        }
        if old.agent_signature.is_some()
            || !matches!(&old.status, None | Some(OperationStatus::Prepared))
        {
            return poll(c, &id, Some(old), journal, &name, wait, None);
        }
        if !same_policy_config(&c.bundle.config, &old.config) {
            return Err(Error::uncertain(
                "The customer key changed. Read the original operation with status; do not authorize replacement bytes.",
            ));
        }
        let pure_intent = old.prepared.is_none() && old.status.is_none();
        let resumed = match c.status(&id, Some(&old)) {
            Ok(response)
                if response.operation.status == OperationStatus::Prepared
                    && response.signed_operation.is_none() =>
            {
                Some(response)
            }
            Ok(_) => return poll(c, &id, Some(old), journal, &name, wait, None),
            Err(error) if error.status == Some(404) && pure_intent => None,
            Err(error) => return Err(error),
        };
        (old, resumed)
    } else {
        (
            Record {
                backend_origin: Some(c.origin.clone()),
                policy_id: policy.clone(),
                request_id: id.clone(),
                config: c.bundle.config.clone(),
                request: request.clone(),
                prepared: None,
                agent_signature: None,
                status: None,
                lapsed: false,
            },
            None,
        )
    };
    // Preserve the original intent. Only an explicit exec can continue unsigned preparation.
    journal.save(&name, &record).map_err(journal_error)?;
    let mut prepared = if let Some(response) = resumed {
        response
    } else {
        progress::report("Preparing the operation with the Allowit server");
        c.post(
            &c.bundle.endpoints.execute,
            json!({"policyId":policy,"requestId":id,"phase":"prepare","request":request}),
        )?
    };
    c.validate(&prepared, &id, Some(&record), false)?;
    if prepared.operation.status != OperationStatus::Prepared || prepared.signed_operation.is_some()
    {
        return Err(Error::uncertain(
            "Stellar prepare returned an unexpected lifecycle state",
        ));
    }
    // Retain observed bytes even when stale. They must never become a fresh all-None intent.
    record.prepared = Some(prepared.prepared.clone());
    record.status = Some(OperationStatus::Prepared);
    journal.save(&name, &record).map_err(journal_error)?;
    prepared.prepared = revalidate_with_rpc_url(&prepared.prepared, clock()?, &c.rpc_url)?;
    checked(sdk::validate_prepared(&prepared.prepared, clock()?))?;
    let signature = checked(sdk::sign_with(
        &prepared.prepared,
        &c.account,
        clock()?,
        |hash| c.signer.sign_hash(hash),
    ))?;
    record.prepared = Some(prepared.prepared);
    record.agent_signature = Some(signature.clone());
    record.status = Some(OperationStatus::SubmissionUnknown);
    journal.save(&name, &record).map_err(journal_error)?;
    progress::report("Submitting the signed operation and waiting for the network");
    let response = match c.post(
        &c.bundle.endpoints.execute,
        json!({"policyId":policy,"requestId":id,"phase":"submit","agentSignature":signature}),
    ) {
        Ok(response) => response,
        // The engine holds the signature and did not resolve the operation in this call, so
        // only the status of the same request ID can tell what happened to it.
        Err(error) if unresolved(&error) => {
            if wait.is_zero() {
                return Err(uncertain(error));
            }
            let outcome = poll(c, &id, Some(record), journal, &name, wait, None)?;
            // Still only prepared: the engine did not accept the signature, and `error` says why.
            return if outcome.status == OperationStatus::Prepared {
                Err(error)
            } else {
                Ok(outcome)
            };
        }
        Err(error) => return Err(error),
    };
    c.validate(&response, &id, Some(&record), false)?;
    record.status = Some(response.operation.status.clone());
    journal.save(&name, &record).map_err(journal_error)?;
    let submitted = render(&response)?;
    if terminal(&response.operation.status) || wait.is_zero() {
        return Ok(submitted);
    }
    poll(c, &id, Some(record), journal, &name, wait, Some(submitted))
}
fn validate_wait_and_id(id: &str, wait: Duration) -> Result<()> {
    if !crate::host::request::request_id_valid(id) {
        return Err(Error::usage("Invalid Stellar request ID"));
    }
    if wait > Duration::from_secs(600) {
        return Err(Error::usage(
            "Stellar polling waits must not exceed 10 minutes",
        ));
    }
    Ok(())
}
fn terminal(status: &OperationStatus) -> bool {
    matches!(status, OperationStatus::Confirmed | OperationStatus::Failed)
}
/// Read the status until it is terminal or `wait` ends. `last` is the outcome that the caller
/// already holds. Without one, the first read is not bounded, because the caller needs one
/// answer; every later engine read ends at the deadline and returns the last outcome. The
/// deadline covers the engine reads only: the lapse proof of a released operation reads the
/// caller's RPC with that client's own timeouts after an answer arrived.
///
/// An unresolved reply is not an outcome. A status read changes nothing, so the read repeats
/// until `wait` ends, and every read after such a reply ends at the deadline. When the wait
/// ends and the newest answer is an unresolved reply, that reply is the error of an uncertain
/// outcome, with the engine's message, and the same request ID reads the status again.
fn poll(
    c: &Client,
    id: &str,
    record: Option<Record>,
    journal: &Store,
    name: &str,
    wait: Duration,
    last: Option<ExecutionOutcome>,
) -> Result<ExecutionOutcome> {
    poll_reads(
        c,
        id,
        record,
        wait,
        last,
        &mut |record, bound| c.status_within(id, record, bound),
        &mut |record| journal.save(name, record).map_err(journal_error),
    )
}
/// A status read of the retained record that ends at the given deadline, if any.
type StatusRead<'a> = dyn FnMut(Option<&Record>, Option<Instant>) -> Result<Option<Response>> + 'a;
/// [`poll`] over the status reads of `read`, retaining each answered record with `save`.
fn poll_reads(
    c: &Client,
    id: &str,
    mut record: Option<Record>,
    wait: Duration,
    mut last: Option<ExecutionOutcome>,
    read: &mut StatusRead<'_>,
    save: &mut dyn FnMut(&Record) -> Result<()>,
) -> Result<ExecutionOutcome> {
    let deadline = Instant::now()
        .checked_add(wait)
        .ok_or_else(|| Error::usage("The Stellar polling deadline is too large"))?;
    let mut reads = 0u32;
    // The newest answer, when it left the operation unresolved.
    let mut open: Option<Error> = None;
    loop {
        if reads == 1 {
            progress::report("Waiting for the operation to settle");
        }
        reads += 1;
        let bound = (last.is_some() || open.is_some()).then_some(deadline);
        let r = match read(record.as_ref(), bound) {
            Ok(Some(r)) => r,
            // The deadline ended the read, so the newest answer decides.
            Ok(None) => {
                return match open {
                    Some(error) => Err(uncertain(error)),
                    None => Ok(last.expect("a bounded status read follows an earlier answer")),
                };
            }
            Err(error) if unresolved(&error) => {
                let left = deadline.saturating_duration_since(Instant::now());
                std::thread::sleep(left.min(Duration::from_secs(1)));
                if Instant::now() >= deadline {
                    return Err(uncertain(error));
                }
                open = Some(error);
                continue;
            }
            Err(error) => return Err(error),
        };
        open = None;
        let old = journaled(c, id, record, &r);
        save(&old)?;
        record = Some(old);
        let outcome = render(&r)?;
        let left = deadline.saturating_duration_since(Instant::now());
        if terminal(&r.operation.status) || left.is_zero() {
            return Ok(outcome);
        }
        last = Some(outcome);
        std::thread::sleep(left.min(Duration::from_secs(1)));
    }
}
/// The journal record after status `r` for request `id`.
fn journaled(c: &Client, id: &str, record: Option<Record>, r: &Response) -> Record {
    let mut old = match record {
        Some(old) => old,
        None => Record {
            backend_origin: Some(c.origin.clone()),
            policy_id: c.bundle.policy_id.clone(),
            request_id: id.into(),
            config: c.bundle.config.clone(),
            request: r.prepared.request.clone(),
            prepared: Some(r.prepared.clone()),
            agent_signature: None,
            status: None,
            lapsed: false,
        },
    };
    if old.prepared.is_none() {
        old.prepared = Some(r.prepared.clone());
    }
    old.status = Some(r.operation.status.clone());
    old.lapsed |= r.lapsed;
    old
}
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionOutcome {
    pub request_id: String,
    pub status: OperationStatus,
    pub transaction_hash: String,
    /// The ledger of the verified receipt and the fee that it charged, in stroops. A receipt of a
    /// fee-bumped transaction holds the inner result, which charges no fee, so it reports none.
    pub settlement: Option<(u32, u64)>,
    /// The one debit of a confirmed operation, in the installed asset. A redeem debits vault
    /// shares, which have no listed unit, so it reports none.
    pub amount: Option<Quantity>,
    /// The fee that the engine counted against the spending limits, in the installed asset.
    pub fee_charged: Option<Quantity>,
    /// The spending limits of the policy as the engine reports them.
    pub limits: Option<Vec<LimitReport>>,
    /// The explorer link of the transaction, once this client holds its verified receipt.
    pub explorer: Option<String>,
}
fn render(r: &Response) -> Result<ExecutionOutcome> {
    let settlement = r
        .receipt
        .as_ref()
        .map(|receipt| receipt_settlement(receipt.ledger, &receipt.result_xdr))
        .transpose()?
        .flatten();
    let config = &r.prepared.config;
    let installed = installed_display(config);
    Ok(ExecutionOutcome {
        request_id: r.operation.id.clone(),
        status: r.operation.status.clone(),
        transaction_hash: r.operation.transaction_hash.clone(),
        settlement,
        amount: (r.receipt.is_some() && r.operation.status == OperationStatus::Confirmed)
            .then(|| debit(&r.prepared, installed.as_ref()))
            .flatten(),
        fee_charged: r
            .fee_charged
            .as_ref()
            .and_then(|value| reported(value, installed.as_ref()?)),
        limits: r
            .limits
            .as_ref()
            .and_then(|value| reported_limits(value, installed.as_ref()?)),
        explorer: r.receipt.as_ref().and_then(|_| {
            crate::provider::server_owner::explorer_link(
                &config.network,
                "tx",
                &r.operation.transaction_hash,
            )
        }),
    })
}

/// The unit of the wallet's installed asset: a listed token, or a classic asset by its code and
/// issuer. An asset contract that is not listed has no known unit.
fn installed_display(c: &WalletConfig) -> Option<AssetDisplay> {
    crate::provider::asset_display(&c.network, &c.asset)
        .ok()
        .or_else(|| {
            let issuer = c.asset_issuer.as_deref()?;
            crate::provider::asset_display(&c.network, &format!("{}:{issuer}", c.asset_symbol)).ok()
        })
}

/// The one debit of a prepared operation as an amount of the installed asset. Transfers and
/// deposits debit the installed asset. A redeem debits shares of its vault, so it has none.
fn debit(p: &PreparedOperation, installed: Option<&AssetDisplay>) -> Option<Quantity> {
    let operation = sdk::operation_from_request(&p.config, &p.request).ok()?;
    let (_, units) = operation.debit();
    if operation.debit_token(&p.config.asset) != p.config.asset {
        return None;
    }
    Some(Quantity::new(units, installed?.clone()))
}

/// An engine quantity as display data. It must count the installed asset; the printed text is
/// built here from the units and this rail's unit, and engine text is never copied.
fn reported(value: &serde_json::Value, installed: &AssetDisplay) -> Option<Quantity> {
    let quantity: Quantity = serde_json::from_value(value.clone()).ok()?;
    let units: i128 = quantity.units.parse().ok()?;
    (quantity.asset.symbol == installed.symbol && quantity.asset.decimals == installed.decimals)
        .then(|| Quantity::new(units, installed.clone()))
}

/// The most spending limits that one report holds.
const MAX_REPORTED_LIMITS: usize = 16;

/// Engine limit reports as display data: a bounded list of param names with quantities of the
/// installed asset. One invalid entry drops the whole report, so a partial list never shows.
fn reported_limits(
    value: &serde_json::Value,
    installed: &AssetDisplay,
) -> Option<Vec<LimitReport>> {
    let entries = value
        .as_array()
        .filter(|v| v.len() <= MAX_REPORTED_LIMITS)?;
    entries
        .iter()
        .map(|entry| {
            let param = entry["param"].as_str().filter(|v| {
                (1..=64).contains(&v.len())
                    && v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            })?;
            Some(LimitReport {
                param: param.into(),
                limit: reported(&entry["limit"], installed)?,
                spent: reported(&entry["spent"], installed)?,
                remaining: reported(&entry["remaining"], installed)?,
            })
        })
        .collect()
}

/// The spending limits of the client's wallet. The engine reports them with the status of an
/// operation, so this reads the status of the newest operation that the journal retains for
/// this policy and service. `None` means that the journal retains no such operation or that the
/// engine sent no report.
pub fn limits(c: &Client, journal: &Store) -> Result<Option<Vec<LimitReport>>> {
    let newest = journal
        .entries::<Record>()
        .map_err(journal_error)?
        .into_iter()
        .filter(|v| {
            v.policy_id == c.bundle.policy_id
                && v.backend_origin.as_ref().is_none_or(|o| o == &c.origin)
                && same_retained_policy_config(&c.bundle.config, &v.config)
        })
        .filter_map(|v| Some((v.prepared.as_ref()?.created_at, v.request_id)))
        .max();
    let Some((_, id)) = newest else {
        return Ok(None);
    };
    Ok(status(c, journal, &id, Duration::ZERO)?.limits)
}

/// The ledger and charged fee of a verified receipt. Every transaction that pays its own fee
/// charges at least the base fee. A zero fee is the inner result of a fee-bumped transaction:
/// the outer transaction paid, and the receipt does not hold that amount, so no fee is reported
/// in place of a wrong one.
fn receipt_settlement(ledger: u32, result_xdr: &str) -> Result<Option<(u32, u64)>> {
    let result: stellar_xdr::TransactionResult = checked(sdk::read(result_xdr))?;
    let fee = u64::try_from(result.fee_charged)
        .map_err(|_| Error::uncertain("Invalid Stellar receipt fee"))?;
    Ok((fee > 0).then_some((ledger, fee)))
}

pub fn verify_native_members(account: &sdk::AccountState, c: &WalletConfig) -> Result<()> {
    if account.address != c.wallet {
        return Err(Error::config(
            "Native account differs from the selected wallet",
        ));
    }
    checked(account.validate_roles(&c.owner, &c.agent, &c.server))
}

#[cfg(test)]
mod portable_descriptor_tests {
    use super::*;
    fn fixtures() -> Vec<serde_json::Value> {
        serde_json::from_str(include_str!(
            "../../../tests/fixtures/provider/stellar-portable-descriptors.json"
        ))
        .unwrap()
    }
    #[test]
    fn actual_native_and_all_policy_wallet_descriptor_shapes_are_accepted() {
        for vector in fixtures() {
            let bundle: Bundle = serde_json::from_value(vector["bundle"].clone()).unwrap();
            validate_bundle("portable-policy", &bundle).unwrap();
            let mut omitted_ir = vector["bundle"].clone();
            omitted_ir.as_object_mut().unwrap().remove("irHash");
            let bundle: Bundle = serde_json::from_value(omitted_ir).unwrap();
            validate_bundle("portable-policy", &bundle).unwrap();
        }
    }
    #[test]
    fn portable_descriptor_mismatch_and_unknown_or_private_fields_are_refused() {
        let original = fixtures()[0]["bundle"].clone();
        for field in ["unexpected", "signing_seed", "privateKey"] {
            let mut changed = original.clone();
            changed[field] = json!("not-public");
            assert!(
                serde_json::from_value::<Bundle>(changed).is_err(),
                "{field}"
            );
        }
        for pointer in [
            "/language",
            "/portable/sourceHash",
            "/portable/paramsHash",
            "/portable/asset/address",
        ] {
            let mut changed = original.clone();
            *changed.pointer_mut(pointer).unwrap() = json!("changed");
            let bundle: Bundle = serde_json::from_value(changed).unwrap();
            assert!(
                validate_bundle("portable-policy", &bundle).is_err(),
                "{pointer}"
            );
        }
        let mut missing = original;
        missing.as_object_mut().unwrap().remove("portable");
        let bundle: Bundle = serde_json::from_value(missing).unwrap();
        assert!(validate_bundle("portable-policy", &bundle).is_err());
    }
}

#[cfg(test)]
mod public_bundle_tests {
    use super::*;
    use crate::host::typed_request::decode_bytes;
    fn fixture() -> serde_json::Value {
        let f: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/provider/stellar-approval.json"
        ))
        .unwrap();
        let policy = &f["policy"];
        let config = WalletConfig {
            network: "stellar:testnet".into(),
            policy_instance: [7; 32],
            wallet: f["intent"]["owner"].as_str().unwrap().into(),
            owner: f["intent"]["owner"].as_str().unwrap().into(),
            agent: sdk::account_for_seed(&[2; 32]),
            server: sdk::account_for_seed(&[3; 32]),
            route: WalletRoute::Native,
            tier: None,
            language: Default::default(),
            rules: vec![],
            params: Default::default(),
            source_digest: [0; 32],
            asset: policy["mint"].as_str().unwrap().into(),
            asset_symbol: "XLM".into(),
            asset_issuer: None,
            policy_source: policy["code"].as_str().unwrap().into(),
            source_hash: sdk::unhex(policy["sourceHash"].as_str().unwrap()).unwrap(),
            module_digest: [5; 32],
            max_fee_stroops: 100,
        };
        json!({"version":1,"profile":sdk::PROFILE,"network":config.network,
            "policyId":policy["id"],"sourceHash":policy["sourceHash"],"irHash":policy["irHash"],
            "moduleDigest":sdk::hex(&config.module_digest),"wallet":config.wallet,
            "route":"native","config":config,
            "endpoints":{"execute":"/api/native/execute","status":"/api/native/execute/status"}})
    }
    #[test]
    fn public_inspection_binds_roles_and_source_without_loading_a_signer() {
        let value = fixture();
        let bundle: Bundle = decode_bytes(&serde_json::to_vec(&value).unwrap()).unwrap();
        validate_bundle("existing-native-policy", &bundle).unwrap();
        let description = public_description(&bundle, false);
        assert!(description.get("policy").is_none());
        assert!(description.get("signingSeed").is_none());
        assert_eq!(description["agent"], sdk::account_for_seed(&[2; 32]));
        assert!(description["assetIssuer"].is_null());
        assert_eq!(
            public_description(&bundle, true)["policy"],
            value["config"]["policySource"]
        );
        let mut wrong: Bundle = decode_bytes(&serde_json::to_vec(&value).unwrap()).unwrap();
        wrong.network = "stellar:mainnet".into();
        assert!(validate_bundle("existing-native-policy", &wrong).is_err());
        let mut issued: Bundle = decode_bytes(&serde_json::to_vec(&value).unwrap()).unwrap();
        issued.config.asset_symbol = "XLM".into();
        issued.config.asset_issuer = Some(sdk::account_for_seed(&[8; 32]));
        issued.config.asset = sdk::sac_address(
            &issued.config.network,
            &sdk::asset_xdr(&issued.config).unwrap(),
        )
        .unwrap();
        validate_bundle("existing-native-policy", &issued).unwrap();
        assert_eq!(
            public_description(&issued, false)["assetIssuer"],
            sdk::account_for_seed(&[8; 32])
        );
    }
    #[test]
    fn public_profile_refuses_private_fields_and_changed_identity() {
        let path = std::env::temp_dir().join(format!(
            "allowit-stellar-public-{}.json",
            std::process::id()
        ));
        let mut value = fixture();
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        let bundle = read_public_bundle(&path).unwrap();
        assert_eq!(bundle.policy_id, "existing-native-policy");
        assert_eq!(bundle.network, "stellar:testnet");
        value["signingSeed"] = json!("must-stay-local");
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(read_public_bundle(&path).is_err());
        value.as_object_mut().unwrap().remove("signingSeed");
        value["config"]["agent"] = value["config"]["owner"].clone();
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(read_public_bundle(&path).is_err());
        value = fixture();
        value["config"]["sourceHash"] = json!(vec![0; 32]);
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(read_public_bundle(&path).is_err());
        std::fs::remove_file(path).unwrap();
        // A server may name the wallet kind at the top level. It must be the kind that the
        // configuration binds; another kind, an unknown id and any other new field are refused.
        let value = fixture();
        let bound = decode_public_bundle(&serde_json::to_vec(&value).unwrap()).unwrap();
        let bound = crate::provider::profiles::wallet_kind(&bound.config).expect("a wallet kind");
        let with = |kind: serde_json::Value| {
            let mut named = value.clone();
            named["walletKind"] = kind;
            decode_public_bundle(&serde_json::to_vec(&named).unwrap())
        };
        assert!(with(json!(bound)).is_ok());
        assert!(with(serde_json::Value::Null).is_ok());
        for other in allowit_core::vendor::kinds::WalletKind::ALL {
            assert_eq!(with(json!(other)).is_ok(), other == bound, "{}", other.id());
        }
        assert!(with(json!("common")).is_err());
        let mut unknown = value.clone();
        unknown["walletKinds"] = json!(["standard"]);
        assert!(decode_public_bundle(&serde_json::to_vec(&unknown).unwrap()).is_err());
    }
}

/// Immutable original journal context. It can only enter the receipt path.
pub struct Retained(Record);
impl Retained {
    pub fn config(&self) -> &WalletConfig {
        &self.0.config
    }
    pub fn policy_id(&self) -> &str {
        &self.0.policy_id
    }
    pub fn request(&self) -> &ExecutionRequest {
        &self.0.request
    }
    pub fn signed(&self) -> bool {
        self.0.agent_signature.is_some()
    }
}
pub fn retained(
    journal: &Store,
    network: &str,
    wallet: Option<&str>,
    id: &str,
) -> Result<Option<Retained>> {
    let mut found = Vec::new();
    for record in journal.entries::<Record>().map_err(journal_error)? {
        if record.request_id != id
            || checked(sdk::network_id(&record.config.network))?
                != checked(sdk::network_id(network))?
            || wallet.is_some_and(|w| w != record.config.wallet)
        {
            continue;
        }
        if record.request.operation.nonce != operation_nonce(&record.policy_id, id) {
            return Err(Error::config("Original operation nonce changed"));
        }
        if let Some(origin) = &record.backend_origin
            && parse_origin(origin)? != *origin
        {
            return Err(Error::config("Original backend identity changed"));
        }
        checked(sdk::validate_config(&record.config))?;
        if let Some(p) = &record.prepared {
            if p.request != record.request
                || !same_retained_policy_config(&record.config, &p.config)
            {
                return Err(Error::config("Original retained preparation changed"));
            }
            checked(sdk::validate_retained_prepared(p))?;
            if let Some(signature) = &record.agent_signature {
                if signature.signer != p.config.agent {
                    return Err(Error::config("Original agent signature changed roles"));
                }
                checked(sdk::signing::verify_digest(
                    &signature.signer,
                    &p.transaction_hash,
                    &signature.signature,
                ))?;
            }
        } else if record.agent_signature.is_some() {
            return Err(Error::config("Signed journal has no original preparation"));
        }
        found.push(Retained(record));
    }
    match found.len() {
        0 => Ok(None),
        1 => Ok(found.pop()),
        _ => Err(Error::config(
            "Several policies retain this request ID. Select its original wallet.",
        )),
    }
}
/// This constructor never returns a client and cannot prepare, sign or submit an operation.
pub fn recover(
    original: Retained,
    journal: &Store,
    signer: Arc<dyn AgentSigner>,
    backend: &str,
    id: &str,
    wait: Duration,
) -> Result<ExecutionOutcome> {
    // New records carry the original service. The supplied origin is only an explicit
    // compatibility binding for old journals; it is never used to replace a stored origin.
    let backend = original.0.backend_origin.as_deref().unwrap_or(backend);
    let client = Client::from_context(
        ExecutionProfile {
            policy_id: original.0.policy_id.clone(),
            config: original.0.config.clone(),
            endpoints: Endpoints {
                execute: "/api/native/execute".into(),
                status: "/api/native/execute/status".into(),
            },
        },
        signer,
        backend,
        None,
    )?;
    status(&client, journal, id, wait)
}

impl Bundle {
    /// Reconstruct the existing v1 public approval message without granting signing authority.
    pub fn source_approval_message(&self, revision: u32) -> Result<String> {
        validate_bundle(&self.policy_id, self)?;
        if revision == 0 || self.config.route != WalletRoute::Native {
            return Err(Error::usage("Select a Native policy revision"));
        }
        let c = &self.config;
        let portable = self
            .portable
            .as_ref()
            .ok_or_else(|| Error::config("Native source binding is missing"))?;
        let payload = super::consent::payload(
            &self.policy_id,
            revision,
            c,
            &self.source_hash,
            &self.ir_hash,
            &self.module_digest,
            super::consent::Portable {
                language: &portable.language,
                tier: &portable.tier,
                rules: &portable.rules,
                params: &portable.params,
                params_hash: &portable.params_hash,
            },
        )?;
        super::consent::message(&payload)
    }
    pub fn verify_server_role(&self, server: &str) -> Result<()> {
        if self.config.server != server
            || (self.config.route == WalletRoute::Native && self.config.owner != self.config.wallet)
        {
            return Err(Error::config(
                "Profile roles differ from independently configured server authority",
            ));
        }
        Ok(())
    }
    pub fn verify_import(&self, endpoint: &str) -> Result<()> {
        let rpc = checked(sdk::rpc::HttpRpc::new(endpoint))?;
        self.verify_import_with(&rpc)
    }
    pub fn verify_optional_import_proof(&self, rpc: &dyn sdk::rpc::Rpc) -> Result<()> {
        if self.source_approval.is_some() {
            self.verify_import_with(rpc)
        } else {
            Ok(())
        }
    }
    pub fn verify_import_with(&self, rpc: &dyn sdk::rpc::Rpc) -> Result<()> {
        let c = &self.config;
        if checked(rpc.call("getNetwork", json!({})))?["passphrase"]
            != checked(sdk::passphrase(&c.network))?
        {
            return Err(Error::config("Import RPC belongs to another network"));
        }
        if c.language != sdk::PolicyLanguage::Portable {
            return Err(Error::unsupported(
                "Retired profiles support retained operation recovery only",
            ));
        }
        if c.route == WalletRoute::PolicyWallet {
            let live = checked(sdk::rpc::trusted_state_for_discovery(rpc, c, None))?;
            if live.paused
                || live.state.owner != c.owner
                || live.state.agent != c.agent
                || live.state.server != c.server
                || live.state.policy_instance != c.policy_instance
                || live.state.module_digest != c.module_digest
                || live.state.policy_state.as_ref().is_none_or(|p| {
                    p.params != c.params || p.rules != c.rules || p.source_digest != c.source_digest
                })
            {
                return Err(Error::config(
                    "Imported profile differs from current native policy or authority",
                ));
            }
            return Ok(());
        }
        let proof=self.source_approval.as_ref().filter(|p|p.revision>0 && (1..=20).contains(&p.signatures.len()))
            .ok_or_else(||Error::config("Native import requires the exact administrator source approval. Export this active policy from the owner workspace."))?;
        let message = self.source_approval_message(proof.revision)?;
        let digest = sdk::signing::signed_message_digest(&message);
        let live = checked(sdk::rpc::get_account(rpc, &c.wallet))?;
        verify_native_members(&live, c)?;
        checked(live.validate_authority_signatures(&digest, &proof.signatures))
    }
}

#[cfg(test)]
mod native_revalidation_tests {
    use super::*;
    use std::{
        io::{Read, Write},
        net::TcpListener,
    };
    fn fixture() -> serde_json::Value {
        serde_json::from_str(include_str!(
            "../../../tests/fixtures/provider/stellar-policy-wallet-revalidation-rpc.json"
        ))
        .unwrap()
    }
    #[test]
    fn recovery_uses_the_original_service_even_if_the_caller_changes_its_default() {
        struct ProofSigner(String);
        impl AgentSigner for ProofSigner {
            fn account(&self) -> &str {
                &self.0
            }
            fn sign_hash(&self, hash: &[u8; 32]) -> sdk::Result<[u8; 64]> {
                use ed25519_dalek::Signer;
                Ok(ed25519_dalek::SigningKey::from_bytes(&[44; 32])
                    .sign(hash)
                    .to_bytes())
            }
        }
        for legacy in [false, true] {
            let original = TcpListener::bind("127.0.0.1:0").unwrap();
            let changed = TcpListener::bind("127.0.0.1:0").unwrap();
            let origin = format!("http://{}", original.local_addr().unwrap());
            let other = format!("http://{}", changed.local_addr().unwrap());
            original.set_nonblocking(true).unwrap();
            changed.set_nonblocking(true).unwrap();
            let server = std::thread::spawn(move || {
                let deadline = std::time::Instant::now() + Duration::from_secs(5);
                loop {
                    for (label, listener) in [("original", &original), ("changed", &changed)] {
                        if let Ok((mut stream, _)) = listener.accept() {
                            stream.set_nonblocking(false).unwrap();
                            stream
                                .set_read_timeout(Some(Duration::from_secs(2)))
                                .unwrap();
                            let mut header = Vec::new();
                            while !header.ends_with(b"\r\n\r\n") {
                                let mut byte = [0];
                                stream.read_exact(&mut byte).unwrap();
                                header.push(byte[0]);
                            }
                            let header = String::from_utf8(header).unwrap();
                            assert!(
                                header
                                    .starts_with("POST /api/native/execute/status?include=limits ")
                            );
                            let length: usize = header
                                .lines()
                                .find_map(|line| {
                                    line.to_ascii_lowercase()
                                        .strip_prefix("content-length:")
                                        .map(|v| v.trim().parse().unwrap())
                                })
                                .unwrap();
                            let mut body = vec![0; length];
                            stream.read_exact(&mut body).unwrap();
                            assert_eq!(
                                serde_json::from_slice::<serde_json::Value>(&body).unwrap()["requestId"],
                                "origin-status-001"
                            );
                            stream.write_all(b"HTTP/1.1 503 Unavailable\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}").unwrap();
                            return label;
                        }
                    }
                    assert!(
                        std::time::Instant::now() < deadline,
                        "No original-operation status request arrived"
                    );
                    std::thread::sleep(Duration::from_millis(5));
                }
            });
            let p: PreparedOperation =
                serde_json::from_value(fixture()["prepared"].clone()).unwrap();
            let policy = "origin-policy";
            let id = "origin-status-001";
            let mut request = p.request.clone();
            request.operation.nonce = operation_nonce(policy, id);
            let record = Record {
                backend_origin: if legacy { None } else { Some(origin.clone()) },
                policy_id: policy.into(),
                request_id: id.into(),
                config: p.config,
                request,
                prepared: None,
                agent_signature: None,
                status: None,
                lapsed: false,
            };
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().canonicalize().unwrap();
            let journal = Store::open(&root.join("journal")).unwrap();
            let key = sdk::hex(&record.request.operation.nonce);
            journal.save(&key, &record).unwrap();
            let before = std::fs::read(root.join("journal").join(format!(
                "request-{}.json",
                allowit_core::digest(key.as_bytes())
            )))
            .unwrap();
            let roundtrip: Record =
                serde_json::from_slice(&serde_json::to_vec(&record).unwrap()).unwrap();
            assert_eq!(roundtrip.backend_origin.is_none(), legacy);
            let supplied = if legacy { &origin } else { &other };
            let signer = Arc::new(ProofSigner(sdk::account_for_seed(&[44; 32])));
            assert!(
                recover(
                    Retained(record),
                    &journal,
                    signer,
                    supplied,
                    id,
                    Duration::ZERO
                )
                .is_err()
            );
            assert_eq!(server.join().unwrap(), "original");
            assert_eq!(
                std::fs::read(root.join("journal").join(format!(
                    "request-{}.json",
                    allowit_core::digest(key.as_bytes())
                )))
                .unwrap(),
                before
            );
        }
    }
    #[test]
    fn local_rpc_revalidates_exact_gateway_bytes_before_signing_without_credentials() {
        let data = fixture();
        let p: PreparedOperation = serde_json::from_value(data["prepared"].clone()).unwrap();
        let calls = data["calls"].as_array().unwrap().clone();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            for expected in calls {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut bytes = Vec::new();
                let end = loop {
                    let mut byte = [0];
                    stream.read_exact(&mut byte).unwrap();
                    bytes.push(byte[0]);
                    if bytes.ends_with(b"\r\n\r\n") {
                        break bytes.len();
                    }
                };
                let headers = std::str::from_utf8(&bytes).unwrap().to_ascii_lowercase();
                assert!(!headers.contains("authorization:"));
                assert!(!headers.contains("cookie:"));
                let length: usize = headers
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length:"))
                    .unwrap()
                    .trim()
                    .parse()
                    .unwrap();
                bytes.resize(end + length, 0);
                stream.read_exact(&mut bytes[end..]).unwrap();
                let body = std::str::from_utf8(&bytes[end..]).unwrap();
                assert!(!body.contains("Bearer"));
                assert!(!body.contains("signing_seed"));
                assert!(!body.contains("ALLOWIT_TOKEN"));
                let request: serde_json::Value = serde_json::from_str(body).unwrap();
                assert_eq!(request["method"], expected["method"]);
                assert_eq!(request["params"], expected["params"]);
                assert_eq!(request["jsonrpc"], "2.0");
                let response = serde_json::to_vec(
                    &json!({"jsonrpc":"2.0","id":request["id"],"result":expected["result"]}),
                )
                .unwrap();
                write!(stream,"HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n",response.len()).unwrap();
                stream.write_all(&response).unwrap();
            }
        });
        let checked = revalidate_with_rpc_url(&p, 86402, &url).unwrap();
        server.join().unwrap();
        assert_eq!(checked, p);
        assert_eq!(checked.transaction_xdr, p.transaction_xdr);
        assert_eq!(checked.transaction_hash, p.transaction_hash);
        assert!(checked.native_preflight.is_some());
        sdk::sign(&checked, &[2; 32], 86402).unwrap();
    }
    #[test]
    fn fresh_signing_requires_rpc_while_historical_validation_keeps_original_bytes() {
        let data = fixture();
        let p: PreparedOperation = serde_json::from_value(data["prepared"].clone()).unwrap();
        assert!(revalidate_with_rpc_url(&p, 86402, "").is_err());
        assert!(revalidate_with_rpc_url(&p, 86700, "http://127.0.0.1:1").is_err());
        let mut changed = p.clone();
        changed.request.operation.nonce[0] ^= 1;
        assert!(revalidate_with_rpc_url(&changed, 86402, "http://127.0.0.1:1").is_err());
        let old: SignedOperation = serde_json::from_str(include_str!(
            "../../../tests/fixtures/provider/canonical-main-9682-native-signed.json"
        ))
        .unwrap();
        assert!(revalidate_with_rpc_url(&old.prepared, 86402, "").is_err());
        sdk::validate_retained_prepared(&old.prepared).unwrap();
    }
    /// Answer one engine request on `listener` with `status` and `body` after `delay`, and
    /// return the request line and body.
    fn reply_once(
        listener: TcpListener,
        delay: Duration,
        status: &'static str,
        body: Vec<u8>,
    ) -> std::thread::JoinHandle<(String, serde_json::Value)> {
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut header = Vec::new();
            while !header.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                stream.read_exact(&mut byte).unwrap();
                header.push(byte[0]);
            }
            let header = String::from_utf8(header).unwrap();
            let length: usize = header
                .lines()
                .find_map(|v| {
                    v.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(|s| s.trim().parse().unwrap())
                })
                .unwrap();
            let mut request = vec![0; length];
            stream.read_exact(&mut request).unwrap();
            std::thread::sleep(delay);
            let _ = write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .and_then(|_| stream.write_all(&body));
            (
                header.lines().next().unwrap().to_owned(),
                serde_json::from_slice(&request).unwrap(),
            )
        })
    }
    fn engine_client(config: WalletConfig, origin: &str) -> Client {
        struct TestKey(String);
        impl AgentSigner for TestKey {
            fn account(&self) -> &str {
                &self.0
            }
            fn sign_hash(&self, hash: &[u8; 32]) -> sdk::Result<[u8; 64]> {
                use ed25519_dalek::Signer;
                Ok(ed25519_dalek::SigningKey::from_bytes(&[43; 32])
                    .sign(hash)
                    .to_bytes())
            }
        }
        Client::from_context(
            ExecutionProfile {
                policy_id: "engine-policy".into(),
                config,
                endpoints: Endpoints {
                    execute: "/api/native/execute".into(),
                    status: "/api/native/execute/status".into(),
                },
            },
            Arc::new(TestKey(sdk::account_for_seed(&[43; 32]))),
            origin,
            None,
        )
        .unwrap()
    }
    #[test]
    fn a_receipt_reports_its_ledger_and_fee_and_no_fee_for_a_fee_bumped_inner_result() {
        use stellar_xdr::{
            Limits, TransactionResult, TransactionResultExt, TransactionResultResult, WriteXdr,
        };
        let result = |fee_charged| {
            TransactionResult {
                fee_charged,
                result: TransactionResultResult::TxSuccess(Default::default()),
                ext: TransactionResultExt::V0,
            }
            .to_xdr_base64(Limits::none())
            .unwrap()
        };
        assert_eq!(
            receipt_settlement(5_661_578, &result(123_456)).unwrap(),
            Some((5_661_578, 123_456))
        );
        // The inner result of a fee-bumped transaction charges nothing; the outer fee is unknown.
        assert_eq!(receipt_settlement(5_661_578, &result(0)).unwrap(), None);
        assert!(receipt_settlement(1, &result(-1)).is_err());
        assert!(receipt_settlement(1, "not-xdr").is_err());
    }
    #[test]
    fn a_status_read_ends_at_its_deadline_and_a_call_without_one_does_not() {
        let p: PreparedOperation = serde_json::from_value(fixture()["prepared"].clone()).unwrap();
        let body = serde_json::to_vec(&json!({"prepared":p,"operation":{"id":"bounded-001","status":OperationStatus::Prepared,"transactionHash":sdk::hex(&p.transaction_hash)}})).unwrap();
        let request = || json!({"policyId":"engine-policy","requestId":"bounded-001"});
        let path = "/api/native/execute/status";
        // The engine answers after 3 s. A 300 ms deadline ends the read with no answer.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let server = reply_once(listener, Duration::from_secs(3), "200 OK", body.clone());
        let client = engine_client(p.config.clone(), &origin);
        let started = Instant::now();
        let deadline = started + Duration::from_millis(300);
        let bounded = client.post_within(path, request(), Some(deadline)).unwrap();
        assert!(bounded.is_none());
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
        server.join().unwrap();
        // A refusal before the deadline is still an error, never a silent timeout.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let server = reply_once(
            listener,
            Duration::ZERO,
            "500 Internal Server Error",
            b"{}".to_vec(),
        );
        let client = engine_client(p.config.clone(), &origin);
        let deadline = Instant::now() + Duration::from_secs(30);
        assert!(client.post_within(path, request(), Some(deadline)).is_err());
        server.join().unwrap();
        // An expired deadline sends nothing.
        let client = engine_client(p.config.clone(), "http://127.0.0.1:9");
        let past = Instant::now() - Duration::from_millis(1);
        assert!(
            client
                .post_within(path, request(), Some(past))
                .unwrap()
                .is_none()
        );
        // An answer inside the deadline arrives.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let server = reply_once(listener, Duration::ZERO, "200 OK", body);
        let client = engine_client(p.config.clone(), &origin);
        let deadline = Instant::now() + Duration::from_secs(30);
        let answered = client
            .post_within(path, request(), Some(deadline))
            .unwrap()
            .unwrap();
        assert_eq!(answered.prepared, p);
        server.join().unwrap();
    }
    #[test]
    fn a_status_reply_reports_the_charged_fee_and_the_limits_in_the_installed_unit() {
        let p: PreparedOperation = serde_json::from_value(fixture()["prepared"].clone()).unwrap();
        let installed = installed_display(&p.config).expect("the fixture asset has a unit");
        let other = AssetDisplay {
            symbol: "EVIL".into(),
            ..installed.clone()
        };
        let quantity = |units: i128| json!(Quantity::new(units, installed.clone()));
        let limit = |param: &str| json!({"param":param,"limit":quantity(50_000_000),"spent":quantity(12_000_000),"remaining":quantity(38_000_000)});
        let operation = json!({"id":"limits-001","status":OperationStatus::Prepared,"transactionHash":sdk::hex(&p.transaction_hash)});
        let reply = json!({"prepared":p,"operation":operation,
            "settlement":{"height":7,"fee":quantity(100),"amount":null},
            "feeCharged":quantity(2_500),"limits":[limit("daily_spending_limit"),limit("lifetime_spending_limit")],
            "explorer":"https://example.invalid/tx","walletKind":"standard"});
        let dir = tempfile::tempdir().unwrap();
        let journal = Store::open(&dir.path().canonicalize().unwrap().join("journal")).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let client = engine_client(p.config.clone(), &origin);
        // A journal without an operation of this policy has no report, and nothing is sent.
        assert_eq!(limits(&client, &journal).unwrap(), None);
        let server = reply_once(
            listener,
            Duration::ZERO,
            "200 OK",
            serde_json::to_vec(&reply).unwrap(),
        );
        let response = client
            .post(
                "/api/native/execute/status",
                json!({"policyId":"engine-policy","requestId":"limits-001"}),
            )
            .unwrap();
        let (line, _) = server.join().unwrap();
        assert!(
            line.starts_with("POST /api/native/execute/status?include=limits "),
            "{line}"
        );
        let outcome = render(&response).unwrap();
        assert_eq!(
            outcome.fee_charged,
            Some(Quantity::new(2_500, installed.clone()))
        );
        let reports = outcome.limits.unwrap();
        assert_eq!(reports.len(), 2);
        assert_eq!(reports[0].param, "daily_spending_limit");
        assert_eq!(
            reports[0].remaining,
            Quantity::new(38_000_000, installed.clone())
        );
        // No receipt: no settlement, no debit and no explorer link, whatever the engine names.
        assert_eq!(
            (outcome.settlement, outcome.amount, outcome.explorer),
            (None, None, None)
        );
        // The wallet read asks for the status of the newest retained operation of the policy.
        let name = sdk::hex(&operation_nonce("engine-policy", "limits-001"));
        let mut request = p.request.clone();
        request.operation.nonce = operation_nonce("engine-policy", "limits-001");
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let reader = engine_client(p.config.clone(), &origin);
        let record = Record {
            backend_origin: Some(reader.origin.clone()),
            policy_id: "engine-policy".into(),
            request_id: "limits-001".into(),
            config: p.config.clone(),
            request,
            prepared: Some(p.clone()),
            agent_signature: None,
            status: Some(OperationStatus::Prepared),
            lapsed: false,
        };
        journal.save(&name, &record).unwrap();
        // The operation of another service is not this wallet's report.
        assert_eq!(limits(&client, &journal).unwrap(), None);
        let server = reply_once(
            listener,
            Duration::ZERO,
            "200 OK",
            serde_json::to_vec(&reply).unwrap(),
        );
        let read = limits(&reader, &journal);
        let (line, body) = server.join().unwrap();
        assert!(
            line.starts_with("POST /api/native/execute/status?include=limits "),
            "{line}"
        );
        assert_eq!(body["requestId"], "limits-001");
        // The fixture preparation is not operation `limits-001`, so the reply fails the same
        // identity checks as every status read and its report is not shown.
        assert_eq!(
            read.unwrap_err().message,
            "Stellar response changed the original operation identity"
        );
        // A reply without the reports reads as before.
        let plain: Response =
            serde_json::from_value(json!({"prepared":p,"operation":operation})).unwrap();
        let outcome = render(&plain).unwrap();
        assert_eq!((outcome.fee_charged, outcome.limits), (None, None));
        // Engine text is never copied: the text is built from the units and this rail's unit.
        let mut hostile = quantity(5);
        hostile["text"] = json!("1000000 USDC\u{1b}[2J");
        assert_eq!(
            reported(&hostile, &installed),
            Some(Quantity::new(5, installed.clone()))
        );
        // A quantity of another asset, a non-decimal amount, a hostile param name, an entry
        // without a field and an oversized list drop the report.
        assert_eq!(reported(&json!(Quantity::new(5, other)), &installed), None);
        let mut text = quantity(5);
        text["units"] = json!("5e3");
        assert_eq!(reported(&text, &installed), None);
        let mut missing = limit("payment_limit");
        missing.as_object_mut().unwrap().remove("spent");
        for invalid in [
            json!([limit("daily\u{1b}[2J")]),
            json!([limit("")]),
            json!([limit("daily_spending_limit"), missing]),
            json!(vec![limit("payment_limit"); MAX_REPORTED_LIMITS + 1]),
            json!({"param":"payment_limit"}),
        ] {
            assert_eq!(reported_limits(&invalid, &installed), None, "{invalid}");
        }
        assert_eq!(reported_limits(&json!([]), &installed), Some(Vec::new()));
        // An unknown field is still refused.
        assert!(
            serde_json::from_value::<Response>(
                json!({"prepared":p,"operation":operation,"extra":1})
            )
            .is_err()
        );
    }
    #[test]
    fn a_confirmed_transfer_reports_its_one_debit_in_the_installed_unit() {
        let p: PreparedOperation = serde_json::from_value(fixture()["prepared"].clone()).unwrap();
        let installed = installed_display(&p.config).unwrap();
        let operation = sdk::operation_from_request(&p.config, &p.request).unwrap();
        let (_, units) = operation.debit();
        assert!(units > 0);
        assert_eq!(
            debit(&p, Some(&installed)),
            Some(Quantity::new(units, installed.clone()))
        );
        // An asset without a known unit reports no amount; it never prints a placeholder unit.
        assert_eq!(debit(&p, None), None);
        let mut unlisted = p.config.clone();
        unlisted.asset = sdk::account_for_seed(&[9; 32]).replacen('G', "C", 1);
        unlisted.asset_issuer = None;
        assert_eq!(installed_display(&unlisted), None);
    }
    #[test]
    fn slow_engine_replies_arrive_for_prepare_submit_and_status() {
        // Engine prepare took up to 138 s, submit up to 90 s and status up to 44 s on testnet.
        // Each reply here outlasts the former 30 s submit and status bound.
        let p: PreparedOperation = serde_json::from_value(fixture()["prepared"].clone()).unwrap();
        let body = serde_json::to_vec(&json!({"prepared":p,"operation":{"id":"slow-engine-001","status":OperationStatus::Prepared,"transactionHash":sdk::hex(&p.transaction_hash)}})).unwrap();
        std::thread::scope(|scope| {
            for (path, phase) in [
                ("/api/native/execute", Some("prepare")),
                ("/api/native/execute", Some("submit")),
                ("/api/native/execute/status", None),
            ] {
                let listener = TcpListener::bind("127.0.0.1:0").unwrap();
                let origin = format!("http://{}", listener.local_addr().unwrap());
                let server = reply_once(listener, Duration::from_secs(32), "200 OK", body.clone());
                let client = engine_client(p.config.clone(), &origin);
                let p = &p;
                scope.spawn(move || {
                    let response = client.post(
                        path,
                        json!({"policyId":"engine-policy","requestId":"slow-engine-001","phase":phase}),
                    );
                    let (line, request) = server.join().unwrap();
                    assert!(line.starts_with(&format!("POST {path}{REPORTS} ")));
                    assert_eq!(request["phase"], json!(phase));
                    let response = response
                        .unwrap_or_else(|e| panic!("{path} {phase:?}: {}", e.message));
                    assert_eq!(response.prepared, *p);
                });
            }
        });
    }
    #[test]
    fn engine_refusals_keep_the_denying_rule_and_exit_code() {
        // The engine replies of the testnet rerun: a portable rule denial and a Custom wallet
        // simulation rejection whose contract the RPC did not identify.
        let p: PreparedOperation = serde_json::from_value(fixture()["prepared"].clone()).unwrap();
        for (status, body, code, text) in [
            (
                "409 Conflict",
                json!({"code":"policy_denied","details":{"contractError":null,"error":"PaymentLimitExceeded","rule":"payment_limit"},"error":"The policy denied this operation: `payment_limit` (PaymentLimitExceeded)."}),
                20,
                "Allowit returned HTTP 409: The policy denied this operation: `payment_limit` (PaymentLimitExceeded)",
            ),
            (
                "409 Conflict",
                json!({"code":"policy_denied","details":{"contractError":18,"error":"PolicyDenied","rule":null},"error":"denied"}),
                20,
                "Allowit returned HTTP 409: The policy denied this operation: PolicyDenied (contract error 18)",
            ),
            (
                "409 Conflict",
                json!({"code":"wallet_rejected","details":{"contract":null,"contractError":18},"error":"The operation failed in simulation: an unidentified contract raised contract error 18."}),
                4,
                "Allowit returned HTTP 409: The operation was rejected in simulation: contract error 18",
            ),
            (
                "409 Conflict",
                json!({"code":"policy_denied","details":{"rule":"payment_limit\u{1b}[2J","error":"Paid\nout"}}),
                20,
                "Allowit returned HTTP 409: The policy denied this operation: no rule named",
            ),
            (
                "409 Conflict",
                json!({"error":"Reconcile the original Stellar operation before preparing another."}),
                4,
                "Allowit returned HTTP 409: Stellar operation was not resolved: Reconcile the original Stellar operation before preparing another; retain the original request ID",
            ),
            (
                "503 Service Unavailable",
                json!({"code":"network_unavailable","error":"The rail network is unavailable."}),
                7,
                "Allowit returned HTTP 503: network unavailable; retry with the same request ID",
            ),
            (
                "504 Gateway Timeout",
                json!({"code":"network_unavailable","error":"The rail network is unavailable."}),
                7,
                "Allowit returned HTTP 504: network unavailable; retry with the same request ID",
            ),
            (
                "503 Service Unavailable",
                json!({"code":"policy_denied","details":{"rule":"payment_limit","error":"PaymentLimitExceeded"}}),
                4,
                "Allowit returned HTTP 503: Stellar operation was not resolved; retain the original request ID",
            ),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let origin = format!("http://{}", listener.local_addr().unwrap());
            let server = reply_once(
                listener,
                Duration::ZERO,
                status,
                serde_json::to_vec(&body).unwrap(),
            );
            let error = match engine_client(p.config.clone(), &origin).post(
                "/api/native/execute",
                json!({"policyId":"engine-policy","requestId":"denied-001","phase":"prepare"}),
            ) {
                Ok(_) => panic!("{body} must be refused"),
                Err(error) => error,
            };
            server.join().unwrap();
            assert_eq!((error.code, error.message.as_str()), (code, text), "{body}");
        }
    }
    /// The engine reply of a status read whose settled receipt was not yet readable.
    const RECEIPT_UNAVAILABLE: &str = "The original terminal receipt is temporarily unavailable. Retain its transaction identity.";
    /// [`poll_reads`] over scripted status reads; the last one repeats. Returns the outcome,
    /// the number of reads and the number of retained records.
    fn scripted_poll(
        wait: Duration,
        script: Vec<Reply>,
    ) -> (Result<ExecutionOutcome>, usize, usize) {
        let (outcome, bounds, saves) = scripted_poll_bounds(wait, script);
        (outcome, bounds.len(), saves)
    }
    /// [`scripted_poll`] that returns, for each read, whether it had a deadline.
    fn scripted_poll_bounds(
        wait: Duration,
        script: Vec<Reply>,
    ) -> (Result<ExecutionOutcome>, Vec<bool>, usize) {
        let p: PreparedOperation = serde_json::from_value(fixture()["prepared"].clone()).unwrap();
        let client = engine_client(p.config.clone(), "http://127.0.0.1:9");
        let (mut reads, mut saves) = (vec![], 0);
        let outcome = poll_reads(
            &client,
            "unresolved-001",
            None,
            wait,
            None,
            &mut |_, bound| {
                reads.push(bound.is_some());
                script[(reads.len() - 1).min(script.len() - 1)]()
            },
            &mut |_| {
                saves += 1;
                Ok(())
            },
        );
        (outcome, reads, saves)
    }
    /// One scripted status read.
    type Reply = Box<dyn Fn() -> Result<Option<Response>>>;
    fn status_reply(status: OperationStatus) -> Reply {
        let p: PreparedOperation = serde_json::from_value(fixture()["prepared"].clone()).unwrap();
        Box::new(move || {
            let reply = json!({"prepared":p,"operation":{"id":"unresolved-001","status":status,"transactionHash":sdk::hex(&p.transaction_hash)}});
            Ok(Some(serde_json::from_value(reply).unwrap()))
        })
    }
    fn refused(status: u16, body: serde_json::Value) -> Reply {
        Box::new(move || Err(refusal(status, &serde_json::to_vec(&body).unwrap())))
    }
    fn unresolved_reply() -> Reply {
        refused(409, json!({"error":RECEIPT_UNAVAILABLE}))
    }
    #[test]
    fn an_unresolved_status_reply_is_read_again_until_the_operation_resolves() {
        // Testnet, 2026-11-11: `exec --wait 4m` ended after 9 s with exit 4 on this reply while
        // the payment settled. The next status read of the same request ID resolves it.
        let (outcome, reads, saves) = scripted_poll(
            Duration::from_secs(30),
            vec![
                unresolved_reply(),
                status_reply(OperationStatus::Submitted),
                unresolved_reply(),
                status_reply(OperationStatus::Confirmed),
            ],
        );
        assert_eq!(outcome.unwrap().status, OperationStatus::Confirmed);
        assert_eq!((reads, saves), (4, 2));
    }
    #[test]
    fn an_unresolved_status_is_uncertain_with_the_engine_message_when_the_wait_ends() {
        let text = "Allowit returned HTTP 409: Stellar operation was not resolved: The original terminal receipt is temporarily unavailable. Retain its transaction identity; retain the original request ID";
        // Without a wait, one read decides.
        let (outcome, reads, saves) = scripted_poll(Duration::ZERO, vec![unresolved_reply()]);
        let error = outcome.unwrap_err();
        assert_eq!(
            (error.code, error.status, error.message.as_str()),
            (5, Some(409), text)
        );
        assert_eq!((reads, saves), (1, 0));
        // With a wait, the read repeats until the wait ends, and never longer.
        let started = Instant::now();
        let (outcome, reads, _) =
            scripted_poll(Duration::from_millis(1500), vec![unresolved_reply()]);
        let error = outcome.unwrap_err();
        assert_eq!((error.code, error.message.as_str()), (5, text));
        assert!(reads >= 2, "{reads}");
        let elapsed = started.elapsed();
        assert!(
            elapsed >= Duration::from_millis(1500) && elapsed < Duration::from_secs(10),
            "{elapsed:?}"
        );
    }
    #[test]
    fn every_read_after_an_unresolved_reply_ends_at_the_deadline() {
        // Codex P2 on this change: a retry without a deadline could wait for the engine timeout
        // of 180 s after a short `--wait`.
        let ended: fn() -> Reply = || Box::new(|| Ok(None));
        let (outcome, bounds, saves) =
            scripted_poll_bounds(Duration::from_secs(30), vec![unresolved_reply(), ended()]);
        // The first read needs one answer, so it has no deadline. The deadline ended the second
        // read, and the newest answer was the unresolved reply.
        assert_eq!(bounds, [false, true]);
        let error = outcome.unwrap_err();
        assert_eq!((error.code, error.status), (5, Some(409)));
        assert!(error.message.contains("temporarily unavailable"));
        assert_eq!(saves, 0);
        // After an answer with a status, the deadline returns that status.
        let (outcome, bounds, saves) = scripted_poll_bounds(
            Duration::from_secs(30),
            vec![
                unresolved_reply(),
                status_reply(OperationStatus::Submitted),
                ended(),
            ],
        );
        assert_eq!(outcome.unwrap().status, OperationStatus::Submitted);
        assert_eq!((bounds.as_slice(), saves), (&[false, true, true][..], 1));
    }
    #[test]
    fn a_typed_refusal_or_another_error_ends_the_poll_at_once() {
        let uncertain: Reply = Box::new(|| Err(Error::uncertain("Stellar transport is uncertain")));
        for (script, code, api_code) in [
            (
                refused(
                    409,
                    json!({"code":"policy_denied","details":{"rule":"payment_limit"}}),
                ),
                20,
                None,
            ),
            // A stable code that this client does not interpret stays a refusal with that code.
            (
                refused(
                    409,
                    json!({"code":"operation_expired","error":"This prepared operation expired before submission."}),
                ),
                4,
                Some("operation_expired"),
            ),
            (refused(500, json!({"error":"Internal error."})), 4, None),
            (uncertain, 5, None),
        ] {
            let (outcome, reads, saves) = scripted_poll(Duration::from_secs(30), vec![script]);
            let error = outcome.unwrap_err();
            assert_eq!(
                (error.code, error.api_code.as_deref()),
                (code, api_code),
                "{}",
                error.message
            );
            assert_eq!((reads, saves), (1, 0), "{}", error.message);
        }
    }
    #[test]
    fn an_unresolved_reply_keeps_the_engine_message_as_plain_bounded_text() {
        let message =
            |body: serde_json::Value| refusal(409, &serde_json::to_vec(&body).unwrap()).message;
        assert_eq!(
            message(json!({"error":"The receipt\u{1b}[2J is\nunavailable.\u{202e}"})),
            "Allowit returned HTTP 409: Stellar operation was not resolved: The receipt[2J isunavailable; retain the original request ID"
        );
        let long = message(json!({"error":"x".repeat(5000)}));
        assert!(long.len() < 300, "{}", long.len());
        // A reply without a message, or one that is not JSON, keeps the plain text.
        for body in [&b"{}"[..], b"<html>", b""] {
            let error = refusal(409, body);
            assert_eq!(
                error.message,
                "Allowit returned HTTP 409: Stellar operation was not resolved; retain the original request ID"
            );
            assert!(unresolved(&error));
        }
        // A hostile code is not an identifier, so it is not kept.
        let hostile = refusal(409, br#"{"code":"a b\n","error":"x"}"#);
        assert_eq!(hostile.api_code, None);
        // Only a 409 without a stable code is an unresolved reply.
        assert!(!unresolved(&refusal(500, b"{}")));
        assert!(!unresolved(&refusal(
            409,
            br#"{"code":"operation_expired"}"#
        )));
        assert!(!unresolved(&refusal(409, br#"{"code":"policy_denied"}"#)));
        assert!(!unresolved(&refusal(409, br#"{"code":"wallet_rejected"}"#)));
    }
    /// A loopback Stellar RPC that answers each JSON-RPC call with `answer(method, params)`
    /// until `stop` is set, and returns the methods it served.
    fn rpc_server(
        answer: impl Fn(&str, &serde_json::Value) -> serde_json::Value + Send + 'static,
    ) -> (
        String,
        Arc<std::sync::atomic::AtomicBool>,
        std::thread::JoinHandle<Vec<String>>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let done = stop.clone();
        let server = std::thread::spawn(move || {
            let mut methods = Vec::new();
            while !done.load(std::sync::atomic::Ordering::SeqCst) {
                let Ok((mut stream, _)) = listener.accept() else {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                };
                stream.set_nonblocking(false).unwrap();
                let mut header = Vec::new();
                while !header.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    stream.read_exact(&mut byte).unwrap();
                    header.push(byte[0]);
                }
                let length: usize = String::from_utf8(header)
                    .unwrap()
                    .lines()
                    .find_map(|v| {
                        v.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|s| s.trim().parse().unwrap())
                    })
                    .unwrap();
                let mut body = vec![0; length];
                stream.read_exact(&mut body).unwrap();
                let request: serde_json::Value = serde_json::from_slice(&body).unwrap();
                let method = request["method"].as_str().unwrap().to_owned();
                let result = answer(&method, &request["params"]);
                methods.push(method);
                let response = serde_json::to_vec(
                    &json!({"jsonrpc":"2.0","id":request["id"],"result":result}),
                )
                .unwrap();
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n", response.len()).unwrap();
                stream.write_all(&response).unwrap();
            }
            methods
        });
        (url, stop, server)
    }
    /// RPC answers for a policy wallet whose fixture packet expires at 86700 with nonce 4: the
    /// original hash, the closing ledger 130 and its close time, then the fixture's wallet
    /// discovery replies dated `entries_ledger`.
    fn lapse_rpc(
        transaction: serde_json::Value,
        entries_ledger: u64,
    ) -> impl Fn(&str, &serde_json::Value) -> serde_json::Value + Send + 'static {
        let calls = fixture()["calls"].as_array().unwrap().clone();
        move |method, params| match method {
            "getTransaction" => transaction.clone(),
            "getLatestLedger" => json!({"sequence":130}),
            _ => {
                let mut result = calls
                    .iter()
                    .find(|c| c["method"] == method && c["params"] == *params)
                    .unwrap_or_else(|| panic!("unexpected {method} {params}"))["result"]
                    .clone();
                if method == "getLedgerEntries" {
                    result["latestLedger"] = json!(entries_ledger);
                }
                result
            }
        }
    }
    #[test]
    fn released_operation_fails_only_with_an_independent_lapse_proof() {
        // Common R4.1 on testnet: the engine released the expired operation as `failed`
        // without a receipt, and the CLI reported `submissionUnknown`.
        let p: PreparedOperation = serde_json::from_value(fixture()["prepared"].clone()).unwrap();
        assert_eq!((p.expires_at, p.state.nonce), (86700, 4));
        let not_found =
            json!({"status":"NOT_FOUND","latestLedger":130,"latestLedgerCloseTime":"86700"});
        let (rpc, stop, server) = rpc_server(lapse_rpc(not_found.clone(), 130));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let engine = reply_once(
            listener,
            Duration::ZERO,
            "200 OK",
            serde_json::to_vec(&json!({"prepared":p,"operation":{"id":"released-001","status":OperationStatus::Failed,"transactionHash":sdk::hex(&p.transaction_hash)},"signedOperation":null,"receipt":null})).unwrap(),
        );
        let mut client = engine_client(p.config.clone(), &origin);
        client.rpc_url = rpc.clone();
        let r = client
            .post(
                "/api/native/execute/status",
                json!({"requestId":"released-001"}),
            )
            .unwrap();
        engine.join().unwrap();
        assert!(r.released);
        assert_eq!(r.operation.status, OperationStatus::SubmissionUnknown);
        let mut record = Record {
            backend_origin: Some(origin.clone()),
            policy_id: "engine-policy".into(),
            request_id: "released-001".into(),
            config: p.config.clone(),
            request: p.request.clone(),
            prepared: Some(p.clone()),
            agent_signature: None,
            status: Some(OperationStatus::SubmissionUnknown),
            lapsed: false,
        };
        assert!(client.proven_release(&r, Some(&record)));
        record.prepared = None;
        assert!(!client.proven_release(&r, Some(&record)));
        assert!(!client.proven_release(&r, None));
        record.prepared = Some(p.clone());
        let mut unreleased = engine_client(p.config.clone(), &origin);
        unreleased.rpc_url = rpc.clone();
        let mut submitted: Response = serde_json::from_value(json!({"prepared":p,"operation":{"id":"released-001","status":OperationStatus::SubmissionUnknown,"transactionHash":sdk::hex(&p.transaction_hash)}})).unwrap();
        assert!(!unreleased.proven_release(&submitted, Some(&record)));
        submitted.released = true;
        unreleased.rpc_url.clear();
        assert!(!unreleased.proven_release(&submitted, Some(&record)));
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        let methods = server.join().unwrap();
        assert_eq!(methods[0], "getTransaction");
        assert!(methods.iter().any(|m| m == "getLedgerEntries"));

        let mut advanced = p.clone();
        advanced.state.nonce = 3;
        for (transaction, entries_ledger, packet, lapsed) in [
            (not_found.clone(), 130, &p, true),
            (
                json!({"status":"FAILED","latestLedger":130,"latestLedgerCloseTime":86701}),
                131,
                &p,
                true,
            ),
            // The closing ledger precedes the expiry: the wallet can still execute it.
            (
                json!({"status":"NOT_FOUND","latestLedger":130,"latestLedgerCloseTime":"86699"}),
                130,
                &p,
                false,
            ),
            (
                json!({"status":"SUCCESS","latestLedger":130,"latestLedgerCloseTime":"86700"}),
                130,
                &p,
                false,
            ),
            (
                json!({"status":"NOT_FOUND","latestLedger":130}),
                130,
                &p,
                false,
            ),
            // The wallet entries predate the closing ledger.
            (not_found.clone(), 129, &p, false),
            // The wallet nonce moved past the packet: some operation executed.
            (not_found.clone(), 130, &advanced, false),
        ] {
            let (rpc, stop, server) = rpc_server(lapse_rpc(transaction.clone(), entries_ledger));
            let result = sdk::rpc::operation_lapsed(&sdk::rpc::HttpRpc::new(&rpc).unwrap(), packet);
            stop.store(true, std::sync::atomic::Ordering::SeqCst);
            server.join().unwrap();
            assert_eq!(result, Ok(lapsed), "{transaction} at {entries_ledger}");
        }
    }
    /// Advance the wallet nonce in the instance entries of a `getLedgerEntries` reply, as if
    /// the wallet executed another operation.
    fn advance_nonce(reply: &mut serde_json::Value) {
        use stellar_xdr::{LedgerEntryData, Limits, ReadXdr, ScVal, WriteXdr};
        fn walk(value: &mut ScVal) {
            let entries = match value {
                ScVal::Map(Some(map)) => map.0.iter_mut(),
                ScVal::ContractInstance(instance) => match &mut instance.storage {
                    Some(map) => map.0.iter_mut(),
                    None => return,
                },
                _ => return,
            };
            for entry in entries {
                match (&entry.key, &mut entry.val) {
                    (ScVal::Symbol(key), ScVal::U64(nonce)) if key.0.as_slice() == b"nonce" => {
                        *nonce += 1
                    }
                    (_, val) => walk(val),
                }
            }
        }
        for entry in reply["entries"].as_array_mut().unwrap() {
            let mut data =
                LedgerEntryData::from_xdr_base64(entry["xdr"].as_str().unwrap(), Limits::none())
                    .unwrap();
            if let LedgerEntryData::ContractData(contract) = &mut data {
                walk(&mut contract.val);
            }
            entry["xdr"] = json!(data.to_xdr_base64(Limits::none()).unwrap());
        }
    }
    #[test]
    fn proven_failure_stays_failed_after_the_nonce_moves_or_rpc_fails() {
        // Codex P2 on PR #45: poll journaled only `failed`, so a later status query that could
        // not repeat the lapse proof overwrote the terminal failure with `submissionUnknown`.
        let p: PreparedOperation = serde_json::from_value(fixture()["prepared"].clone()).unwrap();
        let not_found =
            json!({"status":"NOT_FOUND","latestLedger":130,"latestLedgerCloseTime":"86700"});
        let released = serde_json::to_vec(&json!({"prepared":p,"operation":{"id":"released-001","status":OperationStatus::Failed,"transactionHash":sdk::hex(&p.transaction_hash)},"signedOperation":null,"receipt":null})).unwrap();
        // One engine status reply that releases the operation, read by a client using `rpc`.
        let query = |rpc: &str| {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let origin = format!("http://{}", listener.local_addr().unwrap());
            let engine = reply_once(listener, Duration::ZERO, "200 OK", released.clone());
            let mut client = engine_client(p.config.clone(), &origin);
            client.rpc_url = rpc.into();
            let r = client
                .post(
                    "/api/native/execute/status",
                    json!({"requestId":"released-001"}),
                )
                .unwrap();
            engine.join().unwrap();
            assert!(r.released);
            (client, r)
        };
        let temp = tempfile::tempdir().unwrap();
        let journal = Store::open(&temp.path().canonicalize().unwrap().join("journal")).unwrap();
        let record: Record = serde_json::from_value(json!({"policyId":"engine-policy","requestId":"released-001","config":p.config,"request":p.request,"prepared":p,"agentSignature":null,"status":OperationStatus::SubmissionUnknown})).unwrap();
        let (rpc, stop, server) = rpc_server(lapse_rpc(not_found.clone(), 130));
        let (client, mut r) = query(&rpc);
        client.settle(&mut r, Some(&record)).unwrap();
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        server.join().unwrap();
        assert_eq!(r.operation.status, OperationStatus::Failed);
        journal
            .save(
                "released",
                &journaled(&client, "released-001", Some(record), &r),
            )
            .unwrap();

        let proof = lapse_rpc(not_found, 130);
        let (moved, stop, server) = rpc_server(move |method, params| {
            let mut reply = proof(method, params);
            if method == "getLedgerEntries" {
                advance_nonce(&mut reply);
            }
            reply
        });
        assert_eq!(
            sdk::rpc::operation_lapsed(&sdk::rpc::HttpRpc::new(&moved).unwrap(), &p),
            Ok(false)
        );
        let closed = {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            format!("http://{}", listener.local_addr().unwrap())
        };
        for rpc in [moved.as_str(), closed.as_str(), ""] {
            let record: Record = journal.load("released").unwrap().unwrap();
            let (client, mut r) = query(rpc);
            client.settle(&mut r, Some(&record)).unwrap();
            assert_eq!(r.operation.status, OperationStatus::Failed, "RPC {rpc:?}");
            journal
                .save(
                    "released",
                    &journaled(&client, "released-001", Some(record), &r),
                )
                .unwrap();
        }
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        server.join().unwrap();
        let mut record: Record = journal.load("released").unwrap().unwrap();
        assert_eq!(
            (record.status.clone(), record.lapsed),
            (Some(OperationStatus::Failed), true)
        );
        // A confirmed engine report contradicts the retained proof.
        let (client, mut r) = query("");
        r.operation.status = OperationStatus::Confirmed;
        assert!(client.settle(&mut r, Some(&record)).is_err());
        // A journaled `failed` without this client's proof stays unresolved.
        record.lapsed = false;
        let (client, mut r) = query("");
        client.settle(&mut r, Some(&record)).unwrap();
        assert_eq!(r.operation.status, OperationStatus::SubmissionUnknown);
        assert!(!journaled(&client, "released-001", Some(record), &r).lapsed);
    }
    #[test]
    fn failed_policy_wallet_envelope_remains_unknown_on_the_server_client_wire() {
        use ed25519_dalek::Signer;
        use stellar_xdr::{
            Limits, TransactionResult, TransactionResultExt, TransactionResultResult, WriteXdr,
        };
        struct TestKey {
            account: String,
        }
        impl AgentSigner for TestKey {
            fn account(&self) -> &str {
                &self.account
            }
            fn sign_hash(&self, hash: &[u8; 32]) -> sdk::Result<[u8; 64]> {
                Ok(ed25519_dalek::SigningKey::from_bytes(&[42; 32])
                    .sign(hash)
                    .to_bytes())
            }
        }
        let account = sdk::account_for_seed(&[42; 32]);
        let data = fixture();
        let signed: SignedOperation = serde_json::from_value(data["signed"].clone()).unwrap();
        let result = TransactionResult {
            fee_charged: 100,
            result: TransactionResultResult::TxFailed(Default::default()),
            ext: TransactionResultExt::V0,
        };
        let receipt = sdk::rpc::VerifiedReceipt {
            transaction_hash: signed.transaction_hash,
            status: OperationStatus::Failed,
            ledger: 777,
            envelope_xdr: signed.transaction_xdr.clone(),
            result_xdr: result.to_xdr_base64(Limits::none()).unwrap(),
        };
        sdk::rpc::validate_settled_policy_packet(&signed, &receipt).unwrap();
        let body = serde_json::to_vec(&json!({"prepared":signed.prepared,"signedOperation":signed,"operation":{"id":"wire-status-001","status":OperationStatus::SubmissionUnknown,"transactionHash":sdk::hex(&receipt.transaction_hash)},"receipt":receipt})).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
            }
            let headers = String::from_utf8(request).unwrap();
            let length: usize = headers
                .lines()
                .find_map(|v| {
                    v.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(|s| s.trim().parse().unwrap())
                })
                .unwrap();
            let mut request = vec![0; length];
            stream.read_exact(&mut request).unwrap();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(&body).unwrap();
        });
        // Exercise the private transport projection with the original signed context.
        // Fresh profile admission is tested through the public constructor elsewhere.
        let client = Client::from_context(
            ExecutionProfile {
                policy_id: "wire-status-policy".into(),
                config: signed.prepared.config.clone(),
                endpoints: Endpoints {
                    execute: "/api/native/execute".into(),
                    status: "/api/native/execute/status".into(),
                },
            },
            Arc::new(TestKey { account }),
            &origin,
            None,
        )
        .unwrap();
        let response = client
            .post(
                "/api/native/execute/status",
                json!({"requestId":"wire-status-001"}),
            )
            .unwrap();
        server.join().unwrap();
        assert_eq!(
            response.operation.status,
            OperationStatus::SubmissionUnknown
        );
        validate_response_receipt(&response).unwrap();
        let receipt = response.receipt.unwrap();
        assert_eq!(receipt.status, OperationStatus::Failed);
        assert_eq!(
            super::super::projected_status(&response.prepared.config.route, receipt.status),
            response.operation.status
        );
    }
}
