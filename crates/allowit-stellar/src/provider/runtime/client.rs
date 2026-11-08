//! Agent requests for an installed Stellar wallet profile. The public wallet
//! profile names the wallet, its roles and the engine endpoints; the agent
//! key signs. Requests go to the profile's `/api/native/execute` endpoints and
//! are journaled in caller-supplied private storage before they leave the process.
use crate::host::{
    config::parse_origin,
    error::{Error, Result},
    typed_request::operation_nonce,
};
use crate::rpc::Rpc;
use crate::workflow::ExecutionRequest;
use crate::{
    self as sdk, DetachedSignature, OperationStatus, PreparedOperation, SignedOperation,
    WalletConfig, WalletRoute,
};
use allowit_core::{
    client::store::Store,
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

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
// Preparation can include multiple ledger reads and simulations. Leave time to sign its packet.
const PREPARATION_TIMEOUT: Duration = Duration::from_secs(90);

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
    v.map_err(Error::config)
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
                timeout: PREPARATION_TIMEOUT,
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
    fn post(&self, path: &str, body: serde_json::Value, timeout: Duration) -> Result<Response> {
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
        let response = self
            .http
            .send_success_body(
                Request {
                    method: Method::Post,
                    url: &format!("{}{path}", self.origin),
                    headers: &headers,
                    body: Some(&bytes),
                },
                Some(Instant::now() + timeout),
            )
            .map_err(|_| {
                Error::uncertain(
                    "Stellar transport is uncertain; recover the original request ID with status",
                )
            })?;
        if !(200..300).contains(&response.status) {
            return Err(Error::api(
                response.status,
                "Stellar operation was not resolved; retain the original request ID",
            ));
        }
        let mut parsed: Response = serde_json::from_slice(&response.body).map_err(|_| {
            Error::uncertain("Invalid Stellar response; recover the original request ID")
        })?;
        parsed.operation.status =
            super::projected_status(&parsed.prepared.config.route, parsed.operation.status);
        Ok(parsed)
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
        let r = self.post(
            &self.bundle.endpoints.status,
            json!({"policyId":self.bundle.policy_id,"requestId":id}),
            REQUEST_TIMEOUT,
        )?;
        self.validate(&r, id, record, true)?;
        Ok(r)
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
    poll(c, id, old, journal, &name, wait)
}
/// Prepares, signs and submits one typed request, then polls within `wait`.
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
            return poll(c, &id, Some(old), journal, &name, wait);
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
            Ok(_) => return poll(c, &id, Some(old), journal, &name, wait),
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
            },
            None,
        )
    };
    // Preserve the original intent. Only an explicit exec can continue unsigned preparation.
    journal.save(&name, &record).map_err(journal_error)?;
    let mut prepared = if let Some(response) = resumed {
        response
    } else {
        c.post(
            &c.bundle.endpoints.execute,
            json!({"policyId":policy,"requestId":id,"phase":"prepare","request":request}),
            PREPARATION_TIMEOUT,
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
    let response = c.post(
        &c.bundle.endpoints.execute,
        json!({"policyId":policy,"requestId":id,"phase":"submit","agentSignature":signature}),
        REQUEST_TIMEOUT,
    )?;
    c.validate(&response, &id, Some(&record), false)?;
    record.status = Some(response.operation.status.clone());
    journal.save(&name, &record).map_err(journal_error)?;
    if terminal(&response.operation.status) || wait.is_zero() {
        return Ok(render(&response));
    }
    poll(c, &id, Some(record), journal, &name, wait)
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
fn poll(
    c: &Client,
    id: &str,
    mut record: Option<Record>,
    journal: &Store,
    name: &str,
    wait: Duration,
) -> Result<ExecutionOutcome> {
    let deadline = std::time::Instant::now()
        .checked_add(wait)
        .ok_or_else(|| Error::usage("The Stellar polling deadline is too large"))?;
    loop {
        let r = c.status(id, record.as_ref())?;
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
            },
        };
        if old.prepared.is_none() {
            old.prepared = Some(r.prepared.clone());
        }
        old.status = Some(r.operation.status.clone());
        journal.save(name, &old).map_err(journal_error)?;
        record = Some(old);
        if terminal(&r.operation.status) || std::time::Instant::now() >= deadline {
            return Ok(render(&r));
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionOutcome {
    pub request_id: String,
    pub status: OperationStatus,
    pub transaction_hash: String,
}
fn render(r: &Response) -> ExecutionOutcome {
    ExecutionOutcome {
        request_id: r.operation.id.clone(),
        status: r.operation.status.clone(),
        transaction_hash: r.operation.transaction_hash.clone(),
    }
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
                            assert!(header.starts_with("POST /api/native/execute/status "));
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
                REQUEST_TIMEOUT,
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
