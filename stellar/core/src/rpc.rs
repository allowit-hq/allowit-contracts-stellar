//! Stellar RPC protocol, native observations and transaction validity.
//! Common transport owns HTTP bounds; SDK engine owns persistence, polling and retry workflows.
use crate::contract::{CustodyState, PolicyBinding};
use crate::*;
use allowit_policy_sdk::transport::rpc::{EnvelopeValidation, ErrorKind, RpcClient};
use serde_json::{Value, json};
use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

fn transaction_hash_for(network: &str, tx: &Transaction) -> Result<[u8; 32]> {
    super::transaction_hash(network, tx)
}
pub trait Rpc: Send + Sync {
    fn call(&self, method: &str, params: Value) -> Result<Value>;
}
/// Stellar JSON-RPC protocol adapter over the bounded common host transport.
pub struct HttpRpc {
    client: RpcClient,
    id: AtomicU64,
}
impl HttpRpc {
    pub fn new(url: &str) -> Result<Self> {
        Ok(Self {
            client: RpcClient::new(url, Duration::from_secs(30), MAX_BYTES)
                .map_err(|_| "RPC requires HTTPS or local HTTP without credentials")?
                .accept_success_statuses(),
            id: AtomicU64::new(1),
        })
    }
}
impl Rpc for HttpRpc {
    fn call(&self, method: &str, params: Value) -> Result<Value> {
        self.client
            .call_with_id(
                method,
                &params,
                self.id.fetch_add(1, Ordering::Relaxed),
                EnvelopeValidation::StrictIdentity,
                None,
            )
            .map_err(|error| {
                match error.kind {
                    ErrorKind::Http => "Stellar RPC rejected the HTTP request",
                    ErrorKind::Size => "RPC response exceeds limit",
                    ErrorKind::MissingResult => "Missing RPC result",
                    ErrorKind::Json | ErrorKind::Envelope | ErrorKind::Refused => {
                        "Invalid or failed Stellar RPC response"
                    }
                    _ => "Stellar RPC transport result is unknown",
                }
                .into()
            })
    }
}
pub fn get_account(rpc: &dyn Rpc, address: &str) -> Result<AccountState> {
    let key = LedgerKey::Account(LedgerKeyAccount {
        account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(account_key(
            address,
        )?))),
    });
    let value = rpc.call("getLedgerEntries", json!({"keys":[xdr(&key)?]}))?;
    let entries = value["entries"]
        .as_array()
        .ok_or("Missing account entries")?;
    if entries.len() != 1 {
        return Err("Native account not found".into());
    }
    let raw = entries[0]["xdr"].as_str().ok_or("Missing account XDR")?;
    let LedgerEntryData::Account(account) = read(raw)? else {
        return Err("Wrong ledger entry type".into());
    };
    let PublicKey::PublicKeyTypeEd25519(key) = account.account_id.0;
    let actual = ed25519::PublicKey(key.0).to_string();
    if actual != address {
        return Err("Ledger account identity differs".into());
    }
    let mut signers = Vec::new();
    for s in account.signers.iter() {
        let key = match &s.key {
            SignerKey::Ed25519(key) => ed25519::PublicKey(key.0).to_string(),
            SignerKey::PreAuthTx(key) => stellar_strkey::PreAuthTx(key.0).to_string(),
            SignerKey::HashX(key) => stellar_strkey::HashX(key.0).to_string(),
            SignerKey::Ed25519SignedPayload(key) => ed25519::SignedPayload {
                ed25519: key.ed25519.0,
                payload: key.payload.to_vec(),
            }
            .to_string(),
        };
        signers.push(AccountSigner {
            key,
            weight: s.weight,
        });
    }
    Ok(AccountState {
        address: actual,
        sequence: account.seq_num.0,
        master_weight: u32::from(account.thresholds.0[0]),
        low_threshold: u32::from(account.thresholds.0[1]),
        medium_threshold: u32::from(account.thresholds.0[2]),
        high_threshold: u32::from(account.thresholds.0[3]),
        signers,
    })
}
/// Prepare from authoritative current state and simulate the exact native policy execution.
/// `accounting` is required only for the existing classic/native route. policy wallet property/validation
/// policies receive an ephemeral preflight binding for new signing. Nothing is submitted.
pub fn prepare(
    rpc: &dyn Rpc,
    c: &WalletConfig,
    request: &ExecutionRequest,
    accounting: Option<NativeAccounting>,
    now: u64,
    expires_at: u64,
) -> Result<PreparedOperation> {
    prepare_with(
        rpc,
        c,
        request,
        &ExecutionTerms::default(),
        accounting,
        now,
        expires_at,
    )
}
/// `prepare` with execution args and expense bounds. An operation other than a transfer first
/// checks that the installed code runs it.
pub fn prepare_with(
    rpc: &dyn Rpc,
    c: &WalletConfig,
    request: &ExecutionRequest,
    terms: &ExecutionTerms,
    accounting: Option<NativeAccounting>,
    now: u64,
    expires_at: u64,
) -> Result<PreparedOperation> {
    let state = trusted_state(rpc, c, accounting)?;
    if c.route == WalletRoute::Native {
        return super::prepare_with(c, request, terms, &state, now, expires_at);
    }
    let operation = operation_from_request(c, request)?;
    if operation.kind() != OperationKind::Transfer {
        PolicyBinding::from_scval(&readonly_call(rpc, c, &state.source, "policy_binding")?)?
            .verify(c, operation.kind())?;
    }
    let intent = prepare_for_native_preflight(c, request, terms, &state, now, expires_at)?;
    simulate(rpc, &intent)
}
pub(crate) fn reject_restoration(value: &Value) -> Result<()> {
    if value
        .get("restorePreamble")
        .is_some_and(|value| !value.is_null())
    {
        return Err("Native policy preflight requires restoration".into());
    }
    if let Some(data) = value.get("transactionData") {
        let data: SorobanTransactionData =
            read(data.as_str().ok_or("Invalid native preflight resources")?)?;
        if matches!(data.ext,SorobanTransactionDataExt::V1(ref ext) if !ext.archived_soroban_entries.is_empty())
        {
            return Err("Native policy preflight includes archived entries".into());
        }
    }
    Ok(())
}
/// Simulate an original unsigned policy wallet intent and bind successful native validation to it.
/// Supplied resource XDR or JSON booleans alone never create a signing approval.
pub fn simulate(rpc: &dyn Rpc, p: &PreparedOperation) -> Result<PreparedOperation> {
    let encoded = simulated_resources(rpc, p)?;
    let mut prepared = attach_simulation(p, &encoded)?;
    record_native_preflight(&mut prepared)?;
    Ok(prepared)
}
/// Simulate the unchanged intent and return the checked resource requirements as XDR.
/// This does not build a replacement transaction, so it does not check source quorum against a
/// rebuilt hash. `simulate` attaches the result; revalidation compares it with the original.
fn simulated_resources(rpc: &dyn Rpc, p: &PreparedOperation) -> Result<String> {
    validate_retained_prepared(p)?;
    if p.config.route != WalletRoute::PolicyWallet {
        return Err("Native contract simulation requires policy wallet custody".into());
    }
    if rpc.call("getNetwork", json!({}))?["passphrase"] != passphrase(&p.config.network)? {
        return Err("Simulation network differs from installation".into());
    }
    // Stellar RPC rejects recording mode when the transaction already has auth entries.
    // An unsigned intent is therefore recorded from a copy without them; the recorded scope is
    // compared with the intent's entries below. The signed intent is simulated as is in enforce
    // mode, which supplies the final resources, including the service entry's fixed nonce key.
    let recording = authorization::server_signature(p, false)? == ScVal::Void;
    let (transaction, mode) = if recording {
        let TransactionEnvelope::Tx(mut env) = read(&p.transaction_xdr)? else {
            return Err("Unsupported preflight envelope".into());
        };
        let mut operations = env.tx.operations.to_vec();
        let OperationBody::InvokeHostFunction(op) = &mut operations[0].body else {
            return Err("Expected one native policy invocation".into());
        };
        op.auth = VecM::default();
        env.tx.operations = operations.try_into().map_err(err)?;
        (xdr(&TransactionEnvelope::Tx(env))?, "record")
    } else {
        (p.transaction_xdr.clone(), "enforce")
    };
    let v = rpc.call(
        "simulateTransaction",
        json!({"transaction":transaction,"authMode":mode}),
    )?;
    if v.get("error").is_some_and(|value| !value.is_null()) {
        return Err("policy wallet simulation rejected the exact policy operation".into());
    }
    reject_restoration(&v)?;
    let result = readonly_result(&v)?;
    if result != expected_receipt(p)?.scval()? {
        return Err("Native simulation returned a different transfer receipt".into());
    }
    let TransactionEnvelope::Tx(env) = read(&p.transaction_xdr)? else {
        return Err("Unsupported preflight envelope".into());
    };
    let OperationBody::InvokeHostFunction(op) = &env.tx.operations[0].body else {
        return Err("Expected one native policy invocation".into());
    };
    let observed = v["results"][0]["auth"]
        .as_array()
        .ok_or("Missing native preflight authorization scope")?;
    let auth = observed
        .iter()
        .map(|entry| {
            read(
                entry
                    .as_str()
                    .ok_or("Invalid native preflight authorization")?,
            )
        })
        .collect::<Result<Vec<SorobanAuthorizationEntry>>>()?;
    let same = if recording {
        auth.len() == op.auth.len()
            && auth.iter().zip(op.auth.iter()).all(|(actual, expected)| {
                actual.root_invocation == expected.root_invocation
                    && match (&actual.credentials, &expected.credentials) {
                        (SorobanCredentials::SourceAccount, SorobanCredentials::SourceAccount) => {
                            true
                        }
                        (SorobanCredentials::Address(a), SorobanCredentials::Address(b)) => {
                            a.address == b.address
                        }
                        _ => false,
                    }
            })
    } else {
        auth.as_slice() == op.auth.as_slice()
    };
    if !same {
        return Err("Native preflight authorization differs from the exact intent".into());
    }
    let encoded = v["transactionData"]
        .as_str()
        .ok_or("Missing Soroban resource simulation")?;
    let resources: SorobanTransactionData = read(encoded)?;
    let minimum = v["minResourceFee"]
        .as_str()
        .ok_or("Missing native preflight minimum fee")?
        .parse::<u64>()
        .map_err(err)?;
    if resources.resource_fee < 0 || minimum > resources.resource_fee as u64 {
        return Err("Native preflight fee is below its minimum".into());
    }
    Ok(encoded.into())
}
/// Revalidate an existing unsigned gateway intent through a locally trusted native RPC.
/// The original transaction, hash and operation identity remain unchanged. Current authority,
/// policy configuration and nonce must match the intent; its existing resources must cover
/// fresh simulation. Only the private in-memory signing marker is added. Nothing is submitted.
pub fn revalidate_prepared(
    rpc: &dyn Rpc,
    p: &PreparedOperation,
    now: u64,
) -> Result<PreparedOperation> {
    validate_retained_prepared(p)?;
    if p.config.route != WalletRoute::PolicyWallet
        || p.state.contract_version != Some(CONTRACT_VERSION)
        || p.created_at > now
        || now >= p.expires_at
    {
        return Err(
            "Current unexpired policy wallet intent is required for native revalidation".into(),
        );
    }
    authorization::server_signature(p, true)?;
    let mut current = trusted_state(rpc, &p.config, None)?;
    // Observation ledgers can advance without changing the transaction's authority or state.
    current.ledger = p.state.ledger;
    if current != p.state {
        return Err("Current native state differs from the existing prepared intent".into());
    }
    let original: SorobanTransactionData = read(
        p.simulation_data
            .as_deref()
            .ok_or("Existing intent has no bounded Soroban resources")?,
    )?;
    reject_restoration(&json!({"transactionData":xdr(&original)?}))?;
    let mut keys = std::collections::BTreeSet::new();
    if !original
        .resources
        .footprint
        .read_only
        .iter()
        .chain(original.resources.footprint.read_write.iter())
        .all(|key| keys.insert(key))
    {
        return Err("Existing resource footprint has duplicate or overlapping keys".into());
    }
    // Fresh requirements can be smaller than the existing resources. Attaching them would change
    // the hash, and an exact-hash preauthorization of the source would no longer match. Compare
    // the requirements only; `validate_prepared` below checks quorum on the unchanged original.
    let required: SorobanTransactionData = read(&simulated_resources(rpc, p)?)?;
    let have = &original.resources;
    let need = &required.resources;
    let footprint_covers =
        need.footprint
            .read_write
            .iter()
            .all(|k| have.footprint.read_write.contains(k))
            && need.footprint.read_only.iter().all(|k| {
                have.footprint.read_only.contains(k) || have.footprint.read_write.contains(k)
            });
    if !footprint_covers
        || have.instructions < need.instructions
        || have.disk_read_bytes < need.disk_read_bytes
        || have.write_bytes < need.write_bytes
        || original.resource_fee < required.resource_fee
    {
        return Err("Existing transaction resources do not cover native revalidation".into());
    }
    let mut validated = p.clone();
    record_native_preflight(&mut validated)?;
    validate_prepared(&validated, now)?;
    Ok(validated)
}
/// Native outcome of one `sendTransaction` attempt. Persistence and retry policy belong to SDK engine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Broadcast {
    Submitted,
    RetryLater,
    Rejected { error_result_xdr: Option<String> },
    Unknown,
}
/// Validate a new signed operation and send its exact bytes once.
pub fn broadcast(rpc: &dyn Rpc, signed: &SignedOperation, now: u64) -> Result<Broadcast> {
    validate_signed(signed, now)?;
    send_transaction(
        rpc,
        &signed.prepared.config.network,
        &signed.transaction_xdr,
    )
}
/// Hash a signed native transaction without rebuilding or authorizing it.
pub fn signed_transaction_hash(network: &str, envelope_xdr: &str) -> Result<[u8; 32]> {
    let TransactionEnvelope::Tx(envelope) = read(envelope_xdr)? else {
        return Err("Expected a signed v1 transaction".into());
    };
    // Exact-hash PreAuthTx quorum can legitimately need zero envelope signatures.
    // This helper establishes transaction identity. The caller validates authority.
    transaction_hash_for(network, &envelope.tx)
}
/// Send an already signed native envelope once and decode only the native response.
/// The caller validates owner/agent authority before passing bytes to this transport operation.
pub fn send_transaction(rpc: &dyn Rpc, network: &str, envelope_xdr: &str) -> Result<Broadcast> {
    let expected = hex(&signed_transaction_hash(network, envelope_xdr)?);
    let value = match rpc.call("sendTransaction", json!({"transaction":envelope_xdr})) {
        Ok(value) => value,
        Err(_) => return Ok(Broadcast::Unknown),
    };
    if value["hash"].as_str() != Some(expected.as_str()) {
        return Ok(Broadcast::Unknown);
    }
    Ok(match value["status"].as_str() {
        Some("PENDING" | "DUPLICATE") => Broadcast::Submitted,
        Some("TRY_AGAIN_LATER") => Broadcast::RetryLater,
        Some("ERROR") => Broadcast::Rejected {
            error_result_xdr: value["errorResultXdr"].as_str().map(String::from),
        },
        _ => Broadcast::Unknown,
    })
}
pub fn status_by_hash(
    rpc: &dyn Rpc,
    network: &str,
    transaction_hash: &[u8; 32],
) -> Result<OperationStatus> {
    let v = rpc.call("getTransaction", json!({"hash":hex(transaction_hash)}))?;
    verify_settlement(&v, network, transaction_hash)
}
fn verify_settlement(
    v: &Value,
    network: &str,
    transaction_hash: &[u8; 32],
) -> Result<OperationStatus> {
    if matches!(v["status"].as_str(), Some("SUCCESS" | "FAILED")) {
        let envelope: TransactionEnvelope = read(
            v["envelopeXdr"]
                .as_str()
                .ok_or("Settlement envelope is required")?,
        )?;
        let TransactionEnvelope::Tx(envelope) = envelope else {
            return Err("Unexpected settlement envelope".into());
        };
        if &transaction_hash_for(network, &envelope.tx)? != transaction_hash {
            return Err("Settlement transaction identity differs".into());
        }
        let result: TransactionResult = read(
            v["resultXdr"]
                .as_str()
                .ok_or("Settlement result is required")?,
        )?;
        if v["status"] == "SUCCESS"
            && !matches!(result.result, TransactionResultResult::TxSuccess(_))
        {
            return Err("Settlement success and result differ".into());
        }
        if v["status"] == "FAILED" && matches!(result.result, TransactionResultResult::TxSuccess(_))
        {
            return Err("Settlement failure and result differ".into());
        }
    }
    Ok(match v["status"].as_str() {
        Some("SUCCESS") => OperationStatus::Confirmed,
        Some("FAILED") => OperationStatus::Failed,
        Some("NOT_FOUND") => OperationStatus::SubmissionUnknown,
        _ => return Err("Unknown Stellar settlement state".into()),
    })
}
/// A chain result bound to the requested network and exact transaction bytes.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerifiedReceipt {
    pub transaction_hash: [u8; 32],
    pub status: OperationStatus,
    pub ledger: u32,
    pub envelope_xdr: String,
    pub result_xdr: String,
}
/// Recheck a retained receipt before projecting it through another interface.
pub fn validate_receipt(
    receipt: &VerifiedReceipt,
    network: &str,
    expected_hash: &[u8; 32],
) -> Result<()> {
    if receipt.transaction_hash != *expected_hash
        || receipt.ledger == 0
        || !matches!(
            receipt.status,
            OperationStatus::Confirmed | OperationStatus::Failed
        )
    {
        return Err("Invalid retained Stellar receipt identity".into());
    }
    let value = json!({"status":if receipt.status==OperationStatus::Confirmed {"SUCCESS"} else {"FAILED"},"envelopeXdr":receipt.envelope_xdr,"resultXdr":receipt.result_xdr});
    if verify_settlement(&value, network, expected_hash)? != receipt.status {
        return Err("Retained Stellar receipt result differs".into());
    }
    Ok(())
}
/// Verify an exact policy-wallet envelope using its chain receipt after key rotation.
/// This checks native identity and the retained server authorization, without current signing admission.
/// A failed enclosing transaction does not revoke its reusable address authorization.
pub fn validate_settled_policy_packet(
    signed: &SignedOperation,
    receipt: &VerifiedReceipt,
) -> Result<()> {
    let prepared = &signed.prepared;
    if prepared.config.route != WalletRoute::PolicyWallet {
        return Err("Chain-only recovery requires a policy wallet packet".into());
    }
    validate_retained_prepared(prepared)?;
    validate_receipt(
        receipt,
        &prepared.config.network,
        &prepared.transaction_hash,
    )?;
    if signed.transaction_hash != prepared.transaction_hash
        || signed.transaction_xdr != receipt.envelope_xdr
    {
        return Err("The settlement envelope differs from the verified receipt".into());
    }
    let (TransactionEnvelope::Tx(envelope), TransactionEnvelope::Tx(unsigned)) = (
        read(&signed.transaction_xdr)?,
        read(&prepared.transaction_xdr)?,
    ) else {
        return Err("Unsupported settlement envelope".into());
    };
    if envelope.tx != unsigned.tx {
        return Err("The settlement transaction differs from its original packet".into());
    }
    let Some(OperationBody::InvokeHostFunction(op)) =
        unsigned.tx.operations.first().map(|op| &op.body)
    else {
        return Err("The policy invocation is missing".into());
    };
    // Retained preparation validates the exact server scope/signature when present.
    // Settlement recovery additionally requires that authorization to be present.
    if !matches!(op.auth.get(1).map(|entry| &entry.credentials), Some(SorobanCredentials::Address(credentials)) if credentials.signature != ScVal::Void)
    {
        return Err("The original server authorization is unsigned".into());
    }
    Ok(())
}

/// Read a verified terminal receipt. Absence remains unknown and does not release reservations.
pub fn receipt_by_hash(
    rpc: &dyn Rpc,
    network: &str,
    transaction_hash: &[u8; 32],
) -> Result<Option<VerifiedReceipt>> {
    let v = rpc.call("getTransaction", json!({"hash":hex(transaction_hash)}))?;
    let status = verify_settlement(&v, network, transaction_hash)?;
    if !matches!(status, OperationStatus::Confirmed | OperationStatus::Failed) {
        return Ok(None);
    }
    let ledger = v["ledger"]
        .as_u64()
        .and_then(|v| u32::try_from(v).ok())
        .filter(|v| *v > 0)
        .ok_or("Settlement ledger is required")?;
    Ok(Some(VerifiedReceipt {
        transaction_hash: *transaction_hash,
        status,
        ledger,
        envelope_xdr: v["envelopeXdr"]
            .as_str()
            .ok_or("Settlement envelope is required")?
            .into(),
        result_xdr: v["resultXdr"]
            .as_str()
            .ok_or("Settlement result is required")?
            .into(),
    }))
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeAccounting {
    pub nonce: u64,
    #[serde(alias = "revision")]
    pub deployment_version: u64,
    pub spent_daily: i128,
    pub spent_total: i128,
    pub spent_day: u64,
    pub calls: u64,
}
pub(crate) fn map_field<'a>(value: &'a ScVal, name: &str) -> Result<&'a ScVal> {
    let ScVal::Map(Some(map)) = value else {
        return Err("Expected contract record".into());
    };
    map.iter()
        .find(|e| matches!(&e.key,ScVal::Symbol(key) if key.0.as_slice()==name.as_bytes()))
        .map(|e| &e.val)
        .ok_or_else(|| format!("Missing contract field {name}"))
}
/// The transfer receipt that `execute` returns for this exact packet: a deposit reports its
/// underlying debit to the vault, and a redeem its share debit at the vault.
pub fn expected_receipt(p: &PreparedOperation) -> Result<TransferReceipt> {
    let operation = operation_from_request(&p.config, &p.request)?;
    let (to, amount) = operation.debit();
    Ok(TransferReceipt {
        operation_id: p.request.operation.nonce,
        token: operation.debit_token(&p.config.asset).into(),
        from: p.config.wallet.clone(),
        to: to.into(),
        amount,
        nonce: p.state.nonce,
        deployment_version: p.state.deployment_version,
    })
}
/// Check decoded layout 4 State against the installation: tier binding, rules, server and asset.
pub(crate) fn verify_custody(c: &WalletConfig, state: &CustodyState) -> Result<()> {
    if state.source_digest != c.source_digest
        || state.rules != c.rules
        || state.server != c.server
        || state.asset != c.asset
        || state.policy_instance != c.policy_instance
    {
        return Err("Installed policy tier, source, rules, service signer or asset differs".into());
    }
    Ok(())
}
pub(crate) fn number(value: &ScVal) -> Result<u64> {
    match value {
        ScVal::U32(v) => Ok((*v).into()),
        ScVal::U64(v) => Ok(*v),
        _ => Err("Expected contract unsigned integer".into()),
    }
}
pub(crate) fn wide(value: &ScVal) -> Result<i128> {
    match value {
        ScVal::I128(v) => Ok((i128::from(v.hi) << 64) | i128::from(v.lo)),
        _ => Err("Expected native i128 amount".into()),
    }
}
pub(crate) fn digest_field(value: &ScVal) -> Result<[u8; 32]> {
    match value {
        ScVal::Bytes(v) => {
            v.0.as_slice()
                .try_into()
                .map_err(|_| "Expected bytes32".into())
        }
        _ => Err("Expected bytes32".into()),
    }
}
pub(crate) fn addr(value: &ScVal) -> Result<String> {
    match value {
        ScVal::Address(a) => address_text(a),
        _ => Err("Expected native contract address".into()),
    }
}
pub(crate) fn readonly_call(
    rpc: &dyn Rpc,
    c: &WalletConfig,
    source: &AccountState,
    function: &str,
) -> Result<ScVal> {
    let value = readonly_simulation(rpc, c, source, &c.wallet, function, vec![])?;
    readonly_result(&value)
}
pub(crate) fn readonly_simulation(
    rpc: &dyn Rpc,
    c: &WalletConfig,
    source: &AccountState,
    contract: &str,
    function: &str,
    args: Vec<ScVal>,
) -> Result<Value> {
    validate_config(c)?;
    source.validate_structure()?;
    let call = InvokeContractArgs {
        contract_address: address(contract)?,
        function_name: ScSymbol(function.as_bytes().to_vec().try_into().map_err(err)?),
        args: args.try_into().map_err(err)?,
    };
    let tx = Transaction {
        source_account: muxed(&source.address)?,
        fee: 100,
        seq_num: SequenceNumber(source.sequence.checked_add(1).ok_or("Sequence overflow")?),
        cond: Preconditions::None,
        memo: Memo::None,
        operations: vec![Operation {
            source_account: None,
            body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                host_function: HostFunction::InvokeContract(call),
                auth: VecM::default(),
            }),
        }]
        .try_into()
        .map_err(err)?,
        ext: TransactionExt::V0,
    };
    let value=rpc.call("simulateTransaction",json!({"transaction":xdr(&TransactionEnvelope::Tx(TransactionV1Envelope{tx,signatures:VecM::default()}))?}))?;
    Ok(value)
}
pub(crate) fn readonly_result(value: &Value) -> Result<ScVal> {
    if value.get("error").is_some_and(|value| !value.is_null()) {
        return Err("Contract binding simulation failed".into());
    }
    let results = value["results"]
        .as_array()
        .ok_or("Missing binding result")?;
    if results.len() != 1 {
        return Err("Unexpected binding result count".into());
    }
    read(results[0]["xdr"].as_str().ok_or("Missing binding XDR")?)
}
/// Read an explicitly selected shared checker's executable release metadata without authorizing a call.
/// `None` requires a host diagnostic that the selected engine has no `engine_version` export.
/// Transport failures, unavailable diagnostics and malformed metadata are errors. This query
/// does not attest engine health or code identity and is never required by owner operations.
/// `rpc` must serve the configured network; `checker` selects a contract distinct from the service signer.
/// `source` supplies the native simulation account; this function does not load keys or sign.
pub fn checker_version(
    rpc: &dyn Rpc,
    c: &WalletConfig,
    source: &AccountState,
    checker: &str,
) -> Result<Option<u32>> {
    validate_config(c)?;
    Contract::from_string(checker).map_err(err)?;
    if rpc.call("getNetwork", json!({}))?["passphrase"] != passphrase(&c.network)? {
        return Err("Stellar RPC network differs from installation".into());
    }
    let value = readonly_simulation(rpc, c, source, checker, "engine_version", vec![])?;
    if let Some(error) = value.get("error") {
        if !error
            .as_str()
            .is_some_and(|v| v.contains("Error(WasmVm, MissingValue)"))
        {
            return Err("Engine version simulation failed".into());
        }
        let ScAddress::Contract(engine) = address(checker)? else {
            return Err("Engine is not a contract".into());
        };
        let events = value["events"]
            .as_array()
            .ok_or("Missing engine version diagnostics")?;
        let mut absent = false;
        for encoded in events {
            let event: DiagnosticEvent =
                read(encoded.as_str().ok_or("Invalid engine diagnostic XDR")?)?;
            let ContractEventBody::V0(body) = &event.event.body;
            if !event.in_successful_contract_call
                && event.event.type_ == ContractEventType::Diagnostic
                && event.event.contract_id.as_ref() == Some(&engine)
                && body.topics.as_slice()
                    == [
                        value_symbol("error")?,
                        ScVal::Error(ScError::WasmVm(ScErrorCode::MissingValue)),
                    ]
                && matches!(&body.data, ScVal::Vec(Some(args)) if args.len() == 2
                    && matches!(&args[0], ScVal::String(message) if message.0.as_slice() == b"trying to invoke non-existent contract function")
                    && args[1] == value_symbol("engine_version")?)
            {
                absent = true;
            }
        }
        return if absent {
            Ok(None)
        } else {
            Err("Engine metadata failure is not an absent version export".into())
        };
    }
    match readonly_result(&value)? {
        ScVal::U32(version) if version > 0 => Ok(Some(version)),
        _ => Err("Invalid engine release version".into()),
    }
}
/// Fetch native authority and policy wallet state from the configured chain. Native usage must
/// come from the authoritative durable coordinator, never an implicit zero counter.
pub fn trusted_state(
    rpc: &dyn Rpc,
    c: &WalletConfig,
    accounting: Option<NativeAccounting>,
) -> Result<TrustedState> {
    Ok(trusted_state_inner(rpc, c, accounting, true)?.state)
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiscoveredState {
    pub state: TrustedState,
    pub paused: bool,
}
/// Read public live authority without requiring a previously configured customer key.
/// Discovery reports authority; it does not authorize an execution.
pub fn trusted_state_for_discovery(
    rpc: &dyn Rpc,
    c: &WalletConfig,
    accounting: Option<NativeAccounting>,
) -> Result<DiscoveredState> {
    trusted_state_inner(rpc, c, accounting, false)
}
fn trusted_state_inner(
    rpc: &dyn Rpc,
    c: &WalletConfig,
    accounting: Option<NativeAccounting>,
    require_customer_quorum: bool,
) -> Result<DiscoveredState> {
    validate_config(c)?;
    if c.route == WalletRoute::Odc && require_customer_quorum {
        return Err("Historical wallet discovery cannot authorize new execution".into());
    }
    let network = rpc.call("getNetwork", json!({}))?;
    if network["passphrase"].as_str() != Some(passphrase(&c.network)?) {
        return Err("Stellar RPC network differs from installation".into());
    }
    let latest = rpc.call("getLatestLedger", json!({}))?;
    let ledger = u32::try_from(
        latest["sequence"]
            .as_u64()
            .ok_or("Missing ledger sequence")?,
    )
    .map_err(err)?;
    if c.route == WalletRoute::Native {
        let source = get_account(rpc, &c.wallet)?;
        source.validate_structure()?;
        if require_customer_quorum {
            source.validate_wallet(c)?;
        }
        let a = accounting.ok_or("Native wallet requires authoritative policy accounting")?;
        return Ok(DiscoveredState {
            state: TrustedState {
                contract_version: None,
                policy_state: None,
                source,
                nonce: a.nonce,
                deployment_version: a.deployment_version,
                spent_daily: a.spent_daily,
                spent_total: a.spent_total,
                spent_day: a.spent_day,
                calls: a.calls,
                ledger,
                module_digest: c.module_digest,
                source_hash: c.source_hash,
                owner: c.owner.clone(),
                agent: c.agent.clone(),
                server: c.server.clone(),
                policy_instance: c.policy_instance,
            },
            paused: false,
        });
    }
    let key = LedgerKey::ContractData(LedgerKeyContractData {
        contract: address(&c.wallet)?,
        key: ScVal::LedgerKeyContractInstance,
        durability: ContractDataDurability::Persistent,
    });
    let entries = rpc.call("getLedgerEntries", json!({"keys":[xdr(&key)?]}))?;
    let list = entries["entries"]
        .as_array()
        .ok_or("Missing policy wallet ledger entry")?;
    if list.len() != 1 {
        return Err("policy wallet instance not found".into());
    }
    let entry: LedgerEntryData = read(list[0]["xdr"].as_str().ok_or("Missing instance XDR")?)?;
    let LedgerEntryData::ContractData(data) = entry else {
        return Err("Unexpected policy wallet ledger entry".into());
    };
    if data.contract != address(&c.wallet)?
        || data.key != ScVal::LedgerKeyContractInstance
        || data.durability != ContractDataDurability::Persistent
    {
        return Err("policy wallet instance ledger key differs".into());
    }
    let ScVal::ContractInstance(instance) = data.val else {
        return Err("Missing policy wallet instance state".into());
    };
    let ContractExecutable::Wasm(module) = instance.executable else {
        return Err("policy wallet must use an owner-selected Wasm executable".into());
    };
    if module.0 != c.module_digest {
        return Err("policy wallet executable differs from installed code".into());
    }
    let storage = instance.storage.ok_or("Missing policy wallet storage")?;
    let state = storage
        .iter()
        .find(|e| e.key == ScVal::U32(0))
        .map(|e| &e.val)
        .ok_or("Missing policy wallet custody state")?;
    if c.route == WalletRoute::PolicyWallet {
        return current_wallet_state(rpc, c, state, module.0, ledger, require_customer_quorum);
    }
    historical_wallet_state(rpc, c, state, module.0, ledger, require_customer_quorum)
}
/// Layout 4 discovery: decode State exactly, verify the tier binding and read params and
/// policy state from the instance entry.
fn current_wallet_state(
    rpc: &dyn Rpc,
    c: &WalletConfig,
    raw: &ScVal,
    module: [u8; 32],
    ledger: u32,
    require_customer_quorum: bool,
) -> Result<DiscoveredState> {
    let state = CustodyState::from_scval(raw)?;
    if require_customer_quorum && state.paused {
        return Err("policy wallet automation is paused".into());
    }
    verify_custody(c, &state)?;
    let source = get_account(rpc, &state.agent)?;
    source.validate_structure()?;
    if require_customer_quorum && source.signer_weight(&c.agent)? == 0 {
        return Err("Customer is not a current policy wallet agent account signer".into());
    }
    PolicyBinding::from_scval(&readonly_call(rpc, c, &source, "policy_binding")?)?
        .verify(c, OperationKind::Transfer)?;
    if require_customer_quorum {
        let server = get_account(rpc, &c.server)?;
        server.validate_signer_quorum(&[&c.server], server.medium_threshold)?;
    }
    let standard = |key: &str| match state.policy_state.get(key) {
        Some(PolicyValue::Int(v)) => Ok(*v),
        None => Ok(0),
        _ => Err(format!("Invalid standard policy state {key}")),
    };
    let counter = |key: &str| -> Result<u64> { u64::try_from(standard(key)?).map_err(err) };
    Ok(DiscoveredState {
        state: TrustedState {
            contract_version: Some(state.contract_version),
            policy_state: Some(PolicyStateSnapshot {
                params: state.params.clone(),
                state: state.policy_state.clone(),
                rules: state.rules.clone(),
                source_digest: state.source_digest,
                x402_enabled: state.x402_enabled,
            }),
            source,
            nonce: state.nonce,
            deployment_version: state.deployment_version,
            spent_daily: standard("day_spent")?,
            spent_total: standard("spent")?,
            spent_day: counter("day")?,
            calls: counter("calls")?,
            ledger,
            module_digest: module,
            source_hash: c.source_hash,
            owner: state.owner,
            agent: state.agent,
            server: state.server,
            policy_instance: c.policy_instance,
        },
        paused: state.paused,
    })
}
/// Read-only discovery of a historical ODC wallet, for status and recovery of retained bytes.
fn historical_wallet_state(
    rpc: &dyn Rpc,
    c: &WalletConfig,
    state: &ScVal,
    module: [u8; 32],
    ledger: u32,
    require_customer_quorum: bool,
) -> Result<DiscoveredState> {
    if map_field(state, "version")? != &ScVal::U32(1) {
        return Err("Unsupported historical wallet state".into());
    }
    let paused = match map_field(state, "paused")? {
        ScVal::Bool(value) => *value,
        _ => return Err("Invalid policy wallet pause state".into()),
    };
    if require_customer_quorum && paused {
        return Err("policy wallet automation is paused".into());
    }
    let current_agent = addr(map_field(state, "agent")?)?;
    let source = get_account(rpc, &current_agent)?;
    source.validate_structure()?;
    if require_customer_quorum && source.signer_weight(&c.agent)? == 0 {
        return Err("Customer is not a current policy wallet agent account signer".into());
    }
    let binding = readonly_call(rpc, c, &source, "policy_binding")?;
    if digest_field(map_field(&binding, "policy_instance")?)? != c.policy_instance
        || digest_field(map_field(&binding, "module_digest")?)? != c.module_digest
        || digest_field(map_field(&binding, "source_digest")?)? != c.source_hash
        || digest_field(map_field(&binding, "argument_schema_digest")?)?
            != hash(ODC_TRANSFER_SCHEMA)
        || map_field(&binding, "entrypoint")? != &value_symbol("_execute")?
    {
        return Err("Compiled policy binding differs from installation".into());
    }
    if addr(map_field(map_field(state, "grant")?, "asset")?)? != c.asset {
        return Err("policy wallet asset differs from installation".into());
    }
    let out = TrustedState {
        contract_version: None,
        policy_state: None,
        source,
        nonce: number(map_field(state, "nonce")?)?,
        deployment_version: number(map_field(state, "revision")?)?,
        spent_daily: wide(map_field(state, "spent_daily")?)?,
        spent_total: wide(map_field(state, "spent_total")?)?,
        spent_day: number(map_field(state, "spent_day")?)?,
        calls: number(map_field(state, "calls")?)?,
        ledger,
        module_digest: module,
        source_hash: c.source_hash,
        owner: addr(map_field(state, "owner")?)?,
        agent: addr(map_field(state, "agent")?)?,
        server: addr(map_field(state, "engine")?)?,
        policy_instance: c.policy_instance,
    };
    Ok(DiscoveredState { state: out, paused })
}

/// Settled effects of one operation, read from the wallet's persistent receipts.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutionReceipt {
    /// The replay marker's transfer receipt: for a deposit, the underlying debit to the vault;
    /// for a redeem, the share debit at the vault.
    pub transfer: TransferReceipt,
    /// The settled share credit of a deposit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deposit: Option<DepositReceipt>,
    /// The settled asset credit of a redeem.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redeem: Option<RedeemReceipt>,
}
fn persistent_entry(rpc: &dyn Rpc, key: &LedgerKey) -> Result<Option<ScVal>> {
    let encoded = xdr(key)?;
    let response = rpc.call("getLedgerEntries", json!({"keys":[encoded]}))?;
    let entries = response["entries"]
        .as_array()
        .ok_or("Missing ledger entries")?;
    let entry = match entries.as_slice() {
        [] => return Ok(None),
        [entry] => entry,
        _ => return Err("Unexpected ledger entry count".into()),
    };
    if entry["key"].as_str().is_some_and(|k| k != encoded) {
        return Err("Ledger entry key differs".into());
    }
    let LedgerEntryData::ContractData(data) =
        read(entry["xdr"].as_str().ok_or("Missing ledger entry XDR")?)?
    else {
        return Err("Unexpected receipt ledger entry".into());
    };
    let LedgerKey::ContractData(expected) = key else {
        unreachable!()
    };
    if data.contract != expected.contract
        || data.key != expected.key
        || data.durability != expected.durability
    {
        return Err("Receipt ledger key differs".into());
    }
    Ok(Some(data.val))
}
/// Read the settled receipts of `operation_id` from the wallet's persistent storage. `None`
/// means no successful execution consumed it yet.
pub fn operation_receipt(
    rpc: &dyn Rpc,
    c: &WalletConfig,
    operation_id: &[u8; 32],
) -> Result<Option<ExecutionReceipt>> {
    validate_config(c)?;
    if c.route != WalletRoute::PolicyWallet {
        return Err("Operation receipts require policy wallet custody".into());
    }
    if rpc.call("getNetwork", json!({}))?["passphrase"] != passphrase(&c.network)? {
        return Err("Stellar RPC network differs from installation".into());
    }
    let Some(transfer) = persistent_entry(rpc, &contract::operation_key(&c.wallet, operation_id)?)?
    else {
        return Ok(None);
    };
    let transfer = TransferReceipt::from_scval(&transfer)?;
    let deposit = persistent_entry(rpc, &contract::deposit_key(&c.wallet, operation_id)?)?
        .map(|value| DepositReceipt::from_scval(&value))
        .transpose()?;
    let redeem = persistent_entry(rpc, &contract::redeem_key(&c.wallet, operation_id)?)?
        .map(|value| RedeemReceipt::from_scval(&value))
        .transpose()?;
    // A redeem debits the vault's shares; every other operation debits the asset.
    let token = redeem.as_ref().map_or(&c.asset, |r| &r.vault);
    if transfer.operation_id != *operation_id
        || transfer.from != c.wallet
        || transfer.token != *token
        || (deposit.is_some() && redeem.is_some())
    {
        return Err("Receipt differs from the requested operation".into());
    }
    if let Some(d) = &deposit
        && (d.operation_id != *operation_id
            || d.vault != transfer.to
            || d.assets != transfer.amount
            || d.nonce != transfer.nonce)
    {
        return Err("Deposit receipt differs from its transfer receipt".into());
    }
    if let Some(r) = &redeem
        && (r.operation_id != *operation_id
            || r.vault != transfer.to
            || r.shares != transfer.amount
            || r.nonce != transfer.nonce)
    {
        return Err("Redeem receipt differs from its transfer receipt".into());
    }
    Ok(Some(ExecutionReceipt {
        transfer,
        deposit,
        redeem,
    }))
}
