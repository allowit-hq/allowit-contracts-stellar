//! Bounded JSON-RPC transport. Submission never retries an uncertain transaction.
use crate::*;
use serde_json::{Value, json};
use std::{
    io::Read,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

fn transaction_hash_for(network: &str, tx: &Transaction) -> Result<[u8; 32]> {
    super::transaction_hash(network, tx)
}
pub trait Rpc: Send + Sync {
    fn call(&self, method: &str, params: Value) -> Result<Value>;
}
pub struct HttpRpc {
    url: String,
    client: reqwest::blocking::Client,
    id: AtomicU64,
}
impl HttpRpc {
    pub fn new(url: &str) -> Result<Self> {
        let parsed = reqwest::Url::parse(url).map_err(err)?;
        if !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.fragment().is_some()
            || !(parsed.scheme() == "https"
                || (parsed.scheme() == "http"
                    && matches!(parsed.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))))
        {
            return Err("RPC requires HTTPS or local HTTP without credentials".into());
        }
        Ok(Self {
            url: url.into(),
            client: reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(30))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .map_err(err)?,
            id: AtomicU64::new(1),
        })
    }
}
impl Rpc for HttpRpc {
    fn call(&self, method: &str, params: Value) -> Result<Value> {
        let id = self.id.fetch_add(1, Ordering::Relaxed);
        let response = self
            .client
            .post(&self.url)
            .json(&json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}))
            .send()
            .map_err(|_| "Stellar RPC transport result is unknown")?;
        if !response.status().is_success() {
            return Err("Stellar RPC rejected the HTTP request".into());
        }
        let mut bytes = Vec::new();
        response
            .take((MAX_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(err)?;
        if bytes.len() > MAX_BYTES {
            return Err("RPC response exceeds limit".into());
        }
        let value: Value = serde_json::from_slice(&bytes).map_err(err)?;
        if value["id"] != id || value["jsonrpc"] != "2.0" || value.get("error").is_some() {
            return Err("Invalid or failed Stellar RPC response".into());
        }
        value
            .get("result")
            .cloned()
            .ok_or("Missing RPC result".into())
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
    let state = trusted_state(rpc, c, accounting)?;
    if c.route == WalletRoute::Native {
        return super::prepare(c, request, &state, now, expires_at);
    }
    let intent = prepare_for_native_preflight(c, request, &state, now, expires_at)?;
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
    let transfer = transfer_from_request(&p.config, &p.request)?;
    let expected = value_map(vec![
        ("operation_id", value_bytes(&p.request.operation.nonce)?),
        ("token", ScVal::Address(address(&p.config.asset)?)),
        ("from", ScVal::Address(address(&p.config.wallet)?)),
        ("to", ScVal::Address(address(&transfer.recipient)?)),
        ("amount", i128_value(transfer.amount)),
        ("nonce", ScVal::U64(p.state.nonce)),
        ("deployment_version", ScVal::U64(p.state.deployment_version)),
    ])?;
    if result != expected {
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
    let mut prepared = attach_simulation(p, encoded)?;
    record_native_preflight(&mut prepared)?;
    Ok(prepared)
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
        || p.state.contract_version != Some(1)
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
    let simulated = simulate(rpc, p)?;
    let required: SorobanTransactionData = read(
        simulated
            .simulation_data
            .as_deref()
            .ok_or("Native simulation omitted resource requirements")?,
    )?;
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
pub trait OperationStore {
    fn record(
        &mut self,
        operation_id: [u8; 32],
        signed: &SignedOperation,
        status: OperationStatus,
    ) -> Result<()>;
    fn load(&self, operation_id: [u8; 32]) -> Result<Option<(SignedOperation, OperationStatus)>>;
}
/// Persist exact signed bytes before broadcast. An uncertain response retains them for lookup.
/// A later call for the same operation looks up the original hash first. While that
/// transaction is not on the ledger and the signed operation is still valid, the call resends
/// the retained bytes. They keep their sequence number and hash, so the network includes them
/// at most once. It never re-signs or replaces the transaction.
pub fn submit(
    rpc: &dyn Rpc,
    store: &mut dyn OperationStore,
    signed: &SignedOperation,
    now: u64,
) -> Result<OperationStatus> {
    let id = signed.prepared.request.operation.nonce;
    if let Some((previous, status)) = store.load(id)? {
        if previous != *signed {
            return Err("Operation ID already binds different signed bytes".into());
        }
        validate_retained_signed(&previous)?;
        if matches!(status, OperationStatus::Confirmed | OperationStatus::Failed) {
            return Ok(status);
        }
        if status != OperationStatus::Prepared {
            let observed = status_by_hash(
                rpc,
                &signed.prepared.config.network,
                &signed.transaction_hash,
            )?;
            // NOT_FOUND after TRY_AGAIN_LATER, a lost response or a dropped pending transaction:
            // resend the same bytes only while they are still valid.
            if observed != OperationStatus::SubmissionUnknown
                || validate_signed(signed, now).is_err()
            {
                store.record(id, signed, observed.clone())?;
                return Ok(observed);
            }
        }
    }
    validate_signed(signed, now)?;
    store.record(id, signed, OperationStatus::SubmissionUnknown)?;
    match rpc.call(
        "sendTransaction",
        json!({"transaction":signed.transaction_xdr}),
    ) {
        Ok(v) => {
            if v["hash"].as_str() != Some(hex(&signed.transaction_hash).as_str()) {
                return Ok(OperationStatus::SubmissionUnknown);
            }
            let status = match v["status"].as_str() {
                Some("PENDING" | "DUPLICATE") => OperationStatus::Submitted,
                Some("ERROR") => status_by_hash(
                    rpc,
                    &signed.prepared.config.network,
                    &signed.transaction_hash,
                )
                .unwrap_or(OperationStatus::SubmissionUnknown),
                // The network did not accept the transaction. A later submit resends it.
                Some("TRY_AGAIN_LATER") => OperationStatus::SubmissionUnknown,
                _ => OperationStatus::SubmissionUnknown,
            };
            store.record(id, signed, status.clone())?;
            Ok(status)
        }
        Err(_) => Ok(OperationStatus::SubmissionUnknown),
    }
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
pub fn recover(
    rpc: &dyn Rpc,
    store: &mut dyn OperationStore,
    operation_id: [u8; 32],
) -> Result<OperationStatus> {
    let (signed, previous) = store.load(operation_id)?.ok_or("No retained operation")?;
    if signed.prepared.request.operation.nonce != operation_id {
        return Err("Retained operation identity differs".into());
    }
    validate_retained_signed(&signed)?;
    if matches!(
        previous,
        OperationStatus::Confirmed | OperationStatus::Failed
    ) {
        return Ok(previous);
    }
    let status = status_by_hash(
        rpc,
        &signed.prepared.config.network,
        &signed.transaction_hash,
    )?;
    store.record(operation_id, &signed, status.clone())?;
    Ok(status)
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
pub(crate) fn current_contract_version(value: &ScVal) -> Result<u32> {
    match map_field(value, "contract_version")? {
        ScVal::U32(1) => Ok(1),
        _ => Err("Unsupported policy contract version".into()),
    }
}

pub(crate) fn verify_policy_engine(c: &WalletConfig, state: &ScVal, binding: &ScVal) -> Result<()> {
    let kind = c
        .policy_engine
        .ok_or("Selected policy engine is required")?;
    if map_field(binding, "engine_kind")? != &value_symbol(kind.symbol())?
        || digest_field(map_field(state, "source_digest")?)? != c.source_hash
        || addr(map_field(state, "server")?)? != c.server
    {
        return Err("Installed policy engine, source or service signer differs".into());
    }
    let selected = allowit_policy_sdk::select_stellar_engine(
        &c.policy_source,
        allowit_policy_sdk::StellarRail::PolicyWallet,
        kind,
        false,
    )
    .map_err(err)?;
    let rules = ScVal::Vec(Some(
        selected
            .rules
            .iter()
            .map(|name| value_symbol(name))
            .collect::<Result<Vec<_>>>()?
            .try_into()
            .map_err(err)?,
    ));
    if map_field(state, "rules")? != &rules {
        return Err("Installed rules differ from complete compiled policy".into());
    }
    Ok(())
}
pub(crate) fn deployment_version_field(state: &ScVal) -> Result<u64> {
    if ["revision", "policy_version"]
        .iter()
        .any(|key| map_field(state, key).is_ok())
    {
        return Err("Unexpected legacy deployment field in current state".into());
    }
    number(map_field(state, "deployment_version")?)
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
    let historical = c.route == WalletRoute::Odc;
    let contract_version = if historical {
        if map_field(state, "version")? != &ScVal::U32(1) {
            return Err("Unsupported historical wallet state".into());
        }
        1
    } else {
        current_contract_version(state)?
    };
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
    if !historical {
        verify_policy_engine(c, state, &binding)?;
    }
    if !historical && require_customer_quorum {
        let server = get_account(rpc, &c.server)?;
        server.validate_signer_quorum(&[&c.server], server.medium_threshold)?;
    }
    if digest_field(map_field(&binding, "policy_instance")?)? != c.policy_instance
        || digest_field(map_field(&binding, "module_digest")?)? != c.module_digest
        || digest_field(map_field(&binding, "source_digest")?)? != c.source_hash
        || digest_field(map_field(&binding, "argument_schema_digest")?)? != hash(ARGUMENT_SCHEMA)
        || map_field(&binding, "entrypoint")? != &value_symbol("_execute")?
    {
        return Err("Compiled policy binding differs from installation".into());
    }
    if !historical && current_contract_version(&binding)? != contract_version {
        return Err("Policy contract release differs from stored state".into());
    }
    let asset = if historical {
        map_field(map_field(state, "grant")?, "asset")?
    } else {
        map_field(state, "asset")?
    };
    if addr(asset)? != c.asset {
        return Err("policy wallet asset differs from installation".into());
    }
    let policy_state = if historical {
        None
    } else {
        Some(PolicyStateSnapshot {
            grant: NativeValues::from_value(map_field(state, "grant")?)?,
            spent: properties::read_spent(rpc, c, &source)?,
        })
    };
    let out = TrustedState {
        contract_version: (!historical).then_some(contract_version),
        policy_state,
        source,
        nonce: number(map_field(state, "nonce")?)?,
        deployment_version: if historical {
            number(map_field(state, "revision")?)?
        } else {
            deployment_version_field(state)?
        },
        spent_daily: if historical {
            wide(map_field(state, "spent_daily")?)?
        } else {
            0
        },
        spent_total: if historical {
            wide(map_field(state, "spent_total")?)?
        } else {
            0
        },
        spent_day: if historical {
            number(map_field(state, "spent_day")?)?
        } else {
            0
        },
        calls: if historical {
            number(map_field(state, "calls")?)?
        } else {
            0
        },
        ledger,
        module_digest: module.0,
        source_hash: c.source_hash,
        owner: addr(map_field(state, "owner")?)?,
        agent: addr(map_field(state, "agent")?)?,
        server: addr(map_field(
            state,
            if historical { "engine" } else { "server" },
        )?)?,
        policy_instance: c.policy_instance,
    };
    Ok(DiscoveredState { state: out, paused })
}

#[cfg(test)]
mod version_tests {
    use super::*;
    #[test]
    fn current_contract_metadata_and_counter_are_exact() {
        for value in [
            ScVal::U32(0),
            ScVal::U32(2),
            ScVal::U64(1),
            ScVal::Bool(true),
        ] {
            assert!(
                current_contract_version(&value_map(vec![("contract_version", value)]).unwrap())
                    .is_err()
            );
        }
        assert_eq!(
            current_contract_version(
                &value_map(vec![("contract_version", ScVal::U32(1))]).unwrap()
            )
            .unwrap(),
            1
        );
        for old in ["revision", "policy_version"] {
            assert!(
                deployment_version_field(
                    &value_map(vec![
                        ("deployment_version", ScVal::U64(3)),
                        (old, ScVal::U64(3))
                    ])
                    .unwrap()
                )
                .is_err()
            );
        }
    }
}
