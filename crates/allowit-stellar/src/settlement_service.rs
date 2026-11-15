//! The settlement service of the x402 `exact` scheme on Stellar: what a facilitator checks and
//! submits.
//!
//! A seller forwards the payer's payment payload and its own payment requirements. The payload
//! holds a transaction with one invocation, `transfer(from, payTo, amount)` on the token
//! contract, and the payer's signed authorization entry for exactly that call. The service
//! checks it against the requirements and the ledger, then puts the invocation into its own
//! transaction, pays the network fee and submits it.
//!
//! The service can do one thing with a payload: submit that one transfer, once, before the
//! entry expires. The entry names the token, the payer, the payee and the amount, and the
//! ledger consumes its nonce, so the service cannot redirect it, change it or settle it
//! twice. The checks here protect the service itself: its key is never the payer or a party
//! of the invocation, the simulation shows the one expected transfer and no other event, and
//! the network fee stays under the host's ceiling.
//!
//! Every field of a request is the caller's claim. A refusal names its reason in the reply
//! and submits nothing.
use crate::host::{
    error::{Error, Result as HostResult},
    runtime::Signer,
    settlement_service::{
        Authorization, Limits, Outcome, Settled, SettlementProvider, Supported, Verified,
    },
};
use crate::*;
use serde_json::{Value, json};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// The payment scheme that this service settles.
pub const SCHEME: &str = "exact";
/// The protocol version of the scheme on this rail.
pub const VERSION: u64 = 2;
/// The inclusion fee that a settlement bids on top of the resource fee, in stroops.
pub const INCLUSION_FEE: u32 = 100;
/// The ledger time that bounds an entry's expiry: the scheme's fallback estimate.
const LEDGER_SECONDS: u64 = 5;
/// The ledgers that an entry's expiry may exceed the seller's timeout by.
const EXPIRY_TOLERANCE: u64 = 2;
/// The seller's timeout when its requirements state none.
const DEFAULT_TIMEOUT: u64 = 60;
/// The longest timeout that a seller may state.
const MAX_TIMEOUT: u64 = 86_400;
/// The longest transaction text that is decoded.
const MAX_TRANSACTION_BYTES: usize = 16_384;

pub struct Service;
pub static SERVICE: Service = Service;

/// A refusal of the payload: the reason code of the reply and the payer when it is known.
struct Refusal(&'static str, Option<String>);
type Checked<T> = std::result::Result<T, Refusal>;

fn refuse<T>(reason: &'static str) -> Checked<T> {
    Err(Refusal(reason, None))
}

/// A payload that passed every check.
struct Admitted {
    authorization: Authorization,
    /// The invocation with the payer's entry, as the payload holds it.
    operation: InvokeHostFunctionOp,
    /// The resources of the invocation from the simulation.
    resources: SorobanTransactionData,
    /// The network fee of a settlement: the resource fee and the inclusion fee.
    fee: u32,
    /// The seller's timeout in seconds.
    timeout: u64,
}

fn rail(error: String) -> Error {
    crate::provider::failure(error)
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}
fn muxed_account(account: &MuxedAccount) -> String {
    match account {
        MuxedAccount::Ed25519(key) => account_for_public_key(&key.0),
        MuxedAccount::MuxedEd25519(muxed) => account_for_public_key(&muxed.ed25519.0),
    }
}

/// Check the structure of the payload against the requirements. This reads no ledger.
fn structure(
    network: &str,
    signer: &str,
    request: &Value,
) -> Checked<(InvokeHostFunctionOp, Authorization, u64, String)> {
    let payload = &request["paymentPayload"];
    let requirements = &request["paymentRequirements"];
    if payload["x402Version"].as_u64() != Some(VERSION) {
        return refuse("invalid_x402_version");
    }
    if payload["accepted"]["scheme"] != SCHEME || requirements["scheme"] != SCHEME {
        return refuse("unsupported_scheme");
    }
    let named = requirements["network"].as_str().unwrap_or_default();
    if payload["accepted"]["network"].as_str() != Some(named) {
        return refuse("network_mismatch");
    }
    if crate::host::routing::normalize(named).ok() != Some(network) {
        return refuse("invalid_network");
    }
    let malformed = || Refusal("invalid_exact_stellar_payload_malformed", None);
    let text = payload["payload"]["transaction"]
        .as_str()
        .filter(|text| text.len() <= MAX_TRANSACTION_BYTES)
        .ok_or_else(malformed)?;
    let TransactionEnvelope::Tx(envelope) = read(text).map_err(|_| malformed())? else {
        return Err(malformed());
    };
    let [operation] = envelope.tx.operations.as_slice() else {
        return refuse("invalid_exact_stellar_payload_wrong_operation");
    };
    let OperationBody::InvokeHostFunction(op) = &operation.body else {
        return refuse("invalid_exact_stellar_payload_wrong_operation");
    };
    // The service's own account is never the source of what the payer built.
    if muxed_account(&envelope.tx.source_account) == signer
        || operation
            .source_account
            .as_ref()
            .is_some_and(|source| muxed_account(source) == signer)
    {
        return refuse("invalid_exact_stellar_payload_unsafe_tx_or_op_source");
    }
    let HostFunction::InvokeContract(call) = &op.host_function else {
        return refuse("invalid_exact_stellar_payload_wrong_operation");
    };
    let asset = requirements["asset"].as_str().unwrap_or_default();
    if address_text(&call.contract_address).ok().as_deref() != Some(asset) || asset.is_empty() {
        return refuse("invalid_exact_stellar_payload_wrong_asset");
    }
    let [
        ScVal::Address(from),
        ScVal::Address(to),
        ScVal::I128(amount),
    ] = call.args.as_slice()
    else {
        return refuse("invalid_exact_stellar_payload_wrong_function_name");
    };
    if call.function_name.0.as_slice() != b"transfer" {
        return refuse("invalid_exact_stellar_payload_wrong_function_name");
    }
    let payer = address_text(from).map_err(|_| malformed())?;
    let refused = |reason| Refusal(reason, Some(payer.clone()));
    if payer == signer {
        return Err(refused(
            "invalid_exact_stellar_payload_facilitator_is_payer",
        ));
    }
    let pay_to = requirements["payTo"].as_str().unwrap_or_default();
    if address_text(to).ok().as_deref() != Some(pay_to) || pay_to.is_empty() {
        return Err(refused("invalid_exact_stellar_payload_wrong_recipient"));
    }
    let units = (i128::from(amount.hi) << 64) | i128::from(amount.lo);
    let required = requirements["amount"]
        .as_str()
        .filter(|text| !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|text| text.parse::<i128>().ok())
        .filter(|units| *units > 0);
    if required != Some(units) {
        return Err(refused("invalid_exact_stellar_payload_wrong_amount"));
    }
    // One entry: the payer's, for exactly this call, with a signature and no further calls.
    let [entry] = op.auth.as_slice() else {
        return Err(refused(if op.auth.is_empty() {
            "invalid_exact_stellar_payload_no_auth_entries"
        } else {
            "invalid_exact_stellar_payload_unexpected_auth_entry"
        }));
    };
    let (SorobanCredentials::Address(credentials) | SorobanCredentials::AddressV2(credentials)) =
        &entry.credentials
    else {
        return Err(refused(
            "invalid_exact_stellar_payload_unsupported_credential_type",
        ));
    };
    let authorizer = address_text(&credentials.address).map_err(|_| malformed())?;
    if authorizer == signer {
        return Err(refused("invalid_exact_stellar_payload_facilitator_in_auth"));
    }
    if authorizer != payer || credentials.signature == ScVal::Void {
        return Err(refused(
            "invalid_exact_stellar_payload_missing_payer_signature",
        ));
    }
    if !entry.root_invocation.sub_invocations.is_empty()
        || entry.root_invocation.function != SorobanAuthorizedFunction::ContractFn(call.clone())
    {
        return Err(refused("invalid_exact_stellar_payload_has_subinvocations"));
    }
    let timeout = match &requirements["maxTimeoutSeconds"] {
        Value::Null => DEFAULT_TIMEOUT,
        value => match value.as_u64().filter(|s| (1..=MAX_TIMEOUT).contains(s)) {
            Some(seconds) => seconds,
            None => return Err(refused("invalid_payment_requirements")),
        },
    };
    let authorization = Authorization {
        id: hash(xdr(entry).map_err(|_| malformed())?),
        payer: payer.clone(),
        pay_to: pay_to.to_owned(),
        asset: asset.to_owned(),
        units,
        expires_height: u64::from(credentials.signature_expiration_ledger),
    };
    Ok((op.clone(), authorization, timeout, text.to_owned()))
}

/// Check the events of the simulation: one transfer of the asset from the payer to the payee
/// of the amount, and no other contract event.
fn events(simulated: &Value, a: &Authorization) -> Checked<()> {
    let refused = |reason| Refusal(reason, Some(a.payer.clone()));
    let mut transfers = 0;
    for event in simulated["events"].as_array().into_iter().flatten() {
        let event: DiagnosticEvent = event
            .as_str()
            .and_then(|text| read(text).ok())
            .ok_or_else(|| refused("unexpected_verify_error"))?;
        if event.event.type_ != ContractEventType::Contract {
            continue;
        }
        let ContractEventBody::V0(body) = &event.event.body;
        let contract = event
            .event
            .contract_id
            .as_ref()
            .and_then(|id| address_text(&ScAddress::Contract(id.clone())).ok());
        if contract.as_deref() != Some(a.asset.as_str()) {
            return Err(refused("invalid_exact_stellar_payload_event_wrong_asset"));
        }
        let [
            ScVal::Symbol(name),
            ScVal::Address(from),
            ScVal::Address(to),
            ..,
        ] = body.topics.as_slice()
        else {
            return Err(refused("invalid_exact_stellar_payload_event_not_transfer"));
        };
        if name.0.as_slice() != b"transfer" {
            return Err(refused("invalid_exact_stellar_payload_event_not_transfer"));
        }
        if address_text(from).ok().as_deref() != Some(a.payer.as_str()) {
            return Err(refused("invalid_exact_stellar_payload_event_wrong_from"));
        }
        if address_text(to).ok().as_deref() != Some(a.pay_to.as_str()) {
            return Err(refused("invalid_exact_stellar_payload_event_wrong_to"));
        }
        if body.data != i128_value(a.units) {
            return Err(refused("invalid_exact_stellar_payload_event_wrong_amount"));
        }
        transfers += 1;
    }
    match transfers {
        1 => Ok(()),
        0 => Err(refused("invalid_exact_stellar_payload_no_transfer_events")),
        _ => Err(refused("invalid_exact_stellar_payload_multiple_transfers")),
    }
}

/// Check the payload of `request` against its requirements and the ledger. The outer error is
/// a fault of this service or its ledger read; the inner one refuses the payload.
fn admit(
    rpc: &dyn rpc::Rpc,
    network: &str,
    signer: &str,
    request: &Value,
    limits: &Limits,
) -> HostResult<Checked<Admitted>> {
    account_key(signer).map_err(rail)?;
    let (operation, authorization, timeout, transaction) = match structure(network, signer, request)
    {
        Ok(checked) => checked,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let refused = |reason| Ok(Err(Refusal(reason, Some(authorization.payer.clone()))));
    if rpc.call("getNetwork", json!({})).map_err(rail)?["passphrase"]
        != passphrase(network).map_err(rail)?
    {
        return Err(Error::config("The ledger endpoint serves another network"));
    }
    let latest = rpc.call("getLatestLedger", json!({})).map_err(rail)?["sequence"]
        .as_u64()
        .ok_or_else(|| Error::uncertain("The ledger endpoint reports no ledger"))?;
    // The seller's timeout bounds the life of the entry.
    if authorization.expires_height > latest + timeout.div_ceil(LEDGER_SECONDS) + EXPIRY_TOLERANCE {
        return refused("invalid_exact_stellar_signature_expiration_too_far");
    }
    let simulated = rpc
        .call(
            "simulateTransaction",
            json!({"transaction": transaction, "authMode": "enforce"}),
        )
        .map_err(rail)?;
    if simulated.get("error").is_some_and(|value| !value.is_null())
        || rpc::reject_restoration(&simulated).is_err()
    {
        return refused("invalid_exact_stellar_payload_simulation_failed");
    }
    let resources: Option<SorobanTransactionData> = simulated["transactionData"]
        .as_str()
        .and_then(|text| read(text).ok());
    let minimum = simulated["minResourceFee"]
        .as_str()
        .and_then(|text| text.parse::<u64>().ok());
    let (Some(resources), Some(minimum)) = (resources, minimum) else {
        return Err(Error::uncertain(
            "The ledger endpoint returned no resources",
        ));
    };
    let resource_fee = u64::try_from(resources.resource_fee)
        .ok()
        .filter(|fee| *fee >= minimum);
    let fee = resource_fee
        .and_then(|fee| fee.checked_add(u64::from(INCLUSION_FEE)))
        .and_then(|fee| u32::try_from(fee).ok());
    let Some(fee) = fee.filter(|fee| u128::from(*fee) <= limits.max_fee) else {
        return refused("invalid_exact_stellar_payload_fee_exceeds_maximum");
    };
    if let Err(refusal) = events(&simulated, &authorization) {
        return Ok(Err(refusal));
    }
    Ok(Ok(Admitted {
        authorization,
        operation,
        resources,
        fee,
        timeout,
    }))
}

fn verify_reply(valid: bool, reason: Option<&str>, payer: Option<&str>) -> Value {
    let mut reply = json!({ "isValid": valid });
    if let Some(reason) = reason {
        reply["invalidReason"] = json!(reason);
    }
    if let Some(payer) = payer {
        reply["payer"] = json!(payer);
    }
    reply
}
fn settle_reply(
    network: &str,
    success: bool,
    reason: Option<&str>,
    payer: Option<&str>,
    transaction: Option<&[u8; 32]>,
) -> Value {
    let mut reply = json!({
        "success": success,
        "transaction": transaction.map(|hash| hex(hash)).unwrap_or_default(),
        "network": network,
    });
    if let Some(reason) = reason {
        reply["errorReason"] = json!(reason);
    }
    if let Some(payer) = payer {
        reply["payer"] = json!(payer);
    }
    reply
}

/// The outcome of the submitted transaction `hash`, as the ledger shows it now.
fn outcome(
    rpc: &dyn rpc::Rpc,
    network: &str,
    authorization: Option<Authorization>,
    hash: [u8; 32],
) -> HostResult<Option<Settled>> {
    let Some(receipt) = rpc::receipt_by_hash(rpc, network, &hash).map_err(rail)? else {
        return Ok(None);
    };
    let payer = authorization.as_ref().map(|a| a.payer.as_str());
    let result: TransactionResult = read(&receipt.result_xdr).map_err(rail)?;
    let fee_paid = u128::try_from(result.fee_charged).ok();
    let success = receipt.status == OperationStatus::Confirmed;
    Ok(Some(Settled {
        reply: settle_reply(
            network,
            success,
            (!success).then_some("settle_exact_stellar_transaction_failed"),
            payer,
            Some(&hash),
        ),
        outcome: if success {
            Outcome::Settled
        } else {
            Outcome::Refused
        },
        authorization,
        transaction: Some(hash),
        fee_paid,
    }))
}

fn pending(network: &str, authorization: Option<Authorization>, hash: [u8; 32]) -> Settled {
    Settled {
        reply: settle_reply(
            network,
            false,
            Some("settlement_pending"),
            authorization.as_ref().map(|a| a.payer.as_str()),
            Some(&hash),
        ),
        outcome: Outcome::Pending,
        authorization,
        transaction: Some(hash),
        fee_paid: None,
    }
}

impl SettlementProvider for Service {
    fn supported(&self, network: &str) -> HostResult<Supported> {
        let network = crate::host::routing::normalize(network)?;
        Ok(Supported {
            kinds: vec![json!({
                "x402Version": VERSION,
                "scheme": SCHEME,
                "network": network,
                "extra": {"areFeesSponsored": true},
            })],
            signers_key: "stellar:*".into(),
        })
    }

    fn verify(
        &self,
        network: &str,
        endpoint: &str,
        signer: &str,
        request: &Value,
        limits: &Limits,
    ) -> HostResult<Verified> {
        let rpc = rpc::HttpRpc::new(endpoint).map_err(rail)?;
        Ok(match admit(&rpc, network, signer, request, limits)? {
            Ok(admitted) => Verified {
                reply: verify_reply(true, None, Some(&admitted.authorization.payer)),
                fee: u128::from(admitted.fee),
                authorization: Some(admitted.authorization),
            },
            Err(Refusal(reason, payer)) => Verified {
                reply: verify_reply(false, Some(reason), payer.as_deref()),
                authorization: None,
                fee: 0,
            },
        })
    }

    fn settle(
        &self,
        network: &str,
        endpoint: &str,
        signer: &dyn Signer,
        request: &Value,
        limits: &Limits,
    ) -> HostResult<Settled> {
        let rpc = rpc::HttpRpc::new(endpoint).map_err(rail)?;
        let source = signer.identity().to_owned();
        let admitted = match admit(&rpc, network, &source, request, limits)? {
            Ok(admitted) => admitted,
            Err(Refusal(reason, payer)) => {
                return Ok(Settled {
                    reply: settle_reply(network, false, Some(reason), payer.as_deref(), None),
                    outcome: Outcome::Refused,
                    authorization: None,
                    transaction: None,
                    fee_paid: None,
                });
            }
        };
        // The service's own transaction: its account is the source, it pays the fee, and the
        // invocation and the payer's entry are the payload's, unchanged.
        let account = rpc::get_account(&rpc, &source).map_err(rail)?;
        let tx = Transaction {
            source_account: MuxedAccount::Ed25519(Uint256(account_key(&source).map_err(rail)?)),
            fee: admitted.fee,
            seq_num: SequenceNumber(
                account
                    .sequence
                    .checked_add(1)
                    .ok_or_else(|| Error::config("The service account sequence overflowed"))?,
            ),
            cond: Preconditions::Time(TimeBounds {
                min_time: TimePoint(0),
                max_time: TimePoint(now().saturating_add(admitted.timeout)),
            }),
            memo: Memo::None,
            operations: vec![Operation {
                source_account: None,
                body: OperationBody::InvokeHostFunction(admitted.operation.clone()),
            }]
            .try_into()
            .map_err(|_| Error::config("The settlement transaction cannot be built"))?,
            ext: TransactionExt::V1(admitted.resources.clone()),
        };
        let hash = transaction_hash(network, &tx).map_err(rail)?;
        let signature = signer.sign_hash(&hash)?;
        signing::verify_digest(&source, &hash, &signature).map_err(rail)?;
        let key = account_key(&source).map_err(rail)?;
        let envelope = xdr(&TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: vec![DecoratedSignature {
                hint: SignatureHint(key[28..].try_into().expect("four bytes")),
                signature: Signature(
                    signature
                        .try_into()
                        .map_err(|_| Error::config("Invalid service signature"))?,
                ),
            }]
            .try_into()
            .map_err(|_| Error::config("The settlement transaction cannot be signed"))?,
        }))
        .map_err(rail)?;
        let authorization = Some(admitted.authorization);
        let payer = authorization.as_ref().map(|a| a.payer.clone());
        match rpc::send_transaction(&rpc, network, &envelope).map_err(rail)? {
            rpc::Broadcast::Submitted => {}
            rpc::Broadcast::Rejected { .. } => {
                // The network refused it before inclusion. The ledger decides when it shows
                // the hash anyway; else nothing was submitted.
                if let Some(settled) = outcome(&rpc, network, authorization.clone(), hash)? {
                    return Ok(settled);
                }
                return Ok(Settled {
                    reply: settle_reply(
                        network,
                        false,
                        Some("settle_exact_stellar_transaction_submission_failed"),
                        payer.as_deref(),
                        None,
                    ),
                    outcome: Outcome::Refused,
                    authorization,
                    transaction: None,
                    fee_paid: None,
                });
            }
            rpc::Broadcast::RetryLater | rpc::Broadcast::Unknown => {
                return Ok(pending(network, authorization, hash));
            }
        }
        let deadline = Instant::now() + limits.wait;
        loop {
            // A failed read leaves the outcome unknown: the transaction can still settle.
            if let Ok(Some(settled)) = outcome(&rpc, network, authorization.clone(), hash) {
                return Ok(settled);
            }
            if Instant::now() >= deadline {
                return Ok(pending(network, authorization, hash));
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    }

    fn observe(
        &self,
        network: &str,
        endpoint: &str,
        request: &Value,
        transaction: &[u8; 32],
    ) -> HostResult<Settled> {
        let rpc = rpc::HttpRpc::new(endpoint).map_err(rail)?;
        // The request names the payer of the reply; the ledger decides the outcome.
        let authorization = structure(network, "", request)
            .ok()
            .map(|(_, authorization, ..)| authorization);
        Ok(outcome(&rpc, network, authorization.clone(), *transaction)?
            .unwrap_or_else(|| pending(network, authorization, *transaction)))
    }
}
