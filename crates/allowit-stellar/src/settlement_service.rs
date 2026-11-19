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
const DEFAULT_TIMEOUT: u64 = seller_settled::DEFAULT_SETTLE_WITHIN;
/// The longest timeout that a seller may state.
const MAX_TIMEOUT: u64 = 86_400;
/// The longest transaction text that is decoded.
const MAX_TRANSACTION_BYTES: usize = 16_384;

pub struct Service;
pub static SERVICE: Service = Service;

/// A refusal of the payload: the reason code of the reply and the payer when it is known.
#[derive(Debug)]
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
    let mut committed = Vec::new();
    for event in simulated["events"].as_array().into_iter().flatten() {
        let event: DiagnosticEvent = event
            .as_str()
            .and_then(|text| read(text).ok())
            .ok_or_else(|| Refusal("unexpected_verify_error", Some(a.payer.clone())))?;
        // A call that failed inside the transfer rolled its events back: the ledger keeps
        // none of them.
        if event.in_successful_contract_call {
            committed.push(event.event);
        }
    }
    one_transfer(&committed, a)
}

/// Check that the contract events in `events` are exactly one transfer of the asset from the
/// payer to the payee of the amount.
fn one_transfer(events: &[ContractEvent], a: &Authorization) -> Checked<()> {
    let refused = |reason| Refusal(reason, Some(a.payer.clone()));
    let mut transfers = 0;
    for event in events {
        if event.type_ != ContractEventType::Contract {
            continue;
        }
        let ContractEventBody::V0(body) = &event.body;
        let contract = event
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
    // The fee that the ledger charged for the service's transaction, the fee bump's charge when
    // a fee bump carried it; unknown when the receipt does not hold it.
    let fee_paid = rpc::fee_paid(&receipt).map_err(rail)?.map(|paid| paid.fee);
    // A successful transaction paid the seller only when its committed events are the one
    // transfer: a token can behave otherwise in the ledger than in the simulation. Without
    // the authorization or the committed events, the payment is not established.
    let reason = if receipt.status != OperationStatus::Confirmed {
        Some("settle_exact_stellar_transaction_failed")
    } else {
        let (Some(a), Some(events)) = (&authorization, committed(rpc, &hash)?) else {
            return Ok(Some(pending(network, authorization, hash)));
        };
        one_transfer(&events, a).err().map(|refusal| refusal.0)
    };
    Ok(Some(Settled {
        reply: settle_reply(network, reason.is_none(), reason, payer, Some(&hash)),
        outcome: if reason.is_none() {
            Outcome::Settled
        } else {
            Outcome::Refused
        },
        authorization,
        transaction: Some(hash),
        fee_paid,
    }))
}

/// The contract events that the transaction `hash` committed, when the ledger returns them.
fn committed(rpc: &dyn rpc::Rpc, hash: &[u8; 32]) -> HostResult<Option<Vec<ContractEvent>>> {
    let reply = rpc
        .call("getTransaction", json!({"hash": hex(hash)}))
        .map_err(rail)?;
    // A current endpoint lists the events of each operation.
    if let Some(operations) = reply["events"]["contractEventsXdr"].as_array() {
        let mut events = Vec::new();
        for event in operations
            .iter()
            .flat_map(|of| of.as_array().into_iter().flatten())
        {
            let Some(event) = event.as_str().and_then(|text| read(text).ok()) else {
                return Ok(None);
            };
            events.push(event);
        }
        return Ok(Some(events));
    }
    let Some(meta) = reply["resultMetaXdr"].as_str() else {
        return Ok(None);
    };
    Ok(match read::<TransactionMeta>(meta) {
        Ok(TransactionMeta::V3(meta)) => Some(
            meta.soroban_meta
                .map(|soroban| soroban.events.to_vec())
                .unwrap_or_default(),
        ),
        Ok(TransactionMeta::V4(meta)) => Some(
            meta.operations
                .iter()
                .flat_map(|operation| operation.events.to_vec())
                .collect(),
        ),
        _ => None,
    })
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
            // The transaction is valid for the seller's timeout and no longer than the entry
            // that it carries: after the ledger bound the network takes it in no form, so a
            // hash that the ledger does not know then is never included.
            cond: Preconditions::V2(PreconditionsV2 {
                time_bounds: Some(TimeBounds {
                    min_time: TimePoint(0),
                    max_time: TimePoint(now().saturating_add(admitted.timeout)),
                }),
                ledger_bounds: Some(LedgerBounds {
                    min_ledger: 0,
                    max_ledger: last_ledger(&admitted.authorization)?,
                }),
                min_seq_num: None,
                min_seq_age: stellar_xdr::Duration(0),
                min_seq_ledger_gap: 0,
                extra_signers: VecM::default(),
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
            rpc::Broadcast::Rejected { .. } | rpc::Broadcast::RetryLater => {
                // The network did not take the transaction: it refused it, or it asks for a
                // later attempt. The ledger decides when it shows the hash anyway; else
                // nothing was submitted, and the caller may settle again.
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
            rpc::Broadcast::Unknown => {
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
        let read = structure(network, "", request).ok();
        let authorization = read
            .as_ref()
            .map(|(_, authorization, ..)| authorization.clone());
        if let Some(settled) = outcome(&rpc, network, authorization.clone(), *transaction)? {
            return Ok(settled);
        }
        // A transaction that the ledger never took, and can never take, settles nothing: the
        // caller may settle the authorization again while it is valid.
        if let Some((_, a, timeout, _)) = &read
            && never_included(&rpc, a, *timeout, transaction)?
        {
            return Ok(Settled {
                reply: settle_reply(
                    network,
                    false,
                    Some("settle_exact_stellar_transaction_not_included"),
                    Some(&a.payer),
                    None,
                ),
                outcome: Outcome::Refused,
                authorization,
                transaction: None,
                fee_paid: None,
            });
        }
        Ok(pending(network, authorization, *transaction))
    }
}

/// The ledger bound of the settlement transaction of `a`: one ledger after the expiry ledger
/// of its entry. The network reads the bound as the last valid ledger or as the first invalid
/// one; with this value the entry is valid in every ledger that takes the transaction, and
/// no ledger after it takes the transaction, even as a failed one.
fn last_ledger(a: &Authorization) -> HostResult<u32> {
    a.expires_height
        .checked_add(1)
        .and_then(|ledger| u32::try_from(ledger).ok())
        .ok_or_else(|| Error::config("The expiry ledger of the authorization overflows"))
}

/// Whether the transaction `hash`, which carries the entry of `a`, is not in the ledger and
/// can never be. Its ledger bound ends one ledger after the expiry ledger of the entry
/// ([`last_ledger`]). The service sent it no earlier than the ledger at which that expiry was
/// inside the bound of `timeout`. So an endpoint whose history covers that span, past the
/// ledger bound, proves the absence when it does not know the hash.
fn never_included(
    rpc: &dyn rpc::Rpc,
    a: &Authorization,
    timeout: u64,
    hash: &[u8; 32],
) -> HostResult<bool> {
    let reply = rpc
        .call("getTransaction", json!({"hash": hex(hash)}))
        .map_err(rail)?;
    let (Some(oldest), Some(latest)) = (
        reply["oldestLedger"].as_u64(),
        reply["latestLedger"].as_u64(),
    ) else {
        return Ok(false);
    };
    let earliest = a
        .expires_height
        .saturating_sub(timeout.div_ceil(LEDGER_SECONDS) + EXPIRY_TOLERANCE);
    Ok(reply["status"] == "NOT_FOUND" && latest > u64::from(last_ledger(a)?) && oldest <= earliest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support;
    use std::sync::Mutex;

    const NETWORK: &str = "stellar:testnet";
    const NOW: u64 = 86_401;
    const SERVICE: [u8; 32] = [6; 32];

    /// A keypair wallet's signed authorization and the transfer that it pays.
    fn signed() -> (SignedOperation, Transfer) {
        let ordinary = test_support::native_signed().prepared;
        let t = transfer_from_request(&ordinary.config, &ordinary.request).unwrap();
        let r = seller_settled::request(
            &ordinary.config,
            ordinary.request.operation.nonce,
            &t.recipient,
            t.amount,
        )
        .unwrap();
        let p = seller_settled::attach(ordinary, &r, NOW).unwrap();
        let sign = |seed: [u8; 32]| {
            seller_settled::sign(&p, &account_for_seed(&seed), NOW, |digest| {
                Ok(test_support::sign_digest(seed, digest))
            })
            .unwrap()
        };
        let signed = seller_settled::assemble(&p, &[sign([2; 32]), sign([3; 32])], NOW).unwrap();
        (signed, t)
    }
    fn asset(signed: &SignedOperation) -> String {
        let c = &signed.prepared.config;
        sac_address(&c.network, &asset_xdr(c).unwrap()).unwrap()
    }
    /// The seller's request for `signed`: the payload and the requirements that it accepted.
    fn request(signed: &SignedOperation, t: &Transfer) -> Value {
        let requirements = json!({"scheme": SCHEME, "network": NETWORK, "amount": t.amount.to_string(),
            "asset": asset(signed), "payTo": t.recipient, "maxTimeoutSeconds": 300,
            "extra": {"areFeesSponsored": true}});
        json!({"x402Version": 2, "paymentRequirements": requirements,
            "paymentPayload": {"x402Version": 2, "accepted": requirements,
                "payload": {"transaction": signed.transaction_xdr}}})
    }
    fn service() -> String {
        account_for_seed(&SERVICE)
    }
    fn reason(request: &Value) -> &'static str {
        match structure(NETWORK, &service(), request) {
            Ok(_) => "valid",
            Err(Refusal(reason, _)) => reason,
        }
    }
    /// The payload of `signed` after `change` to its transaction.
    fn changed(signed: &SignedOperation, t: &Transfer, change: &dyn Fn(&mut Transaction)) -> Value {
        let TransactionEnvelope::Tx(mut envelope) = read(&signed.transaction_xdr).unwrap() else {
            panic!("a transaction")
        };
        change(&mut envelope.tx);
        let mut request = request(signed, t);
        request["paymentPayload"]["payload"]["transaction"] =
            json!(xdr(&TransactionEnvelope::Tx(envelope)).unwrap());
        request
    }
    fn invocation(tx: &mut Transaction, change: &dyn Fn(&mut InvokeHostFunctionOp)) {
        let mut operations = tx.operations.to_vec();
        let OperationBody::InvokeHostFunction(op) = &mut operations[0].body else {
            panic!("an invocation")
        };
        change(op);
        tx.operations = operations.try_into().unwrap();
    }

    #[test]
    fn a_standard_payload_reads_as_one_authorization() {
        let (signed, t) = signed();
        let (_, authorization, timeout, _) = structure(NETWORK, &service(), &request(&signed, &t))
            .ok()
            .unwrap();
        assert_eq!(authorization.payer, signed.prepared.config.wallet);
        assert_eq!(authorization.pay_to, t.recipient);
        assert_eq!(authorization.units, t.amount);
        assert_eq!(authorization.asset, asset(&signed));
        assert_eq!(timeout, 300);
        // Another signed entry is another authorization.
        assert_ne!(authorization.id, [0; 32]);
        let supported = SERVICE_HOOK.supported(NETWORK).unwrap();
        assert_eq!(supported.signers_key, "stellar:*");
        assert_eq!(supported.kinds[0]["extra"]["areFeesSponsored"], true);
        assert_eq!(supported.kinds[0]["network"], NETWORK);
    }
    static SERVICE_HOOK: Service = Service;

    #[test]
    fn the_protocol_fields_of_a_request_are_strict() {
        let (signed, t) = signed();
        let with = |change: &dyn Fn(&mut Value)| {
            let mut request = request(&signed, &t);
            change(&mut request);
            reason(&request)
        };
        assert_eq!(with(&|_| {}), "valid");
        assert_eq!(
            with(&|r| r["paymentPayload"]["x402Version"] = json!(1)),
            "invalid_x402_version"
        );
        assert_eq!(
            with(&|r| r["paymentRequirements"]["scheme"] = json!("upto")),
            "unsupported_scheme"
        );
        assert_eq!(
            with(&|r| r["paymentPayload"]["accepted"]["network"] = json!("stellar:pubnet")),
            "network_mismatch"
        );
        assert_eq!(
            with(&|r| {
                r["paymentPayload"]["accepted"]["network"] = json!("stellar:pubnet");
                r["paymentRequirements"]["network"] = json!("stellar:pubnet");
            }),
            "invalid_network"
        );
        assert_eq!(
            with(&|r| r["paymentPayload"]["payload"]["transaction"] = json!("AAAA")),
            "invalid_exact_stellar_payload_malformed"
        );
        assert_eq!(
            with(&|r| r["paymentRequirements"]["asset"] = json!(test_support::vault(3))),
            "invalid_exact_stellar_payload_wrong_asset"
        );
        assert_eq!(
            with(&|r| r["paymentRequirements"]["payTo"] = json!(account_for_seed(&[9; 32]))),
            "invalid_exact_stellar_payload_wrong_recipient"
        );
        for amount in [json!("1"), json!(t.amount), json!("-5"), json!("")] {
            assert_eq!(
                with(&|r| r["paymentRequirements"]["amount"] = amount.clone()),
                "invalid_exact_stellar_payload_wrong_amount",
                "{amount}"
            );
        }
        assert_eq!(
            with(&|r| r["paymentRequirements"]["maxTimeoutSeconds"] = json!(0)),
            "invalid_payment_requirements"
        );
    }

    #[test]
    fn the_service_is_never_a_party_of_the_payment() {
        let (signed, t) = signed();
        let key = account_key(&service()).unwrap();
        // The service as the source of the payer's transaction or of its operation.
        let source = changed(&signed, &t, &|tx| {
            tx.source_account = MuxedAccount::Ed25519(Uint256(key))
        });
        assert_eq!(
            reason(&source),
            "invalid_exact_stellar_payload_unsafe_tx_or_op_source"
        );
        let operation = changed(&signed, &t, &|tx| {
            let mut operations = tx.operations.to_vec();
            operations[0].source_account = Some(MuxedAccount::Ed25519(Uint256(key)));
            tx.operations = operations.try_into().unwrap();
        });
        assert_eq!(
            reason(&operation),
            "invalid_exact_stellar_payload_unsafe_tx_or_op_source"
        );
        // The service as the payer: the wallet of the payload is the service's own account.
        let request = request(&signed, &t);
        assert!(matches!(
            structure(NETWORK, &signed.prepared.config.wallet, &request),
            Err(Refusal(
                "invalid_exact_stellar_payload_facilitator_is_payer",
                _
            ))
        ));
    }

    #[test]
    fn one_signed_entry_of_the_payer_for_exactly_the_call_is_required() {
        let (signed, t) = signed();
        let with = |change: &dyn Fn(&mut InvokeHostFunctionOp)| {
            reason(&changed(&signed, &t, &|tx| invocation(tx, change)))
        };
        assert_eq!(
            with(&|op| op.auth = VecM::default()),
            "invalid_exact_stellar_payload_no_auth_entries"
        );
        assert_eq!(
            with(&|op| {
                let entry = op.auth[0].clone();
                op.auth = vec![entry.clone(), entry].try_into().unwrap();
            }),
            "invalid_exact_stellar_payload_unexpected_auth_entry"
        );
        let entry = |change: &dyn Fn(&mut SorobanAuthorizationEntry)| {
            with(&|op| {
                let mut entry = op.auth[0].clone();
                change(&mut entry);
                op.auth = vec![entry].try_into().unwrap();
            })
        };
        assert_eq!(
            entry(&|e| e.credentials = SorobanCredentials::SourceAccount),
            "invalid_exact_stellar_payload_unsupported_credential_type"
        );
        assert_eq!(
            entry(&|e| {
                let SorobanCredentials::Address(credentials) = &mut e.credentials else {
                    panic!("an address authorization")
                };
                credentials.signature = ScVal::Void;
            }),
            "invalid_exact_stellar_payload_missing_payer_signature"
        );
        assert_eq!(
            entry(&|e| {
                let SorobanCredentials::Address(credentials) = &mut e.credentials else {
                    panic!("an address authorization")
                };
                credentials.address = address(&account_for_seed(&[9; 32])).unwrap();
            }),
            "invalid_exact_stellar_payload_missing_payer_signature"
        );
        assert_eq!(
            entry(&|e| {
                let nested = e.root_invocation.clone();
                e.root_invocation.sub_invocations = vec![nested].try_into().unwrap();
            }),
            "invalid_exact_stellar_payload_has_subinvocations"
        );
        // Another function, more arguments, or a second operation is no transfer.
        assert_eq!(
            with(&|op| {
                let HostFunction::InvokeContract(call) = &mut op.host_function else {
                    panic!("a contract call")
                };
                call.function_name = ScSymbol(b"approve".to_vec().try_into().unwrap());
            }),
            "invalid_exact_stellar_payload_wrong_function_name"
        );
        let two = changed(&signed, &t, &|tx| {
            let operation = tx.operations[0].clone();
            tx.operations = vec![operation.clone(), operation].try_into().unwrap();
        });
        assert_eq!(
            reason(&two),
            "invalid_exact_stellar_payload_wrong_operation"
        );
    }

    /// A ledger endpoint with a fixed head and one simulation reply. It counts sends.
    struct Ledger {
        latest: u64,
        simulated: Value,
        sent: Mutex<u32>,
    }
    impl rpc::Rpc for Ledger {
        fn call(&self, method: &str, _: Value) -> Result<Value> {
            Ok(match method {
                "getNetwork" => json!({"passphrase": passphrase(NETWORK).unwrap()}),
                "getLatestLedger" => json!({"sequence": self.latest}),
                "simulateTransaction" => self.simulated.clone(),
                "sendTransaction" => {
                    *self.sent.lock().unwrap() += 1;
                    json!({})
                }
                other => panic!("unexpected ledger call {other}"),
            })
        }
    }
    fn transfer_event(contract: &str, from: &str, to: &str, units: i128) -> String {
        let ScAddress::Contract(id) = address(contract).unwrap() else {
            panic!("a contract")
        };
        xdr(&DiagnosticEvent {
            in_successful_contract_call: true,
            event: ContractEvent {
                ext: ExtensionPoint::V0,
                contract_id: Some(id),
                type_: ContractEventType::Contract,
                body: ContractEventBody::V0(ContractEventV0 {
                    topics: vec![
                        value_symbol("transfer").unwrap(),
                        ScVal::Address(address(from).unwrap()),
                        ScVal::Address(address(to).unwrap()),
                    ]
                    .try_into()
                    .unwrap(),
                    data: i128_value(units),
                }),
            },
        })
        .unwrap()
    }
    fn simulation(events: Vec<String>, resource_fee: i64) -> Value {
        let resources = SorobanTransactionData {
            ext: SorobanTransactionDataExt::V0,
            resources: SorobanResources {
                footprint: LedgerFootprint {
                    read_only: VecM::default(),
                    read_write: VecM::default(),
                },
                instructions: 1,
                disk_read_bytes: 0,
                write_bytes: 0,
            },
            resource_fee,
        };
        json!({"transactionData": xdr(&resources).unwrap(), "minResourceFee": resource_fee.to_string(),
            "events": events})
    }
    fn admitted(
        ledger: &Ledger,
        request: &Value,
        max_fee: u128,
    ) -> std::result::Result<u32, &'static str> {
        let limits = Limits {
            max_fee,
            wait: Duration::ZERO,
        };
        match admit(ledger, NETWORK, &service(), request, &limits).unwrap() {
            Ok(admitted) => Ok(admitted.fee),
            Err(Refusal(reason, _)) => Err(reason),
        }
    }

    #[test]
    fn the_ledger_must_show_the_one_transfer_under_the_fee_ceiling() {
        let (signed, t) = signed();
        let request = request(&signed, &t);
        let wallet = signed.prepared.config.wallet.clone();
        let token = asset(&signed);
        let head = u64::from(signed.prepared.state.ledger);
        let event = transfer_event(&token, &wallet, &t.recipient, t.amount);
        let ledger = |events: Vec<String>, fee: i64| Ledger {
            latest: head,
            simulated: simulation(events, fee),
            sent: Mutex::new(0),
        };
        // The fee of a settlement is the resource fee and the inclusion fee.
        assert_eq!(
            admitted(&ledger(vec![event.clone()], 40_000), &request, 50_000),
            Ok(40_000 + INCLUSION_FEE)
        );
        assert_eq!(
            admitted(&ledger(vec![event.clone()], 49_901), &request, 50_000),
            Err("invalid_exact_stellar_payload_fee_exceeds_maximum")
        );
        // An event of a call that failed inside the transfer is rolled back and counts as
        // nothing.
        let mut rolled_back: DiagnosticEvent =
            read(&transfer_event(&token, &wallet, &t.recipient, t.amount + 1)).unwrap();
        rolled_back.in_successful_contract_call = false;
        assert_eq!(
            admitted(
                &ledger(vec![xdr(&rolled_back).unwrap(), event.clone()], 100),
                &request,
                50_000
            ),
            Ok(100 + INCLUSION_FEE)
        );
        // After the settlement, the committed events decide: a successful transaction that
        // moved nothing, or something else, paid nobody. Without the events the payment is
        // not established.
        let authorization = structure(NETWORK, "", &request).unwrap().1;
        struct Committed(Value);
        impl rpc::Rpc for Committed {
            fn call(&self, method: &str, _: Value) -> Result<Value> {
                assert_eq!(method, "getTransaction");
                Ok(self.0.clone())
            }
        }
        let paid: DiagnosticEvent = read(&event).unwrap();
        let listed = |events: Vec<&ContractEvent>| {
            let events: Vec<String> = events.into_iter().map(|e| xdr(e).unwrap()).collect();
            committed(
                &Committed(json!({"events": {"contractEventsXdr": [events]}})),
                &[9; 32],
            )
            .unwrap()
            .unwrap()
        };
        assert!(one_transfer(&listed(vec![&paid.event]), &authorization).is_ok());
        assert_eq!(
            one_transfer(&listed(vec![]), &authorization).unwrap_err().0,
            "invalid_exact_stellar_payload_no_transfer_events"
        );
        assert_eq!(
            one_transfer(&listed(vec![&rolled_back.event]), &authorization)
                .unwrap_err()
                .0,
            "invalid_exact_stellar_payload_event_wrong_amount"
        );
        assert!(
            committed(&Committed(json!({"status": "SUCCESS"})), &[9; 32])
                .unwrap()
                .is_none()
        );
        // A transaction that the ledger does not know after the expiry ledger of its entry
        // was never included, when the endpoint's history covers the span in which the
        // service can have sent it.
        let expires = authorization.expires_height;
        let absent = |status: &str, oldest: u64, latest: u64| {
            never_included(
                &Committed(
                    json!({"status": status, "oldestLedger": oldest, "latestLedger": latest}),
                ),
                &authorization,
                300,
                &[9; 32],
            )
            .unwrap()
        };
        let earliest = expires - (60 + EXPIRY_TOLERANCE);
        assert!(absent("NOT_FOUND", earliest, expires + 2));
        // Before the ledger bound of the transaction passed, with a shorter history, or when
        // the ledger knows the hash, nothing is proven.
        assert!(!absent("NOT_FOUND", earliest, expires + 1));
        assert!(!absent("NOT_FOUND", earliest + 1, expires + 2));
        assert!(!absent("SUCCESS", earliest, expires + 2));
        // No transfer, two transfers, and a transfer of another amount, payee, payer or token.
        assert_eq!(
            admitted(&ledger(vec![], 100), &request, 50_000),
            Err("invalid_exact_stellar_payload_no_transfer_events")
        );
        assert_eq!(
            admitted(
                &ledger(vec![event.clone(), event.clone()], 100),
                &request,
                50_000
            ),
            Err("invalid_exact_stellar_payload_multiple_transfers")
        );
        let other = account_for_seed(&[9; 32]);
        for (changed, reason) in [
            (
                transfer_event(&token, &wallet, &t.recipient, t.amount + 1),
                "invalid_exact_stellar_payload_event_wrong_amount",
            ),
            (
                transfer_event(&token, &wallet, &other, t.amount),
                "invalid_exact_stellar_payload_event_wrong_to",
            ),
            (
                transfer_event(&token, &other, &t.recipient, t.amount),
                "invalid_exact_stellar_payload_event_wrong_from",
            ),
            (
                transfer_event(&test_support::vault(3), &wallet, &t.recipient, t.amount),
                "invalid_exact_stellar_payload_event_wrong_asset",
            ),
        ] {
            assert_eq!(
                admitted(&ledger(vec![event.clone(), changed], 100), &request, 50_000),
                Err(reason)
            );
        }
        // A simulation that the ledger refuses, and an entry that outlives the seller's timeout.
        let refused = Ledger {
            latest: head,
            simulated: json!({"error": "host error"}),
            sent: Mutex::new(0),
        };
        assert_eq!(
            admitted(&refused, &request, 50_000),
            Err("invalid_exact_stellar_payload_simulation_failed")
        );
        let mut short = request.clone();
        short["paymentRequirements"]["maxTimeoutSeconds"] = json!(30);
        short["paymentPayload"]["accepted"]["maxTimeoutSeconds"] = json!(30);
        assert_eq!(
            admitted(&ledger(vec![event.clone()], 100), &short, 50_000),
            Err("invalid_exact_stellar_signature_expiration_too_far")
        );
        // Nothing was sent by any check.
        let checked = ledger(vec![event], 100);
        admitted(&checked, &request, 50_000).unwrap();
        assert_eq!(*checked.sent.lock().unwrap(), 0);
    }
}
