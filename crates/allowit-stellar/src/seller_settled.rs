//! Payment authorizations that the seller settles: the x402 `exact` scheme.
//!
//! A seller's challenge of the `exact` scheme asks the payer for one signed Soroban
//! authorization entry: `transfer(from, payTo, amount)` on the token contract, with a nonce
//! and an expiry ledger. The seller's facilitator puts the entry into its own transaction,
//! pays the network fee and submits it. The payer signs no transaction and pays no fee.
//!
//! Here such a payment is an ordinary operation with one difference: who submits it. The
//! request names the same transfer, carries no fee bound and holds [`marker`]. Preparation
//! prepares that transfer as the wallet would execute it itself, so the wallet contract and
//! the service decide on it exactly as on any payment, and then adds a
//! [`PaymentAuthorization`]: the entry of exactly that transfer and the digest that the agent
//! and the service sign. The wallet's custom-account check admits the entry only with both
//! signatures, at the wallet nonce of the preparation, before the expiry, and counts the
//! amount without gas. Nothing else can be done with the entry: it names the token, the
//! payer, the payee and the amount, the ledger consumes its nonce once, and it expires.
//!
//! The service sends nothing. It reads the outcome from the ledger: the wallet stores a
//! receipt under the operation id when the entry settles, and the token's transfer event
//! names the transaction. An entry that did not settle by its expiry lapses as any policy
//! wallet operation does, once the wallet still shows its nonce after the expiry.
//!
//! Only a policy wallet with owner-enabled x402 signs such an entry.
use crate::workflow::{
    Chain, EvidenceKind, EvidenceRef, WorkflowAsset, WorkflowEffectBound, WorkflowFeeBound,
};
use crate::*;
use serde_json::json;

/// The longest validity of an entry, in ledgers: the bound of [`x402`].
pub const MAX_LEDGERS: u32 = 64;
/// The ledger time that bounds the entry's expiry ledger. A facilitator admits an expiry of
/// at most the seller's timeout divided by its own estimate of the ledger time, which is 5 or
/// 6 seconds. The longer time gives the earlier ledger, which both estimates admit.
pub const LEDGER_SECONDS: u64 = 6;
/// The fault of a wallet whose owner has not enabled payment authorizations.
pub const DISABLED: &str = "The owner has not enabled x402 payment authorizations for this wallet. The owner enables them with a signed update of the wallet.";
const EVIDENCE_NAMESPACE: u32 = 402;
const EVIDENCE_SCHEMA: u16 = 1;
const DOMAIN: &[u8] = b"allowit-seller-settled-payment-v1";
/// The fee that the payload transaction declares. The facilitator replaces it.
const PAYLOAD_FEE: u32 = 100;

/// The evidence reference that marks a request as a payment that the seller settles.
pub fn marker() -> EvidenceRef {
    EvidenceRef {
        namespace_id: EVIDENCE_NAMESPACE,
        schema: EVIDENCE_SCHEMA,
        kind: EvidenceKind::PaymentChallenge,
        digest: hash(DOMAIN),
    }
}

/// Whether `r` asks for a payment authorization: no fee bound, and the marker alone.
pub fn is_request(r: &ExecutionRequest) -> bool {
    r.fee_bounds.is_none() && r.evidence.as_slice() == [marker()]
}

/// The request of a transfer of `amount` of the wallet asset to `to` that the seller settles.
pub fn request(
    c: &WalletConfig,
    operation_id: [u8; 32],
    to: &str,
    amount: i128,
) -> Result<ExecutionRequest> {
    let (instruction, asset) = request::transfer_instruction(c, to, amount)?;
    let units = request::units(amount)?;
    let request = ExecutionRequest {
        operation: workflow::OperationRef {
            policy_instance: c.policy_instance,
            nonce: operation_id,
        },
        input: ExecutionInput::Instructions(vec![instruction]),
        effect_bounds: vec![WorkflowEffectBound {
            asset,
            source: request::account(&c.wallet)?,
            beneficiary: request::account(to)?,
            max_debit: units,
            min_credit: units,
            max_burn: 0u64.into(),
        }],
        fee_bounds: None,
        evidence: vec![marker()],
    };
    transfer(c, &request)?;
    Ok(request)
}

/// The same transfer in the shape of an ordinary request, for decoding alone: the fee bound
/// names a role key and pays nothing.
fn shaped(c: &WalletConfig, r: &ExecutionRequest) -> Result<ExecutionRequest> {
    if !is_request(r) {
        return Err("The request asks for no payment authorization".into());
    }
    let payer = if c.route == WalletRoute::Native {
        &c.wallet
    } else {
        &c.agent
    };
    let mut out = r.clone();
    out.evidence.clear();
    out.fee_bounds = Some(vec![WorkflowFeeBound {
        payer: request::account(payer)?,
        asset: WorkflowAsset::Native {
            chain: Chain::Stellar,
            network: network_id(&c.network)?,
        },
        max_fee: u64::from(c.max_fee_stroops).into(),
    }]);
    Ok(out)
}

/// The transfer that a request for a payment authorization names.
pub fn transfer(c: &WalletConfig, r: &ExecutionRequest) -> Result<Transfer> {
    transfer_from_request(c, &shaped(c, r)?)
}

fn retained_transfer(c: &WalletConfig, r: &ExecutionRequest) -> Result<Transfer> {
    match retained_operation_from_request(c, r)? {
        StellarOperation::Transfer(t) => Ok(t),
        _ => Err("A payment authorization holds one transfer".into()),
    }
}

/// The part of a prepared operation that makes it a payment authorization. The operation
/// around it is the same transfer prepared for the wallet's own execution: it carries the
/// decision, and nobody signs or sends its transaction.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PaymentAuthorization {
    /// The request as the agent sent it.
    pub request: ExecutionRequest,
    /// The execution terms that both signers sign: the terms of the operation without gas,
    /// because the facilitator pays the network fee.
    pub terms: ExecutionTerms,
    /// The unsigned authorization entry of the wallet for exactly the transfer.
    pub authorization_xdr: String,
    /// What the agent and the service sign.
    pub digest: [u8; 32],
    /// The service's signature of `digest`, once it approved the operation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_signature: Option<Vec<u8>>,
}

/// The request that the agent sent for `p`: the authorization request, or the operation's.
pub fn intent(p: &PreparedOperation) -> &ExecutionRequest {
    p.payment_authorization
        .as_deref()
        .map_or(&p.request, |a| &a.request)
}

fn part(p: &PreparedOperation) -> Result<&PaymentAuthorization> {
    p.payment_authorization
        .as_deref()
        .ok_or_else(|| "The operation is no payment authorization".into())
}

/// The terms without gas: the wallet counts the amount alone.
fn terms_without_gas(terms: &ExecutionTerms) -> Result<ExecutionTerms> {
    let mut out = terms.clone();
    if let Some(expense) = &mut out.expense {
        expense.spent_units = expense
            .spent_units
            .checked_sub(expense.gas_units)
            .ok_or("Expense bounds overflow")?;
        expense.gas_units = 0;
        expense.max_fee_stroops = 0;
    }
    Ok(out)
}

/// The unsigned entry of `p`: the wallet authorizes `transfer(wallet, recipient, amount)` on
/// its asset contract. The nonce derives from the operation id, so one request ID has one
/// entry. The expiry ledger follows the validity of the operation.
fn entry(p: &PreparedOperation) -> Result<SorobanAuthorizationEntry> {
    let c = &p.config;
    let t = retained_transfer(c, &p.request)?;
    let mut identity = DOMAIN.to_vec();
    identity.extend(network_id(&c.network)?);
    identity.extend(address(&c.wallet)?.to_xdr(limits()).map_err(err)?);
    identity.extend(p.request.operation.nonce);
    identity.extend(p.state.deployment_version.to_be_bytes());
    let nonce = i64::from_be_bytes(hash(identity)[..8].try_into().unwrap()) & i64::MAX;
    let seconds = p
        .expires_at
        .checked_sub(p.created_at)
        .ok_or("Invalid operation validity")?;
    let ledgers = (seconds / LEDGER_SECONDS).clamp(1, u64::from(MAX_LEDGERS)) as u32;
    Ok(SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: address(&c.wallet)?,
            nonce,
            signature_expiration_ledger: p
                .state
                .ledger
                .checked_add(ledgers)
                .ok_or("Authorization ledger overflow")?,
            signature: ScVal::Void,
        }),
        root_invocation: SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                contract_address: address(&c.asset)?,
                function_name: ScSymbol(b"transfer".to_vec().try_into().map_err(err)?),
                args: vec![
                    ScVal::Address(address(&c.wallet)?),
                    ScVal::Address(address(&t.recipient)?),
                    i128_value(t.amount),
                ]
                .try_into()
                .map_err(err)?,
            }),
            sub_invocations: VecM::default(),
        },
    })
}

/// The execution packet that the wallet reads from the entry's signature.
fn execution(p: &PreparedOperation, a: &PaymentAuthorization) -> Result<ScVal> {
    let t = retained_transfer(&p.config, &p.request)?;
    policy_wallet_request(
        &p.config,
        &p.request,
        &a.terms,
        &p.state,
        &StellarOperation::Transfer(t),
        p.expires_at,
    )
}

/// The digest that both signers sign: the wallet's domain, the host payload of the entry and
/// the execution packet. This is the encoding of [`x402::signing_digest`], without its checks
/// of the current time, so a retained packet reads after its expiry.
fn digest(p: &PreparedOperation, a: &PaymentAuthorization) -> Result<[u8; 32]> {
    let entry: SorobanAuthorizationEntry = read(&a.authorization_xdr)?;
    let host_payload = authorization::payload(&p.config.network, &entry)?;
    let domain = ScVal::Vec(Some(
        vec![
            value_symbol("allowit_wallet_v1")?,
            value_bytes(&host_payload)?,
            execution(p, a)?,
        ]
        .try_into()
        .map_err(err)?,
    ));
    Ok(hash(domain.to_xdr(limits()).map_err(err)?))
}

/// The raw-key signing request of `p`, as [`x402`] checks it.
pub fn signing_request(p: &PreparedOperation) -> Result<x402::SigningRequest> {
    let a = part(p)?;
    let policy = p
        .state
        .policy_state
        .as_ref()
        .ok_or("A payment authorization needs the wallet's policy state")?;
    Ok(x402::SigningRequest {
        config: p.config.clone(),
        request: p.request.clone(),
        state: x402::WalletState {
            custody: p.state.clone(),
            tier: p.config.tier.ok_or("Selected policy tier is required")?,
            x402_enabled: policy.x402_enabled,
            paused: false,
        },
        expires_at: p.expires_at,
        terms: a.terms.clone(),
        authorization_xdr: a.authorization_xdr.clone(),
    })
}

fn signature(bytes: &[u8]) -> Result<[u8; 64]> {
    bytes
        .try_into()
        .map_err(|_| "Invalid signature length".into())
}

/// Check the retained authorization part of `p` against the operation around it. Every field
/// is rebuilt: the request names the operation's transfer, the terms are the operation's
/// without gas, the entry is the one entry of that transfer, and the digest binds them. This
/// reads no time and grants nothing.
pub fn validate(p: &PreparedOperation) -> Result<()> {
    let a = part(p)?;
    let c = &p.config;
    if c.route != WalletRoute::PolicyWallet {
        return Err("Only a policy wallet signs a payment authorization".into());
    }
    if !is_request(&a.request)
        || a.request.operation != p.request.operation
        || a.request.input != p.request.input
        || a.request.effect_bounds != p.request.effect_bounds
    {
        return Err("The payment authorization names another operation".into());
    }
    // The agent's request and the operation name one transfer.
    retained_transfer(c, &shaped(c, &a.request)?)?;
    if a.terms != terms_without_gas(&p.terms)?
        || a.authorization_xdr != xdr(&entry(p)?)?
        || a.digest != digest(p, a)?
    {
        return Err("The payment authorization differs from its operation".into());
    }
    if let Some(bytes) = &a.server_signature {
        signing::verify_digest(&c.server, &a.digest, bytes)
            .map_err(|_| "Invalid service signature of the payment authorization")?;
    }
    Ok(())
}

/// Admit `p` for a new signature at `now`: the policy holds on the exact terms that the
/// signers sign, and every binding of [`x402::signing_digest`] holds now.
pub fn admit(p: &PreparedOperation, now: u64) -> Result<[u8; 32]> {
    let a = part(p)?;
    validate_retained_prepared(p)?;
    if p.version != 1 || p.created_at > now || now >= p.expires_at {
        return Err("Prepared operation is stale".into());
    }
    // The host policy check of an operation, on the terms that the signers sign.
    verify_operation(
        &p.config,
        &p.request,
        &a.terms,
        &p.state,
        p.created_at,
        p.expires_at,
        None,
    )?;
    let digest = x402::signing_digest(&signing_request(p)?, now).map_err(|error| {
        if p.state
            .policy_state
            .as_ref()
            .is_some_and(|state| !state.x402_enabled)
        {
            DISABLED.to_owned()
        } else {
            error
        }
    })?;
    if digest != a.digest {
        return Err("The payment authorization digest differs".into());
    }
    Ok(digest)
}

/// Prepare the payment authorization of `r`. The same transfer is first prepared as the
/// wallet would execute it itself: the recording simulation of that invocation runs the
/// wallet's own checks and its policy. The authorization part is then derived from it.
pub fn prepare(
    rpc: &dyn rpc::Rpc,
    c: &WalletConfig,
    r: &ExecutionRequest,
    terms: &ExecutionTerms,
    accounting: Option<rpc::NativeAccounting>,
    now: u64,
    expires_at: u64,
) -> Result<PreparedOperation> {
    if c.route != WalletRoute::PolicyWallet {
        return Err("Only a policy wallet signs a payment authorization".into());
    }
    let t = transfer(c, r)?;
    let found = rpc::trusted_state_for_discovery(rpc, c, None)?;
    if found.paused {
        return Err("The wallet is paused".into());
    }
    if found
        .state
        .policy_state
        .as_ref()
        .is_none_or(|state| !state.x402_enabled)
    {
        return Err(DISABLED.into());
    }
    let ordinary = request::transfer(c, &found.state, r.operation.nonce, &t.recipient, t.amount)?;
    let mut p = rpc::prepare_with(rpc, c, &ordinary, terms, accounting, now, expires_at)?;
    let mut a = PaymentAuthorization {
        request: r.clone(),
        terms: terms_without_gas(&p.terms)?,
        authorization_xdr: xdr(&entry(&p)?)?,
        digest: [0; 32],
        server_signature: None,
    };
    a.digest = digest(&p, &a)?;
    p.payment_authorization = Some(Box::new(a));
    // The simulation above established the preflight of the operation. It now binds the
    // authorization part too.
    record_native_preflight(&mut p)?;
    admit(&p, now)?;
    Ok(p)
}

/// The service's approval: after the same policy gates as for an operation that it submits
/// itself, the service signs the digest. A Simple or Common wallet whose source is not
/// canonical-only needs `evaluator`, as [`x402::verify_server`] states.
pub fn authorize_server(
    p: &PreparedOperation,
    signer_account: &str,
    now: u64,
    evaluator: Option<policy::PortableEvaluator>,
    sign_hash: impl FnOnce(&[u8; 32]) -> Result<[u8; 64]>,
) -> Result<PreparedOperation> {
    let a = part(p)?;
    if signer_account != p.config.server {
        return Err("Configured policy service signer required".into());
    }
    if a.server_signature.is_some() {
        return Err("Service authorization is already signed".into());
    }
    validate_prepared(p, now)?;
    let digest = x402::verify_server(&signing_request(p)?, now, evaluator)?;
    if digest != a.digest {
        return Err("The payment authorization digest differs".into());
    }
    let signature = sign_hash(&digest)?;
    signing::verify_digest(signer_account, &digest, &signature)?;
    let mut out = p.clone();
    let mut signed = a.clone();
    signed.server_signature = Some(signature.to_vec());
    out.payment_authorization = Some(Box::new(signed));
    out.native_preflight = None;
    validate(&out)?;
    Ok(out)
}

/// Check `p` against the wallet as the ledger shows it now: the same nonce and configuration
/// revision, x402 enabled and no pause. Another state means that the entry cannot settle.
pub fn revalidate(rpc: &dyn rpc::Rpc, p: &PreparedOperation, now: u64) -> Result<()> {
    admit(p, now)?;
    let found = rpc::trusted_state_for_discovery(rpc, &p.config, None)?;
    let enabled = found
        .state
        .policy_state
        .as_ref()
        .is_some_and(|state| state.x402_enabled);
    if found.paused
        || !enabled
        || found.state.nonce != p.state.nonce
        || found.state.deployment_version != p.state.deployment_version
        || found.state.module_digest != p.state.module_digest
    {
        return Err("The wallet changed since this payment authorization was prepared".into());
    }
    Ok(())
}

/// The agent's signature of the digest of `p`, after the same admission as [`admit`]. The
/// service's signature must be present: the agent signs only what the service approved.
pub fn sign(
    p: &PreparedOperation,
    signer: &str,
    now: u64,
    sign_hash: impl FnOnce(&[u8; 32]) -> Result<[u8; 64]>,
) -> Result<DetachedSignature> {
    let digest = admit(p, now)?;
    if part(p)?.server_signature.is_none() {
        return Err("Service authorization is unsigned".into());
    }
    if signer != p.config.agent {
        return Err("Signer has no automated role".into());
    }
    let signature = sign_hash(&digest)?;
    signing::verify_digest(signer, &digest, &signature)
        .map_err(|_| "Signing capability returned an invalid signature")?;
    Ok(DetachedSignature {
        signer: signer.into(),
        signature: signature.to_vec(),
    })
}

/// The transaction that the agent presents to the seller: one invocation of the transfer with
/// the signed entry, from a placeholder source. The facilitator replaces the source, the
/// sequence number and the fee, so nothing here pays or can be submitted as it is.
fn payload_transaction(entry: &SorobanAuthorizationEntry) -> Result<String> {
    let SorobanAuthorizedFunction::ContractFn(call) = &entry.root_invocation.function else {
        return Err("A payment authorization invokes one contract".into());
    };
    let tx = Transaction {
        source_account: MuxedAccount::Ed25519(Uint256([0; 32])),
        fee: PAYLOAD_FEE,
        seq_num: SequenceNumber(1),
        cond: Preconditions::None,
        memo: Memo::None,
        operations: vec![Operation {
            source_account: None,
            body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                host_function: HostFunction::InvokeContract(call.clone()),
                auth: vec![entry.clone()].try_into().map_err(err)?,
            }),
        }]
        .try_into()
        .map_err(err)?,
        ext: TransactionExt::V0,
    };
    xdr(&TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: VecM::default(),
    }))
}

/// The signed entry: the entry of `p` with the wallet's `PolicyAuthorization` as its
/// signature, in the encoding of [`x402::assemble`].
fn signed_entry(
    p: &PreparedOperation,
    a: &PaymentAuthorization,
    agent_signature: &[u8; 64],
) -> Result<SorobanAuthorizationEntry> {
    let server_signature = signature(
        a.server_signature
            .as_deref()
            .ok_or("Service authorization is unsigned")?,
    )?;
    let mut entry: SorobanAuthorizationEntry = read(&a.authorization_xdr)?;
    let SorobanCredentials::Address(credentials) = &mut entry.credentials else {
        return Err("A payment authorization needs wallet-address authorization".into());
    };
    credentials.signature = value_map(vec![
        ("execution", execution(p, a)?),
        ("agent_signature", value_bytes(agent_signature)?),
        ("server_signature", value_bytes(&server_signature)?),
    ])?;
    Ok(entry)
}

/// Assemble the signed authorization from the agent's signature and check it against the
/// ledger: the enforce-mode simulation of the payload runs the wallet's own check with both
/// signatures. A wallet that refuses it releases nothing to the seller.
pub fn authorize(
    rpc: &dyn rpc::Rpc,
    p: &PreparedOperation,
    signatures: &[DetachedSignature],
    now: u64,
) -> Result<SignedOperation> {
    let a = part(p)?;
    let [agent] = signatures else {
        return Err("A payment authorization takes the agent's signature alone".into());
    };
    if agent.signer != p.config.agent {
        return Err("Signer has no automated role".into());
    }
    revalidate(rpc, p, now)?;
    let agent_signature = signature(&agent.signature)?;
    let server_signature = signature(
        a.server_signature
            .as_deref()
            .ok_or("Service authorization is unsigned")?,
    )?;
    // The reviewed assembly verifies both signatures and every binding at `now`.
    let assembled = x402::assemble(
        &signing_request(p)?,
        &agent_signature,
        &server_signature,
        now,
    )?;
    let entry = signed_entry(p, a, &agent_signature)?;
    if assembled != xdr(&entry)? {
        return Err("The assembled payment authorization differs".into());
    }
    let transaction = payload_transaction(&entry)?;
    let simulated = rpc.call(
        "simulateTransaction",
        json!({"transaction": transaction, "authMode": "enforce"}),
    )?;
    if simulated.get("error").is_some_and(|value| !value.is_null()) {
        return Err("The wallet refuses this payment authorization".into());
    }
    rpc::reject_restoration(&simulated)?;
    let signed = SignedOperation {
        prepared: p.clone(),
        transaction_xdr: transaction,
        transaction_hash: p.transaction_hash,
        role_signatures: vec![agent.clone()],
    };
    validate_signed(&signed)?;
    Ok(signed)
}

/// The signed entry that `s` carries, after checking the whole retained packet: the
/// preparation, the service's and the agent's signatures of its digest, and a payload that is
/// exactly the transaction of the signed entry.
fn retained_entry(s: &SignedOperation) -> Result<SorobanAuthorizationEntry> {
    let p = &s.prepared;
    let a = part(p)?;
    validate_retained_prepared(p)?;
    if s.transaction_hash != p.transaction_hash {
        return Err("Signed transaction identity differs".into());
    }
    let [agent] = s.role_signatures.as_slice() else {
        return Err("A payment authorization holds the agent's signature".into());
    };
    if agent.signer != p.config.agent {
        return Err("The agent's signature names another signer".into());
    }
    signing::verify_digest(&agent.signer, &a.digest, &agent.signature)
        .map_err(|_| "Invalid agent signature of the payment authorization")?;
    let entry = signed_entry(p, a, &signature(&agent.signature)?)?;
    if s.transaction_xdr != payload_transaction(&entry)? {
        return Err("The payment authorization payload differs".into());
    }
    Ok(entry)
}

/// Verify a retained signed authorization. This reads no time and grants nothing.
pub fn validate_signed(s: &SignedOperation) -> Result<()> {
    retained_entry(s).map(drop)
}

/// Whether the transaction of `receipt` carries `entry` in its one invocation.
fn carries(receipt: &rpc::VerifiedReceipt, entry: &SorobanAuthorizationEntry) -> Result<bool> {
    let TransactionEnvelope::Tx(envelope) = read(&receipt.envelope_xdr)? else {
        return Ok(false);
    };
    let [operation] = envelope.tx.operations.as_slice() else {
        return Ok(false);
    };
    let OperationBody::InvokeHostFunction(op) = &operation.body else {
        return Ok(false);
    };
    Ok(op.auth.iter().any(|carried| carried == entry))
}

/// Check that `receipt` is the settlement of `s`: a successful transaction, on the network of
/// the wallet, whose invocation carries the exact signed entry of `s`. The ledger admits that
/// entry once, so one transaction can carry it and succeed.
pub fn validate_settled(s: &SignedOperation, receipt: &rpc::VerifiedReceipt) -> Result<()> {
    let entry = retained_entry(s)?;
    rpc::validate_receipt(
        receipt,
        &s.prepared.config.network,
        &receipt.transaction_hash,
    )?;
    if receipt.settles != Some(s.prepared.transaction_hash)
        || receipt.status != OperationStatus::Confirmed
        || !carries(receipt, &entry)?
    {
        return Err("The receipt does not settle this payment authorization".into());
    }
    Ok(())
}

fn topic(value: &ScVal) -> Result<String> {
    xdr(value)
}

/// The transactions in which the token reported a transfer from the wallet to the payee of
/// `p`, from the ledger of its preparation through the expiry ledger of its entry.
fn transfer_transactions(rpc: &dyn rpc::Rpc, p: &PreparedOperation) -> Result<Vec<[u8; 32]>> {
    let a = part(p)?;
    let c = &p.config;
    let t = retained_transfer(c, &p.request)?;
    let entry: SorobanAuthorizationEntry = read(&a.authorization_xdr)?;
    let SorobanCredentials::Address(credentials) = &entry.credentials else {
        return Err("A payment authorization needs wallet-address authorization".into());
    };
    let last = credentials.signature_expiration_ledger;
    let prefix = [
        topic(&value_symbol("transfer")?)?,
        topic(&ScVal::Address(address(&c.wallet)?))?,
        topic(&ScVal::Address(address(&t.recipient)?))?,
    ];
    // A token reports three topics. An asset contract adds the asset as the fourth.
    let mut with_asset = prefix.to_vec();
    with_asset.push("*".into());
    let mut found = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..8 {
        let mut params = json!({
            "filters": [{"type": "contract", "contractIds": [c.asset], "topics": [prefix, with_asset]}],
            "pagination": {"limit": 200},
        });
        match &cursor {
            Some(cursor) => params["pagination"]["cursor"] = json!(cursor),
            None => params["startLedger"] = json!(p.state.ledger),
        }
        let reply = rpc.call("getEvents", params)?;
        let events = reply["events"].as_array().ok_or("Missing ledger events")?;
        for event in events {
            let ledger = event["ledger"].as_u64().ok_or("Invalid event ledger")?;
            if ledger > u64::from(last) {
                return Ok(found);
            }
            let hash = unhex::<32>(
                event["txHash"]
                    .as_str()
                    .ok_or("Invalid event transaction")?,
            )?;
            if !found.contains(&hash) {
                found.push(hash);
            }
        }
        let next = reply["cursor"].as_str().map(str::to_owned);
        if events.len() < 200 || next.is_none() || next == cursor {
            return Ok(found);
        }
        cursor = next;
    }
    Err("The token reported too many transfers to read this settlement".into())
}

/// A settlement that the ledger shows: the signed entry and the receipt of its transaction.
pub struct Settlement {
    pub signed: SignedOperation,
    pub receipt: rpc::VerifiedReceipt,
}

/// Read the settlement of the authorization of `p` from the ledger. `None` means that the
/// wallet has executed no operation of this id: the entry is open or lapsed, and
/// [`rpc::operation_lapsed`] proves a lapse. The wallet's own receipt under the operation id
/// shows that the entry settled; the token's transfer event then names the transaction, and
/// the transaction must carry the wallet's entry of `p` with both signatures.
pub fn settlement(rpc: &dyn rpc::Rpc, p: &PreparedOperation) -> Result<Option<Settlement>> {
    let a = part(p)?;
    validate_retained_prepared(p)?;
    let Some(executed) = rpc::operation_receipt(rpc, &p.config, &p.request.operation.nonce)? else {
        return Ok(None);
    };
    if executed.transfer != rpc::expected_receipt(p)? {
        return Err("The wallet executed another operation under this id".into());
    }
    let unsigned: SorobanAuthorizationEntry = read(&a.authorization_xdr)?;
    for hash in transfer_transactions(rpc, p)? {
        let Some(mut receipt) = rpc::receipt_by_hash(rpc, &p.config.network, &hash)? else {
            continue;
        };
        if receipt.status != OperationStatus::Confirmed {
            continue;
        }
        let TransactionEnvelope::Tx(envelope) = read(&receipt.envelope_xdr)? else {
            continue;
        };
        let Some(OperationBody::InvokeHostFunction(op)) =
            envelope.tx.operations.first().map(|op| &op.body)
        else {
            continue;
        };
        // The entry of this operation, whatever its signature: the nonce binds it.
        let Some(carried) = op.auth.iter().find(|carried| {
            let mut bare = (*carried).clone();
            if let SorobanCredentials::Address(credentials) = &mut bare.credentials {
                credentials.signature = ScVal::Void;
            }
            bare == unsigned
        }) else {
            continue;
        };
        let SorobanCredentials::Address(credentials) = &carried.credentials else {
            continue;
        };
        let ScVal::Bytes(agent_signature) =
            rpc::map_field(&credentials.signature, "agent_signature")?
        else {
            return Err("The settled entry holds no agent signature".into());
        };
        let signed = SignedOperation {
            prepared: p.clone(),
            transaction_xdr: payload_transaction(carried)?,
            transaction_hash: p.transaction_hash,
            role_signatures: vec![DetachedSignature {
                signer: p.config.agent.clone(),
                signature: agent_signature.to_vec(),
            }],
        };
        receipt.settles = Some(p.transaction_hash);
        validate_settled(&signed, &receipt)?;
        return Ok(Some(Settlement { signed, receipt }));
    }
    Err(
        "The wallet executed this payment, and the ledger events no longer name its transaction"
            .into(),
    )
}
