//! Payment authorizations that the seller settles: the x402 `exact` scheme.
//!
//! A seller's challenge of the `exact` scheme asks the payer for one signed Soroban
//! authorization entry: `transfer(from, payTo, amount)` on the token contract, with a nonce
//! and an expiry ledger. The seller's facilitator puts the entry into its own transaction,
//! pays the network fee and submits it. The payer signs no transaction and pays no fee.
//!
//! Here such a payment is an ordinary operation with one difference: who submits it. The
//! request names the same transfer, carries no fee bound and holds [`marker`]. Preparation
//! prepares that transfer as the wallet would execute it itself, so the same policy checks
//! decide on it as on any payment, and then adds a [`PaymentAuthorization`]: the entry of
//! exactly that transfer and the digest that the agent and the service sign. Nothing else can
//! be done with the entry: it names the token, the payer, the payee and the amount, the
//! ledger consumes its nonce once, and it expires.
//!
//! The service sends nothing. It reads the outcome from the ledger: the token's transfer
//! events from the wallet to the payee, through the expiry ledger of the entry, name the
//! transaction that carries the entry, or show that none does.
//!
//! Only a keypair wallet signs such an entry. It is a classic account: the agent and the
//! service each sign the host payload of the entry, and the entry holds both account
//! signatures. Their weights reach the account's medium threshold only together.
//!
//! A policy wallet signs none. Its contract can check such an authorization against the
//! agent's and the service's raw keys, but the check costs a network fee far above the fee
//! ceiling of a seller's facilitator, which then refuses the payment. A policy wallet pays a
//! seller that takes the proof of a settled transaction.
use crate::workflow::{
    Chain, EvidenceKind, EvidenceRef, WorkflowAsset, WorkflowEffectBound, WorkflowFeeBound,
};
use crate::*;
use serde_json::json;

/// The longest validity of an entry, in ledgers.
pub const MAX_LEDGERS: u32 = 64;
/// The ledger time that bounds the entry's expiry ledger. A facilitator admits an expiry of
/// at most the seller's timeout divided by its own estimate of the ledger time, which is 5 or
/// 6 seconds. The longer time gives the earlier ledger, which both estimates admit.
pub const LEDGER_SECONDS: u64 = 6;
/// The fault of a wallet that signs no payment authorization. It names the fix: the wallet
/// kind that signs one.
pub const POLICY_WALLET: &str = "A policy wallet signs no payment authorization for a seller's facilitator: the network fee of an authorization that its contract checks is far above the fee ceiling of a seller's facilitator, so the facilitator refuses it. Use a Native wallet to pay this seller: it signs the authorization, and the seller's facilitator pays the network fee. A policy wallet pays a seller that takes the proof of a settled transaction.";
/// The fault of a policy whose decision depends on a time that an authorization can outlive.
pub const TIME_LIMIT: &str = "This policy allows the payment only until a time that is less than one day after the request expires. A payment authorization expires at a ledger, which can close after that time, so this wallet signs none now. It pays a seller that takes the proof of a settled transaction.";
/// How far past the expiry of its operation, in seconds, the policy must still allow a
/// payment authorization.
///
/// The ledger binds an authorization entry to an expiry ledger, not to a time. Ledgers that
/// close more slowly than [`LEDGER_SECONDS`], or a halted network, close that ledger after
/// the expiry of the operation, and no part of the entry can stop the transfer then. So the
/// policy is asked again for an operation that expires this much later: a time limit of the
/// policy that falls inside the margin refuses the authorization. A network that stops for
/// longer than the margin is outside this bound.
pub const EXPIRY_MARGIN: u64 = 86_400;
/// The fault of an authorization that could settle on the day after its limits count it.
pub const DAY_END: &str = "A payment authorization is not signed in the last minutes of the UTC day: it expires at a ledger, which can close on the next day, and the daily limits count it today. Retry after 00:00 UTC, or pay a seller that takes the proof of a settled transaction.";
/// How long before the end of the UTC day, in seconds, the operation of a payment
/// authorization must expire. The limits count a payment in the day of its preparation, and
/// the wallet's own transaction cannot be included after that day. An authorization entry
/// has no such bound: its expiry ledger can close late. This margin keeps the entry inside
/// the day while ledgers close within it. A network that stops for longer is outside this
/// bound, like [`EXPIRY_MARGIN`]; the harm is then one payment counted in the day before.
pub const DAY_MARGIN: u64 = 600;
/// The fault of a payee that a payment authorization cannot pay.
pub const CONTRACT_PAYEE: &str = "A payment authorization pays an account. The payee of this seller is a contract address, which this wallet does not pay.";
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

/// Whether the wallet of `c` signs a payment authorization. This is the one place that decides
/// it by wallet kind; every other part of the module asks here.
///
/// A keypair wallet signs: its entry carries the account signatures of the agent and the
/// service ([`signed_entry`]). A policy wallet signs none today, see [`POLICY_WALLET`]. An
/// authorization form of a policy wallet has two places to fill: this function admits its
/// kind, and [`signed_entry`] produces the signature that its contract checks.
pub fn signs(c: &WalletConfig) -> Result<()> {
    match c.route {
        WalletRoute::Native => Ok(()),
        _ => Err(POLICY_WALLET.into()),
    }
}

/// The same transfer in the shape of an ordinary request, for decoding alone: the fee bound
/// names the wallet and pays nothing.
fn shaped(c: &WalletConfig, r: &ExecutionRequest) -> Result<ExecutionRequest> {
    if !is_request(r) {
        return Err("The request asks for no payment authorization".into());
    }
    signs(c)?;
    let mut out = r.clone();
    out.evidence.clear();
    out.fee_bounds = Some(vec![WorkflowFeeBound {
        payer: request::account(&c.wallet)?,
        asset: WorkflowAsset::Native {
            chain: Chain::Stellar,
            network: network_id(&c.network)?,
        },
        max_fee: u64::from(c.max_fee_stroops).into(),
    }]);
    Ok(out)
}

/// The transfer that a request for a payment authorization names. Its payee is an account:
/// the wallet's own payment, which carries the policy decision, pays no contract.
pub fn transfer(c: &WalletConfig, r: &ExecutionRequest) -> Result<Transfer> {
    let t = transfer_from_request(c, &shaped(c, r)?)?;
    if account_key(&t.recipient).is_err() {
        return Err(CONTRACT_PAYEE.into());
    }
    Ok(t)
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
    /// The unsigned authorization entry of the wallet for exactly the transfer.
    pub authorization_xdr: String,
    /// What the agent and the service sign: the host payload of the entry.
    pub digest: [u8; 32],
}

/// The request that the agent sent for `p`: the authorization request, or the operation's.
pub fn intent(p: &PreparedOperation) -> &ExecutionRequest {
    p.payment_authorization
        .as_deref()
        .map_or(&p.request, |a| &a.request)
}

/// What a role signs for `p`: the digest of its payment authorization, or the hash of its
/// transaction.
pub fn signing_hash(p: &PreparedOperation) -> [u8; 32] {
    p.payment_authorization
        .as_deref()
        .map_or(p.transaction_hash, |a| a.digest)
}

fn part(p: &PreparedOperation) -> Result<&PaymentAuthorization> {
    p.payment_authorization
        .as_deref()
        .ok_or_else(|| "The operation is no payment authorization".into())
}

/// The unsigned entry of `p`: the wallet account authorizes
/// `transfer(wallet, recipient, amount)` on the contract of its asset. The nonce derives from
/// the operation id, so one request ID has one entry. The expiry ledger follows the validity
/// of the operation.
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
                contract_address: address(&sac_address(&c.network, &asset_xdr(c)?)?)?,
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

fn signature(bytes: &[u8]) -> Result<[u8; 64]> {
    bytes
        .try_into()
        .map_err(|_| "Invalid signature length".into())
}

/// Check the retained authorization part of `p` against the operation around it. Every field
/// is rebuilt: the request names the operation's transfer under its operation id, the entry
/// is the one entry of that transfer, and the digest is its host payload. This reads no time
/// and grants nothing.
pub fn validate(p: &PreparedOperation) -> Result<()> {
    let a = part(p)?;
    let c = &p.config;
    signs(c)?;
    if !is_request(&a.request)
        || a.request.operation != p.request.operation
        || retained_transfer(c, &shaped(c, &a.request)?)? != retained_transfer(c, &p.request)?
    {
        return Err("The payment authorization names another operation".into());
    }
    let entry = entry(p)?;
    if a.authorization_xdr != xdr(&entry)?
        || a.digest != authorization::payload(&c.network, &entry)?
    {
        return Err("The payment authorization differs from its operation".into());
    }
    Ok(())
}

/// Admit `p` for a new signature at `now`: the packet is whole and unexpired, the wallet
/// account has exactly its roles, weights and thresholds, and the host policy check of an
/// operation holds.
pub fn admit(p: &PreparedOperation, now: u64) -> Result<[u8; 32]> {
    let a = part(p)?;
    validate_retained_prepared(p)?;
    if p.version != 1 || p.created_at > now || now >= p.expires_at {
        return Err("Prepared operation is stale".into());
    }
    p.state.source.validate_wallet(&p.config)?;
    verify_operation(
        &p.config,
        &p.request,
        &p.terms,
        &p.state,
        p.created_at,
        p.expires_at,
        None,
    )?;
    // The entry stays inside the UTC day that the limits count it in: see `DAY_MARGIN`.
    let day_end = (p.created_at / allowit_core::DAY + 1) * allowit_core::DAY;
    if p.expires_at.saturating_add(DAY_MARGIN) > day_end {
        return Err(DAY_END.into());
    }
    admit_later(p, None)?;
    Ok(a.digest)
}

/// The decision of the policy for the operation of `p` expiring a margin later: see
/// [`EXPIRY_MARGIN`]. `evaluator` is the compiled evaluator of a source that the server
/// evaluates; without it only the part that the rail evaluates itself decides, as in the
/// admission of the operation.
pub fn admit_later(
    p: &PreparedOperation,
    evaluator: Option<policy::PortableEvaluator>,
) -> Result<()> {
    part(p)?;
    let later = p
        .expires_at
        .checked_add(EXPIRY_MARGIN)
        .ok_or("Invalid operation validity")?;
    verify_operation(
        &p.config,
        &p.request,
        &p.terms,
        &p.state,
        p.created_at,
        later,
        evaluator,
    )
    .map_err(|_| TIME_LIMIT)?;
    Ok(())
}

/// Prepare the payment authorization of `r`. The same transfer is first prepared as the
/// wallet would execute it itself, which runs the host policy check against the wallet's
/// accounting. The authorization part is then derived from it.
pub fn prepare(
    rpc: &dyn rpc::Rpc,
    c: &WalletConfig,
    r: &ExecutionRequest,
    terms: &ExecutionTerms,
    accounting: Option<rpc::NativeAccounting>,
    now: u64,
    expires_at: u64,
) -> Result<PreparedOperation> {
    let t = transfer(c, r)?;
    let found = rpc::trusted_state_for_discovery(rpc, c, accounting.clone())?;
    if found.paused {
        return Err("This wallet is paused: its owner removed the agent signer".into());
    }
    let ordinary = request::transfer(c, &found.state, r.operation.nonce, &t.recipient, t.amount)?;
    let p = rpc::prepare_with(rpc, c, &ordinary, terms, accounting, now, expires_at)?;
    attach(p, r, now)
}

/// Add the authorization part of the request `r` to `p`, the same transfer prepared for the
/// wallet's own execution, and admit the result at `now`.
pub fn attach(
    mut p: PreparedOperation,
    r: &ExecutionRequest,
    now: u64,
) -> Result<PreparedOperation> {
    if p.payment_authorization.is_some() {
        return Err("The operation is already a payment authorization".into());
    }
    signs(&p.config)?;
    let entry = entry(&p)?;
    p.payment_authorization = Some(Box::new(PaymentAuthorization {
        request: r.clone(),
        authorization_xdr: xdr(&entry)?,
        digest: authorization::payload(&p.config.network, &entry)?,
    }));
    admit(&p, now)?;
    Ok(p)
}

/// How many ledgers the ledger of a preparation may be ahead of the signer's own ledger read:
/// two endpoints do not close a ledger at the same moment.
pub const LEDGER_AHEAD: u32 = 5;

/// Check the ledger that `p` names against the signer's own read of the network. The expiry
/// ledger of the entry counts from the ledger of the preparation, and the party that prepared
/// `p` states that ledger. A later one would make the entry valid for longer than its
/// operation, so a ledger that the network has not closed is refused before a signature.
pub fn current_ledger(rpc: &dyn rpc::Rpc, p: &PreparedOperation) -> Result<()> {
    part(p)?;
    let latest = rpc.call("getLatestLedger", json!({}))?["sequence"]
        .as_u64()
        .ok_or("Missing ledger sequence")?;
    if u64::from(p.state.ledger) > latest + u64::from(LEDGER_AHEAD) {
        return Err(
            "The payment authorization counts its expiry from a ledger that the network has not closed"
                .into(),
        );
    }
    Ok(())
}

/// Check `p` against the wallet account as the ledger shows it now: the same signers,
/// weights, thresholds and sequence as at the preparation. Another state means that the
/// entry may no longer settle as it was decided.
pub fn revalidate(rpc: &dyn rpc::Rpc, p: &PreparedOperation, now: u64) -> Result<()> {
    admit(p, now)?;
    current_ledger(rpc, p)?;
    let current = rpc::get_account(rpc, &p.config.wallet)?;
    current.validate_roles(&p.config.owner, &p.config.agent, &p.config.server)?;
    if current != p.state.source {
        return Err("The wallet changed since this payment authorization was prepared".into());
    }
    Ok(())
}

/// A role's signature of the digest of `p`, after the admission of [`admit`]. The agent and
/// the service both sign here, each with its own key.
pub fn sign(
    p: &PreparedOperation,
    signer: &str,
    now: u64,
    sign_hash: impl FnOnce(&[u8; 32]) -> Result<[u8; 64]>,
) -> Result<DetachedSignature> {
    let digest = admit(p, now)?;
    if signer != p.config.agent && signer != p.config.server {
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
/// sequence number and the fee, so nothing here pays or can be submitted as it is. Its time
/// bound ends with the validity of the operation: a facilitator reads the transaction with
/// tools that require one.
fn payload_transaction(p: &PreparedOperation, entry: &SorobanAuthorizationEntry) -> Result<String> {
    let SorobanAuthorizedFunction::ContractFn(call) = &entry.root_invocation.function else {
        return Err("A payment authorization invokes one contract".into());
    };
    let tx = Transaction {
        source_account: MuxedAccount::Ed25519(Uint256([0; 32])),
        fee: PAYLOAD_FEE,
        seq_num: SequenceNumber(1),
        cond: Preconditions::Time(TimeBounds {
            min_time: TimePoint(0),
            max_time: TimePoint(p.expires_at),
        }),
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

/// The roles that sign a payment authorization, in role order: the agent, then the service.
fn roles(c: &WalletConfig) -> [&str; 2] {
    [c.agent.as_str(), c.server.as_str()]
}

/// Check `signatures` against the roles of `p`: one valid signature of the digest per role,
/// in role order.
fn role_signatures(
    p: &PreparedOperation,
    a: &PaymentAuthorization,
    signatures: &[DetachedSignature],
) -> Result<[[u8; 64]; 2]> {
    let roles = roles(&p.config);
    let [agent, server] = signatures else {
        return Err("The agent and the service must each sign the payment authorization".into());
    };
    if roles[0] == roles[1] || agent.signer != roles[0] || server.signer != roles[1] {
        return Err("A role signature names another signer".into());
    }
    for proof in [agent, server] {
        signing::verify_digest(&proof.signer, &a.digest, &proof.signature)
            .map_err(|_| "Invalid role signature of the payment authorization")?;
    }
    Ok([signature(&agent.signature)?, signature(&server.signature)?])
}

/// The signed entry of `p`: the entry with the account signatures of the agent and the
/// service, in the order of their public keys.
///
/// This is the one function that produces the signature of a payment authorization. The
/// signature of another wallet kind, which [`signs`] would admit first, is produced here.
fn signed_entry(
    p: &PreparedOperation,
    a: &PaymentAuthorization,
    signatures: &[[u8; 64]; 2],
) -> Result<SorobanAuthorizationEntry> {
    let c = &p.config;
    let mut entry: SorobanAuthorizationEntry = read(&a.authorization_xdr)?;
    let SorobanCredentials::Address(credentials) = &mut entry.credentials else {
        return Err("A payment authorization needs wallet-address authorization".into());
    };
    let mut signers = [
        (account_key(&c.agent)?, &signatures[0]),
        (account_key(&c.server)?, &signatures[1]),
    ];
    signers.sort_by_key(|(key, _)| *key);
    credentials.signature = ScVal::Vec(Some(
        signers
            .iter()
            .map(|(key, signature)| {
                value_map(vec![
                    ("public_key", value_bytes(key)?),
                    ("signature", value_bytes(*signature)?),
                ])
            })
            .collect::<Result<Vec<_>>>()?
            .try_into()
            .map_err(err)?,
    ));
    Ok(entry)
}

/// Assemble the signed authorization of `p` from the signatures of the agent and the
/// service. Each signature is verified against the digest and its role.
pub fn assemble(
    p: &PreparedOperation,
    signatures: &[DetachedSignature],
    now: u64,
) -> Result<SignedOperation> {
    let a = part(p)?;
    admit(p, now)?;
    let entry = signed_entry(p, a, &role_signatures(p, a, signatures)?)?;
    let signed = SignedOperation {
        prepared: p.clone(),
        transaction_xdr: payload_transaction(p, &entry)?,
        transaction_hash: p.transaction_hash,
        role_signatures: signatures.to_vec(),
    };
    validate_signed(&signed)?;
    Ok(signed)
}

/// Assemble the signed authorization and check it against the ledger: the wallet account is
/// as the preparation read it, and the enforce-mode simulation of the payload passes the
/// account's signature check with both signatures. An entry that the ledger refuses is not
/// released to the seller.
pub fn authorize(
    rpc: &dyn rpc::Rpc,
    p: &PreparedOperation,
    signatures: &[DetachedSignature],
    now: u64,
) -> Result<SignedOperation> {
    revalidate(rpc, p, now)?;
    let signed = assemble(p, signatures, now)?;
    let simulated = rpc.call(
        "simulateTransaction",
        json!({"transaction": signed.transaction_xdr, "authMode": "enforce"}),
    )?;
    if simulated.get("error").is_some_and(|value| !value.is_null()) {
        return Err("The ledger refuses this payment authorization".into());
    }
    rpc::reject_restoration(&simulated)?;
    Ok(signed)
}

/// The signed entry that `s` carries, after checking the whole retained packet: the
/// preparation, each role's signature of its digest, and a payload that is exactly the
/// transaction of the signed entry.
fn retained_entry(s: &SignedOperation) -> Result<SorobanAuthorizationEntry> {
    let p = &s.prepared;
    let a = part(p)?;
    validate_retained_prepared(p)?;
    if s.transaction_hash != p.transaction_hash {
        return Err("Signed transaction identity differs".into());
    }
    let entry = signed_entry(p, a, &role_signatures(p, a, &s.role_signatures)?)?;
    if s.transaction_xdr != payload_transaction(p, &entry)? {
        return Err("The payment authorization payload differs".into());
    }
    Ok(entry)
}

/// Verify a retained signed authorization. This reads no time and grants nothing.
pub fn validate_signed(s: &SignedOperation) -> Result<()> {
    retained_entry(s).map(drop)
}

/// The seller's bound on the time from an authorization to its settlement, in seconds, when
/// its requirement states none. The payer and the settlement service use the same value.
pub const DEFAULT_SETTLE_WITHIN: u64 = 60;

/// The one invocation of `receipt`'s transaction. A fee bump carries the transaction that it
/// pays for.
fn invocation(receipt: &rpc::VerifiedReceipt) -> Result<Option<InvokeHostFunctionOp>> {
    let operations = match read::<TransactionEnvelope>(&receipt.envelope_xdr)? {
        TransactionEnvelope::Tx(envelope) => envelope.tx.operations,
        TransactionEnvelope::TxFeeBump(envelope) => {
            let FeeBumpTransactionInnerTx::Tx(inner) = envelope.tx.inner_tx;
            inner.tx.operations
        }
        TransactionEnvelope::TxV0(_) => return Ok(None),
    };
    let [operation] = operations.as_slice() else {
        return Ok(None);
    };
    let OperationBody::InvokeHostFunction(op) = &operation.body else {
        return Ok(None);
    };
    Ok(Some(op.clone()))
}

/// The authorization entries of the one invocation of `receipt`'s transaction.
fn carried(receipt: &rpc::VerifiedReceipt) -> Result<Vec<SorobanAuthorizationEntry>> {
    Ok(invocation(receipt)?.map_or_else(Vec::new, |op| op.auth.to_vec()))
}

/// Whether the transaction of `receipt` executes `entry` when it succeeds. The ledger admits
/// an entry that no call uses and leaves its nonce unspent, so the presence of the entry
/// proves nothing. The transaction executes it when its one invocation is the call that the
/// entry authorizes and the entry is its only authorization: the token then asks the wallet
/// for exactly this entry.
fn executes(receipt: &rpc::VerifiedReceipt, entry: &SorobanAuthorizationEntry) -> Result<bool> {
    let Some(op) = invocation(receipt)? else {
        return Ok(false);
    };
    let HostFunction::InvokeContract(call) = &op.host_function else {
        return Ok(false);
    };
    if !matches!(&entry.credentials, SorobanCredentials::Address(_)) {
        return Ok(false);
    }
    // The entry is the only authorization of the transaction: with any other entry, of any
    // credential kind, another authorization could have admitted the transfer and left this
    // one unspent.
    Ok(op.auth.as_slice() == std::slice::from_ref(entry)
        && entry.root_invocation.sub_invocations.is_empty()
        && entry.root_invocation.function == SorobanAuthorizedFunction::ContractFn(call.clone()))
}

/// Check that `receipt` is the settlement of `s`: a successful transaction, on the network of
/// the wallet, whose one invocation is the transfer that the exact signed entry of `s`
/// authorizes. The ledger admits that entry once, so one such transaction can succeed.
pub fn validate_settled(s: &SignedOperation, receipt: &rpc::VerifiedReceipt) -> Result<()> {
    let entry = retained_entry(s)?;
    rpc::validate_receipt(
        receipt,
        &s.prepared.config.network,
        &receipt.transaction_hash,
    )?;
    if receipt.settles != Some(s.prepared.transaction_hash)
        || receipt.status != OperationStatus::Confirmed
        || !executes(receipt, &entry)?
    {
        return Err("The receipt does not settle this payment authorization".into());
    }
    Ok(())
}

/// The expiry ledger of the entry of `a`: the last ledger in which it can settle.
fn expiry_ledger(a: &PaymentAuthorization) -> Result<u32> {
    let entry: SorobanAuthorizationEntry = read(&a.authorization_xdr)?;
    let SorobanCredentials::Address(credentials) = &entry.credentials else {
        return Err("A payment authorization needs wallet-address authorization".into());
    };
    Ok(credentials.signature_expiration_ledger)
}

/// What the token's transfer events show for the entry of `p`.
struct Transfers {
    /// The transactions in which the token reported a transfer from the wallet to the payee,
    /// from the ledger of the preparation through the expiry ledger of the entry.
    transactions: Vec<[u8; 32]>,
    /// The events cover every ledger through the expiry ledger: the read reached an event
    /// after it, or an empty page whose cursor is at that ledger or after it.
    complete: bool,
}

fn transfers(rpc: &dyn rpc::Rpc, p: &PreparedOperation) -> Result<Transfers> {
    let a = part(p)?;
    let c = &p.config;
    let t = retained_transfer(c, &p.request)?;
    let last = u64::from(expiry_ledger(a)?);
    let prefix = [
        xdr(&value_symbol("transfer")?)?,
        xdr(&ScVal::Address(address(&c.wallet)?))?,
        xdr(&ScVal::Address(address(&t.recipient)?))?,
    ];
    // A token reports three topics. An asset contract adds the asset as the fourth.
    let mut with_asset = prefix.to_vec();
    with_asset.push("*".into());
    let token = sac_address(&c.network, &asset_xdr(c)?)?;
    let mut transactions = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..16 {
        let mut params = json!({
            "filters": [{"type": "contract", "contractIds": [token], "topics": [prefix, with_asset]}],
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
            if ledger > last {
                return Ok(Transfers {
                    transactions,
                    complete: true,
                });
            }
            let hash = unhex::<32>(
                event["txHash"]
                    .as_str()
                    .ok_or("Invalid event transaction")?,
            )?;
            if !transactions.contains(&hash) {
                transactions.push(hash);
            }
        }
        let next = reply["cursor"].as_str().map(str::to_owned);
        // A page can end before the endpoint's limit, so only an empty page ends the read. Its
        // cursor names the last ledger that the endpoint scanned: the read is complete when
        // that ledger is the expiry ledger or a later one. The head of the endpoint says
        // nothing about how far a page scanned.
        if events.is_empty() {
            let scanned = next.as_deref().and_then(cursor_ledger);
            return Ok(Transfers {
                transactions,
                complete: scanned.is_some_and(|ledger| ledger >= last),
            });
        }
        // A page with events and no way forward leaves the rest unread.
        if next.is_none() || next == cursor {
            return Ok(Transfers {
                transactions,
                complete: false,
            });
        }
        cursor = next;
    }
    Err("The token reported too many transfers to read this settlement".into())
}

/// The ledger of an event cursor: `<id>-<index>`, where the id holds the ledger in its high
/// 32 bits.
fn cursor_ledger(cursor: &str) -> Option<u64> {
    let (id, _) = cursor.split_once('-')?;
    Some(id.parse::<u64>().ok()? >> 32)
}

/// A settlement that the ledger shows: the signed entry and the receipt of its transaction.
pub struct Settlement {
    pub signed: SignedOperation,
    pub receipt: rpc::VerifiedReceipt,
}

/// What the ledger shows of the authorization of `p`.
pub enum Observed {
    /// A successful transaction carries the entry.
    Settled(Box<Settlement>),
    /// The entry did not settle and can no longer settle: its expiry ledger passed, and no
    /// transaction of the token's transfers through that ledger carries it.
    Lapsed,
    /// Neither is established.
    Open,
}

/// The role signatures of the entry `found` on the ledger, in role order.
fn carried_signatures(
    c: &WalletConfig,
    found: &SorobanAuthorizationEntry,
) -> Result<Vec<DetachedSignature>> {
    let SorobanCredentials::Address(credentials) = &found.credentials else {
        return Err("The settled entry is no address authorization".into());
    };
    let ScVal::Vec(Some(signers)) = &credentials.signature else {
        return Err("The settled entry holds no account signatures".into());
    };
    roles(c)
        .into_iter()
        .map(|role| {
            let key = value_bytes(&account_key(role)?)?;
            let signer = signers
                .iter()
                .find(|signer| rpc::map_field(signer, "public_key").ok() == Some(&key))
                .ok_or("The settled entry lacks a role signature")?;
            let ScVal::Bytes(bytes) = rpc::map_field(signer, "signature")? else {
                return Err("The settled entry holds an invalid signature".into());
            };
            Ok(DetachedSignature {
                signer: role.to_owned(),
                signature: bytes.to_vec(),
            })
        })
        .collect()
}

/// Read what the ledger shows of the authorization of `p`.
///
/// A classic account keeps no record of the entry, so the token's transfer events from the
/// wallet to the payee are read, from the ledger of the preparation through the expiry ledger
/// of the entry. A successful transaction that carries the wallet's entry of `p`, which the
/// nonce binds, with the signatures of both roles, settled it. A complete read without such a
/// transaction, after the expiry ledger, proves the lapse: a settled entry moved the amount
/// and the token reported it. The read is complete only when the ledger also returned the
/// transaction of every reported transfer.
pub fn observe(rpc: &dyn rpc::Rpc, p: &PreparedOperation) -> Result<Observed> {
    let a = part(p)?;
    validate_retained_prepared(p)?;
    if rpc.call("getNetwork", json!({}))?["passphrase"] != passphrase(&p.config.network)? {
        return Err("Stellar RPC network differs from installation".into());
    }
    let unsigned: SorobanAuthorizationEntry = read(&a.authorization_xdr)?;
    let found = transfers(rpc, p)?;
    // A reported transfer whose transaction cannot be read may be the settlement.
    let mut unread = false;
    for hash in &found.transactions {
        // An event names the transaction that the ledger applied: for a payment that a fee
        // bump carries, that is the wrapper.
        let Some(mut receipt) = rpc::receipt_by_reported_hash(rpc, &p.config.network, hash)? else {
            unread = true;
            continue;
        };
        if receipt.status != OperationStatus::Confirmed {
            continue;
        }
        // The entry of this operation, whatever its signature: the nonce binds it.
        let Some(entry) = carried(&receipt)?.into_iter().find(|entry| {
            let mut bare = entry.clone();
            if let SorobanCredentials::Address(credentials) = &mut bare.credentials {
                credentials.signature = ScVal::Void;
            }
            bare == unsigned
        }) else {
            continue;
        };
        // A transaction that carries the entry in another shape, such as a call of another
        // contract that moves the amount, may have spent it. Its outcome stays open.
        if !executes(&receipt, &entry)? {
            return Ok(Observed::Open);
        }
        let signed = SignedOperation {
            prepared: p.clone(),
            transaction_xdr: payload_transaction(p, &entry)?,
            transaction_hash: p.transaction_hash,
            role_signatures: carried_signatures(&p.config, &entry)?,
        };
        receipt.settles = Some(p.transaction_hash);
        validate_settled(&signed, &receipt)?;
        return Ok(Observed::Settled(Box::new(Settlement { signed, receipt })));
    }
    Ok(if found.complete && !unread {
        Observed::Lapsed
    } else {
        Observed::Open
    })
}

/// The settlement of the authorization of `p`, when the ledger shows it.
pub fn settlement(rpc: &dyn rpc::Rpc, p: &PreparedOperation) -> Result<Option<Settlement>> {
    Ok(match observe(rpc, p)? {
        Observed::Settled(settled) => Some(*settled),
        Observed::Lapsed | Observed::Open => None,
    })
}

/// Whether the authorization of `p` lapsed: it did not settle and can no longer settle.
/// `false` means not proven.
pub fn lapsed(rpc: &dyn rpc::Rpc, p: &PreparedOperation) -> Result<bool> {
    Ok(matches!(observe(rpc, p)?, Observed::Lapsed))
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::test_support;

    const NOW: u64 = 86_401;
    const EXPIRES: u64 = 86_700;
    const AGENT: [u8; 32] = [2; 32];
    const SERVER: [u8; 32] = [3; 32];

    fn signed_by(seed: [u8; 32], p: &PreparedOperation) -> DetachedSignature {
        sign(p, &account_for_seed(&seed), NOW, |digest| {
            Ok(test_support::sign_digest(seed, digest))
        })
        .unwrap()
    }
    /// The transfer that `ordinary` names, as a request for a payment authorization.
    fn authorization_request(ordinary: &PreparedOperation) -> ExecutionRequest {
        let t = transfer_from_request(&ordinary.config, &ordinary.request).unwrap();
        request(
            &ordinary.config,
            ordinary.request.operation.nonce,
            &t.recipient,
            t.amount,
        )
        .unwrap()
    }
    /// A keypair wallet's prepared authorization.
    fn keypair_wallet() -> PreparedOperation {
        let ordinary = test_support::native_signed().prepared;
        assert_eq!(ordinary.config.agent, account_for_seed(&AGENT));
        assert_eq!(ordinary.config.server, account_for_seed(&SERVER));
        let r = authorization_request(&ordinary);
        attach(ordinary, &r, NOW).unwrap()
    }
    fn entry_of(s: &SignedOperation) -> SorobanAuthorizationEntry {
        let TransactionEnvelope::Tx(envelope) = read(&s.transaction_xdr).unwrap() else {
            panic!("the payload is a transaction")
        };
        let OperationBody::InvokeHostFunction(op) = &envelope.tx.operations[0].body else {
            panic!("the payload holds one invocation")
        };
        op.auth[0].clone()
    }

    #[test]
    fn a_request_for_an_authorization_names_the_transfer_and_no_fee_payer() {
        let ordinary = test_support::native_signed().prepared;
        let r = authorization_request(&ordinary);
        assert!(is_request(&r) && !is_request(&ordinary.request));
        assert!(r.fee_bounds.is_none());
        assert_eq!(
            transfer(&ordinary.config, &r).unwrap(),
            transfer_from_request(&ordinary.config, &ordinary.request).unwrap()
        );
        // The ordinary decoder refuses it, and this decoder refuses an ordinary request.
        assert!(operation_from_request(&ordinary.config, &r).is_err());
        assert!(transfer(&ordinary.config, &ordinary.request).is_err());
        // A contract payee is refused when the request is built, before anything is signed.
        let contract = test_support::vault(3);
        assert_eq!(
            request(&ordinary.config, [5; 32], &contract, 1_000)
                .unwrap_err()
                .to_string(),
            CONTRACT_PAYEE
        );
        // Another evidence reference is no marker.
        let mut other = r.clone();
        other.evidence[0].schema += 1;
        assert!(!is_request(&other));
    }

    #[test]
    fn a_keypair_wallet_signs_one_entry_for_exactly_the_transfer() {
        let p = keypair_wallet();
        let a = part(&p).unwrap();
        validate(&p).unwrap();
        let t = transfer_from_request(&p.config, &p.request).unwrap();
        let unsigned: SorobanAuthorizationEntry = read(&a.authorization_xdr).unwrap();
        let SorobanCredentials::Address(credentials) = &unsigned.credentials else {
            panic!("an address authorization")
        };
        // The entry names the wallet, expires within the validity and calls the asset contract.
        assert_eq!(address_text(&credentials.address).unwrap(), p.config.wallet);
        assert_eq!(
            credentials.signature_expiration_ledger,
            p.state.ledger + ((EXPIRES - NOW) / LEDGER_SECONDS) as u32
        );
        let SorobanAuthorizedFunction::ContractFn(call) = &unsigned.root_invocation.function else {
            panic!("a contract call")
        };
        assert_eq!(
            address_text(&call.contract_address).unwrap(),
            sac_address(&p.config.network, &asset_xdr(&p.config).unwrap()).unwrap()
        );
        assert_eq!(call.function_name.0.as_slice(), b"transfer");
        assert_eq!(
            call.args.as_slice(),
            [
                ScVal::Address(address(&p.config.wallet).unwrap()),
                ScVal::Address(address(&t.recipient).unwrap()),
                i128_value(t.amount)
            ]
        );
        assert!(unsigned.root_invocation.sub_invocations.is_empty());
        // The signers sign the host payload of that entry.
        assert_eq!(
            a.digest,
            authorization::payload(&p.config.network, &unsigned).unwrap()
        );
        assert_eq!(signing_hash(&p), a.digest);

        let signatures = [signed_by(AGENT, &p), signed_by(SERVER, &p)];
        let signed = assemble(&p, &signatures, NOW).unwrap();
        validate_signed(&signed).unwrap();
        validate_retained_signed(&signed).unwrap();
        assert_eq!(signed.transaction_hash, p.transaction_hash);
        // The entry holds both account signatures, in the order of the keys.
        let entry = entry_of(&signed);
        let SorobanCredentials::Address(credentials) = &entry.credentials else {
            panic!("an address authorization")
        };
        let ScVal::Vec(Some(signers)) = &credentials.signature else {
            panic!("account signatures")
        };
        let keys: Vec<_> = signers
            .iter()
            .map(|signer| rpc::map_field(signer, "public_key").unwrap().clone())
            .collect();
        let mut sorted = [
            value_bytes(&account_key(&p.config.agent).unwrap()).unwrap(),
            value_bytes(&account_key(&p.config.server).unwrap()).unwrap(),
        ];
        sorted.sort();
        assert_eq!(keys, sorted);
        // The payload is no transaction of the wallet: another source, and no signature.
        let TransactionEnvelope::Tx(envelope) = read(&signed.transaction_xdr).unwrap() else {
            panic!("a transaction")
        };
        assert!(envelope.signatures.is_empty());
        assert_ne!(
            envelope.tx.source_account,
            MuxedAccount::Ed25519(Uint256(account_key(&p.config.wallet).unwrap()))
        );
        // The payer never sends it.
        assert!(rpc::broadcast(&Unreachable, &signed, NOW).is_err());
        assert!(authorize(&p, &signatures, NOW).is_err());
    }

    #[test]
    fn a_keypair_wallet_needs_both_roles_once_and_in_order() {
        let p = keypair_wallet();
        let (agent, server) = (signed_by(AGENT, &p), signed_by(SERVER, &p));
        for signatures in [
            vec![agent.clone()],
            vec![server.clone(), agent.clone()],
            vec![agent.clone(), agent.clone()],
            vec![agent.clone(), server.clone(), server.clone()],
        ] {
            assert!(assemble(&p, &signatures, NOW).is_err());
        }
        // A signature of another digest, and a signature that names another signer.
        let mut forged = server.clone();
        forged.signature = test_support::sign_digest(SERVER, &[9; 32]).to_vec();
        assert!(assemble(&p, &[agent.clone(), forged], NOW).is_err());
        let mut renamed = server.clone();
        renamed.signer = account_for_seed(&[4; 32]);
        assert!(assemble(&p, &[agent.clone(), renamed], NOW).is_err());
        // Another key has no role.
        assert!(
            sign(&p, &account_for_seed(&[4; 32]), NOW, |digest| Ok(
                test_support::sign_digest([4; 32], digest)
            ))
            .is_err()
        );
        // After the validity nothing is signed or assembled.
        assert!(
            sign(&p, &p.config.agent, EXPIRES, |digest| Ok(
                test_support::sign_digest(AGENT, digest)
            ))
            .is_err()
        );
        assert!(assemble(&p, &[agent, server], EXPIRES).is_err());
    }

    #[test]
    fn a_policy_wallet_signs_no_payment_authorization() {
        let ordinary = test_support::policy_signed().prepared;
        // Neither the request nor the part is built for it, and a part put on it is refused.
        let t = transfer_from_request(&ordinary.config, &ordinary.request).unwrap();
        assert_eq!(
            request(
                &ordinary.config,
                ordinary.request.operation.nonce,
                &t.recipient,
                t.amount
            )
            .unwrap_err(),
            POLICY_WALLET
        );
        let r = authorization_request(&test_support::native_signed().prepared);
        assert_eq!(
            attach(ordinary.clone(), &r, NOW).unwrap_err(),
            POLICY_WALLET
        );
        let mut forged = ordinary;
        forged.payment_authorization = keypair_wallet().payment_authorization;
        assert_eq!(validate(&forged).unwrap_err(), POLICY_WALLET);
        assert!(validate_retained_prepared(&forged).is_err());
    }

    #[test]
    fn a_changed_authorization_part_is_refused() {
        {
            let p = keypair_wallet();
            let change = |change: &dyn Fn(&mut PaymentAuthorization)| {
                let mut changed = p.clone();
                change(changed.payment_authorization.as_mut().unwrap());
                assert!(validate(&changed).is_err());
                assert!(validate_retained_prepared(&changed).is_err());
                assert!(validate_prepared(&changed, NOW).is_err());
            };
            // Another payee or amount in the agent's request, another entry, digest or terms.
            change(&|a| a.request.effect_bounds[0].max_debit = 1u64.into());
            change(&|a| a.request.operation.nonce = [9; 32]);
            change(&|a| a.request.evidence.clear());
            change(&|a| a.digest = [1; 32]);
            change(&|a| {
                let mut entry: SorobanAuthorizationEntry = read(&a.authorization_xdr).unwrap();
                let SorobanCredentials::Address(credentials) = &mut entry.credentials else {
                    panic!("an address authorization")
                };
                credentials.signature_expiration_ledger += 1;
                a.authorization_xdr = xdr(&entry).unwrap();
            });
            change(&|a| {
                let mut entry: SorobanAuthorizationEntry = read(&a.authorization_xdr).unwrap();
                let SorobanAuthorizedFunction::ContractFn(call) =
                    &mut entry.root_invocation.function
                else {
                    panic!("a contract call")
                };
                let mut args = call.args.to_vec();
                args[2] = i128_value(i128::MAX);
                call.args = args.try_into().unwrap();
                a.authorization_xdr = xdr(&entry).unwrap();
            });
            // The operation around it cannot change either: the part binds its transfer.
            let mut moved = p.clone();
            moved.expires_at += 1;
            assert!(validate_retained_prepared(&moved).is_err());
        }
    }

    #[test]
    fn a_signed_authorization_with_another_payload_or_signature_is_refused() {
        let p = keypair_wallet();
        let signed = assemble(&p, &[signed_by(AGENT, &p), signed_by(SERVER, &p)], NOW).unwrap();
        let mut other = signed.clone();
        other.transaction_xdr = test_support::native_signed().transaction_xdr;
        assert!(validate_signed(&other).is_err());
        let mut other = signed.clone();
        other.transaction_hash = [1; 32];
        assert!(validate_signed(&other).is_err());
        let mut other = signed.clone();
        other.role_signatures.pop();
        assert!(validate_signed(&other).is_err());
        // An ordinary signed operation is no authorization, and the reverse.
        assert!(validate_signed(&test_support::native_signed()).is_err());
        assert!(crate::authorize(&p, &signed.role_signatures, NOW).is_err());
    }

    #[test]
    fn a_receipt_settles_an_authorization_only_when_its_transaction_carries_the_entry() {
        let p = keypair_wallet();
        let signed = assemble(&p, &[signed_by(AGENT, &p), signed_by(SERVER, &p)], NOW).unwrap();
        // The facilitator's transaction: its own source, the same invocation and entry.
        let TransactionEnvelope::Tx(mut envelope) = read(&signed.transaction_xdr).unwrap() else {
            panic!("a transaction")
        };
        envelope.tx.source_account = MuxedAccount::Ed25519(Uint256([6; 32]));
        envelope.tx.seq_num = SequenceNumber(77);
        let settling = |envelope: &TransactionV1Envelope, success: bool| {
            let result = TransactionResult {
                fee_charged: 12_345,
                result: if success {
                    TransactionResultResult::TxSuccess(VecM::default())
                } else {
                    TransactionResultResult::TxFailed(VecM::default())
                },
                ext: TransactionResultExt::V0,
            };
            rpc::VerifiedReceipt {
                transaction_hash: transaction_hash(&p.config.network, &envelope.tx).unwrap(),
                status: if success {
                    OperationStatus::Confirmed
                } else {
                    OperationStatus::Failed
                },
                ledger: 130,
                envelope_xdr: xdr(&TransactionEnvelope::Tx(envelope.clone())).unwrap(),
                result_xdr: xdr(&result).unwrap(),
                settles: Some(p.transaction_hash),
                closed_at: None,
            }
        };
        let receipt = settling(&envelope, true);
        validate_settled(&signed, &receipt).unwrap();
        rpc::validate_settled_policy_packet(&signed, &receipt).unwrap();
        // A failed transaction, a receipt of another authorization and a transaction with
        // another entry settle nothing.
        assert!(validate_settled(&signed, &settling(&envelope, false)).is_err());
        let mut other = receipt.clone();
        other.settles = Some([1; 32]);
        assert!(validate_settled(&signed, &other).is_err());
        other.settles = None;
        assert!(validate_settled(&signed, &other).is_err());
        let mut without = envelope.clone();
        let mut operations = without.tx.operations.to_vec();
        let OperationBody::InvokeHostFunction(op) = &mut operations[0].body else {
            panic!("an invocation")
        };
        op.auth = VecM::default();
        without.tx.operations = operations.try_into().unwrap();
        assert!(validate_settled(&signed, &settling(&without, true)).is_err());
        // The ledger admits an unused entry: a successful call of another function that
        // carries the entry spends nothing. A second entry of the wallet leaves open which
        // one the transfer used.
        let mut unused = envelope.clone();
        let mut operations = unused.tx.operations.to_vec();
        let OperationBody::InvokeHostFunction(op) = &mut operations[0].body else {
            panic!("an invocation")
        };
        let HostFunction::InvokeContract(call) = &mut op.host_function else {
            panic!("a contract call")
        };
        call.function_name = ScSymbol("balance".try_into().unwrap());
        unused.tx.operations = operations.try_into().unwrap();
        assert!(validate_settled(&signed, &settling(&unused, true)).is_err());
        let mut twice = envelope.clone();
        let mut operations = twice.tx.operations.to_vec();
        let OperationBody::InvokeHostFunction(op) = &mut operations[0].body else {
            panic!("an invocation")
        };
        let mut second = op.auth[0].clone();
        if let SorobanCredentials::Address(credentials) = &mut second.credentials {
            credentials.nonce += 1;
        }
        op.auth = vec![op.auth[0].clone(), second].try_into().unwrap();
        twice.tx.operations = operations.try_into().unwrap();
        assert!(validate_settled(&signed, &settling(&twice, true)).is_err());
        // Only the receipt of an authorization carries the mark: an operation that settled
        // by its own transaction refuses a receipt with it.
        let network = &p.config.network;
        assert!(rpc::validate_own_receipt(&receipt, network, &receipt.transaction_hash).is_err());
        let mut unmarked = receipt.clone();
        unmarked.settles = None;
        rpc::validate_own_receipt(&unmarked, network, &receipt.transaction_hash).unwrap();
        // The receipt of an authorization settles no ordinary operation.
        assert!(
            rpc::validate_settled_policy_packet(&test_support::policy_signed(), &receipt).is_err()
        );
        // The server settles the authorization by the facilitator's transaction: that
        // transaction's identity, and no fee for the wallet, which paid none.
        use crate::host::runtime::{Accounting, Kind, OperationOutcome, Prepared, Receipt, Signed};
        use crate::host::vendors::RuntimeProvider;
        let restored = |kind, value: String| {
            crate::provider::server::restore(
                kind,
                serde_json::value::RawValue::from_string(value).unwrap(),
            )
            .unwrap()
        };
        let settled = crate::provider::server::Provider::new(network, "https://rpc.example")
            .unwrap()
            .settle_receipt(
                &Prepared(restored(Kind::Prepared, serde_json::to_string(&p).unwrap())),
                &Signed(restored(
                    Kind::Signed,
                    serde_json::to_string(&signed).unwrap(),
                )),
                &Receipt(restored(
                    Kind::Receipt,
                    serde_json::to_string(&receipt).unwrap(),
                )),
                Some(&Accounting::default()),
                0,
            )
            .unwrap();
        assert_eq!(
            (settled.outcome, settled.transaction, settled.fee_units),
            (
                OperationOutcome::Executed,
                receipt.transaction_hash.to_vec(),
                0
            )
        );
    }

    #[test]
    fn the_ledger_of_a_preparation_is_one_that_the_signers_endpoint_has() {
        struct Latest(u64);
        impl rpc::Rpc for Latest {
            fn call(&self, method: &str, _: serde_json::Value) -> Result<serde_json::Value> {
                assert_eq!(method, "getLatestLedger");
                Ok(json!({"sequence": self.0}))
            }
        }
        let p = keypair_wallet();
        let named = u64::from(p.state.ledger);
        // The expiry ledger counts from the ledger that the preparation names. An endpoint
        // that is a few ledgers behind is no reason to refuse; a ledger further ahead is.
        current_ledger(&Latest(named + 100), &p).unwrap();
        current_ledger(&Latest(named - u64::from(LEDGER_AHEAD)), &p).unwrap();
        assert!(current_ledger(&Latest(named - u64::from(LEDGER_AHEAD) - 1), &p).is_err());
        // A preparation that names a far later ledger would make the entry valid far longer.
        let mut far = p.clone();
        far.state.ledger += 100_000;
        assert!(current_ledger(&Latest(named), &far).is_err());
    }

    #[test]
    fn no_authorization_is_signed_at_the_end_of_the_utc_day() {
        // The same wallet, prepared `before` seconds before the end of its UTC day, valid
        // for 100 seconds.
        let at = |before: u64| {
            let ordinary = test_support::native_signed().prepared;
            let now = 2 * allowit_core::DAY - before;
            let prepared = crate::prepare(
                &ordinary.config,
                &ordinary.request,
                &ordinary.state,
                now,
                now + 100,
            )
            .expect("the wallet's own payment ends inside the day");
            let r = authorization_request(&prepared);
            attach(prepared, &r, now)
        };
        // The wallet's own payment may expire at the last second of the day. An
        // authorization must expire a margin earlier: its ledger can close late.
        assert_eq!(at(100).unwrap_err().to_string(), DAY_END);
        assert_eq!(at(100 + DAY_MARGIN - 1).unwrap_err().to_string(), DAY_END);
        assert!(
            at(100 + DAY_MARGIN)
                .unwrap()
                .payment_authorization
                .is_some()
        );
    }

    #[test]
    fn a_policy_time_limit_inside_the_margin_signs_no_authorization() {
        // A policy that allows payments until `end`.
        let limited = |end: u64| {
            let ordinary = test_support::native_signed().prepared;
            let mut config = ordinary.config;
            config.policy_source = "use allowit::prelude::*;\npub fn execute(ctx: &AllowitContext) -> allowit::Result {\n    allowit::expires_at(ctx, &ctx.params[allowit::EXPIRES_AT])?;\n    Ok(())\n}\n".into();
            config.source_hash = hash(&config.policy_source);
            config.params.0.insert(
                "expires_at".into(),
                policy::PolicyValue::Int(i128::from(end)),
            );
            let mut state = ordinary.state;
            state.source_hash = config.source_hash;
            let prepared = crate::prepare(&config, &ordinary.request, &state, NOW, EXPIRES)
                .expect("the policy allows the wallet's own payment");
            let r = authorization_request(&prepared);
            attach(prepared, &r, NOW)
        };
        // The wallet's own payment needs the limit at the expiry of the operation. An
        // authorization needs it one margin later: its ledger can close after the expiry.
        assert_eq!(
            limited(EXPIRES + EXPIRY_MARGIN - 1)
                .unwrap_err()
                .to_string(),
            TIME_LIMIT
        );
        assert_eq!(limited(EXPIRES).unwrap_err().to_string(), TIME_LIMIT);
        let admitted = limited(EXPIRES + EXPIRY_MARGIN).unwrap();
        assert!(admitted.payment_authorization.is_some());
    }

    /// A ledger past the expiry of the entry, with the token's transfer events and one reply
    /// to every transaction lookup.
    struct Events {
        passphrase: String,
        latest: u64,
        /// The pages of events, in order. A page past the last one is empty.
        pages: Vec<Vec<serde_json::Value>>,
        /// The last ledger that the endpoint scanned when it returns an empty page.
        scanned: u64,
        transaction: serde_json::Value,
    }
    impl rpc::Rpc for Events {
        fn call(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
            Ok(match method {
                "getNetwork" => json!({"passphrase": self.passphrase}),
                "getEvents" => {
                    // The cursor of a page with events is `page-<number>`; that of an empty
                    // page names the scanned ledger, as the network's endpoint does.
                    let page = params["pagination"]["cursor"]
                        .as_str()
                        .and_then(|cursor| cursor.strip_prefix("page-")?.parse::<usize>().ok())
                        .unwrap_or(0);
                    let events = self.pages.get(page).cloned().unwrap_or_default();
                    let cursor = if events.is_empty() {
                        format!("{}-4294967295", (self.scanned << 32) | 0xffff_ffff)
                    } else {
                        format!("page-{}", page + 1)
                    };
                    json!({"latestLedger": self.latest, "events": events, "cursor": cursor})
                }
                "getTransaction" => self.transaction.clone(),
                other => panic!("unexpected ledger call: {other}"),
            })
        }
    }

    #[test]
    fn an_unreadable_candidate_transaction_keeps_the_outcome_open() {
        let p = keypair_wallet();
        let last = u64::from(expiry_ledger(part(&p).unwrap()).unwrap());
        let read = |pages: Vec<Vec<serde_json::Value>>, scanned: u64| Events {
            passphrase: passphrase(&p.config.network).unwrap().to_owned(),
            latest: last + 5,
            pages,
            scanned,
            transaction: json!({
                "status": "NOT_FOUND",
                "oldestLedger": 1,
                "latestLedger": last + 5,
                "latestLedgerCloseTime": "86800",
            }),
        };
        // No transfer through the expiry ledger: the entry lapsed.
        assert!(lapsed(&read(Vec::new(), last), &p).unwrap());
        // The head of the endpoint is past the expiry ledger, and its scan stopped before
        // it: the rest is unread, so nothing is proven.
        assert!(!lapsed(&read(Vec::new(), last - 1), &p).unwrap());
        // A page can end early. A transfer on a later page is found, and a transfer whose
        // transaction the ledger does not return may have settled the entry.
        let candidate = json!({"ledger": last, "txHash": "09".repeat(32)});
        let earlier = json!({"ledger": last - 1, "txHash": "08".repeat(32)});
        for pages in [
            vec![vec![candidate.clone()]],
            vec![vec![earlier.clone()], vec![candidate.clone()]],
        ] {
            assert!(matches!(
                observe(&read(pages.clone(), last + 5), &p).unwrap(),
                Observed::Open
            ));
            assert!(!lapsed(&read(pages, last + 5), &p).unwrap());
        }
        // An event after the expiry ledger ends the read: everything before it was returned.
        let after = json!({"ledger": last + 1, "txHash": "07".repeat(32)});
        assert!(lapsed(&read(vec![vec![after]], last - 1), &p).unwrap());
        assert_eq!(
            cursor_ledger("0024835489475330047-4294967295"),
            Some(5_782_462)
        );
        assert_eq!(cursor_ledger("end"), None);
    }

    #[test]
    fn observation_reports_the_settlement_and_lapses_an_entry_that_no_transaction_carried() {
        let p = keypair_wallet();
        let signed = assemble(&p, &[signed_by(AGENT, &p), signed_by(SERVER, &p)], NOW).unwrap();
        // The expiry ledger as the entry states it, read here without `expiry_ledger`.
        let entry: SorobanAuthorizationEntry = read(&part(&p).unwrap().authorization_xdr).unwrap();
        let SorobanCredentials::Address(credentials) = &entry.credentials else {
            panic!("an address authorization")
        };
        let last = u64::from(credentials.signature_expiration_ledger);
        assert!(last > u64::from(p.state.ledger));
        // The facilitator's transaction: its own source, the same invocation and entry.
        let TransactionEnvelope::Tx(mut envelope) = read(&signed.transaction_xdr).unwrap() else {
            panic!("a transaction")
        };
        envelope.tx.source_account = MuxedAccount::Ed25519(Uint256([6; 32]));
        envelope.tx.seq_num = SequenceNumber(77);
        // The token reported one transfer through the expiry ledger, in the successful
        // transaction `envelope`, and the ledger returns that transaction.
        let ledger = |envelope: &TransactionV1Envelope| {
            let result = TransactionResult {
                fee_charged: 12_345,
                result: TransactionResultResult::TxSuccess(VecM::default()),
                ext: TransactionResultExt::V0,
            };
            let hash = transaction_hash(&p.config.network, &envelope.tx).unwrap();
            Events {
                passphrase: passphrase(&p.config.network).unwrap().to_owned(),
                latest: last + 5,
                pages: vec![vec![json!({"ledger": last, "txHash": hex(&hash)})]],
                scanned: last + 5,
                transaction: json!({
                    "status": "SUCCESS",
                    "ledger": last,
                    "envelopeXdr": xdr(&TransactionEnvelope::Tx(envelope.clone())).unwrap(),
                    "resultXdr": xdr(&result).unwrap(),
                }),
            }
        };
        // A confirmed transaction that carries the entry settled it: the payer paid, and the
        // settlement comes with its receipt.
        let hash = transaction_hash(&p.config.network, &envelope.tx).unwrap();
        let Observed::Settled(settled) = observe(&ledger(&envelope), &p).unwrap() else {
            panic!("the confirmed settlement is not reported")
        };
        assert_eq!(settled.receipt.transaction_hash, hash);
        assert_eq!(settled.receipt.settles, Some(p.transaction_hash));
        assert_eq!(settled.signed.role_signatures, signed.role_signatures);
        assert!(!lapsed(&ledger(&envelope), &p).unwrap());
        let settled = settlement(&ledger(&envelope), &p).unwrap().unwrap();
        assert_eq!(settled.receipt.transaction_hash, hash);
        // The same transfer settled by another entry of the wallet (another nonce) is not this
        // entry's settlement: the read reaches past the expiry ledger, so this entry lapsed.
        let mut other = envelope.clone();
        let mut operations = other.tx.operations.to_vec();
        let OperationBody::InvokeHostFunction(op) = &mut operations[0].body else {
            panic!("an invocation")
        };
        let mut auth = op.auth.to_vec();
        if let SorobanCredentials::Address(credentials) = &mut auth[0].credentials {
            credentials.nonce += 1;
        }
        op.auth = auth.try_into().unwrap();
        other.tx.operations = operations.try_into().unwrap();
        assert!(matches!(
            observe(&ledger(&other), &p).unwrap(),
            Observed::Lapsed
        ));
    }

    /// The nonce of the entry of `p`.
    fn nonce_of(p: &PreparedOperation) -> i64 {
        let entry: SorobanAuthorizationEntry = read(&part(p).unwrap().authorization_xdr).unwrap();
        let SorobanCredentials::Address(credentials) = entry.credentials else {
            panic!("an address authorization")
        };
        credentials.nonce
    }

    #[test]
    fn each_operation_has_its_own_nonce_and_a_retained_entry_keeps_it() {
        // A retained packet rebuilds its entry, so the derivation of the nonce never changes:
        // this is the nonce of the fixture's operation.
        assert_eq!(nonce_of(&keypair_wallet()), 1_125_705_196_250_729_941);
        // Each operation id has its own nonce, which the ledger takes once.
        let ordinary = test_support::native_signed().prepared;
        let mut seen = std::collections::BTreeSet::new();
        for id in 1..=4u8 {
            let mut request = ordinary.request.clone();
            request.operation.nonce = [id; 32];
            let prepared =
                crate::prepare(&ordinary.config, &request, &ordinary.state, NOW, EXPIRES).unwrap();
            let r = authorization_request(&prepared);
            let nonce = nonce_of(&attach(prepared, &r, NOW).unwrap());
            assert!(nonce >= 0);
            assert!(seen.insert(nonce), "operation {id} repeats a nonce");
        }
    }

    #[test]
    fn a_payment_authorization_is_admitted_only_from_its_creation_until_its_expiry() {
        let p = keypair_wallet();
        admit(&p, p.created_at).unwrap();
        admit(&p, p.expires_at - 1).unwrap();
        for now in [p.created_at - 1, p.expires_at] {
            assert_eq!(admit(&p, now).unwrap_err(), "Prepared operation is stale");
        }
    }

    /// A ledger at `latest` that shows the wallet account as `account` and answers the
    /// simulation of the payload with `simulated`. It keeps the parameters of each simulation.
    struct Simulating {
        latest: u64,
        account: AccountState,
        simulated: serde_json::Value,
        simulations: std::sync::Mutex<Vec<serde_json::Value>>,
    }
    impl rpc::Rpc for Simulating {
        fn call(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
            Ok(match method {
                "getLatestLedger" => json!({"sequence": self.latest}),
                "getLedgerEntries" => test_support::owner::account_entry(&self.account),
                "simulateTransaction" => {
                    self.simulations.lock().unwrap().push(params);
                    self.simulated.clone()
                }
                other => panic!("unexpected ledger call: {other}"),
            })
        }
    }
    /// A successful simulation: the resources of the invocation and its fee.
    fn simulation_passes() -> serde_json::Value {
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
            resource_fee: 100,
        };
        json!({"latestLedger": 1, "transactionData": xdr(&resources).unwrap(), "minResourceFee": "100"})
    }

    #[test]
    fn an_authorization_that_the_ledger_refuses_is_not_released() {
        // A keypair wallet whose account has exactly its roles, with an owner of its own, as the
        // ledger shows it.
        let ordinary = test_support::native_signed().prepared;
        let mut config = ordinary.config.clone();
        config.owner = account_for_seed(&[10; 32]);
        let c = &config;
        let mut state = ordinary.state.clone();
        state.owner = c.owner.clone();
        state.source = test_support::wallet_account(
            &c.wallet,
            &c.owner,
            &c.agent,
            &c.server,
            state.source.sequence,
        );
        let ordinary = crate::prepare(c, &ordinary.request, &state, NOW, EXPIRES).unwrap();
        let r = authorization_request(&ordinary);
        let p = attach(ordinary, &r, NOW).unwrap();
        let signatures = [signed_by(AGENT, &p), signed_by(SERVER, &p)];
        let passes = simulation_passes();
        let ledger = |simulated| Simulating {
            latest: u64::from(p.state.ledger),
            account: p.state.source.clone(),
            simulated,
            simulations: Default::default(),
        };
        let release = |ledger: &Simulating| super::authorize(ledger, &p, &signatures, NOW);
        // The ledger simulates exactly the released payload, with the account's signature check
        // enforced.
        let passing = ledger(passes.clone());
        let released = release(&passing).unwrap();
        assert_eq!(
            *passing.simulations.lock().unwrap(),
            [json!({"transaction": released.transaction_xdr, "authMode": "enforce"})]
        );
        assert_eq!(
            release(&ledger(
                json!({"error": "the account's signature check failed"})
            ))
            .unwrap_err(),
            "The ledger refuses this payment authorization"
        );
        // The ledger passes the simulation, but the preparation named a ledger that the network
        // has not closed, so the entry would stay valid longer than its operation.
        let mut behind = ledger(passes.clone());
        behind.latest -= u64::from(LEDGER_AHEAD) + 1;
        assert_eq!(
            release(&behind).unwrap_err(),
            "The payment authorization counts its expiry from a ledger that the network has not closed"
        );
        // The wallet account changed since the preparation.
        let mut changed = ledger(passes);
        changed.account.sequence += 1;
        assert_eq!(
            release(&changed).unwrap_err(),
            "The wallet changed since this payment authorization was prepared"
        );
    }

    /// A ledger endpoint that must never be called.
    struct Unreachable;
    impl rpc::Rpc for Unreachable {
        fn call(&self, method: &str, _: serde_json::Value) -> Result<serde_json::Value> {
            panic!("the ledger was called: {method}")
        }
    }
    /// The ordinary assembly refuses a payment authorization.
    fn authorize(
        p: &PreparedOperation,
        signatures: &[DetachedSignature],
        now: u64,
    ) -> Result<SignedOperation> {
        crate::authorize(p, signatures, now)
    }
}
