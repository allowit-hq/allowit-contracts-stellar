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
//! Both custody forms sign such an entry:
//!
//! - A policy wallet is a contract account. Its entry carries the wallet's
//!   `PolicyAuthorization`: the execution packet and the raw signatures of the agent and the
//!   service over the digest of [`x402`]. The owner must have enabled x402 for the wallet.
//! - A keypair wallet is a classic account. The agent and the service each sign the host
//!   payload of the entry, and the entry holds both account signatures. Their weights reach
//!   the account's medium threshold only together. The ledger keeps no record of the
//!   operation for such a wallet, so its settlement and its lapse both read the token's
//!   transfer events up to the expiry ledger of the entry.
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

/// The token contract of the wallet's asset: the installed contract of a policy wallet, or
/// the asset contract of a keypair wallet's classic asset.
fn token_contract(c: &WalletConfig) -> Result<String> {
    if c.route == WalletRoute::Native {
        sac_address(&c.network, &asset_xdr(c)?)
    } else {
        Ok(c.asset.clone())
    }
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
                contract_address: address(&token_contract(c)?)?,
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

/// The digest that both signers sign. For a policy wallet: the wallet's domain, the host
/// payload of the entry and the execution packet, in the encoding of
/// [`x402::signing_digest`] without its checks of the current time, so a retained packet reads
/// after its expiry. For a keypair wallet: the host payload of the entry.
fn digest(p: &PreparedOperation, a: &PaymentAuthorization) -> Result<[u8; 32]> {
    let entry: SorobanAuthorizationEntry = read(&a.authorization_xdr)?;
    let host_payload = authorization::payload(&p.config.network, &entry)?;
    if p.config.route == WalletRoute::Native {
        // The signers of a classic account sign the host payload of the entry itself.
        return Ok(host_payload);
    }
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
    if !matches!(c.route, WalletRoute::PolicyWallet | WalletRoute::Native) {
        return Err("This wallet signs no payment authorization".into());
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
    match (&a.server_signature, &c.route) {
        (None, _) => {}
        // The service of a keypair wallet signs with the agent when the entry is assembled.
        (Some(_), WalletRoute::Native) => {
            return Err("A keypair wallet's preparation holds no service signature".into());
        }
        (Some(bytes), _) => signing::verify_digest(&c.server, &a.digest, bytes)
            .map_err(|_| "Invalid service signature of the payment authorization")?,
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
    let digest = if p.config.route == WalletRoute::Native {
        // The exact roles, weights and thresholds of the wallet account, as for a payment.
        p.state.source.validate_wallet(&p.config)?;
        digest(p, a)?
    } else {
        x402::signing_digest(&signing_request(p)?, now).map_err(|error| {
            if p.state
                .policy_state
                .as_ref()
                .is_some_and(|state| !state.x402_enabled)
            {
                DISABLED.to_owned()
            } else {
                error
            }
        })?
    };
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
    let policy_wallet = match c.route {
        WalletRoute::PolicyWallet => true,
        WalletRoute::Native => false,
        WalletRoute::Odc => return Err("This wallet signs no payment authorization".into()),
    };
    let t = transfer(c, r)?;
    let found = rpc::trusted_state_for_discovery(rpc, c, accounting.clone())?;
    if found.paused {
        return Err("The wallet is paused".into());
    }
    if policy_wallet
        && found
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
    if policy_wallet {
        // The simulation above established the preflight of the operation. It now binds the
        // authorization part too.
        record_native_preflight(&mut p)?;
    }
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
    if p.config.route != WalletRoute::PolicyWallet || signer_account != p.config.server {
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
    if p.config.route == WalletRoute::Native {
        let current = rpc::get_account(rpc, &p.config.wallet)?;
        current.validate_roles(&p.config.owner, &p.config.agent, &p.config.server)?;
        if current != p.state.source {
            return Err("The wallet changed since this payment authorization was prepared".into());
        }
        return Ok(());
    }
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

/// A role's signature of the digest of `p`, after the same admission as [`admit`]. The agent
/// of a policy wallet signs only what the service approved: the service's signature must be
/// present. The agent and the service of a keypair wallet both sign here.
pub fn sign(
    p: &PreparedOperation,
    signer: &str,
    now: u64,
    sign_hash: impl FnOnce(&[u8; 32]) -> Result<[u8; 64]>,
) -> Result<DetachedSignature> {
    let digest = admit(p, now)?;
    let allowed = if p.config.route == WalletRoute::Native {
        // The agent and the service of a keypair wallet sign the same payload.
        signer == p.config.agent || signer == p.config.server
    } else {
        if part(p)?.server_signature.is_none() {
            return Err("Service authorization is unsigned".into());
        }
        signer == p.config.agent
    };
    if !allowed {
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

/// The role signatures that a signed authorization holds, in role order: the agent alone for
/// a policy wallet, whose preparation holds the service's signature, and the agent then the
/// service for a keypair wallet.
fn roles(c: &WalletConfig) -> Vec<&str> {
    if c.route == WalletRoute::Native {
        vec![c.agent.as_str(), c.server.as_str()]
    } else {
        vec![c.agent.as_str()]
    }
}

/// Check `signatures` against the roles of `p`: one valid signature of the digest per role,
/// in role order.
fn role_signatures(
    p: &PreparedOperation,
    a: &PaymentAuthorization,
    signatures: &[DetachedSignature],
) -> Result<Vec<[u8; 64]>> {
    let roles = roles(&p.config);
    if p.config.agent == p.config.server || signatures.len() != roles.len() {
        return Err("Every automated role must sign the payment authorization once".into());
    }
    roles
        .iter()
        .zip(signatures)
        .map(|(role, proof)| {
            if proof.signer != *role {
                return Err("A role signature names another signer".into());
            }
            signing::verify_digest(role, &a.digest, &proof.signature)
                .map_err(|_| "Invalid role signature of the payment authorization")?;
            signature(&proof.signature)
        })
        .collect()
}

/// The signed entry of `p`. A policy wallet's entry holds the wallet's `PolicyAuthorization`,
/// in the encoding of [`x402::assemble`]. A keypair wallet's entry holds the account
/// signatures of the agent and the service, in the order of their public keys.
fn signed_entry(
    p: &PreparedOperation,
    a: &PaymentAuthorization,
    signatures: &[[u8; 64]],
) -> Result<SorobanAuthorizationEntry> {
    let c = &p.config;
    let mut entry: SorobanAuthorizationEntry = read(&a.authorization_xdr)?;
    let SorobanCredentials::Address(credentials) = &mut entry.credentials else {
        return Err("A payment authorization needs wallet-address authorization".into());
    };
    credentials.signature = if c.route == WalletRoute::Native {
        let [agent, server] = signatures else {
            return Err("A keypair wallet's entry holds two account signatures".into());
        };
        let mut signers = [
            (account_key(&c.agent)?, agent),
            (account_key(&c.server)?, server),
        ];
        signers.sort_by_key(|(key, _)| *key);
        ScVal::Vec(Some(
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
        ))
    } else {
        let [agent] = signatures else {
            return Err("A policy wallet's entry holds the agent's signature".into());
        };
        let server = signature(
            a.server_signature
                .as_deref()
                .ok_or("Service authorization is unsigned")?,
        )?;
        value_map(vec![
            ("execution", execution(p, a)?),
            ("agent_signature", value_bytes(agent)?),
            ("server_signature", value_bytes(&server)?),
        ])?
    };
    Ok(entry)
}

/// Assemble the signed authorization from the role signatures and check it against the
/// ledger: the enforce-mode simulation of the payload runs the wallet's own check, or the
/// account's signature check, with both signatures. A wallet that refuses it releases
/// nothing to the seller.
pub fn authorize(
    rpc: &dyn rpc::Rpc,
    p: &PreparedOperation,
    signatures: &[DetachedSignature],
    now: u64,
) -> Result<SignedOperation> {
    let a = part(p)?;
    revalidate(rpc, p, now)?;
    let verified = role_signatures(p, a, signatures)?;
    let entry = signed_entry(p, a, &verified)?;
    if p.config.route == WalletRoute::PolicyWallet {
        let server = signature(
            a.server_signature
                .as_deref()
                .ok_or("Service authorization is unsigned")?,
        )?;
        // The reviewed assembly verifies both signatures and every binding at `now`.
        let assembled = x402::assemble(&signing_request(p)?, &verified[0], &server, now)?;
        if assembled != xdr(&entry)? {
            return Err("The assembled payment authorization differs".into());
        }
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
        role_signatures: signatures.to_vec(),
    };
    validate_signed(&signed)?;
    Ok(signed)
}

/// The signed entry that `s` carries, after checking the whole retained packet: the
/// preparation, every role's signature of its digest, and a payload that is exactly the
/// transaction of the signed entry.
fn retained_entry(s: &SignedOperation) -> Result<SorobanAuthorizationEntry> {
    let p = &s.prepared;
    let a = part(p)?;
    validate_retained_prepared(p)?;
    if s.transaction_hash != p.transaction_hash {
        return Err("Signed transaction identity differs".into());
    }
    let entry = signed_entry(p, a, &role_signatures(p, a, &s.role_signatures)?)?;
    if s.transaction_xdr != payload_transaction(&entry)? {
        return Err("The payment authorization payload differs".into());
    }
    Ok(entry)
}

/// Verify a retained signed authorization. This reads no time and grants nothing.
pub fn validate_signed(s: &SignedOperation) -> Result<()> {
    retained_entry(s).map(drop)
}

/// The authorization entries of the one invocation of `receipt`'s transaction.
fn carried(receipt: &rpc::VerifiedReceipt) -> Result<Vec<SorobanAuthorizationEntry>> {
    let TransactionEnvelope::Tx(envelope) = read(&receipt.envelope_xdr)? else {
        return Ok(Vec::new());
    };
    let [operation] = envelope.tx.operations.as_slice() else {
        return Ok(Vec::new());
    };
    let OperationBody::InvokeHostFunction(op) = &operation.body else {
        return Ok(Vec::new());
    };
    Ok(op.auth.to_vec())
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
        || !carried(receipt)?.contains(&entry)
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
    /// The events cover every ledger through the expiry ledger: the ledger passed it, and the
    /// read reached the end of the events or an event after it.
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
    let mut transactions = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..8 {
        let mut params = json!({
            "filters": [{"type": "contract", "contractIds": [token_contract(c)?], "topics": [prefix, with_asset]}],
            "pagination": {"limit": 200},
        });
        match &cursor {
            Some(cursor) => params["pagination"]["cursor"] = json!(cursor),
            None => params["startLedger"] = json!(p.state.ledger),
        }
        let reply = rpc.call("getEvents", params)?;
        let latest = reply["latestLedger"]
            .as_u64()
            .ok_or("Missing latest ledger of the events")?;
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
        if events.len() < 200 || next.is_none() || next == cursor {
            return Ok(Transfers {
                transactions,
                complete: latest > last,
            });
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

/// What the ledger shows of the authorization of `p`.
pub enum Observed {
    /// A successful transaction carries the entry.
    Settled(Box<Settlement>),
    /// The entry did not settle and can no longer settle: its expiry ledger passed and no
    /// transaction of the token's transfers through that ledger carries it. Only a keypair
    /// wallet reports this here; a policy wallet's lapse is [`rpc::operation_lapsed`].
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
    let bytes = |value: &ScVal| match value {
        ScVal::Bytes(bytes) => Ok(bytes.to_vec()),
        _ => Err("The settled entry holds an invalid signature".to_owned()),
    };
    if c.route != WalletRoute::Native {
        return Ok(vec![DetachedSignature {
            signer: c.agent.clone(),
            signature: bytes(rpc::map_field(&credentials.signature, "agent_signature")?)?,
        }]);
    }
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
            Ok(DetachedSignature {
                signer: role.to_owned(),
                signature: bytes(rpc::map_field(signer, "signature")?)?,
            })
        })
        .collect()
}

/// Read what the ledger shows of the authorization of `p`.
///
/// A policy wallet stores a receipt under the operation id when the entry settles. Without
/// that receipt the entry is open. With it, the token's transfer event names the
/// transaction. A keypair wallet stores nothing, so the transfer events are read at once, and
/// a complete read without the entry after its expiry ledger proves the lapse.
///
/// The transaction must succeed and carry the wallet's entry of `p`, which the nonce binds,
/// with the signatures of the roles.
pub fn observe(rpc: &dyn rpc::Rpc, p: &PreparedOperation) -> Result<Observed> {
    let a = part(p)?;
    validate_retained_prepared(p)?;
    let policy_wallet = p.config.route == WalletRoute::PolicyWallet;
    if policy_wallet {
        let Some(executed) = rpc::operation_receipt(rpc, &p.config, &p.request.operation.nonce)?
        else {
            return Ok(Observed::Open);
        };
        if executed.transfer != rpc::expected_receipt(p)? {
            return Err("The wallet executed another operation under this id".into());
        }
    } else if rpc.call("getNetwork", json!({}))?["passphrase"] != passphrase(&p.config.network)? {
        return Err("Stellar RPC network differs from installation".into());
    }
    let unsigned: SorobanAuthorizationEntry = read(&a.authorization_xdr)?;
    let found = transfers(rpc, p)?;
    for hash in &found.transactions {
        let Some(mut receipt) = rpc::receipt_by_hash(rpc, &p.config.network, hash)? else {
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
        let signed = SignedOperation {
            prepared: p.clone(),
            transaction_xdr: payload_transaction(&entry)?,
            transaction_hash: p.transaction_hash,
            role_signatures: carried_signatures(&p.config, &entry)?,
        };
        receipt.settles = Some(p.transaction_hash);
        validate_settled(&signed, &receipt)?;
        return Ok(Observed::Settled(Box::new(Settlement { signed, receipt })));
    }
    if policy_wallet {
        return Err(
            "The wallet executed this payment, and the ledger events no longer name its transaction"
                .into(),
        );
    }
    Ok(if found.complete {
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
/// A policy wallet proves it with its nonce after the expiry ([`rpc::operation_lapsed`]), a
/// keypair wallet with the token's transfer events through the expiry ledger of the entry.
/// `false` means not proven.
pub fn lapsed(rpc: &dyn rpc::Rpc, p: &PreparedOperation) -> Result<bool> {
    part(p)?;
    if p.config.route == WalletRoute::PolicyWallet {
        return rpc::operation_lapsed(rpc, p);
    }
    Ok(matches!(observe(rpc, p)?, Observed::Lapsed))
}
