//! Service authorization precedes the agent's transaction signature.
use crate::*;

/// The ledger blocks into which a wallet's authorization entry stays valid.
pub const WALLET_AUTH_LEDGERS: u32 = 64;

/// The wallet's own authorization entry of `execute(request)`, unsigned. The wallet's
/// `__check_auth` takes the agent's and the server's signatures of its payload. The nonce comes
/// from the operation id, so every preparation of one operation shares it, and the ledger lets at
/// most one of them run while it keeps the nonce.
pub(crate) fn wallet_entry(
    c: &WalletConfig,
    r: &ExecutionRequest,
    state: &TrustedState,
    call: InvokeContractArgs,
) -> Result<SorobanAuthorizationEntry> {
    let mut identity = b"allowit-wallet-auth-v1".to_vec();
    identity.extend(network_id(&c.network)?);
    identity.extend(address(&c.wallet)?.to_xdr(limits()).map_err(err)?);
    identity.extend(r.operation.nonce);
    let nonce = i64::from_be_bytes(hash(identity)[..8].try_into().unwrap()) & i64::MAX;
    Ok(SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: address(&c.wallet)?,
            nonce,
            signature_expiration_ledger: state
                .ledger
                .checked_add(WALLET_AUTH_LEDGERS)
                .ok_or("Authorization ledger overflow")?,
            signature: ScVal::Void,
        }),
        root_invocation: SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(call),
            sub_invocations: VecM::default(),
        },
    })
}

pub(crate) fn payload(network: &str, entry: &SorobanAuthorizationEntry) -> Result<[u8; 32]> {
    let SorobanCredentials::Address(credentials) = &entry.credentials else {
        return Err("Service address authorization is required".into());
    };
    Ok(hash(
        HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
            network_id: Hash(network_id(network)?),
            nonce: credentials.nonce,
            signature_expiration_ledger: credentials.signature_expiration_ledger,
            invocation: entry.root_invocation.clone(),
        })
        .to_xdr(limits())
        .map_err(err)?,
    ))
}

/// Verify that `entry` carries exactly one Ed25519 signature by the G-address `account`.
pub(crate) fn verify_account_signature(
    network: &str,
    entry: &SorobanAuthorizationEntry,
    account: &str,
) -> Result<()> {
    let SorobanCredentials::Address(credentials) = &entry.credentials else {
        return Err("Address authorization is required".into());
    };
    let ScVal::Vec(Some(signatures)) = &credentials.signature else {
        return Err("Invalid account signature".into());
    };
    if signatures.len() != 1 {
        return Err("One exact account signature is required".into());
    }
    let key = account_key(account)?;
    let ScVal::Bytes(bytes) = rpc::map_field(&signatures[0], "signature")? else {
        return Err("Invalid account signature bytes".into());
    };
    let bytes: [u8; 64] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "Invalid account signature length")?;
    let expected = value_map(vec![
        ("public_key", value_bytes(&key)?),
        ("signature", value_bytes(&bytes)?),
    ])?;
    if signatures[0] != expected {
        return Err("Account signer or signature fields differ".into());
    }
    VerifyingKey::from_bytes(&key)
        .map_err(err)?
        .verify_strict(&payload(network, entry)?, &EdSignature::from_bytes(&bytes))
        .map_err(err)
}

/// Sign an unsigned address authorization entry with a G-account seed, as a classic account
/// signature, valid through `expiration_ledger`. Use it for a new owner's handoff entry.
pub fn sign_account_entry(
    network: &str,
    entry: &SorobanAuthorizationEntry,
    seed: &[u8; 32],
    expiration_ledger: u32,
) -> Result<SorobanAuthorizationEntry> {
    let mut signed = entry.clone();
    let SorobanCredentials::Address(credentials) = &mut signed.credentials else {
        return Err("Address authorization is required".into());
    };
    let signer = account_for_seed(seed);
    if credentials.address != address(&signer)? || credentials.signature != ScVal::Void {
        return Err("The seed does not own this unsigned authorization entry".into());
    }
    credentials.signature_expiration_ledger = expiration_ledger;
    let signature = SigningKey::from_bytes(seed)
        .sign(&payload(network, &signed)?)
        .to_bytes();
    let value = ScVal::Vec(Some(
        vec![value_map(vec![
            ("public_key", value_bytes(&account_key(&signer)?)?),
            ("signature", value_bytes(&signature)?),
        ])?]
        .try_into()
        .map_err(err)?,
    ));
    let SorobanCredentials::Address(credentials) = &mut signed.credentials else {
        unreachable!()
    };
    credentials.signature = value;
    verify_account_signature(network, &signed, &signer)?;
    Ok(signed)
}

/// The one wallet authorization entry of a prepared policy wallet operation, checked against the
/// entry that its request gives.
pub(crate) fn wallet_authorization(p: &PreparedOperation) -> Result<SorobanAuthorizationEntry> {
    let TransactionEnvelope::Tx(envelope) = read(&p.transaction_xdr)? else {
        return Err("Expected a policy transaction".into());
    };
    if envelope.tx.operations.len() != 1 {
        return Err("One exact policy invocation is required".into());
    }
    let OperationBody::InvokeHostFunction(op) = &envelope.tx.operations[0].body else {
        return Err("Expected policy invocation".into());
    };
    let HostFunction::InvokeContract(call) = &op.host_function else {
        return Err("Expected policy invocation".into());
    };
    if op.auth.len() != 1 {
        return Err("Exactly the wallet's own authorization is required".into());
    }
    let entry = op.auth[0].clone();
    let mut unsigned = entry.clone();
    if let SorobanCredentials::Address(c) = &mut unsigned.credentials {
        c.signature = ScVal::Void;
    }
    if unsigned != wallet_entry(&p.config, &p.request, &p.state, call.clone())? {
        return Err("Wallet authorization scope differs".into());
    }
    Ok(entry)
}
/// The digest that the agent and the server sign for a policy wallet operation: the payload of
/// the wallet's own authorization entry.
pub fn wallet_payload(p: &PreparedOperation) -> Result<[u8; 32]> {
    payload(&p.config.network, &wallet_authorization(p)?)
}
/// The agent's and the server's signatures in the wallet's entry, verified; a placeholder of
/// zeros stands for a part that is not signed yet.
pub(crate) fn cosignatures(p: &PreparedOperation) -> Result<(Option<[u8; 64]>, Option<[u8; 64]>)> {
    let entry = wallet_authorization(p)?;
    let SorobanCredentials::Address(credentials) = &entry.credentials else {
        return Err("Expected the wallet's address authorization".into());
    };
    if credentials.signature == ScVal::Void {
        return Ok((None, None));
    }
    let ScVal::Vec(Some(parts)) = &credentials.signature else {
        return Err("Invalid wallet cosignatures".into());
    };
    let part = |i: usize| -> Result<Option<[u8; 64]>> {
        let ScVal::Bytes(bytes) = parts.get(i).ok_or("Two wallet cosignatures are required")?
        else {
            return Err("Invalid wallet cosignature".into());
        };
        let bytes: [u8; 64] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| "Invalid wallet cosignature length")?;
        Ok((bytes != [0; 64]).then_some(bytes))
    };
    if parts.len() != 2 {
        return Err("Two wallet cosignatures are required".into());
    }
    let (agent, server) = (part(0)?, part(1)?);
    let digest = payload(&p.config.network, &entry)?;
    for (signature, signer) in [(agent, &p.config.agent), (server, &p.config.server)] {
        if let Some(signature) = signature {
            signing::verify_digest(signer, &digest, &signature)?;
        }
    }
    Ok((agent, server))
}
/// The signature value of the wallet's entry, after checking each part that is signed.
pub(crate) fn wallet_signature(p: &PreparedOperation) -> Result<ScVal> {
    cosignatures(p)?;
    let SorobanCredentials::Address(credentials) = wallet_authorization(p)?.credentials else {
        return Err("Expected the wallet's address authorization".into());
    };
    Ok(credentials.signature)
}
/// The server's verified signature of the wallet's entry, or an error when `require_signed`
/// and it is missing.
pub(crate) fn server_signature(
    p: &PreparedOperation,
    require_signed: bool,
) -> Result<Option<[u8; 64]>> {
    let (_, server) = cosignatures(p)?;
    if require_signed && server.is_none() {
        return Err("Service authorization is unsigned".into());
    }
    Ok(server)
}
/// Validate the retained service authorization without signing or changing the packet.
/// This does not establish execution validity or settlement.
pub fn validate_server_authorization(p: &PreparedOperation) -> Result<()> {
    server_signature(p, true).map(|_| ())
}

/// Put `signature` into the wallet's entry. The transaction hash changes with it.
pub(crate) fn attach(p: &PreparedOperation, signature: ScVal) -> Result<PreparedOperation> {
    let TransactionEnvelope::Tx(mut envelope) = read(&p.transaction_xdr)? else {
        return Err("Expected policy transaction".into());
    };
    let mut operations = envelope.tx.operations.to_vec();
    let OperationBody::InvokeHostFunction(op) = &mut operations[0].body else {
        return Err("Expected policy invocation".into());
    };
    let mut auth = op.auth.to_vec();
    let SorobanCredentials::Address(credentials) = &mut auth[0].credentials else {
        return Err("Expected the wallet's authorization".into());
    };
    credentials.signature = signature;
    op.auth = auth.try_into().map_err(err)?;
    envelope.tx.operations = operations.try_into().map_err(err)?;
    let mut out = p.clone();
    out.transaction_hash = transaction_hash(&p.config.network, &envelope.tx)?;
    out.transaction_xdr = xdr(&TransactionEnvelope::Tx(envelope))?;
    out.native_preflight = None;
    Ok(out)
}

/// Sign the service's half of the wallet's authorization after its policy gates, before the agent
/// signs. This changes the transaction hash. Persist and deliver the returned packet to the agent.
///
/// The service evaluates the installed policy on the host first. A Custom wallet runs its whole
/// policy onchain, so native preflight completes it. A Simple or Common wallet runs at most its
/// prefix onchain: a policy that is not canonical-only needs `authorize_server_with` and the
/// compiled evaluator of its source. Layout 4 wallets keep standard accounting onchain, so
/// `accounting` must be `None`.
pub fn authorize_server(
    p: &PreparedOperation,
    seed: &[u8; 32],
    now: u64,
    accounting: Option<rpc::NativeAccounting>,
) -> Result<PreparedOperation> {
    if accounting.is_some() {
        return Err("Contract policy accounting cannot be replaced by service counters".into());
    }
    authorize_service(p, seed, now, None)
}
/// `authorize_server` with the compiled evaluator of the installed source, built by the
/// server's policy build gate from the same bytes as `config.policy_source`.
pub fn authorize_server_with(
    p: &PreparedOperation,
    seed: &[u8; 32],
    now: u64,
    evaluator: policy::PortableEvaluator,
) -> Result<PreparedOperation> {
    authorize_service(p, seed, now, Some(evaluator))
}
fn authorize_service(
    p: &PreparedOperation,
    seed: &[u8; 32],
    now: u64,
    evaluator: Option<policy::PortableEvaluator>,
) -> Result<PreparedOperation> {
    authorize_server_using(p, &account_for_seed(seed), now, evaluator, |digest| {
        Ok(SigningKey::from_bytes(seed).sign(digest).to_bytes())
    })
}
/// Authorize through a caller-owned signing capability after the same complete policy gates.
/// The callback receives only the native digest. Its signature must match the declared server.
pub fn authorize_server_using(
    p: &PreparedOperation,
    signer_account: &str,
    now: u64,
    evaluator: Option<policy::PortableEvaluator>,
    sign_hash: impl FnOnce(&[u8; 32]) -> Result<[u8; 64]>,
) -> Result<PreparedOperation> {
    if p.config.route != WalletRoute::PolicyWallet || signer_account != p.config.server {
        return Err("Configured policy service signer required".into());
    }
    validate_prepared(p, now)?;
    let tier = p.config.tier.ok_or("Selected policy tier is required")?;
    let evaluation = verify_operation(
        &p.config,
        &p.request,
        &p.terms,
        &p.state,
        now,
        p.expires_at,
        evaluator,
    )?;
    if tier.standard() && evaluation == policy::Evaluation::Prefix {
        return Err("The service must evaluate the full Simple or Common policy; supply its compiled evaluator".into());
    }
    if cosignatures(p)? != (None, None) {
        return Err("Service authorization is already signed".into());
    }
    let digest = wallet_payload(p)?;
    let signature = sign_hash(&digest)?;
    signing::verify_digest(signer_account, &digest, &signature)?;
    // The agent's part stays zero until the agent signs the same payload.
    let out = attach(p, contract::cosignatures(&[0; 64], &signature)?)?;
    server_signature(&out, true)?;
    Ok(out)
}
