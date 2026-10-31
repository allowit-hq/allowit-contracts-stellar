//! Service authorization precedes the agent's transaction signature.
use crate::*;

pub(crate) fn server_entry(
    c: &WalletConfig,
    r: &ExecutionRequest,
    state: &TrustedState,
    root: SorobanAuthorizedInvocation,
) -> Result<SorobanAuthorizationEntry> {
    let mut identity = b"allowit-server-auth-v1".to_vec();
    identity.extend(network_id(&c.network)?);
    identity.extend(r.operation.nonce);
    identity.extend(state.deployment_version.to_be_bytes());
    identity.extend(account_key(&c.server)?);
    let nonce = i64::from_be_bytes(hash(identity)[..8].try_into().unwrap()) & i64::MAX;
    Ok(SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: address(&c.server)?,
            nonce,
            signature_expiration_ledger: state
                .ledger
                .checked_add(64)
                .ok_or("Authorization ledger overflow")?,
            signature: ScVal::Void,
        }),
        root_invocation: root,
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

pub(crate) fn server_signature(p: &PreparedOperation, require_signed: bool) -> Result<ScVal> {
    let TransactionEnvelope::Tx(envelope) = read(&p.transaction_xdr)? else {
        return Err("Expected a policy transaction".into());
    };
    if envelope.tx.operations.len() != 1 {
        return Err("One exact policy invocation is required".into());
    }
    let OperationBody::InvokeHostFunction(op) = &envelope.tx.operations[0].body else {
        return Err("Expected policy invocation".into());
    };
    if op.auth.len() != 2 {
        return Err("Agent and service authorization are required".into());
    }
    let entry = &op.auth[1];
    let SorobanCredentials::Address(credentials) = &entry.credentials else {
        return Err("Expected service address authorization".into());
    };
    let expected = server_entry(
        &p.config,
        &p.request,
        &p.state,
        op.auth[0].root_invocation.clone(),
    )?;
    let mut actual = entry.clone();
    if let SorobanCredentials::Address(c) = &mut actual.credentials {
        c.signature = ScVal::Void;
    }
    if actual != expected {
        return Err("Service authorization scope differs".into());
    }
    if credentials.signature == ScVal::Void {
        return if require_signed {
            Err("Service authorization is unsigned".into())
        } else {
            Ok(ScVal::Void)
        };
    }
    let ScVal::Vec(Some(signatures)) = &credentials.signature else {
        return Err("Invalid service signature".into());
    };
    if signatures.len() != 1 {
        return Err("One exact service signature is required".into());
    }
    let key = account_key(&p.config.server)?;
    let public = rpc::map_field(&signatures[0], "public_key")?;
    if public != &value_bytes(&key)? {
        return Err("Service signer differs".into());
    }
    let ScVal::Bytes(bytes) = rpc::map_field(&signatures[0], "signature")? else {
        return Err("Invalid service signature bytes".into());
    };
    let bytes: [u8; 64] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "Invalid service signature length")?;
    let expected_value = value_map(vec![
        ("public_key", value_bytes(&key)?),
        ("signature", value_bytes(&bytes)?),
    ])?;
    if signatures[0] != expected_value {
        return Err("Unexpected service signature fields".into());
    }
    VerifyingKey::from_bytes(&key)
        .map_err(err)?
        .verify_strict(
            &payload(&p.config.network, entry)?,
            &EdSignature::from_bytes(&bytes),
        )
        .map_err(err)?;
    Ok(credentials.signature.clone())
}

pub(crate) fn attach(p: &PreparedOperation, signature: ScVal) -> Result<PreparedOperation> {
    let TransactionEnvelope::Tx(mut envelope) = read(&p.transaction_xdr)? else {
        return Err("Expected policy transaction".into());
    };
    let mut operations = envelope.tx.operations.to_vec();
    let OperationBody::InvokeHostFunction(op) = &mut operations[0].body else {
        return Err("Expected policy invocation".into());
    };
    let mut auth = op.auth.to_vec();
    let SorobanCredentials::Address(credentials) = &mut auth[1].credentials else {
        return Err("Expected service authorization".into());
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

/// Sign the service's exact native authorization after trusted simulation, before agent signing.
/// This changes the transaction hash. Persist and deliver the returned packet to the agent.
pub fn authorize_server(
    p: &PreparedOperation,
    seed: &[u8; 32],
    now: u64,
    accounting: Option<rpc::NativeAccounting>,
) -> Result<PreparedOperation> {
    if p.config.route != WalletRoute::PolicyWallet || account_for_seed(seed) != p.config.server {
        return Err("Configured policy service signer required".into());
    }
    validate_prepared(p, now)?;
    if p.config.policy_engine == Some(PolicyEngine::SimplePolicyEngine) {
        let usage =
            accounting.ok_or("SimplePolicyEngine requires authoritative service accounting")?;
        if usage.nonce != p.state.nonce || usage.deployment_version != p.state.deployment_version {
            return Err("Service accounting differs from active policy ordering".into());
        }
        let policy =
            allowit_policy_sdk::compile_stellar_policy(&p.config.policy_source).map_err(err)?;
        let transfer = transfer_from_request(&p.config, &p.request)?;
        let pass_through = policy.engine_recommendations().iter().any(|choice| {
            choice.engine == PolicyEngine::SimplePolicyEngine && choice.onchain_policy
        });
        if !pass_through
            && (policy.uses_named_state()
                || !policy.explicit_engine_checks.is_empty()
                || !policy.evaluate_classic(&allowit_policy_sdk::StellarPolicyContext {
                    asset: p.config.asset.clone(),
                    recipient: transfer.recipient,
                    token: p.config.asset_symbol.clone(),
                    decimals: 7,
                    amount: transfer.amount,
                    spent_daily: usage.spent_daily,
                    spent_total: usage.spent_total,
                    spent_day: usage.spent_day,
                    calls: usage.calls,
                    now,
                }))
        {
            return Err("SimplePolicyEngine service policy denied the exact transfer".into());
        }
    } else if accounting.is_some() {
        return Err("Contract policy accounting cannot be replaced by service counters".into());
    }
    if server_signature(p, false)? != ScVal::Void {
        return Err("Service authorization is already signed".into());
    }
    let TransactionEnvelope::Tx(envelope) = read(&p.transaction_xdr)? else {
        unreachable!()
    };
    let OperationBody::InvokeHostFunction(op) = &envelope.tx.operations[0].body else {
        unreachable!()
    };
    let signature = SigningKey::from_bytes(seed)
        .sign(&payload(&p.config.network, &op.auth[1])?)
        .to_bytes();
    let value = ScVal::Vec(Some(
        vec![value_map(vec![
            ("public_key", value_bytes(&account_key(&p.config.server)?)?),
            ("signature", value_bytes(&signature)?),
        ])?]
        .try_into()
        .map_err(err)?,
    ));
    let out = attach(p, value)?;
    server_signature(&out, true)?;
    // Re-simulate the signed authorization in enforce mode before the agent signs.
    // Signature checks can change the required resource footprint and fee.
    Ok(out)
}
