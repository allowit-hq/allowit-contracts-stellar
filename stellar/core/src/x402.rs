//! Exact custom-account authorization packets for external raw-key signers.
//!
//! `signing_digest` and `assemble` encode and verify signatures. They do not approve policy
//! execution. Each signer must obtain current trusted wallet state and enforce its own approval
//! boundary before signing.
//!
//! The server signs `signing_digest` only after `verify_server` accepts the exact request and
//! terms. A Simple or Common wallet runs at most its standard prefix onchain, so native preflight
//! does not enforce the rest of the authored policy: unless the source is canonical-only, the
//! server supplies the compiled evaluator of its source, and `verify_server` refuses a
//! prefix-only evaluation. Only a Custom wallet runs its whole policy onchain and can rely on
//! native preflight for the rest. Layout 4 keeps standard accounting onchain; the server supplies
//! no accounting. The facilitator simulates the final transaction in enforce mode before
//! submission.
use crate::*;

/// Native wallet observations required by raw-key authorization.
/// The engine kind comes from the verified policy binding; flags come from custody state.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WalletState {
    pub custody: TrustedState,
    /// Installed tier from the verified policy binding.
    #[serde(alias = "policyEngine")]
    pub tier: PolicyTier,
    pub x402_enabled: bool,
    pub paused: bool,
}

/// Public request reviewed by both independent raw-key signers.
/// `state` must come from current trusted native observations, not payer input.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SigningRequest {
    pub config: WalletConfig,
    pub request: ExecutionRequest,
    pub state: WalletState,
    pub expires_at: u64,
    /// Execution args and expense bounds signed inside the execution packet.
    #[serde(default, skip_serializing_if = "ExecutionTerms::is_empty")]
    pub terms: ExecutionTerms,
    /// Unsigned wallet-address authorization for exactly one SAC transfer.
    pub authorization_xdr: String,
}

fn checked(
    request: &SigningRequest,
    now: u64,
) -> Result<(SorobanAuthorizationEntry, ScVal, [u8; 32])> {
    let c = &request.config;
    let state = &request.state.custody;
    validate_config(c)?;
    if c.route != WalletRoute::PolicyWallet
        || Some(request.state.tier) != c.tier
        || !request.state.x402_enabled
        || request.state.paused
        || state.contract_version != Some(CONTRACT_VERSION)
        || state.agent != c.agent
        || state.server != c.server
        || state.policy_instance != c.policy_instance
        || state.module_digest != c.module_digest
        || state.source_hash != c.source_hash
        || request.expires_at <= now
        || request.expires_at > now.saturating_add(300)
    {
        return Err("Current exact policy wallet and raw signer bindings are required".into());
    }
    // Raw x402 identity is the configured public key. Native account signer changes
    // do not change that key, and no funded agent/server account is required here.
    account_key(&c.agent)?;
    account_key(&c.server)?;
    let transfer = transfer_from_request(c, &request.request)?;
    let entry: SorobanAuthorizationEntry = read(&request.authorization_xdr)?;
    let SorobanCredentials::Address(credentials) = &entry.credentials else {
        return Err("x402 requires wallet-address authorization".into());
    };
    if credentials.address != address(&c.wallet)?
        || credentials.nonce < 0
        || credentials.signature != ScVal::Void
        || credentials.signature_expiration_ledger <= state.ledger
        || credentials.signature_expiration_ledger > state.ledger.saturating_add(64)
    {
        return Err(
            "Invalid wallet authorization address, nonce, signature or ledger bounds".into(),
        );
    }
    let expected = SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
            contract_address: address(&c.asset)?,
            function_name: ScSymbol(b"transfer".to_vec().try_into().map_err(err)?),
            args: vec![
                ScVal::Address(address(&c.wallet)?),
                ScVal::Address(address(&transfer.recipient)?),
                i128_value(transfer.amount),
            ]
            .try_into()
            .map_err(err)?,
        }),
        sub_invocations: VecM::default(),
    };
    if entry.root_invocation != expected {
        return Err("x402 authorization must match the one exact approved SAC transfer".into());
    }
    if let Some(expense) = &request.terms.expense {
        if expense.day != now / allowit::DAY {
            return Err("x402 expense bounds belong to another UTC day".into());
        }
        // The kernel checks the day against the settlement ledger time, which can be as late as
        // `expires_at`. Both signers would sign a request that fails after UTC midnight.
        if request.expires_at / allowit::DAY != expense.day {
            return Err("Priced x402 settlement cannot cross its UTC expense day".into());
        }
    }
    let execution = policy_wallet_request(
        c,
        &request.request,
        &request.terms,
        state,
        &StellarOperation::Transfer(transfer.clone()),
        request.expires_at,
    )?;
    let host_payload = authorization::payload(&c.network, &entry)?;
    let domain = ScVal::Vec(Some(
        vec![
            value_symbol("allowit_wallet_v1")?,
            value_bytes(&host_payload)?,
            execution.clone(),
        ]
        .try_into()
        .map_err(err)?,
    ));
    Ok((
        entry,
        execution,
        hash(domain.to_xdr(limits()).map_err(err)?),
    ))
}

/// The server's approval rule for one raw-key request, then the digest it signs.
///
/// This checks the exact bindings as `signing_digest` does and runs `verify_operation` on the
/// exact request and terms. For a Simple or Common wallet the full policy must run on the host:
/// a source that is not canonical-only needs `evaluator`, compiled by the server's policy build
/// gate from `config.policy_source`, and a prefix-only evaluation is refused, as
/// `authorize_server_with` refuses it for direct execution.
pub fn verify_server(
    request: &SigningRequest,
    now: u64,
    evaluator: Option<policy::PortableEvaluator>,
) -> Result<[u8; 32]> {
    let digest = checked(request, now)?.2;
    let evaluation = verify_operation(
        &request.config,
        &request.request,
        &request.terms,
        &request.state.custody,
        now,
        request.expires_at,
        evaluator,
    )?;
    if request.state.tier.standard() && evaluation == policy::Evaluation::Prefix {
        return Err(
            "The server must evaluate the full Simple or Common policy; supply its compiled evaluator"
                .into(),
        );
    }
    Ok(digest)
}

/// Hash reviewed by each raw Ed25519 signer. This is not a signing approval; the server calls
/// `verify_server` instead.
/// It binds the network, complete authorization tree and native execution packet.
pub fn signing_digest(request: &SigningRequest, now: u64) -> Result<[u8; 32]> {
    Ok(checked(request, now)?.2)
}

/// Verify both raw signatures and encode the contract's exact PolicyAuthorization.
/// Missing, swapped, stale or transplanted signatures cannot produce a final entry.
pub fn assemble(
    request: &SigningRequest,
    agent_signature: &[u8; 64],
    server_signature: &[u8; 64],
    now: u64,
) -> Result<String> {
    let (mut entry, execution, digest) = checked(request, now)?;
    for (signer, bytes) in [
        (&request.config.agent, agent_signature),
        (&request.config.server, server_signature),
    ] {
        VerifyingKey::from_bytes(&account_key(signer)?)
            .map_err(err)?
            .verify_strict(&digest, &EdSignature::from_bytes(bytes))
            .map_err(err)?;
    }
    let SorobanCredentials::Address(credentials) = &mut entry.credentials else {
        unreachable!()
    };
    credentials.signature = value_map(vec![
        ("execution", execution),
        ("agent_signature", value_bytes(agent_signature)?),
        ("server_signature", value_bytes(server_signature)?),
    ])?;
    xdr(&entry)
}
