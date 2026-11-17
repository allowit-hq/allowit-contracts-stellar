//! Caller-approved owner intent, native transaction validation and capability signing.
//!
//! Expected values must come from the owner's selected policy, reviewed executable and amount,
//! not from the prepared packet. The caller reads the source sequence independently. Simulation
//! supplies only bounded resource data and source-account authorization of the exact operation.
//! A validated packet is an in-memory proof, not a receipt or permission to broadcast. Persisted
//! JSON must be validated again before it can request another signature.
use crate::*;

const MAX_OWNER_XDR: usize = 192 * 1024;
const MAX_WASM: usize = 128 * 1024;
const MAX_FOOTPRINT: usize = 256;

/// Untrusted common fields of a server-prepared owner step. SDK clients parse the server's
/// hexadecimal transaction hash into `transaction_hash`; no field is signing authority.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OwnerTransaction {
    pub network: String,
    pub action: String,
    #[serde(rename = "payload")]
    pub transaction_xdr: String,
    pub transaction_hash: [u8; 32],
    pub expires_at: u64,
}

/// Validate retained unsigned bytes and their descriptive identity without granting fresh authority.
/// Expired packets remain readable for history and restart recovery.
pub fn validate_retained_owner_transaction(original: &OwnerTransaction) -> Result<()> {
    if original.transaction_xdr.len() > MAX_OWNER_XDR {
        return Err("Owner transaction exceeds limit".into());
    }
    let TransactionEnvelope::Tx(envelope) = read(&original.transaction_xdr)? else {
        return Err("Expected an unsigned v1 owner transaction".into());
    };
    let tx = &envelope.tx;
    let Preconditions::Time(bounds) = &tx.cond else {
        return Err("Owner transaction requires time bounds".into());
    };
    if !envelope.signatures.is_empty()
        || !matches!(tx.source_account, MuxedAccount::Ed25519(_))
        || bounds.max_time.0 == 0
        || bounds.min_time.0 >= bounds.max_time.0
        || bounds.max_time.0 != original.expires_at
        || transaction_hash(&original.network, tx)? != original.transaction_hash
        || xdr(&TransactionEnvelope::Tx(envelope.clone()))? != original.transaction_xdr
    {
        return Err("Retained owner identity differs from its transaction".into());
    }
    let action_matches = match tx.operations.as_slice() {
        [
            Operation {
                body: OperationBody::InvokeHostFunction(invoke),
                ..
            },
        ] => match &invoke.host_function {
            HostFunction::UploadContractWasm(_) => original.action == "upload_wasm",
            HostFunction::CreateContractV2(_) => original.action == "create_wallet",
            HostFunction::InvokeContract(call) => {
                let function = call.function_name.0.as_slice();
                // A server retains each step under its own name for the owner action. Those
                // names describe these contract calls; a pause and a resume differ only in
                // the first argument.
                function == original.action.as_bytes()
                    || match (original.action.as_str(), function) {
                        ("fund", b"transfer")
                        | ("update_params", b"deploy_policy")
                        | ("withdraw", b"recover") => true,
                        ("pause" | "resume", b"set_pause") => matches!(
                            call.args.first(),
                            Some(ScVal::Bool(paused)) if *paused == (original.action == "pause")
                        ),
                        _ => false,
                    }
            }
            _ => false,
        },
        [
            Operation {
                body: OperationBody::ExtendFootprintTtl(_),
                ..
            },
        ] => original.action == "extend",
        operations => classic_action_matches(&original.action, operations),
    };
    if !action_matches {
        return Err("Retained owner action differs from its transaction".into());
    }
    Ok(())
}

/// Whether a classic owner transaction has the operations of its named action: the creation
/// of a wallet account or one owner action on it. This describes retained bytes; the exact
/// roles and amounts are checked against caller intent before signing.
fn classic_action_matches(action: &str, operations: &[Operation]) -> bool {
    let wallet_sourced = |op: &Operation| op.source_account.is_some();
    match (action, operations) {
        // The setup of earlier releases configured the owner's own account with three
        // operations. Its retained packets stay readable; nothing prepares or signs it now.
        ("native_setup", [a, b, c])
            if [a, b, c].iter().all(|op| {
                !wallet_sourced(op) && matches!(op.body, OperationBody::SetOptions(_))
            }) =>
        {
            true
        }
        ("native_setup", [create, rest @ ..]) => {
            matches!(create.body, OperationBody::CreateAccount(_))
                && create.source_account.is_none()
                && (3..=4).contains(&rest.len())
                && rest.iter().all(|op| {
                    wallet_sourced(op)
                        && matches!(
                            op.body,
                            OperationBody::SetOptions(_) | OperationBody::ChangeTrust(_)
                        )
                })
        }
        ("fund", [op]) => !wallet_sourced(op) && matches!(op.body, OperationBody::Payment(_)),
        ("withdraw", [op]) => wallet_sourced(op) && matches!(op.body, OperationBody::Payment(_)),
        ("pause" | "resume", [op]) => {
            wallet_sourced(op) && matches!(op.body, OperationBody::SetOptions(_))
        }
        ("close", [rest @ .., merge]) => {
            wallet_sourced(merge)
                && matches!(merge.body, OperationBody::AccountMerge(_))
                && (2..=5).contains(&rest.len())
                && rest.iter().all(|op| {
                    wallet_sourced(op)
                        && matches!(
                            op.body,
                            OperationBody::SetOptions(_)
                                | OperationBody::ChangeTrust(_)
                                | OperationBody::Payment(_)
                        )
                })
        }
        _ => false,
    }
}

/// Match external owner-signed bytes to the exact retained unsigned v1 transaction and digest.
/// This checks one real source-owner signature, not current roles, expiry, source admission or
/// settlement. Fresh broadcast requires independent current authority and validity checks.
pub fn validate_signed_owner_transaction(
    original: &OwnerTransaction,
    signed_xdr: &str,
) -> Result<[u8; 32]> {
    validate_retained_owner_transaction(original)?;
    if original.transaction_xdr.len() > MAX_OWNER_XDR || signed_xdr.len() > MAX_OWNER_XDR {
        return Err("Owner transaction exceeds limit".into());
    }
    let (TransactionEnvelope::Tx(unsigned), TransactionEnvelope::Tx(signed)) =
        (read(&original.transaction_xdr)?, read(signed_xdr)?)
    else {
        return Err("Expected original and signed v1 owner transactions".into());
    };
    if !unsigned.signatures.is_empty() || unsigned.tx != signed.tx {
        return Err("Signed owner transaction differs from the retained original".into());
    }
    let digest = transaction_hash(&original.network, &unsigned.tx)?;
    if digest != original.transaction_hash {
        return Err("Retained owner transaction hash differs".into());
    }
    let MuxedAccount::Ed25519(key) = &unsigned.tx.source_account else {
        return Err("Expected a native G-account owner source".into());
    };
    let [signature] = signed.signatures.as_slice() else {
        return Err("Exactly one source-owner signature is required".into());
    };
    if signature.hint.0 != key.0[28..] {
        return Err("Owner signature hint differs".into());
    }
    signing::verify_digest(
        &ed25519::PublicKey(key.0).to_string(),
        &digest,
        signature.signature.as_slice(),
    )?;
    Ok(digest)
}

/// Independent caller constraints. `next_sequence` is the freshly observed source sequence
/// plus one; `valid_until` is the owner's latest acceptable expiry, not the server's value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerLimits {
    pub network: String,
    pub owner: String,
    pub next_sequence: i64,
    pub max_fee_stroops: u32,
    pub valid_until: u64,
}

/// The owner actions needed to establish, fund and renew native and policy-wallet custody.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OwnerAction {
    /// The hash of the independently reviewed wallet executable. The packet must contain its
    /// exact bytes and declare the supported custody layout.
    UploadWasm { wasm_hash: [u8; 32] },
    /// The complete selected policy installation, constructor and deterministic wallet address.
    /// `config` includes the selected tier, source, params, roles, asset and executable hash.
    CreateWallet {
        config: Box<WalletConfig>,
        salt: [u8; 32],
        x402_enabled: bool,
    },
    /// Exactly one SEP-41 transfer from the selected owner to the selected policy wallet.
    Fund {
        asset: String,
        from: String,
        to: String,
        amount: i128,
    },
    /// Extend exactly the selected policy wallet instance and executable to the caller-observed
    /// network lifetime target. The caller obtains `extend_to` from `rpc::wallet_lifetime`.
    Extend {
        wallet: String,
        wasm_hash: [u8; 32],
        extend_to: u32,
    },
    /// Exactly one `deploy_policy` call on the selected wallet with the complete caller-selected
    /// packet at the caller-observed next version. The packet installs no code and keeps the
    /// owner, so the transaction source alone authorizes it.
    UpdatePolicy {
        wallet: String,
        deployment: Box<admin::PolicyDeployment>,
        version: u64,
    },
    /// The exact creation of one agent's wallet account, reconstructed from the caller-observed
    /// owner account. No server-provided signer or threshold is accepted as expected intent.
    NativeSetup {
        state: AccountState,
        wallet: String,
        agent: String,
        engine: String,
        request_id: String,
        fee_per_operation: u32,
        starting_balance: Option<i64>,
        trustline: Option<owner::Trustline>,
        created_at: u64,
    },
    /// One owner action on a wallet account (fund, pause, resume, withdraw or close),
    /// reconstructed from the caller-observed owner and wallet accounts and the selected roles.
    /// The packet chooses only its fee, within the caller's fee limit, and its expiry.
    Wallet {
        owner_state: AccountState,
        wallet_state: AccountState,
        agent: String,
        engine: String,
        action: owner::WalletAction,
        asset_symbol: String,
        asset_issuer: Option<String>,
    },
}
impl OwnerAction {
    fn name(&self) -> &'static str {
        match self {
            Self::UploadWasm { .. } => "upload_wasm",
            Self::CreateWallet { .. } => "create_wallet",
            Self::Fund { .. } => "fund",
            Self::Extend { .. } => "extend",
            Self::UpdatePolicy { .. } => "update_params",
            Self::NativeSetup { .. } => "native_setup",
            Self::Wallet { action, .. } => action.name(),
        }
    }
}

/// Business intent and envelope constraints selected by the caller before reading a packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpectedOwnerIntent {
    pub limits: OwnerLimits,
    pub action: OwnerAction,
}

/// Sealed, immutable and deliberately not serializable. Only complete native validation can
/// construct this proof. Signing consumes it, and the callback receives only its approved hash.
pub struct ValidatedOwnerTransaction {
    envelope: TransactionV1Envelope,
    unsigned_xdr: String,
    digest: [u8; 32],
    owner: [u8; 32],
    expires_at: u64,
    validated_at: u64,
}
impl ValidatedOwnerTransaction {
    pub fn transaction_hash(&self) -> [u8; 32] {
        self.digest
    }
    pub fn unsigned_xdr(&self) -> &str {
        &self.unsigned_xdr
    }
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
    /// Request one signature for exactly the validated digest. Refuse expired proofs and clock
    /// rollback before calling the capability; verify its Ed25519 result before attachment.
    pub fn sign_with(
        self,
        now: u64,
        sign_hash: impl FnOnce(&[u8; 32]) -> Result<[u8; 64]>,
    ) -> Result<String> {
        self.sign(now, sign_hash, None)
    }
    /// Sign the creation of a wallet account: the owner's signature, then the one signature of
    /// the new account's own key, which the network requires for the operations that the new
    /// account is the source of. The key must be the key of the account that the validated
    /// transaction creates.
    pub fn sign_with_wallet_key(
        self,
        now: u64,
        sign_hash: impl FnOnce(&[u8; 32]) -> Result<[u8; 64]>,
        wallet: &owner::WalletKey,
    ) -> Result<String> {
        let created = self.envelope.tx.operations.first().and_then(|op| {
            let OperationBody::CreateAccount(create) = &op.body else {
                return None;
            };
            let PublicKey::PublicKeyTypeEd25519(key) = &create.destination.0;
            Some(account_for_public_key(&key.0))
        });
        if created.as_deref() != Some(&wallet.account()) {
            return Err("The wallet key differs from the account that this setup creates".into());
        }
        self.sign(now, sign_hash, Some(wallet))
    }
    fn sign(
        mut self,
        now: u64,
        sign_hash: impl FnOnce(&[u8; 32]) -> Result<[u8; 64]>,
        wallet: Option<&owner::WalletKey>,
    ) -> Result<String> {
        if now < self.validated_at || now >= self.expires_at {
            return Err("Validated owner transaction is no longer current".into());
        }
        let signature = sign_hash(&self.digest)?;
        VerifyingKey::from_bytes(&self.owner)
            .map_err(err)?
            .verify_strict(&self.digest, &EdSignature::from_bytes(&signature))
            .map_err(|_| "Owner signing capability returned an invalid signature")?;
        let mut signatures = vec![DecoratedSignature {
            hint: SignatureHint(self.owner[28..].try_into().unwrap()),
            signature: stellar_xdr::Signature(signature.to_vec().try_into().map_err(err)?),
        }];
        if let Some(wallet) = wallet {
            let key = account_key(&wallet.account())?;
            signatures.push(DecoratedSignature {
                hint: SignatureHint(key[28..].try_into().unwrap()),
                signature: stellar_xdr::Signature(
                    wallet
                        .sign_hash(&self.digest)
                        .to_vec()
                        .try_into()
                        .map_err(err)?,
                ),
            });
        }
        self.envelope.signatures = signatures.try_into().map_err(err)?;
        xdr(&TransactionEnvelope::Tx(self.envelope))
    }
}

/// Validate all unsigned transaction bytes and common metadata against independent intent.
/// No signer is called here. Muxed sources, signed envelopes, fee bumps, extra operations,
/// additional address authorizations and unbounded lifetimes are refused.
pub fn validate_owner_transaction(
    packet: &OwnerTransaction,
    expected: &ExpectedOwnerIntent,
    now: u64,
) -> Result<ValidatedOwnerTransaction> {
    let limits = &expected.limits;
    passphrase(&limits.network)?;
    let owner = account_key(&limits.owner)?;
    let latest = now.checked_add(300).ok_or("Owner validity overflow")?;
    if packet.network != limits.network
        || packet.action != expected.action.name()
        || limits.next_sequence <= 0
        || limits.max_fee_stroops < 100
        || packet.expires_at <= now
        || packet.expires_at > latest
        || packet.expires_at > limits.valid_until
        || packet.transaction_xdr.len() > MAX_OWNER_XDR
    {
        return Err("Prepared owner identity, lifetime or size differs from caller intent".into());
    }
    let TransactionEnvelope::Tx(envelope) = read(&packet.transaction_xdr)? else {
        return Err("Expected an unsigned v1 owner transaction".into());
    };
    let tx = &envelope.tx;
    if !envelope.signatures.is_empty()
        || tx.source_account != muxed(&limits.owner)?
        || tx.seq_num.0 != limits.next_sequence
        || tx.fee < 100
        || tx.fee > limits.max_fee_stroops
        || tx.cond
            != Preconditions::Time(TimeBounds {
                min_time: TimePoint(0),
                max_time: TimePoint(packet.expires_at),
            })
        || transaction_hash(&limits.network, tx)? != packet.transaction_hash
        || xdr(&TransactionEnvelope::Tx(envelope.clone()))? != packet.transaction_xdr
    {
        return Err("Prepared owner envelope differs from caller intent".into());
    }
    match &expected.action {
        OwnerAction::NativeSetup { state, .. } => {
            if state.address != limits.owner {
                return Err("Native setup source differs from caller intent".into());
            }
            let exact = exact_native_setup(&expected.action, &limits.network, now)?;
            if packet.transaction_xdr != exact.transaction_xdr
                || packet.transaction_hash != unhex::<32>(&exact.transaction_hash)?
                || packet.expires_at != exact.expires_at
            {
                return Err("Native setup differs from the exact caller-selected template".into());
            }
        }
        OwnerAction::Wallet {
            owner_state,
            wallet_state,
            agent,
            engine,
            action,
            asset_symbol,
            asset_issuer,
        } => {
            if owner_state.address != limits.owner {
                return Err("Wallet action source differs from caller intent".into());
            }
            // The fee and the expiry are the packet's own, within the limits checked above.
            // Every operation is rebuilt from the caller's accounts, roles and action.
            let count = u32::try_from(tx.operations.len()).map_err(err)?;
            if count == 0 || !tx.fee.is_multiple_of(count) {
                return Err("Wallet action fee is not a whole fee per operation".into());
            }
            let created_at = packet
                .expires_at
                .checked_sub(300)
                .ok_or("Wallet action expiry is invalid")?;
            let exact = owner::prepare_wallet_action(
                owner_state,
                wallet_state,
                owner::WalletRoles {
                    wallet: &wallet_state.address,
                    owner: &limits.owner,
                    agent,
                    engine,
                },
                action,
                &asset_from_identity(asset_symbol, asset_issuer.as_deref())?,
                &limits.network,
                tx.fee / count,
                created_at,
            )?;
            if packet != &exact {
                return Err("Wallet action differs from the exact caller-selected roles".into());
            }
        }
        OwnerAction::Extend {
            wallet,
            wasm_hash,
            extend_to,
        } => {
            if *extend_to == 0 || *wasm_hash == [0; 32] || tx.memo != Memo::None {
                return Err("Invalid caller-selected wallet lifetime extension".into());
            }
            Contract::from_string(wallet).map_err(err)?;
            let [operation] = tx.operations.as_slice() else {
                return Err("Expected exactly one wallet lifetime operation".into());
            };
            if operation.source_account.is_some()
                || operation.body
                    != OperationBody::ExtendFootprintTtl(ExtendFootprintTtlOp {
                        ext: ExtensionPoint::V0,
                        extend_to: *extend_to,
                    })
            {
                return Err("Wallet lifetime operation differs from caller intent".into());
            }
            validate_resources(tx)?;
            let TransactionExt::V1(data) = &tx.ext else {
                unreachable!("validated resources");
            };
            let keys = rpc::owner_observation::lifetime_keys(wallet, wasm_hash)?;
            if data.resources.footprint.read_only.as_slice() != keys.as_slice()
                || !data.resources.footprint.read_write.is_empty()
            {
                return Err(
                    "Wallet lifetime footprint differs from the selected instance and code".into(),
                );
            }
        }
        action => {
            if tx.memo != Memo::None {
                return Err("Owner host-function transaction must not carry a memo".into());
            }
            let [operation] = tx.operations.as_slice() else {
                return Err("Expected exactly one owner host-function operation".into());
            };
            if operation.source_account.is_some() {
                return Err("Owner operation must use only its transaction source".into());
            }
            let OperationBody::InvokeHostFunction(invoke) = &operation.body else {
                return Err("Expected an owner host-function operation".into());
            };
            validate_resources(tx)?;
            validate_host(limits, action, invoke)?;
        }
    }
    Ok(ValidatedOwnerTransaction {
        envelope,
        unsigned_xdr: packet.transaction_xdr.clone(),
        digest: packet.transaction_hash,
        owner,
        expires_at: packet.expires_at,
        validated_at: now,
    })
}

fn validate_resources(tx: &Transaction) -> Result<()> {
    let TransactionExt::V1(data) = &tx.ext else {
        return Err("Owner host-function transaction needs simulation resources".into());
    };
    if data.resource_fee < 0
        || u64::try_from(data.resource_fee)
            .map_err(err)?
            .checked_add(100)
            != Some(u64::from(tx.fee))
        || matches!(&data.ext, SorobanTransactionDataExt::V1(v) if !v.archived_soroban_entries.is_empty())
    {
        return Err("Owner resource fee or restoration scope is invalid".into());
    }
    let footprint = &data.resources.footprint;
    if footprint
        .read_only
        .len()
        .saturating_add(footprint.read_write.len())
        > MAX_FOOTPRINT
    {
        return Err("Owner simulation footprint exceeds limit".into());
    }
    let mut seen = std::collections::BTreeSet::new();
    for key in footprint
        .read_only
        .iter()
        .chain(footprint.read_write.iter())
    {
        if !matches!(
            key,
            LedgerKey::Account(_)
                | LedgerKey::Trustline(_)
                | LedgerKey::ContractData(_)
                | LedgerKey::ContractCode(_)
        ) || !seen.insert(key)
        {
            return Err("Owner simulation footprint has an unsupported or duplicate entry".into());
        }
    }
    Ok(())
}

fn validate_host(
    limits: &OwnerLimits,
    action: &OwnerAction,
    invoke: &InvokeHostFunctionOp,
) -> Result<()> {
    match action {
        OwnerAction::UploadWasm { wasm_hash } => {
            let HostFunction::UploadContractWasm(wasm) = &invoke.host_function else {
                return Err("Expected the caller-selected Wasm upload".into());
            };
            if wasm.len() > MAX_WASM
                || *wasm_hash == [0; 32]
                || admin::check_wallet_code(wasm)? != *wasm_hash
                || !invoke.auth.is_empty()
            {
                return Err("Owner upload differs from the reviewed executable".into());
            }
        }
        OwnerAction::CreateWallet {
            config,
            salt,
            x402_enabled,
        } => {
            if config.network != limits.network || config.owner != limits.owner {
                return Err("Wallet configuration differs from caller network or owner".into());
            }
            let constructor = admin::PolicyConfig::for_policy(config, *x402_enabled)?;
            let wallet = admin::wallet_address(&limits.network, &limits.owner, salt)?;
            if wallet != config.wallet
                || [&config.owner, &config.agent, &config.server].contains(&&wallet)
            {
                return Err(
                    "Wallet address differs from the caller-selected creation preimage".into(),
                );
            }
            let exact = HostFunction::CreateContractV2(CreateContractArgsV2 {
                contract_id_preimage: ContractIdPreimage::Address(ContractIdPreimageFromAddress {
                    address: address(&limits.owner)?,
                    salt: Uint256(*salt),
                }),
                executable: ContractExecutable::Wasm(Hash(config.module_digest)),
                constructor_args: constructor.constructor_args()?.try_into().map_err(err)?,
            });
            if invoke.host_function != exact || invoke.auth.len() != 1 {
                return Err("Owner creation differs from the complete selected constructor".into());
            }
            admin::validate_auth(&limits.network, &exact, &invoke.auth, None)?;
        }
        OwnerAction::Fund {
            asset,
            from,
            to,
            amount,
        } => {
            Contract::from_string(asset).map_err(err)?;
            Contract::from_string(to).map_err(err)?;
            if from != &limits.owner || from == to || *amount <= 0 {
                return Err("Owner funding source, destination or amount is invalid".into());
            }
            let exact = HostFunction::InvokeContract(InvokeContractArgs {
                contract_address: address(asset)?,
                function_name: ScSymbol("transfer".try_into().map_err(err)?),
                args: vec![
                    ScVal::Address(address(from)?),
                    ScVal::Address(address(to)?),
                    i128_value(*amount),
                ]
                .try_into()
                .map_err(err)?,
            });
            if invoke.host_function != exact
                || invoke.auth.len() != 1
                || invoke.auth[0].credentials != SorobanCredentials::SourceAccount
            {
                return Err("Owner funding differs from the exact selected transfer".into());
            }
            admin::validate_auth(&limits.network, &exact, &invoke.auth, None)?;
        }
        OwnerAction::UpdatePolicy {
            wallet,
            deployment,
            version,
        } => {
            Contract::from_string(wallet).map_err(err)?;
            if deployment.owner != limits.owner || deployment.wasm_hash.is_some() {
                return Err("Owner update must keep the owner and the installed code".into());
            }
            let exact = HostFunction::InvokeContract(InvokeContractArgs {
                contract_address: address(wallet)?,
                function_name: ScSymbol("deploy_policy".try_into().map_err(err)?),
                args: vec![deployment.scval(allowit_core::admin::DeploymentVersion(*version))?]
                    .try_into()
                    .map_err(err)?,
            });
            if invoke.host_function != exact
                || invoke.auth.len() != 1
                || invoke.auth[0].credentials != SorobanCredentials::SourceAccount
            {
                return Err("Owner update differs from the exact selected policy packet".into());
            }
            admin::validate_auth(&limits.network, &exact, &invoke.auth, None)?;
        }
        OwnerAction::NativeSetup { .. }
        | OwnerAction::Wallet { .. }
        | OwnerAction::Extend { .. } => unreachable!(),
    }
    Ok(())
}

/// Validate every deployment metadata field as well as its complete transaction. This adapter
/// accepts only upload/create intent, so unrelated prepared-operation metadata cannot be reused.
pub fn validate_deployment(
    packet: &admin::PreparedDeployment,
    expected: &ExpectedOwnerIntent,
    now: u64,
) -> Result<ValidatedOwnerTransaction> {
    let (wasm, wallet) = match &expected.action {
        OwnerAction::UploadWasm { wasm_hash } => (*wasm_hash, None),
        OwnerAction::CreateWallet { config, .. } => {
            (config.module_digest, Some(config.wallet.clone()))
        }
        _ => return Err("Expected upload or wallet-creation intent".into()),
    };
    if packet.source != expected.limits.owner
        || packet.wasm_hash != wasm
        || packet.wallet != wallet
        || packet.network != expected.limits.network
        || packet.function != expected.action.name()
        || packet.transaction_xdr.len() > MAX_OWNER_XDR
    {
        return Err("Deployment metadata differs from caller intent".into());
    }
    validate_owner_transaction(
        &OwnerTransaction {
            network: packet.network.clone(),
            action: packet.function.clone(),
            transaction_xdr: packet.transaction_xdr.clone(),
            transaction_hash: packet.transaction_hash,
            expires_at: packet.expires_at,
        },
        expected,
        now,
    )
}

/// The setup that the caller's intent selects, built again from the caller's own values.
fn exact_native_setup(action: &OwnerAction, network: &str, now: u64) -> Result<owner::NativeSetup> {
    let OwnerAction::NativeSetup {
        state,
        wallet,
        agent,
        engine,
        request_id,
        fee_per_operation,
        starting_balance,
        trustline,
        created_at,
    } = action
    else {
        return Err("Expected native setup intent".into());
    };
    if *created_at > now {
        return Err("Native setup creation time differs from caller intent".into());
    }
    owner::prepare_native_setup(
        state,
        &owner::SetupTerms {
            wallet,
            agent,
            engine,
            request_id,
            network,
            fee_per_operation: *fee_per_operation,
            starting_balance: *starting_balance,
            trustline: trustline.as_ref(),
        },
        *created_at,
    )
}

/// Validate the public setup packet's identity digest, metadata and exact native reconstruction
/// before producing signing authority. The expected fresh account and roles remain caller-owned.
pub fn validate_native_setup(
    packet: &owner::NativeSetup,
    expected: &ExpectedOwnerIntent,
    now: u64,
) -> Result<ValidatedOwnerTransaction> {
    if packet.transaction_xdr.len() > MAX_OWNER_XDR {
        return Err("Native setup XDR exceeds limit".into());
    }
    owner::validate_native_setup(packet)?;
    let exact = exact_native_setup(&expected.action, &expected.limits.network, now)?;
    if packet != &exact {
        return Err("Native setup metadata differs from caller intent".into());
    }
    validate_owner_transaction(
        &OwnerTransaction {
            network: packet.network.clone(),
            action: "native_setup".into(),
            transaction_xdr: packet.transaction_xdr.clone(),
            transaction_hash: unhex(&packet.transaction_hash)?,
            expires_at: packet.expires_at,
        },
        expected,
        now,
    )
}

/// Read the immutable digest of a bounded v1 owner envelope. This is identity, not authority.
/// When `require_signature` is true, an absent signature is rejected; callers must still match
/// the exact retained packet with `validate_signed_owner_transaction` before broadcasting.
pub fn owner_envelope_hash(
    network: &str,
    payload: &str,
    require_signature: bool,
) -> Result<[u8; 32]> {
    if payload.len() > MAX_OWNER_XDR {
        return Err("Owner transaction exceeds limit".into());
    }
    let TransactionEnvelope::Tx(envelope) = read(payload)? else {
        return Err("Expected v1 owner transaction".into());
    };
    if require_signature && envelope.signatures.is_empty() {
        return Err("Owner transaction has no signature".into());
    }
    transaction_hash(network, &envelope.tx)
}
