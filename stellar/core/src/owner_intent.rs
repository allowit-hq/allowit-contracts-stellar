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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerTransaction {
    pub network: String,
    pub action: String,
    pub transaction_xdr: String,
    pub transaction_hash: [u8; 32],
    pub expires_at: u64,
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

/// The four owner actions needed to establish and fund native and policy-wallet custody.
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
    /// The exact existing three-operation native setup, reconstructed from a caller-observed
    /// fresh account. No server-provided signer or threshold is accepted as expected intent.
    NativeSetup {
        state: AccountState,
        agent: String,
        engine: String,
        request_id: String,
        fee_per_operation: u32,
        created_at: u64,
    },
}
impl OwnerAction {
    fn name(&self) -> &'static str {
        match self {
            Self::UploadWasm { .. } => "upload_wasm",
            Self::CreateWallet { .. } => "create_wallet",
            Self::Fund { .. } => "fund",
            Self::NativeSetup { .. } => "native_setup",
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
        mut self,
        now: u64,
        sign_hash: impl FnOnce(&[u8; 32]) -> Result<[u8; 64]>,
    ) -> Result<String> {
        if now < self.validated_at || now >= self.expires_at {
            return Err("Validated owner transaction is no longer current".into());
        }
        let signature = sign_hash(&self.digest)?;
        VerifyingKey::from_bytes(&self.owner)
            .map_err(err)?
            .verify_strict(&self.digest, &EdSignature::from_bytes(&signature))
            .map_err(|_| "Owner signing capability returned an invalid signature")?;
        self.envelope.signatures = vec![DecoratedSignature {
            hint: SignatureHint(self.owner[28..].try_into().unwrap()),
            signature: stellar_xdr::Signature(signature.to_vec().try_into().map_err(err)?),
        }]
        .try_into()
        .map_err(err)?;
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
        OwnerAction::NativeSetup {
            state,
            agent,
            engine,
            request_id,
            fee_per_operation,
            created_at,
        } => {
            if state.address != limits.owner || *created_at > now {
                return Err(
                    "Native setup source or creation time differs from caller intent".into(),
                );
            }
            let exact = owner::prepare_native_setup(
                state,
                agent,
                engine,
                request_id,
                &limits.network,
                *fee_per_operation,
                *created_at,
            )?;
            if packet.transaction_xdr != exact.transaction_xdr
                || packet.transaction_hash != unhex::<32>(&exact.transaction_hash)?
                || packet.expires_at != exact.expires_at
            {
                return Err("Native setup differs from the exact caller-selected template".into());
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
        OwnerAction::NativeSetup { .. } => unreachable!(),
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
    let OwnerAction::NativeSetup {
        state,
        agent,
        engine,
        request_id,
        fee_per_operation,
        created_at,
    } = &expected.action
    else {
        return Err("Expected native setup intent".into());
    };
    let exact = owner::prepare_native_setup(
        state,
        agent,
        engine,
        request_id,
        &expected.limits.network,
        *fee_per_operation,
        *created_at,
    )?;
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
