//! Canonical execution requests of the operations this crate maps. Each builder returns the
//! `ExecutionRequest` that [`operation_from_request`] decodes, so a client sends exactly what the
//! service checks. Classic custody pays fees from the wallet account. A policy wallet pays them
//! from its current agent account, the transaction source in the trusted state, which can differ
//! from the configured customer signer.
use crate::*;
use allowit_policy_sdk::typed_workflow::{
    AssetId, OperationRef, WorkflowEffectBound, WorkflowFeeBound,
};

/// A canonical G account or C contract as a workflow account.
pub fn account(value: &str) -> Result<WorkflowAccount> {
    let key = Strkey::from_string(value).map_err(err)?;
    let (kind, address) = match &key {
        Strkey::PublicKeyEd25519(k) => (AccountKind::Wallet, k.0),
        Strkey::Contract(c) => (AccountKind::Contract, c.0),
        _ => return Err("Only canonical G and C addresses are admitted".into()),
    };
    if key.to_string() != value {
        return Err("Only canonical G and C addresses are admitted".into());
    }
    Ok(WorkflowAccount {
        chain: Chain::Stellar,
        kind,
        address,
    })
}

/// A transfer of `amount` of the wallet asset to `to`: a native payment of XLM, or a SEP-41
/// `transfer` of an issued asset.
pub fn transfer(
    c: &WalletConfig,
    state: &TrustedState,
    operation_id: [u8; 32],
    to: &str,
    amount: i128,
) -> Result<ExecutionRequest> {
    let wallet = account(&c.wallet)?;
    let (instruction, asset) = if asset_xdr(c)? == Asset::Native {
        let instruction = NativeInstruction::StellarNativeTransfer {
            source: wallet,
            destination: account(to)?,
            stroops: u64::try_from(amount).map_err(|_| "Transfer amount must be positive")?,
        };
        (instruction, native_xlm(c)?)
    } else {
        let arguments = vec![
            AbiValue::Account(wallet),
            AbiValue::Account(account(to)?),
            AbiValue::Signed128(amount),
        ];
        (call(&c.asset, "transfer", arguments)?, token(c, &c.asset)?)
    };
    request(c, state, operation_id, instruction, asset, to, amount)
}

/// A SEP-56 deposit of `assets` of the wallet asset into `vault` for at least `min_shares`.
/// Policy wallets only.
pub fn deposit(
    c: &WalletConfig,
    state: &TrustedState,
    operation_id: [u8; 32],
    vault: &str,
    assets: i128,
    min_shares: i128,
) -> Result<ExecutionRequest> {
    let instruction = call(vault, "deposit", sep56(c, assets, min_shares)?)?;
    request(
        c,
        state,
        operation_id,
        instruction,
        token(c, &c.asset)?,
        vault,
        assets,
    )
}

/// A SEP-56 redeem of `shares` of `vault` for at least `min_assets` of the wallet asset. Its
/// effect bound is on the vault's share token. Policy wallets only.
pub fn redeem(
    c: &WalletConfig,
    state: &TrustedState,
    operation_id: [u8; 32],
    vault: &str,
    shares: i128,
    min_assets: i128,
) -> Result<ExecutionRequest> {
    let instruction = call(vault, "redeem", sep56(c, shares, min_assets)?)?;
    request(
        c,
        state,
        operation_id,
        instruction,
        token(c, vault)?,
        vault,
        shares,
    )
}

/// SEP-56 `(amount, receiver, holder, operator)` with the wallet as every party, then the
/// wallet's minimum output.
fn sep56(c: &WalletConfig, amount: i128, minimum: i128) -> Result<Vec<AbiValue>> {
    let wallet = AbiValue::Account(account(&c.wallet)?);
    Ok(vec![
        AbiValue::Signed128(amount),
        wallet.clone(),
        wallet.clone(),
        wallet,
        AbiValue::Signed128(minimum),
    ])
}

/// A Stellar call. The service identifies it by its contract, function and typed arguments, so
/// the schema digest stays zero.
fn call(contract: &str, function: &str, arguments: Vec<AbiValue>) -> Result<NativeInstruction> {
    Ok(NativeInstruction::StellarCall {
        contract: account(contract)?,
        schema_digest: [0; 32],
        function: function.into(),
        arguments,
    })
}

fn native_xlm(c: &WalletConfig) -> Result<WorkflowAsset> {
    Ok(WorkflowAsset::Native {
        chain: Chain::Stellar,
        network: network_id(&c.network)?,
    })
}

fn token(c: &WalletConfig, token: &str) -> Result<WorkflowAsset> {
    Ok(WorkflowAsset::Token(AssetId {
        network: network_id(&c.network)?,
        token: account(token)?,
    }))
}

fn units(value: i128) -> Result<Amount256> {
    let value = u128::try_from(value).map_err(|_| "Amounts must be positive")?;
    let mut bytes = [0; 32];
    bytes[16..].copy_from_slice(&value.to_be_bytes());
    Ok(Amount256(bytes))
}

/// One request whose `instruction` debits exactly `amount` of `asset` from the wallet to
/// `beneficiary`, within the installed fee bound paid by the trusted fee payer. It returns only a request that decodes.
fn request(
    c: &WalletConfig,
    state: &TrustedState,
    operation_id: [u8; 32],
    instruction: NativeInstruction,
    asset: WorkflowAsset,
    beneficiary: &str,
    amount: i128,
) -> Result<ExecutionRequest> {
    let wallet = account(&c.wallet)?;
    let payer = if c.route == WalletRoute::Native {
        wallet.clone()
    } else {
        account(&state.source.address)?
    };
    let request = ExecutionRequest {
        operation: OperationRef {
            policy_instance: c.policy_instance,
            nonce: operation_id,
        },
        input: ExecutionInput::Instructions(vec![instruction]),
        effect_bounds: vec![WorkflowEffectBound {
            asset,
            source: wallet,
            beneficiary: account(beneficiary)?,
            max_debit: units(amount)?,
            min_credit: units(amount)?,
            max_burn: 0u64.into(),
        }],
        fee_bounds: Some(vec![WorkflowFeeBound {
            payer,
            asset: native_xlm(c)?,
            max_fee: u64::from(c.max_fee_stroops).into(),
        }]),
        evidence: vec![],
    };
    operation_from_request(c, &request)?;
    Ok(request)
}
