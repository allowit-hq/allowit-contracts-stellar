//! Browser bridge to the native owner-intent verifier. No RPC, signer or broadcast.
use crate::owner_intent::{ExpectedOwnerIntent, OwnerAction, OwnerLimits, OwnerTransaction};
use crate::{PolicyLanguage, PolicyParams, PolicyTier, Result, WalletConfig, WalletRoute};
use std::cell::RefCell;

const NETWORK: &str = "stellar:testnet";
const COMMON_WASM_HASH: &str = "30a48ea031932e9458aa46f989e161aacf6d081b14659b94d9f1372597572b1d";
const INPUT_BYTES: usize = 512 * 1024;

thread_local! {
    static INPUT: RefCell<[u8; INPUT_BYTES]> = const { RefCell::new([0; INPUT_BYTES]) };
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Step {
    network: String,
    action: String,
    transaction_xdr: String,
    transaction_hash: String,
    expires_at: u64,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Selection {
    owner: String,
    agent: String,
    server: String,
    policy_instance: String,
    code: String,
    source_hash: String,
    params: PolicyParams,
    wasm_hash: String,
    wallet: Option<String>,
    asset: String,
    max_fee_stroops: u32,
    policy_max_fee_stroops: u32,
    amount: String,
    next_sequence: String,
    valid_until: u64,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Input {
    step: Step,
    expected: Selection,
    now: u64,
    signed_xdr: Option<String>,
}

fn stroops(amount: &str) -> Result<i128> {
    let (whole, fraction) = amount.split_once('.').unwrap_or((amount, ""));
    if whole.is_empty()
        || fraction.len() > 7
        || !whole
            .bytes()
            .chain(fraction.bytes())
            .all(|b| b.is_ascii_digit())
    {
        return Err("Invalid XLM amount".into());
    }
    let whole = whole.parse::<i64>().map_err(crate::err)? as i128;
    let fraction_units = fraction.parse::<i64>().unwrap_or(0) as i128;
    let value = whole * 10_000_000 + fraction_units * 10_i128.pow(7 - fraction.len() as u32);
    if value <= 0 || value > i128::from(i64::MAX) {
        return Err("Invalid XLM amount".into());
    }
    Ok(value)
}

fn verify(input: Input) -> Result<()> {
    let Input {
        step,
        expected,
        now,
        signed_xdr,
    } = input;
    let instance = crate::unhex(&expected.policy_instance)?;
    let salt = crate::admin::wallet_salt(&instance);
    let wallet = crate::admin::wallet_address(NETWORK, &expected.owner, &salt)?;
    let wasm_hash = crate::unhex(&expected.wasm_hash)?;
    let source_hash = crate::unhex(&expected.source_hash)?;
    let native_asset = crate::sac_address(NETWORK, &stellar_xdr::Asset::Native)?;
    if wasm_hash != crate::unhex(COMMON_WASM_HASH)?
        || source_hash != crate::hash(expected.code.as_bytes())
        || expected.asset != native_asset
        || expected
            .wallet
            .as_ref()
            .is_some_and(|selected| selected != &wallet)
    {
        return Err("The owner selection differs from the reviewed draft".into());
    }
    let action = match step.action.as_str() {
        "upload_wasm" => OwnerAction::UploadWasm { wasm_hash },
        "create_wallet" => {
            let tier = PolicyTier::Common;
            let rules = crate::policy::tier_rules(tier, &expected.code)?;
            let source_digest = crate::policy::installed_source_digest(
                tier,
                &wasm_hash,
                &expected.asset,
                &rules,
                &expected.code,
            )?;
            OwnerAction::CreateWallet {
                config: Box::new(WalletConfig {
                    network: NETWORK.into(),
                    policy_instance: instance,
                    wallet,
                    owner: expected.owner.clone(),
                    agent: expected.agent,
                    server: expected.server,
                    route: WalletRoute::PolicyWallet,
                    tier: Some(tier),
                    language: PolicyLanguage::Portable,
                    rules,
                    params: expected.params,
                    source_digest,
                    asset: expected.asset,
                    asset_symbol: "XLM".into(),
                    asset_issuer: None,
                    policy_source: expected.code,
                    source_hash,
                    module_digest: wasm_hash,
                    max_fee_stroops: expected.policy_max_fee_stroops,
                }),
                salt,
                x402_enabled: false,
            }
        }
        "fund" if expected.wallet.is_some() => OwnerAction::Fund {
            asset: expected.asset,
            from: expected.owner.clone(),
            to: wallet,
            amount: stroops(&expected.amount)?,
        },
        _ => return Err("Unsupported browser owner action".into()),
    };
    let packet = OwnerTransaction {
        network: step.network,
        action: step.action,
        transaction_xdr: step.transaction_xdr,
        transaction_hash: crate::unhex(&step.transaction_hash)?,
        expires_at: step.expires_at,
    };
    let intent = ExpectedOwnerIntent {
        limits: OwnerLimits {
            network: NETWORK.into(),
            owner: expected.owner,
            next_sequence: expected.next_sequence.parse().map_err(crate::err)?,
            max_fee_stroops: expected.max_fee_stroops,
            valid_until: expected.valid_until,
        },
        action,
    };
    crate::owner_intent::validate_owner_transaction(&packet, &intent, now)?;
    if let Some(signed) = signed_xdr {
        crate::owner_intent::validate_signed_owner_transaction(&packet, &signed)?;
    }
    Ok(())
}

#[unsafe(no_mangle)]
pub extern "C" fn owner_input() -> *mut u8 {
    INPUT.with(|input| input.borrow_mut().as_mut_ptr())
}

#[unsafe(no_mangle)]
pub extern "C" fn owner_verify(len: usize) -> u32 {
    INPUT.with(|input| {
        let bytes = input.borrow();
        let result = bytes
            .get(..len)
            .ok_or_else(|| "Owner transaction input exceeds the browser limit".to_owned())
            .and_then(|bytes| serde_json::from_slice(bytes).map_err(crate::err))
            .and_then(verify);
        u32::from(result.is_ok())
    })
}
