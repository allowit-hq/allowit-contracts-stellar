//! Browser bridge to the native owner-intent verifier. No RPC, signer or broadcast.
use crate::owner_intent::{ExpectedOwnerIntent, OwnerAction, OwnerLimits, OwnerTransaction};
use crate::{PolicyLanguage, PolicyParams, PolicyTier, Result, WalletConfig, WalletRoute};
use std::cell::RefCell;

const NETWORK: &str = "stellar:testnet";
/// SHA-256 of the built Common engine Wasm. `scripts/build-contracts.sh` writes the file.
const COMMON_WASM_HASH: &str =
    include_str!("../allowit_common_policy_engine.wasm.sha256").trim_ascii_end();
const _: () = assert!(COMMON_WASM_HASH.len() == 64);
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
    /// The params update that the owner reviewed. `params` then holds the complete new params.
    #[serde(default)]
    update: Option<Update>,
}

/// The facts of a params update that the host read from the installation: the configuration
/// revision that the update writes and the x402 choice that it keeps.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Update {
    deployment_version: String,
    x402_enabled: bool,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Input {
    step: Step,
    expected: Selection,
    now: u64,
    signed_xdr: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WalletSelection {
    owner: String,
    policy_instance: String,
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

/// The browser has no RPC to observe the network lifetime target, so it reads the target from the
/// step. The owner fee ceiling bounds the rent of any target, and the footprint stays the selected
/// wallet instance and code.
fn extension_target(transaction_xdr: &str) -> Result<u32> {
    use stellar_xdr::{Operation, OperationBody, TransactionEnvelope};
    let TransactionEnvelope::Tx(envelope) = crate::read(transaction_xdr)? else {
        return Err("Expected an unsigned v1 owner transaction".into());
    };
    match envelope.tx.operations.as_slice() {
        [
            Operation {
                body: OperationBody::ExtendFootprintTtl(op),
                ..
            },
        ] => Ok(op.extend_to),
        _ => Err("Expected exactly one wallet lifetime operation".into()),
    }
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
    // The Common installation of the reviewed draft: its source binding, roles and params.
    let installation = |expected: &Selection, wallet: &str| -> Result<WalletConfig> {
        let tier = PolicyTier::Common;
        let rules = crate::policy::tier_rules(tier, &expected.code)?;
        let source_digest = crate::policy::installed_source_digest(
            tier,
            &wasm_hash,
            &expected.asset,
            &rules,
            &expected.code,
        )?;
        Ok(WalletConfig {
            network: NETWORK.into(),
            policy_instance: instance,
            wallet: wallet.into(),
            owner: expected.owner.clone(),
            agent: expected.agent.clone(),
            server: expected.server.clone(),
            route: WalletRoute::PolicyWallet,
            tier: Some(tier),
            language: PolicyLanguage::Portable,
            rules,
            params: expected.params.clone(),
            source_digest,
            asset: expected.asset.clone(),
            asset_symbol: "XLM".into(),
            asset_issuer: None,
            policy_source: expected.code.clone(),
            source_hash,
            module_digest: wasm_hash,
            max_fee_stroops: expected.policy_max_fee_stroops,
        })
    };
    // A selection that reviews a params update admits that step alone.
    if expected.update.is_some() && step.action != "update_params" {
        return Err("The owner selection reviews a params update only".into());
    }
    let action = match step.action.as_str() {
        "upload_wasm" => OwnerAction::UploadWasm { wasm_hash },
        "create_wallet" => OwnerAction::CreateWallet {
            config: Box::new(installation(&expected, &wallet)?),
            salt,
            x402_enabled: false,
        },
        // The packet keeps the installed roles, source binding and code and holds the complete
        // new params at the revision that the host read.
        "update_params" if expected.wallet.is_some() && expected.update.is_some() => {
            let update = expected.update.as_ref().ok_or("Missing update selection")?;
            let config = installation(&expected, &wallet)?;
            let (deployment, _) = crate::admin::PolicyDeployment::for_source(
                &config,
                &config.policy_source,
                config.params.clone(),
                update.x402_enabled,
            )?;
            OwnerAction::UpdatePolicy {
                wallet,
                deployment: Box::new(deployment),
                version: update
                    .deployment_version
                    .parse::<u64>()
                    .ok()
                    .filter(|version| {
                        *version > 0 && version.to_string() == update.deployment_version
                    })
                    .ok_or("Invalid update revision")?,
            }
        }
        "fund" if expected.wallet.is_some() => OwnerAction::Fund {
            asset: expected.asset,
            from: expected.owner.clone(),
            to: wallet,
            amount: stroops(&expected.amount)?,
        },
        "extend" if expected.wallet.is_some() => OwnerAction::Extend {
            wallet,
            wasm_hash,
            extend_to: extension_target(&step.transaction_xdr)?,
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

#[unsafe(no_mangle)]
pub extern "C" fn owner_wallet(len: usize) -> usize {
    INPUT.with(|input| {
        let mut bytes = input.borrow_mut();
        let result = bytes
            .get(..len)
            .ok_or_else(|| "Owner selection exceeds the browser limit".to_owned())
            .and_then(|value| serde_json::from_slice::<WalletSelection>(value).map_err(crate::err))
            .and_then(|selection| {
                crate::account_key(&selection.owner)?;
                let instance = crate::unhex(&selection.policy_instance)?;
                crate::admin::wallet_address(
                    NETWORK,
                    &selection.owner,
                    &crate::admin::wallet_salt(&instance),
                )
            });
        if let Ok(wallet) = result {
            bytes[..wallet.len()].copy_from_slice(wallet.as_bytes());
            wallet.len()
        } else {
            0
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::owner::{account, update_step};
    const NOW: u64 = 1_800_000_000;
    const CODE: &str = "use allowit::prelude::*;\npub fn execute(ctx: &AllowitContext) -> allowit::Result {\n    allowit::payment_limit(ctx, &ctx.params[allowit::PAYMENT_LIMIT])?;\n    Ok(())\n}\n";
    /// The selection of a Common wallet whose owner changes its payment limit to `limit`.
    fn selection(limit: i64, version: &str) -> serde_json::Value {
        let instance = [4; 32];
        let owner = account(11);
        serde_json::json!({
            "owner": owner, "agent": account(12), "server": account(13),
            "policyInstance": crate::hex(&instance), "code": CODE,
            "sourceHash": crate::hex(&crate::hash(CODE.as_bytes())),
            "params": {"payment_limit": {"Int": limit.to_string()}},
            "wasmHash": COMMON_WASM_HASH,
            "wallet": crate::admin::wallet_address(NETWORK, &owner, &crate::admin::wallet_salt(&instance)).unwrap(),
            "asset": crate::sac_address(NETWORK, &stellar_xdr::Asset::Native).unwrap(),
            "maxFeeStroops": 10_000, "policyMaxFeeStroops": 1_000_000, "amount": "1",
            "nextSequence": "42", "validUntil": NOW + 300,
            "update": {"deploymentVersion": version, "x402Enabled": false},
        })
    }
    /// The step that a server prepares for that selection.
    fn step(limit: i64, version: u64) -> serde_json::Value {
        let expected: Selection = serde_json::from_value(selection(limit, "2")).unwrap();
        let config = WalletConfig {
            network: NETWORK.into(),
            policy_instance: [4; 32],
            wallet: expected.wallet.clone().unwrap(),
            owner: expected.owner.clone(),
            agent: expected.agent.clone(),
            server: expected.server.clone(),
            route: WalletRoute::PolicyWallet,
            tier: Some(PolicyTier::Common),
            language: PolicyLanguage::Portable,
            rules: crate::policy::tier_rules(PolicyTier::Common, CODE).unwrap(),
            params: expected.params.clone(),
            source_digest: [0; 32],
            asset: expected.asset.clone(),
            asset_symbol: "XLM".into(),
            asset_issuer: None,
            policy_source: CODE.into(),
            source_hash: crate::hash(CODE.as_bytes()),
            module_digest: crate::unhex(COMMON_WASM_HASH).unwrap(),
            max_fee_stroops: 1_000_000,
        };
        let (deployment, _) =
            crate::admin::PolicyDeployment::for_source(&config, CODE, config.params.clone(), false)
                .unwrap();
        let step = update_step(&config, &deployment, version, NOW);
        serde_json::json!({
            "network": step["network"], "action": step["action"],
            "transactionXdr": step["payload"], "transactionHash": step["transactionHash"],
            "expiresAt": step["expiresAt"],
        })
    }
    fn check(step: serde_json::Value, expected: serde_json::Value) -> Result<()> {
        verify(
            serde_json::from_value(
                serde_json::json!({"step": step, "expected": expected, "now": NOW}),
            )
            .map_err(crate::err)?,
        )
    }
    #[test]
    fn the_browser_verifier_binds_a_params_update_to_the_reviewed_values_and_revision() {
        check(step(20_000_000, 2), selection(20_000_000, "2")).unwrap();
        // Another value, another revision, another x402 choice or another wallet differs.
        assert!(check(step(90_000_000, 2), selection(20_000_000, "2")).is_err());
        assert!(check(step(20_000_000, 3), selection(20_000_000, "2")).is_err());
        let mut x402 = selection(20_000_000, "2");
        x402["update"]["x402Enabled"] = true.into();
        assert!(check(step(20_000_000, 2), x402).is_err());
        let mut other = selection(20_000_000, "2");
        other["policyInstance"] = crate::hex(&[5; 32]).into();
        other["wallet"] = serde_json::Value::Null;
        assert!(check(step(20_000_000, 2), other).is_err());
        // An update step needs the update facts and a canonical revision.
        let mut plain = selection(20_000_000, "2");
        plain.as_object_mut().unwrap().remove("update");
        assert!(check(step(20_000_000, 2), plain).is_err());
        for revision in ["0", "02", "two"] {
            assert!(check(step(20_000_000, 2), selection(20_000_000, revision)).is_err());
        }
        // A funding transfer under the update action is refused, and an update selection
        // admits no funding step: the exact transfer verifies only without the update facts.
        let mut transfer = step(20_000_000, 2);
        transfer["action"] = "fund".into();
        assert!(check(transfer, selection(20_000_000, "2")).is_err());
        let expected: Selection = serde_json::from_value(selection(20_000_000, "2")).unwrap();
        let config = WalletConfig {
            network: NETWORK.into(),
            policy_instance: [4; 32],
            wallet: expected.wallet.clone().unwrap(),
            owner: expected.owner.clone(),
            agent: expected.agent.clone(),
            server: expected.server.clone(),
            route: WalletRoute::PolicyWallet,
            tier: Some(PolicyTier::Common),
            language: PolicyLanguage::Portable,
            rules: vec![],
            params: expected.params.clone(),
            source_digest: [1; 32],
            asset: expected.asset.clone(),
            asset_symbol: "XLM".into(),
            asset_issuer: None,
            policy_source: CODE.into(),
            source_hash: crate::hash(CODE.as_bytes()),
            module_digest: crate::unhex(COMMON_WASM_HASH).unwrap(),
            max_fee_stroops: 1_000_000,
        };
        let funding = crate::test_support::owner::fund_step(&config, 10_000_000, NOW);
        let funding = serde_json::json!({
            "network": funding["network"], "action": funding["action"],
            "transactionXdr": funding["payload"], "transactionHash": funding["transactionHash"],
            "expiresAt": funding["expiresAt"],
        });
        let mut reviewed = selection(20_000_000, "2");
        assert!(check(funding.clone(), reviewed.clone()).is_err());
        reviewed.as_object_mut().unwrap().remove("update");
        check(funding, reviewed).unwrap();
    }
}
