//! The owner params update of an installed policy wallet, and ledger verification.
//! The server prepares the update and the owner client reconstructs it from its own document
//! and its own RPC, so both sides derive the same `deploy_policy` packet.
use crate::admin::PolicyDeployment;
use crate::contract::CustodyState;
use crate::host::{
    error::{Error, Result},
    owner::{Comparison, Counters, StateReadback, Verification},
    runtime::ParamsUpdate,
};
use crate::{self as native, PolicyParams, PolicyTier, WalletConfig, WalletRoute, rpc};
use allowit_core::admin::DeploymentVersion;
use allowit_core::vendor::kinds::WalletKind;
use serde_json::json;
use std::collections::BTreeMap;
use stellar_xdr::{
    ContractDataDurability, ContractExecutable, LedgerEntryData, LedgerKey, LedgerKeyContractData,
    ScVal,
};

/// The action name of the owner step of a params update.
pub const ACTION: &str = "update_params";

fn checked<T>(value: native::Result<T>) -> Result<T> {
    value.map_err(crate::provider::failure)
}
fn core_params(
    params: &PolicyParams,
) -> Result<BTreeMap<String, allowit_core::policy::PolicyValue>> {
    params
        .0
        .iter()
        .map(|(key, value)| checked(value.to_core()).map(|value| (key.clone(), value)))
        .collect()
}
/// The installed params with the update applied, checked as the wallet tier checks them.
/// The caller binds `update.policy_id` to this installation: the installation holds no policy id.
pub fn next_params(c: &WalletConfig, update: &ParamsUpdate) -> Result<PolicyParams> {
    let tier = match (&c.route, c.tier) {
        (WalletRoute::PolicyWallet, Some(tier)) => tier,
        _ => {
            return Err(Error::unsupported(
                "A params update needs an installed policy wallet",
            ));
        }
    };
    let next = PolicyParams(
        update
            .apply(&core_params(&c.params)?)?
            .into_iter()
            .map(|(key, value)| {
                native::PolicyValue::from_core(&value)
                    .map(|value| (key, value))
                    .map_err(Error::usage)
            })
            .collect::<Result<_>>()?,
    );
    next.check(tier).map_err(Error::usage)?;
    Ok(next)
}
/// The installation after the update settled: the same wallet, source and identity.
pub fn updated_config(c: &WalletConfig, update: &ParamsUpdate) -> Result<WalletConfig> {
    let mut next = c.clone();
    next.params = next_params(c, update)?;
    checked(native::validate_config(&next))?;
    Ok(next)
}
/// The exact owner packet of an update: the installed roles, source binding and x402 choice
/// with the new params. It installs no code and changes no role.
pub fn deployment(
    c: &WalletConfig,
    update: &ParamsUpdate,
    x402_enabled: bool,
) -> Result<PolicyDeployment> {
    let (deployment, _) = checked(PolicyDeployment::for_source(
        c,
        &c.policy_source,
        next_params(c, update)?,
        x402_enabled,
    ))?;
    Ok(deployment)
}
/// What the ledger holds for the update: the revision it replaces and the x402 choice it keeps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Installed {
    pub revision: u64,
    pub x402_enabled: bool,
}
/// Read the installed revision and check that the wallet still holds this installation: its
/// code, source binding, rules, roles, asset, policy instance and params. The read is the
/// wallet instance alone, so an update needs no account of the agent or the server.
/// A wallet at another revision than the expected one is refused.
pub fn installed(rpc: &dyn rpc::Rpc, c: &WalletConfig, update: &ParamsUpdate) -> Result<Installed> {
    if c.route != WalletRoute::PolicyWallet {
        return Err(Error::unsupported(
            "A params update needs an installed policy wallet",
        ));
    }
    checked(native::validate_config(c))?;
    if checked(rpc.call("getNetwork", json!({})))?["passphrase"]
        != checked(native::passphrase(&c.network))?
    {
        return Err(Error::config(
            "The RPC serves another network than the installation",
        ));
    }
    let (module, state) = wallet_instance(rpc, &c.wallet)?;
    if module != c.module_digest
        || state.source_digest != c.source_digest
        || state.rules != c.rules
        || state.owner != c.owner
        || state.agent != c.agent
        || state.server != c.server
        || state.asset != c.asset
        || state.policy_instance != c.policy_instance
        || state.params != c.params
    {
        return Err(Error::config(
            "The wallet's code, roles or params differ from this installation. Verify the installation first.",
        ));
    }
    let revision = state.deployment_version;
    if update
        .expected_revision
        .is_some_and(|expected| expected != revision)
    {
        return Err(Error::config(format!(
            "The wallet is at configuration revision {revision}, not the expected revision"
        )));
    }
    Ok(Installed {
        revision,
        x402_enabled: state.x402_enabled,
    })
}
/// The target revision of an update over `revision`.
pub fn next_version(revision: u64) -> Result<DeploymentVersion> {
    revision
        .checked_add(1)
        .map(DeploymentVersion)
        .ok_or_else(|| Error::config("Deployment version overflow"))
}

fn kind_of(c: &WalletConfig) -> Option<WalletKind> {
    match (&c.route, c.tier) {
        (WalletRoute::Native, _) => Some(WalletKind::Native),
        (WalletRoute::PolicyWallet, Some(PolicyTier::Simple)) => Some(WalletKind::Simple),
        (WalletRoute::PolicyWallet, Some(PolicyTier::Common)) => Some(WalletKind::Standard),
        (WalletRoute::PolicyWallet, Some(PolicyTier::Custom)) => Some(WalletKind::Custom),
        _ => None,
    }
}
fn ledger_height(rpc: &dyn rpc::Rpc) -> Result<u64> {
    checked(rpc.call("getLatestLedger", json!({})))?["sequence"]
        .as_u64()
        .ok_or_else(|| Error::uncertain("The RPC reported no ledger height"))
}
/// The executable hash and the decoded state of the wallet instance, read without trusting
/// the document: a difference is a result of verification, not a failure of the read.
fn wallet_instance(rpc: &dyn rpc::Rpc, wallet: &str) -> Result<([u8; 32], CustodyState)> {
    let contract = checked(native::address(wallet))?;
    let key = LedgerKey::ContractData(LedgerKeyContractData {
        contract: contract.clone(),
        key: ScVal::LedgerKeyContractInstance,
        durability: ContractDataDurability::Persistent,
    });
    let entries = checked(rpc.call(
        "getLedgerEntries",
        json!({"keys":[checked(native::xdr(&key))?]}),
    ))?;
    let missing = || Error::config("The ledger holds no policy wallet at this address");
    let list = entries["entries"].as_array().ok_or_else(missing)?;
    let [entry] = list.as_slice() else {
        return Err(missing());
    };
    let LedgerEntryData::ContractData(data) =
        checked(native::read(entry["xdr"].as_str().ok_or_else(missing)?))?
    else {
        return Err(missing());
    };
    if data.contract != contract
        || data.key != ScVal::LedgerKeyContractInstance
        || data.durability != ContractDataDurability::Persistent
    {
        return Err(Error::config(
            "The RPC returned another ledger entry than the wallet instance",
        ));
    }
    let ScVal::ContractInstance(instance) = data.val else {
        return Err(missing());
    };
    let ContractExecutable::Wasm(module) = instance.executable else {
        return Err(Error::config(
            "The wallet does not run an uploaded executable",
        ));
    };
    let storage = instance.storage.ok_or_else(missing)?;
    let raw = storage
        .iter()
        .find(|entry| entry.key == ScVal::U32(0))
        .map(|entry| &entry.val)
        .ok_or_else(missing)?;
    Ok((module.0, checked(CustodyState::from_scval(raw))?))
}
/// Compare the owner's installation document with the ledger and read the wallet state back.
/// The read uses the owner's RPC only. A difference is reported, not raised.
pub fn verify(rpc: &dyn rpc::Rpc, policy_id: &str, c: &WalletConfig) -> Result<Verification> {
    checked(native::validate_config(c))?;
    if checked(rpc.call("getNetwork", json!({})))?["passphrase"]
        != checked(native::passphrase(&c.network))?
    {
        return Err(Error::config(
            "The RPC serves another network than the installation",
        ));
    }
    let observed_height = ledger_height(rpc)?;
    let kind = kind_of(c);
    if c.route == WalletRoute::Native {
        // A keypair account holds no policy: the ledger shows the signers, and the server
        // records the usage.
        let account = checked(rpc::get_account(rpc, &c.wallet))?;
        let roles = account.validate_roles(&c.owner, &c.agent, &c.server);
        let comparisons = vec![
            Comparison::new("wallet", json!(c.wallet), json!(account.address)),
            Comparison::new(
                "signers",
                json!("owner, agent and server hold their roles"),
                json!(match &roles {
                    Ok(()) => "owner, agent and server hold their roles".to_owned(),
                    Err(reason) => reason.clone(),
                }),
            ),
        ];
        return Ok(Verification::new(
            policy_id.into(),
            c.network.clone(),
            comparisons,
            StateReadback {
                wallet: c.wallet.clone(),
                wallet_kind: kind,
                revision: 0,
                paused: false,
                counters_from: "server".into(),
                counters: None,
                params: BTreeMap::new(),
                observed_height,
            },
        ));
    }
    if c.route != WalletRoute::PolicyWallet {
        return Err(Error::unsupported(
            "A retired wallet has no ledger verification",
        ));
    }
    let (module, state) = wallet_instance(rpc, &c.wallet)?;
    let params = |params: &PolicyParams| serde_json::to_value(params).unwrap_or(json!(null));
    let bound = module == c.module_digest
        && state.source_digest == c.source_digest
        && state.rules == c.rules;
    let comparisons = vec![
        Comparison::new(
            "executable",
            json!(native::hex(&c.module_digest)),
            json!(native::hex(&module)),
        ),
        Comparison::new(
            "source",
            json!(native::hex(&c.source_digest)),
            json!(native::hex(&state.source_digest)),
        ),
        Comparison::new("rules", json!(c.rules), json!(state.rules)),
        Comparison::new("params", params(&c.params), params(&state.params)),
        // The executable, the source binding and the rules select the wallet kind.
        Comparison::new(
            "walletKind",
            json!(kind),
            json!(bound.then_some(kind).flatten()),
        ),
        Comparison::new("owner", json!(c.owner), json!(state.owner)),
        Comparison::new("agent", json!(c.agent), json!(state.agent)),
        Comparison::new("server", json!(c.server), json!(state.server)),
        Comparison::new("asset", json!(c.asset), json!(state.asset)),
        Comparison::new(
            "policyInstance",
            json!(native::hex(&c.policy_instance)),
            json!(native::hex(&state.policy_instance)),
        ),
    ];
    let counter = |key: &str| match state.policy_state.0.get(key) {
        Some(native::PolicyValue::Int(value)) => Ok(*value),
        None => Ok(0),
        _ => Err(Error::config(format!(
            "The wallet holds an invalid counter `{key}`"
        ))),
    };
    let count = |key: &str| {
        u64::try_from(counter(key)?)
            .map_err(|_| Error::config(format!("The wallet holds an invalid counter `{key}`")))
    };
    Ok(Verification::new(
        policy_id.into(),
        c.network.clone(),
        comparisons,
        StateReadback {
            wallet: c.wallet.clone(),
            wallet_kind: kind,
            revision: state.deployment_version,
            paused: state.paused,
            // Every policy wallet tier commits its usage with each operation, also a Simple
            // wallet, whose rules the server evaluates: the counters are the ledger's.
            counters_from: "ledger".into(),
            counters: Some(Counters {
                spent_total: counter("spent")?,
                spent_daily: counter("day_spent")?,
                spent_day: count("day")?,
                calls: count("calls")?,
                nonce: state.nonce,
            }),
            params: core_params(&state.params)?,
            observed_height,
        },
    ))
}
