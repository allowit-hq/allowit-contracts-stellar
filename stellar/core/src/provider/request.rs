//! Builds the typed request of one `exec` operation with the request builders
//! of `allowit-stellar-wallet`. A transfer moves the wallet's asset to a G or C
//! address. A policy wallet also deposits its asset into a SEP-56 vault for a
//! minimum of shares, and redeems vault shares for a minimum of its asset.
use super::typed::TypedRequest;
use crate::host::{
    error::{Error, Result},
    execution::Request as ExecRequest,
    input::asset::{Amount, Asset},
    typed_request::operation_nonce,
};
use allowit_stellar_wallet::workflow::{AccountKind, ExecutionRequest};
use allowit_stellar_wallet::{self as sdk, AccountState, TrustedState, WalletConfig, WalletRoute};

/// Checks the operation flags alone, before any profile, journal or network
/// access.
pub fn check(op: &str, to: &str, token_out: Option<&Amount>, args: bool) -> Result<()> {
    if args {
        return Err(Error::usage("--args applies to custom operations"));
    }
    let vault = sdk::request::account(to).is_ok_and(|a| a.kind == AccountKind::Contract);
    match (op, token_out) {
        ("transfer", None) => Ok(()),
        ("transfer", Some(_)) => Err(Error::usage(
            "--token-out applies to swap, deposit and redeem, not transfer",
        )),
        ("deposit" | "redeem", _) if !vault => Err(Error::usage(format!(
            "a {op} goes to a C… vault contract, not {to}"
        ))),
        ("deposit", None) => Err(Error::usage(
            "a deposit needs --token-out MIN_SHARES, the fewest vault shares to receive",
        )),
        ("redeem", None) => Err(Error::usage(
            "a redeem needs --token-out ASSET:MIN, the least of the wallet asset to receive",
        )),
        ("redeem", Some(min)) if min.units() == 0 => Err(Error::usage(
            "a redeem needs a positive --token-out minimum",
        )),
        ("deposit" | "redeem", Some(_)) => Ok(()),
        _ => Err(Error::unsupported(format!(
            "exec --op {op} is not available on Stellar yet"
        ))),
    }
}

/// The typed request of one checked operation. Amounts are checked against the
/// installed asset before `state` is read.
pub fn build(
    policy_id: &str,
    config: &WalletConfig,
    r: &ExecRequest,
    state: impl FnOnce() -> Result<TrustedState>,
) -> Result<TypedRequest> {
    let minimum = || {
        r.token_out
            .as_ref()
            .ok_or_else(|| Error::usage(format!("a {} needs --token-out", r.op)))
    };
    if config.route == WalletRoute::Native && r.op != "transfer" {
        return Err(Error::unsupported(format!(
            "a classic Stellar wallet only transfers; a {} needs a policy wallet",
            r.op
        )));
    }
    let (amount, min) = match r.op.as_str() {
        "transfer" => (installed_units(config, &r.amount)?, 0),
        "deposit" => (installed_units(config, &r.amount)?, shares(minimum()?)?),
        "redeem" => (shares(&r.amount)?, installed_units(config, minimum()?)?),
        op => {
            return Err(Error::unsupported(format!(
                "exec --op {op} is not available on Stellar yet"
            )));
        }
    };
    let state = state()?;
    let id = operation_nonce(policy_id, &r.request_id);
    let request = match r.op.as_str() {
        "transfer" => sdk::request::transfer(config, &state, id, &r.to, amount),
        "deposit" => sdk::request::deposit(config, &state, id, &r.to, amount, min),
        _ => sdk::request::redeem(config, &state, id, &r.to, amount, min),
    }
    .map_err(|e| Error::usage(format!("the {} does not fit this wallet: {e}", r.op)))?;
    TypedRequest::new(policy_id, &r.request_id, request)
}

/// The request of a retried request ID: rebuilt from its flags with the
/// retained fee bounds. The fee payer was chain state at the first attempt, so
/// the journal compares only the operator's intent, and a retry reads no RPC.
pub fn rebuild(
    policy_id: &str,
    config: &WalletConfig,
    r: &ExecRequest,
    retained: &ExecutionRequest,
) -> Result<TypedRequest> {
    let mut typed = build(policy_id, config, r, || Ok(profile_state(config)))?;
    typed.request.fee_bounds.clone_from(&retained.fee_bounds);
    Ok(typed)
}

/// The chain state that the builders read: the fee payer. A policy wallet pays
/// fees from its current agent account, which Stellar RPC reports. Classic
/// custody pays them from the wallet and the builders read no state for it, so
/// the profile fills it; the engine checks every request against its own.
pub fn state(c: &WalletConfig, rpc_url: Option<&str>) -> Result<TrustedState> {
    if c.route == WalletRoute::Native {
        return Ok(profile_state(c));
    }
    let url = rpc_url.filter(|u| !u.is_empty()).ok_or_else(|| {
        Error::config(
            "a policy wallet request names its current agent account from Stellar RPC; pass --rpc-url URL or set rpc_url for this rail",
        )
    })?;
    let rpc = sdk::rpc::HttpRpc::new(url).map_err(Error::config)?;
    sdk::rpc::trusted_state_for_discovery(&rpc, c, None)
        .map(|found| found.state)
        .map_err(Error::config)
}

/// The profile's view of the state: the configured agent account pays.
fn profile_state(c: &WalletConfig) -> TrustedState {
    TrustedState {
        contract_version: None,
        policy_state: None,
        source: AccountState {
            address: c.agent.clone(),
            sequence: 0,
            master_weight: 0,
            low_threshold: 0,
            medium_threshold: 0,
            high_threshold: 0,
            signers: vec![],
        },
        nonce: 0,
        deployment_version: 0,
        spent_daily: 0,
        spent_total: 0,
        spent_day: 0,
        calls: 0,
        ledger: 0,
        module_digest: c.module_digest,
        source_hash: c.source_hash,
        owner: c.owner.clone(),
        agent: c.agent.clone(),
        server: c.server.clone(),
        policy_instance: c.policy_instance,
    }
}

/// Checks that the amount names the wallet's installed asset and returns its
/// base units.
pub fn installed_units(config: &WalletConfig, amount: &Amount) -> Result<i128> {
    let matches = match &amount.asset {
        Asset::Installed => true,
        Asset::Native { .. } => config.asset_symbol == "XLM" && config.asset_issuer.is_none(),
        Asset::Token { code, issuer } => {
            *code == config.asset_symbol
                && issuer
                    .as_deref()
                    .is_none_or(|i| Some(i) == config.asset_issuer.as_deref())
        }
        Asset::Contract(contract) => *contract == config.asset,
    };
    if !matches {
        return Err(Error {
            code: 4,
            message: format!(
                "the wallet holds only its installed asset {}; {} names another asset",
                config.asset_symbol, amount.text
            ),
            status: None,
            config: false,
        });
    }
    units(amount)
}

/// Vault shares: INTEGER base units, never a named asset.
fn shares(amount: &Amount) -> Result<i128> {
    if amount.asset != Asset::Installed {
        return Err(Error::usage(format!(
            "{} is not a share amount; vault shares are INTEGER base units",
            amount.text
        )));
    }
    units(amount)
}

fn units(amount: &Amount) -> Result<i128> {
    let units = amount.units();
    i128::try_from(units).map_err(|_| Error::usage("the amount is too large"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn a_classic_wallet_moves_only_its_installed_asset() {
        let retained: sdk::SignedOperation = serde_json::from_str(include_str!(
            "../../tests/fixtures/provider/canonical-main-9682-native-signed.json"
        ))
        .unwrap();
        let mut c = retained.prepared.config;
        c.asset_symbol = "XLM".into();
        c.asset_issuer = None;
        c.asset = sdk::sac_address(&c.network, &stellar_xdr::Asset::Native).unwrap();
        let xlm = Amount {
            asset: Asset::Native { code: "XLM".into() },
            quantity: 50_000_000,
            decimals: Some(7),
            text: "XLM:5".into(),
        };
        assert_eq!(installed_units(&c, &xlm).unwrap(), 50_000_000);
        let usdc = Amount {
            asset: Asset::Token {
                code: "USDC".into(),
                issuer: None,
            },
            quantity: 10_000_000,
            decimals: Some(7),
            text: "USDC:1".into(),
        };
        assert_eq!(installed_units(&c, &usdc).unwrap_err().code, 4);
        let request = ExecRequest {
            op: "deposit".into(),
            to: sdk::sac_address(
                "stellar:testnet",
                &sdk::asset_from_identity("VLT", Some(&sdk::account_for_seed(&[21; 32]))).unwrap(),
            )
            .unwrap(),
            amount: xlm,
            token_out: Some(Amount {
                asset: Asset::Installed,
                quantity: 4_900_000,
                decimals: None,
                text: "4900000".into(),
            }),
            args: None,
            request_id: "request-0001".into(),
            wait: std::time::Duration::ZERO,
            build_only: true,
            wallet: None,
        };
        let error = build("policy-1", &c, &request, || unreachable!()).unwrap_err();
        assert_eq!(error.code, 3, "{}", error.message);
    }
}
