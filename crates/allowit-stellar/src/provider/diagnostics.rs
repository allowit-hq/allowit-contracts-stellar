//! Native error classification. Event hints never establish contract authority.
use crate::host::runtime::Problem;
pub use allowit_stellar_wallet::rpc::{ContractFault, simulation_fault};
use serde_json::json;
fn fail(message: impl Into<String>) -> Problem {
    Problem {
        status: 409,
        code: "",
        message: message.into(),
        details: None,
    }
}
fn coded(status: u16, code: &'static str, message: impl Into<String>) -> Problem {
    Problem {
        status,
        code,
        message: message.into(),
        details: None,
    }
}
trait Details {
    fn with_details(self, value: serde_json::Value) -> Self;
}
impl Details for Problem {
    fn with_details(mut self, value: serde_json::Value) -> Self {
        self.details = Some(value);
        self
    }
}
/// `AllowitError` names, their codes and the canonical rule each one reports.
use allowit::{AllowitError as E, AllowitRule as R};
const RULE_ERRORS: &[(E, Option<R>)] = &[
    (E::MissingParam, None),
    (E::PaymentLimitExceeded, Some(R::payment_limit)),
    (
        E::LifetimeSpendingLimitExceeded,
        Some(R::lifetime_spending_limit),
    ),
    (E::DailySpendingLimitExceeded, Some(R::daily_spending_limit)),
    (E::DailyVolumeLimitExceeded, Some(R::daily_volume_limit)),
    (E::CallLimitExceeded, Some(R::call_limit)),
    (E::DestinationNotAllowed, Some(R::destinations)),
    (E::TokenNotAllowed, Some(R::tokens)),
    (E::Expired, Some(R::expires_at)),
    (E::Unpriced, None),
    (E::InvalidParam, None),
    (E::InvalidState, None),
    (E::Overflow, None),
    (E::Unsupported, None),
    (E::OperationNotAllowed, Some(R::operations)),
    (E::Panicked, None),
];
fn rule_error(code: u32) -> Option<(String, Option<&'static str>)> {
    RULE_ERRORS
        .iter()
        .find(|(error, _)| *error as u32 == code)
        .map(|(error, rule)| (format!("{error:?}"), rule.map(R::key)))
}
/// The client-visible codes of operational wallet contract errors.
fn wallet_error_code(name: &str) -> &'static str {
    match name {
        "Paused" => "wallet_paused",
        "InsufficientFunds" => "insufficient_funds",
        "Replay" | "StaleRequest" => "stale_request",
        _ => "wallet_rejected",
    }
}
fn policy_denied(name: &str, rule: Option<&str>, contract: Option<u32>) -> Problem {
    let text = match (rule, contract) {
        (Some(rule), _) => format!("The policy denied this operation: `{rule}` ({name})."),
        (None, Some(code)) => format!(
            "The policy wallet denied this operation in simulation: {name} (contract error {code})."
        ),
        (None, None) => format!("The policy denied this operation: {name}."),
    };
    coded(409, "policy_denied", text)
        .with_details(json!({"rule":rule,"error":name,"contractError":contract}))
}
/// A host evaluator's `AllowitError`, by its code, as `policy_denied`.
pub fn rule_denial(code: u32) -> Problem {
    match rule_error(code) {
        Some((name, rule)) => policy_denied(&name, rule, None),
        None => fail(format!("The policy evaluator failed with error {code}.")),
    }
}
/// A client-visible fault for a rejected operation. Only a structured rule denial of the rail
/// core's host evaluation, or a rule error code or `PolicyDenied` that the installed `wallet`
/// itself raised in simulation, becomes `policy_denied`. Other wallet contract errors keep their
/// own codes. An error that another contract raised, such as the asset contract or a vault, or
/// whose origin is unknown, is a plain wallet rejection with the raw code. A stale owner
/// observation is `stale_owner_observation`, which a caller can retry once. Anything else stays
/// a plain conflict.
pub fn denial(message: &str, contract: Option<&ContractFault>, wallet: &str) -> Problem {
    if contract.is_none() && message == crate::rpc::owner_observation::STALE_OBSERVATION {
        return coded(409, "stale_owner_observation", message);
    }
    let named = contract
        .is_none()
        .then(|| allowit_stellar_wallet::rpc::host_policy_denial(message))
        .flatten()
        .and_then(|name| {
            RULE_ERRORS
                .iter()
                .find(|(error, _)| format!("{error:?}") == name)
        });
    if let Some((error, rule)) = named {
        return policy_denied(
            &format!("{error:?}"),
            rule.map(R::key),
            contract.map(|c| c.code),
        );
    }
    let Some(fault) = contract else {
        return fail(message.to_string());
    };
    let code = fault.code;
    if fault.contract.as_deref() != Some(wallet) {
        let origin = fault
            .contract
            .as_deref()
            .unwrap_or("an unidentified contract");
        return coded(
            409,
            "wallet_rejected",
            format!("The operation failed in simulation: {origin} raised contract error {code}."),
        )
        .with_details(json!({"contractError":code,"contract":fault.contract}));
    }
    if let Some((name, rule)) = rule_error(code) {
        return policy_denied(&name, rule, Some(code));
    }
    match allowit_stellar_wallet::rpc::WalletError::from_code(code) {
        Some(allowit_stellar_wallet::rpc::WalletError::PolicyDenied) => policy_denied("PolicyDenied", None, Some(code)),
        Some(error) => coded(
            409,
            wallet_error_code(error.name()),
            format!(
                "The policy wallet rejected this operation in simulation: {} (contract error {code}).", error.name()
            ),
        )
        .with_details(json!({"error":error.name(),"contractError":code})),
        None => fail(format!(
            "The policy wallet rejected this operation in simulation with contract error {code}."
        ))
        .with_details(json!({"contractError":code})),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rpc_text_cannot_turn_unknown_contract_provenance_into_a_local_rule_denial() {
        let message = "HostError: Error(Contract, #18)\nPolicy prefix denied: PaymentLimitExceeded";
        let fault = simulation_fault(message, &[]).unwrap();
        assert_eq!(
            denial(message, Some(&fault), "wallet").code,
            "wallet_rejected"
        );
        let local = denial("Policy prefix denied: PaymentLimitExceeded", None, "");
        assert_eq!(local.code, "policy_denied");
        assert!(local.details.unwrap()["contractError"].is_null());
    }
    #[test]
    fn a_stale_owner_observation_has_its_own_code() {
        use crate::{host::error::Error, rpc::owner_observation::STALE_OBSERVATION};
        let problem = denial(&Error::config(STALE_OBSERVATION).to_string(), None, "");
        assert_eq!(problem.code, "stale_owner_observation");
        assert_eq!(problem.status, 409);
    }
    #[test]
    fn only_explicit_wallet_provenance_selects_native_contract_diagnostics() {
        for (code, expected) in [(18, "policy_denied"), (6, "wallet_paused")] {
            let own = ContractFault {
                code,
                contract: Some("wallet".into()),
            };
            assert_eq!(denial("failed", Some(&own), "wallet").code, expected);
            for contract in [None, Some("foreign".into())] {
                let other = ContractFault { code, contract };
                assert_eq!(
                    denial("failed", Some(&other), "wallet").code,
                    "wallet_rejected"
                );
            }
            let actual_rpc = simulation_fault(
                &format!("HostError: Error(Contract, #{code})"),
                &["wallet".into()],
            )
            .unwrap();
            assert!(actual_rpc.contract.is_none());
            assert_eq!(
                denial("failed", Some(&actual_rpc), "wallet").code,
                "wallet_rejected"
            );
        }
    }
}
