//! Native error classification. Event hints never establish contract authority.
use crate::host::runtime::Problem;
pub use crate::rpc::{ContractFault, simulation_fault};
use serde_json::json;
/// The refusal of a return of funds from a keypair wallet that holds none. Its code is
/// `nothing_to_return`. A caller that returns the funds as one step of a larger owner action
/// reads that code as a step that the ledger already shows.
pub const NOTHING_TO_RETURN: &str = "This wallet holds no funds to return";
/// The same refusal as `admin::OwnerAdmin::recover_funds` words it for a policy wallet.
const NOTHING_TO_RECOVER: &str = "Selected token has no recoverable balance";
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
use allowit_core::{AllowitError as E, AllowitRule as R};
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
        "StaleRequest" => "stale_request",
        _ => "wallet_rejected",
    }
}
/// The code of an `AllowitError` that the policy raised: one recovery for each code. A denial by
/// a rule, or a Custom wallet's own `PolicyDenied`, is `policy_denied`; a value of the policy in
/// the wrong form is `param_invalid`; a call without a price is `call_unpriced`; any other error
/// means that the policy itself failed on this request.
fn policy_code(name: &str, rule: Option<&str>) -> &'static str {
    match (rule, name) {
        (Some(_), _) | (None, "PolicyDenied") => "policy_denied",
        (None, "MissingParam" | "InvalidParam") => "param_invalid",
        (None, "Unpriced") => "call_unpriced",
        _ => "policy_evaluation_failed",
    }
}
fn policy_denied(name: &str, rule: Option<&str>, contract: Option<u32>) -> Problem {
    let code = policy_code(name, rule);
    // Words, not a code: the catalogue test reads each code-shaped literal of this file as a code.
    let what = if code == "policy_denied" {
        "denied this operation"
    } else {
        "could not evaluate this operation"
    };
    let text = match (rule, contract) {
        (Some(rule), _) => format!("The policy {what}: `{rule}` ({name})."),
        (None, Some(contract)) => {
            format!("The policy wallet {what} in simulation: {name} (contract error {contract}).")
        }
        (None, None) => format!("The policy {what}: {name}."),
    };
    coded(409, code, text).with_details(json!({"rule":rule,"error":name,"contractError":contract}))
}
/// A host evaluator's `AllowitError`, by its code: `policy_denied` for a rule's denial.
pub fn rule_denial(code: u32) -> Problem {
    match rule_error(code) {
        Some((name, rule)) => policy_denied(&name, rule, None),
        None => fail(format!("The policy evaluator failed with error {code}.")),
    }
}
/// A client-visible fault for a rejected operation. Only a structured rule denial of the rail
/// core's host evaluation, or a rule error code or `PolicyDenied` that the installed `wallet`
/// itself raised in simulation, becomes `policy_denied`. That is how a Custom wallet denies: it
/// compiles its whole policy and fails with the denying rule's own code, which names the rule.
/// A Custom wallet whose code reports `PolicyDenied` names no rule. `contract`
/// names the wallet only with the proof of `rpc::simulation_fault`. Other wallet contract errors
/// keep their own codes. An error that another contract raised, such as the asset contract or a
/// vault, or whose origin is unknown, is a plain wallet rejection with the raw code. A stale owner
/// observation is `stale_owner_observation`, which a caller can retry once. Anything else stays
/// a plain conflict. An owner address without an account on the ledger is
/// `owner_account_unfunded`, a wallet account without one `wallet_closed`, the server's own
/// sending account without one `service_not_configured`, and another address without one
/// `account_not_found`.
pub fn denial(message: &str, contract: Option<&ContractFault>, wallet: &str) -> Problem {
    if contract.is_none() && message == crate::rpc::owner_observation::STALE_OBSERVATION {
        return coded(409, "stale_owner_observation", message);
    }
    if contract.is_none() && [NOTHING_TO_RETURN, NOTHING_TO_RECOVER].contains(&message) {
        return coded(409, "nothing_to_return", message);
    }
    if contract.is_none() && message == crate::rpc::CONTRACT_EXPIRED {
        return coded(
            409,
            allowit_core::vendor::runtime::CONTRACT_EXPIRED,
            "The wallet lapsed on the network: nothing restores it, and nothing was signed or sent. Its owner restores it outside Allowit.",
        );
    }
    if contract.is_none() && message == crate::rpc::PARAMS_DIFFER {
        return coded(
            409,
            "params_differ_from_wallet",
            "The wallet's params on the ledger are not the ones that its installation stores.",
        );
    }
    if contract.is_none() && message == crate::rpc::ACCOUNT_NOT_FOUND {
        return coded(
            409,
            "account_not_found",
            "The network holds no account for an address of this step: the owner account holds no funds yet, or the wallet account was closed.",
        );
    }
    if contract.is_none() && message == crate::rpc::SENDING_ACCOUNT_NOT_FOUND {
        return coded(409, "service_not_configured", message);
    }
    if contract.is_none() && message == crate::rpc::OWNER_ACCOUNT_NOT_FOUND {
        return coded(409, "owner_account_unfunded", message);
    }
    if contract.is_none() && message == crate::rpc::WALLET_ACCOUNT_NOT_FOUND {
        return coded(409, "wallet_closed", message);
    }
    if contract.is_none() && message == crate::rpc::EXECUTABLE_DIFFERS {
        return coded(
            409,
            allowit_core::vendor::custom_build::code::CODE_HASH_MISMATCH,
            "The wallet's code on the ledger differs from the code of its configuration.",
        );
    }
    let named = contract
        .is_none()
        .then(|| crate::rpc::host_policy_denial(message))
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
    match crate::rpc::WalletError::from_code(code) {
        Some(crate::rpc::WalletError::PolicyDenied) => policy_denied("PolicyDenied", None, Some(code)),
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
    fn a_wallet_whose_params_differ_from_its_installation_has_its_own_code() {
        let problem = denial(crate::rpc::PARAMS_DIFFER, None, "wallet");
        assert_eq!(problem.code, "params_differ_from_wallet");
        assert_eq!(problem.status, 409);
    }
    #[test]
    fn an_error_of_the_policy_has_the_code_of_its_recovery() {
        // A rule's denial is changed by the owner; a value in the wrong form is entered again; a
        // call without a price needs the operator; any other error is a failure of the policy.
        for (error, code) in [
            (E::PaymentLimitExceeded, "policy_denied"),
            (E::DestinationNotAllowed, "policy_denied"),
            (E::MissingParam, "param_invalid"),
            (E::InvalidParam, "param_invalid"),
            (E::Unpriced, "call_unpriced"),
            (E::Panicked, "policy_evaluation_failed"),
            (E::Overflow, "policy_evaluation_failed"),
            (E::InvalidState, "policy_evaluation_failed"),
        ] {
            assert_eq!(rule_denial(error as u32).code, code, "{error:?}");
        }
        assert_eq!(policy_code("PolicyDenied", None), "policy_denied");
    }
    #[test]
    fn a_wallet_with_other_code_than_its_configuration_has_its_own_code() {
        let problem = denial(crate::rpc::EXECUTABLE_DIFFERS, None, "wallet");
        assert_eq!(problem.code, "custom_code_hash_mismatch");
        assert_eq!(problem.status, 409);
    }
    #[test]
    fn an_address_without_an_account_has_its_own_code() {
        let problem = denial(crate::rpc::ACCOUNT_NOT_FOUND, None, "");
        assert_eq!((problem.status, problem.code), (409, "account_not_found"));
        // The server's own sending account is the operator's matter, not the owner's.
        let sending = denial(crate::rpc::SENDING_ACCOUNT_NOT_FOUND, None, "");
        assert_eq!(
            (sending.status, sending.code),
            (409, "service_not_configured")
        );
        // The owner funds a new owner account; a closed wallet needs a new policy.
        let owner = denial(crate::rpc::OWNER_ACCOUNT_NOT_FOUND, None, "");
        assert_eq!((owner.status, owner.code), (409, "owner_account_unfunded"));
        let wallet = denial(crate::rpc::WALLET_ACCOUNT_NOT_FOUND, None, "");
        assert_eq!((wallet.status, wallet.code), (409, "wallet_closed"));
        // A contract's own error with the same text is not the ledger's answer.
        let fault = ContractFault {
            code: 1,
            contract: None,
        };
        assert_ne!(
            denial(crate::rpc::ACCOUNT_NOT_FOUND, Some(&fault), "").code,
            "account_not_found"
        );
    }
    #[test]
    fn a_stale_owner_observation_has_its_own_code() {
        use crate::{host::error::Error, rpc::owner_observation::STALE_OBSERVATION};
        let problem = denial(&Error::config(STALE_OBSERVATION).to_string(), None, "");
        assert_eq!(problem.code, "stale_owner_observation");
        assert_eq!(problem.status, 409);
    }
    #[test]
    fn a_return_from_an_empty_wallet_has_its_own_code() {
        use crate::host::error::Error;
        // The keypair wallet's wording and the policy wallet's wording share the code.
        for message in [NOTHING_TO_RETURN, NOTHING_TO_RECOVER] {
            let problem = denial(&Error::config(message).to_string(), None, "");
            assert_eq!((problem.status, problem.code), (409, "nothing_to_return"));
        }
    }
    /// A host `error` event of the simulation RPC: `contract` raised or relayed `code`.
    fn error_event(contract: [u8; 32], code: u32) -> String {
        use stellar_xdr as x;
        crate::xdr(&x::DiagnosticEvent {
            in_successful_contract_call: false,
            event: x::ContractEvent {
                ext: x::ExtensionPoint::V0,
                contract_id: Some(x::ContractId(x::Hash(contract))),
                type_: x::ContractEventType::Diagnostic,
                body: x::ContractEventBody::V0(x::ContractEventV0 {
                    topics: vec![
                        x::ScVal::Symbol(x::ScSymbol(b"error".to_vec().try_into().unwrap())),
                        x::ScVal::Error(x::ScError::Contract(code)),
                    ]
                    .try_into()
                    .unwrap(),
                    data: x::ScVal::Void,
                }),
            },
        })
        .unwrap()
    }
    /// A Custom wallet compiles its whole policy, so its denial exists only as an error of the
    /// wallet in simulation: the denying rule's own code, or `PolicyDenied` from a wallet whose
    /// code reports no rule. The host events of the reply prove which contract raised it.
    #[test]
    fn a_custom_wallet_denial_is_a_policy_denial_only_with_wallet_provenance() {
        const WALLET: [u8; 32] = [7; 32];
        const FOREIGN: [u8; 32] = [8; 32];
        let wallet = stellar_strkey::Contract(WALLET).to_string();
        let classify = |code: u32, events: &[String]| {
            let message = format!("HostError: Error(Contract, #{code})");
            let fault = simulation_fault(&message, events).unwrap();
            denial(&message, Some(&fault), &wallet)
        };
        // The wallet's policy denied: `PolicyDenied` of the wallet's own error enum.
        let denied = classify(18, &[error_event(WALLET, 18)]);
        assert_eq!(denied.code, "policy_denied");
        assert_eq!(
            denied.details.unwrap(),
            json!({"rule":null,"error":"PolicyDenied","contractError":18})
        );
        // A wallet whose contract reports the rule error itself names the rule.
        let limit = E::PaymentLimitExceeded as u32;
        let named = classify(limit, &[error_event(WALLET, limit)]);
        assert_eq!(named.code, "policy_denied");
        assert_eq!(named.details.unwrap()["rule"], "payment_limit");
        // Another error of the same wallet is a rejection with its own code, never a denial.
        for (code, expected) in [
            (17, "wallet_rejected"),
            (14, "insufficient_funds"),
            (6, "wallet_paused"),
            (5, "stale_request"),
        ] {
            let other = classify(code, &[error_event(WALLET, code)]);
            assert_eq!(other.code, expected, "{code}");
            assert_eq!(other.details.unwrap()["contractError"], code);
        }
        // A code that the wallet's enum does not define is a plain conflict.
        assert_eq!(classify(19, &[error_event(WALLET, 19)]).code, "");
        // The same code from another contract is a rejection: raised by it alone, relayed
        // through the wallet, or without events.
        for events in [
            vec![error_event(FOREIGN, 18)],
            vec![error_event(FOREIGN, 18), error_event(WALLET, 18)],
            vec![],
        ] {
            let foreign = classify(18, &events);
            assert_eq!(foreign.code, "wallet_rejected", "{events:?}");
            assert_eq!(foreign.details.unwrap()["contractError"], 18);
        }
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
