//! Native contract-error decoding. Caller policy maps these observations to user actions.
use crate::*;
/// The contract error that rejected a simulation: its code and the contract that raised it
/// first. A contract that a failed call reaches, such as the asset contract or a vault, raises
/// the error; each calling frame then repeats the same code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContractFault {
    pub code: u32,
    /// The originating contract, or `None` when the reply does not identify it.
    pub contract: Option<String>,
}
const CONTRACT_ERROR: &str = "Error(Contract, #";
fn error_code(text: &str) -> Option<u32> {
    let start = text.find(CONTRACT_ERROR)? + CONTRACT_ERROR.len();
    text[start..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>()
        .parse()
        .ok()
}
/// The first contract error event of a simulation's diagnostic events, which Stellar RPC
/// returns in emission order.
fn first_error_event(events: &[String]) -> Option<ContractFault> {
    events.iter().find_map(|event| {
        let event: stellar_xdr::DiagnosticEvent = read(event).ok()?;
        let stellar_xdr::ContractEventBody::V0(body) = &event.event.body;
        let [
            ScVal::Symbol(name),
            ScVal::Error(stellar_xdr::ScError::Contract(code)),
            ..,
        ] = body.topics.as_slice()
        else {
            return None;
        };
        if name.0.as_slice() != b"error" {
            return None;
        }
        let contract = event
            .event
            .contract_id
            .as_ref()
            .and_then(|id| address_text(&stellar_xdr::ScAddress::Contract(id.clone())).ok());
        Some(ContractFault {
            code: *code,
            contract,
        })
    })
}
/// The oldest contract error line of the host's event log text, which lists events newest
/// first, as `contract:C..., topics:[error, Error(Contract, #N)]`.
fn oldest_logged_error(text: &str) -> Option<ContractFault> {
    text.lines()
        .rev()
        .filter(|line| line.contains("topics:[error, Error(Contract, #"))
        .filter_map(|line| {
            let code = error_code(line)?;
            let contract = line
                .split_once("contract:")
                .map(|(_, rest)| rest.split([',', ' ']).next().unwrap_or_default())
                .filter(|id| id.starts_with('C'))
                .map(str::to_owned);
            Some(ContractFault { code, contract })
        })
        .next()
}
/// The contract error of a rejected simulation reply. Structured diagnostic events identify
/// the originating contract; the event log text is the fallback. Without either, only the
/// code is known.
pub fn simulation_fault(error: &str, events: &[String]) -> Option<ContractFault> {
    first_error_event(events)
        .or_else(|| oldest_logged_error(error))
        .or_else(|| {
            error_code(error).map(|code| ContractFault {
                code,
                contract: None,
            })
        })
}
