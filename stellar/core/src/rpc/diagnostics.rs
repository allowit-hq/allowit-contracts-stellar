//! Terminal native contract errors. Application events and caught calls cannot establish cause.

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContractFault {
    pub code: u32,
    /// Native event/log hints do not prove the terminal invocation's originating contract.
    pub contract: Option<String>,
}
/// Decode only the terminal host error, never a later event or log occurrence.
/// A budget/transport failure remains such a failure even beside earlier contract error events.
/// Invocation provenance is unavailable here, so the result makes no contract attribution.
pub fn simulation_fault(error: &str, _events: &[String]) -> Option<ContractFault> {
    let terminal = error.lines().find(|line| !line.trim().is_empty())?.trim();
    let terminal = terminal.strip_prefix("HostError: ").unwrap_or(terminal);
    let code = terminal
        .strip_prefix("Error(Contract, #")?
        .split_once(')')?
        .0
        .parse::<u32>()
        .ok()?;
    Some(ContractFault {
        code,
        contract: None,
    })
}
