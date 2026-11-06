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

/// Decode the fee encoded in native simulation resources, without granting settlement authority.
pub fn simulation_resource_fee(data: &str) -> Option<u64> {
    let resources: stellar_xdr::SorobanTransactionData = crate::read(data).ok()?;
    u64::try_from(resources.resource_fee).ok()
}

/// Native wallet contract errors. Core rule errors occupy their separate code range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum WalletError {
    InvalidState = 1,
    InvalidParam = 2,
    UnsupportedAsset = 3,
    InvalidActor = 4,
    StaleRequest = 5,
    Paused = 6,
    Expired = 7,
    InvalidAmount = 8,
    InvalidRecipient = 9,
    Overflow = 11,
    InsufficientFunds = 14,
    InvalidEffects = 15,
    UnsupportedOperation = 16,
    InvalidInvocation = 17,
    PolicyDenied = 18,
    Replay = 19,
}
impl WalletError {
    pub fn from_code(code: u32) -> Option<Self> {
        Some(match code {
            1 => Self::InvalidState,
            2 => Self::InvalidParam,
            3 => Self::UnsupportedAsset,
            4 => Self::InvalidActor,
            5 => Self::StaleRequest,
            6 => Self::Paused,
            7 => Self::Expired,
            8 => Self::InvalidAmount,
            9 => Self::InvalidRecipient,
            11 => Self::Overflow,
            14 => Self::InsufficientFunds,
            15 => Self::InvalidEffects,
            16 => Self::UnsupportedOperation,
            17 => Self::InvalidInvocation,
            18 => Self::PolicyDenied,
            19 => Self::Replay,
            _ => return None,
        })
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::InvalidState => "InvalidState",
            Self::InvalidParam => "InvalidParam",
            Self::UnsupportedAsset => "UnsupportedAsset",
            Self::InvalidActor => "InvalidActor",
            Self::StaleRequest => "StaleRequest",
            Self::Paused => "Paused",
            Self::Expired => "Expired",
            Self::InvalidAmount => "InvalidAmount",
            Self::InvalidRecipient => "InvalidRecipient",
            Self::Overflow => "Overflow",
            Self::InsufficientFunds => "InsufficientFunds",
            Self::InvalidEffects => "InvalidEffects",
            Self::UnsupportedOperation => "UnsupportedOperation",
            Self::InvalidInvocation => "InvalidInvocation",
            Self::PolicyDenied => "PolicyDenied",
            Self::Replay => "Replay",
        }
    }
}
/// Parse only the native host evaluator's denial envelope, without granting contract provenance.
/// The caller resolves the returned name against the shared Core error type.
pub fn host_policy_denial(message: &str) -> Option<&str> {
    [
        "Policy prefix denied: ",
        "Authored policy denied this exact operation: ",
    ]
    .into_iter()
    .find_map(|marker| {
        let rest = &message[message.find(marker)? + marker.len()..];
        let end = rest
            .find(|c: char| !c.is_ascii_alphanumeric())
            .unwrap_or(rest.len());
        (end > 0).then_some(&rest[..end])
    })
}
