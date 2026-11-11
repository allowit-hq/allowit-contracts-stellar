//! Terminal native contract errors. Application events and caught calls cannot establish cause.
use stellar_xdr::{
    ContractEventBody, ContractEventType, DiagnosticEvent, HostFunction, OperationBody, ScAddress,
    ScError, ScVal, TransactionEnvelope,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContractFault {
    pub code: u32,
    /// The contract that raised `code`, when the host's diagnostic events prove one origin.
    pub contract: Option<String>,
}
/// Decode only the terminal host error, never a later event or log occurrence.
/// A budget/transport failure remains such a failure even beside earlier contract error events.
/// The contract attribution follows [`raising_contract`]; without that proof it stays empty.
pub fn simulation_fault(error: &str, events: &[String]) -> Option<ContractFault> {
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
        contract: raising_contract(code, events),
    })
}

/// The one contract that raised contract error `code`, proved by the host's diagnostic events
/// of the simulation (`events` of the RPC reply, each a base64 `DiagnosticEvent`).
///
/// The host records an `error` event of type `Diagnostic` in the frame of every contract that
/// raises or relays a contract error, with that contract's id. A contract cannot write such an
/// event: its own events have type `Contract`, and its log lines carry the `log` topic. So a
/// foreign contract that raised `code` always appears under its own id, and a relay through the
/// wallet shows two ids. The proof therefore needs every event to decode and every `error` event
/// of `code` that names a contract to name the same one. Anything else gives no attribution:
/// no events, an undecodable event, or two contracts with this code (a relayed or caught call).
fn raising_contract(code: u32, events: &[String]) -> Option<String> {
    let mut origin: Option<[u8; 32]> = None;
    for event in events {
        let DiagnosticEvent { event, .. } = crate::read(event).ok()?;
        if event.type_ != ContractEventType::Diagnostic {
            continue;
        }
        let ContractEventBody::V0(body) = &event.body;
        let [
            ScVal::Symbol(topic),
            ScVal::Error(ScError::Contract(raised)),
        ] = body.topics.as_slice()
        else {
            continue;
        };
        if topic.0.as_slice() != b"error" || *raised != code {
            continue;
        }
        // The host frame of the transaction itself has no contract id.
        let Some(contract) = &event.contract_id else {
            continue;
        };
        match origin {
            None => origin = Some(contract.0.0),
            Some(seen) if seen == contract.0.0 => {}
            Some(_) => return None,
        }
    }
    origin.map(|id| stellar_strkey::Contract(id).to_string())
}

/// The contract that a simulated transaction invokes: the target of its single
/// `InvokeContract` operation. Any other transaction names no contract.
pub fn simulated_contract(transaction: &str) -> Option<String> {
    let TransactionEnvelope::Tx(envelope) = crate::read(transaction).ok()? else {
        return None;
    };
    let [operation] = envelope.tx.operations.as_slice() else {
        return None;
    };
    let OperationBody::InvokeHostFunction(invoke) = &operation.body else {
        return None;
    };
    let HostFunction::InvokeContract(call) = &invoke.host_function else {
        return None;
    };
    let ScAddress::Contract(contract) = &call.contract_address else {
        return None;
    };
    Some(stellar_strkey::Contract(contract.0.0).to_string())
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
