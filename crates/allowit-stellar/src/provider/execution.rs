//! Shared native execution orchestration. Original journal names and signed records remain unchanged.
use super::runtime::client::{self, ExecutionOutcome};
use crate::OperationStatus;
use crate::host::execution::{Quantity, Settlement};
use crate::host::{
    Signer,
    error::{Error, Result},
    execution::{Outcome, Request},
    profiles::Profile,
};
use allowit_core::client::store::Store;
use std::{sync::Arc, time::Duration};
fn typed(
    profile: &Profile,
    store: &dyn Fn() -> Result<Store>,
    rpc: Option<&str>,
    r: &Request,
) -> Result<super::typed::TypedRequest> {
    let bundle = bundle(profile)?;
    let retained = if r.build_only {
        None
    } else {
        client::retained_request(&store()?, &bundle.policy_id, &r.request_id)?
    };
    if let Some(old) = retained {
        super::request::rebuild(&bundle.policy_id, &bundle.config, r, &old)
    } else {
        super::request::build(&bundle.policy_id, &bundle.config, r, || {
            super::request::state(&bundle.config, rpc)
        })
    }
}
pub fn build(
    profile: &Profile,
    store: &dyn Fn() -> Result<Store>,
    rpc: Option<&str>,
    r: &Request,
) -> Result<serde_json::Value> {
    typed(profile, store, rpc, r)?.wire()
}
fn client(
    profile: Profile,
    signer: Arc<dyn Signer>,
    rpc: Option<String>,
) -> Result<client::Client> {
    if profile.description().network != signer.network() {
        return Err(Error::config(
            "Agent signer belongs to another profile rail",
        ));
    }
    let authority = profile.require_authority()?.clone();
    let bundle = client::decode_public_bundle(profile.descriptor.get().as_bytes())?;
    client::Client::new(
        bundle,
        Arc::new(super::AgentSignerArc(signer)),
        &authority,
        rpc,
    )
}
pub fn execute(
    profile: Profile,
    signer: Arc<dyn Signer>,
    store: &dyn Fn() -> Result<Store>,
    rpc: Option<String>,
    r: &Request,
) -> Result<Outcome> {
    let typed = typed(&profile, store, rpc.as_deref(), r)?;
    client::exec(
        &client(profile, signer, rpc)?,
        &store()?,
        &r.request_id,
        typed.request,
        r.wait,
    )
    .map(render)
}
pub fn retained(
    store: &dyn Fn() -> Result<Store>,
    network: &str,
    wallet: Option<&str>,
    id: &str,
) -> Result<Option<crate::host::execution::Recovery>> {
    client::retained(&store()?, network, wallet, id).map(|r| {
        r.map(|r| crate::host::execution::Recovery {
            binding: Box::new(r),
        })
    })
}
pub fn recover(
    original: crate::host::execution::Recovery,
    signer: Arc<dyn Signer>,
    backend: &str,
    store: &dyn Fn() -> Result<Store>,
    id: &str,
    wait: Duration,
    request: Option<&Request>,
) -> Result<Outcome> {
    let original = *original
        .binding
        .into_any()
        .downcast::<client::Retained>()
        .map_err(|_| Error::config("Retained operation belongs to another selected rail"))?;
    if let Some(request) = request {
        if !original.signed() {
            return Err(Error::config(
                "Unsigned history requires current verified execution authority",
            ));
        }
        let rebuilt = super::request::rebuild(
            original.policy_id(),
            original.config(),
            request,
            original.request(),
        )?;
        if rebuilt.request != *original.request() {
            return Err(Error::usage(
                "Original request ID already binds different input",
            ));
        }
    }
    client::recover(
        original,
        &store()?,
        Arc::new(super::AgentSignerArc(signer)),
        backend,
        id,
        wait,
    )
    .map(render)
}
pub fn status(
    profile: Profile,
    signer: Arc<dyn Signer>,
    store: &dyn Fn() -> Result<Store>,
    rpc: Option<String>,
    id: &str,
    wait: Duration,
) -> Result<Outcome> {
    client::status(&client(profile, signer, rpc)?, &store()?, id, wait).map(render)
}

fn render(out: ExecutionOutcome) -> Outcome {
    let status = match out.status {
        OperationStatus::Confirmed => crate::host::runtime::Status::Confirmed,
        OperationStatus::Failed => crate::host::runtime::Status::Failed,
        OperationStatus::SubmissionUnknown => crate::host::runtime::Status::SubmissionUnknown,
        OperationStatus::Prepared => crate::host::runtime::Status::Prepared,
        OperationStatus::Submitted => crate::host::runtime::Status::Submitted,
    };
    let mut document = serde_json::json!({"requestId":out.request_id,"status":out.status,"transactionHash":out.transaction_hash});
    if let Some((ledger, fee)) = out.settlement {
        // The transaction pays its fee in the native asset, whatever asset the wallet holds.
        let settlement = Settlement {
            height: u64::from(ledger),
            fee: Quantity::new(i128::from(fee), super::native_display()),
            amount: None,
        };
        document[Settlement::KEY] =
            serde_json::to_value(settlement).expect("a settlement encodes as JSON");
    }
    Outcome { document, status }
}

fn bundle(profile: &Profile) -> Result<&client::Bundle> {
    profile
        .binding
        .as_any()
        .downcast_ref::<client::Bundle>()
        .ok_or_else(|| Error::config("Public profile belongs to another selected rail"))
}
impl crate::host::execution::RecoveryBinding for client::Retained {
    fn binding(&self) -> crate::host::execution::Binding {
        crate::host::execution::Binding {
            wallet: self.config().wallet.clone(),
            policy: format!(
                "{}@{}",
                self.policy_id(),
                crate::hex(&self.config().module_digest)
            ),
        }
    }
    fn signed(&self) -> bool {
        self.signed()
    }
    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any + Send + Sync> {
        self
    }
}

#[cfg(test)]
mod storage_boundary_tests {
    use super::*;
    #[test]
    fn a_settled_outcome_reports_its_ledger_and_fee_in_the_native_unit() {
        let outcome = |settlement| ExecutionOutcome {
            request_id: "transfer-001".into(),
            status: OperationStatus::Confirmed,
            transaction_hash: "ab".repeat(32),
            settlement,
        };
        let settled = render(outcome(Some((5_661_578, 123_456)))).document;
        let settlement = Settlement::of(&settled).unwrap();
        assert_eq!(settlement.height, 5_661_578);
        assert_eq!(settlement.fee.units, "123456");
        assert_eq!(settlement.fee.text, "0.0123456 XLM");
        assert_eq!(settled["settlement"]["fee"]["asset"]["symbol"], "XLM");
        assert_eq!(settlement.amount, None);
        let pending = render(outcome(None)).document;
        assert!(pending.get("settlement").is_none());
        assert_eq!(pending["requestId"], "transfer-001");
    }
    #[test]
    fn build_only_does_not_request_a_caller_store() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/provider/stellar-portable-descriptors.json"
        ))
        .unwrap();
        let descriptor = serde_json::to_vec(&fixture[0]["bundle"]).unwrap();
        let (description, binding) =
            crate::provider::profiles::decode("stellar:testnet", &descriptor).unwrap();
        let profile = Profile {
            description,
            binding,
            backend: "http://localhost:3000".into(),
            descriptor: serde_json::value::RawValue::from_string(
                String::from_utf8(descriptor).unwrap(),
            )
            .unwrap(),
            authority: None,
        };
        let request = Request {
            op: "transfer".into(),
            to: crate::account_for_seed(&[9; 32]),
            amount: crate::host::input::asset::Amount {
                asset: crate::host::input::asset::Asset::Installed,
                quantity: 1,
                decimals: None,
                text: "1".into(),
            },
            token_out: None,
            args: None,
            request_id: "build-only-001".into(),
            wait: Duration::ZERO,
            build_only: true,
            wallet: None,
        };
        let output = build(
            &profile,
            &|| panic!("build-only requested a journal"),
            None,
            &request,
        )
        .unwrap();
        assert_eq!(output["requestId"], "build-only-001");
    }
}
