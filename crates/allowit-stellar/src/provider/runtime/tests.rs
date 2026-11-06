use super::Runtime as NativeRuntime;
use crate::{self as native, PreparedOperation};
use serde_json::Value;
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};
type Events = Arc<Mutex<Vec<String>>>;
struct ScriptedRpc {
    events: Events,
    responses: Mutex<VecDeque<native::Result<Value>>>,
}
impl native::rpc::Rpc for ScriptedRpc {
    fn call(&self, method: &str, _: Value) -> native::Result<Value> {
        self.events.lock().unwrap().push(format!("rpc:{method}"));
        self.responses
            .lock()
            .unwrap()
            .pop_front()
            .expect("scripted RPC")
    }
}
fn policy_signed() -> native::SignedOperation {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/provider/stellar-policy-wallet-revalidation-rpc.json"
    ))
    .unwrap();
    serde_json::from_value(fixture["signed"].clone()).unwrap()
}
#[test]
fn authorization_retention_precedes_second_rpc_and_simulation_failure_keeps_it() {
    let prepared = policy_signed().prepared;
    let events = Events::default();
    let runtime = NativeRuntime::from_rpc(Arc::new(ScriptedRpc {
        events: events.clone(),
        responses: Mutex::new(vec![Err("post-sign simulation unavailable".into())].into()),
    }));
    let retained = Mutex::new(None::<PreparedOperation>);
    let result = runtime.finalize_authorization(
        &prepared,
        |p| {
            events.lock().unwrap().push("authorize".into());
            Ok(p.clone())
        },
        |p| {
            events.lock().unwrap().push("retain".into());
            *retained.lock().unwrap() = Some(p.clone());
            Ok(())
        },
    );
    assert!(result.is_err());
    assert_eq!(
        *events.lock().unwrap(),
        vec!["authorize", "retain", "rpc:getNetwork"]
    );
    let original = retained.lock().unwrap().take().unwrap();
    assert_eq!(original, prepared);
    native::validate_retained_prepared(&original).unwrap();
    events.lock().unwrap().clear();
    assert!(
        runtime
            .finalize_authorization(
                &prepared,
                |p| Ok(p.clone()),
                |_| Err("retention failed".into())
            )
            .is_err()
    );
    assert!(events.lock().unwrap().is_empty());
}
