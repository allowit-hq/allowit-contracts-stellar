use super::*;
use allowit::{AllowitContext, AllowitOperation, AllowitParams, AllowitRequest, AllowitValue};
use allowit_wallet_engine::AllowitEngineClient;
use soroban_sdk::{
    Bytes, IntoVal, Val, Vec,
    testutils::{Address as _, MockAuth, MockAuthInvoke},
};

const ENGINE_WASM: &[u8] =
    include_bytes!("../../../target/wasm32v1-none/release/allowit_wallet_engine.wasm");
const DENY_ENGINE_WASM: &[u8] = include_bytes!("../../../target/test-fixtures/engine_deny.wasm");
const PARENT_WASM: &[u8] =
    include_bytes!("../../../target/wasm32v1-none/release/allowit_engine_parent.wasm");

struct Fixture {
    env: Env,
    parent: Address,
    admin: Address,
    engine_hash: BytesN<32>,
}
impl Fixture {
    fn new(compiled_parent: bool) -> Self {
        let env = Env::default();
        env.mock_all_auths_allowing_non_root_auth();
        let admin = Address::generate(&env);
        let engine_hash = env
            .deployer()
            .upload_contract_wasm(Bytes::from_slice(&env, ENGINE_WASM));
        let parent = if compiled_parent {
            env.register(PARENT_WASM, (admin.clone(), engine_hash.clone()))
        } else {
            env.register(AllowitEngineParent, (admin.clone(), engine_hash.clone()))
        };
        env.mock_auths(&[]);
        Self {
            env,
            parent,
            admin,
            engine_hash,
        }
    }
    fn client(&self) -> AllowitEngineParentClient<'_> {
        AllowitEngineParentClient::new(&self.env, &self.parent)
    }
    fn auth(&self, actor: &Address, method: &str, args: Vec<Val>) {
        self.env.mock_auths(&[MockAuth {
            address: actor,
            invoke: &MockAuthInvoke {
                contract: &self.parent,
                fn_name: method,
                args,
                sub_invokes: &[],
            },
        }]);
    }
}
fn context(env: &Env) -> AllowitContext {
    let asset = Address::generate(env);
    AllowitContext {
        env: env.clone(),
        params: AllowitParams(soroban_sdk::Map::from_array(
            env,
            [(
                soroban_sdk::Symbol::new(env, allowit::TRANSACTION_CAP),
                AllowitValue::Int(10),
            )],
        )),
        state: soroban_sdk::Map::new(env),
        request: AllowitRequest {
            operation: AllowitOperation::sep41_transfer,
            asset: asset.clone(),
            recipient: Address::generate(env),
            amount: 1,
            token_in: asset,
            amount_in: 1,
            token_out: None,
            min_out: 0,
            now: 100,
            expires_at: 200,
            spent_units: 1,
            gas_units: 0,
            unpriced: false,
            args: AllowitParams(soroban_sdk::Map::new(env)),
        },
    }
}
/// Call the engine's `transaction_cap` with the fixture context.
fn transaction_cap(
    env: &Env,
    engine: &Address,
) -> Result<Result<i128, soroban_sdk::Error>, Result<allowit::AllowitError, soroban_sdk::InvokeError>>
{
    let ctx = context(env);
    AllowitEngineClient::new(env, engine).try_transaction_cap(
        &ctx.params.0,
        &ctx.state,
        &ctx.request,
    )
}
fn approved(env: &Env, engine: &Address) -> bool {
    transaction_cap(env, engine).is_ok_and(|left| left == Ok(9))
}

#[test]
fn compiled_parent_deploys_compiled_external_reference_engine() {
    let f = Fixture::new(true);
    let state = f.client().state();
    assert_eq!(state.owner, f.admin);
    assert_eq!(state.version, 0);
    assert_eq!(f.client().engine(), state.engine);
    assert!(approved(&f.env, &state.engine));
}

#[test]
fn wrong_or_absent_admin_cannot_upgrade_and_stale_version_does_not_commit() {
    let f = Fixture::new(false);
    let c = f.client();
    let before = c.state();
    assert!(c.try_upgrade_engine(&f.engine_hash, &0).is_err());
    let wrong = Address::generate(&f.env);
    f.auth(
        &wrong,
        "upgrade_engine",
        (f.engine_hash.clone(), 0u64).into_val(&f.env),
    );
    assert!(c.try_upgrade_engine(&f.engine_hash, &0).is_err());
    f.auth(
        &f.admin,
        "upgrade_engine",
        (f.engine_hash.clone(), 1u64).into_val(&f.env),
    );
    assert_eq!(
        c.try_upgrade_engine(&f.engine_hash, &1),
        Err(Ok(AllowitParentError::StaleVersion))
    );
    assert_eq!(c.state(), before);
    f.auth(
        &f.admin,
        "upgrade_engine",
        (f.engine_hash.clone(), 0u64).into_val(&f.env),
    );
    c.upgrade_engine(&f.engine_hash, &0);
    assert_eq!(c.state().version, 1);
    assert_eq!(c.engine(), before.engine);
}

#[test]
fn missing_uploaded_code_rolls_back_parent_version() {
    let f = Fixture::new(false);
    let bad = BytesN::from_array(&f.env, &[99; 32]);
    f.auth(
        &f.admin,
        "upgrade_engine",
        (bad.clone(), 0u64).into_val(&f.env),
    );
    assert!(f.client().try_upgrade_engine(&bad, &0).is_err());
    assert_eq!(f.client().state().version, 0);
    assert!(approved(&f.env, &f.client().engine()));
}

#[test]
fn rotation_requires_both_current_admin_and_candidate_for_exact_arguments() {
    let f = Fixture::new(false);
    let next = Address::generate(&f.env);
    let args: Vec<Val> = (next.clone(), 0u64).into_val(&f.env);
    f.auth(&f.admin, "set_admin", args.clone());
    assert!(f.client().try_set_admin(&next, &0).is_err());
    f.auth(&next, "set_admin", args.clone());
    assert!(f.client().try_set_admin(&next, &0).is_err());
    assert_eq!(f.client().state().version, 0);
    f.env.mock_auths(&[
        MockAuth {
            address: &f.admin,
            invoke: &MockAuthInvoke {
                contract: &f.parent,
                fn_name: "set_admin",
                args: args.clone(),
                sub_invokes: &[],
            },
        },
        MockAuth {
            address: &next,
            invoke: &MockAuthInvoke {
                contract: &f.parent,
                fn_name: "set_admin",
                args,
                sub_invokes: &[],
            },
        },
    ]);
    f.client().set_admin(&next, &0);
    assert_eq!(f.client().state().owner, next);
    assert_eq!(f.client().state().version, 1);
    f.auth(
        &f.admin,
        "upgrade_engine",
        (f.engine_hash.clone(), 1u64).into_val(&f.env),
    );
    assert!(f.client().try_upgrade_engine(&f.engine_hash, &1).is_err());
}

#[test]
fn compiled_parent_self_upgrade_preserves_state_and_admin_gate() {
    let f = Fixture::new(true);
    // An inert valid custom section produces a distinct executable hash.
    let mut replacement = Bytes::from_slice(&f.env, PARENT_WASM);
    replacement.append(&Bytes::from_slice(&f.env, &[0, 2, 1, b'x']));
    let wasm = f.env.deployer().upload_contract_wasm(replacement);
    let before = f.client().state();
    assert!(f.client().try_upgrade_parent(&wasm, &0).is_err());
    f.auth(
        &f.admin,
        "upgrade_parent",
        (wasm.clone(), 0u64).into_val(&f.env),
    );
    f.client().upgrade_parent(&wasm, &0);
    let after = f.client().state();
    assert_eq!(after.engine, before.engine);
    assert_eq!(after.owner, before.owner);
    assert_eq!(after.version, 1);
    assert!(approved(&f.env, &after.engine));
}

#[test]
fn compiled_engine_reference_upgrade_changes_veto_without_changing_address() {
    let f = Fixture::new(true);
    let engine = f.client().engine();
    assert!(approved(&f.env, &engine));
    let deny = f
        .env
        .deployer()
        .upload_contract_wasm(Bytes::from_slice(&f.env, DENY_ENGINE_WASM));
    assert_ne!(deny, f.engine_hash);
    f.auth(
        &f.admin,
        "upgrade_engine",
        (deny.clone(), 0u64).into_val(&f.env),
    );
    f.client().upgrade_engine(&deny, &0);
    assert_eq!(f.client().engine(), engine);
    assert_eq!(
        transaction_cap(&f.env, &engine),
        Err(Err(soroban_sdk::InvokeError::Contract(
            allowit_wallet_engine::TEST_DENY
        )))
    );
    assert_eq!(f.client().state().version, 1);
    // A later authorized release can restore the engine, preserving identity.
    f.auth(
        &f.admin,
        "upgrade_engine",
        (f.engine_hash.clone(), 1u64).into_val(&f.env),
    );
    f.client().upgrade_engine(&f.engine_hash, &1);
    assert!(approved(&f.env, &engine));
    assert_eq!(f.client().state().version, 2);
}

#[test]
fn engine_cannot_become_its_own_upgrade_admin() {
    let f = Fixture::new(false);
    let engine = f.client().engine();
    f.auth(
        &f.admin,
        "set_admin",
        (engine.clone(), 0u64).into_val(&f.env),
    );
    assert_eq!(
        f.client().try_set_admin(&engine, &0),
        Err(Ok(AllowitParentError::InvalidAdmin))
    );
    assert_eq!(f.client().state().version, 0);
}

#[test]
fn version_overflow_rejects_without_switching_engine() {
    let f = Fixture::new(false);
    f.env.as_contract(&f.parent, || {
        let mut state: AllowitParentState = f.env.storage().instance().get(&STATE_KEY).unwrap();
        state.version = u64::MAX;
        f.env.storage().instance().set(&STATE_KEY, &state);
    });
    let before = f.client().state();
    f.auth(
        &f.admin,
        "upgrade_engine",
        (f.engine_hash.clone(), u64::MAX).into_val(&f.env),
    );
    assert_eq!(
        f.client().try_upgrade_engine(&f.engine_hash, &u64::MAX),
        Err(Ok(AllowitParentError::Overflow))
    );
    assert_eq!(f.client().state(), before);
}

#[contract]
pub struct ConstructorDeployer;
#[contractimpl]
impl ConstructorDeployer {
    pub fn deploy_parent(
        env: Env,
        parent_wasm: BytesN<32>,
        admin: Address,
        engine_wasm: BytesN<32>,
    ) -> Address {
        env.deployer()
            .with_current_contract(BytesN::from_array(&env, &[0; 32]))
            .deploy_contract(ContractExecutable::Wasm(parent_wasm), (admin, engine_wasm))
    }
}

#[test]
fn constructor_requires_admin_authorization() {
    let env = Env::default();
    let admin = Address::generate(&env);
    let engine_hash = env
        .deployer()
        .upload_contract_wasm(Bytes::from_slice(&env, ENGINE_WASM));
    let parent_hash = env
        .deployer()
        .upload_contract_wasm(Bytes::from_slice(&env, PARENT_WASM));
    let deployer = env.register(ConstructorDeployer, ());
    env.mock_auths(&[]);
    assert!(
        ConstructorDeployerClient::new(&env, &deployer)
            .try_deploy_parent(&parent_hash, &admin, &engine_hash)
            .is_err()
    );
}

#[test]
fn engine_lookup_extends_cold_reference_instance_and_code_ttl() {
    use soroban_sdk::testutils::Deployer as _;
    let f = Fixture::new(true);
    let state = f.client().state();
    let before_code = f.env.deployer().get_contract_code_ttl(&state.engine);
    let before_instance = f.env.deployer().get_contract_instance_ttl(&state.engine);
    let before_ref = f
        .env
        .as_contract(&f.parent, || f.env.executable_refs().get_ttl(&tag(&f.env)));
    let max = f.env.storage().max_ttl();
    assert_eq!(f.env.deployer().get_contract_code_ttl(&f.parent), max);
    assert!(before_code < max / 2);
    assert!(before_instance < max / 2);
    assert!(before_ref < max / 2);
    assert_eq!(f.client().engine(), state.engine);
    assert_eq!(f.env.deployer().get_contract_code_ttl(&state.engine), max);
    assert_eq!(
        f.env.deployer().get_contract_instance_ttl(&state.engine),
        max
    );
    assert_eq!(
        f.env
            .as_contract(&f.parent, || f.env.executable_refs().get_ttl(&tag(&f.env))),
        max
    );
}

#[test]
fn constructor_initializes_parent_lifetime_without_an_extra_state_read() {
    use soroban_sdk::testutils::Deployer as _;
    let f = Fixture::new(true);
    let max = f.env.storage().max_ttl();
    assert_eq!(f.env.deployer().get_contract_instance_ttl(&f.parent), max);
    assert_eq!(f.env.deployer().get_contract_code_ttl(&f.parent), max);
}

#[test]
fn parent_administration_does_not_load_an_unavailable_engine() {
    let f = Fixture::new(false);
    let missing = Address::generate(&f.env);
    f.env.as_contract(&f.parent, || {
        let mut state: AllowitParentState = f.env.storage().instance().get(&STATE_KEY).unwrap();
        state.engine = missing.clone();
        f.env.storage().instance().set(&STATE_KEY, &state);
    });
    assert!(f.client().try_engine().is_err());
    f.auth(
        &f.admin,
        "upgrade_engine",
        (f.engine_hash.clone(), 0u64).into_val(&f.env),
    );
    f.client().upgrade_engine(&f.engine_hash, &0);
    assert_eq!(f.client().state().version, 1);
    assert_eq!(f.client().state().engine, missing);
}

#[test]
fn previous_parent_layout_is_not_read_as_current_state() {
    use soroban_sdk::{Map, Symbol};
    let f = Fixture::new(false);
    f.env.as_contract(&f.parent, || {
        let mut old = Map::<Symbol, Val>::new(&f.env);
        old.set(
            Symbol::new(&f.env, "upgrade_authority"),
            f.admin.clone().into_val(&f.env),
        );
        old.set(Symbol::new(&f.env, "revision"), 0u64.into_val(&f.env));
        old.set(
            Symbol::new(&f.env, "engine"),
            Address::generate(&f.env).into_val(&f.env),
        );
        f.env.storage().instance().set(&STATE_KEY, &old);
    });
    assert!(f.client().try_state().is_err());
}
