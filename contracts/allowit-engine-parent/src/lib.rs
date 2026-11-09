#![no_std]
//! Owns the shared engine's executable reference and its independent administration authority.
//! Wallet custody, wallet owner operations and server signing keys are outside this contract.
use soroban_sdk::{
    Address, BytesN, ContractExecutable, ContractExecutableRef, Env, String, contract,
    contracterror, contractimpl, contracttype,
};

// Keep the native u32 key unchanged. Renaming this constant does not move existing state.
const STATE_KEY: u32 = 0;

/// Parent configuration stored under STATE_KEY in this contract's instance storage.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllowitParentState {
    /// Current engine-administrator address, authorized through native account or contract rules.
    pub owner: Address,
    /// Engine-administrator configuration sequence. It changes on parent administration and is not engine_version release metadata.
    pub version: u64,
    /// Shared veto-engine address. Engine approval cannot replace local policy checks or authorize owner administration.
    pub engine: Address,
}

#[contracterror]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum AllowitParentError {
    /// The supplied administration version differs from the stored version.
    StaleVersion = 1,
    /// The u64 administration version cannot advance.
    Overflow = 2,
    /// A handoff selects the parent or its managed engine as administrator.
    InvalidAdmin = 3,
}

#[contract]
pub struct AllowitEngineParent;

/// Stable executable-reference tag owned by this parent. It is not a custody contract identifier.
fn tag(env: &Env) -> String {
    String::from_str(env, "engine")
}
/// Initialize constructor state or read it, then maintain the parent instance and code lifetime.
fn load(env: &Env, initial: Option<AllowitParentState>) -> AllowitParentState {
    if let Some(state) = initial {
        env.storage().instance().set(&STATE_KEY, &state);
    }
    let ttl = env.storage().max_ttl();
    env.deployer()
        .extend_ttl(env.current_contract_address(), ttl / 2, ttl);
    env.storage().instance().get(&STATE_KEY).unwrap()
}
/// Commit state after load and authorization; no second lifetime update is needed.
fn save(env: &Env, state: &AllowitParentState) {
    env.storage().instance().set(&STATE_KEY, state);
}
/// Authenticate the current owner and advance one administration version without touching the engine.
fn authorize(env: &Env, version: u64) -> Result<AllowitParentState, AllowitParentError> {
    let mut state = load(env, None);
    state.owner.require_auth();
    if state.version != version {
        return Err(AllowitParentError::StaleVersion);
    }
    state.version = state
        .version
        .checked_add(1)
        .ok_or(AllowitParentError::Overflow)?;
    Ok(state)
}

// Engine maintenance is separate so parent administration can recover unavailable dependencies.
mod engine {
    use super::*;

    /// Renew the engine's instance and code lifetime and return its address.
    pub(super) fn load(env: &Env, address: Address) -> Address {
        let ttl = env.storage().max_ttl();
        env.deployer().extend_ttl(address.clone(), ttl / 2, ttl);
        address
    }
}

#[contractimpl]
impl AllowitEngineParent {
    /// Create the shared engine and its independent upgrade authority.
    /// The engine uses this parent's "engine" executable reference and the all-zero deployment salt.
    /// Its constructor receives no arguments. The parent starts at administration version zero.
    ///
    /// # Parameters
    /// - `env`: Host-provided execution environment; callers do not serialize this argument.
    /// - `owner`: Initial native or contract upgrade authority, distinct from parent and engine.
    /// - `engine_wasm`: Uploaded engine Wasm hash selected by that authority.
    ///
    /// # Returns
    /// Returns no value. Failed owner authorization or deployment rolls back the reference and state writes.
    pub fn __constructor(env: Env, owner: Address, engine_wasm: BytesN<32>) {
        owner.require_auth();
        env.executable_refs().set(&tag(&env), &engine_wasm);
        let engine = env
            .deployer()
            .with_current_contract(BytesN::from_array(&env, &[0; 32]))
            .deploy_contract(
                ContractExecutable::ExternalRef(ContractExecutableRef {
                    owner: env.current_contract_address(),
                    tag: tag(&env),
                }),
                (),
            );
        load(
            &env,
            Some(AllowitParentState {
                owner,
                version: 0,
                engine,
            }),
        );
    }

    /// Read engine-parent configuration.
    ///
    /// # Parameters
    /// - `env`: Host-provided execution environment; callers do not serialize this argument.
    ///
    /// # Returns
    /// Returns owner, engine address and administrative version. It renews parent lifetime without reading engine dependencies.
    pub fn state(env: Env) -> AllowitParentState {
        load(&env, None)
    }

    /// Read the engine address and refresh parent, engine and reference lifetimes.
    ///
    /// # Parameters
    /// - `env`: Host-provided execution environment; callers do not serialize this argument.
    ///
    /// # Returns
    /// Returns the shared engine address after renewing its instance, referenced code and executable-reference entry. It grants no spending authority.
    pub fn engine(env: Env) -> Address {
        engine::load(&env, load(&env, None).engine)
    }

    /// Replace shared engine executable bytes under current administrator authorization.
    ///
    /// # Parameters
    /// - `env`: Host-provided execution environment; callers do not serialize this argument.
    /// - `new_hash`: Uploaded engine Wasm hash; its own release metadata is independent of this admin version.
    /// - `version`: Exact current parent administrative version, not a policy deployment or engine release version.
    ///
    /// # Returns
    /// Returns success after one version increment and reference update. The engine address and instance data stay unchanged.
    pub fn upgrade_engine(
        env: Env,
        new_hash: BytesN<32>,
        version: u64,
    ) -> Result<(), AllowitParentError> {
        let state = authorize(&env, version)?;
        // The host rejects hashes that do not identify uploaded Wasm.
        env.executable_refs().set(&tag(&env), &new_hash);
        save(&env, &state);
        Ok(())
    }

    /// Transfer engine upgrade administration with both authorities' authorization.
    ///
    /// # Parameters
    /// - `env`: Host-provided execution environment; callers do not serialize this argument.
    /// - `owner`: Candidate native or contract administrator; it must accept the exact handoff.
    /// - `version`: Exact current parent administrative version.
    ///
    /// # Returns
    /// Returns success after the handoff and one version increment; wallet owner rights remain independent.
    pub fn set_admin(env: Env, owner: Address, version: u64) -> Result<(), AllowitParentError> {
        let mut state = authorize(&env, version)?;
        if owner == env.current_contract_address() || owner == state.engine {
            return Err(AllowitParentError::InvalidAdmin);
        }
        owner.require_auth();
        state.owner = owner;
        save(&env, &state);
        Ok(())
    }

    /// Upgrade parent code under its current independent administrator.
    ///
    /// # Parameters
    /// - `env`: Host-provided execution environment; callers do not serialize this argument.
    /// - `new_hash`: Uploaded parent Wasm hash chosen by the administrator.
    /// - `version`: Exact current parent administrative version.
    ///
    /// # Returns
    /// Returns success after the invocation commits the new code and version. The selected executable must understand the retained state layout.
    pub fn upgrade_parent(
        env: Env,
        new_hash: BytesN<32>,
        version: u64,
    ) -> Result<(), AllowitParentError> {
        let state = authorize(&env, version)?;
        env.deployer()
            .update_current_contract(ContractExecutable::Wasm(new_hash));
        save(&env, &state);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
