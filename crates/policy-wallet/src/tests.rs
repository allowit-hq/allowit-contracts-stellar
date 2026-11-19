//! Kernel tests on the released Simple, Standard (Common) and Custom wallet Wasm.
extern crate std;
use super::*;
use allowit::{
    AllowitError, CALL_LIMIT, DAILY_SPENDING_LIMIT, DAILY_VOLUME_LIMIT, DESTINATIONS, EXPIRES_AT,
    LIFETIME_SPENDING_LIMIT, OPERATIONS, PAYMENT_LIMIT, TOKENS,
};
use allowit_sep56_test_vault::AllowitSep56TestVaultClient;
use allowit_wallet_protocol::{AllowitExpense, AllowitStellarOperation};
use ed25519_dalek::{Signer, SigningKey};
use soroban_sdk::{
    Bytes, InvokeError, TryFromVal, TryIntoVal, contract, contractimpl,
    testutils::{
        Address as _, Deployer as _, Events as _, Ledger, MockAuth, MockAuthInvoke,
        storage::{Persistent as _, Temporary as _},
    },
    token::StellarAssetClient,
    xdr::{self, WriteXdr},
};
use std::vec::Vec as List;

mod native {
    crate::policy_wallet!(Harness, crate::AllowitCommon);
}
use native::HarnessClient as Client;
pub(super) const SIMPLE: &[u8] =
    include_bytes!("../../../target/wasm32v1-none/release/allowit_simple_policy_engine.wasm");
pub(super) const COMMON: &[u8] =
    include_bytes!("../../../target/wasm32v1-none/release/allowit_common_policy_engine.wasm");
pub(super) const CUSTOM: &[u8] =
    include_bytes!("../../../target/wasm32v1-none/release/allowit_custom_policy.wasm");
/// `AllowitCustomPolicy` built with `test-catching` by `scripts/build-contracts.sh`: a policy
/// that calls `set_state`.
pub(super) const CATCHING: &[u8] =
    include_bytes!("../../../target/test-fixtures/custom_catching.wasm");
/// `AllowitCustomPolicy` built with `test-daily`: a policy with one daily state entry,
/// `day_payments`.
pub(super) const DAILY_STATE: &[u8] =
    include_bytes!("../../../target/test-fixtures/custom_daily.wasm");
pub(super) const VAULT: &[u8] =
    include_bytes!("../../../target/wasm32v1-none/release/allowit_sep56_test_vault.wasm");

/// A `List` of `Addr` values.
fn addresses(env: &Env, items: &[&Address]) -> AllowitValue {
    let mut list = Vec::new(env);
    for item in items {
        list.push_back(AllowitValue::Addr((*item).clone()));
    }
    AllowitValue::List(list)
}
/// A `List` of `Str` op names.
fn op_names(env: &Env, names: &[&str]) -> AllowitValue {
    let mut list = Vec::new(env);
    for name in names {
        list.push_back(AllowitValue::Str(soroban_sdk::String::from_str(env, name)));
    }
    AllowitValue::List(list)
}

/// A classic account of `key`.
pub(super) fn add_account(env: &Env, key: &SigningKey) -> Address {
    let account_id = xdr::AccountId(xdr::PublicKey::PublicKeyTypeEd25519(xdr::Uint256(
        key.verifying_key().to_bytes(),
    )));
    let ledger_key = std::rc::Rc::new(xdr::LedgerKey::Account(xdr::LedgerKeyAccount {
        account_id: account_id.clone(),
    }));
    let entry = std::rc::Rc::new(xdr::LedgerEntry {
        data: xdr::LedgerEntryData::Account(xdr::AccountEntry {
            account_id,
            balance: 1_000_000_000,
            flags: 0,
            home_domain: Default::default(),
            inflation_dest: None,
            num_sub_entries: 0,
            seq_num: xdr::SequenceNumber(0),
            thresholds: xdr::Thresholds([1; 4]),
            signers: Default::default(),
            ext: xdr::AccountEntryExt::V0,
        }),
        last_modified_ledger_seq: 1,
        ext: xdr::LedgerEntryExt::V0,
    });
    env.host()
        .add_ledger_entry(&ledger_key, &entry, None)
        .unwrap();
    Address::from_payload(
        env,
        AddressPayload::AccountIdPublicKeyEd25519(BytesN::from_array(
            env,
            &key.verifying_key().to_bytes(),
        )),
    )
}
pub(super) fn native_sac(env: &Env) -> Address {
    let created = env
        .host()
        .invoke_function(xdr::HostFunction::CreateContract(xdr::CreateContractArgs {
            contract_id_preimage: xdr::ContractIdPreimage::Asset(xdr::Asset::Native),
            executable: xdr::ContractExecutable::StellarAsset,
        }))
        .unwrap();
    Address::try_from_val(env, &created).unwrap()
}
fn hash(env: &Env, bytes: &[u8]) -> BytesN<32> {
    env.crypto()
        .sha256(&Bytes::from_slice(env, bytes))
        .to_bytes()
}

pub(super) struct Fixture {
    pub(super) env: Env,
    pub(super) wallet: Address,
    owner: Address,
    /// The wallet's asset: XLM unless the fixture says otherwise.
    pub(super) asset: Address,
    native: Address,
    pub(super) recipient: Address,
    pub(super) payee: Address,
    pub(super) akey: SigningKey,
    pub(super) skey: SigningKey,
    source: BytesN<32>,
    nonce: core::cell::Cell<i64>,
}

impl Fixture {
    fn env() -> Env {
        let env = Env::new_with_config(soroban_sdk::testutils::EnvTestConfig {
            capture_snapshot_at_drop: false,
        });
        env.ledger().with_mut(|l| {
            l.timestamp = 86_410;
            l.sequence_number = 100;
        });
        env
    }
    /// A wallet of `wasm` holding 1,000 units of XLM, with the standard rules for Common.
    fn new(wasm: &'static [u8]) -> Self {
        Self::with(wasm, false, |_, _| {})
    }
    /// A wallet of `wasm`; `issued` makes an issued asset the wallet's asset, and `edit` changes
    /// the configuration before creation.
    pub(super) fn with(
        wasm: &'static [u8],
        issued: bool,
        edit: impl FnOnce(&Env, &mut AllowitPolicyConfig),
    ) -> Self {
        let env = Self::env();
        env.mock_all_auths_allowing_non_root_auth();
        let native = native_sac(&env);
        let funder = add_account(&env, &SigningKey::from_bytes(&[44; 32]));
        let asset = if issued {
            env.register_stellar_asset_contract_v2(Address::generate(&env))
                .address()
        } else {
            native.clone()
        };
        let owner = Address::generate(&env);
        let recipient = Address::generate(&env);
        let payee = add_account(&env, &SigningKey::from_bytes(&[6; 32]));
        let akey = SigningKey::from_bytes(&[7; 32]);
        let skey = SigningKey::from_bytes(&[8; 32]);
        let mut params = Map::new(&env);
        for (key, value) in [
            (PAYMENT_LIMIT, AllowitValue::Int(100)),
            (LIFETIME_SPENDING_LIMIT, AllowitValue::Int(250)),
            (DAILY_SPENDING_LIMIT, AllowitValue::Int(200)),
            (DAILY_VOLUME_LIMIT, AllowitValue::Int(160)),
            (CALL_LIMIT, AllowitValue::Int(4)),
            (DESTINATIONS, addresses(&env, &[&recipient])),
            (TOKENS, addresses(&env, &[&asset])),
            (EXPIRES_AT, AllowitValue::Int(10_000_000)),
            (
                OPERATIONS,
                op_names(&env, &["transfer", "swap", "deposit", "redeem"]),
            ),
        ] {
            params.set(Symbol::new(&env, key), value);
        }
        let mut rules = Vec::new(&env);
        if wasm == COMMON {
            for rule in RULES {
                rules.push_back(rule);
            }
        }
        if wasm == SIMPLE {
            params = Map::new(&env);
        }
        let source = if wasm == CUSTOM {
            hash(
                &env,
                include_bytes!("../../../contracts/allowit-custom-policy/policy/policy.rs"),
            )
        } else if wasm == CATCHING {
            hash(
                &env,
                include_bytes!("../../../contracts/allowit-custom-policy/src/catching_policy.rs"),
            )
        } else if wasm == DAILY_STATE {
            hash(
                &env,
                include_bytes!("../../../contracts/allowit-custom-policy/src/daily_policy.rs"),
            )
        } else {
            BytesN::from_array(&env, &[9; 32])
        };
        let mut config = AllowitPolicyConfig {
            owner: owner.clone(),
            agent: BytesN::from_array(&env, &akey.verifying_key().to_bytes()),
            server: BytesN::from_array(&env, &skey.verifying_key().to_bytes()),
            asset: asset.clone(),
            source_hash: source.clone(),
            gas_cap: 20,
            rules,
            params,
        };
        edit(&env, &mut config);
        let wallet = env.register(wasm, (config,));
        if issued {
            StellarAssetClient::new(&env, &asset).mint(&wallet, &1_000);
        } else {
            token::Client::new(&env, &native).transfer(&funder, &wallet, &1_000);
        }
        if issued {
            token::Client::new(&env, &native).transfer(&funder, &wallet, &500);
        }
        env.set_auths(&[]);
        Self {
            env,
            wallet,
            owner,
            asset,
            native,
            recipient,
            payee,
            akey,
            skey,
            source,
            nonce: core::cell::Cell::new(1_000),
        }
    }
    pub(super) fn client(&self) -> Client<'_> {
        Client::new(&self.env, &self.wallet)
    }
    fn balance(&self, token: &Address, holder: &Address) -> i128 {
        token::Client::new(&self.env, token).balance(holder)
    }
    /// A priced transfer of `amount` with `gas` stroops repaid.
    fn transfer(&self, amount: i128, gas: i128) -> AllowitExecutionRequest {
        let mut id = [0u8; 32];
        id[..16].copy_from_slice(&amount.to_be_bytes());
        id[16..24].copy_from_slice(&u64::from(self.env.ledger().sequence()).to_be_bytes());
        id[31] = 1;
        let gas_units = if self.asset == self.native {
            gas
        } else {
            gas * 2
        };
        AllowitExecutionRequest(
            BytesN::from_array(&self.env, &id),
            self.client().state().deployment_version,
            self.env.ledger().timestamp() + 100,
            AllowitStellarOperation::Transfer(self.asset.clone(), self.recipient.clone(), amount),
            AllowitExpense::Priced(
                gas_units,
                0,
                amount + gas_units,
                self.env.ledger().sequence(),
            ),
            gas,
            self.payee.clone(),
            Map::new(&self.env),
        )
    }
    /// Run `e` under the wallet's own authorization, signed by the agent and the server with a
    /// fresh ledger nonce.
    pub(super) fn run(
        &self,
        e: &AllowitExecutionRequest,
    ) -> Result<(), Result<AllowitWalletError, InvokeError>> {
        let nonce = self.nonce.get();
        self.nonce.set(nonce + 1);
        let entry = self.signed(
            e,
            &self.akey,
            &self.skey,
            nonce,
            self.env.ledger().sequence() + 50,
        );
        self.env.set_auths(&[entry]);
        let result = self.client().try_execute(e);
        self.env.set_auths(&[]);
        result.map(|_| ())
    }
    /// The wallet's own authorization entry for `e`, signed by `agent` and `server`.
    pub(super) fn signed(
        &self,
        e: &AllowitExecutionRequest,
        agent: &SigningKey,
        server: &SigningKey,
        nonce: i64,
        expiration: u32,
    ) -> xdr::SorobanAuthorizationEntry {
        let invoke = MockAuthInvoke {
            contract: &self.wallet,
            fn_name: "execute",
            args: (e.clone(),).into_val(&self.env),
            sub_invokes: &[],
        };
        let invocation: xdr::SorobanAuthorizedInvocation = (&invoke).into();
        let preimage =
            xdr::HashIdPreimage::SorobanAuthorization(xdr::HashIdPreimageSorobanAuthorization {
                network_id: xdr::Hash(self.env.ledger().network_id().to_array()),
                nonce,
                signature_expiration_ledger: expiration,
                invocation: invocation.clone(),
            });
        let payload = hash(&self.env, &preimage.to_xdr(xdr::Limits::none()).unwrap());
        let signatures = AllowitCosignatures(
            BytesN::from_array(&self.env, &agent.sign(&payload.to_array()).to_bytes()),
            BytesN::from_array(&self.env, &server.sign(&payload.to_array()).to_bytes()),
        );
        let signature: Val = signatures.into_val(&self.env);
        xdr::SorobanAuthorizationEntry {
            credentials: xdr::SorobanCredentials::Address(xdr::SorobanAddressCredentials {
                address: (&self.wallet).into(),
                nonce,
                signature_expiration_ledger: expiration,
                signature: signature.try_into_val(&self.env).unwrap(),
            }),
            root_invocation: invocation,
        }
    }
    pub(super) fn run_signed(
        &self,
        e: &AllowitExecutionRequest,
        entry: xdr::SorobanAuthorizationEntry,
    ) -> bool {
        self.env.set_auths(&[entry]);
        let ok = self.client().try_execute(e).is_ok();
        self.env.set_auths(&[]);
        ok
    }
    /// Run an owner call with the owner's authorization of exactly these arguments.
    fn owner_call(&self, function: &str, args: Vec<Val>) -> Result<(), AllowitWalletError> {
        let invoke = MockAuthInvoke {
            contract: &self.wallet,
            fn_name: function,
            args: args.clone(),
            sub_invokes: &[],
        };
        self.env.mock_auths(&[MockAuth {
            address: &self.owner,
            invoke: &invoke,
        }]);
        let result = self.env.try_invoke_contract::<(), AllowitWalletError>(
            &self.wallet,
            &Symbol::new(&self.env, function),
            args,
        );
        self.env.set_auths(&[]);
        match result {
            Ok(_) => Ok(()),
            Err(Ok(error)) => Err(error),
            Err(Err(error)) => panic!("{function}: {error:?}"),
        }
    }
    fn update(&self) -> AllowitPolicyUpdate {
        let s = self.client().state();
        AllowitPolicyUpdate {
            deployment_version: s.deployment_version + 1,
            owner: s.owner,
            agent: s.agent,
            server: s.server,
            source_hash: s.source_hash,
            gas_cap: s.gas_cap,
            rules: s.rules,
            params: s.params,
            wasm_hash: None,
        }
    }
    fn figures(&self) -> AllowitFigures {
        self.client().state().figures
    }
    fn advance(&self, ledgers: u32) {
        self.env.ledger().with_mut(|l| {
            l.sequence_number += ledgers;
            l.timestamp += u64::from(ledgers) * 5;
        });
    }
    /// The wallet's own contract data entries, key and value XDR, with their live-until ledger.
    /// The ledger's nonce entries of the wallet's authorizations are left out: the ledger writes
    /// them, not the wallet.
    fn entries(&self) -> List<(List<u8>, List<u8>, Option<u32>)> {
        let wallet: xdr::ScAddress = (&self.wallet).into();
        let mut found: List<_> = self
            .env
            .to_ledger_snapshot()
            .ledger_entries
            .into_iter()
            .filter_map(|(key, (entry, live_until))| match (*key, entry.data) {
                (xdr::LedgerKey::ContractData(k), xdr::LedgerEntryData::ContractData(d))
                    if k.contract == wallet && !matches!(k.key, xdr::ScVal::LedgerKeyNonce(_)) =>
                {
                    Some((
                        k.key.to_xdr(xdr::Limits::none()).unwrap(),
                        d.val.to_xdr(xdr::Limits::none()).unwrap(),
                        live_until,
                    ))
                }
                _ => None,
            })
            .collect();
        found.sort();
        found
    }
    /// The serialized size of the wallet's instance ledger entry.
    fn instance_bytes(&self) -> usize {
        let wallet: xdr::ScAddress = (&self.wallet).into();
        self.env
            .to_ledger_snapshot()
            .ledger_entries
            .into_iter()
            .find_map(|(key, (entry, _))| match &*key {
                xdr::LedgerKey::ContractData(k)
                    if k.contract == wallet && k.key == xdr::ScVal::LedgerKeyContractInstance =>
                {
                    Some(entry.to_xdr(xdr::Limits::none()).unwrap().len())
                }
                _ => None,
            })
            .unwrap()
    }
    fn daily_ttl(&self) -> u32 {
        self.env.as_contract(&self.wallet, || {
            self.env.storage().temporary().get_ttl(&DAILY)
        })
    }
    /// The wallet's own events: topics and data.
    fn events(&self) -> List<(List<xdr::ScVal>, xdr::ScVal)> {
        self.env
            .events()
            .all()
            .filter_by_contract(&self.wallet)
            .events()
            .iter()
            .map(|event| match &event.body {
                xdr::ContractEventBody::V0(body) => (body.topics.to_vec(), body.data.clone()),
            })
            .collect()
    }
}

fn denied(wasm: &[u8], rule: AllowitError) -> Result<(), Result<AllowitWalletError, InvokeError>> {
    if wasm == CUSTOM || wasm == CATCHING || wasm == DAILY_STATE {
        Err(Err(InvokeError::Contract(rule as u32)))
    } else {
        Err(Ok(AllowitWalletError::PolicyDenied))
    }
}

// --- The wallet's own authorization ----------------------------------------------------------

#[test]
fn a_payment_needs_the_wallets_own_authorization_signed_by_agent_and_server() {
    for wasm in [SIMPLE, COMMON, CUSTOM] {
        let f = Fixture::new(wasm);
        assert_eq!(f.client().state().source_hash, f.source);
        let e = f.transfer(10, 5);
        let stranger = SigningKey::from_bytes(&[99; 32]);
        // Each key alone, a stranger in either place, and the two keys swapped are refused.
        for (agent, server) in [
            (&f.akey, &stranger),
            (&stranger, &f.skey),
            (&f.skey, &f.akey),
        ] {
            assert!(!f.run_signed(&e, f.signed(&e, agent, server, 1, 150)));
        }
        // No authorization at all.
        assert!(f.client().try_execute(&e).is_err());
        assert_eq!(f.balance(&f.asset, &f.recipient), 0);
        assert!(f.run_signed(&e, f.signed(&e, &f.akey, &f.skey, 1, 150)));
        assert_eq!(f.balance(&f.asset, &f.recipient), 10);
        assert_eq!(f.balance(&f.native, &f.payee), 1_000_000_000 + 5);
    }
}

#[test]
fn a_signed_payment_runs_once_and_never_after_its_expiration_ledger() {
    let f = Fixture::new(COMMON);
    let e = f.transfer(10, 0);
    let entry = f.signed(&e, &f.akey, &f.skey, 7, 150);
    assert!(f.run_signed(&e, entry.clone()));
    // The same entry again: the ledger keeps its nonce until the expiration ledger.
    assert!(!f.run_signed(&e, entry.clone()));
    // A new nonce whose expiration ledger has passed.
    let late = f.signed(&e, &f.akey, &f.skey, 8, 160);
    f.advance(61);
    assert!(!f.run_signed(&e, late));
    // The first entry after its expiration ledger, when the ledger no longer keeps its nonce.
    assert!(!f.run_signed(&e, entry));
    assert_eq!(f.balance(&f.asset, &f.recipient), 10);
}

#[test]
fn a_signature_of_changed_arguments_is_refused() {
    let f = Fixture::new(SIMPLE);
    let e = f.transfer(10, 0);
    let entry = f.signed(&e, &f.akey, &f.skey, 1, 150);
    let mut changed = e.clone();
    changed.5 = 20;
    assert!(!f.run_signed(&changed, entry));
}

#[test]
fn check_auth_authorizes_only_this_wallets_execute() {
    let f = Fixture::new(SIMPLE);
    let payload = BytesN::from_array(&f.env, &[5; 32]);
    let sign = |key: &SigningKey| BytesN::from_array(&f.env, &key.sign(&[5; 32]).to_bytes());
    let signatures = AllowitCosignatures(sign(&f.akey), sign(&f.skey));
    let call = |contract: &Address, name: &str| {
        Context::Contract(soroban_sdk::auth::ContractContext {
            contract: contract.clone(),
            fn_name: Symbol::new(&f.env, name),
            args: Vec::new(&f.env),
        })
    };
    let check = |contexts: List<Context>| {
        let mut list = Vec::new(&f.env);
        for c in contexts {
            list.push_back(c);
        }
        f.env.try_invoke_contract_check_auth::<AllowitWalletError>(
            &f.wallet,
            &payload,
            signatures.clone().into_val(&f.env),
            &list,
        )
    };
    assert!(check(std::vec![call(&f.wallet, "execute")]).is_ok());
    // A token transfer in the wallet's name, another wallet function, two contexts, none.
    assert_eq!(
        check(std::vec![call(&f.asset, "transfer")]),
        Err(Ok(AllowitWalletError::UnsupportedOperation))
    );
    assert_eq!(
        check(std::vec![call(&f.wallet, "recover")]),
        Err(Ok(AllowitWalletError::UnsupportedOperation))
    );
    assert_eq!(
        check(std::vec![
            call(&f.wallet, "execute"),
            call(&f.wallet, "execute")
        ]),
        Err(Ok(AllowitWalletError::InvalidInvocation))
    );
    assert_eq!(
        check(std::vec![]),
        Err(Ok(AllowitWalletError::InvalidInvocation))
    );
    // A signature of another payload.
    let other = AllowitCosignatures(
        BytesN::from_array(&f.env, &f.akey.sign(&[6; 32]).to_bytes()),
        signatures.1.clone(),
    );
    let mut list = Vec::new(&f.env);
    list.push_back(call(&f.wallet, "execute"));
    assert!(
        f.env
            .try_invoke_contract_check_auth::<AllowitWalletError>(
                &f.wallet,
                &payload,
                other.into_val(&f.env),
                &list
            )
            .is_err()
    );
}

// --- Request checks ---------------------------------------------------------------------------

/// A named edit of a request and the error it must give.
type RequestCase = (
    &'static str,
    fn(&Fixture, &mut AllowitExecutionRequest),
    AllowitWalletError,
);
/// A named edit of a configuration that creation must refuse.
type ConfigCase = (&'static str, fn(&Env, &mut AllowitPolicyConfig));

#[test]
fn request_bindings_and_gas_are_checked() {
    let f = Fixture::new(SIMPLE);
    let cases: [RequestCase; 8] = [
        (
            "stale version",
            |_, e| e.1 = 1,
            AllowitWalletError::StaleRequest,
        ),
        (
            "expired",
            |f, e| e.2 = f.env.ledger().timestamp(),
            AllowitWalletError::Expired,
        ),
        (
            "zero operation id",
            |f, e| e.0 = BytesN::from_array(&f.env, &[0; 32]),
            AllowitWalletError::InvalidInvocation,
        ),
        (
            "gas above the gas cap",
            |_, e| {
                e.5 = 21;
                if let AllowitExpense::Priced(gas_units, _, spent, _) = &mut e.4 {
                    *gas_units = 21;
                    *spent = 31;
                }
            },
            AllowitWalletError::ExcessGas,
        ),
        (
            "negative gas",
            |_, e| e.5 = -1,
            AllowitWalletError::InvalidAmount,
        ),
        (
            "XLM gas counted as another amount",
            |_, e| {
                e.5 = 5;
                if let AllowitExpense::Priced(gas_units, _, spent, _) = &mut e.4 {
                    *gas_units = 4;
                    *spent = 14;
                }
            },
            AllowitWalletError::InvalidInvocation,
        ),
        (
            "gas repaid to the wallet itself",
            |f, e| {
                e.6 = f.wallet.clone();
            },
            AllowitWalletError::InvalidRecipient,
        ),
        (
            "gas repaid on an unpriced request",
            |_, e| {
                e.4 = AllowitExpense::Unpriced;
            },
            AllowitWalletError::InvalidInvocation,
        ),
    ];
    for (name, edit, error) in cases {
        let mut e = f.transfer(10, 5);
        edit(&f, &mut e);
        assert_eq!(f.run(&e), Err(Ok(error)), "{name}");
    }
    // A transfer to the wallet itself; an unpriced request without gas runs.
    let mut e = f.transfer(10, 0);
    if let AllowitStellarOperation::Transfer(_, to, _) = &mut e.3 {
        *to = f.wallet.clone();
    }
    assert_eq!(f.run(&e), Err(Ok(AllowitWalletError::InvalidRecipient)));
    let mut e = f.transfer(10, 0);
    e.4 = AllowitExpense::Unpriced;
    assert_eq!(f.run(&e), Ok(()));
    assert_eq!(f.balance(&f.asset, &f.recipient), 10);
}

#[test]
fn a_wallet_of_another_asset_repays_gas_in_xlm_and_counts_its_attested_units() {
    let f = Fixture::with(COMMON, true, |_, _| {});
    let e = f.transfer(10, 4);
    assert_eq!(f.run(&e), Ok(()));
    assert_eq!(f.balance(&f.asset, &f.recipient), 10);
    assert_eq!(f.balance(&f.native, &f.wallet), 496);
    assert_eq!(f.balance(&f.native, &f.payee), 1_000_000_004);
    // Spent counts the payment and the attested gas units, 10 + 8.
    assert_eq!(f.figures().spent, 18);
    // Gas without units, or units without gas, is refused.
    let mut e = f.transfer(10, 4);
    if let AllowitExpense::Priced(gas_units, _, spent, _) = &mut e.4 {
        *gas_units = 0;
        *spent = 10;
    }
    assert_eq!(f.run(&e), Err(Ok(AllowitWalletError::InvalidInvocation)));
    // A USDC-only wallet gets a signed repayment of zero.
    let f = Fixture::with(COMMON, true, |_, c| c.gas_cap = 0);
    assert_eq!(
        f.run(&f.transfer(10, 1)),
        Err(Ok(AllowitWalletError::ExcessGas))
    );
    assert_eq!(f.run(&f.transfer(10, 0)), Ok(()));
}

// --- Storage ------------------------------------------------------------------------------------

#[test]
fn a_simple_payment_writes_no_contract_data() {
    let f = Fixture::new(SIMPLE);
    let before = f.entries();
    assert_eq!(before.len(), 1, "the instance only");
    assert_eq!(f.run(&f.transfer(10, 5)), Ok(()));
    assert_eq!(f.entries(), before);
    assert_eq!(f.balance(&f.asset, &f.recipient), 10);
    // A Standard wallet whose rules read no figure writes nothing either.
    let f = Fixture::with(COMMON, false, |env, c| {
        c.rules = Vec::from_array(env, [AllowitRule::destinations, AllowitRule::payment_limit]);
    });
    let before = f.entries();
    assert_eq!(f.run(&f.transfer(10, 5)), Ok(()));
    assert_eq!(f.entries(), before);
    assert_eq!(f.client().state().kept, 0);
}

#[test]
fn instance_sizes_stay_within_the_design() {
    let simple = Fixture::new(SIMPLE).instance_bytes();
    let common = Fixture::new(COMMON).instance_bytes();
    std::println!("instance bytes: simple {simple}, common {common}");
    assert!(simple <= 390, "simple {simple}");
    assert!(common <= 700, "common {common}");
}

#[test]
fn daily_figures_live_in_a_window_that_ends_with_its_own_ledger() {
    let f = Fixture::with(COMMON, false, |env, c| {
        c.rules = Vec::from_array(env, [AllowitRule::daily_spending_limit]);
    });
    assert_eq!(f.client().state().kept, u32::from(DAY_SPENT));
    assert!(f.entries().len() == 1, "no t without a total figure");
    assert_eq!(f.run(&f.transfer(100, 0)), Ok(()));
    let start = f.env.ledger().sequence();
    let figures = f.figures();
    assert_eq!(
        (figures.day_spent, figures.day_ends),
        (100, start + DAY_LEDGERS - 1)
    );
    assert_eq!(f.daily_ttl(), DAY_LEDGERS - 1);
    // Within the window: 100 + 101 > 200.
    f.advance(10);
    assert_eq!(
        f.run(&f.transfer(101, 0)),
        denied(COMMON, AllowitError::DailySpendingLimitExceeded)
    );
    assert_eq!(f.run(&f.transfer(100, 0)), Ok(()));
    assert_eq!(f.figures().day_spent, 200);
    assert_eq!(f.daily_ttl(), DAY_LEDGERS - 11, "a payment never extends d");
    // Someone pays to keep d alive past its end: the window still ends at its own ledger.
    f.env.as_contract(&f.wallet, || {
        f.env
            .storage()
            .temporary()
            .extend_ttl(&DAILY, 100_000, 100_000)
    });
    f.advance(DAY_LEDGERS - 11);
    assert_eq!(f.env.ledger().sequence(), start + DAY_LEDGERS - 1);
    assert_eq!(
        f.run(&f.transfer(1, 0)),
        denied(COMMON, AllowitError::DailySpendingLimitExceeded)
    );
    f.advance(1);
    assert_eq!(f.figures().day_ends, 0, "the window has ended");
    assert_eq!(f.run(&f.transfer(100, 0)), Ok(()));
    let now = f.env.ledger().sequence();
    assert_eq!(f.figures().day_ends, now + DAY_LEDGERS - 1);
    assert!(f.daily_ttl() >= DAY_LEDGERS - 1);
    // After the entry lapses the figures are zero again.
    f.advance(200_000);
    assert_eq!(f.figures(), AllowitFigures::default());
    assert_eq!(f.run(&f.transfer(100, 0)), Ok(()));
}

/// The window of `d` follows Core's rule at its edges (`allowit::daily_window_end`, the end being
/// the window's last ledger): a write at the last ledger keeps the end; one ledger later the
/// figures read as zero, and the next write opens a window from that ledger.
#[test]
fn daily_figures_keep_cores_window_at_its_edges() {
    let f = Fixture::with(COMMON, false, |env, c| {
        c.rules = Vec::from_array(env, [AllowitRule::daily_spending_limit]);
    });
    assert_eq!(f.run(&f.transfer(10, 0)), Ok(()));
    let start = f.env.ledger().sequence();
    let end = start + DAY_LEDGERS - 1;
    assert_eq!(f.figures().day_ends, end);
    f.advance(DAY_LEDGERS - 1);
    assert_eq!(f.env.ledger().sequence(), end);
    assert_eq!(f.run(&f.transfer(10, 0)), Ok(()));
    assert_eq!((f.figures().day_spent, f.figures().day_ends), (20, end));
    f.advance(1);
    assert_eq!(f.figures().day_ends, 0, "the window has ended");
    assert_eq!(f.run(&f.transfer(10, 0)), Ok(()));
    assert_eq!(
        (f.figures().day_spent, f.figures().day_ends),
        (10, end + DAY_LEDGERS)
    );
    // The same ends from Core's rule for a changed value.
    let (before, after) = (AllowitValue::Bool(false), AllowitValue::Bool(true));
    for (open, at, want) in [(Some(end), end, end), (None, end + 1, end + DAY_LEDGERS)] {
        assert_eq!(
            allowit::daily_window_end(
                open.map(|end| (&before, u64::from(end))),
                &after,
                u64::from(at),
                u64::from(DAY_LEDGERS)
            ),
            Ok(u64::from(want))
        );
    }
}

/// Each call keeps the wallet live. Once the instance has at most `TOTAL_LEDGERS - RENEWAL_LEDGERS`
/// ledgers left, a call renews it to `TOTAL_LEDGERS - 1`; a call above that threshold renews
/// nothing. A Custom wallet's code is its own, and a call renews it the same way;
/// the code that a fixed tier shares with every wallet of its kind is Allowit's to keep live, and
/// no call of a wallet renews it.
#[test]
fn a_call_below_the_threshold_renews_the_instance_and_a_custom_wallets_own_code() {
    for (wasm, owns_code) in [(SIMPLE, false), (COMMON, false), (CUSTOM, true)] {
        let f = Fixture::new(wasm);
        let instance = || f.env.deployer().get_contract_instance_ttl(&f.wallet);
        let code = || f.env.deployer().get_contract_code_ttl(&f.wallet);
        let advance = |ledgers: u32| f.env.ledger().with_mut(|l| l.sequence_number += ledgers);
        assert_eq!(instance(), TOTAL_LEDGERS - 1);
        if owns_code {
            assert_eq!(code(), TOTAL_LEDGERS - 1);
        }
        // Each owner call names the next deployment version.
        let mut version = 0u32;
        let mut pause = |paused: bool| {
            version += 1;
            f.owner_call("set_pause", (paused, version).into_val(&f.env))
        };
        // Above the threshold a call renews nothing.
        advance(RENEWAL_LEDGERS - 2);
        let (live_instance, live_code) = (instance(), code());
        assert_eq!(pause(true), Ok(()));
        assert_eq!((instance(), code()), (live_instance, live_code));
        // At it, the instance lives `TOTAL_LEDGERS - 1` again, and a Custom wallet's code too.
        advance(1);
        let shared_code = code();
        assert_eq!(pause(false), Ok(()));
        assert_eq!(instance(), TOTAL_LEDGERS - 1);
        if owns_code {
            assert_eq!(code(), TOTAL_LEDGERS - 1);
        } else {
            assert_eq!(code(), shared_code);
        }
    }
    // The agent's operation keeps the wallet live as well.
    let f = Fixture::new(COMMON);
    f.env
        .ledger()
        .with_mut(|l| l.sequence_number += RENEWAL_LEDGERS + 1);
    assert_eq!(f.run(&f.transfer(10, 0)), Ok(()));
    assert_eq!(
        f.env.deployer().get_contract_instance_ttl(&f.wallet),
        TOTAL_LEDGERS - 1
    );
}

/// Every committed call of a wallet keeps it live, also a read of its state: at the threshold it
/// renews the instance, and a Custom wallet's own code too; above it, nothing.
#[test]
fn a_committed_state_read_renews_the_wallet_under_the_threshold() {
    for (wasm, owns_code) in [(SIMPLE, false), (COMMON, false), (CUSTOM, true)] {
        let f = Fixture::new(wasm);
        let instance = || f.env.deployer().get_contract_instance_ttl(&f.wallet);
        let code = || f.env.deployer().get_contract_code_ttl(&f.wallet);
        let advance = |ledgers: u32| f.env.ledger().with_mut(|l| l.sequence_number += ledgers);
        advance(RENEWAL_LEDGERS - 2);
        let (live_instance, live_code) = (instance(), code());
        f.client().state();
        assert_eq!((instance(), code()), (live_instance, live_code));
        advance(1);
        let shared_code = code();
        f.client().state();
        assert_eq!(instance(), TOTAL_LEDGERS - 1);
        if owns_code {
            assert_eq!(code(), TOTAL_LEDGERS - 1);
        } else {
            assert_eq!(code(), shared_code);
        }
    }
}

/// An upgrade keeps the code that it installs live, whatever the tier that it leaves or enters:
/// the owner's upgrade renews the new code, whose own upload gave it the network's minimum
/// lifetime only.
#[test]
fn an_upgrade_renews_the_code_that_it_installs() {
    for (from, to) in [
        (CUSTOM, CATCHING),
        (SIMPLE, CATCHING),
        (CUSTOM, DAILY_STATE),
    ] {
        let f = Fixture::new(from);
        let next = f.env.deployer().upload_contract_wasm(to);
        let mut u = f.update();
        u.wasm_hash = Some(next.clone());
        assert_eq!(f.owner_call("deploy_policy", (u,).into_val(&f.env)), Ok(()));
        assert_eq!(
            f.env.deployer().get_contract_code_ttl(&f.wallet),
            TOTAL_LEDGERS - 1
        );
    }
}

#[test]
fn total_figures_are_created_at_deployment_and_kept_for_their_checks() {
    let f = Fixture::with(COMMON, false, |env, c| {
        c.rules = Vec::from_array(
            env,
            [
                AllowitRule::lifetime_spending_limit,
                AllowitRule::call_limit,
            ],
        );
    });
    assert_eq!(f.client().state().kept, u32::from(TOTALS));
    let ttl = f
        .env
        .as_contract(&f.wallet, || f.env.storage().persistent().get_ttl(&TOTAL));
    assert_eq!(ttl, TOTAL_LEDGERS - 1);
    assert_eq!(
        f.env.deployer().get_contract_instance_ttl(&f.wallet),
        TOTAL_LEDGERS - 1
    );
    let total_bytes = || {
        f.env.as_contract(&f.wallet, || {
            let raw: Bytes = f.env.storage().persistent().get(&TOTAL).unwrap();
            raw.len()
        })
    };
    // `t` has one fixed size, so no payment pays rent for a larger value.
    assert_eq!(total_bytes(), 12);
    for amount in [100, 100] {
        assert_eq!(f.run(&f.transfer(amount, 0)), Ok(()));
        assert_eq!(total_bytes(), 12);
    }
    assert_eq!(
        f.run(&f.transfer(51, 0)),
        denied(COMMON, AllowitError::LifetimeSpendingLimitExceeded)
    );
    assert_eq!(f.run(&f.transfer(50, 0)), Ok(()));
    let figures = f.figures();
    assert_eq!((figures.spent, figures.calls), (250, 3));
    // The call limit of 4 counts the next one, then denies.
    let mut e = f.transfer(1, 0);
    e.4 = AllowitExpense::Unpriced;
    assert_eq!(
        f.run(&e),
        denied(COMMON, AllowitError::LifetimeSpendingLimitExceeded)
    );
    // No daily entry exists for a wallet without daily checks.
    assert!(
        f.env
            .as_contract(&f.wallet, || !f.env.storage().temporary().has(&DAILY))
    );
}

#[test]
fn an_owner_update_reshapes_the_kept_figures() {
    let f = Fixture::with(COMMON, false, |env, c| {
        c.rules = Vec::from_array(env, [AllowitRule::destinations]);
    });
    assert_eq!(f.run(&f.transfer(100, 0)), Ok(()));
    assert_eq!(f.entries().len(), 1);
    // Adding a lifetime limit creates t at zero: it counts from its installation.
    let mut u = f.update();
    u.rules = Vec::from_array(&f.env, [AllowitRule::lifetime_spending_limit]);
    assert_eq!(
        f.owner_call("deploy_policy", (u.clone(),).into_val(&f.env)),
        Ok(())
    );
    assert_eq!(
        f.client().state().kept,
        0,
        "a rule without its param reads no figure"
    );
    let mut u = f.update();
    u.params.set(
        Symbol::new(&f.env, LIFETIME_SPENDING_LIMIT),
        AllowitValue::Int(250),
    );
    assert_eq!(f.owner_call("deploy_policy", (u,).into_val(&f.env)), Ok(()));
    assert_eq!(f.client().state().kept, u32::from(SPENT));
    assert_eq!(f.figures().spent, 0);
    assert_eq!(f.run(&f.transfer(200, 0)), Ok(()));
    assert_eq!(f.figures().spent, 200);
    // No check reads the call count, so it is not kept.
    assert_eq!(f.figures().calls, 0);
    let stored_calls = || {
        f.env.as_contract(&f.wallet, || {
            let raw: Bytes = f.env.storage().persistent().get(&TOTAL).unwrap();
            raw.slice(8..12)
        })
    };
    assert_eq!(stored_calls(), Bytes::from_array(&f.env, &[0; 4]));
    // Keeping it carries the figure; dropping every total removes t.
    let mut u = f.update();
    u.params.set(
        Symbol::new(&f.env, LIFETIME_SPENDING_LIMIT),
        AllowitValue::Int(300),
    );
    assert_eq!(f.owner_call("deploy_policy", (u,).into_val(&f.env)), Ok(()));
    assert_eq!(f.figures().spent, 200);
    let mut u = f.update();
    u.rules = Vec::new(&f.env);
    assert_eq!(f.owner_call("deploy_policy", (u,).into_val(&f.env)), Ok(()));
    assert_eq!(f.entries().len(), 1);
    // A request signed before the update is stale.
    let mut e = f.transfer(1, 0);
    e.1 = 0;
    assert_eq!(f.run(&e), Err(Ok(AllowitWalletError::StaleRequest)));
}

#[test]
fn standard_keeps_only_the_params_of_its_rules_and_packs_them() {
    let f = Fixture::with(COMMON, false, |env, c| {
        c.rules = Vec::from_array(
            env,
            [AllowitRule::destinations, AllowitRule::daily_volume_limit],
        );
    });
    let params = f.client().state().params;
    assert_eq!(params.len(), 2);
    assert!(params.contains_key(Symbol::new(&f.env, DESTINATIONS)));
    assert!(params.contains_key(Symbol::new(&f.env, DAILY_VOLUME_LIMIT)));
}

#[test]
fn custom_params_of_every_kind_round_trip_through_the_packed_instance() {
    fn values(env: &Env) -> List<(&'static str, AllowitValue)> {
        let account = Address::from_payload(
            env,
            AddressPayload::AccountIdPublicKeyEd25519(BytesN::from_array(env, &[50; 32])),
        );
        let contract = Address::from_payload(
            env,
            AddressPayload::ContractIdHash(BytesN::from_array(env, &[51; 32])),
        );
        let mut nested = Vec::new(env);
        nested.push_back(AllowitValue::Int(-1));
        nested.push_back(AllowitValue::List(Vec::from_array(
            env,
            [AllowitValue::Bool(false)],
        )));
        std::vec![
            ("zero", AllowitValue::Int(0)),
            ("negative", AllowitValue::Int(i128::MIN)),
            ("large", AllowitValue::Int(i128::MAX)),
            ("flag", AllowitValue::Bool(true)),
            (
                "text",
                AllowitValue::Str(soroban_sdk::String::from_str(env, "an invoice, \u{e9}"))
            ),
            (
                "empty",
                AllowitValue::Str(soroban_sdk::String::from_str(env, ""))
            ),
            ("account", AllowitValue::Addr(account)),
            ("contract", AllowitValue::Addr(contract)),
            ("nested", AllowitValue::List(nested)),
            ("a_key_of_exactly_thirty_two_char", AllowitValue::Int(7)),
        ]
    }
    let f = Fixture::with(CUSTOM, false, |env, c| {
        for (key, value) in values(env) {
            c.params.set(Symbol::new(env, key), value);
        }
    });
    let stored = f.client().state().params;
    for (key, value) in values(&f.env) {
        assert_eq!(stored.get(Symbol::new(&f.env, key)), Some(value), "{key}");
    }
}

// --- Policies -------------------------------------------------------------------------------------

#[test]
fn standard_and_custom_rules_deny_on_chain_and_simple_runs_none() {
    for wasm in [COMMON, CUSTOM] {
        let f = Fixture::new(wasm);
        assert_eq!(f.client().state().kept, u32::from(ALL), "every figure");
        assert_eq!(
            f.run(&f.transfer(101, 0)),
            denied(wasm, AllowitError::PaymentLimitExceeded)
        );
        let mut e = f.transfer(10, 0);
        if let AllowitStellarOperation::Transfer(_, to, _) = &mut e.3 {
            *to = Address::generate(&f.env);
        }
        assert_eq!(f.run(&e), denied(wasm, AllowitError::DestinationNotAllowed));
        // 100 + 5 gas, then 50 + 5: the daily volume of 160 holds 160 but not 161; the daily
        // spending limit is 200.
        assert_eq!(f.run(&f.transfer(100, 5)), Ok(()));
        assert_eq!(
            f.run(&f.transfer(50, 6)),
            denied(wasm, AllowitError::DailyVolumeLimitExceeded)
        );
        assert_eq!(f.run(&f.transfer(50, 5)), Ok(()));
        let figures = f.figures();
        assert_eq!(
            (
                figures.calls,
                figures.spent,
                figures.day_spent,
                figures.day_total
            ),
            (2, 160, 160, 160)
        );
    }
    let f = Fixture::new(SIMPLE);
    assert_eq!(f.client().state().kept, 0);
    assert_eq!(f.run(&f.transfer(500, 0)), Ok(()));
}

/// The storage key of the catching fixture's `over_daily_spending_limit`.
const OVER_KEY: u32 = 0xce9c7d57;
/// The storage key of the daily fixture's `day_payments`.
const DAY_PAYMENTS_KEY: u32 = 0x6df215e2;

impl Fixture {
    /// The raw value of a persistent policy state entry, with the ledgers that it still lives.
    fn persistent_state(&self, key: u32) -> Option<(soroban_sdk::Bytes, u32)> {
        self.env.as_contract(&self.wallet, || {
            let storage = self.env.storage().persistent();
            storage
                .get::<u32, soroban_sdk::Bytes>(&key)
                .map(|raw| (raw, storage.get_ttl(&key)))
        })
    }
    /// The raw value of a daily policy state entry, with the ledgers that it still lives.
    fn daily_state(&self, key: u32) -> Option<(soroban_sdk::Bytes, u32)> {
        self.env.as_contract(&self.wallet, || {
            let storage = self.env.storage().temporary();
            storage
                .get::<u32, soroban_sdk::Bytes>(&key)
                .map(|raw| (raw, storage.get_ttl(&key)))
        })
    }
}

#[test]
fn a_custom_source_keeps_its_own_state_under_a_short_key() {
    let f = Fixture::new(CATCHING);
    // The source reads the daily spending figure and its own counter: the wallet keeps that one
    // figure, not every figure.
    assert_eq!(f.client().state().kept, u32::from(DAY_SPENT));
    // The deployment creates the persistent entry, empty, for the minimum persistent lifetime.
    let (raw, ttl) = f.persistent_state(OVER_KEY).unwrap();
    assert_eq!((raw.len(), ttl), (0, TOTAL_LEDGERS - 1));
    // Within the daily limit of 200 nothing is written.
    assert_eq!(f.run(&f.transfer(100, 0)), Ok(()));
    assert_eq!(f.persistent_state(OVER_KEY).unwrap().0.len(), 0);
    // Over it the source catches the denial and counts: twice.
    for count in 1..=2 {
        f.advance(10);
        assert_eq!(f.run(&f.transfer(101, 0)), Ok(()));
        let (raw, ttl) = f.persistent_state(OVER_KEY).unwrap();
        let mut value = [0u8; 64];
        raw.copy_into_slice(&mut value[..raw.len() as usize]);
        // The packed value: one type byte and the integer, nothing else.
        let mut r = pack::Reader::new(&value[..raw.len() as usize]);
        assert_eq!(
            pack::get_value(&f.env, &mut r).ok(),
            Some(AllowitValue::Int(count))
        );
        assert!(r.done());
        // A write never extends the entry: it lives from the deployment.
        assert_eq!(ttl, TOTAL_LEDGERS - 1 - 10 * count as u32);
    }
    // The third time the counter denies.
    f.advance(10);
    assert_eq!(
        f.run(&f.transfer(101, 0)),
        denied(CATCHING, AllowitError::DailySpendingLimitExceeded)
    );
    assert_eq!(f.balance(&f.asset, &f.recipient), 302);
    // The wallet stores no key name: only the configuration, the daily figures and the counter.
    let keys: List<List<u8>> = f.entries().into_iter().map(|(key, _, _)| key).collect();
    assert_eq!(keys.len(), 3, "{keys:?}");
}

#[test]
fn a_write_of_a_denied_run_never_reaches_a_later_one() {
    let f = Fixture::with(CATCHING, false, |env, config| {
        config
            .params
            .set(Symbol::new(env, "invoice_limit"), AllowitValue::Int(50));
    });
    assert_eq!(f.run(&f.transfer(150, 0)), Ok(()));
    // Over the daily limit with an invoice above its limit: the source counts, then the invoice
    // limit denies.
    f.advance(10);
    let mut e = f.transfer(60, 0);
    e.7.set(Symbol::new(&f.env, "invoice"), AllowitValue::Int(1));
    assert_eq!(
        f.run(&e),
        denied(CATCHING, AllowitError::PaymentLimitExceeded)
    );
    assert_eq!(f.persistent_state(OVER_KEY).unwrap().0.len(), 0);
    // The next run writes nothing: the denied run's count never reaches it.
    f.advance(10);
    assert_eq!(f.run(&f.transfer(10, 0)), Ok(()));
    assert_eq!(f.persistent_state(OVER_KEY).unwrap().0.len(), 0);
}

#[test]
fn a_daily_state_entry_lives_one_window_and_a_read_never_extends_it() {
    let f = Fixture::new(DAILY_STATE);
    // The source reads no figure and creates no persistent entry.
    assert_eq!(f.client().state().kept, 0);
    assert!(f.daily_state(DAY_PAYMENTS_KEY).is_none());
    let start = f.env.ledger().sequence();
    assert_eq!(f.run(&f.transfer(10, 0)), Ok(()));
    // The first write opens a window: the entry holds its end ledger and lives that long.
    let (raw, ttl) = f.daily_state(DAY_PAYMENTS_KEY).unwrap();
    let mut value = [0u8; 68];
    raw.copy_into_slice(&mut value[..raw.len() as usize]);
    assert_eq!(&value[..4], &(start + DAY_LEDGERS - 1).to_be_bytes());
    assert_eq!(ttl, DAY_LEDGERS - 1);
    f.advance(100);
    assert_eq!(f.run(&f.transfer(10, 0)), Ok(()));
    // A write in an open window keeps its end and its lifetime.
    assert_eq!(
        f.daily_state(DAY_PAYMENTS_KEY).unwrap().1,
        DAY_LEDGERS - 101
    );
    // Two payments today: the third is denied, and the denial writes nothing.
    f.advance(100);
    assert_eq!(
        f.run(&f.transfer(10, 0)),
        denied(DAILY_STATE, AllowitError::CallLimitExceeded)
    );
    // Someone pays to keep the entry alive past its end ledger: after that ledger it still reads
    // as absent.
    f.env.as_contract(&f.wallet, || {
        f.env
            .storage()
            .temporary()
            .extend_ttl(&DAY_PAYMENTS_KEY, DAY_LEDGERS, DAY_LEDGERS)
    });
    f.advance(DAY_LEDGERS - 200);
    assert!(f.daily_state(DAY_PAYMENTS_KEY).is_some());
    assert_eq!(f.run(&f.transfer(10, 0)), Ok(()));
    // The new window starts now and the entry lives one window again.
    let now = f.env.ledger().sequence();
    let (raw, ttl) = f.daily_state(DAY_PAYMENTS_KEY).unwrap();
    raw.copy_into_slice(&mut value[..raw.len() as usize]);
    assert_eq!(&value[..4], &(now + DAY_LEDGERS - 1).to_be_bytes());
    assert_eq!(ttl, DAY_LEDGERS - 1);
    assert_eq!(f.balance(&f.asset, &f.recipient), 30);
}

/// A policy that declares one persistent and one daily entry, for direct calls of the state
/// functions.
struct Declared;
impl AllowitPolicy for Declared {
    const KIND: &'static str = "declared";
    const STATE: &'static [AllowitStateKey] = &[
        AllowitStateKey {
            name: "note",
            key: 1,
            daily: false,
        },
        AllowitStateKey {
            name: "day_note",
            key: 2,
            daily: true,
        },
    ];
    fn check(_: &AllowitContext, _: &Vec<AllowitRule>) -> Result<(), AllowitWalletError> {
        Ok(())
    }
}

#[test]
fn a_state_value_over_its_bound_or_an_undeclared_key_is_refused() {
    let f = Fixture::new(SIMPLE);
    let env = &f.env;
    f.env.as_contract(&f.wallet, || {
        let before: [Slot; MAX_POLICY_STATE] = Default::default();
        let text =
            |len: usize| AllowitValue::Str(soroban_sdk::String::from_str(env, &"x".repeat(len)));
        let write = |key: &str, value: AllowitValue| {
            let mut state = Map::new(env);
            state.set(Symbol::new(env, key), value);
            write_policy_state::<Declared>(env, &state, &before)
        };
        // 62 text bytes pack into 64: the most that a value holds.
        assert_eq!(write("note", text(62)), Ok(()));
        assert_eq!(write("day_note", text(62)), Ok(()));
        assert_eq!(
            write("note", text(63)),
            Err(AllowitWalletError::InvalidState)
        );
        assert_eq!(
            write("day_note", text(63)),
            Err(AllowitWalletError::InvalidState)
        );
        // A key that the build did not declare is never stored.
        assert_eq!(
            write("other", AllowitValue::Int(1)),
            Err(AllowitWalletError::InvalidState)
        );
        // Both entries read back with their values.
        let slots = read_policy_state::<Declared>(env).unwrap();
        assert_eq!(slots[0].value, Some(text(62)));
        assert_eq!(slots[1].value, Some(text(62)));
    });
}

/// The wallet keeps a daily entry by Core's rule (`allowit::daily_window_end`): the window's end
/// is its last ledger, inclusive. A write at that ledger keeps the window; the entry reads as
/// absent one ledger later, and the next write opens a new window there.
#[test]
fn a_daily_entry_keeps_its_window_through_its_last_ledger_by_cores_rule() {
    let f = Fixture::new(SIMPLE);
    let env = &f.env;
    let write = |value: i128| {
        env.as_contract(&f.wallet, || {
            let before = read_policy_state::<Declared>(env).unwrap();
            let mut state = Map::new(env);
            state.set(Symbol::new(env, "day_note"), AllowitValue::Int(value));
            write_policy_state::<Declared>(env, &state, &before)
        })
    };
    let read = || {
        env.as_contract(&f.wallet, || {
            read_policy_state::<Declared>(env).unwrap()[1].clone()
        })
    };
    let start = env.ledger().sequence();
    assert_eq!(write(1), Ok(()));
    let end = start + DAY_LEDGERS - 1;
    assert_eq!(read().day_ends, Some(end));
    assert_eq!(
        u64::from(end),
        allowit::daily_window_end(
            None,
            &AllowitValue::Int(1),
            u64::from(start),
            u64::from(DAY_LEDGERS)
        )
        .unwrap()
    );
    // At the window's last ledger the value still reads, and a write keeps the end.
    f.advance(end - start);
    assert_eq!(read().value, Some(AllowitValue::Int(1)));
    assert_eq!(write(2), Ok(()));
    assert_eq!(read().day_ends, Some(end));
    // One ledger later the window has ended: the value reads as absent, and a write opens a new
    // window from that ledger.
    f.advance(1);
    assert_eq!(read().value, None);
    assert_eq!(write(3), Ok(()));
    assert_eq!(read().day_ends, Some(end + DAY_LEDGERS));
}

#[test]
fn one_event_names_the_operation_and_its_output() {
    let f = Fixture::new(SIMPLE);
    let e = f.transfer(10, 5);
    assert_eq!(f.run(&e), Ok(()));
    let events = f.events();
    assert_eq!(events.len(), 1);
    let (topics, data) = &events[0];
    assert_eq!(
        topics,
        &std::vec![
            xdr::ScVal::Symbol("allowit".try_into().unwrap()),
            xdr::ScVal::Bytes(e.0.to_array().to_vec().try_into().unwrap()),
        ]
    );
    assert_eq!(data, &xdr::ScVal::I128(xdr::Int128Parts { hi: 0, lo: 10 }));
}

// --- Swap, deposit and redeem through `execute` ----------------------------------------------

/// Test pair: holds output reserves and pays them out for the router.
#[contract]
pub struct MockPair;
#[contractimpl]
impl MockPair {
    pub fn pay(env: Env, token: Address, to: Address, amount: i128) {
        token::Client::new(&env, &token).transfer(&env.current_contract_address(), &to, &amount);
    }
}
/// Test router of the Soroswap shape: pays `amount_in * rate / 100`.
#[contract]
pub struct MockRouter;
#[contractimpl]
impl MockRouter {
    pub fn __constructor(env: Env, pair: Address, rate: i128) {
        env.storage().instance().set(&0u32, &(pair, rate));
    }
    pub fn router_pair_for(env: Env, _a: Address, _b: Address) -> Address {
        let (pair, _): (Address, i128) = env.storage().instance().get(&0u32).unwrap();
        pair
    }
    pub fn swap_exact_tokens_for_tokens(
        env: Env,
        amount_in: i128,
        amount_out_min: i128,
        path: Vec<Address>,
        to: Address,
        _deadline: u64,
    ) -> Vec<i128> {
        let (pair, rate): (Address, i128) = env.storage().instance().get(&0u32).unwrap();
        to.require_auth();
        let out = amount_in * rate / 100;
        assert!(out >= amount_out_min);
        token::Client::new(&env, &path.get_unchecked(0)).transfer(&to, &pair, &amount_in);
        MockPairClient::new(&env, &pair).pay(&path.get_unchecked(path.len() - 1), &to, &out);
        let mut amounts = Vec::new(&env);
        amounts.push_back(amount_in);
        for _ in 1..path.len() {
            amounts.push_back(out);
        }
        amounts
    }
}

/// Price a swap, deposit or redeem: its spent units are the conversion loss plus gas.
fn priced(f: &Fixture, e: &mut AllowitExecutionRequest, conversion: i128) {
    e.4 = AllowitExpense::Priced(e.5, conversion, conversion + e.5, f.env.ledger().sequence());
}

#[test]
fn swap_deposit_and_redeem_run_through_execute_with_effect_checks() {
    // A Custom wallet's deposit runs in `a_custom_wallet_deposits_within_its_policy`.
    for wasm in [SIMPLE, COMMON] {
        let f = Fixture::with(wasm, false, |env, c| {
            if !c.rules.is_empty() {
                c.rules = Vec::from_array(env, [AllowitRule::payment_limit]);
            }
        });
        f.env.mock_all_auths();
        // Swap 50 XLM for 47 of another SAC.
        let other = f
            .env
            .register_stellar_asset_contract_v2(Address::generate(&f.env))
            .address();
        let pair = f.env.register(MockPair, ());
        StellarAssetClient::new(&f.env, &other).mint(&pair, &1_000);
        let router = f.env.register(MockRouter, (pair.clone(), 95i128));
        f.env.set_auths(&[]);
        let mut e = f.transfer(1, 0);
        e.3 = AllowitStellarOperation::Swap(
            router.clone(),
            50,
            47,
            Vec::from_array(&f.env, [f.asset.clone(), other.clone()]),
            e.2,
        );
        priced(&f, &mut e, 3);
        assert_eq!(f.run(&e), Ok(()));
        assert_eq!(
            f.events().last().unwrap().1,
            xdr::ScVal::I128(xdr::Int128Parts { hi: 0, lo: 47 })
        );
        assert_eq!(
            (f.balance(&f.asset, &f.wallet), f.balance(&other, &f.wallet)),
            (950, 47)
        );
        // Deposit 40 into a vault and redeem 30 shares.
        let vault = f.env.register(VAULT, (f.asset.clone(), 0u32));
        let mut e = f.transfer(1, 0);
        e.0 = BytesN::from_array(&f.env, &[2; 32]);
        e.3 = AllowitStellarOperation::Deposit(vault.clone(), 40, 40);
        priced(&f, &mut e, 0);
        assert_eq!(f.run(&e), Ok(()));
        let vault_client = AllowitSep56TestVaultClient::new(&f.env, &vault);
        assert_eq!(vault_client.balance(&f.wallet), 40);
        let mut e = f.transfer(1, 0);
        e.0 = BytesN::from_array(&f.env, &[3; 32]);
        e.3 = AllowitStellarOperation::Redeem(vault.clone(), 30, 30);
        priced(&f, &mut e, 0);
        assert_eq!(f.run(&e), Ok(()));
        assert_eq!(
            (
                vault_client.balance(&f.wallet),
                f.balance(&f.asset, &f.wallet)
            ),
            (10, 940)
        );
        // A deposit into a vault of another asset is refused.
        let wrong = f.env.register(VAULT, (other.clone(), 0u32));
        let mut e = f.transfer(1, 0);
        e.0 = BytesN::from_array(&f.env, &[4; 32]);
        e.3 = AllowitStellarOperation::Deposit(wrong, 10, 10);
        priced(&f, &mut e, 0);
        assert_eq!(f.run(&e), Err(Ok(AllowitWalletError::UnsupportedAsset)));
    }
}

#[test]
fn a_custom_wallet_deposits_within_its_policy() {
    let f = Fixture::with(CUSTOM, false, |env, c| {
        c.params
            .set(Symbol::new(env, OPERATIONS), op_names(env, &["deposit"]));
    });
    f.env.mock_all_auths();
    let vault = f.env.register(VAULT, (f.asset.clone(), 0u32));
    f.env.set_auths(&[]);
    let mut params = f.update();
    params.params.set(
        Symbol::new(&f.env, DESTINATIONS),
        addresses(&f.env, &[&f.recipient, &vault]),
    );
    assert_eq!(
        f.owner_call("deploy_policy", (params,).into_val(&f.env)),
        Ok(())
    );
    let mut e = f.transfer(1, 0);
    e.3 = AllowitStellarOperation::Deposit(vault.clone(), 40, 40);
    priced(&f, &mut e, 0);
    assert_eq!(f.run(&e), Ok(()));
    // The sample source limits each payment to 100: a deposit of 101 is denied.
    let mut e = f.transfer(1, 0);
    e.0 = BytesN::from_array(&f.env, &[2; 32]);
    e.3 = AllowitStellarOperation::Deposit(vault, 101, 101);
    priced(&f, &mut e, 0);
    assert_eq!(
        f.run(&e),
        denied(CUSTOM, AllowitError::PaymentLimitExceeded)
    );
    // A transfer is not among the operations now.
    assert_eq!(
        f.run(&f.transfer(1, 0)),
        denied(CUSTOM, AllowitError::OperationNotAllowed)
    );
}

// --- The owner ------------------------------------------------------------------------------------

#[test]
fn the_owner_pauses_resumes_and_stops_with_the_funds_back() {
    let f = Fixture::with(COMMON, true, |_, _| {});
    assert_eq!(
        f.owner_call("set_pause", (true, 0u32).into_val(&f.env)),
        Err(AllowitWalletError::StaleRequest)
    );
    assert_eq!(
        f.owner_call("set_pause", (true, 1u32).into_val(&f.env)),
        Ok(())
    );
    let e = f.transfer(10, 0);
    assert_eq!(f.run(&e), Err(Ok(AllowitWalletError::Paused)));
    assert_eq!(
        f.owner_call("set_pause", (false, 2u32).into_val(&f.env)),
        Ok(())
    );
    // The request of version 1 is stale now.
    assert_eq!(f.run(&e), Err(Ok(AllowitWalletError::StaleRequest)));
    assert_eq!(f.run(&f.transfer(10, 0)), Ok(()));
    // A stranger cannot stop it.
    let stranger = Address::generate(&f.env);
    let invoke = MockAuthInvoke {
        contract: &f.wallet,
        fn_name: "stop",
        args: (3u32,).into_val(&f.env),
        sub_invokes: &[],
    };
    f.env.mock_auths(&[MockAuth {
        address: &stranger,
        invoke: &invoke,
    }]);
    assert!(f.client().try_stop(&3).is_err());
    let owner_xlm = f.balance(&f.native, &f.owner);
    assert_eq!(f.owner_call("stop", (3u32,).into_val(&f.env)), Ok(()));
    assert!(f.client().state().paused);
    assert_eq!(
        (
            f.balance(&f.asset, &f.wallet),
            f.balance(&f.native, &f.wallet)
        ),
        (0, 0)
    );
    assert_eq!(f.balance(&f.asset, &f.owner), 990);
    assert_eq!(f.balance(&f.native, &f.owner), owner_xlm + 500);
    assert_eq!(
        f.run(&f.transfer(1, 0)),
        Err(Ok(AllowitWalletError::Paused))
    );
}

#[test]
fn the_owner_recovers_any_token_and_passes_calls_through() {
    let f = Fixture::new(SIMPLE);
    let to = Address::generate(&f.env);
    assert_eq!(
        f.owner_call(
            "recover",
            (f.native.clone(), f.wallet.clone(), 5i128).into_val(&f.env)
        ),
        Err(AllowitWalletError::InvalidRecipient)
    );
    assert_eq!(
        f.owner_call(
            "recover",
            (f.native.clone(), to.clone(), 0i128).into_val(&f.env)
        ),
        Err(AllowitWalletError::InvalidAmount)
    );
    assert_eq!(
        f.owner_call(
            "recover",
            (f.native.clone(), to.clone(), 5i128).into_val(&f.env)
        ),
        Ok(())
    );
    assert_eq!(f.balance(&f.native, &to), 5);
}

#[test]
fn an_owner_update_checks_its_version_and_a_new_owner_cosigns() {
    let f = Fixture::new(COMMON);
    let mut u = f.update();
    u.deployment_version = 2;
    assert_eq!(
        f.owner_call("deploy_policy", (u,).into_val(&f.env)),
        Err(AllowitWalletError::StaleRequest)
    );
    // Roles stay distinct.
    let mut u = f.update();
    u.server = u.agent.clone();
    assert_eq!(
        f.owner_call("deploy_policy", (u,).into_val(&f.env)),
        Err(AllowitWalletError::InvalidActor)
    );
    // A new owner must sign too.
    let mut u = f.update();
    let new_owner = Address::generate(&f.env);
    u.owner = new_owner.clone();
    let args: Vec<Val> = (u.clone(),).into_val(&f.env);
    let invoke = MockAuthInvoke {
        contract: &f.wallet,
        fn_name: "deploy_policy",
        args: args.clone(),
        sub_invokes: &[],
    };
    f.env.mock_auths(&[MockAuth {
        address: &f.owner,
        invoke: &invoke,
    }]);
    assert!(
        f.client().try_deploy_policy(&u).is_err(),
        "the new owner did not sign"
    );
    f.env.mock_auths(&[
        MockAuth {
            address: &f.owner,
            invoke: &invoke,
        },
        MockAuth {
            address: &new_owner,
            invoke: &invoke,
        },
    ]);
    assert!(f.client().try_deploy_policy(&u).is_ok());
    assert_eq!(f.client().state().owner, new_owner);
}

#[test]
fn construction_checks_the_owner_configuration() {
    let cases: [ConfigCase; 4] = [
        ("agent equals server", |_, c| c.server = c.agent.clone()),
        ("negative gas cap", |_, c| c.gas_cap = -1),
        ("zero source hash", |env, c| {
            c.source_hash = BytesN::from_array(env, &[0; 32])
        }),
        ("simple with a rule", |env, c| {
            c.rules = Vec::from_array(env, [AllowitRule::payment_limit])
        }),
    ];
    for (name, edit) in cases {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            Fixture::with(SIMPLE, false, edit)
        }));
        assert!(result.is_err(), "{name}");
    }
    // A Custom wallet binds the hash of its own source.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        Fixture::with(CUSTOM, false, |env, c| {
            c.source_hash = BytesN::from_array(env, &[9; 32])
        })
    }));
    assert!(result.is_err());
}

// --- Packing ----------------------------------------------------------------------------------

#[test]
fn leb128_and_zigzag_round_trip_at_their_bounds() {
    for value in [
        0u128,
        1,
        127,
        128,
        16_383,
        16_384,
        u64::MAX as u128,
        u128::MAX,
    ] {
        let mut buf = [0u8; 32];
        let mut w = Writer::new(&mut buf);
        w.uint(value).unwrap();
        let n = w.bytes().len();
        let mut r = Reader::new(&buf[..n]);
        assert_eq!(r.uint().unwrap(), value);
        assert!(r.done());
    }
    for value in [0i128, -1, 1, i128::MIN, i128::MAX, -64, 64] {
        let mut buf = [0u8; 32];
        let mut w = Writer::new(&mut buf);
        w.int(value).unwrap();
        let n = w.bytes().len();
        assert_eq!(Reader::new(&buf[..n]).int().unwrap(), value);
    }
    // An overlong integer does not decode.
    let overlong = [0xffu8; 20];
    assert!(Reader::new(&overlong).uint().is_err());
    let mut buf = [0u8; 2];
    assert_eq!(
        Writer::new(&mut buf).put(&[1, 2, 3]),
        Err(AllowitWalletError::InvalidParam)
    );
}

#[test]
fn a_stored_value_with_trailing_bytes_does_not_decode() {
    let f = Fixture::new(SIMPLE);
    let e = f.transfer(1, 0);
    f.env.as_contract(&f.wallet, || {
        let mut raw: Bytes = f.env.storage().instance().get(&CONFIG).unwrap();
        raw.push_back(0);
        f.env.storage().instance().set(&CONFIG, &raw);
    });
    assert_eq!(f.run(&e), Err(Ok(AllowitWalletError::InvalidState)));
    // The owner still stops it: owner calls read only the fixed header.
    assert_eq!(f.owner_call("stop", (1u32,).into_val(&f.env)), Ok(()));
    assert_eq!(f.balance(&f.native, &f.wallet), 0);
}
