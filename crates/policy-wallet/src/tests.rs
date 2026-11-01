extern crate std;
use super::*;
use allowit::{
    AllowitError, AllowitStandardState, CALL_LIMIT, DAILY_SPENDING_LIMIT, DAILY_VOLUME_LIMIT,
    DESTINATIONS, EXPIRES_AT, LIFETIME_SPENDING_LIMIT, OPERATIONS, PAYMENT_LIMIT, TOKENS,
};
use allowit_wallet_protocol::{AllowitExpense, AllowitTransferArgs};
use ed25519_dalek::{Signer, SigningKey};
use soroban_sdk::xdr::FromXdr;
use soroban_sdk::{
    IntoVal, Map, TryIntoVal, contract, contractimpl,
    testutils::{Address as _, Ledger, MockAuth, MockAuthInvoke},
    token::StellarAssetClient,
    vec,
};
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
/// `AllowitCustomPolicy` built with `test-catching` by `scripts/build-contracts.sh`.
pub(super) const CATCHING: &[u8] =
    include_bytes!("../../../target/test-fixtures/custom_catching.wasm");

/// A `List` of `Addr` values.
pub(super) fn addresses(env: &Env, items: &[&Address]) -> AllowitValue {
    let mut list = Vec::new(env);
    for item in items {
        list.push_back(AllowitValue::Addr((*item).clone()));
    }
    AllowitValue::List(list)
}
/// A `List` of `Str` op names, an `operations` value.
pub(super) fn op_names(env: &Env, names: &[&str]) -> AllowitValue {
    let mut list = Vec::new(env);
    for name in names {
        list.push_back(AllowitValue::Str(String::from_str(env, name)));
    }
    AllowitValue::List(list)
}
/// Set one param, or remove it with `None`.
pub(super) fn set_param(
    params: &mut Map<Symbol, AllowitValue>,
    key: &str,
    value: Option<AllowitValue>,
) {
    let key = Symbol::new(params.env(), key);
    match value {
        Some(value) => params.set(key, value),
        None => {
            params.remove(key);
        }
    }
}

/// The transfer arguments of `e`, for edits.
pub(super) fn transfer_args(e: &mut AllowitExecutionRequest) -> &mut AllowitTransferArgs {
    match &mut e.operation {
        AllowitStellarOperation::Transfer(args) => args,
        other => panic!("not a transfer: {other:?}"),
    }
}

pub(super) struct Fixture {
    pub(super) env: Env,
    pub(super) wallet: Address,
    pub(super) owner: Address,
    pub(super) agent: Address,
    pub(super) server: Address,
    pub(super) asset: Address,
    pub(super) recipient: Address,
    pub(super) akey: SigningKey,
    pub(super) skey: SigningKey,
}
/// A classic account of `key` with master weight one, so native account authorization works.
pub(super) fn add_account(env: &Env, key: &SigningKey) -> Address {
    use soroban_sdk::xdr as x;
    let account_id = x::AccountId(x::PublicKey::PublicKeyTypeEd25519(x::Uint256(
        key.verifying_key().to_bytes(),
    )));
    let ledger_key = std::rc::Rc::new(x::LedgerKey::Account(x::LedgerKeyAccount {
        account_id: account_id.clone(),
    }));
    let entry = std::rc::Rc::new(x::LedgerEntry {
        data: x::LedgerEntryData::Account(x::AccountEntry {
            account_id,
            balance: 1_000_000_000,
            flags: 0,
            home_domain: Default::default(),
            inflation_dest: None,
            num_sub_entries: 0,
            seq_num: x::SequenceNumber(0),
            thresholds: x::Thresholds([1; 4]),
            signers: Default::default(),
            ext: x::AccountEntryExt::V0,
        }),
        last_modified_ledger_seq: 100,
        ext: x::LedgerEntryExt::V0,
    });
    env.host()
        .add_ledger_entry(&ledger_key, &entry, None)
        .unwrap();
    address(env, key)
}
/// Native signature of a classic account over an authorization payload.
#[contracttype]
pub(super) struct AccountSignature {
    pub(super) public_key: BytesN<32>,
    pub(super) signature: BytesN<64>,
}
fn address(env: &Env, key: &SigningKey) -> Address {
    let mut bytes = Bytes::from_slice(env, &[0, 0, 0, 18, 0, 0, 0, 0, 0, 0, 0, 0]);
    bytes.append(&Bytes::from_slice(env, &key.verifying_key().to_bytes()));
    Address::from_xdr(env, &bytes).unwrap()
}
impl Fixture {
    pub(super) fn new(wasm: &[u8], x402: bool) -> Self {
        Self::new_with_native(wasm, x402, false)
    }
    pub(super) fn new_native(wasm: &[u8]) -> Self {
        Self::new_with_native(wasm, false, true)
    }
    fn new_with_native(wasm: &[u8], x402: bool, native: bool) -> Self {
        let env = Env::new_with_config(soroban_sdk::testutils::EnvTestConfig {
            capture_snapshot_at_drop: false,
        });
        env.mock_all_auths_allowing_non_root_auth();
        env.ledger().with_mut(|l| {
            l.timestamp = 86_410;
            l.sequence_number = 100;
        });
        let owner = Address::generate(&env);
        let akey = SigningKey::from_bytes(&[7; 32]);
        let skey = SigningKey::from_bytes(&[8; 32]);
        let agent = if x402 {
            address(&env, &akey)
        } else {
            Address::generate(&env)
        };
        let server = if x402 {
            address(&env, &skey)
        } else {
            Address::generate(&env)
        };
        let recipient = Address::generate(&env);
        let asset = if native {
            use soroban_sdk::xdr as x;
            let created = env
                .host()
                .invoke_function(x::HostFunction::CreateContract(x::CreateContractArgs {
                    contract_id_preimage: x::ContractIdPreimage::Asset(x::Asset::Native),
                    executable: x::ContractExecutable::StellarAsset,
                }))
                .unwrap();
            Address::try_from_val(&env, &created).unwrap()
        } else {
            env.register_stellar_asset_contract_v2(Address::generate(&env))
                .address()
        };
        let mut params = Map::new(&env);
        for (key, value) in [
            (PAYMENT_LIMIT, AllowitValue::Int(100)),
            (LIFETIME_SPENDING_LIMIT, AllowitValue::Int(250)),
            (DAILY_SPENDING_LIMIT, AllowitValue::Int(150)),
            (DAILY_VOLUME_LIMIT, AllowitValue::Int(150)),
            (CALL_LIMIT, AllowitValue::Int(3)),
            (DESTINATIONS, addresses(&env, &[&recipient])),
            (TOKENS, addresses(&env, &[&asset])),
            (EXPIRES_AT, AllowitValue::Int(1_000_000)),
            (OPERATIONS, op_names(&env, &["transfer", "deposit"])),
        ] {
            params.set(Symbol::new(&env, key), value);
        }
        let mut rules = Vec::new(&env);
        if wasm == COMMON {
            for rule in [
                AllowitRule::destinations,
                AllowitRule::tokens,
                AllowitRule::payment_limit,
                AllowitRule::daily_spending_limit,
                AllowitRule::daily_volume_limit,
                AllowitRule::lifetime_spending_limit,
                AllowitRule::call_limit,
                AllowitRule::expires_at,
            ] {
                rules.push_back(rule);
            }
        }
        let source_digest = if wasm == CUSTOM || wasm == CATCHING {
            let source: &[u8] = if wasm == CUSTOM {
                include_bytes!("../../custom-policy/policy/policy.rs")
            } else {
                include_bytes!("../../custom-policy/src/catching_policy.rs")
            };
            env.crypto()
                .sha256(&Bytes::from_slice(&env, source))
                .to_bytes()
        } else {
            let kind = if wasm == COMMON {
                "common_policy_engine"
            } else {
                "simple_policy_engine"
            };
            standard_prefix_digest(
                &env,
                &Symbol::new(&env, kind),
                &env.crypto()
                    .sha256(&Bytes::from_slice(&env, wasm))
                    .to_bytes(),
                &asset,
                &rules,
            )
        };
        let config = AllowitPolicyConfig {
            owner: owner.clone(),
            agent: agent.clone(),
            server: server.clone(),
            asset: asset.clone(),
            policy_instance: BytesN::from_array(&env, &[1; 32]),
            source_digest,
            rules,
            params,
            x402_enabled: x402,
        };
        let wallet = env.register(wasm, (config,));
        if native {
            let funding_key = SigningKey::from_bytes(&[44; 32]);
            let funder = add_account(&env, &funding_key);
            token::Client::new(&env, &asset).transfer(&funder, &wallet, &1_000);
        } else {
            StellarAssetClient::new(&env, &asset).mint(&wallet, &1_000);
        }
        env.mock_auths(&[]);
        Self {
            env,
            wallet,
            owner,
            agent,
            server,
            asset,
            recipient,
            akey,
            skey,
        }
    }
    pub(super) fn client(&self) -> Client<'_> {
        Client::new(&self.env, &self.wallet)
    }
    pub(super) fn execution(&self, amount: i128) -> AllowitExecutionRequest {
        let s = self.client().state();
        let b = self.client().policy_binding();
        let mut id = [0u8; 32];
        id[24..].copy_from_slice(&(s.nonce + 1).to_be_bytes());
        AllowitExecutionRequest {
            source_hash: if b.engine_kind == Symbol::new(&self.env, "custom_policy") {
                b.source_digest.clone()
            } else {
                BytesN::from_array(&self.env, &[9; 32])
            },
            expense: AllowitExpense::Priced(AllowitExpenseBounds {
                gas_units: 0,
                conversion_units: 0,
                spent_units: amount.max(0),
                max_fee_stroops: 0,
                observed_ledger: 1,
                day: self.env.ledger().timestamp() / 86_400,
            }),
            policy_instance: b.policy_instance,
            operation_id: BytesN::from_array(&self.env, &id),
            nonce: s.nonce,
            deployment_version: s.deployment_version,
            expires_at: self.env.ledger().timestamp() + 100,
            args: Map::new(&self.env),
            module_digest: b.module_digest,
            operation: AllowitStellarOperation::Transfer(AllowitTransferArgs {
                token: self.asset.clone(),
                to: self.recipient.clone(),
                amount,
            }),
        }
    }
    /// Execution for a module whose binding no longer resolves.
    fn execution_unbound(&self, amount: i128, module: &BytesN<32>) -> AllowitExecutionRequest {
        let s = self.client().state();
        let mut id = [0u8; 32];
        id[24..].copy_from_slice(&(s.nonce + 1).to_be_bytes());
        AllowitExecutionRequest {
            source_hash: BytesN::from_array(&self.env, &[9; 32]),
            expense: AllowitExpense::Unpriced,
            policy_instance: s.policy_instance,
            operation_id: BytesN::from_array(&self.env, &id),
            nonce: s.nonce,
            deployment_version: s.deployment_version,
            expires_at: self.env.ledger().timestamp() + 100,
            args: Map::new(&self.env),
            module_digest: module.clone(),
            operation: AllowitStellarOperation::Transfer(AllowitTransferArgs {
                token: self.asset.clone(),
                to: self.recipient.clone(),
                amount,
            }),
        }
    }
    pub(super) fn auth(&self, actors: &[&Address], method: &str, args: Vec<Val>) {
        let invoke = MockAuthInvoke {
            contract: &self.wallet,
            fn_name: method,
            args,
            sub_invokes: &[],
        };
        self.env.mock_auths(
            &actors
                .iter()
                .map(|actor| MockAuth {
                    address: actor,
                    invoke: &invoke,
                })
                .collect::<std::vec::Vec<_>>(),
        );
    }
    pub(super) fn transfer(&self, amount: i128) -> AllowitTransferReceipt {
        let e = self.execution(amount);
        self.auth(
            &[&self.agent, &self.server],
            "execute",
            (e.clone(),).into_val(&self.env),
        );
        self.client().execute(&e)
    }
    /// Standard values of the stored policy state.
    pub(super) fn history(&self) -> AllowitStandardState {
        AllowitStandardState::read(&self.client().policy_state()).unwrap()
    }
    pub(super) fn balance(&self) -> i128 {
        token::Client::new(&self.env, &self.asset).balance(&self.wallet)
    }
    /// Exact raw encoding of a typed packet, for edits the typed client cannot express.
    pub(super) fn packet(&self, p: &AllowitPolicyDeployment) -> Map<Symbol, Val> {
        let raw: Val = p.clone().into_val(&self.env);
        Map::try_from_val(&self.env, &raw).unwrap()
    }
    /// Invoke deploy_policy with a raw packet that the owner authorized exactly as sent.
    pub(super) fn deploy_raw(&self, packet: Map<Symbol, Val>) -> bool {
        let args: Vec<Val> = (packet,).into_val(&self.env);
        self.auth(&[&self.owner], "deploy_policy", args.clone());
        self.env
            .try_invoke_contract::<(), AllowitWalletError>(
                &self.wallet,
                &Symbol::new(&self.env, "deploy_policy"),
                args,
            )
            .is_ok()
    }
    pub(super) fn deployment(&self) -> AllowitPolicyDeployment {
        let s = self.client().state();
        AllowitPolicyDeployment {
            deployment_version: s.deployment_version + 1,
            owner: s.owner,
            agent: s.agent,
            server: s.server,
            source_digest: s.source_digest,
            rules: s.rules,
            params: s.params,
            x402_enabled: s.x402_enabled,
            wasm_hash: None,
        }
    }
    pub(super) fn authorization(
        &self,
        execution: AllowitExecutionRequest,
        payload: &BytesN<32>,
    ) -> AllowitPolicyAuthorization {
        let digest = self.env.crypto().sha256(
            &(
                Symbol::new(&self.env, "allowit_wallet_v1"),
                payload.clone(),
                execution.clone(),
            )
                .to_xdr(&self.env),
        );
        AllowitPolicyAuthorization {
            execution,
            agent_signature: BytesN::from_array(
                &self.env,
                &self.akey.sign(&digest.to_array()).to_bytes(),
            ),
            server_signature: BytesN::from_array(
                &self.env,
                &self.skey.sign(&digest.to_array()).to_bytes(),
            ),
        }
    }
    /// A native authorization entry of the wallet for the x402 transfer of `execution`.
    pub(super) fn host_entry(
        &self,
        execution: AllowitExecutionRequest,
        amount: i128,
        nonce: i64,
    ) -> soroban_sdk::xdr::SorobanAuthorizationEntry {
        let invoke = MockAuthInvoke {
            contract: &self.asset,
            fn_name: "transfer",
            args: (self.wallet.clone(), self.recipient.clone(), amount).into_val(&self.env),
            sub_invokes: &[],
        };
        self.signed_entry(&self.wallet, &invoke, nonce, &|payload| {
            self.authorization(execution.clone(), payload)
                .into_val(&self.env)
        })
    }
    /// A native authorization entry of `address` for `invoke`, signed by `sign` over its payload.
    pub(super) fn signed_entry(
        &self,
        address: &Address,
        invoke: &MockAuthInvoke,
        nonce: i64,
        sign: &dyn Fn(&BytesN<32>) -> Val,
    ) -> soroban_sdk::xdr::SorobanAuthorizationEntry {
        use soroban_sdk::xdr::{self, WriteXdr};
        let invocation: xdr::SorobanAuthorizedInvocation = invoke.into();
        let preimage =
            xdr::HashIdPreimage::SorobanAuthorization(xdr::HashIdPreimageSorobanAuthorization {
                network_id: xdr::Hash(self.env.ledger().network_id().to_array()),
                nonce,
                signature_expiration_ledger: 100,
                invocation: invocation.clone(),
            });
        let payload = self
            .env
            .crypto()
            .sha256(&Bytes::from_slice(
                &self.env,
                &preimage.to_xdr(xdr::Limits::none()).unwrap(),
            ))
            .to_bytes();
        let signature = sign(&payload);
        xdr::SorobanAuthorizationEntry {
            credentials: xdr::SorobanCredentials::Address(xdr::SorobanAddressCredentials {
                address: address.into(),
                nonce,
                signature_expiration_ledger: 100,
                signature: signature.try_into_val(&self.env).unwrap(),
            }),
            root_invocation: invocation,
        }
    }
}
#[test]
fn simple_requires_both_signers_and_does_not_infer_rules_from_params() {
    let f = Fixture::new(SIMPLE, false);
    let e = f.execution(200);
    for actors in [&[&f.agent][..], &[&f.server][..], &[&f.owner][..], &[][..]] {
        f.auth(actors, "execute", (e.clone(),).into_val(&f.env));
        assert!(f.client().try_execute(&e).is_err());
        assert_eq!(f.balance(), 1_000);
        assert_eq!(f.client().state().nonce, 0);
    }
    assert_eq!(f.transfer(200).amount, 200);
    assert_eq!(f.balance(), 800);
    assert_eq!(f.history().calls, 1);
    assert_eq!(
        f.client().policy_binding().engine_kind,
        Symbol::new(&f.env, "simple_policy_engine")
    );
}
#[test]
fn common_rules_bound_transfers_and_commit_usage_once() {
    let f = Fixture::new(COMMON, false);
    f.transfer(100);
    f.transfer(50);
    assert_eq!(f.history().day_spent, 150);
    assert_eq!(f.history().spent, 150);
    assert_eq!(f.history().calls, 2);
    let before = f.history();
    let e = f.execution(1);
    f.auth(
        &[&f.agent, &f.server],
        "execute",
        (e.clone(),).into_val(&f.env),
    );
    assert_eq!(
        f.client().try_execute(&e),
        Err(Ok(AllowitWalletError::PolicyDenied))
    );
    assert_eq!(f.history(), before);
    assert_eq!(f.client().state().nonce, 2);
    f.env.ledger().with_mut(|l| l.timestamp = 172_800);
    f.transfer(100);
    assert_eq!(f.history().day_spent, 100);
    assert_eq!(f.history().spent, 250);
}
#[test]
fn common_skips_absent_params_and_rejects_unknown_names_keys_and_values() {
    let f = Fixture::new(COMMON, false);
    // Soroban decodes vector and map elements when read. The packet binds a digest over the raw
    // rules, so only the kernel's element decoding rejects them before they are stored.
    let module = f.env.crypto().sha256(&Bytes::from_slice(&f.env, COMMON));
    let kind = Symbol::new(&f.env, "common_policy_engine");
    let packet = |rule: Val, param: Option<(&str, Val)>| {
        let rules: Val = vec![&f.env, rule].into_val(&f.env);
        let lazy = Vec::<AllowitRule>::try_from_val(&f.env, &rules).unwrap();
        let digest = standard_prefix_digest(&f.env, &kind, &module.to_bytes(), &f.asset, &lazy);
        let mut packet = f.packet(&f.deployment());
        packet.set(Symbol::new(&f.env, "rules"), rules);
        packet.set(
            Symbol::new(&f.env, "source_digest"),
            digest.into_val(&f.env),
        );
        if let Some((name, value)) = param {
            let raw = packet.get(Symbol::new(&f.env, "params")).unwrap();
            let mut fields = Map::<Symbol, Val>::try_from_val(&f.env, &raw).unwrap();
            fields.set(Symbol::new(&f.env, name), value);
            packet.set(Symbol::new(&f.env, "params"), fields.into_val(&f.env));
        }
        packet
    };
    let deploy = |packet: Map<Symbol, Val>| {
        let args: Vec<Val> = (packet,).into_val(&f.env);
        f.auth(&[&f.owner], "deploy_policy", args.clone());
        let deploy_policy = Symbol::new(&f.env, "deploy_policy");
        let result =
            f.env
                .try_invoke_contract::<(), AllowitWalletError>(&f.wallet, &deploy_policy, args);
        assert_eq!(f.client().state().deployment_version, 0);
        result
    };
    // A malformed rule element, param value or list item is InvalidParam.
    let junk: Val = 5u32.into_val(&f.env);
    let recipient: Val = vec![&f.env, Symbol::new(&f.env, "destinations")].into_val(&f.env);
    let list: Val = Symbol::new(&f.env, "List").into_val(&f.env);
    let junk_list: Val = vec![&f.env, list, vec![&f.env, junk].into_val(&f.env)].into_val(&f.env);
    for raw in [
        packet(junk, None),
        packet(recipient, Some(("destinations", junk))),
        packet(recipient, Some(("destinations", junk_list))),
        packet(recipient, Some(("tokens", junk_list))),
    ] {
        assert_eq!(deploy(raw), Err(Ok(AllowitWalletError::InvalidParam)));
    }
    // A name outside the enum aborts in the host's symbol lookup.
    let rule: Val = vec![&f.env, Symbol::new(&f.env, "daily_cap")].into_val(&f.env);
    assert!(deploy(packet(rule, None)).is_err());
    // The standard contract admits only the canonical keys, each with its rule's type.
    let text = AllowitValue::Str(String::from_str(&f.env, "100"));
    let invalid = [
        (PAYMENT_LIMIT, AllowitValue::Int(-1)),
        (DAILY_VOLUME_LIMIT, text),
        ("vendor_cap", AllowitValue::Int(5)),
    ];
    for (key, value) in invalid {
        let mut p = f.deployment();
        set_param(&mut p.params, key, Some(value));
        f.auth(&[&f.owner], "deploy_policy", (p.clone(),).into_val(&f.env));
        assert_eq!(
            f.client().try_deploy_policy(&p),
            Err(Ok(AllowitWalletError::InvalidParam)),
            "{key}"
        );
    }
    let mut p = f.deployment();
    p.params = Map::new(&f.env);
    f.auth(&[&f.owner], "deploy_policy", (p.clone(),).into_val(&f.env));
    f.client().deploy_policy(&p);
    assert!(f.client().state().params.is_empty());
    // Every selected rule is skipped by the standard preflight when its param is absent.
    assert_eq!(f.transfer(500).amount, 500);
    // The same raw path stores a known rule.
    assert!(f.deploy_raw(packet(recipient, None)));
    assert_eq!(
        f.client().state().rules,
        vec![&f.env, AllowitRule::destinations]
    );
}
/// Fill `map` toward `budget` encoded bytes with a `fill` list of texts, as `allowit` counts them.
fn fill(env: &Env, map: &mut Map<Symbol, AllowitValue>, budget: u32) {
    let size = |map: &Map<Symbol, AllowitValue>| {
        map.values()
            .iter()
            .map(|value| allowit::KEY_BYTES + allowit::check_value(&value).unwrap())
            .sum::<u32>()
    };
    let mut left = budget - size(map) - allowit::KEY_BYTES - allowit::VALUE_BYTES;
    let mut texts = Vec::new(env);
    while left >= allowit::VALUE_BYTES {
        let n = (left - allowit::VALUE_BYTES).min(allowit::MAX_TEXT);
        texts.push_back(AllowitValue::Str(String::from_str(
            env,
            &"x".repeat(n as usize),
        )));
        left -= allowit::VALUE_BYTES + n.div_ceil(4) * 4;
    }
    map.set(Symbol::new(env, "fill"), AllowitValue::List(texts));
    assert!(size(map) <= budget && size(map) + allowit::VALUE_BYTES > budget);
}
#[test]
fn wallet_entry_holds_params_and_state_at_their_byte_budgets() {
    let f = Fixture::new(CUSTOM, false);
    let mut p = f.deployment();
    fill(&f.env, &mut p.params, allowit::MAX_PARAM_BYTES);
    f.auth(&[&f.owner], "deploy_policy", (p.clone(),).into_val(&f.env));
    f.client().deploy_policy(&p);
    // One more text passes the byte budget and rejects.
    let mut over = f.deployment();
    let text = AllowitValue::Str(String::from_str(&f.env, "xxxx"));
    set_param(&mut over.params, "extra", Some(text));
    f.auth(
        &[&f.owner],
        "deploy_policy",
        (over.clone(),).into_val(&f.env),
    );
    assert_eq!(
        f.client().try_deploy_policy(&over),
        Err(Ok(AllowitWalletError::InvalidParam))
    );
    // The first operation writes the standard keys; then fill the state to its budget.
    f.transfer(10);
    f.env.as_contract(&f.wallet, || {
        let mut s = state(&f.env).unwrap();
        fill(&f.env, &mut s.policy_state, allowit::MAX_STATE_BYTES);
        store(&f.env, &s);
    });
    f.transfer(10);
    assert_eq!(f.history().calls, 2);
    // Full params and state leave the wallet's entry far below the 64 KiB entry limit.
    assert!(f.client().state().to_xdr(&f.env).len() < 40 * 1024);
}
#[test]
fn owner_signs_the_canonical_packet_so_absent_or_extra_keys_reject() {
    let f = Fixture::new(COMMON, false);
    let p = f.deployment();
    let mut extra_top = f.packet(&p);
    extra_top.set(Symbol::new(&f.env, "per_transfer"), 5i128.into_val(&f.env));
    let mut absent_top = f.packet(&p);
    absent_top.remove(Symbol::new(&f.env, "wasm_hash"));
    // Params that are not key-value maps do not decode: a text-keyed map and a struct of raw
    // values, the earlier layouts' encodings.
    let mut text_keys = Map::<String, Val>::new(&f.env);
    text_keys.set(
        String::from_str(&f.env, "payment_limit"),
        AllowitValue::Int(10).into_val(&f.env),
    );
    let mut raw_values = Map::<Symbol, Val>::new(&f.env);
    raw_values.set(Symbol::new(&f.env, "call_limit"), 3u64.into_val(&f.env));
    let mut packets = std::vec![extra_top, absent_top];
    for params in [text_keys.into_val(&f.env), raw_values.into_val(&f.env)] {
        let mut raw = f.packet(&p);
        raw.set(Symbol::new(&f.env, "params"), params);
        packets.push(raw);
    }
    for packet in packets {
        assert!(!f.deploy_raw(packet));
        assert_eq!(f.client().state().deployment_version, 0);
        assert_eq!(f.client().state().params, p.params);
    }
    // The canonical raw packet passes through the same path; an absent key is unset.
    let mut unset = p.clone();
    set_param(&mut unset.params, EXPIRES_AT, None);
    assert!(f.deploy_raw(f.packet(&unset)));
    assert_eq!(f.client().state().deployment_version, 1);
    assert_eq!(f.client().state().params, unset.params);
}
#[test]
fn wallet_wasm_declares_its_custody_layout() {
    // XDR ScMetaEntry V0 { key, val }, as written into the `contractmetav0` section.
    let mut entry = std::vec![0u8; 4];
    let layout = std::format!("{CONTRACT_VERSION}");
    for field in [&b"allowit_custody_layout"[..], layout.as_bytes()] {
        entry.extend((field.len() as u32).to_be_bytes());
        entry.extend(field);
        entry.resize(entry.len().next_multiple_of(4), 0);
    }
    for wasm in [SIMPLE, COMMON, CUSTOM] {
        assert!(wasm.windows(entry.len()).any(|w| w == entry));
    }
}
#[test]
fn exact_request_replay_pause_and_expiry_are_independent_of_business_rules() {
    let f = Fixture::new(SIMPLE, false);
    let e = f.execution(1);
    f.auth(
        &[&f.agent, &f.server],
        "execute",
        (e.clone(),).into_val(&f.env),
    );
    f.client().execute(&e);
    f.auth(
        &[&f.agent, &f.server],
        "execute",
        (e.clone(),).into_val(&f.env),
    );
    assert_eq!(
        f.client().try_execute(&e),
        Err(Ok(AllowitWalletError::Replay))
    );
    let mut bad = f.execution(1);
    bad.expires_at = f.env.ledger().timestamp();
    f.auth(
        &[&f.agent, &f.server],
        "execute",
        (bad.clone(),).into_val(&f.env),
    );
    assert_eq!(
        f.client().try_execute(&bad),
        Err(Ok(AllowitWalletError::Expired))
    );
    f.auth(&[&f.owner], "set_pause", (true, 1u64).into_val(&f.env));
    f.client().set_pause(&true, &1);
    let next = f.execution(1);
    f.auth(
        &[&f.agent, &f.server],
        "execute",
        (next.clone(),).into_val(&f.env),
    );
    assert_eq!(
        f.client().try_execute(&next),
        Err(Ok(AllowitWalletError::Paused))
    );
    f.auth(
        &[&f.owner],
        "recover",
        (f.recipient.clone(), 10i128).into_val(&f.env),
    );
    f.client().recover(&f.recipient, &10);
    assert_eq!(f.balance(), 989);
}
#[test]
fn owner_packet_requires_current_and_candidate_authorization_and_preserves_usage() {
    let f = Fixture::new(COMMON, false);
    f.transfer(10);
    let before = f.history();
    let next = Address::generate(&f.env);
    let mut p = f.deployment();
    p.owner = next.clone();
    f.auth(&[&f.owner], "deploy_policy", (p.clone(),).into_val(&f.env));
    assert!(f.client().try_deploy_policy(&p).is_err());
    f.auth(
        &[&f.owner, &next],
        "deploy_policy",
        (p.clone(),).into_val(&f.env),
    );
    f.client().deploy_policy(&p);
    assert_eq!(f.client().state().owner, next);
    assert_eq!(f.history(), before);
    assert_eq!(f.client().state().nonce, 1);
    f.auth(&[&next], "deploy_policy", (p.clone(),).into_val(&f.env));
    assert_eq!(
        f.client().try_deploy_policy(&p),
        Err(Ok(AllowitWalletError::StaleRequest))
    );
}
#[test]
fn real_x402_requires_both_signatures_and_commits_with_native_effects() {
    for wasm in [SIMPLE, COMMON, CUSTOM] {
        let f = Fixture::new(wasm, true);
        let e = f.execution(10);
        let entry = f.host_entry(e.clone(), 10, 1);
        f.env.set_auths(core::slice::from_ref(&entry));
        token::Client::new(&f.env, &f.asset).transfer(&f.wallet, &f.recipient, &10);
        assert_eq!(f.balance(), 990);
        assert_eq!(f.client().state().nonce, 1);
        f.env.set_auths(&[f.host_entry(e.clone(), 10, 2)]);
        assert!(
            token::Client::new(&f.env, &f.asset)
                .try_transfer(&f.wallet, &f.recipient, &10)
                .is_err()
        );
        assert_eq!(f.balance(), 990);
        // The settled operation replays as `Replay` even under a new host payload.
        let payload = BytesN::from_array(&f.env, &[42; 32]);
        assert_eq!(
            f.env.try_invoke_contract_check_auth::<AllowitWalletError>(
                &f.wallet,
                &payload,
                f.authorization(e.clone(), &payload).into_val(&f.env),
                &vec![&f.env, transfer_context(&f, 10)]
            ),
            Err(Ok(AllowitWalletError::Replay))
        );
        assert_eq!(f.client().state().nonce, 1);
        let mut bad = f.host_entry(f.execution(10), 10, 3);
        if let soroban_sdk::xdr::SorobanCredentials::Address(ref mut credential) = bad.credentials {
            let mut auth: AllowitPolicyAuthorization =
                AllowitPolicyAuthorization::try_from_val(&f.env, &credential.signature).unwrap();
            auth.server_signature = BytesN::from_array(&f.env, &[0; 64]);
            let raw: Val = auth.into_val(&f.env);
            credential.signature = raw.try_into_val(&f.env).unwrap();
        }
        f.env.set_auths(&[bad]);
        assert!(
            token::Client::new(&f.env, &f.asset)
                .try_transfer(&f.wallet, &f.recipient, &10)
                .is_err()
        );
        assert_eq!(f.balance(), 990);
    }
}
#[test]
fn failed_native_transfer_rolls_back_spent_nonce_and_operation_marker() {
    let f = Fixture::new(SIMPLE, true);
    let e = f.execution(2_000);
    f.env.set_auths(&[f.host_entry(e.clone(), 2_000, 1)]);
    assert!(
        token::Client::new(&f.env, &f.asset)
            .try_transfer(&f.wallet, &f.recipient, &2_000)
            .is_err()
    );
    assert_eq!(f.client().state().nonce, 0);
    assert_eq!(f.balance(), 1_000);
    f.env.mock_all_auths();
    StellarAssetClient::new(&f.env, &f.asset).mint(&f.wallet, &2_000);
    f.env.set_auths(&[f.host_entry(e, 2_000, 2)]);
    token::Client::new(&f.env, &f.asset).transfer(&f.wallet, &f.recipient, &2_000);
    assert_eq!(f.client().state().nonce, 1);
}
#[contract]
struct Forwarder;
#[contractimpl]
impl Forwarder {
    pub fn send(env: Env, asset: Address, from: Address, to: Address, amount: i128) {
        token::Client::new(&env, &asset).transfer(&from, &to, &amount);
    }
}
#[test]
fn owner_passthrough_supports_exact_nested_auth_without_agent_access() {
    use soroban_sdk::auth::{ContractContext, SubContractInvocation};
    let f = Fixture::new(COMMON, false);
    let forwarder = f.env.register(Forwarder, ());
    let function = Symbol::new(&f.env, "send");
    let args: Vec<Val> = (
        f.asset.clone(),
        f.wallet.clone(),
        f.recipient.clone(),
        200i128,
    )
        .into_val(&f.env);
    let auth = vec![
        &f.env,
        InvokerContractAuthEntry::Contract(SubContractInvocation {
            context: ContractContext {
                contract: f.asset.clone(),
                fn_name: Symbol::new(&f.env, "transfer"),
                args: (f.wallet.clone(), f.recipient.clone(), 200i128).into_val(&f.env),
            },
            sub_invocations: Vec::new(&f.env),
        }),
    ];
    let owner_args: Vec<Val> = (
        forwarder.clone(),
        function.clone(),
        args.clone(),
        auth.clone(),
    )
        .into_val(&f.env);
    f.auth(&[&f.agent, &f.server], "invoke", owner_args.clone());
    assert!(
        f.client()
            .try_invoke(&forwarder, &function, &args, &auth)
            .is_err()
    );
    f.auth(&[&f.owner], "invoke", owner_args);
    f.client().invoke(&forwarder, &function, &args, &auth);
    assert_eq!(f.balance(), 800);
    assert_eq!(f.client().state().nonce, 0);
    assert_eq!(f.history(), AllowitStandardState::default());
    let changed: Vec<Val> = (
        f.asset.clone(),
        f.wallet.clone(),
        f.recipient.clone(),
        201i128,
    )
        .into_val(&f.env);
    f.auth(
        &[&f.owner],
        "invoke",
        (
            forwarder.clone(),
            function.clone(),
            changed.clone(),
            auth.clone(),
        )
            .into_val(&f.env),
    );
    assert!(
        f.client()
            .try_invoke(&forwarder, &function, &changed, &auth)
            .is_err()
    );
    assert_eq!(f.balance(), 800);
}
#[test]
fn owner_upgrades_exact_code_without_server_and_preserves_state() {
    let f = Fixture::new(SIMPLE, false);
    let mut bytes = Bytes::from_slice(&f.env, SIMPLE);
    bytes.append(&Bytes::from_slice(&f.env, &[0, 2, 1, b'x']));
    let hash = f.env.deployer().upload_contract_wasm(bytes);
    let mut p = f.deployment();
    p.wasm_hash = Some(hash.clone());
    p.source_digest = standard_prefix_digest(
        &f.env,
        &Symbol::new(&f.env, "simple_policy_engine"),
        &hash,
        &f.asset,
        &p.rules,
    );
    f.auth(
        &[&f.agent, &f.server],
        "deploy_policy",
        (p.clone(),).into_val(&f.env),
    );
    assert!(f.client().try_deploy_policy(&p).is_err());
    f.auth(&[&f.owner], "deploy_policy", (p.clone(),).into_val(&f.env));
    f.client().deploy_policy(&p);
    assert_eq!(f.client().policy_binding().module_digest, hash);
    assert_eq!(f.client().state().deployment_version, 1);
    assert_eq!(f.balance(), 1_000);
}

#[test]
fn request_bindings_reject_changed_fields_and_unexpected_effects() {
    let f = Fixture::new(SIMPLE, false);
    let e = f.execution(10);
    for field in 0..9 {
        let mut bad = e.clone();
        match field {
            0 => bad.policy_instance = BytesN::from_array(&f.env, &[3; 32]),
            1 => bad.module_digest = BytesN::from_array(&f.env, &[3; 32]),
            2 => bad.nonce += 1,
            3 => bad.deployment_version += 1,
            4 => bad.operation_id = BytesN::from_array(&f.env, &[0; 32]),
            5 => transfer_args(&mut bad).token = f.recipient.clone(),
            6 => transfer_args(&mut bad).to = f.wallet.clone(),
            7 => transfer_args(&mut bad).amount = 0,
            _ => transfer_args(&mut bad).amount = -1,
        }
        f.auth(
            &[&f.agent, &f.server],
            "execute",
            (bad.clone(),).into_val(&f.env),
        );
        assert!(f.client().try_execute(&bad).is_err());
        assert_eq!(f.balance(), 1_000);
        assert_eq!(f.client().state().nonce, 0);
    }
    f.auth(
        &[&f.agent, &f.server],
        "execute",
        (e.clone(),).into_val(&f.env),
    );
    let mut changed = e;
    transfer_args(&mut changed).amount = 11;
    assert!(f.client().try_execute(&changed).is_err());
    assert_eq!(f.balance(), 1_000);
}

#[test]
fn custom_source_and_unknown_storage_layout_reject() {
    let f = Fixture::new(CUSTOM, false);
    let mut p = f.deployment();
    p.source_digest = BytesN::from_array(&f.env, &[5; 32]);
    f.auth(&[&f.owner], "deploy_policy", (p.clone(),).into_val(&f.env));
    assert_eq!(
        f.client().try_deploy_policy(&p),
        Err(Ok(AllowitWalletError::InvalidState))
    );
    let original: AllowitState = f.client().state();
    let extra = Symbol::new(&f.env, "per_transfer");
    for case in 0..5 {
        f.env.as_contract(&f.wallet, || {
            let mut raw: Map<Symbol, Val> = f.env.storage().instance().get(&STATE_KEY).unwrap();
            match case {
                0 => {
                    raw.remove(Symbol::new(&f.env, "server"));
                }
                1 => raw.set(extra.clone(), 5i128.into_val(&f.env)),
                // Params must be a map.
                2 => raw.set(Symbol::new(&f.env, "params"), 5u32.into_val(&f.env)),
                // Policy state must be a map.
                3 => raw.set(Symbol::new(&f.env, "policy_state"), 5u32.into_val(&f.env)),
                // The earlier layout's field beside the params does not decode as this layout.
                _ => raw.set(
                    Symbol::new(&f.env, "grant"),
                    Map::<Symbol, Val>::new(&f.env).into_val(&f.env),
                ),
            }
            f.env.storage().instance().set(&STATE_KEY, &raw);
        });
        assert_eq!(
            f.client().try_state(),
            Err(Ok(AllowitWalletError::InvalidState))
        );
        f.env.as_contract(&f.wallet, || {
            f.env.storage().instance().set(&STATE_KEY, &original)
        });
        assert_eq!(f.client().state(), original);
    }
}

/// Accounting history of layouts 1 and 2, stored as a struct.
#[contracttype]
#[derive(Clone)]
struct LegacyHistory {
    calls: u64,
    spent: i128,
    unpriced: bool,
    day: u64,
    day_spent: i128,
    day_total: i128,
    day_unpriced: bool,
}

/// Version 1 layout: a text-keyed map of raw params stored as `grant`, symbol rules and a history
/// struct.
#[contracttype]
#[derive(Clone)]
struct LegacyState {
    history: LegacyHistory,
    contract_version: u32,
    owner: Address,
    agent: Address,
    server: Address,
    asset: Address,
    policy_instance: BytesN<32>,
    source_digest: BytesN<32>,
    rules: Vec<Symbol>,
    grant: Map<String, Val>,
    x402_enabled: bool,
    token: String,
    deployment_version: u64,
    nonce: u64,
    paused: bool,
}

#[test]
fn earlier_layouts_keep_owner_recovery_and_do_not_migrate_implicitly() {
    let f = Fixture::new(COMMON, false);
    f.transfer(10);
    let current = f.client().state();
    let mut params = Map::<String, Val>::new(&f.env);
    params.set(
        String::from_str(&f.env, "payment_limit"),
        5i128.into_val(&f.env),
    );
    let mut legacy = LegacyState {
        history: LegacyHistory {
            calls: 1,
            spent: 10,
            unpriced: false,
            day: 1,
            day_spent: 10,
            day_total: 10,
            day_unpriced: false,
        },
        contract_version: 1,
        owner: current.owner.clone(),
        agent: current.agent.clone(),
        server: current.server.clone(),
        asset: current.asset.clone(),
        policy_instance: current.policy_instance.clone(),
        source_digest: current.source_digest.clone(),
        rules: vec![&f.env, Symbol::new(&f.env, "payment_limit")],
        grant: params,
        x402_enabled: false,
        token: current.token.clone(),
        deployment_version: current.deployment_version,
        nonce: current.nonce,
        paused: false,
    };
    let install = |state: &LegacyState| {
        f.env.as_contract(&f.wallet, || {
            f.env.storage().instance().set(&STATE_KEY, state)
        })
    };
    install(&legacy);
    // The state written by an in-place upgrade from an earlier release does not decode.
    assert!(f.client().try_state().is_err());
    // Only the owner recovers funds from it.
    f.auth(
        &[&f.agent],
        "recover",
        (f.recipient.clone(), 7i128).into_val(&f.env),
    );
    assert!(f.client().try_recover(&f.recipient, &7).is_err());
    f.auth(
        &[&f.owner],
        "recover",
        (f.recipient.clone(), 7i128).into_val(&f.env),
    );
    f.client().recover(&f.recipient, &7);
    assert_eq!(f.balance(), 983);
    // A complete owner packet does not convert an earlier history into policy state.
    let p = AllowitPolicyDeployment {
        deployment_version: current.deployment_version + 1,
        owner: current.owner.clone(),
        agent: current.agent.clone(),
        server: current.server.clone(),
        source_digest: current.source_digest.clone(),
        rules: current.rules.clone(),
        params: current.params.clone(),
        x402_enabled: false,
        wasm_hash: None,
    };
    for version in [1, 2] {
        legacy.contract_version = version;
        install(&legacy);
        f.auth(&[&f.owner], "deploy_policy", (p.clone(),).into_val(&f.env));
        assert_eq!(
            f.client().try_deploy_policy(&p),
            Err(Ok(AllowitWalletError::InvalidState))
        );
        assert!(f.client().try_state().is_err());
    }
    // Layout 3 also stored `policy_state`, with raw values, so it does not carry over either.
    f.env.as_contract(&f.wallet, || {
        let encoded: Val = current.clone().into_val(&f.env);
        let mut raw = Map::<Symbol, Val>::try_from_val(&f.env, &encoded).unwrap();
        raw.set(
            Symbol::new(&f.env, "contract_version"),
            3u32.into_val(&f.env),
        );
        f.env.storage().instance().set(&STATE_KEY, &raw);
    });
    f.auth(&[&f.owner], "deploy_policy", (p.clone(),).into_val(&f.env));
    assert_eq!(
        f.client().try_deploy_policy(&p),
        Err(Ok(AllowitWalletError::InvalidState))
    );
    assert!(f.client().try_state().is_err());
    // A later layout may change kept fields, so even owner recovery rejects it.
    legacy.contract_version = CONTRACT_VERSION + 1;
    install(&legacy);
    f.auth(
        &[&f.owner],
        "recover",
        (f.recipient.clone(), 1i128).into_val(&f.env),
    );
    assert_eq!(
        f.client().try_recover(&f.recipient, &1),
        Err(Ok(AllowitWalletError::InvalidState))
    );
}

#[test]
fn constructor_state_reads_and_operation_receipts_maintain_full_lifetimes() {
    use soroban_sdk::testutils::{Deployer as _, storage::Persistent as _};
    let f = Fixture::new(COMMON, false);
    let max = f.env.storage().max_ttl();
    assert_eq!(f.env.deployer().get_contract_instance_ttl(&f.wallet), max);
    assert_eq!(f.env.deployer().get_contract_code_ttl(&f.wallet), max);
    f.env
        .ledger()
        .with_mut(|l| l.sequence_number += max / 2 + 1);
    f.client().state();
    assert_eq!(f.env.deployer().get_contract_instance_ttl(&f.wallet), max);
    let receipt = f.transfer(1);
    let key = Key::Operation(receipt.operation_id);
    assert_eq!(
        f.env
            .as_contract(&f.wallet, || f.env.storage().persistent().get_ttl(&key)),
        max
    );
}

#[contract]
struct Constructor;
#[contractimpl]
impl Constructor {
    pub fn deploy(env: Env, wasm: BytesN<32>, config: AllowitPolicyConfig) -> Address {
        env.deployer()
            .with_current_contract(BytesN::from_array(&env, &[0; 32]))
            .deploy_contract(soroban_sdk::ContractExecutable::Wasm(wasm), (config,))
    }
    /// Deploy with an exact raw packet, for edits the typed config cannot express.
    pub fn deploy_raw(env: Env, wasm: BytesN<32>, config: Map<Symbol, Val>) -> Address {
        env.deployer()
            .with_current_contract(BytesN::from_array(&env, &[0; 32]))
            .deploy_contract(soroban_sdk::ContractExecutable::Wasm(wasm), (config,))
    }
}
#[test]
fn constructor_owner_signs_the_canonical_packet_so_absent_or_extra_keys_reject() {
    let f = Fixture::new(COMMON, false);
    let s = f.client().state();
    let config = AllowitPolicyConfig {
        owner: s.owner,
        agent: s.agent,
        server: s.server,
        asset: s.asset,
        policy_instance: s.policy_instance,
        source_digest: s.source_digest,
        rules: s.rules,
        params: s.params,
        x402_enabled: false,
    };
    let wasm = f.env.deployer().upload_contract_wasm(COMMON);
    let factory = f.env.register(Constructor, ());
    let salt = BytesN::from_array(&f.env, &[0; 32]);
    let wallet = f
        .env
        .deployer()
        .with_address(factory.clone(), salt)
        .deployed_address();
    let key = |name: &str| Symbol::new(&f.env, name);
    let raw = |edit: &dyn Fn(&mut Map<Symbol, Val>)| {
        let encoded: Val = config.clone().into_val(&f.env);
        let mut packet = Map::<Symbol, Val>::try_from_val(&f.env, &encoded).unwrap();
        edit(&mut packet);
        packet
    };
    // The owner authorizes exactly the raw packet sent.
    let deploy = |packet: Map<Symbol, Val>| {
        let args: Vec<Val> = (packet.clone(),).into_val(&f.env);
        f.env.mock_auths(&[MockAuth {
            address: &config.owner,
            invoke: &MockAuthInvoke {
                contract: &wallet,
                fn_name: "__constructor",
                args,
                sub_invokes: &[],
            },
        }]);
        ConstructorClient::new(&f.env, &factory)
            .try_deploy_raw(&wasm, &packet)
            .is_ok()
    };
    for packet in [
        raw(&|packet| packet.set(key("per_transfer"), 5i128.into_val(&f.env))),
        raw(&|packet| {
            packet.remove(key("x402_enabled"));
        }),
    ] {
        assert!(!deploy(packet));
    }
    // Without the owner's authorization the canonical packet does not deploy.
    f.env.mock_auths(&[]);
    assert!(
        ConstructorClient::new(&f.env, &factory)
            .try_deploy_raw(&wasm, &raw(&|_| {}))
            .is_err()
    );
    assert!(deploy(raw(&|_| {})));
    assert_eq!(Client::new(&f.env, &wallet).state().params, config.params);
}
#[test]
fn constructor_and_deploy_policy_reject_a_mismatched_standard_prefix_digest() {
    let f = Fixture::new(COMMON, false);
    let s = f.client().state();
    let env = &f.env;
    let module = env
        .crypto()
        .sha256(&Bytes::from_slice(env, COMMON))
        .to_bytes();
    let common = Symbol::new(env, "common_policy_engine");
    let mut reordered = s.rules.clone();
    let first = reordered.pop_front().unwrap();
    reordered.push_back(first);
    let digest = |kind: &Symbol, module: &BytesN<32>, rules: &Vec<AllowitRule>| {
        standard_prefix_digest(env, kind, module, &s.asset, rules)
    };
    // Another rule order, another kind or another module.
    let wrong = [
        digest(&common, &module, &reordered),
        digest(&Symbol::new(env, "simple_policy_engine"), &module, &s.rules),
        digest(&common, &BytesN::from_array(env, &[3; 32]), &s.rules),
    ];
    let config = |source_digest: &BytesN<32>| AllowitPolicyConfig {
        owner: s.owner.clone(),
        agent: s.agent.clone(),
        server: s.server.clone(),
        asset: s.asset.clone(),
        policy_instance: s.policy_instance.clone(),
        source_digest: source_digest.clone(),
        rules: s.rules.clone(),
        params: s.params.clone(),
        x402_enabled: false,
    };
    let wasm = env.deployer().upload_contract_wasm(COMMON);
    let factory = env.register(Constructor, ());
    let constructor = ConstructorClient::new(env, &factory);
    env.mock_all_auths_allowing_non_root_auth();
    for source_digest in &wrong {
        assert!(
            constructor
                .try_deploy(&wasm, &config(source_digest))
                .is_err()
        );
    }
    for source_digest in &wrong {
        let mut p = f.deployment();
        p.source_digest = source_digest.clone();
        f.auth(&[&f.owner], "deploy_policy", (p.clone(),).into_val(env));
        assert_eq!(
            f.client().try_deploy_policy(&p),
            Err(Ok(AllowitWalletError::InvalidState))
        );
        assert_eq!(f.client().state(), s);
    }
    // The matching digest passes both paths.
    env.mock_all_auths_allowing_non_root_auth();
    assert!(
        constructor
            .try_deploy(&wasm, &config(&s.source_digest))
            .is_ok()
    );
    let mut p = f.deployment();
    p.rules = reordered;
    p.source_digest = wrong[0].clone();
    f.auth(&[&f.owner], "deploy_policy", (p.clone(),).into_val(env));
    f.client().deploy_policy(&p);
    assert_eq!(f.client().state().rules, p.rules);
}

fn transfer_context(f: &Fixture, amount: i128) -> Context {
    Context::Contract(soroban_sdk::auth::ContractContext {
        contract: f.asset.clone(),
        fn_name: Symbol::new(&f.env, "transfer"),
        args: (f.wallet.clone(), f.recipient.clone(), amount).into_val(&f.env),
    })
}

#[test]
fn x402_context_signatures_pause_and_enablement_fail_closed() {
    for case in 0..10 {
        let f = Fixture::new(SIMPLE, true);
        let payload = BytesN::from_array(&f.env, &[4; 32]);
        let mut auth = f.authorization(f.execution(10), &payload);
        let mut context = transfer_context(&f, 10);
        match case {
            0 => auth.agent_signature = BytesN::from_array(&f.env, &[0; 64]),
            1 => core::mem::swap(&mut auth.agent_signature, &mut auth.server_signature),
            2..=5 => {
                if let Context::Contract(ref mut c) = context {
                    match case {
                        2 => c.fn_name = Symbol::new(&f.env, "approve"),
                        3 => c.contract = Address::generate(&f.env),
                        4 => c.args = (f.wallet.clone(), f.wallet.clone(), 10i128).into_val(&f.env),
                        _ => {
                            c.args =
                                (f.wallet.clone(), f.recipient.clone(), 11i128).into_val(&f.env)
                        }
                    }
                }
            }
            7 => {
                let mut p = f.deployment();
                p.x402_enabled = false;
                f.auth(&[&f.owner], "deploy_policy", (p.clone(),).into_val(&f.env));
                f.client().deploy_policy(&p);
                auth = f.authorization(f.execution(10), &payload);
            }
            8 => {
                f.auth(&[&f.owner], "set_pause", (true, 1u64).into_val(&f.env));
                f.client().set_pause(&true, &1);
                auth = f.authorization(f.execution(10), &payload);
            }
            _ => (),
        }
        let contexts = if case == 6 {
            vec![&f.env, context.clone(), context]
        } else if case == 9 {
            Vec::new(&f.env)
        } else {
            vec![&f.env, context]
        };
        let result = f.env.try_invoke_contract_check_auth::<AllowitWalletError>(
            &f.wallet,
            &payload,
            auth.into_val(&f.env),
            &contexts,
        );
        match case {
            0 | 1 => assert_eq!(result, Err(Err(soroban_sdk::InvokeError::Abort))),
            2 | 3 | 7 => assert_eq!(result, Err(Ok(AllowitWalletError::UnsupportedOperation))),
            8 => assert_eq!(result, Err(Ok(AllowitWalletError::Paused))),
            _ => assert_eq!(result, Err(Ok(AllowitWalletError::InvalidInvocation))),
        }
        assert_eq!(f.balance(), 1000);
        assert_eq!(f.client().state().nonce, 0);
    }
}

/// A transfer execution to an arbitrary destination with its matching token context.
pub(super) fn x402_request(
    f: &Fixture,
    to: &Address,
    amount: i128,
) -> (AllowitExecutionRequest, Context) {
    let mut e = f.execution(amount);
    transfer_args(&mut e).to = to.clone();
    let context = Context::Contract(soroban_sdk::auth::ContractContext {
        contract: f.asset.clone(),
        fn_name: Symbol::new(&f.env, "transfer"),
        args: (f.wallet.clone(), to.clone(), amount).into_val(&f.env),
    });
    (e, context)
}

#[test]
fn x402_enforces_compiled_business_rules_without_committing() {
    for wasm in [COMMON, CUSTOM] {
        for case in 0..3 {
            let f = Fixture::new(wasm, true);
            let denied = Ok(AllowitWalletError::PolicyDenied);
            let (to, amount, expected) = match case {
                0 => (f.recipient.clone(), 101, denied),
                1 => (Address::generate(&f.env), 10, denied),
                _ => {
                    let mut p = f.deployment();
                    set_param(&mut p.params, EXPIRES_AT, None);
                    f.auth(&[&f.owner], "deploy_policy", (p.clone(),).into_val(&f.env));
                    f.client().deploy_policy(&p);
                    // Common preflight skips the unset field; Custom indexes it and aborts with
                    // `MissingParam`.
                    let missing = allowit::AllowitError::MissingParam as u32;
                    let expected = if wasm == CUSTOM {
                        Err(soroban_sdk::InvokeError::Contract(missing))
                    } else {
                        denied
                    };
                    (
                        f.recipient.clone(),
                        if wasm == CUSTOM { 10 } else { 101 },
                        expected,
                    )
                }
            };
            let before = f.client().state();
            let payload = BytesN::from_array(&f.env, &[6; 32]);
            let (e, context) = x402_request(&f, &to, amount);
            assert_eq!(
                f.env.try_invoke_contract_check_auth::<AllowitWalletError>(
                    &f.wallet,
                    &payload,
                    f.authorization(e, &payload).into_val(&f.env),
                    &vec![&f.env, context],
                ),
                Err(expected)
            );
            assert_eq!(f.client().state(), before);
            assert_eq!(f.balance(), 1_000);
        }
        // Through a real host entry the token transfer itself fails.
        let f = Fixture::new(wasm, true);
        f.env.set_auths(&[f.host_entry(f.execution(101), 101, 1)]);
        assert!(
            token::Client::new(&f.env, &f.asset)
                .try_transfer(&f.wallet, &f.recipient, &101)
                .is_err()
        );
        assert_eq!(f.balance(), 1_000);
        assert_eq!(f.client().state().nonce, 0);
        assert_eq!(f.history(), AllowitStandardState::default());
    }
}

/// A Custom policy that panics in the Wasm wallet aborts the call with the failed read's
/// `AllowitError` code, which no wallet error shares, on `execute` and on the x402 hook. Its
/// caught-cap write, the nonce and the replay marker stay unwritten, so the same operation then
/// succeeds once the read passes.
#[test]
fn a_panicking_wasm_policy_aborts_with_its_allowit_code_and_writes_nothing() {
    use soroban_sdk::InvokeError::Contract;
    for x402 in [false, true] {
        let f = Fixture::new(CATCHING, x402);
        // Settle `e` for `amount` through the token's x402 hook or through `execute`.
        let settle = |e: &AllowitExecutionRequest, amount, nonce| {
            if x402 {
                f.env.set_auths(&[f.host_entry(e.clone(), amount, nonce)]);
                token::Client::new(&f.env, &f.asset).transfer(&f.wallet, &f.recipient, &amount);
            } else {
                f.auth(
                    &[&f.agent, &f.server],
                    "execute",
                    (e.clone(),).into_val(&f.env),
                );
                f.client().execute(e);
            }
        };
        settle(&f.execution(100), 100, 1);
        // 60 more exceeds the daily cap of 150; the policy catches that and writes its count
        // before it reads the refund's order number.
        let mut e = f.execution(60);
        set_param(&mut e.args, "refund", Some(AllowitValue::Bool(true)));
        let before = f.client().state();
        for (value, error) in [
            (None, AllowitError::MissingParam),
            (Some(AllowitValue::Bool(true)), AllowitError::InvalidParam),
        ] {
            set_param(&mut e.args, "order", value);
            let result = if x402 {
                let payload = BytesN::from_array(&f.env, &[6; 32]);
                f.env.try_invoke_contract_check_auth::<AllowitWalletError>(
                    &f.wallet,
                    &payload,
                    f.authorization(e.clone(), &payload).into_val(&f.env),
                    &vec![&f.env, transfer_context(&f, 60)],
                )
            } else {
                f.auth(
                    &[&f.agent, &f.server],
                    "execute",
                    (e.clone(),).into_val(&f.env),
                );
                f.client().try_execute(&e).map(|_| ())
            };
            assert!(error as u32 > 100);
            assert_eq!(result, Err(Err(Contract(error as u32))), "{error:?}");
            assert_eq!(f.client().state(), before);
            assert_eq!(f.balance(), 900);
        }
        set_param(&mut e.args, "order", Some(AllowitValue::Int(7)));
        settle(&e, 60, 2);
        assert_eq!(f.client().state().nonce, before.nonce + 1);
        let over = f
            .client()
            .policy_state()
            .get(Symbol::new(&f.env, "over_day_cap"));
        assert_eq!(over, Some(AllowitValue::Int(1)));
        assert_eq!(f.balance(), 840);
    }
}

#[test]
fn agent_and_server_sign_the_canonical_request_so_an_extra_key_fails_auth() {
    for wasm in [SIMPLE, COMMON, CUSTOM] {
        let f = Fixture::new(wasm, false);
        let e = f.execution(10);
        // The raw request adds a foreign `from` to the transfer arguments. Typed decoding drops
        // the key, and agent and server must have signed the canonical decoded request.
        let foreign = Address::generate(&f.env);
        let mut transfer = Map::<Symbol, Val>::new(&f.env);
        transfer.set(Symbol::new(&f.env, "token"), f.asset.into_val(&f.env));
        transfer.set(Symbol::new(&f.env, "to"), f.recipient.into_val(&f.env));
        transfer.set(Symbol::new(&f.env, "amount"), 10i128.into_val(&f.env));
        transfer.set(Symbol::new(&f.env, "from"), foreign.into_val(&f.env));
        let operation: Vec<Val> = vec![
            &f.env,
            Symbol::new(&f.env, "Transfer").into_val(&f.env),
            transfer.into_val(&f.env),
        ];
        let raw: Val = e.clone().into_val(&f.env);
        let mut request = Map::<Symbol, Val>::try_from_val(&f.env, &raw).unwrap();
        request.set(Symbol::new(&f.env, "operation"), operation.into_val(&f.env));
        let args: Vec<Val> = (request,).into_val(&f.env);
        let execute = Symbol::new(&f.env, "execute");
        // A signature over the raw request does not cover its decoded meaning.
        f.auth(&[&f.agent, &f.server], "execute", args.clone());
        assert!(
            f.env
                .try_invoke_contract::<AllowitTransferReceipt, AllowitWalletError>(
                    &f.wallet,
                    &execute,
                    args.clone(),
                )
                .is_err()
        );
        assert_eq!(f.client().state().nonce, 0);
        assert_eq!(f.balance(), 1000);
        // A signature over the canonical request covers it; the wallet still pays from itself.
        f.auth(
            &[&f.agent, &f.server],
            "execute",
            (e.clone(),).into_val(&f.env),
        );
        let receipt: AllowitTransferReceipt = f.env.invoke_contract(&f.wallet, &execute, args);
        assert_eq!(receipt.from, f.wallet);
        assert_eq!(receipt.to, f.recipient);
        assert_eq!(f.balance(), 990);
        assert_eq!(token::Client::new(&f.env, &f.asset).balance(&foreign), 0);
    }
}

#[test]
fn x402_rejects_a_deposit_authorization_for_a_token_transfer() {
    for wasm in [SIMPLE, COMMON] {
        let f = Fixture::new(wasm, true);
        let payload = BytesN::from_array(&f.env, &[8; 32]);
        let (mut e, context) = x402_request(&f, &f.recipient, 10);
        // A raw transfer to the vault would mint no shares and charge no principal.
        e.operation = AllowitStellarOperation::Deposit(AllowitDepositArgs {
            vault: f.recipient.clone(),
            assets: 10,
            min_shares: 10,
        });
        e.expense = AllowitExpense::Priced(AllowitExpenseBounds {
            gas_units: 0,
            conversion_units: 0,
            spent_units: 0,
            max_fee_stroops: 0,
            observed_ledger: 1,
            day: f.env.ledger().timestamp() / 86_400,
        });
        assert_eq!(
            f.env.try_invoke_contract_check_auth::<AllowitWalletError>(
                &f.wallet,
                &payload,
                f.authorization(e, &payload).into_val(&f.env),
                &vec![&f.env, context],
            ),
            Err(Ok(AllowitWalletError::UnsupportedOperation))
        );
        assert_eq!(f.client().state().nonce, 0);
        assert_eq!(f.history(), AllowitStandardState::default());
    }
}

#[test]
fn upgraded_standard_wallet_must_rebind_its_prefix_to_the_new_module() {
    let f = Fixture::new(COMMON, false);
    let mut bytes = Bytes::from_slice(&f.env, COMMON);
    bytes.append(&Bytes::from_slice(&f.env, &[0, 2, 1, b'x']));
    let hash = f.env.deployer().upload_contract_wasm(bytes);
    // The upgrade packet keeps the digest bound to the old module.
    let mut p = f.deployment();
    p.wasm_hash = Some(hash.clone());
    f.auth(&[&f.owner], "deploy_policy", (p.clone(),).into_val(&f.env));
    f.client().deploy_policy(&p);
    assert_eq!(
        f.client().try_policy_binding(),
        Err(Ok(AllowitWalletError::InvalidState))
    );
    let e = f.execution_unbound(10, &hash);
    f.auth(
        &[&f.agent, &f.server],
        "execute",
        (e.clone(),).into_val(&f.env),
    );
    assert_eq!(
        f.client().try_execute(&e),
        Err(Ok(AllowitWalletError::InvalidState))
    );
    assert_eq!(f.history(), AllowitStandardState::default());
    let mut fixed = f.deployment();
    fixed.source_digest = standard_prefix_digest(
        &f.env,
        &Symbol::new(&f.env, "common_policy_engine"),
        &hash,
        &f.asset,
        &fixed.rules,
    );
    f.auth(
        &[&f.owner],
        "deploy_policy",
        (fixed.clone(),).into_val(&f.env),
    );
    f.client().deploy_policy(&fixed);
    assert_eq!(f.client().policy_binding().module_digest, hash);
    assert_eq!(f.transfer(10).amount, 10);
}

#[test]
fn upgraded_tiers_validate_retained_rules_and_owner_can_correct_configuration() {
    for target in [SIMPLE, CUSTOM, COMMON] {
        let f = Fixture::new(COMMON, false);
        let mut p = f.deployment();
        p.wasm_hash = Some(
            f.env
                .deployer()
                .upload_contract_wasm(Bytes::from_slice(&f.env, target)),
        );
        if target == CUSTOM {
            p.source_digest = f
                .env
                .crypto()
                .sha256(&Bytes::from_slice(
                    &f.env,
                    include_bytes!("../../custom-policy/policy/policy.rs"),
                ))
                .to_bytes();
        }
        if target == COMMON {
            set_param(
                &mut p.params,
                DAILY_SPENDING_LIMIT,
                Some(AllowitValue::Int(-1)),
            );
        }
        if target == SIMPLE {
            p.source_digest = standard_prefix_digest(
                &f.env,
                &Symbol::new(&f.env, "simple_policy_engine"),
                p.wasm_hash.as_ref().unwrap(),
                &f.asset,
                &p.rules,
            );
        }
        f.auth(&[&f.owner], "deploy_policy", (p.clone(),).into_val(&f.env));
        if target == COMMON {
            assert_eq!(
                f.client().try_deploy_policy(&p),
                Err(Ok(AllowitWalletError::InvalidParam))
            );
            f.transfer(10);
            continue;
        }
        f.client().deploy_policy(&p);
        let e = f.execution(10);
        f.auth(
            &[&f.agent, &f.server],
            "execute",
            (e.clone(),).into_val(&f.env),
        );
        assert_eq!(
            f.client().try_execute(&e),
            Err(Ok(AllowitWalletError::InvalidParam))
        );
        let mut fixed = f.deployment();
        if target == COMMON {
            set_param(
                &mut fixed.params,
                DAILY_SPENDING_LIMIT,
                Some(AllowitValue::Int(150)),
            );
        } else {
            fixed.rules = Vec::new(&f.env);
            if target == SIMPLE {
                let Some(Executable::Wasm(module)) = f.wallet.executable() else {
                    panic!("Expected Wasm")
                };
                fixed.source_digest = standard_prefix_digest(
                    &f.env,
                    &Symbol::new(&f.env, "simple_policy_engine"),
                    &module,
                    &f.asset,
                    &fixed.rules,
                );
            }
        }
        f.auth(
            &[&f.owner],
            "deploy_policy",
            (fixed.clone(),).into_val(&f.env),
        );
        f.client().deploy_policy(&fixed);
        f.transfer(10);
        assert_eq!(f.balance(), 990);
    }
}

#[test]
fn issuer_burn_destinations_reject_in_direct_recovery_and_x402() {
    for enabled in [false, true] {
        let mut f = Fixture::new(SIMPLE, enabled);
        let name = token::Client::new(&f.env, &f.asset).name();
        let mut bytes = std::vec![0u8; name.len() as usize];
        name.copy_into_slice(&mut bytes);
        let name = std::str::from_utf8(&bytes).unwrap();
        f.recipient =
            Address::from_string(&String::from_str(&f.env, name.rsplit(':').next().unwrap()));
        let e = f.execution(10);
        if enabled {
            let payload = BytesN::from_array(&f.env, &[77; 32]);
            assert_eq!(
                f.env.try_invoke_contract_check_auth::<AllowitWalletError>(
                    &f.wallet,
                    &payload,
                    f.authorization(e.clone(), &payload).into_val(&f.env),
                    &vec![&f.env, transfer_context(&f, 10)]
                ),
                Err(Ok(AllowitWalletError::InvalidRecipient))
            );

            f.env.set_auths(&[f.host_entry(e, 10, 1)]);
            assert!(
                token::Client::new(&f.env, &f.asset)
                    .try_transfer(&f.wallet, &f.recipient, &10)
                    .is_err()
            );
        } else {
            f.auth(
                &[&f.agent, &f.server],
                "execute",
                (e.clone(),).into_val(&f.env),
            );
            assert_eq!(
                f.client().try_execute(&e),
                Err(Ok(AllowitWalletError::InvalidRecipient))
            );
            f.auth(
                &[&f.owner],
                "recover",
                (f.recipient.clone(), 10i128).into_val(&f.env),
            );
            assert_eq!(
                f.client().try_recover(&f.recipient, &10),
                Err(Ok(AllowitWalletError::InvalidRecipient))
            );
        }
        assert_eq!(f.balance(), 1000);
        assert_eq!(f.client().state().nonce, 0);
    }
}

#[test]
fn issuer_identity_decodes_real_sac_symbols_and_rejects_malformed_cache() {
    let f = Fixture::new(SIMPLE, true);
    let name = token::Client::new(&f.env, &f.asset).name();
    let mut bytes = std::vec![0u8;name.len() as usize];
    name.copy_into_slice(&mut bytes);
    let text = std::str::from_utf8(&bytes).unwrap();
    let issuer = Address::from_string(&String::from_str(&f.env, text.rsplit(':').next().unwrap()));
    for code in [
        &[b'A', 0, 0, 0][..],
        &[b'A', b'B', b'C', b'D', b'E', 0, 0, 0, 0, 0, 0, 0][..],
        b"ABCDEFGHIJKL",
    ] {
        let mut asset = Bytes::from_array(
            &f.env,
            &(if code.len() == 4 { 1u32 } else { 2u32 }).to_be_bytes(),
        );
        asset.append(&Bytes::from_slice(&f.env, code));
        asset.append(&Bytes::from_array(&f.env, &[0; 4]));
        asset.append(&public_key(&issuer).unwrap().into());
        let deployed = f.env.deployer().with_stellar_asset(asset).deploy();
        let mut state = f.client().state();
        state.asset = deployed.clone();
        state.token = token::Client::new(&f.env, &deployed).symbol();
        assert_eq!(
            issuer_destination(&f.env, &state.token, &state.asset, &issuer),
            Ok(true)
        );
        assert_eq!(
            issuer_destination(&f.env, &state.token, &state.asset, &f.server),
            Ok(false)
        );
    }
    for malformed in ["", r"\xZZ", r"\q", "ABCDEFGHIJKLM"] {
        let mut state = f.client().state();
        state.token = String::from_str(&f.env, malformed);
        f.env.as_contract(&f.wallet, || {
            f.env.storage().instance().set(&STATE_KEY, &state)
        });
        let payload = BytesN::from_array(&f.env, &[4; 32]);
        assert_eq!(
            f.env.try_invoke_contract_check_auth::<AllowitWalletError>(
                &f.wallet,
                &payload,
                f.authorization(f.execution(10), &payload).into_val(&f.env),
                &vec![&f.env, transfer_context(&f, 10)]
            ),
            Err(Ok(AllowitWalletError::InvalidState))
        );
    }
}

#[test]
fn native_master_weight_rotation_does_not_revoke_owner_enabled_raw_key_x402() {
    use soroban_sdk::xdr;
    use std::rc::Rc;
    let f = Fixture::new(SIMPLE, true);
    let id = xdr::AccountId(xdr::PublicKey::PublicKeyTypeEd25519(xdr::Uint256(
        f.akey.verifying_key().to_bytes(),
    )));
    let key = Rc::new(xdr::LedgerKey::Account(xdr::LedgerKeyAccount {
        account_id: id.clone(),
    }));
    let entry = Rc::new(xdr::LedgerEntry {
        data: xdr::LedgerEntryData::Account(xdr::AccountEntry {
            account_id: id,
            balance: 0,
            flags: 0,
            home_domain: Default::default(),
            inflation_dest: None,
            num_sub_entries: 0,
            seq_num: xdr::SequenceNumber(0),
            thresholds: xdr::Thresholds([0, 1, 1, 1]),
            signers: Default::default(),
            ext: xdr::AccountEntryExt::V0,
        }),
        last_modified_ledger_seq: 0,
        ext: xdr::LedgerEntryExt::V0,
    });
    f.env.host().add_ledger_entry(&key, &entry, None).unwrap();
    f.env.set_auths(&[f.host_entry(f.execution(10), 10, 1)]);
    token::Client::new(&f.env, &f.asset).transfer(&f.wallet, &f.recipient, &10);
    let mut p = f.deployment();
    p.x402_enabled = false;
    f.auth(&[&f.owner], "deploy_policy", (p.clone(),).into_val(&f.env));
    f.client().deploy_policy(&p);
    f.env.set_auths(&[f.host_entry(f.execution(10), 10, 2)]);
    assert!(
        token::Client::new(&f.env, &f.asset)
            .try_transfer(&f.wallet, &f.recipient, &10)
            .is_err()
    );
    assert_eq!(f.balance(), 990);
}

#[test]
fn common_empty_rule_constructor_is_an_explicit_simple_configuration() {
    let mut f = Fixture::new(COMMON, false);
    let state = f.client().state();
    let config = AllowitPolicyConfig {
        owner: state.owner,
        agent: state.agent,
        server: state.server,
        asset: state.asset,
        policy_instance: state.policy_instance,
        source_digest: standard_prefix_digest(
            &f.env,
            &Symbol::new(&f.env, "common_policy_engine"),
            &f.env
                .crypto()
                .sha256(&Bytes::from_slice(&f.env, COMMON))
                .to_bytes(),
            &f.asset,
            &Vec::new(&f.env),
        ),
        rules: Vec::new(&f.env),
        params: state.params,
        x402_enabled: false,
    };
    f.env.mock_all_auths_allowing_non_root_auth();
    f.wallet = f.env.register(COMMON, (config,));
    StellarAssetClient::new(&f.env, &f.asset).mint(&f.wallet, &1000);
    f.env.mock_auths(&[]);
    f.transfer(200);
    assert_eq!(f.balance(), 800);
    assert_eq!(f.history().calls, 1);
    assert_eq!(f.client().state().nonce, 1);
}

#[test]
fn replaced_agent_key_cannot_authorize_fresh_x402_execution() {
    let f = Fixture::new(SIMPLE, true);
    let mut p = f.deployment();
    p.agent = address(&f.env, &SigningKey::from_bytes(&[99; 32]));
    f.auth(&[&f.owner], "deploy_policy", (p.clone(),).into_val(&f.env));
    f.client().deploy_policy(&p);
    let payload = BytesN::from_array(&f.env, &[4; 32]);
    assert_eq!(
        f.env.try_invoke_contract_check_auth::<AllowitWalletError>(
            &f.wallet,
            &payload,
            f.authorization(f.execution(10), &payload).into_val(&f.env),
            &vec![&f.env, transfer_context(&f, 10)]
        ),
        Err(Err(soroban_sdk::InvokeError::Abort))
    );
    assert_eq!(f.client().state().nonce, 0);
    assert_eq!(f.balance(), 1000);
}

#[test]
fn full_source_identity_is_covered_by_x402_approvals_and_custom_binding() {
    let f = Fixture::new(SIMPLE, true);
    let e = f.execution(10);
    let payload = BytesN::from_array(&f.env, &[71; 32]);
    let mut authorization = f.authorization(e, &payload);
    authorization.execution.source_hash = BytesN::from_array(&f.env, &[72; 32]);
    assert!(
        f.env
            .try_invoke_contract_check_auth::<AllowitWalletError>(
                &f.wallet,
                &payload,
                authorization.into_val(&f.env),
                &vec![&f.env, transfer_context(&f, 10)]
            )
            .is_err()
    );
    assert_eq!(f.balance(), 1000);
    assert_eq!(f.client().state().nonce, 0);
    let f = Fixture::new(CUSTOM, false);
    let mut e = f.execution(10);
    e.source_hash = BytesN::from_array(&f.env, &[72; 32]);
    f.auth(
        &[&f.agent, &f.server],
        "execute",
        (e.clone(),).into_val(&f.env),
    );
    assert_eq!(
        f.client().try_execute(&e),
        Err(Ok(AllowitWalletError::InvalidInvocation))
    );
}

fn execute_as_actors(
    f: &Fixture,
    e: &AllowitExecutionRequest,
) -> Result<AllowitTransferReceipt, AllowitWalletError> {
    f.auth(
        &[&f.agent, &f.server],
        "execute",
        (e.clone(),).into_val(&f.env),
    );
    match f.client().try_execute(e) {
        Ok(receipt) => Ok(receipt.unwrap()),
        Err(error) => Err(error.unwrap()),
    }
}

#[test]
fn replayed_operation_with_changed_amount_or_expense_is_rejected_without_charging() {
    for wasm in [COMMON, CUSTOM] {
        let f = Fixture::new(wasm, false);
        let first = f.execution(10);
        execute_as_actors(&f, &first).unwrap();
        let before = f.client().state();
        for changed_expense in [false, true] {
            // A fresh nonce cannot reuse the consumed logical operation with other economic facts.
            let mut e = f.execution(if changed_expense { 10 } else { 11 });
            e.operation_id = first.operation_id.clone();
            if changed_expense {
                let mut cost = e.expense.bounds().unwrap().clone();
                cost.gas_units = 1;
                cost.max_fee_stroops = 1;
                cost.spent_units = 11;
                e.expense = AllowitExpense::Priced(cost);
            }
            assert_eq!(execute_as_actors(&f, &e), Err(AllowitWalletError::Replay));
            assert_eq!(f.client().state(), before);
            assert_eq!(f.balance(), 990);
        }
    }
}

#[test]
fn repeated_prefix_rules_read_one_current_state_and_charge_once() {
    let f = Fixture::new(COMMON, false);
    let mut p = f.deployment();
    p.rules = Vec::new(&f.env);
    for rule in [
        AllowitRule::lifetime_spending_limit,
        AllowitRule::lifetime_spending_limit,
        AllowitRule::daily_volume_limit,
        AllowitRule::call_limit,
        AllowitRule::call_limit,
    ] {
        p.rules.push_back(rule);
    }
    p.source_digest = standard_prefix_digest(
        &f.env,
        &Symbol::new(&f.env, "common_policy_engine"),
        &f.env
            .crypto()
            .sha256(&Bytes::from_slice(&f.env, COMMON))
            .to_bytes(),
        &f.asset,
        &p.rules,
    );
    set_param(
        &mut p.params,
        LIFETIME_SPENDING_LIMIT,
        Some(AllowitValue::Int(30)),
    );
    f.auth(&[&f.owner], "deploy_policy", (p.clone(),).into_val(&f.env));
    f.client().deploy_policy(&p);
    f.transfer(20);
    // The boundary passes although lifetime_spending_limit runs twice.
    f.transfer(10);
    assert_eq!(f.history().spent, 30);
    assert_eq!(f.history().day_total, 30);
    assert_eq!(f.history().calls, 2);
    let before = f.client().state();
    assert_eq!(
        execute_as_actors(&f, &f.execution(1)),
        Err(AllowitWalletError::PolicyDenied)
    );
    assert_eq!(f.client().state(), before);
}

#[test]
fn clock_regression_and_cross_day_expense_reject_before_rules_run() {
    let f = Fixture::new(COMMON, false);
    f.transfer(10);
    let before = f.client().state();
    assert_eq!(f.history().day, 1);
    // Rules never see accounting of another day: the kernel rejects a backward ledger day.
    f.env.ledger().with_mut(|l| l.timestamp -= 86_400);
    assert_eq!(
        execute_as_actors(&f, &f.execution(10)),
        Err(AllowitWalletError::InvalidState)
    );
    assert_eq!(f.client().state(), before);
    f.env.ledger().with_mut(|l| l.timestamp += 86_400);
    let mut e = f.execution(10);
    let mut cost = e.expense.bounds().unwrap().clone();
    cost.day += 1;
    e.expense = AllowitExpense::Priced(cost);
    assert_eq!(
        execute_as_actors(&f, &e),
        Err(AllowitWalletError::InvalidInvocation)
    );
    assert_eq!(f.client().state(), before);
}

#[test]
fn address_kind_checks_tell_accounts_from_contracts() {
    use soroban_sdk::xdr as x;
    let env = Env::default();
    let key = [7; 32];
    let account = Address::from_xdr(
        &env,
        &x::ScVal::Address(x::ScAddress::Account(x::AccountId(
            x::PublicKey::PublicKeyTypeEd25519(x::Uint256(key)),
        )))
        .to_xdr(&env),
    )
    .unwrap();
    let contract = Address::from_xdr(
        &env,
        &x::ScVal::Address(x::ScAddress::Contract(x::ContractId(x::Hash(key)))).to_xdr(&env),
    )
    .unwrap();
    assert_eq!(public_key(&account), Ok(BytesN::from_array(&env, &key)));
    assert_eq!(public_key(&contract), Err(AllowitWalletError::InvalidActor));
    assert!(is_contract(&contract) && !is_contract(&account));
}
