use allowit_stellar_wallet::workflow::*;
use allowit_stellar_wallet::*;
use serde_json::{Value, json};
use std::sync::Mutex;
use stellar_strkey::Contract;
use stellar_xdr::{
    Limits, OperationBody, OperationResult, OperationResultTr, PaymentResult, ReadXdr,
    SorobanTransactionData, TransactionEnvelope, TransactionResult, TransactionResultExt,
    TransactionResultResult, WriteXdr,
};
fn wf(value: &str) -> AccountId {
    let address = address(value).unwrap();
    match address {
        stellar_xdr::ScAddress::Account(stellar_xdr::AccountId(
            stellar_xdr::PublicKey::PublicKeyTypeEd25519(key),
        )) => AccountId {
            chain: Chain::Stellar,
            kind: AccountKind::Wallet,
            address: key.0,
        },
        stellar_xdr::ScAddress::Contract(id) => AccountId {
            chain: Chain::Stellar,
            kind: AccountKind::Contract,
            address: id.0.0,
        },
        _ => panic!(),
    }
}
fn fixture(route: WalletRoute, usdc: bool) -> (WalletConfig, ExecutionRequest, TrustedState) {
    fixture_with_wallet(route, usdc, [4; 32])
}
fn fixture_with_wallet(
    route: WalletRoute,
    usdc: bool,
    contract: [u8; 32],
) -> (WalletConfig, ExecutionRequest, TrustedState) {
    let owner = account_for_seed(&[1; 32]);
    let agent = account_for_seed(&[2; 32]);
    let engine = account_for_seed(&[3; 32]);
    let wallet = if route == WalletRoute::Native {
        owner.clone()
    } else {
        Contract(contract).to_string()
    };
    let portable = route == WalletRoute::PolicyWallet;
    let source = PORTABLE.to_string();
    let mut c = WalletConfig {
        network: "stellar:testnet".into(),
        policy_instance: [7; 32],
        wallet,
        owner: owner.clone(),
        agent: agent.clone(),
        server: engine.clone(),
        route: route.clone(),
        tier: portable.then_some(PolicyTier::Simple),
        language: PolicyLanguage::Portable,
        rules: vec![],
        params: PolicyParams::default(),
        source_digest: [0; 32],
        asset: String::new(),
        asset_symbol: if usdc { "USDC" } else { "XLM" }.into(),
        asset_issuer: usdc.then(|| account_for_seed(&[9; 32])),
        policy_source: source.clone(),
        source_hash: hash(source),
        module_digest: [5; 32],
        max_fee_stroops: 50_000,
    };
    c.asset = sac_address(&c.network, &asset_xdr(&c).unwrap()).unwrap();
    let recipient = account_for_seed(&[6; 32]);
    c.params = policy::params_from_json(
        &json!({"destinations": [recipient]}),
        Some(PolicyTier::Simple),
    )
    .unwrap();
    if portable {
        c.source_digest =
            policy::standard_prefix_digest(PolicyTier::Simple, &c.module_digest, &c.asset, &[])
                .unwrap();
    }
    let token = WorkflowAsset::Token(AssetId {
        network: network_id(&c.network).unwrap(),
        token: wf(&c.asset),
    });
    let native = WorkflowAsset::Native {
        chain: Chain::Stellar,
        network: network_id(&c.network).unwrap(),
    };
    let units = 20_000_000u64;
    let instruction = if usdc {
        NativeInstruction::StellarCall {
            contract: wf(&c.asset),
            schema_digest: [0; 32],
            function: "transfer".into(),
            arguments: vec![
                AbiValue::Account(wf(&c.wallet)),
                AbiValue::Account(wf(&recipient)),
                AbiValue::Signed128(units.into()),
            ],
        }
    } else {
        NativeInstruction::StellarNativeTransfer {
            source: wf(&c.wallet),
            destination: wf(&recipient),
            stroops: units,
        }
    };
    let payer = if route == WalletRoute::Native {
        &c.wallet
    } else {
        &c.agent
    };
    let request = ExecutionRequest {
        operation: OperationRef {
            policy_instance: c.policy_instance,
            nonce: [8; 32],
        },
        input: ExecutionInput::Instructions(vec![instruction]),
        effect_bounds: vec![WorkflowEffectBound {
            asset: if usdc { token } else { native.clone() },
            source: wf(&c.wallet),
            beneficiary: wf(&recipient),
            max_debit: units.into(),
            min_credit: units.into(),
            max_burn: 0u64.into(),
        }],
        fee_bounds: Some(vec![WorkflowFeeBound {
            payer: wf(payer),
            asset: native,
            max_fee: 50_000u64.into(),
        }]),
        evidence: vec![],
    };
    let account = if route == WalletRoute::Native {
        AccountState {
            address: c.wallet.clone(),
            sequence: 40,
            master_weight: 3,
            low_threshold: 2,
            medium_threshold: 2,
            high_threshold: 3,
            signers: vec![
                AccountSigner {
                    key: agent,
                    weight: 1,
                },
                AccountSigner {
                    key: engine,
                    weight: 1,
                },
            ],
        }
    } else {
        AccountState {
            address: c.agent.clone(),
            sequence: 40,
            master_weight: 1,
            low_threshold: 0,
            medium_threshold: 0,
            high_threshold: 0,
            signers: vec![],
        }
    };
    let state = TrustedState {
        contract_version: portable.then_some(CONTRACT_VERSION),
        policy_state: portable.then(|| PolicyStateSnapshot {
            params: c.params.clone(),
            state: PolicyParams::default(),
            rules: vec![],
            source_digest: c.source_digest,
            x402_enabled: false,
        }),
        source: account,
        nonce: 9,
        deployment_version: 4,
        spent_daily: 0,
        spent_total: 0,
        spent_day: 1,
        calls: 0,
        ledger: 100,
        module_digest: c.module_digest,
        source_hash: c.source_hash,
        owner: c.owner.clone(),
        agent: c.agent.clone(),
        server: c.server.clone(),
        policy_instance: c.policy_instance,
    };
    (c, request, state)
}
fn sign_native(p: &PreparedOperation) -> SignedOperation {
    let a = sign(p, &[2; 32], 86401).unwrap();
    let e = sign(p, &[3; 32], 86401).unwrap();
    authorize(p, &[a, e], 86401).unwrap()
}

/// Model the authorization rules of Stellar RPC `simulateTransaction`.
/// An omitted `authMode` means enforce when auth entries are present and record otherwise.
/// Record mode rejects a transaction that already has auth entries, as Stellar RPC does, and
/// records one root entry per required address with a fresh nonce. Enforce mode returns only the
/// supplied entries and fails when a required address has no entry.
fn rpc_auth(
    params: &Value,
    tx: &stellar_xdr::Transaction,
    required: &[stellar_xdr::ScAddress],
) -> std::result::Result<Vec<stellar_xdr::SorobanAuthorizationEntry>, String> {
    use stellar_xdr::*;
    let OperationBody::InvokeHostFunction(op) = &tx.operations[0].body else {
        panic!()
    };
    let HostFunction::InvokeContract(call) = &op.host_function else {
        panic!()
    };
    let MuxedAccount::Ed25519(source) = &tx.source_account else {
        panic!()
    };
    let source = ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(source.clone())));
    let mode = match params.get("authMode").and_then(serde_json::Value::as_str) {
        Some(mode) => mode,
        None if op.auth.is_empty() => "record",
        None => "enforce",
    };
    match mode {
        "record" if !op.auth.is_empty() => Err(format!(
            "cannot set authMode to '{mode}' with an auth footprint"
        )),
        "record" => Ok(required
            .iter()
            .enumerate()
            .map(|(index, who)| SorobanAuthorizationEntry {
                credentials: if *who == source {
                    SorobanCredentials::SourceAccount
                } else {
                    SorobanCredentials::Address(SorobanAddressCredentials {
                        address: who.clone(),
                        nonce: 9_000 + index as i64,
                        signature_expiration_ledger: 0,
                        signature: ScVal::Void,
                    })
                },
                root_invocation: SorobanAuthorizedInvocation {
                    function: SorobanAuthorizedFunction::ContractFn(call.clone()),
                    sub_invocations: VecM::default(),
                },
            })
            .collect()),
        "enforce" => {
            for who in required {
                if !op.auth.iter().any(|entry| match &entry.credentials {
                    SorobanCredentials::SourceAccount => *who == source,
                    SorobanCredentials::Address(c) => c.address == *who,
                    _ => false,
                }) {
                    return Err("require_auth has no matching authorization entry".into());
                }
            }
            Ok(op.auth.to_vec())
        }
        _ => Err("invalid authMode".into()),
    }
}

fn server_ready(p: &PreparedOperation) -> PreparedOperation {
    if p.config.route == WalletRoute::Native {
        return p.clone();
    }
    struct Simulation<'a>(&'a PreparedOperation);
    impl rpc::Rpc for Simulation<'_> {
        fn call(&self, method: &str, params: Value) -> Result<Value> {
            use stellar_xdr::*;
            let p = self.0;
            if method == "getNetwork" {
                return Ok(json!({"passphrase":passphrase(&p.config.network)?}));
            }
            assert_eq!(method, "simulateTransaction");
            let TransactionEnvelope::Tx(envelope) = TransactionEnvelope::from_xdr_base64(
                params["transaction"].as_str().unwrap(),
                Limits::none(),
            )
            .unwrap() else {
                panic!()
            };
            // Recording simulation receives the exact intent without its auth entries.
            let TransactionEnvelope::Tx(mut intent) =
                TransactionEnvelope::from_xdr_base64(&p.transaction_xdr, Limits::none()).unwrap()
            else {
                panic!()
            };
            if params["authMode"] == "record" {
                let mut operations = intent.tx.operations.to_vec();
                let OperationBody::InvokeHostFunction(op) = &mut operations[0].body else {
                    panic!()
                };
                op.auth = VecM::default();
                intent.tx.operations = operations.try_into().unwrap();
            }
            assert_eq!(envelope, intent);
            let auth = match rpc_auth(
                &params,
                &envelope.tx,
                &[
                    address(&p.state.source.address)?,
                    address(&p.config.server)?,
                ],
            ) {
                Ok(auth) => auth,
                Err(error) => return Ok(json!({ "error": error })),
            };
            let receipt = rpc::expected_receipt(p)?.scval()?;
            let resources = p.simulation_data.clone().unwrap_or(
                SorobanTransactionData::default()
                    .to_xdr_base64(Limits::none())
                    .unwrap(),
            );
            let data = SorobanTransactionData::from_xdr_base64(&resources, Limits::none()).unwrap();
            Ok(
                json!({"minResourceFee":data.resource_fee.to_string(),"transactionData":resources,"results":[{"xdr":receipt.to_xdr_base64(Limits::none()).unwrap(),"auth":auth.iter().map(|a|a.to_xdr_base64(Limits::none()).unwrap()).collect::<Vec<_>>()}]}),
            )
        }
    }
    let simulated = rpc::simulate(&Simulation(p), p).unwrap();
    let signed = authorize_server(&simulated, &[3; 32], 86401, None).unwrap();
    assert!(signed.native_preflight.is_none());
    rpc::simulate(&Simulation(&signed), &signed).unwrap()
}
#[test]
fn native_classic_payment_has_real_two_party_signatures() {
    for usdc in [false, true] {
        let (c, r, s) = fixture(WalletRoute::Native, usdc);
        let p = prepare(&c, &r, &s, 86401, 86700).unwrap();
        assert!(authorize(&p, &[sign(&p, &[2; 32], 86401).unwrap()], 86401).is_err());
        let signed = sign_native(&p);
        validate_signed(&signed, 86401).unwrap();
        let TransactionEnvelope::Tx(tx) =
            TransactionEnvelope::from_xdr_base64(&signed.transaction_xdr, Limits::none()).unwrap()
        else {
            panic!()
        };
        assert_eq!(
            tx.tx.memo,
            stellar_xdr::Memo::Hash(stellar_xdr::Hash(r.operation.nonce))
        );
        assert_eq!(tx.signatures.len(), 2);
        assert_eq!(tx.tx.seq_num.0, 41);
        let OperationBody::Payment(op) = &tx.tx.operations[0].body else {
            panic!()
        };
        assert_eq!(op.amount, 20_000_000);
        assert_eq!(op.asset, asset_xdr(&c).unwrap());
    }
}
#[test]
fn live_signers_and_thresholds_replace_the_fixed_template() {
    let (c, r, mut s) = fixture(WalletRoute::Native, false);
    s.source.signers.push(AccountSigner {
        key: account_for_seed(&[12; 32]),
        weight: 1,
    });
    assert!(prepare(&c, &r, &s, 86401, 86700).is_ok());
    s.source.high_threshold = 1;
    assert!(prepare(&c, &r, &s, 86401, 86700).is_ok());
    s.source.medium_threshold = 3;
    assert!(prepare(&c, &r, &s, 86401, 86700).is_err());
    s.source.medium_threshold = 2;
    s.source.low_threshold = 3;
    assert!(prepare(&c, &r, &s, 86401, 86700).is_err());
}
#[test]
fn separate_owner_profile_is_explicit_and_exact() {
    let (mut c, mut r, mut s) = fixture(WalletRoute::Native, false);
    c.owner = account_for_seed(&[10; 32]);
    s.owner = c.owner.clone();
    s.source.master_weight = 0;
    s.source.signers.push(AccountSigner {
        key: c.owner.clone(),
        weight: 3,
    });
    assert!(prepare(&c, &r, &s, 86401, 86700).is_ok());
    r.operation.policy_instance = [0; 32];
    assert!(prepare(&c, &r, &s, 86401, 86700).is_err());
}
#[test]
fn stale_or_changed_payload_cannot_be_signed() {
    let (c, r, s) = fixture(WalletRoute::Native, false);
    let mut p = prepare(&c, &r, &s, 86401, 86700).unwrap();
    p.request.effect_bounds[0].min_credit = 1u64.into();
    assert!(sign(&p, &[2; 32], 86401).is_err());
    let p = prepare(&c, &r, &s, 86401, 86700).unwrap();
    assert!(sign(&p, &[2; 32], 86700).is_err());
    assert!(sign(&p, &[1; 32], 86401).is_err());
    let mut signed = sign_native(&p);
    signed.transaction_hash[0] ^= 1;
    assert!(validate_signed(&signed, 86401).is_err());
}
#[test]
fn classic_caps_keep_exact_local_math_while_odc_requires_native_preflight() {
    for route in [WalletRoute::Native, WalletRoute::PolicyWallet] {
        let (mut c, mut r, mut s) = fixture(route.clone(), true);
        if route == WalletRoute::Native {
            c.policy_source = CAPPED.into();
            c.params = policy::params_from_json(
                &json!({"destinations": [account_for_seed(&[6;32])], "payment_limit": 20_000_000}),
                Some(PolicyTier::Simple),
            )
            .unwrap();
            c.source_hash = hash(&c.policy_source);
        } else {
            install(
                &mut c,
                PolicyTier::Common,
                CAPPED,
                json!({"destinations": [account_for_seed(&[6; 32])], "payment_limit": 20_000_000}),
            );
            s.policy_state = Some(PolicyStateSnapshot {
                params: c.params.clone(),
                state: PolicyParams::default(),
                rules: c.rules.clone(),
                source_digest: c.source_digest,
                x402_enabled: false,
            });
        }
        s.source_hash = c.source_hash;
        let prepared = prepare(&c, &r, &s, 86401, 86700).unwrap();
        if c.route == WalletRoute::PolicyWallet {
            // Host evaluation admits it, but signing still needs native preflight.
            assert!(
                sign(&prepared, &[2; 32], 86401)
                    .unwrap_err()
                    .contains("preflight")
            );
        }
        let ExecutionInput::Instructions(v) = &mut r.input else {
            panic!()
        };
        let NativeInstruction::StellarCall { arguments, .. } = &mut v[0] else {
            panic!()
        };
        arguments[2] = AbiValue::Signed128(20_000_001);
        r.effect_bounds[0].max_debit = 20_000_001u64.into();
        r.effect_bounds[0].min_credit = 20_000_001u64.into();
        assert!(prepare(&c, &r, &s, 86401, 86700).is_err());
    }
}
#[test]
fn odc_uses_execute_and_exact_module_schema_payload() {
    let (c, r, s) = fixture(WalletRoute::PolicyWallet, false);
    let p = prepare(&c, &r, &s, 86401, 86700).unwrap();
    assert!(sign(&p, &[2; 32], 86401).is_err());
    let data = SorobanTransactionData::default()
        .to_xdr_base64(Limits::none())
        .unwrap();
    let p = attach_simulation(&p, &data).unwrap();
    let p = server_ready(&p);
    let sig = sign(&p, &[2; 32], 86401).unwrap();
    let signed = authorize(&p, &[sig], 86401).unwrap();
    validate_signed(&signed, 86401).unwrap();
    let TransactionEnvelope::Tx(tx) =
        TransactionEnvelope::from_xdr_base64(&signed.transaction_xdr, Limits::none()).unwrap()
    else {
        panic!()
    };
    let OperationBody::InvokeHostFunction(op) = &tx.tx.operations[0].body else {
        panic!()
    };
    let stellar_xdr::HostFunction::InvokeContract(call) = &op.host_function else {
        panic!()
    };
    assert_eq!(tx.tx.memo, stellar_xdr::Memo::None);
    assert_eq!(call.function_name.0.as_slice(), b"execute");
    let stellar_xdr::ScVal::Map(Some(fields)) = &call.args[0] else {
        panic!()
    };
    let operation = fields.iter().find(|field| matches!(&field.key, stellar_xdr::ScVal::Symbol(key) if key.0.as_slice() == b"operation_id")).unwrap();
    let stellar_xdr::ScVal::Bytes(value) = &operation.val else {
        panic!()
    };
    assert_eq!(value.0.as_slice(), &r.operation.nonce);
    assert_eq!(call.args.len(), 1);
    assert_eq!(op.auth.len(), 2);
    let mut changed = s.clone();
    changed.module_digest[0] ^= 1;
    assert!(prepare(&c, &r, &changed, 86401, 86700).is_err());
}
struct FakeRpc {
    calls: Mutex<Vec<String>>,
    signed: SignedOperation,
    fail_send: bool,
}
impl rpc::Rpc for FakeRpc {
    fn call(&self, method: &str, params: Value) -> Result<Value> {
        self.calls.lock().unwrap().push(method.into());
        if method == "sendTransaction" {
            assert_eq!(params, json!({"transaction":self.signed.transaction_xdr}));
        }
        match method {
            "sendTransaction" if self.fail_send => Err("connection lost".into()),
            "sendTransaction" => {
                Ok(json!({"hash":hex(&self.signed.transaction_hash),"status":"PENDING"}))
            }
            "getTransaction" => {
                let result = TransactionResult {
                    fee_charged: 100,
                    result: TransactionResultResult::TxSuccess(
                        vec![OperationResult::OpInner(OperationResultTr::Payment(
                            PaymentResult::Success,
                        ))]
                        .try_into()
                        .unwrap(),
                    ),
                    ext: TransactionResultExt::V0,
                };
                Ok(
                    json!({"status":"SUCCESS","ledger":777,"envelopeXdr":self.signed.transaction_xdr,"resultXdr":result.to_xdr_base64(Limits::none()).unwrap()}),
                )
            }
            _ => Err("unexpected rpc".into()),
        }
    }
}
#[test]
fn requests_reject_other_rails_unbounded_fees_extra_effects_and_wrong_asset() {
    let (c, mut r, s) = fixture(WalletRoute::Native, false);
    r.fee_bounds = None;
    assert!(prepare(&c, &r, &s, 86401, 86700).is_err());
    let (c, mut r, s) = fixture(WalletRoute::Native, false);
    r.effect_bounds.push(r.effect_bounds[0].clone());
    assert!(prepare(&c, &r, &s, 86401, 86700).is_err());
    let (c, r, _) = fixture(WalletRoute::Native, false);
    let mut foreign = serde_json::to_value(r).unwrap();
    foreign["effect_bounds"][0]["source"]["chain"] = json!("Solana");
    assert!(serde_json::from_value::<ExecutionRequest>(foreign).is_err());
    assert_eq!(c.network, "stellar:testnet");
}
#[test]
fn redeems_admit_only_positive_amounts_for_the_wallet_on_a_policy_wallet() {
    let vault = Contract([0x56; 32]).to_string();
    let (native, _, native_state) = fixture(WalletRoute::Native, false);
    assert!(
        request::redeem(&native, &native_state, [8; 32], &vault, 3, 2)
            .unwrap_err()
            .contains("require a policy wallet")
    );
    let (c, _, s) = fixture(WalletRoute::PolicyWallet, false);
    let r = request::redeem(&c, &s, [8; 32], &vault, 3, 2).unwrap();
    assert_eq!(
        operation_from_request(&c, &r).unwrap(),
        StellarOperation::Redeem(Redeem {
            vault,
            shares: 3,
            min_assets: 2,
        })
    );
    // `redeem(shares, receiver, owner, operator, min_assets)` with one argument replaced.
    let with_argument = |i: usize, value: AbiValue| {
        let mut r = r.clone();
        let ExecutionInput::Instructions(v) = &mut r.input else {
            panic!()
        };
        let NativeInstruction::StellarCall { arguments, .. } = &mut v[0] else {
            panic!()
        };
        arguments[i] = value;
        operation_from_request(&c, &r).unwrap_err()
    };
    let other = AbiValue::Account(wf(&account_for_seed(&[6; 32])));
    for party in 1..=3 {
        assert!(with_argument(party, other.clone()).contains("must be the wallet"));
    }
    for (i, units) in [(0, 0), (0, -3), (4, 0), (4, -1)] {
        assert!(with_argument(i, AbiValue::Signed128(units)).contains("must be positive"));
    }
}

/// sendTransaction answers TRY_AGAIN_LATER first, then PENDING. getTransaction answers
/// NOT_FOUND, as for a transaction the network never accepted.
struct AccountRpc {
    config: WalletConfig,
    account: AccountState,
    wrong_network: bool,
}
impl rpc::Rpc for AccountRpc {
    fn call(&self, method: &str, _: Value) -> Result<Value> {
        match method {
            "getNetwork" => Ok(
                json!({"passphrase":if self.wrong_network{"wrong"}else{passphrase(&self.config.network)?}}),
            ),
            "getLatestLedger" => Ok(json!({"sequence":100})),
            "getLedgerEntries" => {
                let a = &self.account;
                let entry = stellar_xdr::AccountEntry {
                    account_id: stellar_xdr::AccountId(
                        stellar_xdr::PublicKey::PublicKeyTypeEd25519(stellar_xdr::Uint256(
                            account_key(&a.address)?,
                        )),
                    ),
                    seq_num: stellar_xdr::SequenceNumber(a.sequence),
                    thresholds: stellar_xdr::Thresholds([
                        a.master_weight as u8,
                        a.low_threshold as u8,
                        a.medium_threshold as u8,
                        a.high_threshold as u8,
                    ]),
                    signers: a
                        .signers
                        .iter()
                        .map(|s| {
                            Ok(stellar_xdr::Signer {
                                key: match stellar_strkey::Strkey::from_string(&s.key)
                                    .map_err(|e| e.to_string())?
                                {
                                    stellar_strkey::Strkey::PublicKeyEd25519(k) => {
                                        stellar_xdr::SignerKey::Ed25519(stellar_xdr::Uint256(k.0))
                                    }
                                    stellar_strkey::Strkey::PreAuthTx(k) => {
                                        stellar_xdr::SignerKey::PreAuthTx(stellar_xdr::Uint256(k.0))
                                    }
                                    stellar_strkey::Strkey::HashX(k) => {
                                        stellar_xdr::SignerKey::HashX(stellar_xdr::Uint256(k.0))
                                    }
                                    stellar_strkey::Strkey::SignedPayloadEd25519(k) => {
                                        stellar_xdr::SignerKey::Ed25519SignedPayload(
                                            stellar_xdr::SignerKeyEd25519SignedPayload {
                                                ed25519: stellar_xdr::Uint256(k.ed25519),
                                                payload: k.payload.try_into().unwrap(),
                                            },
                                        )
                                    }
                                    _ => return Err("not an account signer".into()),
                                },
                                weight: s.weight,
                            })
                        })
                        .collect::<Result<Vec<_>>>()?
                        .try_into()
                        .unwrap(),
                    ..Default::default()
                };
                Ok(
                    json!({"entries":[{"xdr":stellar_xdr::LedgerEntryData::Account(entry).to_xdr_base64(Limits::none()).unwrap()}]}),
                )
            }
            _ => Err("unexpected RPC".into()),
        }
    }
}
#[test]
fn native_state_uses_network_and_real_account_xdr_with_explicit_usage() {
    let (c, _, s) = fixture(WalletRoute::Native, false);
    let rpc = AccountRpc {
        config: c.clone(),
        account: s.source.clone(),
        wrong_network: false,
    };
    assert!(rpc::trusted_state(&rpc, &c, None).is_err());
    let accounting = rpc::NativeAccounting {
        nonce: 9,
        deployment_version: 4,
        spent_daily: 12,
        spent_total: 20,
        spent_day: 1,
        calls: 2,
    };
    let observed = rpc::trusted_state(&rpc, &c, Some(accounting.clone())).unwrap();
    assert_eq!(observed.source, s.source);
    assert_eq!(observed.spent_daily, 12);
    assert_eq!(observed.nonce, 9);
    let wrong = AccountRpc {
        config: c.clone(),
        account: s.source,
        wrong_network: true,
    };
    assert!(rpc::trusted_state(&wrong, &c, Some(accounting)).is_err());
}

#[test]
fn verified_receipt_retains_exact_network_transaction_and_ledger() {
    let (c, r, s) = fixture(WalletRoute::Native, false);
    let p = prepare(&c, &r, &s, 86401, 86700).unwrap();
    let signed = sign_native(&p);
    let rpc = FakeRpc {
        calls: Mutex::new(vec![]),
        signed: signed.clone(),
        fail_send: false,
    };
    let receipt = rpc::receipt_by_hash(&rpc, &c.network, &signed.transaction_hash)
        .unwrap()
        .unwrap();
    assert_eq!(receipt.ledger, 777);
    assert_eq!(receipt.transaction_hash, signed.transaction_hash);
    assert_eq!(receipt.envelope_xdr, signed.transaction_xdr);
    assert_eq!(receipt.status, OperationStatus::Confirmed);
    rpc::validate_receipt(&receipt, &c.network, &signed.transaction_hash).unwrap();
    let mut changed = receipt.clone();
    changed.status = OperationStatus::Failed;
    assert!(rpc::validate_receipt(&changed, &c.network, &signed.transaction_hash).is_err());
    assert!(rpc::receipt_by_hash(&rpc, "stellar:mainnet", &signed.transaction_hash).is_err());
    assert!(rpc::receipt_by_hash(&rpc, &c.network, &[0; 32]).is_err());
}

#[test]
fn odc_resource_fees_require_explicit_config_and_request_budget() {
    let (mut config, mut request, state) = fixture(WalletRoute::PolicyWallet, false);
    config.max_fee_stroops = 1_000_000;
    request.fee_bounds.as_mut().unwrap()[0].max_fee = 1_000_000u64.into();
    let original = prepare(&config, &request, &state, 86401, 86700).unwrap();
    let mut resource = SorobanTransactionData {
        resource_fee: 1_331_294,
        ..Default::default()
    };
    let encode = |data: &SorobanTransactionData| data.to_xdr_base64(Limits::none()).unwrap();
    assert!(attach_simulation(&original, &encode(&resource)).is_err());
    config.max_fee_stroops = 2_000_000;
    assert!(prepare(&config, &request, &state, 86401, 86700).is_err());
    request.fee_bounds.as_mut().unwrap()[0].max_fee = 2_000_000u64.into();
    let approved = prepare(&config, &request, &state, 86401, 86700).unwrap();
    let prepared = attach_simulation(&approved, &encode(&resource)).unwrap();
    let TransactionEnvelope::Tx(envelope) =
        TransactionEnvelope::from_xdr_base64(&prepared.transaction_xdr, Limits::none()).unwrap()
    else {
        panic!()
    };
    assert_eq!(envelope.tx.fee, 1_331_394);
    assert_eq!(envelope.tx.memo, stellar_xdr::Memo::None);
    for fee in [-1, i64::MAX, i64::from(u32::MAX), 1_999_901] {
        resource.resource_fee = fee;
        assert!(attach_simulation(&approved, &encode(&resource)).is_err());
    }
    resource.resource_fee = 1_999_900;
    assert!(attach_simulation(&approved, &encode(&resource)).is_ok());
    config.max_fee_stroops = POLICY_WALLET_MAX_FEE_STROOPS;
    validate_config(&config).unwrap();
    config.max_fee_stroops = POLICY_WALLET_MAX_FEE_STROOPS + 1;
    assert!(validate_config(&config).is_err());
    let (mut native, _, _) = fixture(WalletRoute::Native, false);
    native.max_fee_stroops = 1_000_000;
    validate_config(&native).unwrap();
    native.max_fee_stroops = 1_000_001;
    assert!(validate_config(&native).is_err());
}

fn native_packet_bounds(mut prepared: PreparedOperation, min: u64, max: u64) -> PreparedOperation {
    let TransactionEnvelope::Tx(mut envelope) =
        TransactionEnvelope::from_xdr_base64(&prepared.transaction_xdr, Limits::none()).unwrap()
    else {
        panic!()
    };
    envelope.tx.cond = stellar_xdr::Preconditions::Time(stellar_xdr::TimeBounds {
        min_time: stellar_xdr::TimePoint(min),
        max_time: stellar_xdr::TimePoint(max),
    });
    prepared.transaction_hash = hash(
        stellar_xdr::TransactionSignaturePayload {
            network_id: stellar_xdr::Hash(network_id(&prepared.config.network).unwrap()),
            tagged_transaction: stellar_xdr::TransactionSignaturePayloadTaggedTransaction::Tx(
                envelope.tx.clone(),
            ),
        }
        .to_xdr(Limits::none())
        .unwrap(),
    );
    prepared.transaction_xdr = envelope_to_xdr(envelope);
    prepared
}
fn envelope_to_xdr(envelope: stellar_xdr::TransactionV1Envelope) -> String {
    TransactionEnvelope::Tx(envelope)
        .to_xdr_base64(Limits::none())
        .unwrap()
}
fn retained_native_signed(prepared: PreparedOperation) -> SignedOperation {
    use ed25519_dalek::{Signer, SigningKey};
    let TransactionEnvelope::Tx(mut envelope) =
        TransactionEnvelope::from_xdr_base64(&prepared.transaction_xdr, Limits::none()).unwrap()
    else {
        panic!()
    };
    envelope.signatures = [2u8, 3]
        .into_iter()
        .map(|value| {
            let key = SigningKey::from_bytes(&[value; 32]);
            stellar_xdr::DecoratedSignature {
                hint: stellar_xdr::SignatureHint(
                    key.verifying_key().to_bytes()[28..].try_into().unwrap(),
                ),
                signature: stellar_xdr::Signature(
                    key.sign(&prepared.transaction_hash)
                        .to_bytes()
                        .to_vec()
                        .try_into()
                        .unwrap(),
                ),
            }
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let role_signatures = [2u8, 3]
        .into_iter()
        .map(|value| {
            let key = SigningKey::from_bytes(&[value; 32]);
            DetachedSignature {
                signer: account_for_seed(&[value; 32]),
                signature: key.sign(&prepared.transaction_hash).to_bytes().to_vec(),
            }
        })
        .collect();
    SignedOperation {
        transaction_xdr: envelope_to_xdr(envelope),
        transaction_hash: prepared.transaction_hash,
        prepared,
        role_signatures,
    }
}
#[test]
fn native_immediate_bounds_exclude_the_expiry_second_and_reject_other_bounds() {
    let (c, r, s) = fixture(WalletRoute::Native, false);
    let p = prepare(&c, &r, &s, 86401, 86700).unwrap();
    let TransactionEnvelope::Tx(envelope) =
        TransactionEnvelope::from_xdr_base64(&p.transaction_xdr, Limits::none()).unwrap()
    else {
        panic!()
    };
    assert_eq!(
        envelope.tx.cond,
        stellar_xdr::Preconditions::Time(stellar_xdr::TimeBounds {
            min_time: stellar_xdr::TimePoint(0),
            max_time: stellar_xdr::TimePoint(86699)
        })
    );
    validate_signed(&sign_native(&p), 86401).unwrap();
    assert!(sign(&p, &[2; 32], 86700).is_err());
    assert!(sign(&p, &[2; 32], 86400).is_err());
    assert!(prepare(&c, &r, &s, 86401, 86702).is_err());
    for lower in [1, 86400, 86402, u64::MAX] {
        assert!(validate_prepared(&native_packet_bounds(p.clone(), lower, 86700), 86401).is_err());
    }
    for upper in [86698, 86701] {
        assert!(validate_prepared(&native_packet_bounds(p.clone(), 0, upper), 86401).is_err());
    }
    // A packet from before the exclusive upper bound stays readable but cannot be signed: its
    // inclusive `maxTime` lets a payment settle in the second the request and policy expire.
    let inclusive = native_packet_bounds(p.clone(), 0, 86700);
    validate_prepared(&inclusive, 86401).unwrap();
    assert!(
        sign(&inclusive, &[2; 32], 86401)
            .unwrap_err()
            .contains("read-only")
    );
}
#[test]
fn retained_native_status_preserves_signed_bytes_without_new_authorization() {
    let (c, r, s) = fixture(WalletRoute::Native, false);
    let current = prepare(&c, &r, &s, 86401, 86700).unwrap();
    let retained = native_packet_bounds(current.clone(), 86401, 86700);
    validate_prepared(&retained, 86401).unwrap();
    assert!(
        sign(&retained, &[2; 32], 86401)
            .unwrap_err()
            .contains("read-only")
    );
    assert!(
        authorize(&retained, &[], 86401)
            .unwrap_err()
            .contains("read-only")
    );
    let signed = retained_native_signed(retained);
    validate_signed(&signed, 86401).unwrap();
    let rpc = FakeRpc {
        calls: Mutex::new(vec![]),
        signed: signed.clone(),
        fail_send: false,
    };
    assert_eq!(
        rpc::status_by_hash(&rpc, &c.network, &signed.transaction_hash).unwrap(),
        OperationStatus::Confirmed
    );
    let mut rewritten = signed.clone();
    let TransactionEnvelope::Tx(mut envelope) =
        TransactionEnvelope::from_xdr_base64(&signed.transaction_xdr, Limits::none()).unwrap()
    else {
        panic!()
    };
    let TransactionEnvelope::Tx(new) =
        TransactionEnvelope::from_xdr_base64(&current.transaction_xdr, Limits::none()).unwrap()
    else {
        panic!()
    };
    envelope.tx = new.tx;
    rewritten.prepared = current.clone();
    rewritten.transaction_hash = current.transaction_hash;
    rewritten.transaction_xdr = envelope_to_xdr(envelope);
    assert!(validate_signed(&rewritten, 86401).is_err());
    assert_eq!(*rpc.calls.lock().unwrap(), vec!["getTransaction"]);
}

#[test]
fn changed_customer_signer_is_resolved_from_current_native_account() {
    let (mut c, r, mut state) = fixture(WalletRoute::Native, false);
    let old = c.clone();
    c.agent = account_for_seed(&[4; 32]);
    state.agent = c.agent.clone();
    state.source.master_weight = 0;
    state.source.signers[0] = AccountSigner {
        key: c.agent.clone(),
        weight: 3,
    };
    state.source.signers[1].weight = 2;
    state.source.medium_threshold = 5;
    state.source.low_threshold = 1;
    state.source.high_threshold = 1;
    let rpc = AccountRpc {
        config: c.clone(),
        account: state.source.clone(),
        wrong_network: false,
    };
    let accounting = rpc::NativeAccounting {
        nonce: state.nonce,
        deployment_version: state.deployment_version,
        spent_daily: state.spent_daily,
        spent_total: state.spent_total,
        spent_day: state.spent_day,
        calls: state.calls,
    };
    assert!(rpc::trusted_state_for_discovery(&rpc, &old, Some(accounting.clone())).is_ok());
    assert!(rpc::trusted_state(&rpc, &old, Some(accounting.clone())).is_err());
    let live = rpc::trusted_state(&rpc, &c, Some(accounting)).unwrap();
    let p = prepare(&c, &r, &live, 86401, 86700).unwrap();
    assert!(sign(&p, &[2; 32], 86401).is_err());
    let signed = authorize(
        &p,
        &[
            sign(&p, &[4; 32], 86401).unwrap(),
            sign(&p, &[3; 32], 86401).unwrap(),
        ],
        86401,
    )
    .unwrap();
    validate_signed(&signed, 86401).unwrap();
}
#[test]
fn exact_chain_quorum_omits_unused_role_signatures_but_verifies_both_proofs() {
    for customer_weight in [1, 3] {
        let (c, r, mut s) = fixture(WalletRoute::Native, false);
        s.source.signers[0].weight = customer_weight;
        s.source.signers[1].weight = 3;
        s.source.medium_threshold = 2;
        s.source.low_threshold = 1;
        let p = prepare(&c, &r, &s, 86401, 86700).unwrap();
        let customer = sign(&p, &[2; 32], 86401).unwrap();
        let engine = sign(&p, &[3; 32], 86401).unwrap();
        let out = authorize(&p, &[customer.clone(), engine.clone()], 86401).unwrap();
        let TransactionEnvelope::Tx(mut env) =
            TransactionEnvelope::from_xdr_base64(&out.transaction_xdr, Limits::none()).unwrap()
        else {
            panic!()
        };
        assert_eq!(env.signatures.len(), 1);
        validate_signed(&out, 86401).unwrap();
        let mut invalid = engine;
        invalid.signature[0] ^= 1;
        assert!(authorize(&p, &[customer, invalid], 86401).is_err());
        let mut extra = env.signatures.to_vec();
        extra.push(extra[0].clone());
        env.signatures = extra.try_into().unwrap();
        let mut changed = out;
        changed.transaction_xdr = env.to_xdr_base64(Limits::none()).unwrap();
        assert!(validate_signed(&changed, 86401).is_err());
    }
}
#[test]
fn native_submission_requires_service_approval_when_agent_alone_meets_thresholds() {
    use ed25519_dalek::{Signer, SigningKey};
    let (c, r, mut s) = fixture(WalletRoute::Native, false);
    s.source.signers[0].weight = 3;
    s.source.low_threshold = 1;
    s.source.medium_threshold = 2;
    let p = prepare(&c, &r, &s, 86401, 86700).unwrap();
    let agent = sign(&p, &[2; 32], 86401).unwrap();
    let service = sign(&p, &[3; 32], 86401).unwrap();
    assert!(authorize(&p, std::slice::from_ref(&agent), 86401).is_err());
    let out = authorize(&p, &[agent.clone(), service.clone()], 86401).unwrap();
    assert_eq!(out.role_signatures, vec![agent.clone(), service]);
    validate_signed(&out, 86401).unwrap();

    // Build the agent-only packet that the chain thresholds alone would accept.
    let key = SigningKey::from_bytes(&[2; 32]);
    let TransactionEnvelope::Tx(mut envelope) =
        TransactionEnvelope::from_xdr_base64(&p.transaction_xdr, Limits::none()).unwrap()
    else {
        panic!()
    };
    envelope.signatures = vec![stellar_xdr::DecoratedSignature {
        hint: stellar_xdr::SignatureHint(key.verifying_key().to_bytes()[28..].try_into().unwrap()),
        signature: stellar_xdr::Signature(
            key.sign(&p.transaction_hash)
                .to_bytes()
                .to_vec()
                .try_into()
                .unwrap(),
        ),
    }]
    .try_into()
    .unwrap();
    let mut bypass = out.clone();
    bypass.transaction_xdr = envelope_to_xdr(envelope);
    assert_eq!(bypass.transaction_xdr, out.transaction_xdr);
    for role_signatures in [
        vec![],
        vec![agent.clone()],
        vec![agent.clone(), agent.clone()],
        {
            let mut forged = out.role_signatures.clone();
            forged[1].signature[0] ^= 1;
            forged
        },
        out.role_signatures.iter().rev().cloned().collect(),
    ] {
        let mut changed = bypass.clone();
        changed.role_signatures = role_signatures;
        assert!(validate_signed(&changed, 86401).is_err());
        let rpc = FakeRpc {
            calls: Mutex::new(vec![]),
            signed: changed.clone(),
            fail_send: false,
        };
        assert!(rpc::broadcast(&rpc, &changed, 86401).is_err());
        assert!(rpc.calls.lock().unwrap().is_empty());
    }
    // A record from before role proofs stays readable for recovery but cannot be broadcast.
    let mut legacy = out.clone();
    legacy.role_signatures.clear();
    validate_retained_signed(&legacy).unwrap();
    let mut serialized: Value = serde_json::to_value(&legacy).unwrap();
    assert!(serialized.get("roleSignatures").is_none());
    serialized["roleSignatures"] = serde_json::to_value(&out.role_signatures).unwrap();
    let restored: SignedOperation = serde_json::from_value(serialized).unwrap();
    assert_eq!(restored, out);
}
#[test]
fn role_proofs_are_rejected_outside_classic_custody() {
    let (c, r, s) = fixture(WalletRoute::PolicyWallet, false);
    let p = server_ready(&prepare(&c, &r, &s, 86401, 86700).unwrap());
    let proof = sign(&p, &[2; 32], 86401).unwrap();
    let signed = authorize(&p, std::slice::from_ref(&proof), 86401).unwrap();
    assert!(signed.role_signatures.is_empty());
    let mut changed = signed;
    changed.role_signatures = vec![proof];
    assert!(validate_retained_signed(&changed).is_err());
}
#[test]
fn additional_hash_preauthorized_and_payload_keys_do_not_lock_the_wallet() {
    let (c, r, mut s) = fixture(WalletRoute::Native, false);
    for key in [
        stellar_strkey::HashX([21; 32]).to_string(),
        stellar_strkey::PreAuthTx([22; 32]).to_string(),
        stellar_strkey::ed25519::SignedPayload {
            ed25519: [23; 32],
            payload: vec![1, 2, 3],
        }
        .to_string(),
    ] {
        s.source.signers.push(AccountSigner { key, weight: 255 });
    }
    let p = prepare(&c, &r, &s, 86401, 86700).unwrap();
    let out = authorize(
        &p,
        &[
            sign(&p, &[2; 32], 86401).unwrap(),
            sign(&p, &[3; 32], 86401).unwrap(),
        ],
        86401,
    )
    .unwrap();
    validate_signed(&out, 86401).unwrap();
    s.source.signers.push(s.source.signers[0].clone());
    assert!(prepare(&c, &r, &s, 86401, 86700).is_err());
}
#[test]
fn current_exact_preauthorization_does_not_add_unused_ed25519_signatures() {
    let (c, r, mut s) = fixture(WalletRoute::Native, false);
    let original = prepare(&c, &r, &s, 86401, 86700).unwrap();
    s.source.signers.push(AccountSigner {
        key: stellar_strkey::PreAuthTx(original.transaction_hash).to_string(),
        weight: 2,
    });
    let p = prepare(&c, &r, &s, 86401, 86700).unwrap();
    assert_eq!(p.transaction_hash, original.transaction_hash);
    let out = authorize(
        &p,
        &[
            sign(&p, &[2; 32], 86401).unwrap(),
            sign(&p, &[3; 32], 86401).unwrap(),
        ],
        86401,
    )
    .unwrap();
    let TransactionEnvelope::Tx(env) =
        TransactionEnvelope::from_xdr_base64(&out.transaction_xdr, Limits::none()).unwrap()
    else {
        panic!()
    };
    assert!(env.signatures.is_empty());
    validate_signed(&out, 86401).unwrap();
    let rpc = FakeRpc {
        calls: Mutex::new(vec![]),
        signed: out.clone(),
        fail_send: false,
    };
    assert_eq!(
        rpc::broadcast(&rpc, &out, 86401).unwrap(),
        rpc::Broadcast::Submitted
    );
    assert_eq!(*rpc.calls.lock().unwrap(), vec!["sendTransaction"]);
    assert_eq!(
        rpc::signed_transaction_hash(&c.network, &out.transaction_xdr).unwrap(),
        original.transaction_hash
    );
}
#[test]
fn odc_current_agent_account_may_have_a_different_customer_signer() {
    let (mut c, r, mut s) = fixture(WalletRoute::PolicyWallet, false);
    let actual_agent = s.agent.clone();
    c.agent = account_for_seed(&[4; 32]);
    s.source.master_weight = 0;
    s.source.low_threshold = 2;
    s.source.medium_threshold = 3;
    s.source.high_threshold = 5;
    s.source.signers = vec![
        AccountSigner {
            key: c.agent.clone(),
            weight: 3,
        },
        AccountSigner {
            key: stellar_strkey::HashX([22; 32]).to_string(),
            weight: 1,
        },
    ];
    assert_eq!(s.source.address, actual_agent);
    // A built request names the agent account, not the customer signer, as its fee payer.
    let built = request::transfer(&c, &s, [8; 32], &account_for_seed(&[6; 32]), 1).unwrap();
    prepare(&c, &built, &s, 86401, 86700).unwrap();
    let mut p = prepare(&c, &r, &s, 86401, 86700).unwrap();
    let resource = SorobanTransactionData {
        ext: stellar_xdr::SorobanTransactionDataExt::V0,
        resources: stellar_xdr::SorobanResources {
            footprint: stellar_xdr::LedgerFootprint {
                read_only: Default::default(),
                read_write: Default::default(),
            },
            instructions: 1,
            disk_read_bytes: 0,
            write_bytes: 0,
        },
        resource_fee: 1000,
    };
    // The fixture's admitted fee bound is high enough for this explicit resource data.
    p = attach_simulation(&p, &resource.to_xdr_base64(Limits::none()).unwrap()).unwrap();
    let p = server_ready(&p);
    let out = authorize(&p, &[sign(&p, &[4; 32], 86401).unwrap()], 86401).unwrap();
    validate_signed(&out, 86401).unwrap();
    let TransactionEnvelope::Tx(env) =
        TransactionEnvelope::from_xdr_base64(&out.transaction_xdr, Limits::none()).unwrap()
    else {
        panic!()
    };
    assert_eq!(
        env.tx.source_account,
        stellar_xdr::MuxedAccount::Ed25519(stellar_xdr::Uint256(
            account_key(&actual_agent).unwrap()
        ))
    );
    s.source.signers[0].weight = 2;
    let mut underweight = p.clone();
    underweight.state.source = s.source;
    assert!(
        attach_simulation(
            &underweight,
            &resource.to_xdr_base64(Limits::none()).unwrap()
        )
        .is_err()
    );
}

#[test]
fn rpc_decodes_known_additional_signer_types_without_an_offline_allowlist() {
    let (c, _, mut state) = fixture(WalletRoute::Native, false);
    for key in [
        stellar_strkey::HashX([21; 32]).to_string(),
        stellar_strkey::PreAuthTx([22; 32]).to_string(),
        stellar_strkey::ed25519::SignedPayload {
            ed25519: [23; 32],
            payload: vec![1, 2, 3],
        }
        .to_string(),
    ] {
        state.source.signers.push(AccountSigner { key, weight: 1 });
    }
    let rpc = AccountRpc {
        config: c.clone(),
        account: state.source.clone(),
        wrong_network: false,
    };
    assert_eq!(rpc::get_account(&rpc, &c.wallet).unwrap(), state.source);
    let usage = rpc::NativeAccounting {
        nonce: 0,
        deployment_version: 0,
        spent_daily: 0,
        spent_total: 0,
        spent_day: 1,
        calls: 0,
    };
    assert!(rpc::trusted_state(&rpc, &c, Some(usage)).is_ok());
}
fn sc_map(fields: Vec<(&str, stellar_xdr::ScVal)>) -> stellar_xdr::ScVal {
    let mut entries: Vec<_> = fields
        .into_iter()
        .map(|(name, val)| stellar_xdr::ScMapEntry {
            key: stellar_xdr::ScVal::Symbol(stellar_xdr::ScSymbol(
                name.as_bytes().to_vec().try_into().unwrap(),
            )),
            val,
        })
        .collect();
    entries.sort_by(|a, b| a.key.cmp(&b.key));
    stellar_xdr::ScVal::Map(Some(entries.try_into().unwrap()))
}
/// Portable canonical-only source of the policy wallet fixtures.
const PORTABLE: &str = "use allowit::prelude::*;\n/// Pay only destinations I approve.\npub fn execute(ctx: &AllowitContext) -> allowit::Result {\n    allowit::destinations(ctx, &ctx.params[allowit::DESTINATIONS])?;\n    Ok(())\n}\n";
/// Layout 4 State of the fixture wallet.
fn custody_scval(
    c: &WalletConfig,
    agent: &str,
    owner: &str,
    paused: bool,
    nonce: u64,
    deployment_version: u64,
) -> stellar_xdr::ScVal {
    allowit_stellar_wallet::contract::CustodyState {
        policy_state: PolicyParams::default(),
        contract_version: CONTRACT_VERSION,
        owner: owner.into(),
        agent: agent.into(),
        server: c.server.clone(),
        asset: c.asset.clone(),
        policy_instance: c.policy_instance,
        source_digest: c.source_digest,
        rules: c.rules.clone(),
        params: c.params.clone(),
        x402_enabled: false,
        token: c.asset_symbol.clone(),
        deployment_version,
        nonce,
        paused,
    }
    .scval()
    .unwrap()
}
/// The installed binding of the fixture wallet: Simple and Common run every operation, Custom
/// no deposit.
fn binding_scval(c: &WalletConfig) -> stellar_xdr::ScVal {
    use OperationKind::*;
    let tier = c.tier.unwrap();
    allowit_stellar_wallet::contract::PolicyBinding {
        engine_kind: tier.kind().into(),
        contract_version: CONTRACT_VERSION,
        policy_instance: c.policy_instance,
        module_digest: c.module_digest,
        source_digest: c.source_digest,
        operations: if tier == PolicyTier::Custom {
            vec![Transfer, Swap, Redeem]
        } else {
            vec![Transfer, Swap, Deposit, Redeem]
        },
    }
    .scval()
    .unwrap()
}
struct PolicyWalletAccountRpc {
    config: WalletConfig,
    source: AccountState,
    paused: bool,
}
impl rpc::Rpc for PolicyWalletAccountRpc {
    fn call(&self, method: &str, params: Value) -> Result<Value> {
        use stellar_xdr::*;
        let c = &self.config;
        match method {
            "getNetwork" => Ok(json!({"passphrase":passphrase(&c.network)?})),
            "getLatestLedger" => Ok(json!({"sequence":120})),
            "getLedgerEntries" => {
                let key =
                    LedgerKey::from_xdr_base64(params["keys"][0].as_str().unwrap(), Limits::none())
                        .unwrap();
                if let LedgerKey::Account(account_key) = &key {
                    let mut account = self.source.clone();
                    if account_key.account_id
                        == stellar_xdr::AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
                            allowit_stellar_wallet::account_key(&c.server)?,
                        )))
                    {
                        account.address = c.server.clone();
                        account.master_weight = 1;
                        account.low_threshold = 1;
                        account.medium_threshold = 1;
                        account.high_threshold = 1;
                        account.signers.clear();
                    }
                    return rpc::Rpc::call(
                        &AccountRpc {
                            config: c.clone(),
                            account,
                            wrong_network: false,
                        },
                        method,
                        params,
                    );
                }
                if matches!(&key,LedgerKey::ContractData(data) if data.key!=ScVal::LedgerKeyContractInstance)
                {
                    return Ok(json!({"latestLedger":120,"entries":[]}));
                }
                let state = custody_scval(
                    c,
                    &self.source.address,
                    &Contract([33; 32]).to_string(),
                    self.paused,
                    4,
                    2,
                );
                let entry = LedgerEntryData::ContractData(ContractDataEntry {
                    ext: ExtensionPoint::V0,
                    contract: address(&c.wallet)?,
                    key: ScVal::LedgerKeyContractInstance,
                    durability: ContractDataDurability::Persistent,
                    val: ScVal::ContractInstance(ScContractInstance {
                        executable: ContractExecutable::Wasm(Hash(c.module_digest)),
                        storage: Some(
                            vec![ScMapEntry {
                                key: ScVal::U32(0),
                                val: state,
                            }]
                            .try_into()
                            .unwrap(),
                        ),
                    }),
                });
                Ok(json!({"entries":[{"xdr":entry.to_xdr_base64(Limits::none()).unwrap()}]}))
            }
            "simulateTransaction" => {
                let TransactionEnvelope::Tx(tx) = TransactionEnvelope::from_xdr_base64(
                    params["transaction"].as_str().unwrap(),
                    Limits::none(),
                )
                .unwrap() else {
                    panic!()
                };
                assert_eq!(
                    tx.tx.source_account,
                    MuxedAccount::Ed25519(Uint256(account_key(&self.source.address)?))
                );
                let OperationBody::InvokeHostFunction(op) = &tx.tx.operations[0].body else {
                    panic!()
                };
                let HostFunction::InvokeContract(call) = &op.host_function else {
                    panic!()
                };
                assert_eq!(call.function_name.0.as_slice(), b"policy_binding");
                let binding = binding_scval(c);
                Ok(json!({"results":[{"xdr":binding.to_xdr_base64(Limits::none()).unwrap()}]}))
            }
            _ => Err("unexpected RPC".into()),
        }
    }
}
#[test]
fn odc_discovery_reads_current_grant_source_and_does_not_lock_to_old_roles() {
    let (mut c, mut r, mut s) = fixture(WalletRoute::PolicyWallet, false);
    let obsolete = c.clone();
    c.agent = account_for_seed(&[4; 32]);
    s.source.address = account_for_seed(&[9; 32]);
    s.source.master_weight = 0;
    s.source.low_threshold = 2;
    s.source.medium_threshold = 3;
    s.source.high_threshold = 5;
    s.source.signers = vec![
        AccountSigner {
            key: c.agent.clone(),
            weight: 3,
        },
        AccountSigner {
            key: stellar_strkey::PreAuthTx([44; 32]).to_string(),
            weight: 1,
        },
    ];
    r.fee_bounds.as_mut().unwrap()[0].payer = wf(&s.source.address);
    let rpc = PolicyWalletAccountRpc {
        config: c.clone(),
        source: s.source.clone(),
        paused: false,
    };
    let discovery = rpc::trusted_state_for_discovery(&rpc, &obsolete, None).unwrap();
    assert_eq!(discovery.state.agent, s.source.address);
    assert_eq!(discovery.state.owner, Contract([33; 32]).to_string());
    assert_eq!(discovery.state.server, c.server);
    assert!(rpc::trusted_state(&rpc, &obsolete, None).is_err());
    let live = rpc::trusted_state(&rpc, &c, None).unwrap();
    assert_eq!(live.source, s.source);
    assert!(prepare(&c, &r, &live, 86401, 86700).is_ok());
    r.fee_bounds.as_mut().unwrap()[0].payer = wf(&c.agent);
    assert!(prepare(&c, &r, &live, 86401, 86700).is_err());
}

#[test]
fn obsolete_engine_role_alias_is_not_an_offline_customer_key_lock() {
    let (mut c, r, mut s) = fixture(WalletRoute::Native, false);
    c.server = c.agent.clone();
    s.server = c.server.clone();
    validate_config(&c).unwrap();
    assert!(prepare(&c, &r, &s, 86401, 86700).is_err()); // One key still weighs only one, not two.
    s.source.signers[0].weight = 2;
    let p = prepare(&c, &r, &s, 86401, 86700).unwrap();
    let p = server_ready(&p);
    let proof = sign(&p, &[2; 32], 86401).unwrap();
    let out = authorize(&p, &[proof.clone(), proof], 86401).unwrap();
    validate_signed(&out, 86401).unwrap();
    let TransactionEnvelope::Tx(env) =
        TransactionEnvelope::from_xdr_base64(&out.transaction_xdr, Limits::none()).unwrap()
    else {
        panic!()
    };
    assert_eq!(env.signatures.len(), 1);
}

#[test]
fn exact_preauthorization_can_complete_an_otherwise_insufficient_native_quorum() {
    let (c, r, mut s) = fixture(WalletRoute::Native, false);
    let initial = prepare(&c, &r, &s, 86401, 86700).unwrap();
    s.source.medium_threshold = 3;
    s.source.low_threshold = 3;
    assert!(prepare(&c, &r, &s, 86401, 86700).is_err());
    s.source.signers.push(AccountSigner {
        key: stellar_strkey::PreAuthTx(initial.transaction_hash).to_string(),
        weight: 1,
    });
    let p = prepare(&c, &r, &s, 86401, 86700).unwrap();
    let out = authorize(
        &p,
        &[
            sign(&p, &[2; 32], 86401).unwrap(),
            sign(&p, &[3; 32], 86401).unwrap(),
        ],
        86401,
    )
    .unwrap();
    validate_signed(&out, 86401).unwrap();
    let mut wrong = r;
    wrong.operation.nonce = [31; 32];
    assert!(prepare(&c, &wrong, &s, 86401, 86700).is_err());
}
#[test]
fn paused_odc_remains_discoverable_but_cannot_authorize_execution() {
    let (c, _, s) = fixture(WalletRoute::PolicyWallet, false);
    let rpc = PolicyWalletAccountRpc {
        config: c.clone(),
        source: s.source,
        paused: true,
    };
    let discovered = rpc::trusted_state_for_discovery(&rpc, &c, None).unwrap();
    assert!(discovered.paused);
    assert_eq!(discovered.state.policy_instance, c.policy_instance);
    assert!(rpc::trusted_state(&rpc, &c, None).is_err());
}

#[test]
fn odc_exact_resource_bound_preauthorization_completes_current_customer_quorum() {
    let (c, r, mut state) = fixture(WalletRoute::PolicyWallet, false);
    let resource = SorobanTransactionData {
        resource_fee: 1000,
        ..Default::default()
    };
    let data = resource.to_xdr_base64(Limits::none()).unwrap();
    let base = prepare(&c, &r, &state, 86401, 86700).unwrap();
    let final_hash = server_ready(&attach_simulation(&base, &data).unwrap()).transaction_hash;
    state.source.low_threshold = 2;
    state.source.medium_threshold = 2;
    let insufficient = prepare(&c, &r, &state, 86401, 86700).unwrap();
    assert!(
        sign(
            &attach_simulation(&insufficient, &data).unwrap(),
            &[2; 32],
            86401
        )
        .is_err()
    );
    state.source.signers.push(AccountSigner {
        key: stellar_strkey::PreAuthTx(final_hash).to_string(),
        weight: 1,
    });
    let before_simulation = prepare(&c, &r, &state, 86401, 86700).unwrap();
    assert!(sign(&before_simulation, &[2; 32], 86401).is_err());
    let prepared = server_ready(&attach_simulation(&before_simulation, &data).unwrap());
    assert_eq!(prepared.transaction_hash, final_hash);
    let signed = authorize(
        &prepared,
        &[sign(&prepared, &[2; 32], 86401).unwrap()],
        86401,
    )
    .unwrap();
    validate_signed(&signed, 86401).unwrap();
    let altered = SorobanTransactionData {
        resource_fee: 1001,
        ..Default::default()
    }
    .to_xdr_base64(Limits::none())
    .unwrap();
    assert!(attach_simulation(&prepared, &altered).is_err());
}

#[test]
fn retained_packet_validation_does_not_recompile_source_or_grant_execution() {
    let (c, r, state) = fixture(WalletRoute::Native, false);
    let prepared = prepare(&c, &r, &state, 86401, 86700).unwrap();
    let mut signed = sign_native(&prepared);
    // Model source metadata from a retired compiler namespace. The already signed
    // native body and effects stay byte-for-byte identical; this is proof, not admission.
    signed.prepared.config.policy_source="use allowit::v1::prelude::*; async fn _execute(ctx:&Context)->PolicyResult { retired_vendor::check(ctx)?; Ok(()) }".into();
    signed.prepared.config.source_hash = hash(&signed.prepared.config.policy_source);
    signed.prepared.state.source_hash = signed.prepared.config.source_hash;
    let original = serde_json::to_vec(&signed).unwrap();
    validate_retained_prepared(&signed.prepared).unwrap();
    validate_retained_signed(&signed).unwrap();
    assert!(validate_prepared(&signed.prepared, 86401).is_err());
    assert!(sign(&signed.prepared, &[2; 32], 86401).is_err());
    assert!(validate_signed(&signed, 86401).is_err());
    let rpc = FakeRpc {
        calls: Mutex::new(vec![]),
        signed: signed.clone(),
        fail_send: false,
    };
    assert!(rpc::broadcast(&rpc, &signed, 86401).is_err());
    assert!(rpc.calls.lock().unwrap().is_empty());
    assert_eq!(
        rpc::status_by_hash(&rpc, &c.network, &signed.transaction_hash).unwrap(),
        OperationStatus::Confirmed
    );
    assert_eq!(*rpc.calls.lock().unwrap(), vec!["getTransaction"]);
    assert_eq!(serde_json::to_vec(&signed).unwrap(), original);
}

struct AdminRpc {
    base: PolicyWalletAccountRpc,
    state_contract_version: u32,
    binding_contract_version: Option<stellar_xdr::ScVal>,
    calls: Mutex<Vec<(String, Vec<stellar_xdr::ScVal>)>>,
    balance: i128,
    wrong_owner: bool,
    bad_auth: bool,
    address_v2: bool,
}
fn replace_field(value: &mut stellar_xdr::ScVal, name: &str, new: stellar_xdr::ScVal) {
    let stellar_xdr::ScVal::Map(Some(map)) = value else {
        panic!()
    };
    let mut fields = map.to_vec();
    fields.retain(
        |e| !matches!(&e.key,stellar_xdr::ScVal::Symbol(s) if s.0.as_slice()==name.as_bytes()),
    );
    fields.push(stellar_xdr::ScMapEntry {
        key: stellar_xdr::ScVal::Symbol(stellar_xdr::ScSymbol(
            name.as_bytes().to_vec().try_into().unwrap(),
        )),
        val: new,
    });
    fields.sort_by(|a, b| a.key.cmp(&b.key));
    *map = fields.try_into().unwrap();
}
impl rpc::Rpc for AdminRpc {
    fn call(&self, method: &str, params: Value) -> Result<Value> {
        use stellar_xdr::*;
        if method == "getLedgerEntries" {
            let key =
                LedgerKey::from_xdr_base64(params["keys"][0].as_str().unwrap(), Limits::none())
                    .unwrap();
            if matches!(&key,LedgerKey::ContractData(data) if data.key!=ScVal::LedgerKeyContractInstance)
            {
                return self.base.call(method, params);
            }
            if matches!(key, LedgerKey::Account(_)) {
                // Trusted delegated discovery reads the agent; owner administration reads the
                // current owner and a new owner of a handoff.
                let LedgerKey::Account(a) = &key else {
                    unreachable!()
                };
                let Some(owner) = [self.base.config.owner.clone(), account_for_seed(&[51; 32])]
                    .into_iter()
                    .find(|owner| {
                        a.account_id
                            == AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
                                account_key(owner).unwrap(),
                            )))
                    })
                else {
                    return self.base.call(method, params);
                };
                let account = AccountState {
                    address: owner,
                    sequence: 40,
                    master_weight: 1,
                    low_threshold: 1,
                    medium_threshold: 1,
                    high_threshold: 1,
                    signers: vec![],
                };
                return AccountRpc {
                    config: self.base.config.clone(),
                    account,
                    wrong_network: false,
                }
                .call(method, params);
            }
            let mut response = self.base.call(method, params)?;
            let mut entry = LedgerEntryData::from_xdr_base64(
                response["entries"][0]["xdr"].as_str().unwrap(),
                Limits::none(),
            )
            .unwrap();
            let LedgerEntryData::ContractData(ref mut data) = entry else {
                panic!()
            };
            let ScVal::ContractInstance(ref mut instance) = data.val else {
                panic!()
            };
            let mut storage = instance.storage.clone().unwrap().to_vec();
            let state = &mut storage[0].val;
            replace_field(
                state,
                "contract_version",
                ScVal::U32(self.state_contract_version),
            );
            replace_field(
                state,
                "owner",
                ScVal::Address(address(if self.wrong_owner {
                    &self.base.source.address
                } else {
                    &self.base.config.owner
                })?),
            );
            instance.storage = Some(storage.try_into().unwrap());
            response["entries"][0]["xdr"] = json!(entry.to_xdr_base64(Limits::none()).unwrap());
            return Ok(response);
        }
        if method == "simulateTransaction" {
            let TransactionEnvelope::Tx(envelope) = TransactionEnvelope::from_xdr_base64(
                params["transaction"].as_str().unwrap(),
                Limits::none(),
            )
            .unwrap() else {
                panic!()
            };
            let OperationBody::InvokeHostFunction(op) = &envelope.tx.operations[0].body else {
                panic!()
            };
            let HostFunction::InvokeContract(call) = &op.host_function else {
                panic!()
            };
            let function = String::from_utf8(call.function_name.0.to_vec()).unwrap();
            if function == "policy_binding" {
                let mut binding = binding_scval(&self.base.config);
                let ScVal::Map(Some(map)) = &mut binding else {
                    panic!()
                };
                let mut fields = map.to_vec();
                fields.retain(|e| {
                    e.key
                        != ScVal::Symbol(ScSymbol(b"contract_version".to_vec().try_into().unwrap()))
                });
                *map = fields.try_into().unwrap();
                if let Some(version) = &self.binding_contract_version {
                    replace_field(&mut binding, "contract_version", version.clone());
                }
                return Ok(
                    json!({"results":[{"xdr":binding.to_xdr_base64(Limits::none()).unwrap()}]}),
                );
            }
            self.calls
                .lock()
                .unwrap()
                .push((function.clone(), call.args.to_vec()));
            if function == "balance" {
                return Ok(
                    json!({"results":[{"xdr":ScVal::I128(Int128Parts{hi:(self.balance>>64) as i64,lo:self.balance as u64}).to_xdr_base64(Limits::none()).unwrap()}]}),
                );
            }
            // The contract calls require_auth on the current owner and, for an owner
            // handoff through deploy_policy, also on the new owner.
            let mut required = vec![address(&self.base.config.owner)?];
            if function == "deploy_policy" {
                let ScVal::Map(Some(fields)) = &call.args[0] else {
                    panic!()
                };
                let owner = fields
                    .iter()
                    .find(|e| {
                        e.key == ScVal::Symbol(ScSymbol(b"owner".to_vec().try_into().unwrap()))
                    })
                    .unwrap();
                let ScVal::Address(next_owner) = &owner.val else {
                    panic!()
                };
                if address_text(next_owner)? != self.base.config.owner {
                    required.push(next_owner.clone());
                }
            }
            let mut auth = match rpc_auth(&params, &envelope.tx, &required) {
                Ok(auth) => auth,
                Err(error) => return Ok(json!({ "error": error })),
            };
            if self.bad_auth {
                auth[0].root_invocation.sub_invocations =
                    vec![auth[0].root_invocation.clone()].try_into().unwrap();
            }
            if self.address_v2 {
                for entry in &mut auth {
                    if let SorobanCredentials::Address(c) = &entry.credentials {
                        entry.credentials = SorobanCredentials::AddressV2(c.clone());
                    }
                }
            }
            // Enforce mode also verifies signatures, so it reports a higher resource fee.
            let fee: i64 = if params["authMode"] == "enforce" {
                1500
            } else {
                1000
            };
            return Ok(
                json!({"minResourceFee":fee.to_string(),"transactionData":SorobanTransactionData{resource_fee:fee,..Default::default()}.to_xdr_base64(Limits::none()).unwrap(),"results":[{"xdr":ScVal::Void.to_xdr_base64(Limits::none()).unwrap(),"auth":auth.iter().map(|a|a.to_xdr_base64(Limits::none()).unwrap()).collect::<Vec<_>>()}]}),
            );
        }
        self.base.call(method, params)
    }
}
fn admin_fixture(
    state_contract_version: u32,
    binding_contract_version: Option<stellar_xdr::ScVal>,
) -> AdminRpc {
    let (config, _, state) = fixture(WalletRoute::PolicyWallet, false);
    AdminRpc {
        base: PolicyWalletAccountRpc {
            config,
            source: state.source,
            paused: true,
        },
        state_contract_version,
        binding_contract_version,
        calls: Mutex::new(vec![]),
        balance: 1234567,
        wrong_owner: false,
        bad_auth: false,
        address_v2: false,
    }
}
#[test]
fn owner_admin_delegates_full_balance_and_versions_without_agent_or_engine_calls() {
    use allowit_policy_sdk::admin::{Admin, DeploymentVersion};
    use allowit_stellar_wallet::admin::OwnerAdmin;
    let rpc = admin_fixture(4, Some(stellar_xdr::ScVal::U32(4)));
    let c = &rpc.base.config;
    let mut facade = Admin::new(OwnerAdmin {
        rpc: &rpc,
        config: c,
        now: 86401,
    });
    let recovered = facade.recover_funds(&c.asset).unwrap();
    assert_eq!(recovered.function, "recover");
    assert_eq!(recovered.deployment_version, 2);
    let calls = rpc.calls.lock().unwrap();
    let (_, args) = calls.last().unwrap();
    assert_eq!(args.len(), 2);
    assert_eq!(
        args[0],
        stellar_xdr::ScVal::Address(address(&c.owner).unwrap())
    );
    assert_eq!(
        args[1],
        stellar_xdr::ScVal::I128(stellar_xdr::Int128Parts { hi: 0, lo: 1234567 })
    );
    drop(calls);
    assert!(facade.recover_funds(&c.wallet).is_err());
    assert!(facade.set_pause(false, DeploymentVersion(2)).is_err());
    assert!(facade.set_pause(false, DeploymentVersion(4)).is_err());
    let paused = facade.set_pause(false, DeploymentVersion(3)).unwrap();
    assert_eq!(paused.function, "set_pause");
    assert_eq!(paused.deployment_version, 3);
    let TransactionEnvelope::Tx(envelope) =
        TransactionEnvelope::from_xdr_base64(&paused.transaction_xdr, Limits::none()).unwrap()
    else {
        panic!()
    };
    assert!(envelope.signatures.is_empty());
    assert_eq!(envelope.tx.fee, 1100);
    assert_eq!(paused.required_authorizers, vec![c.owner.clone()]);
}
#[test]
fn owner_admin_fails_closed_on_release_owner_mismatch_auth_and_empty_balance() {
    use allowit_policy_sdk::admin::{Admin, DeploymentVersion};
    use allowit_stellar_wallet::admin::OwnerAdmin;
    for case in ["release", "owner", "auth", "balance"] {
        let mut rpc = admin_fixture(4, Some(stellar_xdr::ScVal::U32(4)));
        match case {
            "release" => {
                rpc.state_contract_version = 0;
                rpc.binding_contract_version = None
            }
            "owner" => rpc.wrong_owner = true,
            "auth" => rpc.bad_auth = true,
            "balance" => rpc.balance = 0,
            _ => unreachable!(),
        }
        let mut admin = Admin::new(OwnerAdmin {
            rpc: &rpc,
            config: &rpc.base.config,
            now: 86401,
        });
        assert!(
            admin.recover_funds(&rpc.base.config.asset).is_err(),
            "{case}"
        );
        if case != "balance" {
            assert!(
                admin.set_pause(true, DeploymentVersion(3)).is_err(),
                "{case}"
            );
        }
    }
}
#[test]
fn contract_release_and_persisted_counter_names_are_exact() {
    use stellar_xdr::ScVal;
    for (state, binding, works) in [
        (4, Some(ScVal::U32(4)), true),
        (0, Some(ScVal::U32(4)), false),
        (1, Some(ScVal::U32(4)), false),
        (5, Some(ScVal::U32(4)), false),
        (4, None, false),
        (4, Some(ScVal::U32(1)), false),
        (4, Some(ScVal::Bool(true)), false),
    ] {
        let rpc = admin_fixture(state, binding);
        let observed = rpc::trusted_state_for_discovery(&rpc, &rpc.base.config, None);
        assert_eq!(observed.is_ok(), works);
        if let Ok(observed) = observed {
            assert_eq!(observed.state.deployment_version, 2);
            assert_eq!(observed.state.contract_version, Some(CONTRACT_VERSION));
        }
    }
    let (_, _, mut old) = fixture(WalletRoute::PolicyWallet, false);
    old.contract_version = None;
    let mut legacy = serde_json::to_value(&old).unwrap();
    let version = legacy
        .as_object_mut()
        .unwrap()
        .remove("deploymentVersion")
        .unwrap();
    legacy["revision"] = version;
    assert_eq!(
        serde_json::from_value::<TrustedState>(legacy.clone()).unwrap(),
        old
    );
    legacy["deploymentVersion"] = json!(4);
    assert!(serde_json::from_value::<TrustedState>(legacy).is_err());
    for unshipped in [
        "interfaceVersion",
        "contractInterfaceVersion",
        "policyVersion",
        "policyDeploymentVersion",
    ] {
        let mut invalid = serde_json::to_value(&old).unwrap();
        invalid[unshipped] = json!(1);
        assert!(serde_json::from_value::<TrustedState>(invalid).is_err());
    }
}

#[test]
fn full_policy_deployment_uses_one_versioned_owner_flow_and_owner_handoff_authorization() {
    use allowit_policy_sdk::admin::{Admin, DeploymentVersion};
    use allowit_stellar_wallet::admin::{OwnerAdmin, PolicyDeployment};
    for enabled in [false, true] {
        let rpc = admin_fixture(4, Some(stellar_xdr::ScVal::U32(4)));
        let c = &rpc.base.config;
        let next_owner = account_for_seed(&[51; 32]);
        let artifact = PolicyDeployment {
            owner: next_owner.clone(),
            agent: c.agent.clone(),
            server: c.server.clone(),
            source_digest: c.source_digest,
            rules: Vec::new(),
            params: policy::params_from_json(
                &json!({"destinations": [account_for_seed(&[6; 32])], "call_limit": 20}),
                Some(PolicyTier::Simple),
            )
            .unwrap(),
            x402_enabled: enabled,
            wasm_hash: None,
        };
        let mut admin = Admin::new(OwnerAdmin {
            rpc: &rpc,
            config: c,
            now: 86401,
        });
        assert!(
            admin
                .deploy_policy(DeploymentVersion(2), artifact.clone())
                .is_err()
        );
        assert!(
            admin
                .deploy_policy(DeploymentVersion(4), artifact.clone())
                .is_err()
        );
        let prepared = admin.deploy_policy(DeploymentVersion(3), artifact).unwrap();
        assert_eq!(
            prepared.required_authorizers,
            vec![c.owner.clone(), next_owner.clone()]
        );
        // The unsigned transaction carries the recorded entries of both owners.
        let stellar_xdr::TransactionEnvelope::Tx(envelope) =
            stellar_xdr::TransactionEnvelope::from_xdr_base64(
                &prepared.transaction_xdr,
                Limits::none(),
            )
            .unwrap()
        else {
            panic!()
        };
        let OperationBody::InvokeHostFunction(op) = &envelope.tx.operations[0].body else {
            panic!()
        };
        assert_eq!(op.auth.len(), 2);
        assert_eq!(
            op.auth[0].credentials,
            stellar_xdr::SorobanCredentials::SourceAccount
        );
        assert!(matches!(
            &op.auth[1].credentials,
            stellar_xdr::SorobanCredentials::Address(c) if c.address == address(&next_owner).unwrap()
        ));
        assert_eq!(prepared.pending_authorizers, vec![next_owner.clone()]);
        let calls = rpc.calls.lock().unwrap();
        let (name, args) = calls.last().unwrap();
        assert_eq!(name, "deploy_policy");
        assert_eq!(args.len(), 1);
        let stellar_xdr::ScVal::Map(Some(fields)) = &args[0] else {
            panic!()
        };
        assert_eq!(fields.len(), 9);
        assert!(fields.iter().any(|e|matches!(&e.key,stellar_xdr::ScVal::Symbol(k) if k.0.as_slice()==b"deployment_version") && e.val==stellar_xdr::ScVal::U64(3)));
        assert!(fields.iter().any(
            |e| matches!(&e.key,stellar_xdr::ScVal::Symbol(k) if k.0.as_slice()==b"x402_enabled")
                && e.val == stellar_xdr::ScVal::Bool(enabled)
        ));
        assert!(!fields.iter().any(|e| matches!(&e.key,stellar_xdr::ScVal::Symbol(k) if [b"x402_signer".as_slice(),b"policy_version".as_slice()].contains(&k.0.as_slice()))));
        drop(calls);
        owner_handoff_completes_with_the_new_owner_signature(&rpc, &prepared, &op.auth[1]);
    }
}

/// Sign the new owner's recorded entry as a native wallet does.
fn sign_owner_entry(
    network: &str,
    recorded: &stellar_xdr::SorobanAuthorizationEntry,
    seed: &[u8; 32],
    expiration: u32,
) -> stellar_xdr::SorobanAuthorizationEntry {
    use ed25519_dalek::{Signer, SigningKey};
    use stellar_xdr::*;
    let mut entry = recorded.clone();
    let SorobanCredentials::Address(c) = &mut entry.credentials else {
        panic!()
    };
    c.signature_expiration_ledger = expiration;
    let payload = hash(
        HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
            network_id: Hash(network_id(network).unwrap()),
            nonce: c.nonce,
            signature_expiration_ledger: expiration,
            invocation: entry.root_invocation.clone(),
        })
        .to_xdr(Limits::none())
        .unwrap(),
    );
    let key = SigningKey::from_bytes(seed);
    let bytes = |v: &[u8]| ScVal::Bytes(ScBytes(v.to_vec().try_into().unwrap()));
    c.signature = ScVal::Vec(Some(
        vec![sc_map(vec![
            ("public_key", bytes(key.verifying_key().as_bytes())),
            ("signature", bytes(&key.sign(&payload).to_bytes())),
        ])]
        .try_into()
        .unwrap(),
    ));
    entry
}

fn owner_handoff_completes_with_the_new_owner_signature(
    rpc: &AdminRpc,
    prepared: &allowit_stellar_wallet::admin::PreparedOwnerOperation,
    recorded: &stellar_xdr::SorobanAuthorizationEntry,
) {
    use allowit_policy_sdk::admin::{Admin, DeploymentVersion};
    use allowit_stellar_wallet::admin::{OwnerAdmin, PreparedOwnerOperation};
    use stellar_xdr::*;
    let c = &rpc.base.config;
    let owner_admin = OwnerAdmin {
        rpc,
        config: c,
        now: 86401,
    };
    // The latest ledger in the mock is 120.
    let signed = sign_owner_entry(&c.network, recorded, &[51; 32], 130);
    let signed_xdr = signed.to_xdr_base64(Limits::none()).unwrap();
    let rejects = |entry: SorobanAuthorizationEntry| {
        owner_admin
            .complete_owner_handoff(prepared, &entry.to_xdr_base64(Limits::none()).unwrap())
            .is_err()
    };
    assert!(rejects(sign_owner_entry(
        &c.network, recorded, &[52; 32], 130
    )));
    assert!(rejects(sign_owner_entry(
        &c.network, recorded, &[51; 32], 120
    )));
    // A validly signed entry with another nonce or scope is not the recorded entry.
    let mut other = recorded.clone();
    if let SorobanCredentials::Address(credentials) = &mut other.credentials {
        credentials.nonce += 1;
    }
    assert!(rejects(sign_owner_entry(
        &c.network, &other, &[51; 32], 130
    )));
    let mut forged = signed.clone();
    if let SorobanCredentials::Address(credentials) = &mut forged.credentials {
        credentials.signature_expiration_ledger = 131;
    }
    assert!(rejects(forged));
    let stale = OwnerAdmin {
        rpc,
        config: c,
        now: prepared.expires_at,
    };
    assert!(stale.complete_owner_handoff(prepared, &signed_xdr).is_err());
    let mut tampered = prepared.clone();
    tampered.transaction_hash[0] ^= 1;
    assert!(
        owner_admin
            .complete_owner_handoff(&tampered, &signed_xdr)
            .is_err()
    );
    let json = serde_json::to_value(prepared).unwrap();
    assert_eq!(
        serde_json::from_value::<PreparedOwnerOperation>(json).unwrap(),
        *prepared
    );

    let done = owner_admin
        .complete_owner_handoff(prepared, &signed_xdr)
        .unwrap();
    assert!(done.pending_authorizers.is_empty());
    assert_eq!(done.required_authorizers, prepared.required_authorizers);
    assert_ne!(done.transaction_hash, prepared.transaction_hash);
    let TransactionEnvelope::Tx(envelope) =
        TransactionEnvelope::from_xdr_base64(&done.transaction_xdr, Limits::none()).unwrap()
    else {
        panic!()
    };
    assert!(envelope.signatures.is_empty());
    // Fee and resources come from the enforce-mode simulation of the signed entry.
    assert_eq!(envelope.tx.fee, 1600);
    let TransactionExt::V1(data) = &envelope.tx.ext else {
        panic!()
    };
    assert_eq!(data.resource_fee, 1500);
    let OperationBody::InvokeHostFunction(op) = &envelope.tx.operations[0].body else {
        panic!()
    };
    assert_eq!(op.auth[0].credentials, SorobanCredentials::SourceAccount);
    assert_eq!(op.auth[1], signed);
    // The returned hash is the hash of the final transaction the current owner signs.
    let payload = TransactionSignaturePayload {
        network_id: Hash(network_id(&c.network).unwrap()),
        tagged_transaction: TransactionSignaturePayloadTaggedTransaction::Tx(envelope.tx.clone()),
    };
    assert_eq!(
        done.transaction_hash,
        hash(payload.to_xdr(Limits::none()).unwrap())
    );
    assert!(
        owner_admin
            .complete_owner_handoff(&done, &signed_xdr)
            .is_err()
    );
    // An operation without a new owner has nothing to complete.
    let paused = Admin::new(OwnerAdmin {
        rpc,
        config: c,
        now: 86401,
    })
    .set_pause(true, DeploymentVersion(3))
    .unwrap();
    assert!(paused.pending_authorizers.is_empty());
    assert!(
        !serde_json::to_string(&paused)
            .unwrap()
            .contains("pendingAuthorizers")
    );
    assert!(
        owner_admin
            .complete_owner_handoff(&paused, &signed_xdr)
            .is_err()
    );
}
#[test]
fn canonical_main_revision_packet_is_status_only_and_preserves_signed_bytes() {
    let signed: SignedOperation =
        serde_json::from_str(include_str!("fixtures/canonical-main-9682-odc-signed.json")).unwrap();
    validate_retained_signed(&signed).unwrap();
    assert!(
        prepare(
            &signed.prepared.config,
            &signed.prepared.request,
            &signed.prepared.state,
            signed.prepared.created_at,
            signed.prepared.expires_at
        )
        .is_err()
    );
    assert!(sign(&signed.prepared, &[2; 32], signed.prepared.created_at).is_err());
    let mut changed = signed.clone();
    changed.prepared.state.contract_version = Some(99);
    assert!(validate_retained_signed(&changed).is_err());
}

#[test]
fn enabled_x402_rejects_contract_agents() {
    use allowit_policy_sdk::admin::{Admin, DeploymentVersion};
    use allowit_stellar_wallet::admin::{OwnerAdmin, PolicyDeployment};
    let rpc = admin_fixture(4, Some(stellar_xdr::ScVal::U32(4)));
    let c = &rpc.base.config;
    let mut admin = Admin::new(OwnerAdmin {
        rpc: &rpc,
        config: c,
        now: 86401,
    });
    let artifact = PolicyDeployment {
        owner: c.owner.clone(),
        agent: c.wallet.clone(),
        server: c.server.clone(),
        source_digest: c.source_digest,
        rules: Vec::new(),
        params: c.params.clone(),
        x402_enabled: true,
        wasm_hash: None,
    };
    assert!(admin.deploy_policy(DeploymentVersion(3), artifact).is_err());
    assert!(rpc.calls.lock().unwrap().is_empty());
}

#[test]
fn explicit_engine_release_query_distinguishes_legacy_absence_from_failures() {
    use stellar_xdr::*;
    struct MetadataRpc {
        response: serde_json::Value,
        network: &'static str,
    }
    impl rpc::Rpc for MetadataRpc {
        fn call(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
            if method == "getNetwork" {
                return Ok(json!({"passphrase": self.network}));
            }
            assert_eq!(method, "simulateTransaction");
            let TransactionEnvelope::Tx(env) = TransactionEnvelope::from_xdr_base64(
                params["transaction"].as_str().unwrap(),
                Limits::none(),
            )
            .unwrap() else {
                panic!()
            };
            let OperationBody::InvokeHostFunction(op) = &env.tx.operations[0].body else {
                panic!()
            };
            let HostFunction::InvokeContract(call) = &op.host_function else {
                panic!()
            };
            assert_eq!(
                call.contract_address,
                address(&Contract([3; 32]).to_string()).unwrap()
            );
            assert_eq!(call.function_name.0.as_slice(), b"engine_version");
            assert!(call.args.is_empty() && op.auth.is_empty() && env.signatures.is_empty());
            Ok(self.response.clone())
        }
    }
    let (c, _, state) = fixture(WalletRoute::PolicyWallet, false);
    let invoke = |response| {
        rpc::checker_version(
            &MetadataRpc {
                response,
                network: "Test SDF Network ; September 2015",
            },
            &c,
            &state.source,
            &Contract([3; 32]).to_string(),
        )
    };
    for (value, expected) in [
        (ScVal::U32(1), Ok(Some(1))),
        (ScVal::U32(7), Ok(Some(7))),
        (ScVal::U32(0), Err(())),
        (ScVal::U64(1), Err(())),
        (ScVal::Bool(true), Err(())),
    ] {
        assert_eq!(
            invoke(json!({"results":[{"xdr":value.to_xdr_base64(Limits::none()).unwrap()}]}))
                .map_err(|_| ()),
            expected
        );
    }
    let event = DiagnosticEvent {
        in_successful_contract_call: false,
        event: ContractEvent {
            ext: ExtensionPoint::V0,
            contract_id: Some(ContractId(Hash([3; 32]))),
            type_: ContractEventType::Diagnostic,
            body: ContractEventBody::V0(ContractEventV0 {
                topics: vec![
                    ScVal::Symbol(ScSymbol(b"error".to_vec().try_into().unwrap())),
                    ScVal::Error(ScError::WasmVm(ScErrorCode::MissingValue)),
                ]
                .try_into()
                .unwrap(),
                data: ScVal::Vec(Some(
                    vec![
                        ScVal::String(ScString(
                            b"trying to invoke non-existent contract function"
                                .to_vec()
                                .try_into()
                                .unwrap(),
                        )),
                        ScVal::Symbol(ScSymbol(b"engine_version".to_vec().try_into().unwrap())),
                    ]
                    .try_into()
                    .unwrap(),
                )),
            }),
        },
    };
    let missing = |event: &DiagnosticEvent| json!({"error":"HostError: Error(WasmVm, MissingValue)","events":[event.to_xdr_base64(Limits::none()).unwrap()]});
    assert_eq!(invoke(missing(&event)).unwrap(), None);
    let mut wrong_contract = event.clone();
    wrong_contract.event.contract_id = Some(ContractId(Hash([9; 32])));
    assert!(invoke(missing(&wrong_contract)).is_err());
    let mut wrong_function = event.clone();
    let ContractEventBody::V0(body) = &mut wrong_function.event.body;
    body.data = ScVal::Void;
    assert!(invoke(missing(&wrong_function)).is_err());
    for response in [
        json!({"error":"HostError: Error(WasmVm, MissingValue)"}),
        json!({"error":"network unavailable"}),
        json!({"error":"HostError: Error(WasmVm, MissingValue)","events":["bad-xdr"]}),
        json!({"results":[]}),
    ] {
        assert!(invoke(response).is_err());
    }
    assert!(
        rpc::checker_version(
            &MetadataRpc {
                response: json!({}),
                network: "wrong network"
            },
            &c,
            &state.source,
            &Contract([3; 32]).to_string(),
        )
        .is_err()
    );
}

struct PreflightRpc {
    base: PolicyWalletAccountRpc,
    request: ExecutionRequest,
    failure: &'static str,
}
impl rpc::Rpc for PreflightRpc {
    fn call(&self, method: &str, params: Value) -> Result<Value> {
        use stellar_xdr::*;
        if method != "simulateTransaction" {
            return self.base.call(method, params);
        }
        let TransactionEnvelope::Tx(env) = TransactionEnvelope::from_xdr_base64(
            params["transaction"].as_str().unwrap(),
            Limits::none(),
        )
        .unwrap() else {
            panic!()
        };
        let OperationBody::InvokeHostFunction(op) = &env.tx.operations[0].body else {
            panic!()
        };
        let HostFunction::InvokeContract(call) = &op.host_function else {
            panic!()
        };
        if call.function_name.0.as_slice() != b"execute" {
            return self.base.call(method, params);
        }
        assert!([json!("enforce"), json!("record")].contains(&params["authMode"]));
        assert!(env.signatures.is_empty());
        if self.failure == "deny" {
            return Ok(json!({"error":"native policy denied"}));
        }
        let c = &self.base.config;
        let transfer = transfer_from_request(c, &self.request)?;
        let receipt = sc_map(vec![
            (
                "operation_id",
                ScVal::Bytes(ScBytes(
                    self.request.operation.nonce.to_vec().try_into().unwrap(),
                )),
            ),
            ("token", ScVal::Address(address(&c.asset)?)),
            ("from", ScVal::Address(address(&c.wallet)?)),
            ("to", ScVal::Address(address(&transfer.recipient)?)),
            (
                "amount",
                ScVal::I128(Int128Parts {
                    hi: 0,
                    lo: if self.failure == "receipt" {
                        1
                    } else {
                        transfer.amount as u64
                    },
                }),
            ),
            ("nonce", ScVal::U64(4)),
            ("deployment_version", ScVal::U64(2)),
        ]);
        let mut auth = match rpc_auth(
            &params,
            &env.tx,
            &[address(&self.base.source.address)?, address(&c.server)?],
        ) {
            Ok(auth) => auth,
            Err(error) => return Ok(json!({ "error": error })),
        };
        if self.failure == "auth" {
            auth[0].root_invocation.sub_invocations =
                vec![auth[0].root_invocation.clone()].try_into().unwrap();
        }
        let mut value = json!({"minResourceFee":"1000","transactionData":SorobanTransactionData{resource_fee:1000,..Default::default()}.to_xdr_base64(Limits::none()).unwrap(),"results":[{"xdr":receipt.to_xdr_base64(Limits::none()).unwrap(),"auth":auth.iter().map(|a|a.to_xdr_base64(Limits::none()).unwrap()).collect::<Vec<_>>()}]});
        if self.failure == "restore" {
            value["restorePreamble"] = json!({"transactionData":"restore"});
        }
        if self.failure == "fee" {
            value["minResourceFee"] = json!("1001");
        }
        if self.failure == "instructions" {
            value["transactionData"] = json!(
                SorobanTransactionData {
                    resource_fee: 1000,
                    resources: SorobanResources {
                        instructions: 1,
                        ..Default::default()
                    },
                    ..Default::default()
                }
                .to_xdr_base64(Limits::none())
                .unwrap()
            );
        }
        Ok(value)
    }
}
fn preflight_fixture() -> PreflightRpc {
    let (mut c, r, s) = fixture(WalletRoute::PolicyWallet, true);
    c.tier = Some(PolicyTier::Custom);
    c.source_digest = c.source_hash;
    PreflightRpc {
        base: PolicyWalletAccountRpc {
            config: c,
            source: s.source,
            paused: false,
        },
        request: r,
        failure: "",
    }
}
#[test]
fn native_preflight_binds_new_signing_and_json_cannot_restore_it() {
    let rpc = preflight_fixture();
    let c = &rpc.base.config;
    let p = rpc::prepare(&rpc, c, &rpc.request, None, 86401, 86700).unwrap();
    assert!(p.native_preflight.is_some());
    let p = server_ready(&p);
    let proof = sign(&p, &[2; 32], 86401).unwrap();
    let signed = authorize(&p, &[proof], 86401).unwrap();
    let saved = serde_json::to_string(&signed).unwrap();
    let restored: SignedOperation = serde_json::from_str(&saved).unwrap();
    assert!(restored.prepared.native_preflight.is_none());
    assert_eq!(restored, signed);
    validate_retained_signed(&restored).unwrap();
    validate_signed(&restored, 86401).unwrap();
    assert!(
        sign(&restored.prepared, &[2; 32], 86401)
            .unwrap_err()
            .contains("preflight")
    );
    for change in ["amount", "expires_at", "source", "spent"] {
        let mut changed = p.clone();
        match change {
            "amount" => changed.request.effect_bounds[0].max_debit = 1u64.into(),
            "expires_at" => changed.expires_at -= 1,
            "source" => changed.config.policy_source.push(' '),
            "spent" => {
                changed
                    .state
                    .policy_state
                    .as_mut()
                    .unwrap()
                    .state
                    .0
                    .insert("counter".into(), PolicyValue::Int(1));
            }
            _ => unreachable!(),
        };
        assert!(sign(&changed, &[2; 32], 86401).is_err(), "{change}");
    }
}
#[test]
fn local_revalidation_preserves_existing_unsigned_identity_and_checks_current_authority() {
    let rpc = preflight_fixture();
    let prepared = rpc::prepare(&rpc, &rpc.base.config, &rpc.request, None, 86401, 86700).unwrap();
    let prepared = server_ready(&prepared);
    let original: PreparedOperation =
        serde_json::from_str(&serde_json::to_string(&prepared).unwrap()).unwrap();
    assert!(original.native_preflight.is_none());
    let validated = rpc::revalidate_prepared(&rpc, &original, 86402).unwrap();
    assert_eq!(validated, original);
    assert_eq!(validated.transaction_xdr, original.transaction_xdr);
    assert_eq!(validated.transaction_hash, original.transaction_hash);
    assert!(validated.native_preflight.is_some());
    sign(&validated, &[2; 32], 86402).unwrap();
    let repeated = stellar_xdr::LedgerKey::Account(stellar_xdr::LedgerKeyAccount {
        account_id: stellar_xdr::AccountId(stellar_xdr::PublicKey::PublicKeyTypeEd25519(
            stellar_xdr::Uint256([2; 32]),
        )),
    });
    let mut resources = SorobanTransactionData {
        resource_fee: 1000,
        ..Default::default()
    };
    resources.resources.footprint.read_only = vec![repeated.clone()].try_into().unwrap();
    resources.resources.footprint.read_write = vec![repeated].try_into().unwrap();
    let overlap =
        attach_simulation(&original, &resources.to_xdr_base64(Limits::none()).unwrap()).unwrap();
    assert!(rpc::revalidate_prepared(&rpc, &overlap, 86402).is_err());
    assert!(rpc::revalidate_prepared(&rpc, &original, 86700).is_err());
    let mut changed = original.clone();
    changed.expires_at -= 1;
    assert!(rpc::revalidate_prepared(&rpc, &changed, 86402).is_err());
    let mut changed = original.clone();
    changed.request.operation.nonce[0] ^= 1;
    assert!(rpc::revalidate_prepared(&rpc, &changed, 86402).is_err());
    let mut changed_rpc = preflight_fixture();
    changed_rpc.base.source.sequence += 1;
    assert!(rpc::revalidate_prepared(&changed_rpc, &original, 86402).is_err());
    for failure in ["deny", "auth", "receipt", "fee", "restore", "instructions"] {
        let mut changed_rpc = preflight_fixture();
        changed_rpc.failure = failure;
        assert!(
            rpc::revalidate_prepared(&changed_rpc, &original, 86402).is_err(),
            "{failure}"
        );
    }
}
#[test]
fn revalidation_keeps_an_exact_hash_preauthorization_when_fresh_resources_are_smaller() {
    // The original packet carries a 1001 stroop resource fee; fresh simulation needs only 1000.
    // The source meets its threshold only with a preauthorization of the original hash.
    let mut rpc = preflight_fixture();
    let p = rpc::prepare(&rpc, &rpc.base.config, &rpc.request, None, 86401, 86700).unwrap();
    let data = SorobanTransactionData {
        resource_fee: 1001,
        ..Default::default()
    }
    .to_xdr_base64(Limits::none())
    .unwrap();
    let mut p = attach_simulation(&p, &data).unwrap();
    let final_hash = server_ready(&p).transaction_hash;
    rpc.base.source.low_threshold = 2;
    rpc.base.source.medium_threshold = 2;
    rpc.base.source.signers.push(AccountSigner {
        key: stellar_strkey::PreAuthTx(final_hash).to_string(),
        weight: 1,
    });
    p.state.source = rpc.base.source.clone();
    let p = server_ready(&p);
    assert_eq!(p.transaction_hash, final_hash);
    sign(&p, &[2; 32], 86401).unwrap();
    let validated = rpc::revalidate_prepared(&rpc, &p, 86402).unwrap();
    assert_eq!(validated.transaction_hash, final_hash);
    assert_eq!(validated.transaction_xdr, p.transaction_xdr);
    sign(&validated, &[2; 32], 86402).unwrap();
    // Without the preauthorization the same original packet cannot meet the threshold.
    let mut locked = rpc;
    locked.base.source.signers.pop();
    let mut stale = p.clone();
    stale.state.source = locked.base.source.clone();
    assert!(rpc::revalidate_prepared(&locked, &stale, 86402).is_err());
}
#[test]
fn native_failure_or_wrong_auth_receipt_fee_and_restore_never_approve() {
    for failure in ["deny", "auth", "receipt", "fee", "restore"] {
        let mut rpc = preflight_fixture();
        rpc.failure = failure;
        assert!(
            rpc::prepare(&rpc, &rpc.base.config, &rpc.request, None, 86401, 86700).is_err(),
            "{failure}"
        );
    }
}
#[test]
fn first_simulation_records_without_auth_entries_and_signed_simulation_enforces() {
    struct Modes {
        rpc: PreflightRpc,
        seen: Mutex<Vec<(Value, usize)>>,
    }
    impl rpc::Rpc for Modes {
        fn call(&self, method: &str, params: Value) -> Result<Value> {
            use stellar_xdr::*;
            if method == "simulateTransaction" {
                let TransactionEnvelope::Tx(env) = TransactionEnvelope::from_xdr_base64(
                    params["transaction"].as_str().unwrap(),
                    Limits::none(),
                )
                .unwrap() else {
                    panic!()
                };
                let OperationBody::InvokeHostFunction(op) = &env.tx.operations[0].body else {
                    panic!()
                };
                let HostFunction::InvokeContract(call) = &op.host_function else {
                    panic!()
                };
                if call.function_name.0.as_slice() == b"execute" {
                    self.seen
                        .lock()
                        .unwrap()
                        .push((params["authMode"].clone(), op.auth.len()));
                }
            }
            self.rpc.call(method, params)
        }
    }
    let modes = Modes {
        rpc: preflight_fixture(),
        seen: Mutex::new(vec![]),
    };
    let c = &modes.rpc.base.config;
    let prepared = rpc::prepare(&modes, c, &modes.rpc.request, None, 86401, 86700).unwrap();
    let signed = authorize_server(&prepared, &[3; 32], 86401, None).unwrap();
    let ready = rpc::simulate(&modes, &signed).unwrap();
    assert!(ready.native_preflight.is_some());
    assert_eq!(
        *modes.seen.lock().unwrap(),
        vec![(json!("record"), 0), (json!("enforce"), 2)]
    );
}
#[test]
fn odc_cannot_authorize_from_forged_classic_zero_usage() {
    let rpc = preflight_fixture();
    let c = &rpc.base.config;
    let mut state = rpc::trusted_state(&rpc, c, None).unwrap();
    state.spent_daily = 0;
    state.spent_total = 0;
    state.spent_day = 1;
    state.calls = 0;
    // Classic usage fields are informational for a policy wallet: the packet still needs native
    // preflight, which reads the contract's own policy state.
    let offline = prepare(c, &rpc.request, &state, 86401, 86700).unwrap();
    assert!(
        sign(&offline, &[2; 32], 86401)
            .unwrap_err()
            .contains("preflight")
    );
    let mut denied = rpc;
    denied.failure = "deny";
    assert!(
        rpc::prepare(
            &denied,
            &denied.base.config,
            &denied.request,
            None,
            86401,
            86700
        )
        .is_err()
    );
}

// Captured by the exact pre-task canonical main9682 library and its pinned dependencies.
// The immutable records are permanently expired and are never regenerated by this test.
#[test]
fn exact_pre_task_records_preserve_request_bytes_hashes_signatures_and_status_recovery() {
    for (encoded, original_request) in [
        (
            include_str!("fixtures/canonical-main-9682-native-signed.json"),
            include_bytes!("fixtures/canonical-main-9682-native-request.json").as_slice(),
        ),
        (
            include_str!("fixtures/canonical-main-9682-odc-signed.json"),
            include_bytes!("fixtures/canonical-main-9682-odc-request.json").as_slice(),
        ),
    ] {
        let signed: SignedOperation = serde_json::from_str(encoded).unwrap();
        assert_eq!(
            serde_json::to_vec(&signed.prepared.request).unwrap(),
            original_request
        );
        assert_eq!(hash(original_request), signed.prepared.request_hash);
        assert_eq!(signed.prepared.expires_at, 86700); // Permanently expired fixture, not a live capability.
        validate_retained_signed(&signed).unwrap();
        let original: Value = serde_json::from_str(encoded).unwrap();
        assert_eq!(
            signed.transaction_xdr,
            original["transactionXdr"].as_str().unwrap()
        );
        assert_eq!(
            signed.prepared.transaction_xdr,
            original["prepared"]["transactionXdr"].as_str().unwrap()
        );
        let rpc = FakeRpc {
            calls: Mutex::new(vec![]),
            signed: signed.clone(),
            fail_send: false,
        };
        assert_eq!(
            rpc::status_by_hash(
                &rpc,
                &signed.prepared.config.network,
                &signed.transaction_hash
            )
            .unwrap(),
            OperationStatus::Confirmed
        );
        assert_eq!(*rpc.calls.lock().unwrap(), vec!["getTransaction"]);
    }
}

#[test]
fn retired_classic_language_cannot_prepare_or_sign_but_retained_bytes_remain_valid() {
    let (mut config, request, state) = fixture(WalletRoute::Native, false);
    config.language = PolicyLanguage::Legacy;
    assert!(
        prepare(&config, &request, &state, 86401, 86700)
            .unwrap_err()
            .contains("Retired policy language")
    );
    let signed: SignedOperation = serde_json::from_str(include_str!(
        "fixtures/canonical-main-9682-native-signed.json"
    ))
    .unwrap();
    validate_retained_signed(&signed).unwrap();
    assert!(
        sign(&signed.prepared, &[2; 32], signed.prepared.created_at)
            .unwrap_err()
            .contains("Retired policy language")
    );
}

/// Install `source` on the fixture wallet as `tier` with `params`.
fn install(c: &mut WalletConfig, tier: PolicyTier, source: &str, params: Value) {
    c.tier = Some(tier);
    c.policy_source = source.into();
    c.source_hash = hash(source);
    c.rules = policy::tier_rules(tier, source).unwrap();
    c.params = policy::params_from_json(&params, Some(tier)).unwrap();
    c.source_digest =
        policy::installed_source_digest(tier, &c.module_digest, &c.asset, &c.rules, source)
            .unwrap();
}
fn preflight_rpc(c: &WalletConfig, r: &ExecutionRequest, s: &TrustedState) -> PreflightRpc {
    PreflightRpc {
        base: PolicyWalletAccountRpc {
            config: c.clone(),
            source: s.source.clone(),
            paused: false,
        },
        request: r.clone(),
        failure: "",
    }
}
const CAPPED: &str = "use allowit::prelude::*;\npub fn execute(ctx: &AllowitContext) -> allowit::Result {\n    allowit::destinations(ctx, &ctx.params[allowit::DESTINATIONS])?;\n    allowit::payment_limit(ctx, &ctx.params[allowit::PAYMENT_LIMIT])?;\n    Ok(())\n}\n";
const SUFFIXED: &str = "use allowit::prelude::*;\npub fn execute(ctx: &AllowitContext) -> allowit::Result {\n    allowit::destinations(ctx, &ctx.params[allowit::DESTINATIONS])?;\n    let cap: i128 = allowit::param(ctx, \"payment_limit\");\n    if ctx.request.amount > cap {\n        return Err(AllowitError::PaymentLimitExceeded);\n    }\n    Ok(())\n}\n";

#[test]
fn simple_service_authorization_evaluates_the_full_policy() {
    let (mut c, r, s) = fixture(WalletRoute::PolicyWallet, true);
    let recipient = account_for_seed(&[6; 32]);
    // A canonical-only source runs in full on the host: a cap below the amount denies early.
    install(
        &mut c,
        PolicyTier::Simple,
        CAPPED,
        json!({"destinations": [recipient], "payment_limit": 1}),
    );
    let rpc = preflight_rpc(&c, &r, &s);
    assert!(
        rpc::prepare(&rpc, &c, &r, None, 86401, 86700)
            .unwrap_err()
            .contains("denied")
    );
    // Another source runs only its onchain part here; the service needs its compiled evaluator.
    install(
        &mut c,
        PolicyTier::Simple,
        SUFFIXED,
        json!({"destinations": [recipient], "payment_limit": 1}),
    );
    let rpc = preflight_rpc(&c, &r, &s);
    let prepared = rpc::prepare(&rpc, &c, &r, None, 86401, 86700).unwrap();
    let usage = rpc::NativeAccounting {
        nonce: prepared.state.nonce,
        deployment_version: prepared.state.deployment_version,
        spent_daily: 0,
        spent_total: 0,
        spent_day: 1,
        calls: 0,
    };
    assert!(
        authorize_server(&prepared, &[3; 32], 86401, None)
            .unwrap_err()
            .contains("compiled evaluator")
    );
    assert!(authorize_server(&prepared, &[3; 32], 86401, Some(usage)).is_err());
    let compiled = |ctx: &allowit::AllowitContext| -> allowit::Result {
        allowit::destinations(ctx, &ctx.params[allowit::DESTINATIONS])?;
        let cap: i128 = allowit::param(ctx, "payment_limit");
        if ctx.request.amount > cap {
            return Err(allowit::AllowitError::PaymentLimitExceeded);
        }
        Ok(())
    };
    assert!(
        authorize_server_with(&prepared, &[3; 32], 86401, &compiled)
            .unwrap_err()
            .contains("PaymentLimitExceeded")
    );
    assert!(sign(&prepared, &[2; 32], 86401).is_err());
    install(
        &mut c,
        PolicyTier::Simple,
        SUFFIXED,
        json!({"destinations": [recipient], "payment_limit": 100_000_000}),
    );
    let rpc = preflight_rpc(&c, &r, &s);
    let prepared = rpc::prepare(&rpc, &c, &r, None, 86401, 86700).unwrap();
    authorize_server_with(&prepared, &[3; 32], 86401, &compiled).unwrap();
}

#[test]
fn selected_implementations_bind_constructor_and_both_authorities() {
    use allowit_stellar_wallet::admin::PolicyConfig;
    for tier in [PolicyTier::Simple, PolicyTier::Common, PolicyTier::Custom] {
        let (mut c, r, s) = fixture(WalletRoute::PolicyWallet, true);
        install(
            &mut c,
            tier,
            CAPPED,
            json!({"destinations": [account_for_seed(&[6; 32])], "payment_limit": 100_000_000}),
        );
        let config = PolicyConfig::for_policy(&c, false).unwrap();
        assert_eq!(config.source_digest, c.source_digest);
        assert_eq!(config.server, c.server);
        assert_eq!(config.params, c.params);
        assert_eq!(
            config.rules,
            if tier == PolicyTier::Common {
                vec!["destinations".to_string(), "payment_limit".to_string()]
            } else {
                vec![]
            }
        );
        if tier == PolicyTier::Custom {
            assert_eq!(config.source_digest, c.source_hash);
        } else {
            assert_ne!(config.source_digest, c.source_hash);
        }
        assert_eq!(config.constructor_args().unwrap().len(), 1);
        let rpc = preflight_rpc(&c, &r, &s);
        let unsigned = rpc::prepare(&rpc, &c, &r, None, 86401, 86700).unwrap();
        assert!(sign(&unsigned, &[2; 32], 86401).is_err());
        let signed = server_ready(&unsigned);
        assert!(authorize(&signed, &[], 86401).is_err());
        assert!(sign(&signed, &[3; 32], 86401).is_err());
        authorize(&signed, &[sign(&signed, &[2; 32], 86401).unwrap()], 86401).unwrap();
    }
}

#[test]
fn common_installed_rules_cannot_omit_or_reorder_authored_checks() {
    struct ChangedRules {
        base: PreflightRpc,
        rules: Vec<&'static str>,
    }
    impl rpc::Rpc for ChangedRules {
        fn call(&self, method: &str, params: Value) -> Result<Value> {
            use stellar_xdr::*;
            let mut response = self.base.call(method, params)?;
            if method == "getLedgerEntries" {
                let raw = response["entries"][0]["xdr"].as_str().unwrap();
                let mut entry = LedgerEntryData::from_xdr_base64(raw, Limits::none()).unwrap();
                if let LedgerEntryData::ContractData(data) = &mut entry {
                    let ScVal::ContractInstance(instance) = &mut data.val else {
                        panic!()
                    };
                    let mut storage = instance.storage.as_ref().unwrap().to_vec();
                    let state = storage.iter_mut().find(|e| e.key == ScVal::U32(0)).unwrap();
                    let ScVal::Map(Some(fields)) = &state.val else {
                        panic!()
                    };
                    let mut fields = fields.to_vec();
                    fields
                        .iter_mut()
                        .find(|e| {
                            e.key == ScVal::Symbol(ScSymbol(b"rules".to_vec().try_into().unwrap()))
                        })
                        .unwrap()
                        .val = ScVal::Vec(Some(
                        self.rules
                            .iter()
                            .map(|name| {
                                ScVal::Vec(Some(
                                    vec![ScVal::Symbol(ScSymbol(
                                        name.as_bytes().to_vec().try_into().unwrap(),
                                    ))]
                                    .try_into()
                                    .unwrap(),
                                ))
                            })
                            .collect::<Vec<_>>()
                            .try_into()
                            .unwrap(),
                    ));
                    state.val = ScVal::Map(Some(fields.try_into().unwrap()));
                    instance.storage = Some(storage.try_into().unwrap());
                    response["entries"][0]["xdr"] =
                        json!(entry.to_xdr_base64(Limits::none()).unwrap());
                }
            }
            Ok(response)
        }
    }
    let (mut c, r, s) = fixture(WalletRoute::PolicyWallet, true);
    install(
        &mut c,
        PolicyTier::Common,
        CAPPED,
        json!({"destinations": [account_for_seed(&[6; 32])], "payment_limit": 100_000_000}),
    );
    for rules in [
        vec![],
        vec!["destinations"],
        vec!["payment_limit", "destinations"],
        vec!["destinations", "destinations"],
    ] {
        let rpc = ChangedRules {
            base: PreflightRpc {
                base: PolicyWalletAccountRpc {
                    config: c.clone(),
                    source: s.source.clone(),
                    paused: false,
                },
                request: r.clone(),
                failure: "",
            },
            rules,
        };
        assert!(
            rpc::prepare(&rpc, &c, &r, None, 86401, 86700)
                .unwrap_err()
                .contains("rules")
        );
    }
}

#[test]
fn policy_wallet_rpc_revalidation_fixture_matches() {
    struct Recorded {
        rpc: PreflightRpc,
        calls: Mutex<Vec<Value>>,
    }
    impl rpc::Rpc for Recorded {
        fn call(&self, method: &str, params: Value) -> Result<Value> {
            let result = self.rpc.call(method, params.clone())?;
            self.calls
                .lock()
                .unwrap()
                .push(json!({"method":method,"params":params,"result":result}));
            Ok(result)
        }
    }
    let rpc = preflight_fixture();
    let prepared = rpc::prepare(&rpc, &rpc.base.config, &rpc.request, None, 86401, 86700).unwrap();
    let prepared = server_ready(&prepared);
    let recorder = Recorded {
        rpc,
        calls: Mutex::new(vec![]),
    };
    let revalidated = rpc::revalidate_prepared(&recorder, &prepared, 86402).unwrap();
    let signed = authorize(
        &revalidated,
        &[sign(&revalidated, &[2; 32], 86402).unwrap()],
        86402,
    )
    .unwrap();
    let fixture =
        json!({"prepared":prepared,"signed":signed,"calls":recorder.calls.into_inner().unwrap()});
    if let Ok(path) = std::env::var("ALLOWIT_TEST_FIXTURE_OUTPUT") {
        std::fs::write(path, serde_json::to_string_pretty(&fixture).unwrap() + "\n").unwrap();
    } else {
        let expected: Value = serde_json::from_str(include_str!(
            "fixtures/stellar-policy-wallet-revalidation-rpc.json"
        ))
        .unwrap();
        assert_eq!(fixture, expected);
    }
}

#[test]
fn policy_wallet_packets_omit_the_lower_bound_and_the_expiry_second() {
    use stellar_xdr::{Limits, Preconditions, ReadXdr, TimeBounds, TimePoint, TransactionEnvelope};
    fn bounds(xdr: &str) -> TimeBounds {
        let TransactionEnvelope::Tx(envelope) =
            TransactionEnvelope::from_xdr_base64(xdr, Limits::none()).unwrap()
        else {
            panic!()
        };
        let Preconditions::Time(bounds) = envelope.tx.cond else {
            panic!()
        };
        bounds
    }
    // A new packet is valid before the next ledger closes and never lands in the expiry second,
    // where the wallet rejects `expires_at <= now` after the fee is charged.
    let rpc = preflight_fixture();
    let prepared = rpc::prepare(&rpc, &rpc.base.config, &rpc.request, None, 86401, 86700).unwrap();
    let prepared = server_ready(&prepared);
    assert_eq!(
        bounds(&prepared.transaction_xdr),
        TimeBounds {
            min_time: TimePoint(0),
            max_time: TimePoint(86699),
        }
    );
    let signed = authorize(
        &prepared,
        &[sign(&prepared, &[2; 32], 86402).unwrap()],
        86402,
    )
    .unwrap();
    validate_signed(&signed, 86402).unwrap();
    // A packet with other bounds is a changed packet.
    let mut changed = prepared.clone();
    changed.expires_at = 86699;
    assert!(validate_retained_prepared(&changed).is_err());
}

#[test]
fn direct_server_account_must_exist_and_authorize_its_current_threshold() {
    struct ServerRpc {
        base: PreflightRpc,
        missing: bool,
    }
    impl rpc::Rpc for ServerRpc {
        fn call(&self, method: &str, params: Value) -> Result<Value> {
            use stellar_xdr::*;
            if method == "getLedgerEntries" {
                let key =
                    LedgerKey::from_xdr_base64(params["keys"][0].as_str().unwrap(), Limits::none())
                        .unwrap();
                if let LedgerKey::Account(account) = key
                    && account.account_id
                        == stellar_xdr::AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
                            allowit_stellar_wallet::account_key(&self.base.base.config.server)?,
                        )))
                {
                    if self.missing {
                        return Ok(json!({"entries":[]}));
                    }
                    let entry = LedgerEntryData::Account(AccountEntry {
                        account_id: account.account_id,
                        thresholds: Thresholds([1, 1, 2, 2]),
                        ..Default::default()
                    });
                    return Ok(
                        json!({"entries":[{"xdr":entry.to_xdr_base64(Limits::none()).unwrap()}]}),
                    );
                }
            }
            self.base.call(method, params)
        }
    }
    for missing in [false, true] {
        let rpc = ServerRpc {
            base: preflight_fixture(),
            missing,
        };
        assert!(
            rpc::prepare(
                &rpc,
                &rpc.base.base.config,
                &rpc.base.request,
                None,
                86401,
                86700
            )
            .is_err()
        );
        assert!(rpc::trusted_state_for_discovery(&rpc, &rpc.base.base.config, None).is_ok());
    }
}

#[test]
fn x402_packet_binds_both_raw_keys_and_the_complete_native_scope() {
    use ed25519_dalek::{Signer, SigningKey};
    use stellar_xdr::*;
    let (c, r, mut state) = fixture(WalletRoute::PolicyWallet, true);
    // Raw x402 keys do not derive authority from a funded G-account or its weights.
    state.source.master_weight = 0;
    state.source.signers.clear();
    let transfer = transfer_from_request(&c, &r).unwrap();
    let entry = SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: address(&c.wallet).unwrap(),
            nonce: 17,
            signature_expiration_ledger: state.ledger + 20,
            signature: ScVal::Void,
        }),
        root_invocation: SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                contract_address: address(&c.asset).unwrap(),
                function_name: ScSymbol(b"transfer".to_vec().try_into().unwrap()),
                args: vec![
                    ScVal::Address(address(&c.wallet).unwrap()),
                    ScVal::Address(address(&transfer.recipient).unwrap()),
                    ScVal::I128(Int128Parts {
                        hi: 0,
                        lo: transfer.amount as u64,
                    }),
                ]
                .try_into()
                .unwrap(),
            }),
            sub_invocations: VecM::default(),
        },
    };
    let request = x402::SigningRequest {
        config: c,
        request: r,
        state: x402::WalletState {
            custody: state,
            tier: PolicyTier::Simple,
            x402_enabled: true,
            paused: false,
        },
        expires_at: 86700,
        terms: ExecutionTerms::default(),
        authorization_xdr: entry.to_xdr_base64(Limits::none()).unwrap(),
    };
    let digest = x402::signing_digest(&request, 86401).unwrap();
    // The fixture source is canonical-only, so the host runs the full Simple policy.
    assert_eq!(x402::verify_server(&request, 86401, None).unwrap(), digest);
    let agent = SigningKey::from_bytes(&[2; 32]).sign(&digest).to_bytes();
    let server = SigningKey::from_bytes(&[3; 32]).sign(&digest).to_bytes();
    let encoded = x402::assemble(&request, &agent, &server, 86401).unwrap();
    let decoded = SorobanAuthorizationEntry::from_xdr_base64(encoded, Limits::none()).unwrap();
    assert_eq!(decoded.root_invocation, entry.root_invocation);
    let SorobanCredentials::Address(credential) = decoded.credentials else {
        panic!()
    };
    let ScVal::Map(Some(fields)) = credential.signature else {
        panic!()
    };
    assert_eq!(fields.len(), 3);
    for (a, s) in [([0; 64], server), (agent, [0; 64]), (server, agent)] {
        assert!(x402::assemble(&request, &a, &s, 86401).is_err());
    }
    for case in [
        "nonce",
        "version",
        "operation",
        "expires_at",
        "ledger",
        "scope",
        "network",
        "tier",
        "disabled",
        "paused",
        "zero_operation",
    ] {
        let mut changed = request.clone();
        match case {
            "tier" => changed.state.tier = PolicyTier::Common,
            "disabled" => changed.state.x402_enabled = false,
            "paused" => changed.state.paused = true,
            "zero_operation" => changed.request.operation.nonce = [0; 32],
            "nonce" => changed.state.custody.nonce += 1,
            "version" => changed.state.custody.deployment_version += 1,
            "operation" => changed.request.operation.nonce[0] ^= 1,
            "expires_at" => changed.expires_at -= 1,
            "network" => changed.config.network = "stellar:mainnet".into(),
            "ledger" | "scope" => {
                let mut entry = entry.clone();
                if case == "ledger" {
                    let SorobanCredentials::Address(c) = &mut entry.credentials else {
                        panic!()
                    };
                    c.signature_expiration_ledger += 1;
                } else {
                    entry.root_invocation.sub_invocations =
                        vec![entry.root_invocation.clone()].try_into().unwrap();
                }
                changed.authorization_xdr = entry.to_xdr_base64(Limits::none()).unwrap();
            }
            _ => unreachable!(),
        }
        assert!(
            x402::assemble(&changed, &agent, &server, 86401).is_err(),
            "{case}"
        );
    }
    assert!(x402::assemble(&request, &agent, &server, 86700).is_err());
    // A priced request signed before UTC midnight must not settle after it: the kernel checks
    // the expense day against the settlement ledger time.
    let late_now = 2 * 86_400 - 100;
    let mut late = request.clone();
    late.terms.expense = Some(ExpenseBounds {
        gas_units: 100,
        conversion_units: 0,
        spent_units: 100,
        max_fee_stroops: 100,
        observed_ledger: late.state.custody.ledger,
        day: 1,
    });
    for expires_at in [late_now + 200, 2 * 86_400 + 1] {
        late.expires_at = expires_at;
        let error = x402::signing_digest(&late, late_now).unwrap_err();
        assert!(error.contains("cross its UTC expense day"), "{error}");
    }
    // The expiry is exclusive: a request that expires at midnight settles before it.
    for expires_at in [2 * 86_400 - 1, 2 * 86_400] {
        late.expires_at = expires_at;
        if let Err(error) = x402::signing_digest(&late, late_now) {
            assert!(!error.contains("cross its UTC expense day"), "{error}");
        }
    }
}

#[test]
fn x402_server_approval_runs_the_full_simple_policy() {
    use stellar_xdr::*;
    let (mut c, r, state) = fixture(WalletRoute::PolicyWallet, true);
    let recipient = account_for_seed(&[6; 32]);
    let transfer = transfer_from_request(&c, &r).unwrap();
    let entry = SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: address(&c.wallet).unwrap(),
            nonce: 17,
            signature_expiration_ledger: state.ledger + 20,
            signature: ScVal::Void,
        }),
        root_invocation: SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                contract_address: address(&c.asset).unwrap(),
                function_name: ScSymbol(b"transfer".to_vec().try_into().unwrap()),
                args: vec![
                    ScVal::Address(address(&c.wallet).unwrap()),
                    ScVal::Address(address(&transfer.recipient).unwrap()),
                    ScVal::I128(Int128Parts {
                        hi: 0,
                        lo: transfer.amount as u64,
                    }),
                ]
                .try_into()
                .unwrap(),
            }),
            sub_invocations: VecM::default(),
        },
    };
    let compiled = |ctx: &allowit::AllowitContext| -> allowit::Result {
        allowit::destinations(ctx, &ctx.params[allowit::DESTINATIONS])?;
        let cap: i128 = allowit::param(ctx, "payment_limit");
        if ctx.request.amount > cap {
            return Err(allowit::AllowitError::PaymentLimitExceeded);
        }
        Ok(())
    };
    for (cap, approved) in [(1, false), (100_000_000, true)] {
        install(
            &mut c,
            PolicyTier::Simple,
            SUFFIXED,
            json!({"destinations": [recipient], "payment_limit": cap}),
        );
        let mut custody = state.clone();
        custody.source_hash = c.source_hash;
        custody.policy_state = Some(PolicyStateSnapshot {
            params: c.params.clone(),
            state: PolicyParams::default(),
            rules: c.rules.clone(),
            source_digest: c.source_digest,
            x402_enabled: true,
        });
        let request = x402::SigningRequest {
            config: c.clone(),
            request: r.clone(),
            state: x402::WalletState {
                custody,
                tier: PolicyTier::Simple,
                x402_enabled: true,
                paused: false,
            },
            expires_at: 86700,
            terms: ExecutionTerms::default(),
            authorization_xdr: entry.to_xdr_base64(Limits::none()).unwrap(),
        };
        // Encoding the digest is no approval. Only the onchain prefix runs without an evaluator.
        let digest = x402::signing_digest(&request, 86401).unwrap();
        assert!(
            x402::verify_server(&request, 86401, None)
                .unwrap_err()
                .contains("compiled evaluator")
        );
        let verdict = x402::verify_server(&request, 86401, Some(&compiled));
        if approved {
            assert_eq!(verdict.unwrap(), digest);
        } else {
            assert!(verdict.unwrap_err().contains("PaymentLimitExceeded"));
        }
    }
}

#[test]
fn malformed_retained_policy_wallet_envelopes_return_errors() {
    let (c, r, s) = fixture(WalletRoute::PolicyWallet, true);
    let mut p = prepare(&c, &r, &s, 86401, 86700).unwrap();
    let TransactionEnvelope::Tx(mut envelope) =
        TransactionEnvelope::from_xdr_base64(&p.transaction_xdr, Limits::none()).unwrap()
    else {
        panic!()
    };
    envelope.tx.operations = Default::default();
    p.transaction_xdr = TransactionEnvelope::Tx(envelope)
        .to_xdr_base64(Limits::none())
        .unwrap();
    assert!(validate_retained_prepared(&p).is_err());
}

#[test]
fn exact_credit_profile_rejects_issued_asset_burns() {
    for route in [WalletRoute::Native, WalletRoute::PolicyWallet] {
        let (c, mut r, _) = fixture(route, true);
        let issuer = c.asset_issuer.as_ref().unwrap();
        let ExecutionInput::Instructions(ref mut instructions) = r.input else {
            panic!()
        };
        let NativeInstruction::StellarCall { arguments, .. } = &mut instructions[0] else {
            panic!()
        };
        arguments[1] = AbiValue::Account(wf(issuer));
        r.effect_bounds[0].beneficiary = wf(issuer);
        assert!(transfer_from_request(&c, &r).unwrap_err().contains("burn"));
    }
}

#[test]
fn historical_signed_issuer_payment_remains_read_only() {
    let (c, r, state) = fixture(WalletRoute::Native, true);
    let mut prepared = prepare(&c, &r, &state, 86401, 86700).unwrap();
    let issuer = c.asset_issuer.as_ref().unwrap();
    let ExecutionInput::Instructions(ref mut instructions) = prepared.request.input else {
        panic!()
    };
    let NativeInstruction::StellarCall { arguments, .. } = &mut instructions[0] else {
        panic!()
    };
    arguments[1] = AbiValue::Account(wf(issuer));
    prepared.request.effect_bounds[0].beneficiary = wf(issuer);
    let TransactionEnvelope::Tx(mut envelope) =
        TransactionEnvelope::from_xdr_base64(&prepared.transaction_xdr, Limits::none()).unwrap()
    else {
        panic!()
    };
    let mut operations = envelope.tx.operations.to_vec();
    let OperationBody::Payment(payment) = &mut operations[0].body else {
        panic!()
    };
    let stellar_xdr::ScAddress::Account(stellar_xdr::AccountId(
        stellar_xdr::PublicKey::PublicKeyTypeEd25519(key),
    )) = address(issuer).unwrap()
    else {
        panic!()
    };
    payment.destination = stellar_xdr::MuxedAccount::Ed25519(key);
    envelope.tx.operations = operations.try_into().unwrap();
    prepared.transaction_xdr = envelope_to_xdr(envelope);
    // Reconstruct the exact formerly admitted payment and signatures without
    // exposing a preparation path for new issuer-burn operations.
    prepared = native_packet_bounds(prepared, 86401, 86700);
    prepared.request_hash = hash(serde_json::to_vec(&prepared.request).unwrap());
    let signed = retained_native_signed(prepared);
    validate_retained_signed(&signed).unwrap();
    assert!(
        validate_prepared(&signed.prepared, 86401)
            .unwrap_err()
            .contains("burn")
    );
    assert!(
        validate_signed(&signed, 86401)
            .unwrap_err()
            .contains("burn")
    );
    assert!(sign(&signed.prepared, &[2; 32], 86401).is_err());
    assert!(prepare(&c, &signed.prepared.request, &state, 86401, 86700).is_err());
}

#[test]
fn service_auth_nonce_is_scoped_to_the_policy_wallet() {
    use stellar_xdr::*;
    let service_nonce = |contract: [u8; 32]| {
        let (c, r, s) = fixture_with_wallet(WalletRoute::PolicyWallet, false, contract);
        let p = prepare(&c, &r, &s, 86401, 86700).unwrap();
        let TransactionEnvelope::Tx(envelope) =
            TransactionEnvelope::from_xdr_base64(&p.transaction_xdr, Limits::none()).unwrap()
        else {
            panic!()
        };
        let OperationBody::InvokeHostFunction(op) = &envelope.tx.operations[0].body else {
            panic!()
        };
        let SorobanCredentials::Address(credentials) = &op.auth[1].credentials else {
            panic!()
        };
        assert_eq!(credentials.address, address(&c.server).unwrap());
        credentials.nonce
    };
    // Same service signer, operation nonce and deployment version; only the wallet differs.
    // Soroban tracks nonces per signer address, so equal nonces would block the second wallet.
    assert_ne!(service_nonce([4; 32]), service_nonce([14; 32]));
    assert_eq!(service_nonce([4; 32]), service_nonce([4; 32]));
}

#[test]
fn owner_recovery_reads_only_kept_fields_and_pause_only_the_current_layout() {
    use allowit_policy_sdk::admin::{DeployPolicy, DeploymentVersion, RecoverFunds, SetPause};
    use allowit_stellar_wallet::admin::{OwnerAdmin, PolicyDeployment};
    let recipient = account_for_seed(&[6; 32]);
    // A policy binding that does not verify, as after an upgrade whose source digest differs:
    // the contract still accepts recover and set_pause, so preparation must too.
    let broken = admin_fixture(4, None);
    let c = &broken.base.config;
    let mut admin = OwnerAdmin {
        rpc: &broken,
        config: c,
        now: 86401,
    };
    assert!(admin.custody().is_err());
    // The pause version reads only what `set_pause` reads.
    assert_eq!(admin.deployment_version().unwrap(), DeploymentVersion(2));
    let artifact = PolicyDeployment {
        owner: c.owner.clone(),
        agent: c.agent.clone(),
        server: c.server.clone(),
        source_digest: c.source_digest,
        rules: Vec::new(),
        params: c.params.clone(),
        x402_enabled: false,
        wasm_hash: None,
    };
    assert!(
        admin
            .deploy_policy(DeploymentVersion(3), artifact.clone())
            .is_err()
    );
    let recovered = admin.recover_to(&recipient, 5).unwrap();
    assert_eq!(
        (recovered.function.as_str(), recovered.deployment_version),
        ("recover", 2)
    );
    assert_eq!(admin.recover_funds(&c.asset).unwrap().function, "recover");
    assert_eq!(
        admin
            .set_pause(true, DeploymentVersion(3))
            .unwrap()
            .function,
        "set_pause"
    );
    // An earlier readable layout keeps the owner's recovery; set_pause and deploy_policy read
    // the current layout onchain, so they reject.
    for layout in [1, 3] {
        let old = admin_fixture(layout, None);
        let mut admin = OwnerAdmin {
            rpc: &old,
            config: &old.base.config,
            now: 86401,
        };
        assert_eq!(admin.recover_to(&recipient, 5).unwrap().function, "recover");
        assert!(admin.set_pause(true, DeploymentVersion(3)).is_err());
        assert!(admin.deployment_version().is_err());
        assert!(
            admin
                .deploy_policy(DeploymentVersion(3), artifact.clone())
                .is_err()
        );
    }
    // A layout this crate does not know, or no layout, still rejects.
    for layout in [0, 5] {
        let unknown = admin_fixture(layout, None);
        let mut admin = OwnerAdmin {
            rpc: &unknown,
            config: &unknown.base.config,
            now: 86401,
        };
        assert!(admin.recover_to(&recipient, 5).is_err(), "{layout}");
    }
}

#[test]
fn owner_deployment_binds_common_rules_to_the_installed_source_prefix() {
    use allowit_policy_sdk::admin::{DeployPolicy, DeploymentVersion};
    use allowit_stellar_wallet::admin::{OwnerAdmin, PolicyDeployment};
    let rpc = admin_fixture(4, Some(stellar_xdr::ScVal::U32(4)));
    let mut c = rpc.base.config.clone();
    // The installed Common source has the prefix `destinations`.
    c.tier = Some(PolicyTier::Common);
    let mut admin = OwnerAdmin {
        rpc: &rpc,
        config: &c,
        now: 86401,
    };
    // A packet whose digest is derived from other rules matches its own digest but not the
    // source, so it would commit rules that differ from the installation.
    let rules = vec!["lifetime_spending_limit".to_string()];
    let artifact = PolicyDeployment {
        owner: c.owner.clone(),
        agent: c.agent.clone(),
        server: c.server.clone(),
        source_digest: policy::standard_prefix_digest(
            PolicyTier::Common,
            &c.module_digest,
            &c.asset,
            &rules,
        )
        .unwrap(),
        rules,
        params: c.params.clone(),
        x402_enabled: false,
        wasm_hash: None,
    };
    let error = admin
        .deploy_policy(DeploymentVersion(3), artifact)
        .unwrap_err();
    assert!(error.contains("standard prefix derived"), "{error}");
}

#[test]
fn owner_deployment_binds_common_rules_to_a_target_source() {
    use allowit_policy_sdk::admin::{DeployPolicy, DeploymentVersion};
    use allowit_stellar_wallet::admin::{OwnerAdmin, PolicyDeployment};
    // The installed Common wallet binds the prefix `destinations` of its source.
    let mut rpc = admin_fixture(4, Some(stellar_xdr::ScVal::U32(4)));
    let c = &mut rpc.base.config;
    c.tier = Some(PolicyTier::Common);
    c.rules = policy::tier_rules(PolicyTier::Common, &c.policy_source).unwrap();
    assert_eq!(c.rules, ["destinations"]);
    c.source_digest =
        policy::standard_prefix_digest(PolicyTier::Common, &c.module_digest, &c.asset, &c.rules)
            .unwrap();
    validate_config(c).unwrap();
    let c = rpc.base.config.clone();
    let mut admin = OwnerAdmin {
        rpc: &rpc,
        config: &c,
        now: 86401,
    };
    // A rules-only Common update: the target source adds `payment_limit` to the prefix and
    // keeps the installed code.
    let (artifact, _) = PolicyDeployment::for_source(&c, CAPPED, c.params.clone(), false).unwrap();
    assert_eq!(artifact.rules, ["destinations", "payment_limit"]);
    // The installed source does not bind the new prefix.
    let error = admin
        .deploy_policy(DeploymentVersion(3), artifact.clone())
        .unwrap_err();
    assert!(error.contains("standard prefix derived"), "{error}");
    // Rules from another source do not bind the target source.
    let error = admin
        .deploy_policy_source(DeploymentVersion(3), artifact.clone(), PORTABLE)
        .unwrap_err();
    assert!(error.contains("standard prefix derived"), "{error}");
    let prepared = admin
        .deploy_policy_source(DeploymentVersion(3), artifact.clone(), CAPPED)
        .unwrap();
    assert_eq!(prepared.function, "deploy_policy");
    // A Custom wallet binds its compiled source, so a new source needs new code.
    let mut custom = c.clone();
    custom.tier = Some(PolicyTier::Custom);
    let mut admin = OwnerAdmin {
        rpc: &rpc,
        config: &custom,
        now: 86401,
    };
    let artifact = PolicyDeployment {
        source_digest: hash(CAPPED),
        rules: Vec::new(),
        ..artifact
    };
    let error = admin
        .deploy_policy_source(DeploymentVersion(3), artifact, CAPPED)
        .unwrap_err();
    assert!(error.contains("new code"), "{error}");
}

#[test]
fn portable_classic_custody_accepts_only_canonical_only_sources() {
    let (mut c, _, _) = fixture(WalletRoute::Native, false);
    c.language = PolicyLanguage::Portable;
    c.policy_source = PORTABLE.into();
    c.source_hash = hash(PORTABLE);
    validate_config(&c).unwrap();
    // A helper item makes the file more than its prefix: the host cannot run it without a
    // compiled evaluator, which no classic prepare or sign path takes.
    let helper = format!("{PORTABLE}fn helper() -> bool {{ true }}\n");
    let mut other = c.clone();
    other.policy_source = helper.clone();
    other.source_hash = hash(&helper);
    let error = validate_config(&other).unwrap_err();
    assert!(error.contains("canonical-only"), "{error}");
    let mut custom = c.clone();
    custom.params =
        policy::params_from_json(&json!({"supplier_cap": 5}), Some(PolicyTier::Custom)).unwrap();
    let error = validate_config(&custom).unwrap_err();
    assert!(error.contains("canonical params"), "{error}");
}

#[test]
fn owner_preparation_refuses_address_v2_entries_that_the_handoff_cannot_sign() {
    use allowit_policy_sdk::admin::{DeployPolicy, DeploymentVersion};
    use allowit_stellar_wallet::admin::{OwnerAdmin, PolicyDeployment};
    let mut rpc = admin_fixture(4, Some(stellar_xdr::ScVal::U32(4)));
    rpc.address_v2 = true;
    let c = &rpc.base.config;
    let artifact = PolicyDeployment {
        owner: account_for_seed(&[51; 32]),
        agent: c.agent.clone(),
        server: c.server.clone(),
        source_digest: c.source_digest,
        rules: Vec::new(),
        params: c.params.clone(),
        x402_enabled: false,
        wasm_hash: None,
    };
    let mut admin = OwnerAdmin {
        rpc: &rpc,
        config: c,
        now: 86401,
    };
    let error = admin
        .deploy_policy(DeploymentVersion(3), artifact)
        .unwrap_err();
    assert_eq!(error, "Unsupported owner credentials");
}

#[test]
fn caller_owned_signing_runs_only_after_admission_and_verifies_the_exact_hash() {
    use ed25519_dalek::{Signer, SigningKey};
    let (config, request, state) = fixture(WalletRoute::Native, false);
    let prepared = prepare(&config, &request, &state, 86401, 86700).unwrap();
    let signed = sign_with(&prepared, &config.agent, 86401, |hash| {
        assert_eq!(*hash, prepared.transaction_hash);
        Ok(SigningKey::from_bytes(&[2; 32]).sign(hash).to_bytes())
    })
    .unwrap();
    assert_eq!(signed, sign(&prepared, &[2; 32], 86401).unwrap());
    assert!(sign_with(&prepared, &config.agent, 86401, |_| Ok([0; 64])).is_err());
    assert!(
        sign_with(&prepared, &config.owner, 86401, |_| panic!(
            "unauthorized signer reached key capability"
        ))
        .is_err()
    );
    let mut retired = prepared;
    retired.config.language = PolicyLanguage::Legacy;
    assert!(
        sign_with(&retired, &config.agent, 86401, |_| panic!(
            "retired policy reached key capability"
        ))
        .is_err()
    );
}

#[test]
fn chain_receipt_recovers_the_exact_policy_packet_without_new_signing_admission() {
    let fixture: Value = serde_json::from_str(include_str!(
        "fixtures/stellar-policy-wallet-revalidation-rpc.json"
    ))
    .unwrap();
    let signed: SignedOperation = serde_json::from_value(fixture["signed"].clone()).unwrap();
    let chain = FakeRpc {
        calls: Mutex::new(vec![]),
        signed: signed.clone(),
        fail_send: false,
    };
    let receipt = rpc::receipt_by_hash(
        &chain,
        &signed.prepared.config.network,
        &signed.transaction_hash,
    )
    .unwrap()
    .unwrap();
    assert!(validate_prepared(&signed.prepared, 90_000).is_err());
    rpc::validate_settled_policy_packet(&signed, &receipt).unwrap();
    let mut changed = signed.clone();
    changed.transaction_hash[0] ^= 1;
    assert!(rpc::validate_settled_policy_packet(&changed, &receipt).is_err());
    let (config, request, state) = self::fixture(WalletRoute::PolicyWallet, false);
    let unsigned = prepare(&config, &request, &state, 86401, 86700).unwrap();
    let unsigned = SignedOperation {
        transaction_xdr: unsigned.transaction_xdr.clone(),
        transaction_hash: unsigned.transaction_hash,
        prepared: unsigned,
        role_signatures: vec![],
    };
    let chain = FakeRpc {
        calls: Mutex::new(vec![]),
        signed: unsigned.clone(),
        fail_send: false,
    };
    let receipt = rpc::receipt_by_hash(&chain, &config.network, &unsigned.transaction_hash)
        .unwrap()
        .unwrap();
    assert!(
        rpc::validate_settled_policy_packet(&unsigned, &receipt)
            .unwrap_err()
            .contains("unsigned")
    );
}
