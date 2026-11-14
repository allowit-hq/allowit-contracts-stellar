//! Independently assembled owner XDR exercises the caller-intent signing boundary.
use allowit_stellar::owner_intent::*;
use allowit_stellar::*;
use ed25519_dalek::{Signer, SigningKey};
use std::cell::Cell;
use stellar_strkey::Contract;
use stellar_xdr as x;

const NOW: u64 = 1_800_000_000;
const OWNER: [u8; 32] = [11; 32];
const SOURCE: &str = "use allowit::prelude::*;\npub fn execute(ctx: &AllowitContext) -> allowit::Result { allowit::payment_limit(ctx, &ctx.params[allowit::PAYMENT_LIMIT])?; Ok(()) }";
fn owner() -> String {
    account_for_seed(&OWNER)
}
fn account(n: u8) -> String {
    account_for_seed(&[n; 32])
}
fn muxed(value: &str) -> x::MuxedAccount {
    x::MuxedAccount::Ed25519(x::Uint256(account_key(value).unwrap()))
}
fn symbol(value: &str) -> x::ScSymbol {
    x::ScSymbol(value.try_into().unwrap())
}
fn bytes(value: &[u8]) -> x::ScVal {
    x::ScVal::Bytes(x::ScBytes(value.to_vec().try_into().unwrap()))
}
fn scmap(items: Vec<(&str, x::ScVal)>) -> x::ScVal {
    let mut entries: Vec<_> = items
        .into_iter()
        .map(|(k, val)| x::ScMapEntry {
            key: x::ScVal::Symbol(symbol(k)),
            val,
        })
        .collect();
    entries.sort_by(|a, b| a.key.cmp(&b.key));
    x::ScVal::Map(Some(x::ScMap(entries.try_into().unwrap())))
}
fn amount(value: i128) -> x::ScVal {
    x::ScVal::I128(x::Int128Parts {
        hi: (value >> 64) as i64,
        lo: value as u64,
    })
}
fn hash_tx(network: &str, tx: &x::Transaction) -> [u8; 32] {
    hash(
        xdr(&x::TransactionSignaturePayload {
            network_id: x::Hash(network_id(network).unwrap()),
            tagged_transaction: x::TransactionSignaturePayloadTaggedTransaction::Tx(tx.clone()),
        })
        .and_then(|v| {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD
                .decode(v)
                .map_err(|e| e.to_string())
        })
        .unwrap(),
    )
}
fn envelope(packet: &OwnerTransaction) -> x::TransactionV1Envelope {
    let x::TransactionEnvelope::Tx(envelope) = read(&packet.transaction_xdr).unwrap() else {
        panic!("fixture v1")
    };
    envelope
}
fn retain_tx(packet: &mut OwnerTransaction, env: x::TransactionV1Envelope) {
    packet.transaction_hash = hash_tx(&packet.network, &env.tx);
    packet.transaction_xdr = xdr(&x::TransactionEnvelope::Tx(env)).unwrap();
}
fn modify_tx(packet: &mut OwnerTransaction, f: impl FnOnce(&mut x::Transaction)) {
    let mut env = envelope(packet);
    f(&mut env.tx);
    retain_tx(packet, env);
}
fn modify_host(packet: &mut OwnerTransaction, f: impl FnOnce(&mut x::InvokeHostFunctionOp)) {
    modify_tx(packet, |tx| {
        let mut ops = tx.operations.to_vec();
        let x::OperationBody::InvokeHostFunction(host) = &mut ops[0].body else {
            panic!()
        };
        f(host);
        tx.operations = ops.try_into().unwrap();
    });
}
fn limits() -> OwnerLimits {
    OwnerLimits {
        network: "stellar:testnet".into(),
        owner: owner(),
        next_sequence: 42,
        max_fee_stroops: 10_000,
        valid_until: NOW + 300,
    }
}
fn base(
    host: x::HostFunction,
    auth: Vec<x::SorobanAuthorizationEntry>,
    action: &str,
) -> OwnerTransaction {
    let tx = x::Transaction {
        source_account: muxed(&owner()),
        fee: 1100,
        seq_num: x::SequenceNumber(42),
        cond: x::Preconditions::Time(x::TimeBounds {
            min_time: x::TimePoint(0),
            max_time: x::TimePoint(NOW + 300),
        }),
        memo: x::Memo::None,
        operations: vec![x::Operation {
            source_account: None,
            body: x::OperationBody::InvokeHostFunction(x::InvokeHostFunctionOp {
                host_function: host,
                auth: auth.try_into().unwrap(),
            }),
        }]
        .try_into()
        .unwrap(),
        ext: x::TransactionExt::V1(x::SorobanTransactionData {
            ext: x::SorobanTransactionDataExt::V0,
            resources: x::SorobanResources {
                footprint: x::LedgerFootprint::default(),
                instructions: 100_000,
                disk_read_bytes: 100,
                write_bytes: 100,
            },
            resource_fee: 1000,
        }),
    };
    OwnerTransaction {
        network: "stellar:testnet".into(),
        action: action.into(),
        transaction_xdr: xdr(&x::TransactionEnvelope::Tx(x::TransactionV1Envelope {
            tx: tx.clone(),
            signatures: x::VecM::default(),
        }))
        .unwrap(),
        transaction_hash: hash_tx("stellar:testnet", &tx),
        expires_at: NOW + 300,
    }
}
/// This synthetic Wasm declares the required custody layout; no Wasm execution is claimed.
fn wasm() -> Vec<u8> {
    let mut meta = 0u32.to_be_bytes().to_vec();
    for text in [b"allowit_custody_layout".as_slice(), b"4"] {
        meta.extend((text.len() as u32).to_be_bytes());
        meta.extend(text);
        meta.resize(meta.len().div_ceil(4) * 4, 0);
    }
    let mut section = vec![b"contractmetav0".len() as u8];
    section.extend(b"contractmetav0");
    section.extend(meta);
    let mut wasm = b"\0asm\x01\0\0\0".to_vec();
    wasm.extend([0, section.len() as u8]);
    wasm.extend(section);
    wasm
}
fn upload() -> (OwnerTransaction, ExpectedOwnerIntent) {
    let wasm = wasm();
    let expected = ExpectedOwnerIntent {
        limits: limits(),
        action: OwnerAction::UploadWasm {
            wasm_hash: hash(&wasm),
        },
    };
    (
        base(
            x::HostFunction::UploadContractWasm(wasm.try_into().unwrap()),
            vec![],
            "upload_wasm",
        ),
        expected,
    )
}
fn fund() -> (OwnerTransaction, ExpectedOwnerIntent) {
    let asset = sac_address("stellar:testnet", &x::Asset::Native).unwrap();
    let to = Contract([9; 32]).to_string();
    let call = x::InvokeContractArgs {
        contract_address: address(&asset).unwrap(),
        function_name: symbol("transfer"),
        args: vec![
            x::ScVal::Address(address(&owner()).unwrap()),
            x::ScVal::Address(address(&to).unwrap()),
            amount(500),
        ]
        .try_into()
        .unwrap(),
    };
    let auth = x::SorobanAuthorizationEntry {
        credentials: x::SorobanCredentials::SourceAccount,
        root_invocation: x::SorobanAuthorizedInvocation {
            function: x::SorobanAuthorizedFunction::ContractFn(call.clone()),
            sub_invocations: x::VecM::default(),
        },
    };
    (
        base(x::HostFunction::InvokeContract(call), vec![auth], "fund"),
        ExpectedOwnerIntent {
            limits: limits(),
            action: OwnerAction::Fund {
                asset,
                from: owner(),
                to,
                amount: 500,
            },
        },
    )
}
fn config(tier: PolicyTier, salt: &[u8; 32]) -> WalletConfig {
    let asset = sac_address("stellar:testnet", &x::Asset::Native).unwrap();
    let mut c = WalletConfig {
        network: "stellar:testnet".into(),
        policy_instance: [7; 32],
        wallet: admin::wallet_address("stellar:testnet", &owner(), salt).unwrap(),
        owner: owner(),
        agent: account(12),
        server: account(13),
        route: WalletRoute::PolicyWallet,
        tier: Some(tier),
        language: PolicyLanguage::Portable,
        rules: policy::tier_rules(tier, SOURCE).unwrap(),
        params: PolicyParams::default(),
        source_digest: [0; 32],
        asset,
        asset_symbol: "XLM".into(),
        asset_issuer: None,
        policy_source: SOURCE.into(),
        source_hash: hash(SOURCE),
        module_digest: hash(wasm()),
        max_fee_stroops: 10_000,
    };
    c.params
        .0
        .insert("payment_limit".into(), PolicyValue::Int(500));
    c.source_digest =
        policy::installed_source_digest(tier, &c.module_digest, &c.asset, &c.rules, SOURCE)
            .unwrap();
    c
}
fn create(tier: PolicyTier) -> (OwnerTransaction, ExpectedOwnerIntent) {
    let salt = [8; 32];
    let c = config(tier, &salt);
    let constructor = scmap(vec![
        ("agent", x::ScVal::Address(address(&c.agent).unwrap())),
        ("asset", x::ScVal::Address(address(&c.asset).unwrap())),
        ("owner", x::ScVal::Address(address(&c.owner).unwrap())),
        (
            "params",
            scmap(vec![(
                "payment_limit",
                x::ScVal::Vec(Some(
                    vec![x::ScVal::Symbol(symbol("Int")), amount(500)]
                        .try_into()
                        .unwrap(),
                )),
            )]),
        ),
        ("policy_instance", bytes(&c.policy_instance)),
        (
            "rules",
            x::ScVal::Vec(Some(
                c.rules
                    .iter()
                    .map(|rule| {
                        x::ScVal::Vec(Some(
                            vec![x::ScVal::Symbol(symbol(rule))].try_into().unwrap(),
                        ))
                    })
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap(),
            )),
        ),
        ("server", x::ScVal::Address(address(&c.server).unwrap())),
        ("source_digest", bytes(&c.source_digest)),
        ("x402_enabled", x::ScVal::Bool(false)),
    ]);
    let create = x::CreateContractArgsV2 {
        contract_id_preimage: x::ContractIdPreimage::Address(x::ContractIdPreimageFromAddress {
            address: address(&owner()).unwrap(),
            salt: x::Uint256(salt),
        }),
        executable: x::ContractExecutable::Wasm(x::Hash(c.module_digest)),
        constructor_args: vec![constructor].try_into().unwrap(),
    };
    let child = x::SorobanAuthorizedInvocation {
        function: x::SorobanAuthorizedFunction::ContractFn(x::InvokeContractArgs {
            contract_address: address(&c.wallet).unwrap(),
            function_name: symbol("__constructor"),
            args: create.constructor_args.clone(),
        }),
        sub_invocations: x::VecM::default(),
    };
    let auth = x::SorobanAuthorizationEntry {
        credentials: x::SorobanCredentials::SourceAccount,
        root_invocation: x::SorobanAuthorizedInvocation {
            function: x::SorobanAuthorizedFunction::CreateContractV2HostFn(create.clone()),
            sub_invocations: vec![child].try_into().unwrap(),
        },
    };
    (
        base(
            x::HostFunction::CreateContractV2(create),
            vec![auth],
            "create_wallet",
        ),
        ExpectedOwnerIntent {
            limits: limits(),
            action: OwnerAction::CreateWallet {
                config: Box::new(c),
                salt,
                x402_enabled: false,
            },
        },
    )
}
fn native() -> (OwnerTransaction, ExpectedOwnerIntent) {
    let state = AccountState {
        address: owner(),
        sequence: 41,
        master_weight: 1,
        low_threshold: 0,
        medium_threshold: 0,
        high_threshold: 0,
        signers: vec![],
    };
    let prepared = owner::prepare_native_setup(
        &state,
        &owner::SetupTerms {
            wallet: &account(15),
            agent: &account(12),
            engine: &account(13),
            request_id: "intent-fixture-001",
            network: "stellar:testnet",
            fee_per_operation: 100,
            starting_balance: None,
            trustline: None,
        },
        NOW,
    )
    .unwrap();
    (
        OwnerTransaction {
            network: prepared.network,
            action: "native_setup".into(),
            transaction_xdr: prepared.transaction_xdr,
            transaction_hash: unhex(&prepared.transaction_hash).unwrap(),
            expires_at: prepared.expires_at,
        },
        ExpectedOwnerIntent {
            limits: limits(),
            action: OwnerAction::NativeSetup {
                state,
                wallet: account(15),
                starting_balance: None,
                trustline: None,
                agent: account(12),
                engine: account(13),
                request_id: "intent-fixture-001".into(),
                fee_per_operation: 100,
                created_at: NOW,
            },
        },
    )
}
fn assert_refused(packet: &OwnerTransaction, expected: &ExpectedOwnerIntent, label: &str) {
    let calls = Cell::new(0);
    let result = validate_owner_transaction(packet, expected, NOW).and_then(|proof| {
        proof.sign_with(NOW, |digest| {
            calls.set(calls.get() + 1);
            Ok(SigningKey::from_bytes(&OWNER).sign(digest).to_bytes())
        })
    });
    assert!(result.is_err(), "accepted {label}");
    assert_eq!(calls.get(), 0, "signer called for {label}");
}
#[test]
fn four_owner_intents_sign_only_the_validated_digest_once() {
    for (packet, expected) in [
        upload(),
        fund(),
        create(PolicyTier::Simple),
        create(PolicyTier::Common),
        create(PolicyTier::Custom),
        native(),
    ] {
        let proof = validate_owner_transaction(&packet, &expected, NOW).unwrap();
        assert_eq!(proof.transaction_hash(), packet.transaction_hash);
        assert_eq!(proof.unsigned_xdr(), packet.transaction_xdr);
        let calls = Cell::new(0);
        let signed = proof
            .sign_with(NOW, |digest| {
                calls.set(calls.get() + 1);
                assert_eq!(digest, &packet.transaction_hash);
                Ok(SigningKey::from_bytes(&OWNER).sign(digest).to_bytes())
            })
            .unwrap();
        assert_eq!(calls.get(), 1);
        let x::TransactionEnvelope::Tx(signed) = read(&signed).unwrap() else {
            panic!()
        };
        assert_eq!(signed.tx, envelope(&packet).tx);
        assert_eq!(signed.signatures.len(), 1);
    }
}
type TxMutation = (&'static str, fn(&mut x::Transaction));
#[test]
fn envelope_metadata_and_nonbusiness_fields_cannot_bypass_consent() {
    let (packet, expected) = fund();
    let mutations: [TxMutation; 10] = [
        ("source", |tx| tx.source_account = muxed(&account(14))),
        ("sequence", |tx| tx.seq_num = x::SequenceNumber(43)),
        ("memo", |tx| tx.memo = x::Memo::Hash(x::Hash([9; 32]))),
        ("missing expiry", |tx| tx.cond = x::Preconditions::None),
        ("minimum time", |tx| {
            tx.cond = x::Preconditions::Time(x::TimeBounds {
                min_time: x::TimePoint(1),
                max_time: x::TimePoint(NOW + 300),
            })
        }),
        ("extra operation", |tx| {
            let mut ops = tx.operations.to_vec();
            ops.push(ops[0].clone());
            tx.operations = ops.try_into().unwrap();
        }),
        ("foreign operation source", |tx| {
            let mut ops = tx.operations.to_vec();
            ops[0].source_account = Some(muxed(&account(14)));
            tx.operations = ops.try_into().unwrap();
        }),
        ("fee ceiling", |tx| tx.fee = 10_001),
        ("fee mismatch", |tx| tx.fee = 1101),
        ("no simulation resources", |tx| {
            tx.ext = x::TransactionExt::V0
        }),
    ];
    for (name, mutation) in mutations {
        let mut changed = packet.clone();
        modify_tx(&mut changed, mutation);
        assert_refused(&changed, &expected, name);
    }
    for mutation in [0, 1, 2, 3, 4, 5] {
        let mut p = packet.clone();
        match mutation {
            0 => p.network = "stellar:mainnet".into(),
            1 => p.action = "upload_wasm".into(),
            2 => p.transaction_hash = [1; 32],
            3 => p.expires_at += 1,
            4 => p.transaction_xdr = "malformed".into(),
            _ => p.transaction_xdr = "A".repeat(2_097_153),
        }
        assert_refused(&p, &expected, "metadata");
    }
    for expiry in [NOW, NOW + 301, u64::MAX] {
        let mut p = packet.clone();
        p.expires_at = expiry;
        modify_tx(&mut p, |tx| {
            tx.cond = x::Preconditions::Time(x::TimeBounds {
                min_time: x::TimePoint(0),
                max_time: x::TimePoint(expiry),
            })
        });
        assert_refused(&p, &expected, "expiry");
    }
    let mut p = packet.clone();
    let mut signed = envelope(&p);
    signed.signatures = vec![x::DecoratedSignature {
        hint: x::SignatureHint([0; 4]),
        signature: x::Signature(vec![0; 64].try_into().unwrap()),
    }]
    .try_into()
    .unwrap();
    retain_tx(&mut p, signed);
    assert_refused(&p, &expected, "already signed");
    let mut p = packet.clone();
    p.transaction_xdr = xdr(&x::TransactionEnvelope::TxFeeBump(
        x::FeeBumpTransactionEnvelope {
            tx: x::FeeBumpTransaction {
                fee_source: muxed(&owner()),
                fee: 1200,
                inner_tx: x::FeeBumpTransactionInnerTx::Tx(envelope(&packet)),
                ext: x::FeeBumpTransactionExt::V0,
            },
            signatures: x::VecM::default(),
        },
    ))
    .unwrap();
    assert_refused(&p, &expected, "fee bump");
    let mut p = packet;
    modify_tx(&mut p, |tx| {
        let x::TransactionExt::V1(data) = &mut tx.ext else {
            panic!()
        };
        data.resource_fee = -1;
    });
    assert_refused(&p, &expected, "negative resource fee");
}
#[test]
fn upload_and_funding_business_values_and_auth_are_exact() {
    let (packet, expected) = upload();
    let mut p = packet.clone();
    modify_host(&mut p, |host| {
        let x::HostFunction::UploadContractWasm(code) = &mut host.host_function else {
            panic!()
        };
        let mut altered = code.to_vec();
        altered.push(0);
        *code = altered.try_into().unwrap();
    });
    assert_refused(&p, &expected, "upload hash");
    let mut p = packet;
    modify_host(&mut p, |host| {
        host.auth = vec![x::SorobanAuthorizationEntry::default()]
            .try_into()
            .unwrap()
    });
    assert_refused(&p, &expected, "upload hidden auth");
    let (packet, expected) = fund();
    for field in 0..5 {
        let mut p = packet.clone();
        modify_host(&mut p, |host| {
            let x::HostFunction::InvokeContract(call) = &mut host.host_function else {
                panic!()
            };
            match field {
                0 => call.contract_address = address(&Contract([7; 32]).to_string()).unwrap(),
                1 => call.function_name = symbol("approve"),
                _ => {
                    let mut args = call.args.to_vec();
                    args[field - 2] = if field == 4 {
                        amount(501)
                    } else {
                        x::ScVal::Address(address(&account(14)).unwrap())
                    };
                    call.args = args.try_into().unwrap();
                }
            }
            // An internally consistent RPC packet must still be checked against the caller's
            // selected transfer. Auth agreement alone cannot establish owner consent.
            let mut auth = host.auth.to_vec();
            auth[0].root_invocation.function =
                x::SorobanAuthorizedFunction::ContractFn(call.clone());
            host.auth = auth.try_into().unwrap();
        });
        if field == 4 {
            // The compatibility helper signs by source ownership only. This independently
            // reproduces why an SDK must use the new expected-intent boundary instead.
            assert!(
                admin::sign_owner_transaction("stellar:testnet", &p.transaction_xdr, &OWNER)
                    .is_ok()
            );
        }
        assert_refused(&p, &expected, "fund business field");
    }
    for mode in 0..5 {
        let mut p = packet.clone();
        modify_host(&mut p, |host| {
            let mut auth = host.auth.to_vec();
            match mode {
                0 => auth.clear(),
                1 => auth.push(auth[0].clone()),
                2 => {
                    let mut children = auth[0].root_invocation.sub_invocations.to_vec();
                    children.push(auth[0].root_invocation.clone());
                    auth[0].root_invocation.sub_invocations = children.try_into().unwrap();
                }
                3 => {
                    auth[0].credentials =
                        x::SorobanCredentials::Address(x::SorobanAddressCredentials {
                            address: address(&owner()).unwrap(),
                            nonce: 0,
                            signature_expiration_ledger: 100,
                            signature: x::ScVal::Void,
                        })
                }
                _ => {
                    let x::SorobanAuthorizedFunction::ContractFn(call) =
                        &mut auth[0].root_invocation.function
                    else {
                        panic!()
                    };
                    call.function_name = symbol("approve");
                }
            }
            host.auth = auth.try_into().unwrap();
        });
        assert_refused(&p, &expected, "fund auth scope");
    }
}
fn replace_constructor_field(packet: &mut OwnerTransaction, key: &str, value: x::ScVal) {
    modify_host(packet, |host| {
        let x::HostFunction::CreateContractV2(create) = &mut host.host_function else {
            panic!()
        };
        let mut args = create.constructor_args.to_vec();
        let x::ScVal::Map(Some(entries)) = &mut args[0] else {
            panic!()
        };
        let mut values = entries.0.to_vec();
        values
            .iter_mut()
            .find(|e| e.key == x::ScVal::Symbol(symbol(key)))
            .unwrap()
            .val = value;
        entries.0 = values.try_into().unwrap();
        create.constructor_args = args.try_into().unwrap();
        // Make the complete auth tree internally consistent so only caller-owned intent can refuse it.
        let mut auth = host.auth.to_vec();
        auth[0].root_invocation.function =
            x::SorobanAuthorizedFunction::CreateContractV2HostFn(create.clone());
        let mut children = auth[0].root_invocation.sub_invocations.to_vec();
        let x::SorobanAuthorizedFunction::ContractFn(child) = &mut children[0].function else {
            panic!()
        };
        child.args = create.constructor_args.clone();
        auth[0].root_invocation.sub_invocations = children.try_into().unwrap();
        host.auth = auth.try_into().unwrap();
    });
}
#[test]
fn creation_checks_whole_constructor_target_executable_and_auth_tree() {
    let (packet, expected) = create(PolicyTier::Common);
    for role in ["owner", "agent", "server", "asset"] {
        let mut p = packet.clone();
        replace_constructor_field(
            &mut p,
            role,
            x::ScVal::Address(address(&account(14)).unwrap()),
        );
        assert_refused(&p, &expected, role);
    }
    for (key, value) in [
        ("policy_instance", bytes(&[99; 32])),
        ("source_digest", bytes(&[99; 32])),
        ("params", scmap(vec![("payment_limit", amount(501))])),
        (
            "rules",
            x::ScVal::Vec(Some(
                vec![x::ScVal::Symbol(symbol("call_limit"))]
                    .try_into()
                    .unwrap(),
            )),
        ),
        ("x402_enabled", x::ScVal::Bool(true)),
    ] {
        let mut p = packet.clone();
        replace_constructor_field(&mut p, key, value);
        assert_refused(&p, &expected, key);
    }
    for mode in 0..5 {
        let mut p = packet.clone();
        modify_host(&mut p, |host| {
            let x::HostFunction::CreateContractV2(create) = &mut host.host_function else {
                panic!()
            };
            match mode {
                0 => create.executable = x::ContractExecutable::Wasm(x::Hash([99; 32])),
                1 => {
                    let x::ContractIdPreimage::Address(pre) = &mut create.contract_id_preimage
                    else {
                        panic!()
                    };
                    pre.salt = x::Uint256([99; 32]);
                }
                2 => host.auth = x::VecM::default(),
                3 => {
                    let mut auth = host.auth.to_vec();
                    let mut children = auth[0].root_invocation.sub_invocations.to_vec();
                    let x::SorobanAuthorizedFunction::ContractFn(call) = &mut children[0].function
                    else {
                        panic!()
                    };
                    call.contract_address = address(&Contract([99; 32]).to_string()).unwrap();
                    auth[0].root_invocation.sub_invocations = children.try_into().unwrap();
                    host.auth = auth.try_into().unwrap();
                }
                _ => {
                    let mut auth = host.auth.to_vec();
                    let mut children = auth[0].root_invocation.sub_invocations.to_vec();
                    children.push(children[0].clone());
                    auth[0].root_invocation.sub_invocations = children.try_into().unwrap();
                    host.auth = auth.try_into().unwrap();
                }
            }
        });
        assert_refused(&p, &expected, "create target/auth/code");
    }
}
#[test]
fn native_setup_rebuilds_exact_roles_thresholds_and_request_identity() {
    let (packet, expected) = native();
    validate_owner_transaction(&packet, &expected, NOW).unwrap();
    for mode in 0..8 {
        let mut p = packet.clone();
        modify_tx(&mut p, |tx| {
            let mut ops = tx.operations.to_vec();
            // Operations: create the account, add the owner, add the agent, then add the
            // server and set the thresholds and the weight of the account's own key.
            match mode {
                0 | 1 => {
                    let x::OperationBody::SetOptions(options) = &mut ops[1].body else {
                        panic!()
                    };
                    if mode == 0 {
                        options.signer.as_mut().unwrap().weight = 2;
                    } else {
                        options.signer.as_mut().unwrap().key =
                            x::SignerKey::Ed25519(x::Uint256([99; 32]));
                    }
                }
                2 | 3 => {
                    let x::OperationBody::SetOptions(last) = &mut ops[3].body else {
                        panic!()
                    };
                    if mode == 2 {
                        last.high_threshold = Some(2);
                    } else {
                        // The account's own key keeps authority.
                        last.master_weight = Some(1);
                    }
                }
                4 => {
                    let x::OperationBody::CreateAccount(create) = &mut ops[0].body else {
                        panic!()
                    };
                    create.starting_balance += 1;
                }
                5 => {
                    let x::OperationBody::CreateAccount(create) = &mut ops[0].body else {
                        panic!()
                    };
                    create.destination = fixture_account(7);
                }
                6 => ops[2].source_account = None,
                _ => tx.memo = x::Memo::Hash(x::Hash([99; 32])),
            }
            tx.operations = ops.try_into().unwrap();
        });
        assert_refused(&p, &expected, "native exact reconstruction");
    }
    // An owner account whose key cannot pay alone sets up no wallet with one signature.
    let mut changed = expected.clone();
    let OwnerAction::NativeSetup { state, .. } = &mut changed.action else {
        panic!()
    };
    state.medium_threshold = 2;
    assert_refused(&packet, &changed, "native shared owner account");
    let mut changed = expected.clone();
    let OwnerAction::NativeSetup { wallet, .. } = &mut changed.action else {
        panic!()
    };
    *wallet = account(16);
    assert_refused(&packet, &changed, "native other wallet account");
    let mut changed = expected;
    let OwnerAction::NativeSetup {
        fee_per_operation, ..
    } = &mut changed.action
    else {
        panic!()
    };
    *fee_per_operation = u32::MAX;
    assert_refused(&packet, &changed, "native fee overflow");
}
/// The new account's own key signs its creation once, after the owner. A key of another
/// account never co-signs.
#[test]
fn native_setup_takes_the_owner_signature_and_the_wallet_key_signature() {
    let digest = owner::wallet_derivation_digest("stellar:testnet", &account(12), 0).unwrap();
    let key = || {
        owner::WalletKey::from_signature(&SigningKey::from_bytes(&OWNER).sign(&digest).to_bytes())
    };
    let state = AccountState {
        address: owner(),
        sequence: 41,
        master_weight: 1,
        low_threshold: 0,
        medium_threshold: 0,
        high_threshold: 0,
        signers: vec![],
    };
    let terms = owner::SetupTerms {
        wallet: &key().account(),
        agent: &account(12),
        engine: &account(13),
        request_id: "intent-fixture-002",
        network: "stellar:testnet",
        fee_per_operation: 100,
        starting_balance: None,
        trustline: None,
    };
    let prepared = owner::prepare_native_setup(&state, &terms, NOW).unwrap();
    let expected = ExpectedOwnerIntent {
        limits: limits(),
        action: OwnerAction::NativeSetup {
            state,
            wallet: key().account(),
            agent: account(12),
            engine: account(13),
            request_id: "intent-fixture-002".into(),
            fee_per_operation: 100,
            starting_balance: None,
            trustline: None,
            created_at: NOW,
        },
    };
    let sign = |digest: &[u8; 32]| Ok(SigningKey::from_bytes(&OWNER).sign(digest).to_bytes());
    let signed = validate_native_setup(&prepared, &expected, NOW)
        .unwrap()
        .sign_with_wallet_key(NOW, sign, &key())
        .unwrap();
    let x::TransactionEnvelope::Tx(envelope) = read(&signed).unwrap() else {
        panic!()
    };
    let hash = unhex::<32>(&prepared.transaction_hash).unwrap();
    let [by_owner, by_wallet] = envelope.signatures.as_slice() else {
        panic!("expected the owner signature and the wallet key signature")
    };
    allowit_stellar::signing::verify_digest(&owner(), &hash, by_owner.signature.as_slice())
        .unwrap();
    allowit_stellar::signing::verify_digest(
        &key().account(),
        &hash,
        by_wallet.signature.as_slice(),
    )
    .unwrap();
    let stranger = owner::WalletKey::from_signature(&[7; 64]);
    assert!(
        validate_native_setup(&prepared, &expected, NOW)
            .unwrap()
            .sign_with_wallet_key(NOW, sign, &stranger)
            .is_err()
    );
}
#[test]
fn sealed_proof_rechecks_time_and_verifies_the_returned_owner_signature() {
    let (packet, expected) = fund();
    for wrong in [
        [0; 64],
        SigningKey::from_bytes(&[22; 32])
            .sign(&packet.transaction_hash)
            .to_bytes(),
    ] {
        let calls = Cell::new(0);
        let proof = validate_owner_transaction(&packet, &expected, NOW).unwrap();
        assert!(
            proof
                .sign_with(NOW, |_| {
                    calls.set(calls.get() + 1);
                    Ok(wrong)
                })
                .is_err()
        );
        assert_eq!(calls.get(), 1);
    }
    for time in [NOW - 1, NOW + 300] {
        let calls = Cell::new(0);
        let proof = validate_owner_transaction(&packet, &expected, NOW).unwrap();
        assert!(
            proof
                .sign_with(time, |digest| {
                    calls.set(calls.get() + 1);
                    Ok(SigningKey::from_bytes(&OWNER).sign(digest).to_bytes())
                })
                .is_err()
        );
        assert_eq!(calls.get(), 0);
    }
}

fn assert_validation_refused(result: Result<ValidatedOwnerTransaction>, label: &str) {
    let calls = Cell::new(0);
    let result = result.and_then(|proof| {
        proof.sign_with(NOW, |digest| {
            calls.set(calls.get() + 1);
            Ok(SigningKey::from_bytes(&OWNER).sign(digest).to_bytes())
        })
    });
    assert!(result.is_err(), "accepted {label}");
    assert_eq!(calls.get(), 0, "signer called for {label}");
}
#[test]
fn deployment_and_setup_adapters_validate_all_public_metadata() {
    for (packet, expected) in [upload(), create(PolicyTier::Common)] {
        let (wasm_hash, wallet) = match &expected.action {
            OwnerAction::UploadWasm { wasm_hash } => (*wasm_hash, None),
            OwnerAction::CreateWallet { config, .. } => {
                (config.module_digest, Some(config.wallet.clone()))
            }
            _ => unreachable!(),
        };
        let prepared = admin::PreparedDeployment {
            network: packet.network,
            source: owner(),
            function: packet.action,
            wasm_hash,
            wallet,
            transaction_xdr: packet.transaction_xdr,
            transaction_hash: packet.transaction_hash,
            expires_at: packet.expires_at,
        };
        validate_deployment(&prepared, &expected, NOW).unwrap();
        for mode in 0..8 {
            let mut p = prepared.clone();
            match mode {
                0 => p.source = account(14),
                1 => p.wasm_hash = [99; 32],
                2 => p.wallet = Some(Contract([99; 32]).to_string()),
                3 => p.network = "stellar:mainnet".into(),
                4 => p.function = "fund".into(),
                5 => p.transaction_hash = [99; 32],
                6 => p.expires_at += 1,
                _ => p.transaction_xdr = "malformed".into(),
            }
            assert_validation_refused(
                validate_deployment(&p, &expected, NOW),
                "deployment metadata",
            );
        }
    }
    let (_, expected) = native();
    let OwnerAction::NativeSetup {
        state,
        wallet,
        agent,
        engine,
        request_id,
        fee_per_operation,
        created_at,
        ..
    } = &expected.action
    else {
        unreachable!()
    };
    let prepared = owner::prepare_native_setup(
        state,
        &owner::SetupTerms {
            wallet,
            agent,
            engine,
            request_id,
            network: "stellar:testnet",
            fee_per_operation: *fee_per_operation,
            starting_balance: None,
            trustline: None,
        },
        *created_at,
    )
    .unwrap();
    validate_native_setup(&prepared, &expected, NOW).unwrap();
    for mode in 0..14 {
        let mut p = prepared.clone();
        match mode {
            0 => p.version = 1,
            1 => p.profile.push('x'),
            2 => p.request_id.push('x'),
            3 => p.network = "stellar:mainnet".into(),
            4 => p.owner = account(14),
            5 => p.agent = account(14),
            6 => p.engine = account(14),
            7 => p.sequence = "43".into(),
            8 => p.fee_stroops += 4,
            9 => p.expires_at += 1,
            10 => p.transaction_hash = hex(&[99; 32]),
            11 => p.intent_digest = hex(&[99; 32]),
            12 => p.transaction_xdr = "malformed".into(),
            _ => p.sequence = format!("0{}", p.sequence),
        }
        assert_validation_refused(
            validate_native_setup(&p, &expected, NOW),
            "native public metadata",
        );
    }
}
fn fixture_account(n: u16) -> x::AccountId {
    let mut key = [33; 32];
    key[30..].copy_from_slice(&n.to_be_bytes());
    x::AccountId(x::PublicKey::PublicKeyTypeEd25519(x::Uint256(key)))
}
#[test]
fn simulation_resources_are_bounded_without_becoming_business_intent() {
    let (packet, expected) = fund();
    let allowed = vec![
        x::LedgerKey::Account(x::LedgerKeyAccount {
            account_id: fixture_account(1),
        }),
        x::LedgerKey::Trustline(x::LedgerKeyTrustLine {
            account_id: fixture_account(2),
            asset: x::TrustLineAsset::CreditAlphanum4(x::AlphaNum4 {
                asset_code: x::AssetCode4(*b"USD\0"),
                issuer: fixture_account(3),
            }),
        }),
        x::LedgerKey::ContractData(x::LedgerKeyContractData {
            contract: address(&Contract([33; 32]).to_string()).unwrap(),
            key: x::ScVal::Symbol(symbol("State")),
            durability: x::ContractDataDurability::Persistent,
        }),
        x::LedgerKey::ContractCode(x::LedgerKeyContractCode {
            hash: x::Hash([33; 32]),
        }),
    ];
    let mut valid = packet.clone();
    modify_tx(&mut valid, |tx| {
        let x::TransactionExt::V1(data) = &mut tx.ext else {
            panic!()
        };
        data.resources.footprint.read_only = allowed.clone().try_into().unwrap();
        data.ext = x::SorobanTransactionDataExt::V1(x::SorobanResourcesExtV0 {
            archived_soroban_entries: x::VecM::default(),
        });
    });
    let proof = validate_owner_transaction(&valid, &expected, NOW).unwrap();
    let signed = proof
        .sign_with(NOW, |digest| {
            Ok(SigningKey::from_bytes(&OWNER).sign(digest).to_bytes())
        })
        .unwrap();
    let x::TransactionEnvelope::Tx(signed) = read(&signed).unwrap() else {
        panic!()
    };
    assert_eq!(signed.tx, envelope(&valid).tx);
    for mode in 0..5 {
        let mut p = valid.clone();
        modify_tx(&mut p, |tx| {
            let x::TransactionExt::V1(data) = &mut tx.ext else {
                panic!()
            };
            match mode {
                0 => {
                    data.resources.footprint.read_write =
                        vec![allowed[0].clone()].try_into().unwrap()
                }
                1 => {
                    data.resources.footprint.read_only = vec![x::LedgerKey::ConfigSetting(
                        x::LedgerKeyConfigSetting::default(),
                    )]
                    .try_into()
                    .unwrap()
                }
                2 => {
                    data.resources.footprint.read_only = vec![x::LedgerKey::Ttl(x::LedgerKeyTtl {
                        key_hash: x::Hash([33; 32]),
                    })]
                    .try_into()
                    .unwrap()
                }
                3 => {
                    data.resources.footprint.read_only = (0..257)
                        .map(|n| {
                            x::LedgerKey::Account(x::LedgerKeyAccount {
                                account_id: fixture_account(n),
                            })
                        })
                        .collect::<Vec<_>>()
                        .try_into()
                        .unwrap()
                }
                _ => {
                    data.ext = x::SorobanTransactionDataExt::V1(x::SorobanResourcesExtV0 {
                        archived_soroban_entries: vec![0].try_into().unwrap(),
                    })
                }
            }
        });
        assert_refused(&p, &expected, "resource scope");
    }
    assert_validation_refused(
        validate_owner_transaction(&packet, &expected, u64::MAX),
        "validity overflow",
    );
}

fn extend() -> (OwnerTransaction, ExpectedOwnerIntent) {
    let (mut packet, _) = fund();
    packet.action = "extend".into();
    let wallet = Contract([9; 32]).to_string();
    let code = hash(wasm());
    modify_tx(&mut packet, |tx| {
        tx.operations = vec![x::Operation {
            source_account: None,
            body: x::OperationBody::ExtendFootprintTtl(x::ExtendFootprintTtlOp {
                ext: x::ExtensionPoint::V0,
                extend_to: 999,
            }),
        }]
        .try_into()
        .unwrap();
        let x::TransactionExt::V1(data) = &mut tx.ext else {
            panic!()
        };
        data.resources.footprint = x::LedgerFootprint {
            read_only: vec![
                x::LedgerKey::ContractData(x::LedgerKeyContractData {
                    contract: address(&wallet).unwrap(),
                    key: x::ScVal::LedgerKeyContractInstance,
                    durability: x::ContractDataDurability::Persistent,
                }),
                x::LedgerKey::ContractCode(x::LedgerKeyContractCode {
                    hash: x::Hash(code),
                }),
            ]
            .try_into()
            .unwrap(),
            read_write: Default::default(),
        };
    });
    (
        packet,
        ExpectedOwnerIntent {
            limits: limits(),
            action: OwnerAction::Extend {
                wallet,
                wasm_hash: code,
                extend_to: 999,
            },
        },
    )
}
#[test]
fn exact_relative_wallet_lifetime_extension_signs_only_the_selected_two_entries() {
    let (packet, expected) = extend();
    let calls = Cell::new(0);
    let proof = validate_owner_transaction(&packet, &expected, NOW).unwrap();
    let signed = proof
        .sign_with(NOW, |digest| {
            calls.set(calls.get() + 1);
            Ok(SigningKey::from_bytes(&OWNER).sign(digest).to_bytes())
        })
        .unwrap();
    assert_eq!(calls.get(), 1);
    assert_eq!(
        rpc::signed_transaction_hash("stellar:testnet", &signed).unwrap(),
        packet.transaction_hash
    );
}
#[test]
fn lifetime_target_and_footprint_mutations_fail_before_signing() {
    for variant in 0..8 {
        let (mut packet, expected) = extend();
        modify_tx(&mut packet, |tx| {
            match variant {
                0 => {
                    let mut operations = tx.operations.to_vec();
                    let x::OperationBody::ExtendFootprintTtl(op) = &mut operations[0].body else {
                        panic!()
                    };
                    op.extend_to = 1119;
                    tx.operations = operations.try_into().unwrap();
                } // absolute ledger mistaken for relative target
                1 => {
                    let x::TransactionExt::V1(data) = &mut tx.ext else {
                        panic!()
                    };
                    let mut keys = data.resources.footprint.read_only.to_vec();
                    keys[0] = x::LedgerKey::ContractData(x::LedgerKeyContractData {
                        contract: address(&Contract([8; 32]).to_string()).unwrap(),
                        key: x::ScVal::LedgerKeyContractInstance,
                        durability: x::ContractDataDurability::Persistent,
                    });
                    data.resources.footprint.read_only = keys.try_into().unwrap();
                }
                2 => {
                    let x::TransactionExt::V1(data) = &mut tx.ext else {
                        panic!()
                    };
                    let mut keys = data.resources.footprint.read_only.to_vec();
                    keys[1] = x::LedgerKey::ContractCode(x::LedgerKeyContractCode {
                        hash: x::Hash([8; 32]),
                    });
                    data.resources.footprint.read_only = keys.try_into().unwrap();
                }
                3 => {
                    let x::TransactionExt::V1(data) = &mut tx.ext else {
                        panic!()
                    };
                    data.resources.footprint.read_write =
                        vec![data.resources.footprint.read_only[0].clone()]
                            .try_into()
                            .unwrap();
                }
                4 => {
                    let x::TransactionExt::V1(data) = &mut tx.ext else {
                        panic!()
                    };
                    let mut keys = data.resources.footprint.read_only.to_vec();
                    keys.push(x::LedgerKey::Account(x::LedgerKeyAccount {
                        account_id: x::AccountId(x::PublicKey::PublicKeyTypeEd25519(x::Uint256(
                            account_key(&owner()).unwrap(),
                        ))),
                    }));
                    data.resources.footprint.read_only = keys.try_into().unwrap();
                }
                5 => {
                    let mut operations = tx.operations.to_vec();
                    operations[0].source_account = Some(muxed(&owner()));
                    tx.operations = operations.try_into().unwrap();
                }
                6 => tx.memo = x::Memo::Id(1),
                _ => {
                    let x::TransactionExt::V1(data) = &mut tx.ext else {
                        panic!()
                    };
                    data.resource_fee += 1;
                }
            }
        });
        assert_refused(&packet, &expected, &format!("lifetime mutation {variant}"));
    }
}
