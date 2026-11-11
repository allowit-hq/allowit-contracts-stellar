//! Deterministic native protocol fixtures for consumer integration tests.
//! This optional module is not a production signing or network API.
pub mod owner;
use crate::workflow::*;
use crate::{
    self as sdk, AccountSigner, AccountState, PROFILE, SignedOperation, TrustedState, WalletConfig,
    WalletRoute, rpc,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde_json::{Value, json};
use stellar_xdr::{self as x, WriteXdr};

pub fn owner_generation_fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../tests/fixtures/provider/stellar-owner-generation.json"
    ))
    .unwrap()
}
pub fn sign_digest(seed: [u8; 32], digest: &[u8; 32]) -> [u8; 64] {
    SigningKey::from_bytes(&seed).sign(digest).to_bytes()
}
pub fn verify_digest(account: &str, digest: &[u8; 32], signature: &[u8]) -> bool {
    let Ok(key) = crate::account_key(account) else {
        return false;
    };
    let Ok(key) = VerifyingKey::from_bytes(&key) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(signature) else {
        return false;
    };
    key.verify_strict(digest, &signature).is_ok()
}
pub fn verify_owner_challenge(account: &str, message: &str, signature: &str) -> bool {
    let Ok(signature) = STANDARD.decode(signature) else {
        return false;
    };
    let mut bytes = b"Stellar Signed Message:\n".to_vec();
    bytes.extend_from_slice(message.as_bytes());
    verify_digest(account, &crate::hash(bytes), &signature)
}
pub fn verify_request_proof(
    proof: &str,
    path: &str,
    canonical_body: &[u8],
    expected_account: &str,
) -> bool {
    let parts: Vec<_> = proof.split('.').collect();
    if parts.len() != 4 || parts[0] != "stellar-proof" || parts[1] != expected_account {
        return false;
    }
    let Ok(signature) = crate::unhex::<64>(parts[3]) else {
        return false;
    };
    let mut bytes = format!("allowit-stellar-request-v1\n{}\n{path}\n", parts[2]).into_bytes();
    bytes.extend_from_slice(canonical_body);
    verify_digest(parts[1], &crate::hash(bytes), &signature)
}
pub fn contract_address(bytes: [u8; 32]) -> String {
    stellar_strkey::Contract(bytes).to_string()
}
pub fn secret_seed(seed: [u8; 32]) -> String {
    crate::signing::LocalSigner::from_entropy(&seed)
        .unwrap()
        .encoded_secret()
        .to_string()
}
pub fn native_signed() -> SignedOperation {
    let old: SignedOperation = serde_json::from_str(include_str!(
        "../../tests/fixtures/provider/canonical-main-9682-native-signed.json"
    ))
    .unwrap();
    let mut config = old.prepared.config;
    config.language = crate::PolicyLanguage::Portable;
    config.policy_source="use allowit::prelude::*; pub fn execute(ctx: &AllowitContext) -> allowit::Result { Ok(()) }".into();
    config.source_hash = crate::hash(&config.policy_source);
    let mut state = old.prepared.state;
    state.source_hash = config.source_hash;
    let prepared = crate::prepare(&config, &old.prepared.request, &state, 86401, 86700).unwrap();
    crate::authorize(
        &prepared,
        &[
            crate::sign(&prepared, &[2; 32], 86401).unwrap(),
            crate::sign(&prepared, &[3; 32], 86401).unwrap(),
        ],
        86401,
    )
    .unwrap()
}
pub fn policy_signed() -> SignedOperation {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/provider/stellar-policy-wallet-revalidation-rpc.json"
    ))
    .unwrap();
    serde_json::from_value(fixture["signed"].clone()).unwrap()
}
pub fn transaction_status(signed: &SignedOperation, success: bool, ledger: u32, fee: i64) -> Value {
    let result = x::TransactionResult {
        fee_charged: fee,
        result: if success {
            x::TransactionResultResult::TxSuccess(Default::default())
        } else {
            x::TransactionResultResult::TxFailed(Default::default())
        },
        ext: x::TransactionResultExt::V0,
    };
    json!({"status":if success{"SUCCESS"}else{"FAILED"},"ledger":ledger,"envelopeXdr":signed.transaction_xdr,"resultXdr":result.to_xdr_base64(x::Limits::none()).unwrap()})
}
pub fn confirmed_payment_receipt(
    signed: &SignedOperation,
    ledger: u32,
    fee: i64,
) -> rpc::VerifiedReceipt {
    let result = x::TransactionResult {
        fee_charged: fee,
        result: x::TransactionResultResult::TxSuccess(
            vec![x::OperationResult::OpInner(x::OperationResultTr::Payment(
                x::PaymentResult::Success,
            ))]
            .try_into()
            .unwrap(),
        ),
        ext: x::TransactionResultExt::V0,
    };
    rpc::VerifiedReceipt {
        transaction_hash: signed.transaction_hash,
        status: crate::OperationStatus::Confirmed,
        ledger,
        envelope_xdr: signed.transaction_xdr.clone(),
        result_xdr: result.to_xdr_base64(x::Limits::none()).unwrap(),
    }
}

fn fixture_account(value: &str) -> AccountId {
    AccountId {
        chain: Chain::Stellar,
        kind: AccountKind::Wallet,
        address: crate::account_key(value).unwrap(),
    }
}
fn request_nonce(policy_id: &str, request_id: &str) -> [u8; 32] {
    let mut bytes = b"allowit-workflow-operation-v1\0".to_vec();
    bytes.extend(policy_id.as_bytes());
    bytes.push(0);
    bytes.extend(request_id.as_bytes());
    crate::hash(bytes)
}
pub fn portable_descriptor(config: &mut crate::WalletConfig) -> Value {
    use crate::{self as sdk, PolicyTier, WalletRoute};
    let shape = sdk::policy::source_shape(&config.policy_source).unwrap();
    let tier = if config.tier == Some(PolicyTier::Custom) {
        "custom"
    } else {
        "standard"
    };
    let rules = if tier == "standard" {
        shape.prefix.clone()
    } else {
        vec![]
    };
    let params_hash =
        allowit_core::digest(&serde_json_canonicalizer::to_vec(&config.params).unwrap());
    let identity = serde_json::json!({"language":"allowit-portable-v1","tier":tier,"rules":rules,"sourceHash":sdk::hex(&config.source_hash),"paramsHash":params_hash});
    if config.route == WalletRoute::Native {
        config.module_digest = sdk::unhex(&allowit_core::digest(
            &serde_json_canonicalizer::to_vec(&identity).unwrap(),
        ))
        .unwrap();
    }
    serde_json::json!({"language":"allowit-portable-v1","sourceHash":sdk::hex(&config.source_hash),"tier":tier,"rules":rules,"params":config.params,"paramsHash":params_hash,
        "asset":{"symbol":config.asset_symbol,"address":config.asset,"decimals":7},"unresolved":[],
        "build":{"prefix":shape.prefix,"writesState":shape.writes_state,"libraryRevision":"6aa4235e6229e18d1f9780a6a9fdf80aceb0f348","attempts":1}})
}
pub fn agent_fixture(
    policy_id: &str,
    request_id: &str,
    now: u64,
) -> (WalletConfig, ExecutionRequest, TrustedState, u64) {
    let owner = sdk::account_for_seed(&[1; 32]);
    let agent = sdk::account_for_seed(&[2; 32]);
    let engine = sdk::account_for_seed(&[3; 32]);
    let source = "use allowit::prelude::*; pub fn execute(ctx: &AllowitContext) -> allowit::Result { Ok(()) }".to_string();
    let mut c = WalletConfig {
        network: "stellar:testnet".into(),
        policy_instance: [7; 32],
        wallet: owner.clone(),
        owner: owner.clone(),
        agent: agent.clone(),
        server: engine.clone(),
        route: WalletRoute::Native,
        tier: None,
        language: sdk::PolicyLanguage::Portable,
        rules: vec![],
        params: Default::default(),
        source_digest: [0; 32],
        asset: String::new(),
        asset_symbol: "XLM".into(),
        asset_issuer: None,
        source_hash: sdk::hash(&source),
        policy_source: source,
        module_digest: [5; 32],
        max_fee_stroops: 50000,
    };
    c.asset = sdk::sac_address(&c.network, &sdk::asset_xdr(&c).unwrap()).unwrap();
    portable_descriptor(&mut c);
    let asset = WorkflowAsset::Native {
        chain: Chain::Stellar,
        network: sdk::network_id(&c.network).unwrap(),
    };
    let r = ExecutionRequest {
        operation: OperationRef {
            policy_instance: c.policy_instance,
            nonce: request_nonce(policy_id, request_id),
        },
        input: ExecutionInput::Instructions(vec![NativeInstruction::StellarNativeTransfer {
            source: fixture_account(&owner),
            destination: fixture_account(&sdk::account_for_seed(&[6; 32])),
            stroops: 1_000_000,
        }]),
        effect_bounds: vec![WorkflowEffectBound {
            asset: asset.clone(),
            source: fixture_account(&owner),
            beneficiary: fixture_account(&sdk::account_for_seed(&[6; 32])),
            max_debit: 1_000_000u64.into(),
            min_credit: 1_000_000u64.into(),
            max_burn: 0u64.into(),
        }],
        fee_bounds: Some(vec![WorkflowFeeBound {
            payer: fixture_account(&owner),
            asset,
            max_fee: 50000u64.into(),
        }]),
        evidence: vec![],
    };
    let s = TrustedState {
        contract_version: None,
        policy_state: None,
        source: AccountState {
            address: owner.clone(),
            sequence: 40,
            master_weight: 3,
            low_threshold: 2,
            medium_threshold: 2,
            high_threshold: 3,
            signers: vec![
                AccountSigner {
                    key: agent.clone(),
                    weight: 1,
                },
                AccountSigner {
                    key: engine.clone(),
                    weight: 1,
                },
            ],
        },
        nonce: 9,
        deployment_version: 4,
        spent_daily: 0,
        spent_total: 0,
        spent_day: now / 86400,
        calls: 0,
        ledger: 100,
        module_digest: c.module_digest,
        source_hash: c.source_hash,
        owner,
        agent,
        server: engine,
        policy_instance: c.policy_instance,
    };
    (c, r, s, now)
}
pub fn public_profile(c: &WalletConfig, policy_id: &str) -> Value {
    let mut value = json!({"version":1,"profile":PROFILE,"network":c.network,"policyId":policy_id,
        "sourceHash":sdk::hex(&c.source_hash),"irHash":sdk::hex(&[4;32]),
        "moduleDigest":sdk::hex(&c.module_digest),"wallet":c.wallet,"route":c.route,"config":c,
        "endpoints":{"execute":"/api/native/execute","status":"/api/native/execute/status"}});
    if c.language == sdk::PolicyLanguage::Portable {
        let mut checked = c.clone();
        value["portable"] = portable_descriptor(&mut checked);
        assert_eq!(checked.module_digest, c.module_digest);
        value["language"] = json!("allowit-portable-v1");
        value["irHash"] = json!("");
    }
    if c.route == WalletRoute::Native && c.language == sdk::PolicyLanguage::Portable {
        let b = crate::provider::runtime::client::decode_public_bundle(
            &serde_json::to_vec(&value).unwrap(),
        )
        .unwrap();
        let message = b.source_approval_message(1).unwrap();
        let key = sdk::signing::LocalSigner::from_entropy(&[1; 32]).unwrap();
        assert_eq!(key.account(), c.owner);
        value["sourceApproval"] = json!({"revision":1,"signatures":[{"signer":key.account(),"signature":key.sign_digest(&sdk::signing::signed_message_digest(&message)).unwrap()}]});
    }
    value
}
pub fn request_config(route: WalletRoute, usdc: bool) -> WalletConfig {
    let owner = sdk::account_for_seed(&[1; 32]);
    let source = "use allowit::prelude::*; pub fn execute(ctx: &AllowitContext) -> allowit::Result { Ok(()) }".to_string();
    let mut c = WalletConfig {
        network: "stellar:testnet".into(),
        policy_instance: [7; 32],
        wallet: owner.clone(),
        owner,
        agent: sdk::account_for_seed(&[2; 32]),
        server: sdk::account_for_seed(&[3; 32]),
        route: route.clone(),
        tier: (route == WalletRoute::PolicyWallet).then_some(sdk::PolicyTier::Simple),
        language: sdk::PolicyLanguage::Portable,
        rules: vec![],
        params: Default::default(),
        source_digest: [0; 32],
        asset: String::new(),
        asset_symbol: if usdc { "USDC" } else { "XLM" }.into(),
        asset_issuer: usdc.then(|| {
            let tokens = crate::provider::tokens_for("stellar:testnet");
            tokens[1].issuer.unwrap().to_owned()
        }),
        source_hash: sdk::hash(&source),
        policy_source: source,
        module_digest: [5; 32],
        max_fee_stroops: 50_000,
    };
    c.asset = sdk::sac_address(&c.network, &sdk::asset_xdr(&c).unwrap()).unwrap();
    if route == WalletRoute::PolicyWallet {
        c.wallet = vault(0);
        // Policy wallets run portable source with an empty Simple binding.
        let source = "use allowit::prelude::*;\npub fn execute(ctx: &AllowitContext) -> allowit::Result {\n    Ok(())\n}\n";
        c.language = sdk::PolicyLanguage::Portable;
        c.policy_source = source.into();
        c.source_hash = sdk::hash(source);
        c.source_digest = sdk::policy::installed_source_digest(
            sdk::PolicyTier::Simple,
            &c.module_digest,
            &c.asset,
            &[],
            source,
        )
        .unwrap();
    }
    c
}
pub fn vault(n: u8) -> String {
    let asset = sdk::asset_from_identity("VLT", Some(&sdk::account_for_seed(&[20 + n; 32])));
    sdk::sac_address("stellar:testnet", &asset.unwrap()).unwrap()
}
pub fn existing_installation(owner: &str, policy: &Value) -> WalletConfig {
    let fixture: Vec<Value> = serde_json::from_str(include_str!(
        "../../tests/fixtures/provider/stellar-portable-descriptors.json"
    ))
    .unwrap();
    let mut config: crate::WalletConfig =
        serde_json::from_value(fixture[2]["bundle"]["config"].clone()).unwrap();
    let d = &policy["runtime"]["instanceBinding"]["portable"];
    config.owner = owner.into();
    config.agent = crate::account_for_seed(&[12; 32]);
    config.server = crate::account_for_seed(&[13; 32]);
    config.wallet = contract_address([3; 32]);
    config.policy_instance = [7; 32];
    config.module_digest = [44; 32];
    config.asset = d["asset"]["address"].as_str().unwrap().into();
    config.asset_symbol = "USDC".into();
    config.asset_issuer = Some("GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5".into());
    config.policy_source = policy["code"].as_str().unwrap().into();
    config.source_hash = crate::hash(config.policy_source.as_bytes());
    config.params = serde_json::from_value(d["params"].clone()).unwrap();
    config.rules = serde_json::from_value(d["rules"].clone()).unwrap();
    config.tier = Some(crate::PolicyTier::Common);
    config.max_fee_stroops = 5_000_000;
    config.source_digest = crate::policy::standard_prefix_digest(
        crate::PolicyTier::Common,
        &config.module_digest,
        &config.asset,
        &config.rules,
    )
    .unwrap();
    crate::validate_config(&config).unwrap();
    config
}

pub fn portable_descriptors() -> Value {
    serde_json::from_str(include_str!(
        "../../tests/fixtures/provider/stellar-portable-descriptors.json"
    ))
    .unwrap()
}
pub fn portable_approval() -> Value {
    serde_json::from_str(include_str!(
        "../../tests/fixtures/provider/stellar-portable-approval.json"
    ))
    .unwrap()
}
pub fn approval_public_profile(fixture: &Value) -> Value {
    use crate::{self as sdk, WalletConfig, WalletRoute};
    let policy = &fixture["policy"];
    let mut config = WalletConfig {
        network: "stellar:testnet".into(),
        policy_instance: [7; 32],
        wallet: fixture["intent"]["owner"].as_str().unwrap().into(),
        owner: fixture["intent"]["owner"].as_str().unwrap().into(),
        agent: sdk::account_for_seed(&[2; 32]),
        server: sdk::account_for_seed(&[3; 32]),
        route: WalletRoute::Native,
        tier: None,
        language: sdk::PolicyLanguage::Portable,
        rules: vec![],
        params: serde_json::from_value(
            policy["runtime"]["instanceBinding"]["portable"]["params"].clone(),
        )
        .unwrap(),
        source_digest: [0; 32],
        asset: policy["mint"].as_str().unwrap().into(),
        asset_symbol: "XLM".into(),
        asset_issuer: None,
        policy_source: policy["code"].as_str().unwrap().into(),
        source_hash: sdk::unhex(policy["sourceHash"].as_str().unwrap()).unwrap(),
        module_digest: [5; 32],
        max_fee_stroops: 100,
    };
    let portable = portable_descriptor(&mut config);
    json!({"language":"allowit-portable-v1","portable":portable,"version":1,"profile":sdk::PROFILE,"network":config.network,
        "policyId":policy["id"],"sourceHash":policy["sourceHash"],"irHash":policy["irHash"],
        "moduleDigest":sdk::hex(&config.module_digest),"wallet":config.wallet,
        "route":"native","config":config,
        "endpoints":{"execute":"/api/native/execute","status":"/api/native/execute/status"}})
}

pub mod server;

/// Owner source-consent signature fixture. The consumer chooses the signing identity.
pub fn source_consent_signature(
    selection: &crate::provider::runtime::owner_client::workflow::OwnerPolicy,
    seed: [u8; 32],
) -> [u8; 64] {
    let message = owner::consent(selection)["message"]
        .as_str()
        .unwrap()
        .to_owned();
    sign_digest(seed, &crate::signing::signed_message_digest(&message))
}
pub fn active_owner_outcome(
    selection: &crate::provider::runtime::owner_client::workflow::OwnerPolicy,
    request_id: &str,
) -> Value {
    serde_json::to_value(crate::provider::runtime::owner_client::workflow::Outcome {
        request_id: request_id.into(),
        state: "active".into(),
        selection: selection.clone(),
        transactions: vec![],
        receipts: vec![],
    })
    .unwrap()
}
pub fn request_expiry(now: u64) -> u64 {
    (now + 120).min((now / 86400 + 1) * 86400 - 1)
}
pub fn execution_record_filename(request: &ExecutionRequest) -> String {
    format!(
        "request-{}.json",
        crate::hex(&crate::hash(crate::hex(&request.operation.nonce)))
    )
}
pub fn unsigned_execution_record(
    policy_id: &str,
    request_id: &str,
    config: &WalletConfig,
    request: &ExecutionRequest,
    state: &TrustedState,
    now: u64,
) -> Value {
    let prepared = crate::prepare(config, request, state, now, request_expiry(now)).unwrap();
    json!({"policyId":policy_id,"requestId":request_id,"config":config,"request":request,"prepared":prepared,"agentSignature":null,"status":"prepared"})
}
pub fn execution_response(
    prepared: &crate::PreparedOperation,
    signed: Option<&SignedOperation>,
    status: &str,
    request_id: &str,
) -> Value {
    let receipt = if status == "confirmed" {
        signed.map(|signed| confirmed_payment_receipt(signed, 777, 100))
    } else {
        None
    };
    json!({"prepared":prepared,"operation":{"id":request_id,"status":status,"transactionHash":crate::hex(&prepared.transaction_hash)},"signedOperation":signed,"receipt":receipt})
}
