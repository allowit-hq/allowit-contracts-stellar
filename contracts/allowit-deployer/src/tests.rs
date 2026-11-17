extern crate std;
use super::*;
use allowit_policy_wallet::AllowitPolicyConfig;
use soroban_sdk::{
    IntoVal, Map, Symbol, TryFromVal,
    testutils::{Address as _, AuthorizedFunction, MockAuth, MockAuthInvoke},
    token::StellarAssetClient,
    xdr,
};

const SIMPLE: &[u8] =
    include_bytes!("../../../target/wasm32v1-none/release/allowit_simple_policy_engine.wasm");
const COMMON: &[u8] =
    include_bytes!("../../../target/wasm32v1-none/release/allowit_common_policy_engine.wasm");

struct Setup {
    env: Env,
    deployer: Address,
    owner: Address,
    xlm: Address,
    usdc: Address,
    simple: BytesN<32>,
    common: BytesN<32>,
    salt: BytesN<32>,
}

fn setup() -> Setup {
    let env = Env::default();
    env.mock_all_auths_allowing_non_root_auth();
    let created = env
        .host()
        .invoke_function(xdr::HostFunction::CreateContract(xdr::CreateContractArgs {
            contract_id_preimage: xdr::ContractIdPreimage::Asset(xdr::Asset::Native),
            executable: xdr::ContractExecutable::StellarAsset,
        }))
        .unwrap();
    let xlm = Address::try_from_val(&env, &created).unwrap();
    let usdc = env
        .register_stellar_asset_contract_v2(Address::generate(&env))
        .address();
    let owner = Address::generate(&env);
    StellarAssetClient::new(&env, &usdc).mint(&owner, &1_000);
    let deployer = env.register(AllowitDeployer, ());
    let simple = env.deployer().upload_contract_wasm(SIMPLE);
    let common = env.deployer().upload_contract_wasm(COMMON);
    env.set_auths(&[]);
    Setup {
        salt: BytesN::from_array(&env, &[4; 32]),
        env,
        deployer,
        owner,
        xlm,
        usdc,
        simple,
        common,
    }
}

fn config(s: &Setup, asset: &Address) -> AllowitPolicyConfig {
    AllowitPolicyConfig {
        owner: s.owner.clone(),
        agent: BytesN::from_array(&s.env, &[1; 32]),
        server: BytesN::from_array(&s.env, &[2; 32]),
        asset: asset.clone(),
        source_hash: BytesN::from_array(&s.env, &[9; 32]),
        gas_cap: 100_000,
        rules: Vec::new(&s.env),
        params: Map::new(&s.env),
    }
}

#[test]
fn one_owner_authorization_creates_and_funds_the_wallet_at_the_owners_address() {
    let s = setup();
    let client = AllowitDeployerClient::new(&s.env, &s.deployer);
    let args: Vec<Val> = (config(&s, &s.usdc),).into_val(&s.env);
    let funding = Vec::from_array(&s.env, [(s.usdc.clone(), 250i128)]);
    s.env.mock_all_auths_allowing_non_root_auth();
    let wallet = client.deploy(&s.owner, &s.simple, &s.salt, &args, &funding);
    // The address of the owner's own creation with this salt.
    let expected = s
        .env
        .deployer()
        .with_address(s.owner.clone(), s.salt.clone())
        .deployed_address();
    assert_eq!(wallet, expected);
    // One authorization of the owner covers the whole tree: the call, the creation with its exact
    // code and constructor arguments, and the funding transfer.
    let auths = s.env.auths();
    assert_eq!(auths.len(), 1);
    let (address, root) = &auths[0];
    assert_eq!(address, &s.owner);
    match &root.function {
        AuthorizedFunction::Contract((contract, name, _)) => {
            assert_eq!(
                (contract, name),
                (&s.deployer, &Symbol::new(&s.env, "deploy"))
            );
        }
        other => panic!("{other:?}"),
    }
    let names: std::vec::Vec<std::string::String> = root
        .sub_invocations
        .iter()
        .map(|sub| match &sub.function {
            AuthorizedFunction::CreateContractV2HostFn(create) => {
                assert_eq!(
                    create.executable,
                    xdr::ContractExecutable::Wasm(xdr::Hash(s.simple.to_array()))
                );
                std::format!(
                    "create with {} constructor args",
                    create.constructor_args.len()
                )
            }
            AuthorizedFunction::Contract((contract, name, _)) => {
                assert_eq!(name, &Symbol::new(&s.env, "transfer"));
                std::format!(
                    "{}:transfer",
                    if *contract == s.usdc { "usdc" } else { "other" }
                )
            }
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(names, ["create with 1 constructor args", "usdc:transfer"]);
    assert_eq!(token::Client::new(&s.env, &s.usdc).balance(&wallet), 250);
    assert_eq!(token::Client::new(&s.env, &s.usdc).balance(&s.owner), 750);
    // The deployer keeps nothing.
    assert_eq!(token::Client::new(&s.env, &s.usdc).balance(&s.deployer), 0);
    let _ = s.xlm;
}

#[test]
fn the_owners_authorization_binds_the_code_hash() {
    let s = setup();
    let client = AllowitDeployerClient::new(&s.env, &s.deployer);
    let args: Vec<Val> = (config(&s, &s.usdc),).into_val(&s.env);
    let funding: Vec<(Address, i128)> = Vec::new(&s.env);
    // The owner signs a deployment of the Simple code; another registered build cannot use it.
    let signed = MockAuthInvoke {
        contract: &s.deployer,
        fn_name: "deploy",
        args: (
            s.owner.clone(),
            s.simple.clone(),
            s.salt.clone(),
            args.clone(),
            funding.clone(),
        )
            .into_val(&s.env),
        sub_invokes: &[],
    };
    s.env.mock_auths(&[MockAuth {
        address: &s.owner,
        invoke: &signed,
    }]);
    assert!(
        client
            .try_deploy(&s.owner, &s.common, &s.salt, &args, &funding)
            .is_err()
    );
    // Nobody but the owner deploys on the owner's address.
    s.env.set_auths(&[]);
    assert!(
        client
            .try_deploy(&s.owner, &s.simple, &s.salt, &args, &funding)
            .is_err()
    );
}
