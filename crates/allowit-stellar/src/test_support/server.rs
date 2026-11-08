//! Public owner-server protocol documents for consumer replay servers.
use crate::WalletConfig;
use serde_json::{Value, json};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
fn date(value: u64) -> String {
    OffsetDateTime::from_unix_timestamp(value as i64)
        .unwrap()
        .format(&Rfc3339)
        .unwrap()
}
pub fn owner_signin_challenge(owner: &str, origin: &str, now: u64) -> Value {
    let nonce = "ab".repeat(32);
    let expiry = date(now + 300);
    let host = origin.split_once("://").unwrap().1;
    json!({"id":nonce,"address":owner,"origin":origin,"expiresAt":expiry,
        "message":format!("{host} wants you to sign in with your Stellar account:\n{owner}\n\nSign in to AllowIt. This does not authorize spending or move funds.\n\nURI: {origin}\nVersion: 1\nNonce: {nonce}\nIssued At: {}\nExpiration Time: {expiry}",date(now))})
}

/// Native document bundle. Consumer tests control transport, clocks, cookies and injected faults.
pub struct OwnerDocuments {
    pub owner: String,
    pub origin: String,
    pub challenge: Value,
    pub discovery: Value,
    pub templates: Value,
    pub installations: Value,
    pub policy: Value,
}
impl OwnerDocuments {
    pub fn new(owner: &str, origin: &str, now: u64) -> Self {
        let policy = super::owner_generation_fixture()["policy"].clone();
        let b = &policy["runtime"]["instanceBinding"];
        Self {
            owner: owner.into(),
            origin: origin.into(),
            challenge: owner_signin_challenge(owner, origin, now),
            discovery: json!({"wallets":[{"kind":"contract-wallet","profile":"allowit-stellar-policy-wallet-v1","sourceProfiles":["allowit-stellar-transfer-v1"],"networks":["stellar:testnet"],"operations":["stellar::sep41_transfer"],"capabilities":{"generate":true,"fund":true}}],"operations":[{"function":"stellar::sep41_transfer","services":[]}]}),
            templates: json!({"templates":[{"network":"stellar:testnet","profiles":["allowit-stellar-policy-wallet-v1"],"asset":b["asset"],"assetSymbol":b["assetSymbol"],"assetIssuer":b["assetIssuer"],"maxFeeStroops":b["maxFeeStroops"]}]}),
            installations: json!({"installations":[]}),
            policy,
        }
    }
    pub fn install_existing(&mut self, owner: &str) -> WalletConfig {
        let config = super::existing_installation(owner, &self.policy);
        self.installations = json!({"installations":[{"policyId":"07".repeat(32),"profile":"allowit-stellar-policy-wallet-v1","config":config}]});
        let b = &mut self.policy["runtime"]["instanceBinding"];
        b["template"] = json!(false);
        b["wallet"] = json!(config.wallet);
        b["moduleDigest"] = json!(crate::hex(&config.module_digest));
        config
    }
    pub fn use_mainnet(&mut self) {
        let issuer = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";
        let asset = crate::sac_address(
            "stellar:mainnet",
            &crate::asset_from_identity("USDC", Some(issuer)).unwrap(),
        )
        .unwrap();
        self.discovery["wallets"][0]["networks"] = json!(["stellar:mainnet"]);
        self.templates["templates"][0]["network"] = json!("stellar:mainnet");
        self.templates["templates"][0]["asset"] = json!(asset);
        self.templates["templates"][0]["assetIssuer"] = json!(issuer);
        self.policy["network"] = json!("stellar:mainnet");
        self.policy["mint"] = json!(asset);
        let b = &mut self.policy["runtime"]["instanceBinding"];
        b["asset"] = json!(asset);
        b["assetIssuer"] = json!(issuer);
        b["portable"]["asset"]["address"] = json!(asset);
        b["portable"]["params"]["tokens"]["List"][0]["Addr"] = json!(asset);
        b["portable"]["paramsHash"] = json!(allowit_core::digest(
            &serde_json_canonicalizer::to_vec(&b["portable"]["params"]).unwrap()
        ));
    }
    pub fn install_native_existing(&mut self, owner: &str, tampered: bool) {
        let mut config = self.install_existing(owner);
        config.route = crate::WalletRoute::Native;
        config.wallet = crate::account_for_seed(&[14; 32]);
        config.tier = None;
        config.max_fee_stroops = 100_000;
        crate::validate_config(&config).unwrap();
        self.installations = json!({"installations":[{"policyId":"07".repeat(32),"profile":"allowit-stellar-native-v1","config":config}]});
        self.discovery["wallets"][0]["profile"] = json!("allowit-stellar-native-v1");
        self.discovery["wallets"][0]["kind"] = json!("owner-wallet");
        self.policy["runtime"]["wallet"] =
            json!({"kind":"owner-wallet","profile":"allowit-stellar-native-v1"});
        let b = self.policy["runtime"]["instanceBinding"]
            .as_object_mut()
            .unwrap();
        b.remove("tier");
        b.remove("template");
        b.insert("route".into(), json!("native"));
        b.insert("wallet".into(), json!(config.wallet));
        b.insert("maxFeeStroops".into(), json!(config.max_fee_stroops));
        let d = &b["portable"];
        let identity = json!({"language":d["language"],"tier":d["tier"],"rules":d["rules"],"sourceHash":d["sourceHash"],"paramsHash":d["paramsHash"]});
        b.insert(
            "moduleDigest".into(),
            json!(if tampered {
                "44".repeat(32)
            } else {
                allowit_core::digest(&serde_json_canonicalizer::to_vec(&identity).unwrap())
            }),
        );
    }
    pub fn use_empty_standard_prefix(&mut self, tier: &str) {
        let source = "use allowit::prelude::*;\npub fn execute(ctx: &AllowitContext) -> allowit::Result { Ok(()) }\n";
        let digest = allowit_core::digest(source.as_bytes());
        self.policy["code"] = json!(source);
        self.policy["sourceHash"] = json!(digest);
        let b = &mut self.policy["runtime"]["instanceBinding"];
        b["tier"] = json!(tier);
        b["portable"]["sourceHash"] = json!(digest);
        b["portable"]["rules"] = json!([]);
        b["portable"]["build"]["prefix"] = json!([]);
    }
}
/// An authenticated native owner session document, independent of HTTP cookie handling.
pub fn owner_session(owner: &str, expires_at: u64) -> Value {
    json!({"session":{"address":owner,"network":"stellar","expiresAt":date(expires_at)}})
}
pub fn confirmed_owner_submission(network: &str, signed: &str) -> Value {
    let hash = crate::rpc::signed_transaction_hash(network, signed).unwrap();
    json!({"status":"confirmed","transactionHash":crate::hex(&hash)})
}
pub fn generated_policy_reply(policy: &Value, prompt: &Value) -> Value {
    let mut policy = policy.clone();
    policy["originalIntent"] = prompt.clone();
    json!({"selectedId":policy["id"],"policies":[policy]})
}
