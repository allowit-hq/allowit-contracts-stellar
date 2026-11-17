//! x402 payment challenges on Stellar and the proof of a settled payment.
//!
//! A seller answers a request for a paid resource with HTTP 402 and its payment requirements:
//! a JSON body with `accepts` (x402 version 1), or the base64 JSON of the `PAYMENT-REQUIRED`
//! header (version 2). This module reads the requirement for one Stellar network and builds the
//! proof that the client presents after the payment settled.
//!
//! The policy is evaluated on the payment like on any other operation. A requirement states
//! who settles it:
//!
//! - The standard `exact` scheme: the payer signs one authorization entry for exactly the
//!   transfer, and the seller's facilitator submits it and pays the network fee
//!   ([`SettledBy::Seller`]). The proof carries the transaction that holds the signed entry.
//!   See [`crate::seller_settled`].
//! - `extra.proof` is [`SETTLED_PROOF`]: Allowit settles the payment itself, and the proof
//!   names the settled transaction ([`SettledBy::Payer`]). The seller verifies it on its own:
//!   the transaction succeeded on the stated network, moved at least the required amount of
//!   the required asset to `payTo`, closed after the challenge was issued, and its hash was
//!   not used for an earlier delivery.
//!
//! Either proof is built only from an outcome in which the server recorded this purchase: the
//! resource, the recipient, the amount and the asset of the challenge.
use crate::host::{
    error::{Error, Result},
    execution::Quantity,
    paid_service::{
        Challenge, MAX_SETTLE_WITHIN, PaidServiceProvider, Proof, SellerReply, SettledBy,
        challenge_id,
    },
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};

/// The x402 scheme that this rail reads.
pub const SCHEME: &str = "exact";
/// The value of `extra.proof` by which a seller accepts the proof of a settled transaction.
pub const SETTLED_PROOF: &str = "settled-transaction";
/// The key of the signed payment authorization in an outcome document: the transaction that
/// the client presents when the seller settles.
pub const AUTHORIZATION_KEY: &str = "paymentAuthorization";
/// The response header of a version 2 challenge.
pub const CHALLENGE_HEADER: &str = "PAYMENT-REQUIRED";
/// The request header of a version 1 proof.
pub const PROOF_HEADER_V1: &str = "X-PAYMENT";
/// The request header of a version 2 proof.
pub const PROOF_HEADER_V2: &str = "PAYMENT-SIGNATURE";
const MAX_CHALLENGE_BYTES: usize = crate::host::paid_service::MAX_CHALLENGE_BYTES;
const MAX_REQUIREMENTS: usize = 32;
/// The largest accepted terms, as JSON. The proof echoes them, so this bounds the proof header:
/// a challenge whose proof a client could not present is refused before any payment.
pub const MAX_TERMS_BYTES: usize = 4096;

pub struct PaidService;
pub static PAID_SERVICE: PaidService = PaidService;

impl PaidServiceProvider for PaidService {
    fn challenge(
        &self,
        network: &str,
        resource: &str,
        reply: &SellerReply<'_>,
    ) -> Result<Challenge> {
        challenge(network, resource, reply)
    }
    fn proof(&self, challenge: &Challenge, receipt: &Value) -> Result<Proof> {
        proof(challenge, receipt)
    }
}

fn unsupported(message: impl Into<String>) -> Error {
    Error::unsupported(message)
}

/// The payment requirements of a 402 reply: the version 2 header, else the version 1 body.
fn requirements(reply: &SellerReply<'_>) -> Result<Value> {
    if reply.status != 402 {
        return Err(Error::usage(
            "The seller's reply is not a payment challenge (HTTP 402).",
        ));
    }
    let invalid = || Error::usage("The seller's payment challenge is not valid x402 JSON.");
    let bytes = match reply.header(CHALLENGE_HEADER) {
        Some(header) => {
            if header.len() > MAX_CHALLENGE_BYTES {
                return Err(Error::usage("The seller's payment challenge is too large."));
            }
            STANDARD.decode(header.trim()).map_err(|_| invalid())?
        }
        None => reply.body.to_vec(),
    };
    if bytes.len() > MAX_CHALLENGE_BYTES {
        return Err(Error::usage("The seller's payment challenge is too large."));
    }
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    if !value.is_object() {
        return Err(invalid());
    }
    Ok(value)
}

/// The text of a JSON string or of a JSON integer.
fn text(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        _ => None,
    }
}

/// Read one requirement of `document` for `network`. `Ok(None)` means that the requirement is
/// for another network.
fn requirement(
    network: &'static crate::host::routing::RailInfo,
    resource: &str,
    version: u64,
    document: &Value,
    accepted: &Value,
) -> Result<Option<Challenge>> {
    let named = accepted["network"].as_str().unwrap_or_default();
    if named != network.id && !network.aliases.contains(&named) {
        return Ok(None);
    }
    if accepted["scheme"] != SCHEME {
        return Err(unsupported(format!(
            "The seller's payment scheme is not {SCHEME}."
        )));
    }
    let extra = &accepted["extra"];
    // The seller takes the proof of a settled transaction, or the standard authorization that
    // its facilitator submits. The standard form exists in version 2, with the network fee
    // paid by the facilitator.
    let settled_by = if extra["proof"] == SETTLED_PROOF {
        SettledBy::Payer
    } else if !extra["proof"].is_null() {
        return Err(unsupported(
            "The seller asks for a proof of payment that this rail does not build.",
        ));
    } else if version < 2 {
        return Err(unsupported(
            "The seller's payment challenge uses x402 version 1, which has no payment scheme on this network.",
        ));
    } else if extra["areFeesSponsored"] == false {
        return Err(unsupported(
            "The seller's facilitator does not pay the network fee, and the scheme defines no other payer.",
        ));
    } else {
        SettledBy::Seller
    };
    // A payment authorization pays an account. An offer to a contract payee is refused here,
    // so another offer of the same challenge can be chosen.
    if settled_by == SettledBy::Seller
        && accepted["payTo"].as_str().is_some_and(|payee| {
            crate::address(payee).is_ok() && crate::account_key(payee).is_err()
        })
    {
        return Err(unsupported(crate::seller_settled::CONTRACT_PAYEE));
    }
    // The seller may name the resource. It must be the one that the client asked for.
    let named_resource = if version >= 2 {
        document["resource"]["url"].as_str()
    } else {
        accepted["resource"].as_str()
    };
    if named_resource.is_some_and(|named| named != resource) {
        return Err(Error::usage(
            "The seller's payment challenge names another resource.",
        ));
    }
    let pay_to = accepted["payTo"].as_str().unwrap_or_default();
    crate::address(pay_to)
        .map_err(|_| Error::usage("The seller's payment challenge names an invalid recipient."))?;
    // A listed token by its asset contract, its code or `native`. An unlisted contract has no
    // known unit, so it is refused and never paid.
    let asset = accepted["asset"].as_str().unwrap_or_default();
    // An authorization names the token contract itself.
    let listed = super::tokens_for(network.id).iter().find(|token| {
        super::token_contract(network.id, token).as_deref() == Some(asset)
            || (token.native && asset == "native" && settled_by == SettledBy::Payer)
    });
    let Some(token) = listed else {
        return Err(unsupported(
            "The seller's payment challenge names an asset that this network does not list.",
        ));
    };
    let amount = if version >= 2 {
        text(&accepted["amount"])
    } else {
        text(&accepted["maxAmountRequired"]).or_else(|| text(&accepted["amount"]))
    }
    .unwrap_or_default();
    let units = amount
        .parse::<i64>()
        .ok()
        .filter(|units| *units > 0 && !amount.starts_with('0') && !amount.starts_with('+'))
        .ok_or_else(|| Error::usage("The seller's payment challenge names an invalid amount."))?;
    let id = match extra.get("challengeId").or_else(|| extra.get("nonce")) {
        None | Some(Value::Null) => None,
        Some(value) => {
            let id = value.as_str().unwrap_or_default();
            challenge_id(id)
                .map_err(|_| Error::usage("The seller's payment challenge has an invalid id."))?;
            Some(id.to_owned())
        }
    };
    let expires_at = match extra.get("expiresAt") {
        None | Some(Value::Null) => None,
        Some(value) => Some(value.as_u64().ok_or_else(|| {
            Error::usage("The seller's payment challenge has an invalid expiry.")
        })?),
    };
    // The seller's bound on the time from the authorization to its settlement.
    // A seller that states none gets the default that a settlement service applies.
    let settle_within = match (&settled_by, &accepted["maxTimeoutSeconds"]) {
        (SettledBy::Payer, _) => None,
        (SettledBy::Seller, Value::Null) => Some(crate::seller_settled::DEFAULT_SETTLE_WITHIN),
        (SettledBy::Seller, value) => Some(
            value
                .as_u64()
                .filter(|seconds| (1..=MAX_SETTLE_WITHIN).contains(seconds))
                .ok_or_else(|| {
                    Error::usage("The seller's payment challenge has an invalid timeout.")
                })?,
        ),
    };
    let mut terms = json!({"x402Version": version, "accepted": accepted});
    if version >= 2 && document["resource"].is_object() {
        terms["resource"] = document["resource"].clone();
    }
    if serde_json::to_vec(&terms).map_or(true, |encoded| encoded.len() > MAX_TERMS_BYTES) {
        return Err(Error::usage(
            "The seller's payment terms are too large to present as a proof.",
        ));
    }
    Ok(Some(Challenge {
        id,
        resource: resource.to_owned(),
        network: network.id.to_owned(),
        scheme: SCHEME.to_owned(),
        pay_to: pay_to.to_owned(),
        amount: Quantity::new(i128::from(units), super::display(token)),
        asset: asset.to_owned(),
        expires_at,
        settled_by,
        settle_within,
        terms,
    }))
}

/// Parse the seller's challenge for `resource` on `network`: the first requirement of that
/// network that this rail can settle.
pub fn challenge(network: &str, resource: &str, reply: &SellerReply<'_>) -> Result<Challenge> {
    let network = crate::host::routing::info(network)
        .map_err(|_| Error::usage(format!("unknown Stellar network {network}")))?;
    crate::host::paid_service::resource_url(resource)?;
    let document = requirements(reply)?;
    let version = document["x402Version"].as_u64().unwrap_or(1);
    if !(1..=2).contains(&version) {
        return Err(unsupported(
            "The seller's payment challenge uses an unknown x402 version.",
        ));
    }
    let accepts = document["accepts"]
        .as_array()
        .filter(|accepts| !accepts.is_empty() && accepts.len() <= MAX_REQUIREMENTS)
        .ok_or_else(|| Error::usage("The seller's payment challenge lists no requirement."))?;
    // Every wallet kind pays an offer that the payer settles; only some sign an offer that
    // the seller settles. The selection knows no wallet, so the first offer that the payer
    // settles is taken, and the first that the seller settles only when there is no such
    // offer. A seller that lists both takes both.
    let mut refusal = None;
    let mut seller_settled = None;
    for accepted in accepts {
        match requirement(network, resource, version, &document, accepted) {
            Ok(Some(challenge)) if challenge.settled_by == SettledBy::Payer => {
                return Ok(challenge);
            }
            Ok(Some(challenge)) => seller_settled = seller_settled.or(Some(challenge)),
            Ok(None) => {}
            Err(error) => refusal = refusal.or(Some(error)),
        }
    }
    if let Some(challenge) = seller_settled {
        return Ok(challenge);
    }
    Err(refusal.unwrap_or_else(|| {
        unsupported(format!(
            "The seller offers no payment on {}.",
            network.label
        ))
    }))
}

/// Build the proof of the settled payment of `challenge` from the outcome document of its
/// operation.
pub fn proof(challenge: &Challenge, receipt: &Value) -> Result<Proof> {
    let network = crate::host::routing::info(&challenge.network)
        .map_err(|_| Error::usage("The payment challenge names another rail."))?;
    let settled = challenge.terms["accepted"]["extra"]["proof"] == SETTLED_PROOF;
    if challenge.scheme != SCHEME || settled != (challenge.settled_by == SettledBy::Payer) {
        return Err(unsupported(
            "The payment challenge does not state a proof that this rail builds.",
        ));
    }
    let hash = receipt["transactionHash"].as_str().unwrap_or_default();
    // The signed authorization that the seller's facilitator submits, once both the agent and
    // the server signed it. A settled one is presented again for a delivery that failed.
    let authorization = receipt[AUTHORIZATION_KEY]["transaction"]
        .as_str()
        .unwrap_or_default();
    if settled {
        if receipt["status"] != "confirmed" {
            return Err(Error::uncertain(
                "The payment is not confirmed. Read its status with the same request ID.",
            ));
        }
        if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(Error::config(
                "The payment receipt names no transaction hash.",
            ));
        }
    } else {
        if !matches!(receipt["status"].as_str(), Some("submitted" | "confirmed")) {
            return Err(Error::uncertain(
                "The payment authorization is not signed. Read its status with the same request ID.",
            ));
        }
        if authorization.is_empty()
            || authorization.len() > 8192
            || STANDARD.decode(authorization).is_err()
        {
            return Err(Error::config(
                "The payment receipt holds no signed payment authorization.",
            ));
        }
    }
    // The wallet that executed the operation is on one network. An identical purchase on
    // another network of this rail is another payment.
    if receipt["network"] != challenge.network.as_str() {
        return Err(Error::config(
            "The payment receipt is of another network than the challenge.",
        ));
    }
    // The server records what the operation paid for: the resource, the recipient, the amount
    // and the asset, which it checked against the operation that the policy evaluated. The
    // record must be this challenge. A receipt without it binds no recipient and no network,
    // so it proves nothing about this challenge.
    let recorded = &receipt["paidService"];
    if recorded.is_null() {
        return Err(Error::config(
            "The payment receipt does not record what the payment bought.",
        ));
    }
    if *recorded
        != serde_json::to_value(challenge.context())
            .map_err(|_| Error::config("The payment challenge cannot be encoded."))?
    {
        return Err(Error::config(
            "The payment receipt records another purchase.",
        ));
    }
    // The verified receipt states the debit when its transaction reports a settlement. A
    // fee-bumped transaction reports none. A stated debit must be the challenge amount.
    let paid = &receipt["settlement"]["amount"];
    if !paid.is_null()
        && (paid["units"] != challenge.amount.units.as_str()
            || paid["asset"]["symbol"] != challenge.amount.asset.symbol.as_str())
    {
        return Err(Error::config(
            "The payment receipt does not state the amount of this challenge.",
        ));
    }
    let version = challenge.terms["x402Version"].as_u64().unwrap_or(1);
    let accepted = &challenge.terms["accepted"];
    let payload = if settled {
        let mut payload = json!({"transaction": hash.to_ascii_lowercase(), "settled": true});
        if let Some(id) = &challenge.id {
            payload["challengeId"] = json!(id);
        }
        payload
    } else {
        // The standard payload: the transaction that holds the signed authorization entry.
        json!({"transaction": authorization})
    };
    let mut document = if settled {
        json!({
            "x402Version": version,
            "scheme": SCHEME,
            // The network as the seller wrote it.
            "network": accepted["network"].as_str().unwrap_or(network.id),
            "payload": payload,
        })
    } else {
        // The standard payment payload has exactly these fields and the two below.
        json!({"x402Version": version, "payload": payload})
    };
    if version >= 2 {
        document["accepted"] = accepted.clone();
        if challenge.terms["resource"].is_object() {
            document["resource"] = challenge.terms["resource"].clone();
        }
    }
    let encoded = serde_json::to_vec(&document)
        .map_err(|_| Error::config("The payment proof cannot be encoded."))?;
    Ok(Proof {
        header: if version >= 2 {
            PROOF_HEADER_V2
        } else {
            PROOF_HEADER_V1
        }
        .to_owned(),
        value: STANDARD.encode(encoded),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const TESTNET: &str = "stellar:testnet";
    const RESOURCE: &str = "https://seller.example/report?vault=a";
    const PAY_TO: &str = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";

    fn native_contract() -> String {
        let token = &crate::provider::tokens_for(TESTNET)[0];
        crate::provider::token_contract(TESTNET, token).unwrap()
    }
    fn accepted() -> Value {
        json!({"scheme":"exact","network":TESTNET,"maxAmountRequired":"2500000",
            "resource":RESOURCE,"payTo":PAY_TO,"asset":native_contract(),"maxTimeoutSeconds":60,
            "extra":{"proof":SETTLED_PROOF,"challengeId":"c-0001","expiresAt":1_800_000_000u64}})
    }
    fn v1(accepts: Vec<Value>) -> Vec<u8> {
        serde_json::to_vec(&json!({"x402Version":1,"error":"payment required","accepts":accepts}))
            .unwrap()
    }
    fn parse(body: &[u8]) -> Result<Challenge> {
        challenge(
            TESTNET,
            RESOURCE,
            &SellerReply {
                status: 402,
                headers: &[],
                body,
            },
        )
    }
    fn receipt(challenge: &Challenge) -> Value {
        json!({"requestId":"pay-0001","status":"confirmed","transactionHash":"AB".repeat(32),
            "network":challenge.network,
            "settlement":{"height":7,"fee":{"units":"100"},"amount":challenge.amount},
            "paidService":challenge.context()})
    }

    #[test]
    fn a_version_1_challenge_reads_into_rail_neutral_terms() {
        let challenge = parse(&v1(vec![accepted()])).unwrap();
        assert_eq!(challenge.id.as_deref(), Some("c-0001"));
        assert_eq!(challenge.resource, RESOURCE);
        assert_eq!(challenge.network, TESTNET);
        assert_eq!(challenge.scheme, "exact");
        assert_eq!(challenge.pay_to, PAY_TO);
        assert_eq!(challenge.amount.units, "2500000");
        assert_eq!(challenge.amount.text, "0.25 XLM");
        assert_eq!(challenge.asset, native_contract());
        assert_eq!(challenge.expires_at, Some(1_800_000_000));
        assert_eq!(challenge.context().amount, "2500000");
    }

    #[test]
    fn a_version_2_challenge_reads_from_its_header_and_an_alias_names_the_network() {
        let mut accepted = accepted();
        let object = accepted.as_object_mut().unwrap();
        object.remove("maxAmountRequired");
        object.remove("resource");
        object.insert("amount".into(), json!("70"));
        object.insert("network".into(), json!("stellar-testnet"));
        let document = json!({"x402Version":2,"resource":{"url":RESOURCE,"mimeType":"text/plain"},
            "accepts":[accepted]});
        let headers = vec![(
            "payment-required".to_owned(),
            STANDARD.encode(serde_json::to_vec(&document).unwrap()),
        )];
        let reply = SellerReply {
            status: 402,
            headers: &headers,
            body: b"",
        };
        let challenge = challenge(TESTNET, RESOURCE, &reply).unwrap();
        assert_eq!(challenge.amount.units, "70");
        assert_eq!(challenge.network, TESTNET);
        let proof = proof(&challenge, &receipt(&challenge)).unwrap();
        assert_eq!(proof.header, PROOF_HEADER_V2);
        let decoded: Value =
            serde_json::from_slice(&STANDARD.decode(proof.value).unwrap()).unwrap();
        assert_eq!(decoded["x402Version"], 2);
        assert_eq!(decoded["network"], "stellar-testnet");
        assert_eq!(decoded["accepted"]["amount"], "70");
        assert_eq!(decoded["resource"]["url"], RESOURCE);
    }

    #[test]
    fn the_first_requirement_of_the_selected_network_that_can_settle_is_read() {
        let mut other = accepted();
        other["network"] = json!("eip155:8453");
        let mut pubnet = accepted();
        pubnet["network"] = json!("stellar:pubnet");
        let challenge = parse(&v1(vec![other.clone(), pubnet.clone(), accepted()])).unwrap();
        assert_eq!(challenge.network, TESTNET);
        // No requirement of this network: nothing is paid on another one.
        let error = parse(&v1(vec![other, pubnet])).unwrap_err();
        assert_eq!(error.code, 3);
        assert!(
            error.message.contains("Stellar Testnet"),
            "{}",
            error.message
        );
    }

    /// A version 2 reply with one standard `exact` requirement, changed by `change`.
    fn standard(change: &dyn Fn(&mut Value)) -> Result<Challenge> {
        let mut accepted = json!({"scheme":"exact","network":TESTNET,"amount":"2500000",
            "payTo":PAY_TO,"asset":native_contract(),"maxTimeoutSeconds":300,
            "extra":{"areFeesSponsored":true}});
        change(&mut accepted);
        let document = json!({"x402Version":2,"resource":{"url":RESOURCE},"accepts":[accepted]});
        let headers = vec![(
            CHALLENGE_HEADER.to_owned(),
            STANDARD.encode(serde_json::to_vec(&document).unwrap()),
        )];
        challenge(
            TESTNET,
            RESOURCE,
            &SellerReply {
                status: 402,
                headers: &headers,
                body: b"",
            },
        )
    }

    #[test]
    fn an_offer_to_a_contract_payee_is_passed_over_for_one_to_an_account() {
        // A payment authorization pays an account. The token contract stands for any contract
        // address here.
        let contract = standard(&|a| a["payTo"] = json!(native_contract())).unwrap_err();
        assert_eq!(contract.code, 3);
        assert_eq!(contract.message, crate::seller_settled::CONTRACT_PAYEE);
        // A challenge that lists such an offer before one to an account is paid by the second.
        let offer = |payee: String| {
            json!({"scheme":"exact","network":TESTNET,"amount":"2500000","payTo":payee,
                "asset":native_contract(),"maxTimeoutSeconds":300,
                "extra":{"areFeesSponsored":true}})
        };
        let document = json!({"x402Version":2,"resource":{"url":RESOURCE},
            "accepts":[offer(native_contract()), offer(PAY_TO.into())]});
        let headers = vec![(
            CHALLENGE_HEADER.to_owned(),
            STANDARD.encode(serde_json::to_vec(&document).unwrap()),
        )];
        let chosen = challenge(
            TESTNET,
            RESOURCE,
            &SellerReply {
                status: 402,
                headers: &headers,
                body: b"",
            },
        )
        .unwrap();
        assert_eq!(chosen.pay_to, PAY_TO);
        // A challenge that lists a standard offer and one that the payer settles is paid by
        // the second, in either order: every wallet kind can pay it.
        let mut settled = offer(PAY_TO.into());
        settled["extra"] = json!({"proof":"settled-transaction"});
        for accepts in [
            vec![offer(PAY_TO.into()), settled.clone()],
            vec![settled.clone(), offer(PAY_TO.into())],
        ] {
            let document = json!({"x402Version":2,"resource":{"url":RESOURCE},"accepts":accepts});
            let headers = vec![(
                CHALLENGE_HEADER.to_owned(),
                STANDARD.encode(serde_json::to_vec(&document).unwrap()),
            )];
            let chosen = challenge(
                TESTNET,
                RESOURCE,
                &SellerReply {
                    status: 402,
                    headers: &headers,
                    body: b"",
                },
            )
            .unwrap();
            assert_eq!(chosen.settled_by, SettledBy::Payer);
        }
    }

    #[test]
    fn a_standard_requirement_is_settled_by_the_seller_within_its_timeout() {
        let challenge = standard(&|_| {}).unwrap();
        assert_eq!(challenge.settled_by, SettledBy::Seller);
        assert_eq!(challenge.settle_within, Some(300));
        assert_eq!(challenge.amount.units, "2500000");
        assert_eq!(challenge.asset, native_contract());
        let context = challenge.context();
        context.validate().unwrap();
        assert_eq!(
            (context.settled_by, context.settle_within),
            (SettledBy::Seller, Some(300))
        );
        // The settled-transaction form stays the payer's, and carries no timeout.
        let settled = parse(&v1(vec![accepted()])).unwrap();
        assert_eq!(
            (settled.settled_by, settled.settle_within),
            (SettledBy::Payer, None)
        );
        // A seller that states no timeout gets the default of a settlement service, so the
        // authorization does not outlive what that service admits.
        let open = standard(&|a| {
            a.as_object_mut().unwrap().remove("maxTimeoutSeconds");
        })
        .unwrap();
        assert_eq!(
            open.settle_within,
            Some(crate::seller_settled::DEFAULT_SETTLE_WITHIN)
        );
    }

    #[test]
    fn a_standard_requirement_that_this_rail_cannot_sign_is_refused_before_payment() {
        // Another scheme, a fee that the payer would owe, an unknown proof, a timeout out of
        // bounds, an asset by name, and the standard form in version 1.
        assert_eq!(
            standard(&|a| a["scheme"] = json!("upto")).unwrap_err().code,
            3
        );
        let unsponsored =
            standard(&|a| a["extra"] = json!({"areFeesSponsored":false})).unwrap_err();
        assert_eq!(unsponsored.code, 3);
        assert!(
            unsponsored.message.contains("network fee"),
            "{}",
            unsponsored.message
        );
        assert_eq!(
            standard(&|a| a["extra"] = json!({"proof":"other"}))
                .unwrap_err()
                .code,
            3
        );
        for timeout in [json!(0), json!(86_401), json!("300"), json!(-5)] {
            assert_eq!(
                standard(&|a| a["maxTimeoutSeconds"] = timeout.clone())
                    .unwrap_err()
                    .code,
                2,
                "{timeout}"
            );
        }
        assert_eq!(
            standard(&|a| a["asset"] = json!("native"))
                .unwrap_err()
                .code,
            3
        );
        let mut first = accepted();
        first["extra"] = json!({"areFeesSponsored":true});
        let error = parse(&v1(vec![first])).unwrap_err();
        assert_eq!(error.code, 3);
        assert!(error.message.contains("version 1"), "{}", error.message);
    }

    #[test]
    fn the_proof_of_a_standard_requirement_is_the_standard_payment_payload() {
        let challenge = standard(&|_| {}).unwrap();
        let transaction = STANDARD.encode(b"signed authorization entry in a transaction");
        let outcome = |status: &str| {
            json!({"requestId":"pay-0001","status":status,"transactionHash":"",
                "network":challenge.network,"paidService":challenge.context(),
                AUTHORIZATION_KEY:{"transaction":transaction}})
        };
        let built = proof(&challenge, &outcome("submitted")).unwrap();
        assert_eq!(built.header, PROOF_HEADER_V2);
        let decoded: Value =
            serde_json::from_slice(&STANDARD.decode(built.value).unwrap()).unwrap();
        // Exactly the fields of the standard payload: no settled-transaction fields.
        assert_eq!(
            decoded,
            json!({"x402Version":2,"resource":{"url":RESOURCE},
                "accepted":challenge.terms["accepted"],"payload":{"transaction":transaction}})
        );
        // A settled authorization is presented again for a delivery that failed.
        proof(&challenge, &outcome("confirmed")).unwrap();
        // Before both signatures exist there is nothing to present.
        assert_eq!(proof(&challenge, &outcome("prepared")).unwrap_err().code, 5);
        let mut unsigned = outcome("submitted");
        unsigned.as_object_mut().unwrap().remove(AUTHORIZATION_KEY);
        assert!(proof(&challenge, &unsigned).is_err());
        // The outcome must record this purchase and this network.
        let mut other = outcome("submitted");
        other["paidService"]["payTo"] = json!(crate::account_for_seed(&[9; 32]));
        assert!(proof(&challenge, &other).is_err());
        let mut network = outcome("submitted");
        network["network"] = json!("stellar:pubnet");
        assert!(proof(&challenge, &network).is_err());
        // A settled-transaction outcome is no proof for a seller that settles itself.
        assert!(proof(&challenge, &receipt(&challenge)).is_err());
    }

    #[test]
    fn the_network_the_asset_the_recipient_and_the_amount_are_strict() {
        let refused = |change: &dyn Fn(&mut Value), code: i32| {
            let mut accepted = accepted();
            change(&mut accepted);
            let error = parse(&v1(vec![accepted])).unwrap_err();
            assert_eq!(error.code, code, "{}", error.message);
        };
        // An asset contract that the network does not list, and the listed code in place of
        // the contract.
        refused(&|a| a["asset"] = json!(PAY_TO), 3);
        refused(&|a| a["asset"] = json!("USDC"), 3);
        refused(&|a| a["asset"] = Value::Null, 3);
        refused(&|a| a["payTo"] = json!("not-an-address"), 2);
        refused(&|a| a["payTo"] = Value::Null, 2);
        for amount in [
            "0",
            "-1",
            "1.5",
            "01",
            "+5",
            "",
            "9223372036854775808",
            "1e3",
        ] {
            refused(&|a| a["maxAmountRequired"] = json!(amount), 2);
        }
        refused(&|a| a["maxAmountRequired"] = json!(1.5), 2);
        refused(
            &|a| a["resource"] = json!("https://seller.example/other"),
            2,
        );
        refused(&|a| a["extra"]["challengeId"] = json!("a b"), 2);
        refused(&|a| a["extra"]["challengeId"] = json!(7), 2);
        refused(&|a| a["extra"]["expiresAt"] = json!("soon"), 2);
        // A number amount without a fraction reads as its text.
        let mut numeric = accepted();
        numeric["maxAmountRequired"] = json!(2_500_000);
        assert_eq!(parse(&v1(vec![numeric])).unwrap().amount.units, "2500000");
    }

    #[test]
    fn a_reply_that_is_no_bounded_challenge_is_refused() {
        let reply = |status, body: &[u8]| {
            challenge(
                TESTNET,
                RESOURCE,
                &SellerReply {
                    status,
                    headers: &[],
                    body,
                },
            )
        };
        assert_eq!(reply(200, &v1(vec![accepted()])).unwrap_err().code, 2);
        assert_eq!(reply(402, b"<html>pay</html>").unwrap_err().code, 2);
        assert_eq!(reply(402, b"[]").unwrap_err().code, 2);
        assert_eq!(reply(402, &v1(vec![])).unwrap_err().code, 2);
        assert_eq!(
            reply(402, &v1(vec![accepted(); MAX_REQUIREMENTS + 1]))
                .unwrap_err()
                .code,
            2
        );
        let large = vec![b' '; MAX_CHALLENGE_BYTES + 1];
        assert_eq!(reply(402, &large).unwrap_err().code, 2);
        let version = serde_json::to_vec(&json!({"x402Version":3,"accepts":[accepted()]})).unwrap();
        assert_eq!(reply(402, &version).unwrap_err().code, 3);
        // Another rail's network and a resource that is no URL never reach the parser.
        let other = challenge(
            "example:testnet",
            RESOURCE,
            &SellerReply {
                status: 402,
                headers: &[],
                body: &v1(vec![accepted()]),
            },
        );
        assert_eq!(other.unwrap_err().code, 2);
        let scheme = challenge(
            TESTNET,
            "file:///etc/passwd",
            &SellerReply {
                status: 402,
                headers: &[],
                body: &v1(vec![accepted()]),
            },
        );
        assert_eq!(scheme.unwrap_err().code, 2);
    }

    #[test]
    fn terms_too_large_to_present_as_a_proof_are_refused_before_payment() {
        // The proof echoes the accepted terms. A challenge that parses but whose proof no
        // client could present must never be paid.
        let mut large = accepted();
        large["extra"]["note"] = json!("a".repeat(MAX_TERMS_BYTES));
        let error = parse(&v1(vec![large])).unwrap_err();
        assert_eq!(error.code, 2);
        assert!(error.message.contains("too large"), "{}", error.message);
        let mut accepted = accepted();
        let object = accepted.as_object_mut().unwrap();
        object.remove("maxAmountRequired");
        object.remove("resource");
        object.insert("amount".into(), json!("70"));
        let document = json!({"x402Version":2,
            "resource":{"url":RESOURCE,"description":"d".repeat(MAX_TERMS_BYTES)},
            "accepts":[accepted.clone()]});
        let body = serde_json::to_vec(&document).unwrap();
        assert_eq!(parse(&body).unwrap_err().code, 2);
        // The largest accepted terms give a proof within a 16 KiB header value.
        accepted["extra"]["note"] = json!("a".repeat(MAX_TERMS_BYTES - 700));
        let document = json!({"x402Version":2,"resource":{"url":RESOURCE},"accepts":[accepted]});
        let challenge = parse(&serde_json::to_vec(&document).unwrap()).unwrap();
        let proof = proof(&challenge, &receipt(&challenge)).unwrap();
        assert!(proof.value.len() < 16_384, "{}", proof.value.len());
    }

    #[test]
    fn the_proof_names_the_settled_transaction_of_this_challenge() {
        let challenge = parse(&v1(vec![accepted()])).unwrap();
        let proof = proof(&challenge, &receipt(&challenge)).unwrap();
        assert_eq!(proof.header, PROOF_HEADER_V1);
        let decoded: Value =
            serde_json::from_slice(&STANDARD.decode(proof.value).unwrap()).unwrap();
        assert_eq!(
            decoded,
            json!({"x402Version":1,"scheme":"exact","network":TESTNET,
                "payload":{"transaction":"ab".repeat(32),"settled":true,"challengeId":"c-0001"}})
        );
    }

    #[test]
    fn no_proof_is_built_from_an_unconfirmed_or_another_payment() {
        let challenge = parse(&v1(vec![accepted()])).unwrap();
        let refused = |change: &dyn Fn(&mut Value), code: i32| {
            let mut receipt = receipt(&challenge);
            change(&mut receipt);
            let error = proof(&challenge, &receipt).unwrap_err();
            assert_eq!(error.code, code, "{}", error.message);
        };
        for status in ["submitted", "failed", "submissionUnknown", "prepared"] {
            refused(&|r| r["status"] = json!(status), 5);
        }
        refused(&|r| r["transactionHash"] = json!("ab"), 3);
        refused(&|r| r["transactionHash"] = Value::Null, 3);
        // No record of the purchase: the debit alone binds no recipient and no network.
        refused(
            &|r| {
                r.as_object_mut().unwrap().remove("paidService");
            },
            3,
        );
        refused(&|r| r["paidService"] = Value::Null, 3);
        // The same purchase on another network of the rail, or on none.
        refused(&|r| r["network"] = json!("stellar:pubnet"), 3);
        refused(&|r| r["network"] = Value::Null, 3);
        refused(
            &|r| {
                r["paidService"]["payTo"] =
                    json!("GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN")
            },
            3,
        );
        refused(
            &|r| {
                r["settlement"] = Value::Null;
                r["paidService"]["amount"] = json!("1");
            },
            3,
        );
        refused(
            &|r| r["settlement"]["amount"]["units"] = json!("2499999"),
            3,
        );
        refused(
            &|r| r["settlement"]["amount"]["asset"]["symbol"] = json!("USDC"),
            3,
        );
        refused(
            &|r| r["paidService"]["resource"] = json!("https://seller.example/other"),
            3,
        );
        refused(&|r| r["paidService"]["challengeId"] = json!("c-0002"), 3);
        // A fee-bumped transaction reports no settlement: the recorded purchase binds it.
        let mut bumped = receipt(&challenge);
        bumped.as_object_mut().unwrap().remove("settlement");
        proof(&challenge, &bumped).unwrap();
        // A challenge that never accepted the settled proof gets none.
        let mut standard = challenge.clone();
        standard.terms["accepted"]["extra"] = json!({});
        assert_eq!(proof(&standard, &receipt(&challenge)).unwrap_err().code, 3);
    }
}
