//! x402 payment challenges on Stellar and the proof of a settled payment.
//!
//! A seller answers a request for a paid resource with HTTP 402 and its payment requirements:
//! a JSON body with `accepts` (x402 version 1), or the base64 JSON of the `PAYMENT-REQUIRED`
//! header (version 2). This module reads the requirement for one Stellar network and builds the
//! proof that the client presents after the payment settled.
//!
//! Allowit settles the payment itself: the policy is evaluated and the transfer is executed
//! like any other operation, and the proof names the settled transaction. The standard `exact`
//! scheme on Stellar has the seller's facilitator submit a transaction that the payer signed.
//! Allowit signs no such transaction. A requirement is therefore accepted only when the seller
//! states that it takes the proof of a settled transaction: `extra.proof` is
//! [`SETTLED_PROOF`]. Every other requirement is refused before any payment.
//!
//! The seller verifies the proof on its own: the transaction succeeded on the stated network,
//! moved at least the required amount of the required asset to `payTo`, closed after the
//! challenge was issued, and its hash was not used for an earlier delivery.
use crate::host::{
    error::{Error, Result},
    execution::Quantity,
    paid_service::{Challenge, PaidServiceProvider, Proof, SellerReply, challenge_id},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};

/// The x402 scheme that this rail reads.
pub const SCHEME: &str = "exact";
/// The value of `extra.proof` by which a seller accepts the proof of a settled transaction.
pub const SETTLED_PROOF: &str = "settled-transaction";
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
    if accepted["extra"]["proof"] != SETTLED_PROOF {
        return Err(unsupported(
            "The seller requires a facilitator to settle a transaction that the payer signs. \
             Allowit settles the payment itself and presents the settled transaction, and this \
             seller does not accept that proof.",
        ));
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
    let listed = super::tokens_for(network.id).iter().find(|token| {
        super::token_contract(network.id, token).as_deref() == Some(asset)
            || (token.native && asset == "native")
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
    let extra = &accepted["extra"];
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
    let mut refusal = None;
    for accepted in accepts {
        match requirement(network, resource, version, &document, accepted) {
            Ok(Some(challenge)) => return Ok(challenge),
            Ok(None) => {}
            Err(error) => refusal = refusal.or(Some(error)),
        }
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
    if challenge.scheme != SCHEME || challenge.terms["accepted"]["extra"]["proof"] != SETTLED_PROOF
    {
        return Err(unsupported(
            "The payment challenge does not accept the proof of a settled transaction.",
        ));
    }
    if receipt["status"] != "confirmed" {
        return Err(Error::uncertain(
            "The payment is not confirmed. Read its status with the same request ID.",
        ));
    }
    let hash = receipt["transactionHash"].as_str().unwrap_or_default();
    if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Error::config(
            "The payment receipt names no transaction hash.",
        ));
    }
    // The verified receipt states the debit, and the server records what the payment bought.
    // Each one that the document holds must be this challenge, and it must hold one of them.
    // A fee-bumped transaction reports no settlement, so its record alone binds the purchase.
    let paid = &receipt["settlement"]["amount"];
    if !paid.is_null()
        && (paid["units"] != challenge.amount.units.as_str()
            || paid["asset"]["symbol"] != challenge.amount.asset.symbol.as_str())
    {
        return Err(Error::config(
            "The payment receipt does not state the amount of this challenge.",
        ));
    }
    let recorded = &receipt["paidService"];
    if !recorded.is_null()
        && *recorded
            != serde_json::to_value(challenge.context())
                .map_err(|_| Error::config("The payment challenge cannot be encoded."))?
    {
        return Err(Error::config(
            "The payment receipt records another purchase.",
        ));
    }
    if paid.is_null() && recorded.is_null() {
        return Err(Error::config(
            "The payment receipt states neither the amount nor the purchase of this challenge.",
        ));
    }
    let version = challenge.terms["x402Version"].as_u64().unwrap_or(1);
    let accepted = &challenge.terms["accepted"];
    let mut payload = json!({"transaction": hash.to_ascii_lowercase(), "settled": true});
    if let Some(id) = &challenge.id {
        payload["challengeId"] = json!(id);
    }
    let mut document = json!({
        "x402Version": version,
        "scheme": SCHEME,
        // The network as the seller wrote it.
        "network": accepted["network"].as_str().unwrap_or(network.id),
        "payload": payload,
    });
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

    #[test]
    fn a_requirement_that_needs_a_facilitator_is_refused_before_payment() {
        let mut standard = accepted();
        standard["extra"] = json!({"areFeesSponsored":true});
        let error = parse(&v1(vec![standard])).unwrap_err();
        assert_eq!(error.code, 3);
        assert!(error.message.contains("facilitator"), "{}", error.message);
        let mut scheme = accepted();
        scheme["scheme"] = json!("upto");
        assert_eq!(parse(&v1(vec![scheme])).unwrap_err().code, 3);
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
        // Neither the debit nor the record: nothing binds the payment to this challenge.
        refused(
            &|r| {
                r["settlement"] = Value::Null;
                r.as_object_mut().unwrap().remove("paidService");
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
        // A receipt of a server that records no context still proves the payment.
        let mut plain = receipt(&challenge);
        plain.as_object_mut().unwrap().remove("paidService");
        proof(&challenge, &plain).unwrap();
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
