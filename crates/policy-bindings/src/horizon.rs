//! Bounded, read-only price observations from the public Stellar Horizon API.

use allowit_core::transport::{
    http::{HttpClient, Method, Request},
    rpc::Options,
};
use serde_json::Value;
use std::{
    sync::OnceLock,
    time::{Duration, Instant},
};
use stellar_strkey::ed25519::PublicKey;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use url::Url;

const SCALE: i128 = 10_000_000;
const HOUR_MS: i64 = 3_600_000;
const MAX_REPLY: usize = 65_536;
const OBSERVATION_BUDGET: Duration = Duration::from_millis(1800);
const UNAVAILABLE: &str = "Stellar Horizon price is missing, stale, or thin.";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PriceObservation {
    /// Counter base units per whole source unit, from strict-send paths.
    pub path_rate: i128,
    /// Counter base units per whole source unit, from executable order-book depth.
    pub book_rate: i128,
    /// Counter base units per whole source unit, from the last completed trade window.
    pub average_rate: i128,
    pub path_ledger: u32,
    pub book_ledger: u32,
    /// Start of the last completed trade window in Unix milliseconds.
    pub trade_window: i64,
    /// The configured public Horizon origin for the selected network.
    pub source: &'static str,
}

#[derive(PartialEq, Eq)]
struct Asset<'a> {
    kind: &'static str,
    code: &'a str,
    issuer: &'a str,
}

impl<'a> Asset<'a> {
    fn parse(value: &'a str) -> Option<Self> {
        if value == "native" {
            return Some(Self {
                kind: "native",
                code: "",
                issuer: "",
            });
        }
        let (code, issuer) = value.split_once(':')?;
        if !(1..=12).contains(&code.len())
            || !code.bytes().all(|byte| byte.is_ascii_alphanumeric())
            || issuer.parse::<PublicKey>().ok()?.to_string() != issuer
        {
            return None;
        }
        let kind = if code.len() <= 4 {
            "credit_alphanum4"
        } else {
            "credit_alphanum12"
        };
        Some(Self { kind, code, issuer })
    }

    fn query(&self, url: &mut Url, prefix: &str) {
        let mut pairs = url.query_pairs_mut();
        pairs.append_pair(&format!("{prefix}asset_type"), self.kind);
        if self.kind != "native" {
            pairs.append_pair(&format!("{prefix}asset_code"), self.code);
            pairs.append_pair(&format!("{prefix}asset_issuer"), self.issuer);
        }
    }

    fn matches(&self, record: &Value, prefix: &str) -> bool {
        record[format!("{prefix}asset_type")].as_str() == Some(self.kind)
            && (self.kind == "native"
                || (record[format!("{prefix}asset_code")].as_str() == Some(self.code)
                    && record[format!("{prefix}asset_issuer")].as_str() == Some(self.issuer)))
    }
}

fn decimal(value: &str) -> Option<i128> {
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    if whole.is_empty()
        || whole.len() > 12
        || fraction.len() > 7
        || !whole
            .bytes()
            .chain(fraction.bytes())
            .all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let whole = whole.parse::<i128>().ok()?;
    let fraction_value = if fraction.is_empty() {
        0
    } else {
        fraction.parse::<i128>().ok()?
    };
    let units = whole * SCALE + fraction_value * 10_i128.pow(7 - fraction.len() as u32);
    (units > 0 && units <= i128::from(i64::MAX)).then_some(units)
}

fn client() -> Option<&'static HttpClient> {
    static CLIENT: OnceLock<Option<HttpClient>> = OnceLock::new();
    CLIENT
        .get_or_init(|| {
            HttpClient::new(Options {
                timeout: OBSERVATION_BUDGET,
                max_response_bytes: MAX_REPLY,
                no_proxy: true,
                connect_timeout: Some(Duration::from_millis(500)),
            })
            .ok()
        })
        .as_ref()
}

fn get(url: Url, deadline: Instant) -> Option<(Option<u32>, Value)> {
    if url.scheme() != "https" {
        return None;
    }
    let request = Request {
        method: Method::Get,
        url: url.as_str(),
        headers: &[],
        body: None,
    };
    let reply = client()?.send_success_body(request, Some(deadline)).ok()?;
    if !(200..300).contains(&reply.status) {
        return None;
    }
    let ledger = reply
        .header("latest-ledger")
        .and_then(|value| value.parse().ok());
    Some((ledger, serde_json::from_slice(&reply.body).ok()?))
}

fn path_rate(paths: &Value, from: &Asset<'_>, to: &Asset<'_>, amount: i128) -> Option<i128> {
    let received = paths["_embedded"]["records"]
        .as_array()?
        .iter()
        .filter(|record| from.matches(record, "source_") && to.matches(record, "destination_"))
        .filter(|record| record["source_amount"].as_str().and_then(decimal) == Some(amount))
        .filter_map(|record| decimal(record["destination_amount"].as_str()?))
        .max()?;
    let rate = received * SCALE / amount;
    (rate > 0).then_some(rate)
}

fn book_rate(book: &Value, from: &Asset<'_>, to: &Asset<'_>, amount: i128) -> Option<i128> {
    if !from.matches(&book["base"], "") || !to.matches(&book["counter"], "") {
        return None;
    }
    let mut remainder = amount;
    let mut proceeds = 0;
    for bid in book["bids"].as_array()?.iter().take(20) {
        let n = i128::from(i32::try_from(bid["price_r"]["n"].as_i64()?).ok()?);
        let d = i128::from(i32::try_from(bid["price_r"]["d"].as_i64()?).ok()?);
        if n <= 0 || d <= 0 {
            return None;
        }
        let counter = decimal(bid["amount"].as_str()?)?;
        let filled = remainder.min(counter * d / n);
        proceeds += filled * n / d;
        remainder -= filled;
        if remainder == 0 {
            let rate = proceeds * SCALE / amount;
            return (rate > 0).then_some(rate);
        }
    }
    None
}

fn ledger_close(ledger: &Value, sequence: u32, now: i64) -> Option<i64> {
    let closed = OffsetDateTime::parse(ledger["closed_at"].as_str()?, &Rfc3339)
        .ok()?
        .unix_timestamp();
    (ledger["sequence"].as_u64() == Some(u64::from(sequence)) && fresh(closed, now))
        .then_some(closed)
}

fn fresh(closed: i64, now: i64) -> bool {
    now.checked_sub(closed)
        .is_some_and(|age| (0..=30).contains(&age))
}

fn average_rate(trades: &Value, window: i64, amount: i128) -> Option<i128> {
    let trade = trades["_embedded"]["records"]
        .as_array()?
        .iter()
        .find(|trade| {
            let timestamp = &trade["timestamp"];
            timestamp
                .as_i64()
                .or_else(|| timestamp.as_str()?.parse().ok())
                == Some(window)
        })?;
    let trade_count = trade["trade_count"]
        .as_u64()
        .or_else(|| trade["trade_count"].as_str()?.parse().ok())?;
    if trade_count < 2 || decimal(trade["base_volume"].as_str()?)? < amount {
        return None;
    }
    decimal(trade["avg"].as_str()?)
}

/// Observe fresh executable rates and a completed trade-window rate for an exact amount.
///
/// Use `native` or a canonical `CODE:ISSUER` identity for each asset. The input amount is in
/// source base units. All rates use the same 10^7 scale. This function queries only the public
/// Horizon origin of the selected network. This blocking call returns observations for the host
/// to evaluate against the policy's allowed price.
pub fn observe_price(
    network: &str,
    from: &str,
    to: &str,
    amount: i128,
) -> Result<PriceObservation, String> {
    observe(network, from, to, amount).ok_or_else(|| UNAVAILABLE.into())
}

fn observe(network: &str, from: &str, to: &str, amount: i128) -> Option<PriceObservation> {
    let origin = match crate::networks::resolve(network)?.id {
        "stellar:testnet" => "https://horizon-testnet.stellar.org/",
        "stellar:pubnet" => "https://horizon.stellar.org/",
        _ => return None,
    };
    let deadline = Instant::now() + OBSERVATION_BUDGET;
    let destination = to;
    let from = Asset::parse(from)?;
    let to = Asset::parse(to)?;
    if from == to || !(1..=i128::from(i64::MAX)).contains(&amount) {
        return None;
    }

    let base = Url::parse(origin).ok()?;
    let mut paths = base.join("paths/strict-send").ok()?;
    from.query(&mut paths, "source_");
    paths
        .query_pairs_mut()
        .append_pair(
            "source_amount",
            &format!("{}.{:07}", amount / SCALE, amount % SCALE),
        )
        .append_pair("destination_assets", destination);
    let (path_ledger, paths) = get(paths, deadline)?;
    let path_ledger = path_ledger?;
    let path_rate = path_rate(&paths, &from, &to, amount)?;

    let mut book = base.join("order_book").ok()?;
    from.query(&mut book, "selling_");
    to.query(&mut book, "buying_");
    book.query_pairs_mut().append_pair("limit", "20");
    let (book_ledger, book) = get(book, deadline)?;
    let book_ledger = book_ledger?;
    if path_ledger.abs_diff(book_ledger) > 1 {
        return None;
    }
    let older = path_ledger.min(book_ledger);
    let (_, ledger) = get(base.join(&format!("ledgers/{older}")).ok()?, deadline)?;
    let closed = ledger_close(&ledger, older, OffsetDateTime::now_utc().unix_timestamp())?;
    let book_rate = book_rate(&book, &from, &to, amount)?;

    let mut trades = base.join("trade_aggregations").ok()?;
    from.query(&mut trades, "base_");
    to.query(&mut trades, "counter_");
    let hour = closed * 1_000 / HOUR_MS * HOUR_MS;
    let trade_window = hour - HOUR_MS;
    trades
        .query_pairs_mut()
        .append_pair("start_time", &trade_window.to_string())
        .append_pair("end_time", &hour.to_string())
        .append_pair("resolution", &HOUR_MS.to_string())
        .append_pair("order", "desc")
        .append_pair("limit", "2");
    let (_, trades) = get(trades, deadline)?;
    let average_rate = average_rate(&trades, trade_window, amount)?;
    if Instant::now() >= deadline || !fresh(closed, OffsetDateTime::now_utc().unix_timestamp()) {
        return None;
    }
    Some(PriceObservation {
        path_rate,
        book_rate,
        average_rate,
        path_ledger,
        book_ledger,
        trade_window,
        source: origin,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const ISSUED: &str = "USD:GDUKMGUGDZQK6YHYA5Z6AY2G4XDSZPSZ3SW5UN3ARVMO6QSRDWP5YLEX";

    #[test]
    fn rejects_unrecognized_network_and_asset_identities_before_requesting() {
        assert!(observe_price("solana:mainnet", "native", ISSUED, 1).is_err());
        assert!(observe_price("stellar:pubnet", "native", "native", 1).is_err());
        assert!(observe_price("stellar:pubnet", "native", ISSUED, 0).is_err());
        assert!(Asset::parse(&ISSUED.replace("YLEX", "YLEA")).is_none());
    }

    #[test]
    fn paths_bind_the_exact_pair_and_source_amount() {
        let from = Asset::parse("native").unwrap();
        let to = Asset::parse(ISSUED).unwrap();
        let mut record = json!({
            "source_asset_type": from.kind,
            "source_amount": "1.0000000",
            "destination_asset_type": to.kind,
            "destination_asset_code": to.code,
            "destination_asset_issuer": to.issuer,
            "destination_amount": "2.2500000"
        });
        let response = |record: &Value| json!({"_embedded":{"records":[record]}});
        assert_eq!(
            path_rate(&response(&record), &from, &to, SCALE),
            Some(22_500_000)
        );
        assert_eq!(path_rate(&response(&record), &from, &to, SCALE + 1), None);
        record["destination_asset_issuer"] = json!("wrong");
        assert_eq!(path_rate(&response(&record), &from, &to, SCALE), None);
    }

    #[test]
    fn quote_sources_require_fresh_ledgers_and_completed_deep_trade_windows() {
        let ledger = json!({"sequence":42,"closed_at":"2026-11-06T00:00:00Z"});
        let closed = OffsetDateTime::parse("2026-11-06T00:00:00Z", &Rfc3339)
            .unwrap()
            .unix_timestamp();
        assert_eq!(ledger_close(&ledger, 42, closed + 30), Some(closed));
        assert_eq!(ledger_close(&ledger, 42, closed + 31), None);
        assert_eq!(ledger_close(&ledger, 42, closed - 1), None);
        assert_eq!(ledger_close(&ledger, 41, closed), None);

        let window = closed * 1000 - HOUR_MS;
        let mut trade = json!({"timestamp":window,"trade_count":"2","base_volume":"1.0000000","avg":"2.2500000"});
        let response = |trade: &Value| json!({"_embedded":{"records":[trade]}});
        assert_eq!(
            average_rate(&response(&trade), window, SCALE),
            Some(22_500_000)
        );
        assert_eq!(
            average_rate(&response(&trade), window + HOUR_MS, SCALE),
            None
        );
        assert_eq!(average_rate(&response(&trade), window, SCALE + 1), None);
        trade["timestamp"] = json!(window.to_string());
        assert_eq!(
            average_rate(&response(&trade), window, SCALE),
            Some(22_500_000)
        );
        trade["trade_count"] = json!(1);
        assert_eq!(average_rate(&response(&trade), window, SCALE), None);
    }

    #[test]
    fn quotes_use_exact_units_and_require_depth() {
        let from = Asset::parse("native").unwrap();
        let to = Asset::parse(ISSUED).unwrap();
        let book = json!({
            "base": {"asset_type":"native"},
            "counter": {"asset_type": to.kind, "asset_code": to.code, "asset_issuer": to.issuer},
            "bids": [
                {"price_r":{"n":2,"d":1},"amount":"2.0000000"},
                {"price_r":{"n":3,"d":2},"amount":"1.5000000"}
            ]
        });
        assert_eq!(book_rate(&book, &from, &to, 20_000_000), Some(17_500_000));
        assert_eq!(book_rate(&book, &from, &to, 20_000_001), None);
        assert_eq!(decimal("0.0000001"), Some(1));
        assert_eq!(decimal("0.00000001"), None);
    }
}
