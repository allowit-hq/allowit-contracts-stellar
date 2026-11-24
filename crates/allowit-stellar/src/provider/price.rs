//! The `price` evidence function of the Stellar rail: what the order book of a pair pays now.
//!
//! A server policy calls `allowit::price` with an expected price and a band. The host asks this
//! function for one observation and applies the band itself. The observation reads the public
//! Horizon of the network, with three requests:
//!
//! 1. The root: the newest ledger that Horizon ingested and its close time. That time is the
//!    time of the observation, so a Horizon that lags gives a stale observation.
//! 2. The order book of the pair. Selling `amount` of `from` consumes its bids, best price
//!    first. The observed price is what those bids pay for the whole amount. The depth is what
//!    the bids inside the host's band buy: a bid above the band counts as little as one below.
//! 3. The newest order book trades of the pair. Their volume-weighted average is the trade
//!    average, over the trades that closed in the last [`RECENT`] seconds.
//!
//! The observation reads the direct order book only. It reads no path through another asset
//! and no liquidity pool, so a best path pays this price or more. Prices are units of `to` for
//! each unit of `from`, scaled by [`SCALE`]. Every classic asset has seven decimals, so the
//! ratio of base units is the ratio of display units.
//!
//! When `from` is a SEP-56 vault, selling its shares is a redeem, and the vault itself names the
//! price: [`observe_vault`] reads the vault's own `preview_redeem` with read-only simulations on
//! Stellar RPC. The price is then what one share pays in the vault's asset.
use super::{token_contract, tokens_for};
use crate as native;
use serde_json::{Value, json};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

/// Prices are scaled by 10^7, as in `AllowitPrice`.
pub const SCALE: i128 = 10_000_000;
/// A trade counts toward the trade average for this many seconds after its ledger closed.
pub const RECENT: u64 = 3_600;
/// Most price levels of each side that one observation reads. It is Horizon's maximum.
pub const MAX_LEVELS: usize = 200;
/// Most trades behind one trade average.
pub const MAX_TRADES: usize = 20;
/// The name that hosts look the function up by.
pub const FUNCTION: &str = "price";

/// The public Horizon of a network.
fn horizon(network: &str) -> Result<&'static str, String> {
    match network {
        "stellar:testnet" => Ok("https://horizon-testnet.stellar.org"),
        "stellar:pubnet" => Ok("https://horizon.stellar.org"),
        _ => Err(format!("no Horizon is known for {network}")),
    }
}

/// One read of Horizon: the JSON body of `path` under the endpoint of the network.
pub trait Horizon {
    fn get(&self, path: &str) -> Result<Value, String>;
    /// The host of the endpoint, for the source of the observation. Never a credential.
    fn host(&self) -> String;
}

/// A classic asset as Horizon names it in a query.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Classic {
    pub code: String,
    /// `None` for the native asset.
    pub issuer: Option<String>,
}

impl Classic {
    fn native() -> Self {
        Self {
            code: "XLM".into(),
            issuer: None,
        }
    }
    /// The query fields of this asset under `prefix`, such as `selling` or `base`.
    fn query(&self, prefix: &str) -> String {
        match &self.issuer {
            None => format!("{prefix}_asset_type=native"),
            Some(issuer) => format!(
                "{prefix}_asset_type=credit_alphanum{}&{prefix}_asset_code={}&{prefix}_asset_issuer={issuer}",
                if self.code.len() <= 4 { 4 } else { 12 },
                self.code
            ),
        }
    }
}

/// The classic asset that `asset` names on `network`: `native`, `CODE:ISSUER`, the code of a
/// listed token, or a Stellar Asset Contract id of the native asset or of a listed token. The
/// contract id of another asset does not tell its code and issuer, so it names no order book.
pub fn classic(network: &str, asset: &str) -> Result<Classic, String> {
    if asset == "native" || native::sac_address(network, &native::Asset::Native)? == asset {
        return Ok(Classic::native());
    }
    if let Some((code, issuer)) = asset.split_once(':') {
        native::asset_from_identity(code, Some(issuer))?;
        return Ok(Classic {
            code: code.into(),
            issuer: Some(issuer.into()),
        });
    }
    tokens_for(network)
        .iter()
        .find(|token| {
            token.code == asset || token_contract(network, token).as_deref() == Some(asset)
        })
        .map(|token| match token.issuer {
            Some(issuer) => Classic {
                code: token.code.into(),
                issuer: Some(issuer.into()),
            },
            None => Classic::native(),
        })
        .ok_or_else(|| {
            format!(
                "{asset} names no asset whose order book this rail can read; name it as CODE:ISSUER"
            )
        })
}

/// One observation, in the shape that hosts read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Observation {
    /// What the bids pay for the whole amount, or for the part that they fill.
    pub price: i128,
    /// Units of `from` that the bids inside the band fill: at or above its lower bound and at
    /// or below its upper bound. Without a band, every bid counts.
    pub depth: i128,
    /// Volume-weighted average price of the recent trades. Zero without one.
    pub trade_average: i128,
    pub trades: u32,
    /// Close time of the newest ledger that Horizon ingested, or that RPC read for a vault.
    pub observed_at: u64,
    pub source: String,
    /// The facts of a vault observation; `None` for an order book.
    pub vault: Option<VaultFacts>,
}

/// What a vault observation adds: the vault's asset, its share decimals, the share units that
/// the price is for, and the position of a holder when the host asks for one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultFacts {
    /// The contract id of the vault's asset.
    pub asset: String,
    /// The asset's code when this rail lists it, such as `XLM`.
    pub asset_code: Option<String>,
    pub share_decimals: u32,
    /// The share units that `price` and `paid` are for.
    pub shares: i128,
    /// What redeeming `shares` pays now, in asset base units.
    pub paid: i128,
    /// The holder's share units and what redeeming them pays now.
    pub held: Option<(i128, i128)>,
}

impl Observation {
    pub fn to_json(&self) -> Value {
        let mut out = json!({
            "price": self.price.to_string(),
            "depth": self.depth.to_string(),
            "tradeAverage": self.trade_average.to_string(),
            "trades": self.trades,
            "observedAt": self.observed_at,
            "source": self.source,
        });
        if let Some(v) = &self.vault {
            out["vault"] = json!({
                "asset": v.asset,
                "assetCode": v.asset_code,
                "shareDecimals": v.share_decimals,
                "shares": v.shares.to_string(),
                "paid": v.paid.to_string(),
            });
            if let Some((held, value)) = v.held {
                out["vault"]["held"] = held.to_string().into();
                out["vault"]["heldValue"] = value.to_string().into();
            }
        }
        out
    }
}

/// Base units of a Horizon amount: decimal text with at most seven decimals.
fn units(text: &str) -> Result<i128, String> {
    let invalid = || "Invalid Horizon amount".to_string();
    let (whole, fraction) = text.split_once('.').unwrap_or((text, ""));
    if whole.is_empty()
        || fraction.len() > 7
        || !whole
            .bytes()
            .chain(fraction.bytes())
            .all(|b| b.is_ascii_digit())
    {
        return Err(invalid());
    }
    let whole: i128 = whole.parse().map_err(|_| invalid())?;
    let fraction: i128 = format!("{fraction:0<7}").parse().map_err(|_| invalid())?;
    whole
        .checked_mul(SCALE)
        .and_then(|value| value.checked_add(fraction))
        .ok_or_else(invalid)
}

/// A positive integer that Horizon writes as a number or as decimal text.
fn positive(value: &Value) -> Result<i128, String> {
    value
        .as_i64()
        .map(i128::from)
        .or_else(|| value.as_str().and_then(|text| text.parse().ok()))
        .filter(|value| *value > 0)
        .ok_or_else(|| "Invalid Horizon price".to_string())
}

fn seconds(text: &str) -> Result<u64, String> {
    OffsetDateTime::parse(text, &Rfc3339)
        .ok()
        .and_then(|time| u64::try_from(time.unix_timestamp()).ok())
        .ok_or_else(|| "Invalid Horizon time".to_string())
}

/// `a * b / c`, rounded down. An overflow is an error and never a wrapped value.
fn scaled(a: i128, b: i128, c: i128) -> Result<i128, String> {
    a.checked_mul(b)
        .and_then(|product| product.checked_div(c))
        .ok_or_else(|| "The price observation overflows".to_string())
}

/// The expected price and the largest deviation in basis points, when the host states them.
pub type Band = Option<(i128, u32)>;

/// Observe what selling `amount` base units of `from` for `to` pays on `network`.
pub fn observe(
    horizon: &dyn Horizon,
    network: &str,
    from: &str,
    to: &str,
    amount: i128,
    band: Band,
) -> Result<Observation, String> {
    if amount <= 0 {
        return Err("A price observation needs a positive amount".into());
    }
    let (from, to) = (classic(network, from)?, classic(network, to)?);
    if from == to {
        return Err("A price observation needs two assets".into());
    }
    let root = horizon.get("/")?;
    let ledger = root["history_latest_ledger"]
        .as_u64()
        .ok_or("Invalid Horizon root")?;
    let observed_at = seconds(
        root["history_latest_ledger_closed_at"]
            .as_str()
            .ok_or("Invalid Horizon root")?,
    )?;

    // Selling `from` consumes the bids: offers that sell `to` for `from`. Horizon lists them
    // best price first, each with the amount of `to` that it sells.
    let book = horizon.get(&format!(
        "/order_book?{}&{}&limit={MAX_LEVELS}",
        from.query("selling"),
        to.query("buying")
    ))?;
    let bids = book["bids"]
        .as_array()
        .ok_or("Invalid Horizon order book")?;
    let (mut remaining, mut paid, mut depth) = (amount, 0i128, 0i128);
    let mut last: Option<(i128, i128)> = None;
    for bid in bids.iter().take(MAX_LEVELS) {
        let (n, d) = (
            positive(&bid["price_r"]["n"])?,
            positive(&bid["price_r"]["d"])?,
        );
        // A book whose bids are not in price order is not one that this function can walk.
        if let Some((last_n, last_d)) = last
            && n.checked_mul(last_d) > last_n.checked_mul(d)
        {
            return Err("Invalid Horizon order book".into());
        }
        last = Some((n, d));
        let sells = units(bid["amount"].as_str().ok_or("Invalid Horizon order book")?)?;
        // Units of `from` that this bid buys.
        let fills = scaled(sells, d, n)?;
        let inside = match band {
            // The band is `expected` plus or minus `slip` basis points, and the price of this
            // bid is n / d * SCALE. A bid above the band is no more inside it than one below.
            Some((expected, slip)) => {
                let price = n
                    .checked_mul(SCALE)
                    .and_then(|value| value.checked_mul(10_000));
                let bound = |points: i128| {
                    expected
                        .checked_mul(points)
                        .and_then(|value| value.checked_mul(d))
                };
                let slip = i128::from(slip.min(10_000));
                matches!(
                    (price, bound(10_000 - slip), bound(10_000 + slip)),
                    (Some(price), Some(floor), Some(ceiling)) if price >= floor && price <= ceiling
                )
            }
            None => true,
        };
        if inside {
            depth = depth
                .checked_add(fills)
                .ok_or("The price observation overflows")?;
        }
        let take = remaining.min(fills);
        paid = paid
            .checked_add(scaled(take, n, d)?)
            .ok_or("The price observation overflows")?;
        remaining -= take;
    }
    let filled = amount - remaining;
    if filled == 0 {
        return Err("The order book of the pair holds no bid".into());
    }
    let price = scaled(paid, SCALE, filled)?;

    let trades = horizon.get(&format!(
        "/trades?{}&{}&trade_type=orderbook&order=desc&limit={MAX_TRADES}",
        from.query("base"),
        to.query("counter")
    ))?;
    let records = trades["_embedded"]["records"]
        .as_array()
        .ok_or("Invalid Horizon trades")?;
    let (mut sold, mut bought, mut count) = (0i128, 0i128, 0u32);
    for trade in records.iter().take(MAX_TRADES) {
        let closed = seconds(
            trade["ledger_close_time"]
                .as_str()
                .ok_or("Invalid Horizon trades")?,
        )?;
        // Horizon can ingest a ledger between the root request and this one. A trade of that
        // newer ledger is recent too.
        if observed_at.saturating_sub(closed) > RECENT {
            continue;
        }
        let amount = |name: &str| units(trade[name].as_str().ok_or("Invalid Horizon trades")?);
        sold = sold
            .checked_add(amount("base_amount")?)
            .ok_or("The price observation overflows")?;
        bought = bought
            .checked_add(amount("counter_amount")?)
            .ok_or("The price observation overflows")?;
        count += 1;
    }
    let trade_average = if sold > 0 {
        scaled(bought, SCALE, sold)?
    } else {
        0
    };
    Ok(Observation {
        price,
        depth,
        trade_average,
        trades: count,
        observed_at,
        source: format!("{} ledger {ledger}", horizon.host()),
        vault: None,
    })
}

/// The public Stellar RPC of a network. Mainnet has no public endpoint of the network's own;
/// a host names one in its facts.
fn public_rpc(network: &str) -> Result<&'static str, String> {
    match network {
        "stellar:testnet" => Ok("https://soroban-testnet.stellar.org"),
        _ => Err(format!(
            "no public Stellar RPC is known for {network}; the host names one as `rpc`"
        )),
    }
}

/// Whether `asset` names a contract that is not the asset contract of a classic asset that this
/// rail knows: a vault, for this function.
pub fn is_vault(network: &str, asset: &str) -> bool {
    stellar_strkey::Contract::from_string(asset).is_ok() && classic(network, asset).is_err()
}

/// One value that a read-only simulation of `function` on `vault` returns.
fn vault_read(
    rpc: &dyn crate::rpc::Rpc,
    network: &str,
    vault: &str,
    function: &str,
    args: Vec<stellar_xdr::ScVal>,
) -> Result<(stellar_xdr::ScVal, u32), String> {
    crate::rpc::contract_read(rpc, network, vault, function, args)
        .map_err(|e| format!("The vault {vault} gave no {function}: {e}"))
}

/// Observe what redeeming `shares` share units of the SEP-56 vault `vault` pays now, with the
/// vault's own `preview_redeem`; without `shares`, one whole share. `to`, when given, must be the
/// vault's asset. With `holder`, the observation adds the holder's shares and what they pay.
/// The vault fills any amount at its one price, so the depth is the whole amount when the price
/// is inside the band. A vault has no trades. The price is what one share pays in display
/// units, scaled by [`SCALE`].
pub fn observe_vault(
    rpc: &dyn crate::rpc::Rpc,
    network: &str,
    vault: &str,
    to: Option<&str>,
    shares: Option<i128>,
    band: Band,
    holder: Option<&str>,
) -> Result<Observation, String> {
    use stellar_xdr::ScVal;
    let (asset, _) = vault_read(rpc, network, vault, "query_asset", vec![])?;
    let ScVal::Address(asset) = asset else {
        return Err(format!("The vault {vault} names no asset"));
    };
    let asset = native::address_text(&asset)?;
    let listed = |code: &str| {
        let classic = classic(network, code).ok()?;
        let identity = match &classic.issuer {
            None => native::Asset::Native,
            Some(issuer) => native::asset_from_identity(&classic.code, Some(issuer)).ok()?,
        };
        Some((classic.code, native::sac_address(network, &identity).ok()?))
    };
    if let Some(to) = to {
        let (_, expected) =
            listed(to).ok_or_else(|| format!("{to} names no asset of this rail"))?;
        if expected != asset {
            return Err(format!("The vault {vault} holds {asset}, not {to}"));
        }
    }
    let asset_code = listed(&asset).map(|(code, _)| code);
    let (decimals, _) = vault_read(rpc, network, vault, "decimals", vec![])?;
    let share_decimals = match decimals {
        ScVal::U32(d) if d <= 18 => d,
        _ => return Err(format!("The vault {vault} names no share decimals")),
    };
    let one = 10i128.pow(share_decimals);
    let shares = shares.unwrap_or(one);
    if shares <= 0 {
        return Err("A price observation needs a positive amount".into());
    }
    let value = |units: i128| -> Result<(i128, u32), String> {
        let (paid, ledger) = vault_read(
            rpc,
            network,
            vault,
            "preview_redeem",
            vec![native::i128_value(units)],
        )?;
        let paid = native::rpc::wide(&paid)?;
        if paid < 0 {
            return Err(format!("The vault {vault} values its shares below zero"));
        }
        Ok((paid, ledger))
    };
    let (paid, ledger) = value(shares)?;
    // What one share pays, in display units: the asset has seven decimals, as every Stellar asset
    // contract does, and a share has the vault's decimals.
    let price = scaled(paid, one, shares)?;
    let inside = match band {
        Some((expected, slip)) => {
            let slip = i128::from(slip.min(10_000));
            let at = |points: i128| expected.checked_mul(points);
            matches!(
                (price.checked_mul(10_000), at(10_000 - slip), at(10_000 + slip)),
                (Some(p), Some(floor), Some(ceiling)) if p >= floor && p <= ceiling
            )
        }
        None => true,
    };
    let held = match holder {
        Some(holder) => {
            let (balance, _) = vault_read(
                rpc,
                network,
                vault,
                "balance",
                vec![ScVal::Address(native::address(holder)?)],
            )?;
            let held = native::rpc::wide(&balance)?;
            let worth = if held > 0 { value(held)?.0 } else { 0 };
            Some((held, worth))
        }
        None => None,
    };
    let head = rpc
        .call("getLatestLedger", json!({}))
        .map_err(|e| format!("Stellar RPC gave no ledger time: {e}"))?;
    let observed_at = head["closeTime"]
        .as_str()
        .and_then(|t| t.parse().ok())
        .or_else(|| head["closeTime"].as_u64())
        .ok_or("Stellar RPC gave no ledger time")?;
    Ok(Observation {
        price,
        depth: if inside { shares } else { 0 },
        trade_average: 0,
        trades: 0,
        observed_at,
        source: format!("{vault} preview_redeem at ledger {ledger}"),
        vault: Some(VaultFacts {
            asset,
            asset_code,
            share_decimals,
            shares,
            paid,
            held,
        }),
    })
}

/// The public Horizon of a network over the bounded host transport.
#[cfg(not(target_arch = "wasm32"))]
struct Public(&'static str);

#[cfg(not(target_arch = "wasm32"))]
impl Horizon for Public {
    fn get(&self, path: &str) -> Result<Value, String> {
        use allowit_core::transport::{
            http::{HttpClient, Method, Request},
            rpc::Options,
        };
        let client = HttpClient::new(Options {
            timeout: std::time::Duration::from_secs(5),
            max_response_bytes: 1_048_576,
            no_proxy: false,
            connect_timeout: None,
        })
        .map_err(|_| "Cannot initialize the Horizon transport")?;
        let url = format!("{}{path}", self.0);
        let response = client
            .send_success_body(
                Request {
                    method: Method::Get,
                    url: &url,
                    headers: &[("accept".to_string(), "application/json".to_string())],
                    body: None,
                },
                None,
            )
            .map_err(|_| "Horizon did not answer")?;
        if response.status != 200 {
            return Err(format!("Horizon answered HTTP {}", response.status));
        }
        serde_json::from_slice(&response.body).map_err(|_| "Invalid Horizon response".into())
    }
    fn host(&self) -> String {
        self.0.trim_start_matches("https://").to_owned()
    }
}

/// The evidence function. `args` are `{"network", "from", "to", "amount"}` and, when the host
/// states its band, `"price"` and `"slip"`. Amounts and prices are decimal text. `facts` are
/// the host's own: its `network` is the network that the policy runs for, and it decides.
/// When `from` is a SEP-56 vault, `to` and `amount` (share units) are optional, `"holder"` asks
/// for that holder's position, and the host may name its Stellar RPC as `facts.rpc`.
#[cfg(not(target_arch = "wasm32"))]
pub fn price(args: &Value, facts: &Value) -> Result<Value, String> {
    let text = |name: &str| {
        args[name]
            .as_str()
            .ok_or_else(|| format!("A price observation needs `{name}`"))
    };
    let network = match (facts["network"].as_str(), args["network"].as_str()) {
        (Some(host), Some(asked)) if host != asked => {
            return Err("A price observation is for the network of its policy".into());
        }
        (Some(network), _) | (None, Some(network)) => network,
        (None, None) => return Err("A price observation needs `network`".into()),
    };
    let band = match (args["price"].as_str(), args["slip"].as_u64()) {
        (Some(price), Some(slip)) => Some((
            price
                .parse::<i128>()
                .ok()
                .filter(|price| *price > 0)
                .ok_or("A price band needs a positive decimal `price`")?,
            u32::try_from(slip)
                .ok()
                .filter(|slip| *slip <= 10_000)
                .ok_or("A price band needs `slip` in basis points")?,
        )),
        _ => None,
    };
    let amount = |required: bool| -> Result<Option<i128>, String> {
        match args["amount"].as_str() {
            Some(text) => text
                .parse()
                .map(Some)
                .map_err(|_| "A price observation needs a decimal `amount`".into()),
            None if required => Err("A price observation needs `amount`".into()),
            None => Ok(None),
        }
    };
    let from = text("from")?;
    if is_vault(network, from) {
        // A vault: `to` and `amount` are optional, `holder` asks for a position, and the host
        // may name its own Stellar RPC.
        let endpoint = match facts["rpc"].as_str() {
            Some(endpoint) => endpoint,
            None => public_rpc(network)?,
        };
        let rpc = crate::rpc::HttpRpc::new(endpoint)?;
        let observed = observe_vault(
            &rpc,
            network,
            from,
            args["to"].as_str(),
            amount(false)?,
            band,
            args["holder"].as_str(),
        )?;
        return Ok(observed.to_json());
    }
    let observed = observe(
        &Public(horizon(network)?),
        network,
        from,
        text("to")?,
        amount(true)?.unwrap_or_default(),
        band,
    )?;
    Ok(observed.to_json())
}

#[cfg(test)]
mod tests {
    use super::*;

    const NETWORK: &str = "stellar:testnet";
    const USDC: &str = "USDC:GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";

    /// Recorded answers of the public Testnet Horizon, by request path.
    struct Recorded {
        answers: Vec<(&'static str, Value)>,
        asked: std::cell::RefCell<Vec<String>>,
    }
    impl Recorded {
        fn new(root: &str, book: &str, trades: &str) -> Self {
            let json = |text: &str| serde_json::from_str(text).unwrap();
            Self {
                answers: vec![
                    ("/order_book", json(book)),
                    ("/trades", json(trades)),
                    ("/", json(root)),
                ],
                asked: Default::default(),
            }
        }
    }
    impl Horizon for Recorded {
        fn get(&self, path: &str) -> Result<Value, String> {
            self.asked.borrow_mut().push(path.to_owned());
            self.answers
                .iter()
                .find(|(prefix, _)| path.starts_with(prefix))
                .map(|(_, answer)| answer.clone())
                .ok_or_else(|| "no recorded answer".to_string())
        }
        fn host(&self) -> String {
            "horizon-testnet.stellar.org".into()
        }
    }

    /// XLM and USDC on Testnet at ledger 5735831: a book with bids near 0.147 USDC, and
    /// order book trades that closed six hours before.
    fn quiet() -> Recorded {
        Recorded::new(
            include_str!("price_fixtures/quiet/root.json"),
            include_str!("price_fixtures/quiet/order_book.json"),
            include_str!("price_fixtures/quiet/trades.json"),
        )
    }

    /// The same pair at ledger 5736249, after an account of the Testnet proof sold 10 XLM into
    /// the best bid three times, 15 to 35 seconds before that ledger.
    fn traded() -> Recorded {
        Recorded::new(
            include_str!("price_fixtures/own/root.json"),
            include_str!("price_fixtures/own/order_book.json"),
            include_str!("price_fixtures/own/trades.json"),
        )
    }

    /// A market with recent trades gives what a host admits: a price and a trade average
    /// inside a 2% band, three trades of the last hour and enough depth inside the band.
    #[test]
    fn recent_trades_give_a_trade_average_beside_the_book_price() {
        let observed = observe(
            &traded(),
            NETWORK,
            "native",
            USDC,
            2_500_000,
            Some((1_469_302, 200)),
        )
        .unwrap();
        // Each trade sold 9.9999998 XLM for 1.4693018 USDC, at the best bid of 2000000/13611907.
        assert_eq!((observed.trades, observed.trade_average), (3, 1_469_301));
        // 0.25 XLM pays 367325 base units of USDC, rounded down.
        assert_eq!(observed.price, 1_469_300);
        assert_eq!(observed.observed_at, 1_794_704_890);
        assert_eq!(
            observed.source,
            "horizon-testnet.stellar.org ledger 5736249"
        );
        // The five best bids are inside the band; the sixth pays less than 98% of the price.
        assert!(observed.depth > 2_500_000);
        assert!(
            observed.depth
                < observe(&traded(), NETWORK, "native", USDC, 1, None)
                    .unwrap()
                    .depth
        );
    }

    #[test]
    fn an_asset_is_named_by_its_identity_a_listed_code_or_its_contract() {
        let usdc = Classic {
            code: "USDC".into(),
            issuer: Some(USDC.split_once(':').unwrap().1.into()),
        };
        let native_contract = native::sac_address(NETWORK, &native::Asset::Native).unwrap();
        let usdc_contract = token_contract(NETWORK, &tokens_for(NETWORK)[1]).unwrap();
        for (asset, expected) in [
            ("native", Classic::native()),
            ("XLM", Classic::native()),
            (native_contract.as_str(), Classic::native()),
            ("USDC", usdc.clone()),
            (USDC, usdc.clone()),
            (usdc_contract.as_str(), usdc.clone()),
        ] {
            assert_eq!(classic(NETWORK, asset).unwrap(), expected, "{asset}");
        }
        assert_eq!(
            usdc.query("buying"),
            format!(
                "buying_asset_type=credit_alphanum4&buying_asset_code=USDC&buying_asset_issuer={}",
                usdc.issuer.as_deref().unwrap()
            )
        );
        assert_eq!(Classic::native().query("base"), "base_asset_type=native");
        // A contract that is not listed, a bad issuer and free text name no order book.
        for asset in [
            "CAS3J7GYLGXMF6TDJBBYYSE3HQ6BBSMLNUQ34T6TZMYMW2EVH34XOWMA",
            "USDC:GBAD",
            "dollars",
        ] {
            assert!(classic(NETWORK, asset).is_err(), "{asset}");
        }
    }

    #[test]
    fn the_bids_price_the_whole_amount_best_price_first() {
        let horizon = quiet();
        // 100 XLM: the best bid pays 2000000/13611907 USDC for each XLM and buys 886 XLM.
        let small = observe(&horizon, NETWORK, "native", USDC, 1_000_000_000, None).unwrap();
        assert_eq!(small.price, 1_469_301);
        assert_eq!(small.observed_at, 1_794_702_800);
        assert_eq!(small.source, "horizon-testnet.stellar.org ledger 5735831");
        // The recorded trades closed six hours before the ledger: none is recent.
        assert_eq!((small.trades, small.trade_average), (0, 0));
        assert_eq!(
            *horizon.asked.borrow(),
            [
                "/".to_string(),
                format!(
                    "/order_book?selling_asset_type=native&buying_asset_type=credit_alphanum4&buying_asset_code=USDC&buying_asset_issuer={}&limit=200",
                    USDC.split_once(':').unwrap().1
                ),
                format!(
                    "/trades?base_asset_type=native&counter_asset_type=credit_alphanum4&counter_asset_code=USDC&counter_asset_issuer={}&trade_type=orderbook&order=desc&limit=20",
                    USDC.split_once(':').unwrap().1
                ),
            ]
        );
        // A larger amount reaches worse bids, so it gets a lower price.
        let large = observe(&horizon, NETWORK, "native", USDC, 20_000_000_000, None).unwrap();
        assert!(large.price < small.price && large.price > 1_400_000);
        // The depth is the book, whatever the amount.
        assert_eq!(large.depth, small.depth);
        assert!(small.depth > 20_000_000_000);
    }

    #[test]
    fn the_depth_counts_only_the_bids_inside_the_band() {
        let horizon = quiet();
        let within = |slip| {
            observe(
                &horizon,
                NETWORK,
                "native",
                USDC,
                1_000_000_000,
                Some((1_469_301, slip)),
            )
            .unwrap()
            .depth
        };
        let all = observe(&horizon, NETWORK, "native", USDC, 1_000_000_000, None)
            .unwrap()
            .depth;
        // One basis point: only the best level, 130.2207151 USDC at 2000000/13611907. No bid
        // pays exactly the expected price, so no deviation at all leaves no depth.
        assert_eq!(within(1), 1_302_207_151 * 13_611_907 / 2_000_000);
        assert_eq!(within(0), 0);
        assert!(within(1) < within(100) && within(100) < within(1_000));
        assert_eq!(within(10_000), all);
    }

    /// A book and trades that the test states: bids of `(n, d, amount of to)`, and trades of
    /// `(close time, base amount, counter amount)`, at ledger 7 closed at 00:17:40.
    fn stated(bids: &[(i64, i64, &str)], trades: &[(&str, &str, &str)]) -> Recorded {
        let bids: Vec<Value> = bids
            .iter()
            .map(|(n, d, amount)| json!({"price_r": {"n": n, "d": d}, "amount": amount}))
            .collect();
        let trades: Vec<Value> = trades
            .iter()
            .map(|(closed, base, counter)| {
                json!({"ledger_close_time": closed, "base_amount": base, "counter_amount": counter})
            })
            .collect();
        Recorded {
            answers: vec![
                ("/order_book", json!({"bids": bids, "asks": []})),
                ("/trades", json!({"_embedded": {"records": trades}})),
                (
                    "/",
                    json!({"history_latest_ledger": 7,
                        "history_latest_ledger_closed_at": "2026-11-14T18:17:40Z"}),
                ),
            ],
            asked: Default::default(),
        }
    }

    /// A bid above the band is outside it. Five units at 2 and a hundred at 0.9 give an average
    /// inside a band of 1 plus or minus 10% for 105 units, and only the hundred are inside it.
    #[test]
    fn a_bid_above_the_band_adds_no_depth() {
        let horizon = stated(&[(2, 1, "10"), (9, 10, "90")], &[]);
        let observed = observe(
            &horizon,
            NETWORK,
            "native",
            USDC,
            105 * SCALE,
            Some((SCALE, 1_000)),
        )
        .unwrap();
        assert_eq!(observed.price, 9_523_809);
        assert_eq!(observed.depth, 100 * SCALE);
        // The bounds themselves are inside: 0.9 and 1.1 with 10%.
        let edges = stated(&[(11, 10, "11"), (9, 10, "9")], &[]);
        let observed =
            observe(&edges, NETWORK, "native", USDC, SCALE, Some((SCALE, 1_000))).unwrap();
        assert_eq!(observed.depth, 20 * SCALE);
    }

    /// The trade average is the volume-weighted price of the trades of the last hour. A trade
    /// of a ledger that Horizon ingested after the root request counts too.
    #[test]
    fn the_trade_average_counts_the_last_hour_and_a_newer_ledger() {
        let horizon = stated(
            &[(1, 1, "100")],
            &[
                // A newer ledger than the one that the root named.
                ("2026-11-14T18:17:45Z", "10", "11"),
                ("2026-11-14T18:17:40Z", "10", "10"),
                ("2026-11-14T17:17:40Z", "20", "19"),
                // One second more than an hour before the ledger.
                ("2026-11-14T17:17:39Z", "1000", "1"),
            ],
        );
        let observed = observe(&horizon, NETWORK, "native", USDC, SCALE, None).unwrap();
        assert_eq!(observed.trades, 3);
        assert_eq!(observed.trade_average, 10_000_000);
        assert_eq!(observed.observed_at, 1_794_680_260);
    }

    #[test]
    fn an_amount_beyond_the_book_reports_the_depth_that_exists() {
        let horizon = quiet();
        let all = observe(&horizon, NETWORK, "native", USDC, 1, None)
            .unwrap()
            .depth;
        let beyond = observe(&horizon, NETWORK, "native", USDC, all + 1, None).unwrap();
        // The host compares the depth with the amount and denies a thin market.
        assert_eq!(beyond.depth, all);
        assert!(beyond.price > 0);
    }

    #[test]
    fn a_broken_or_empty_answer_is_no_observation() {
        let with = |change: fn(&mut Recorded)| {
            let mut horizon = quiet();
            change(&mut horizon);
            observe(&horizon, NETWORK, "native", USDC, 1_000_000_000, None)
        };
        assert!(with(|_| {}).is_ok());
        assert_eq!(
            with(|h| h.answers[0].1["bids"] = json!([])).unwrap_err(),
            "The order book of the pair holds no bid"
        );
        assert!(with(|h| h.answers[0].1["bids"][0]["amount"] = json!("1.23456789")).is_err());
        assert!(with(|h| h.answers[0].1["bids"][0]["price_r"]["n"] = json!(0)).is_err());
        // The second bid pays more than the first: the book is not in price order.
        assert!(with(|h| h.answers[0].1["bids"][1]["price_r"]["d"] = json!(1)).is_err());
        assert!(
            with(|h| h.answers[2].1["history_latest_ledger_closed_at"] = json!("now")).is_err()
        );
        assert!(with(|h| h.answers[1].1 = json!({})).is_err());
        assert!(with(|h| h.answers.clear()).is_err());
        // The amount and the pair.
        let horizon = quiet();
        assert!(observe(&horizon, NETWORK, "native", USDC, 0, None).is_err());
        assert!(observe(&horizon, NETWORK, "native", "XLM", 1, None).is_err());
    }

    #[test]
    fn amounts_are_exact_base_units() {
        assert_eq!(units("130.2207151").unwrap(), 1_302_207_151);
        assert_eq!(units("5").unwrap(), 50_000_000);
        assert_eq!(units("0.1").unwrap(), 1_000_000);
        for text in ["", ".5", "1.12345678", "-1", "1e3", "1,5"] {
            assert!(units(text).is_err(), "{text}");
        }
    }

    #[test]
    fn the_function_refuses_arguments_before_any_request() {
        let facts = json!({"network": NETWORK, "now": 1});
        for args in [
            json!({"network": "stellar:pubnet", "from": "native", "to": USDC, "amount": "1"}),
            json!({"network": NETWORK, "from": "native", "to": USDC}),
            json!({"network": NETWORK, "from": "native", "to": USDC, "amount": 1}),
            json!({"network": NETWORK, "from": "native", "to": "native", "amount": "1"}),
            json!({"network": NETWORK, "from": "native", "to": USDC, "amount": "1",
                "price": "0", "slip": 100}),
            json!({"network": NETWORK, "from": "native", "to": USDC, "amount": "1",
                "price": "1", "slip": 10_001}),
        ] {
            assert!(price(&args, &facts).is_err(), "{args}");
        }
        assert!(
            price(
                &json!({"from": "native", "to": USDC, "amount": "1"}),
                &json!({})
            )
            .is_err()
        );
        assert!(horizon("stellar:futurenet").is_err());
    }

    /// A Stellar RPC that answers read-only simulations of a priced SEP-56 vault: each function
    /// by name, with the shares worth `price` asset units for each whole share.
    struct VaultRpc {
        asset: String,
        price: i128,
        held: i128,
        auth: bool,
        restore: bool,
        asked: std::sync::Mutex<Vec<String>>,
    }
    impl VaultRpc {
        fn new(price: i128) -> Self {
            Self {
                asset: native::sac_address(NETWORK, &native::Asset::Native).unwrap(),
                price,
                held: 0,
                auth: false,
                restore: false,
                asked: Default::default(),
            }
        }
    }
    impl crate::rpc::Rpc for VaultRpc {
        fn call(&self, method: &str, params: Value) -> native::Result<Value> {
            use stellar_xdr::{HostFunction, OperationBody, ScVal, TransactionEnvelope};
            match method {
                "getNetwork" => Ok(json!({"passphrase": native::passphrase(NETWORK)?})),
                "getLatestLedger" => Ok(json!({"sequence": 101, "closeTime": "1795003303"})),
                "simulateTransaction" => {
                    let TransactionEnvelope::Tx(envelope) =
                        native::read(params["transaction"].as_str().unwrap())?
                    else {
                        panic!("a version 1 envelope");
                    };
                    assert_eq!(
                        envelope.tx.source_account,
                        native::muxed(crate::rpc::NULL_ACCOUNT).unwrap()
                    );
                    let OperationBody::InvokeHostFunction(op) = &envelope.tx.operations[0].body
                    else {
                        panic!("one contract call");
                    };
                    let HostFunction::InvokeContract(call) = &op.host_function else {
                        panic!("one contract call");
                    };
                    let function = String::from_utf8(call.function_name.0.to_vec()).unwrap();
                    self.asked.lock().unwrap().push(function.clone());
                    let units = |v: &ScVal| native::rpc::wide(v).unwrap();
                    let value = match function.as_str() {
                        "query_asset" => ScVal::Address(native::address(&self.asset)?),
                        "decimals" => ScVal::U32(7),
                        "preview_redeem" => {
                            native::i128_value(units(&call.args[0]) * self.price / SCALE)
                        }
                        "balance" => native::i128_value(self.held),
                        other => panic!("unexpected read {other}"),
                    };
                    let auth: Vec<String> = if self.auth {
                        vec!["AAAA".into()]
                    } else {
                        vec![]
                    };
                    let mut reply = json!({
                        "latestLedger": 100,
                        "results": [{"auth": auth, "xdr": native::xdr(&value)?}],
                    });
                    if self.restore {
                        reply["restorePreamble"] = json!({"transactionData": "AAAA"});
                    }
                    Ok(reply)
                }
                other => panic!("unexpected RPC method {other}"),
            }
        }
    }
    fn vault_id() -> String {
        stellar_strkey::Contract([7; 32]).to_string()
    }

    #[test]
    fn a_vault_names_what_one_share_pays_now() {
        let rpc = VaultRpc::new(9_400_000);
        let seen =
            observe_vault(&rpc, NETWORK, &vault_id(), Some("native"), None, None, None).unwrap();
        assert_eq!((seen.price, seen.depth, seen.trades), (9_400_000, SCALE, 0));
        assert_eq!(seen.observed_at, 1_795_003_303);
        let v = seen.vault.clone().unwrap();
        assert_eq!(
            (v.share_decimals, v.shares, v.paid, v.held),
            (7, SCALE, 9_400_000, None)
        );
        assert_eq!(
            (v.asset, v.asset_code.as_deref()),
            (rpc.asset.clone(), Some("XLM"))
        );
        let out = seen.to_json();
        assert_eq!(out["price"], "9400000");
        assert_eq!(out["vault"]["assetCode"], "XLM");
        assert!(out["vault"].get("held").is_none());
        assert!(is_vault(NETWORK, &vault_id()));
        assert!(!is_vault(NETWORK, &rpc.asset));
        assert!(!is_vault(NETWORK, "native"));
    }

    #[test]
    fn a_vault_values_a_holders_position_and_a_given_amount() {
        let mut rpc = VaultRpc::new(9_600_000);
        rpc.held = 1_000_000_000;
        let holder = stellar_strkey::ed25519::PublicKey([3; 32]).to_string();
        let seen = observe_vault(
            &rpc,
            NETWORK,
            &vault_id(),
            None,
            Some(5 * SCALE),
            None,
            Some(&holder),
        )
        .unwrap();
        let v = seen.vault.unwrap();
        assert_eq!(
            (seen.price, v.shares, v.paid),
            (9_600_000, 5 * SCALE, 48_000_000)
        );
        assert_eq!(v.held, Some((1_000_000_000, 960_000_000)));
        assert_eq!(
            rpc.asked.lock().unwrap().as_slice(),
            [
                "query_asset",
                "decimals",
                "preview_redeem",
                "balance",
                "preview_redeem"
            ]
        );
    }

    #[test]
    fn a_vault_price_inside_the_band_has_depth_and_one_outside_has_none() {
        let rpc = VaultRpc::new(9_400_000);
        let observe = |band| observe_vault(&rpc, NETWORK, &vault_id(), None, None, band, None);
        // Expected 1.0 within 5%: 0.94 is outside; within 6%, inside.
        assert_eq!(observe(Some((SCALE, 500))).unwrap().depth, 0);
        assert_eq!(observe(Some((SCALE, 600))).unwrap().depth, SCALE);
    }

    #[test]
    fn a_vault_read_that_differs_or_asks_for_more_is_refused() {
        // A vault of another asset than `to`.
        let rpc = VaultRpc::new(SCALE);
        let usdc = observe_vault(&rpc, NETWORK, &vault_id(), Some(USDC), None, None, None);
        assert!(usdc.unwrap_err().contains("not USDC:"));
        // A read that asks for an authorization, or one that needs a restoration.
        let mut rpc = VaultRpc::new(SCALE);
        rpc.auth = true;
        assert!(observe_vault(&rpc, NETWORK, &vault_id(), None, None, None, None).is_err());
        let mut rpc = VaultRpc::new(SCALE);
        rpc.restore = true;
        assert!(observe_vault(&rpc, NETWORK, &vault_id(), None, None, None, None).is_err());
        // No shares to value.
        let rpc = VaultRpc::new(SCALE);
        assert!(observe_vault(&rpc, NETWORK, &vault_id(), None, Some(0), None, None).is_err());
        // Mainnet has no public RPC: the host names one.
        assert!(public_rpc("stellar:pubnet").is_err());
    }
}
