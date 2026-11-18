//! The stored values of a policy wallet of custody layout 5, decoded as the wallet kernel
//! (`crates/policy-wallet`) packs them: positional fields, raw 32-byte keys and LEB128 integers.
//!
//! - The instance holds one value under the key `c`: a fixed header (layout, flags, deployment
//!   version, owner, agent key, server key, asset, source hash), then the gas cap, the rules and
//!   the params.
//! - `t` (persistent) holds the total figures: spent (8 bytes) and calls (31 bits) with the
//!   unpriced flag in the top bit.
//! - `d` (temporary) holds the end ledger of the daily window, then the kept daily figures.
use crate::policy::{PolicyParams, PolicyValue, param_keys};
use crate::{Result, account_for_public_key};

/// The custody layout that this crate reads and writes.
pub const LAYOUT: u8 = 5;
const HEADER: usize = 166;
const PAUSED: u8 = 1;
const OWNER_CONTRACT: u8 = 2;
const MAX_TEXT: u128 = 256;
const MAX_ITEMS: u128 = 64;
/// Figures: the bits of the wallet's `kept` set.
pub const SPENT: u8 = 1;
pub const CALLS: u8 = 2;
pub const DAY_SPENT: u8 = 4;
pub const DAY_TOTAL: u8 = 8;
/// Every figure.
pub const ALL: u8 = SPENT | CALLS | DAY_SPENT | DAY_TOTAL;

/// The decoded configuration of a policy wallet.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Configuration {
    pub layout: u8,
    pub paused: bool,
    pub deployment_version: u32,
    pub owner: String,
    /// The agent's key as an account address. The agent needs no account.
    pub agent: String,
    /// The server's signing key as an account address.
    pub server: String,
    pub asset: String,
    pub source_hash: [u8; 32],
    pub gas_cap: i128,
    pub rules: Vec<String>,
    pub params: PolicyParams,
}

/// The figures that a policy wallet keeps, as the wallet reads them at `ledger`.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Figures {
    pub calls: u64,
    pub spent: i128,
    pub unpriced: bool,
    pub day_spent: i128,
    pub day_total: i128,
    pub day_unpriced: bool,
    /// Last ledger of the open daily window; zero when no window is open.
    pub day_ends: u32,
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|end| *end <= self.buf.len())
            .ok_or("A stored policy wallet value ends early")?;
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }
    fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn key(&mut self) -> Result<[u8; 32]> {
        Ok(self.take(32)?.try_into().expect("32 bytes"))
    }
    fn uint(&mut self) -> Result<u128> {
        let (mut value, mut shift) = (0u128, 0u32);
        loop {
            let byte = self.byte()?;
            let low = u128::from(byte & 0x7f);
            if shift > 126 || (shift == 126 && low > 3) {
                return Err("A stored policy wallet integer is too long".into());
            }
            value |= low << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
            shift += 7;
        }
    }
    fn amount(&mut self) -> Result<i128> {
        i128::try_from(self.uint()?)
            .map_err(|_| "A stored policy wallet amount is too large".into())
    }
    fn int(&mut self) -> Result<i128> {
        let value = self.uint()?;
        Ok(((value >> 1) as i128) ^ -((value & 1) as i128))
    }
    fn done(&self) -> bool {
        self.pos == self.buf.len()
    }
}

fn address(kind: u8, key: &[u8; 32]) -> Result<String> {
    match kind {
        4 => Ok(account_for_public_key(key)),
        5 => Ok(stellar_strkey::Contract(*key).to_string()),
        _ => Err("A stored policy wallet address has an unknown kind".into()),
    }
}
fn value(r: &mut Reader) -> Result<PolicyValue> {
    Ok(match r.byte()? {
        0 => PolicyValue::Int(r.int()?),
        1 => PolicyValue::Bool(false),
        2 => PolicyValue::Bool(true),
        3 => {
            let len = r.uint()?;
            if len > MAX_TEXT {
                return Err("A stored policy wallet text is too long".into());
            }
            PolicyValue::Str(
                String::from_utf8(r.take(len as usize)?.to_vec())
                    .map_err(|_| "A stored policy wallet text is not UTF-8")?,
            )
        }
        kind @ (4 | 5) => PolicyValue::Addr(address(kind, &r.key()?)?),
        6 => {
            let count = r.uint()?;
            if count > MAX_ITEMS {
                return Err("A stored policy wallet list is too long".into());
            }
            PolicyValue::List((0..count).map(|_| value(r)).collect::<Result<_>>()?)
        }
        _ => return Err("A stored policy wallet value has an unknown type".into()),
    })
}

/// The flags, version, owner and asset at the fixed header offsets, which every layout keeps.
pub struct Header {
    pub layout: u8,
    pub paused: bool,
    pub deployment_version: u32,
    pub owner: String,
    pub asset: String,
}
pub fn header(raw: &[u8]) -> Result<Header> {
    if raw.len() < HEADER {
        return Err("The stored policy wallet configuration is too short".into());
    }
    let key = |at: usize| -> [u8; 32] { raw[at..at + 32].try_into().expect("32 bytes") };
    Ok(Header {
        layout: raw[0],
        paused: raw[1] & PAUSED != 0,
        deployment_version: u32::from_be_bytes(raw[2..6].try_into().expect("4 bytes")),
        owner: address(if raw[1] & OWNER_CONTRACT != 0 { 5 } else { 4 }, &key(6))?,
        asset: address(5, &key(102))?,
    })
}

/// Decode the stored configuration of layout 5 exactly.
pub fn configuration(raw: &[u8]) -> Result<Configuration> {
    let h = header(raw)?;
    if h.layout != LAYOUT {
        return Err(format!(
            "Unsupported policy wallet layout {}; this crate reads layout {LAYOUT}",
            h.layout
        ));
    }
    let key = |at: usize| -> [u8; 32] { raw[at..at + 32].try_into().expect("32 bytes") };
    let mut r = Reader {
        buf: &raw[HEADER..],
        pos: 0,
    };
    let gas_cap = r.amount()?;
    let keys = param_keys();
    let rules = (0..r.byte()?)
        .map(|_| {
            keys.get(usize::from(r.byte()?))
                .map(|k| (*k).to_owned())
                .ok_or_else(|| "A stored rule is unknown".to_string())
        })
        .collect::<Result<Vec<_>>>()?;
    let mut params = std::collections::BTreeMap::new();
    for _ in 0..r.uint()? {
        let name = match r.byte()? {
            0xff => {
                let n = usize::from(r.byte()?);
                String::from_utf8(r.take(n)?.to_vec())
                    .map_err(|_| "A stored param key is not text")?
            }
            index => keys
                .get(usize::from(index))
                .map(|k| (*k).to_owned())
                .ok_or("A stored param key is unknown")?,
        };
        params.insert(name, value(&mut r)?);
    }
    if !r.done() {
        return Err("The stored policy wallet configuration has trailing bytes".into());
    }
    Ok(Configuration {
        layout: h.layout,
        paused: h.paused,
        deployment_version: h.deployment_version,
        owner: h.owner,
        agent: account_for_public_key(&key(38)),
        server: account_for_public_key(&key(70)),
        asset: h.asset,
        source_hash: key(134),
        gas_cap,
        rules,
        params: PolicyParams(params),
    })
}

fn put_uint(out: &mut Vec<u8>, mut value: u128) {
    loop {
        let low = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(low);
            return;
        }
        out.push(low | 0x80);
    }
}
fn put_key(out: &mut Vec<u8>, kind_account: u8, kind_contract: u8, address: &str) -> Result<()> {
    use stellar_strkey::Strkey;
    match Strkey::from_string(address).map_err(|_| "Invalid address")? {
        Strkey::PublicKeyEd25519(k) => {
            out.push(kind_account);
            out.extend(k.0);
        }
        Strkey::Contract(c) => {
            out.push(kind_contract);
            out.extend(c.0);
        }
        _ => return Err("Only account and contract addresses are stored".into()),
    }
    Ok(())
}
fn put_value(out: &mut Vec<u8>, value: &PolicyValue) -> Result<()> {
    match value {
        PolicyValue::Int(n) => {
            out.push(0);
            put_uint(out, ((n << 1) ^ (n >> 127)) as u128);
        }
        PolicyValue::Bool(flag) => out.push(if *flag { 2 } else { 1 }),
        PolicyValue::Str(text) => {
            out.push(3);
            put_uint(out, text.len() as u128);
            out.extend(text.as_bytes());
        }
        PolicyValue::Addr(address) => put_key(out, 4, 5, address)?,
        PolicyValue::List(items) => {
            out.push(6);
            put_uint(out, items.len() as u128);
            for item in items {
                put_value(out, item)?;
            }
        }
    }
    Ok(())
}
fn raw_key(address: &str) -> Result<[u8; 32]> {
    match stellar_strkey::Strkey::from_string(address).map_err(|_| "Invalid address")? {
        stellar_strkey::Strkey::PublicKeyEd25519(k) => Ok(k.0),
        stellar_strkey::Strkey::Contract(c) => Ok(c.0),
        _ => Err("Only account and contract addresses are stored".into()),
    }
}
/// Pack a configuration as the wallet kernel stores it: the exact bytes that
/// [`configuration`] reads back.
pub fn encode(c: &Configuration) -> Result<Vec<u8>> {
    let owner_contract = c.owner.starts_with('C');
    let mut out = vec![
        c.layout,
        (u8::from(c.paused) * PAUSED) | if owner_contract { OWNER_CONTRACT } else { 0 },
    ];
    out.extend(c.deployment_version.to_be_bytes());
    for address in [&c.owner, &c.agent, &c.server, &c.asset] {
        out.extend(raw_key(address)?);
    }
    out.extend(c.source_hash);
    put_uint(
        &mut out,
        u128::try_from(c.gas_cap).map_err(|_| "A negative gas cap")?,
    );
    let keys = param_keys();
    let index = |name: &str| keys.iter().position(|k| *k == name);
    out.push(u8::try_from(c.rules.len()).map_err(|_| "Too many rules")?);
    for rule in &c.rules {
        out.push(index(rule).ok_or("Unknown rule")? as u8);
    }
    put_uint(&mut out, c.params.0.len() as u128);
    for (name, value) in &c.params.0 {
        match index(name) {
            Some(i) => out.push(i as u8),
            None => {
                out.push(0xff);
                out.push(u8::try_from(name.len()).map_err(|_| "Param key too long")?);
                out.extend(name.as_bytes());
            }
        }
        put_value(&mut out, value)?;
    }
    Ok(out)
}

/// The total figures of a stored `t`, the ones that `kept` names.
pub fn totals(raw: &[u8], kept: u8, figures: &mut Figures) -> Result<()> {
    let raw: [u8; 12] = raw
        .try_into()
        .map_err(|_| "The stored total figures have another size")?;
    let calls = u32::from_be_bytes(raw[8..].try_into().expect("4 bytes"));
    if kept & SPENT != 0 {
        figures.spent = i128::from(u64::from_be_bytes(raw[..8].try_into().expect("8 bytes")));
        figures.unpriced = calls & (1 << 31) != 0;
    }
    if kept & CALLS != 0 {
        figures.calls = u64::from(calls & !(1 << 31));
    }
    Ok(())
}

/// The daily figures of a stored `d` at `ledger`: none once its window has ended, even if the
/// entry is still alive.
pub fn daily(raw: &[u8], ledger: u32, figures: &mut Figures) -> Result<()> {
    let mut r = Reader { buf: raw, pos: 0 };
    let end = u32::from_be_bytes(r.take(4)?.try_into().expect("4 bytes"));
    if ledger > end {
        return Ok(());
    }
    figures.day_ends = end;
    let mask = r.byte()?;
    figures.day_unpriced = r.byte()? & 1 != 0;
    if mask & DAY_SPENT != 0 {
        figures.day_spent = r.amount()?;
    }
    if mask & DAY_TOTAL != 0 {
        figures.day_total = r.amount()?;
    }
    if !r.done() {
        return Err("The stored daily figures have trailing bytes".into());
    }
    Ok(())
}

/// The figures that a standard wallet's rules read: a rule counts only with its param set.
pub fn standard_kept(rules: &[String], params: &PolicyParams) -> u8 {
    rules
        .iter()
        .filter(|rule| params.get(rule).is_some())
        .map(|rule| match rule.as_str() {
            "lifetime_spending_limit" => SPENT,
            "call_limit" => CALLS,
            "daily_spending_limit" => DAY_SPENT,
            "daily_volume_limit" => DAY_TOTAL,
            _ => 0,
        })
        .fold(0, |kept, figure| kept | figure)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A configuration with a pause flag, a version, a gas cap, one rule and its param decodes;
    /// a trailing byte refuses it.
    #[test]
    fn a_packed_configuration_decodes_exactly() {
        let mut raw = vec![0u8; HEADER];
        raw[0] = LAYOUT;
        raw[1] = PAUSED;
        raw[2..6].copy_from_slice(&7u32.to_be_bytes());
        raw.extend([0x80, 0x01, 1, 2, 1, 2]); // gas cap 128; rule daily_spending_limit; one param
        raw.extend([0, 0x90, 0x03]); // Int 200 (zigzag 400)
        let c = configuration(&raw).unwrap();
        assert!(c.paused);
        assert_eq!(c.deployment_version, 7);
        assert_eq!(c.gas_cap, 128);
        assert_eq!(c.rules, ["daily_spending_limit"]);
        assert_eq!(
            c.params.get("daily_spending_limit"),
            Some(&PolicyValue::Int(200))
        );
        assert_eq!(encode(&c).unwrap(), raw);
        raw.push(0);
        assert!(configuration(&raw).is_err());
    }

    #[test]
    fn figures_decode_and_an_ended_window_reads_as_zero() {
        let mut t = 250u64.to_be_bytes().to_vec();
        t.extend((3u32 | 1 << 31).to_be_bytes());
        let mut f = Figures::default();
        totals(&t, SPENT | CALLS, &mut f).unwrap();
        assert_eq!((f.spent, f.calls, f.unpriced), (250, 3, true));
        let mut only_calls = Figures::default();
        totals(&t, CALLS, &mut only_calls).unwrap();
        assert_eq!(
            (only_calls.spent, only_calls.calls, only_calls.unpriced),
            (0, 3, false)
        );
        let mut d = 500u32.to_be_bytes().to_vec();
        d.extend([DAY_SPENT, 0, 100]);
        let mut open = Figures::default();
        daily(&d, 500, &mut open).unwrap();
        assert_eq!((open.day_spent, open.day_ends), (100, 500));
        let mut ended = Figures::default();
        daily(&d, 501, &mut ended).unwrap();
        assert_eq!(ended, Figures::default());
    }
}
