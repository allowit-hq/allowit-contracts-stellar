#![no_std]
//! The policy wallet kernel shared by the Simple, Standard (Common) and Custom wallets.
//!
//! One agent path: `execute(request)` is sent by any account, usually the server's. Its first step
//! requires the wallet's own authorization; the ledger calls this contract's `__check_auth`, which
//! verifies the agent's and the server's raw Ed25519 signatures of the ledger's payload. The
//! payload binds the request, a ledger nonce and an expiration ledger. The wallet then checks the
//! request and its policy, acts with its own authority, repays the signed gas to the request's
//! payee and emits one event.
//!
//! Storage holds only what the network cannot give more cheaply:
//! - the instance: one packed configuration value (`c`);
//! - `d`, temporary: the daily figures and the ledger at which their day ends;
//! - `t`, persistent: the total figures.
//!
//! A figure exists only when an installed check reads it. A wallet whose policy has no such check
//! writes nothing for a payment.
use allowit::{
    AllowitArgs, AllowitContext, AllowitOperation, AllowitParams, AllowitRequest, AllowitRule,
    AllowitStandardState, AllowitTier, AllowitValue, DAY, RULES,
};
use allowit_wallet_protocol::{
    AllowitCosignatures, AllowitExecuted, AllowitExecutionRequest, AllowitOperationArgs,
};
use soroban_sdk::{
    Address, Bytes, BytesN, Env, Executable, IntoVal, Map, Symbol, Val, Vec,
    address_payload::AddressPayload,
    auth::{Context, InvokerContractAuthEntry},
    contracterror, contracttype,
    crypto::Hash,
    symbol_short, token,
};
mod ops;
mod pack;
use ops::*;
use pack::{Reader, Writer};

/// Custody layout of this code: the packed configuration, `d` and `t`. Release tooling refuses a
/// code change to Wasm that declares another layout.
pub const CONTRACT_VERSION: u32 = 5;
soroban_sdk::contractmeta!(key = "allowit_custody_layout", val = "5");

/// Ledgers of a daily window: the Mainnet minimum lifetime of a temporary entry, about one day.
pub const DAY_LEDGERS: u32 = 17_280;
/// Ledgers that `t` and the instance live from their creation: the Mainnet minimum lifetime of a
/// persistent entry, about 120 days.
pub const TOTAL_LEDGERS: u32 = 2_073_600;

/// Instance key of the packed configuration.
const CONFIG: Symbol = symbol_short!("c");
/// Temporary key of the daily figures.
const DAILY: Symbol = symbol_short!("d");
/// Persistent key of the total figures.
const TOTAL: Symbol = symbol_short!("t");

/// Figures. Each is stored only when an installed check reads it.
pub const SPENT: u8 = 1;
pub const CALLS: u8 = 2;
pub const DAY_SPENT: u8 = 4;
pub const DAY_TOTAL: u8 = 8;
const TOTALS: u8 = SPENT | CALLS;
/// Size of the `t` value: spent (u64) and calls (u32) with the unpriced flag in its top bit.
const TOTAL_BYTES: usize = 12;
const UNPRICED_BIT: u32 = 1 << 31;
const DAILIES: u8 = DAY_SPENT | DAY_TOTAL;
const ALL: u8 = TOTALS | DAILIES;

// Fixed header of the packed configuration. Every layout keeps these offsets, so an owner call
// reads the owner and the asset whatever the rest holds.
const H_LAYOUT: usize = 0;
const H_FLAGS: usize = 1;
const H_VERSION: usize = 2;
const H_OWNER: usize = 6;
const H_AGENT: usize = 38;
const H_SERVER: usize = 70;
const H_ASSET: usize = 102;
const H_SOURCE: usize = 134;
const HEADER: usize = 166;
const PAUSED: u8 = 1;
const OWNER_CONTRACT: u8 = 2;
/// Largest packed configuration. Core bounds params to 16 KiB of its encoded-size estimate, and
/// every packed value is smaller than its estimate.
const MAX_CONFIG: usize = 16_896;

/// Owner-signed configuration of a new wallet. The asset stays fixed after creation.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllowitPolicyConfig {
    pub owner: Address,
    /// The agent's Ed25519 key. The agent needs no account.
    pub agent: BytesN<32>,
    /// The server's Ed25519 signing key.
    pub server: BytesN<32>,
    /// The Stellar Asset Contract whose units the limits count.
    pub asset: Address,
    /// SHA-256 of the owner's full policy source, which the owner's policy signature binds.
    pub source_hash: BytesN<32>,
    /// Largest gas repayment of one request, in XLM stroops. Zero: the wallet repays nothing.
    pub gas_cap: i128,
    /// Ordered on-chain rules. Only Standard admits a nonempty list.
    pub rules: Vec<AllowitRule>,
    /// Owner params, key => value. Standard keeps the params of its rules only.
    pub params: Map<Symbol, AllowitValue>,
}

/// Complete owner update at the next deployment version. The asset, the pause and the figures
/// carry over.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllowitPolicyUpdate {
    pub deployment_version: u32,
    pub owner: Address,
    pub agent: BytesN<32>,
    pub server: BytesN<32>,
    pub source_hash: BytesN<32>,
    pub gas_cap: i128,
    pub rules: Vec<AllowitRule>,
    pub params: Map<Symbol, AllowitValue>,
    /// New wallet code, or none.
    pub wasm_hash: Option<BytesN<32>>,
}

/// The cumulated figures and the ledger at which the daily ones end. Read-only view.
#[contracttype]
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AllowitFigures {
    pub calls: u64,
    pub spent: i128,
    pub unpriced: bool,
    pub day_spent: i128,
    pub day_total: i128,
    pub day_unpriced: bool,
    /// Last ledger of the current daily window; zero when no window is open.
    pub day_ends: u32,
}

/// Read-only view of the stored wallet.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllowitState {
    pub contract_version: u32,
    pub owner: Address,
    pub agent: BytesN<32>,
    pub server: BytesN<32>,
    pub asset: Address,
    pub deployment_version: u32,
    pub paused: bool,
    pub source_hash: BytesN<32>,
    pub gas_cap: i128,
    pub rules: Vec<AllowitRule>,
    pub params: Map<Symbol, AllowitValue>,
    /// The figures that this wallet keeps, as a bit set of `SPENT`, `CALLS`, `DAY_SPENT` and
    /// `DAY_TOTAL`.
    pub kept: u32,
    pub figures: AllowitFigures,
}

/// Wallet error codes, all below 100; `AllowitError` codes start at 101. Standard rule denials
/// collapse to `PolicyDenied`.
#[contracterror]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum AllowitWalletError {
    InvalidState = 1,
    /// Invalid owner params or rules, or a param that a rule cannot decode.
    InvalidParam = 2,
    UnsupportedAsset = 3,
    InvalidActor = 4,
    StaleRequest = 5,
    Paused = 6,
    Expired = 7,
    InvalidAmount = 8,
    InvalidRecipient = 9,
    Overflow = 11,
    InsufficientFunds = 14,
    InvalidEffects = 15,
    UnsupportedOperation = 16,
    InvalidInvocation = 17,
    PolicyDenied = 18,
    /// The request's gas repayment exceeds the owner-signed gas cap.
    GasAboveCap = 20,
}

/// Compile-time policy mixin. No runtime fallback or system-controlled executable reference exists.
pub trait AllowitPolicy {
    /// Implementation kind.
    const KIND: &'static str;
    /// Simple and Standard run the owner's on-chain rules; Custom runs its compiled source.
    const STANDARD_PREFIX: bool = false;
    /// The general operations that this implementation runs; transfers only unless it selects
    /// more. The owner's `operations` param selects among them.
    const OPERATIONS: &'static [AllowitOperation] = &[AllowitOperation::transfer];
    /// The figures that a compiled source's checks read, from its build. The standard tiers derive
    /// them from their rules.
    const FIGURES: Option<u8> = None;
    /// A bespoke implementation binds the owner's source hash. Fixed tiers take the owner's.
    fn source_digest(_env: &Env) -> Option<BytesN<32>> {
        None
    }
    /// Check the owner's on-chain rules. Only Standard admits a nonempty list.
    fn validate(rules: &Vec<AllowitRule>) -> Result<(), AllowitWalletError> {
        if rules.is_empty() {
            Ok(())
        } else {
            Err(AllowitWalletError::InvalidParam)
        }
    }
    /// Evaluate the compiled checks on the kernel-built rule input. Pass values are discarded.
    fn check(ctx: &AllowitContext, rules: &Vec<AllowitRule>) -> Result<(), AllowitWalletError>;
}

fn tier<P: AllowitPolicy>() -> AllowitTier {
    if P::STANDARD_PREFIX {
        AllowitTier::Standard
    } else {
        AllowitTier::Custom
    }
}
/// A checked arithmetic result, or `Overflow`.
pub(crate) fn checked<T>(value: Option<T>) -> Result<T, AllowitWalletError> {
    value.ok_or(AllowitWalletError::Overflow)
}
/// The Ed25519 key of a G-account address; any other address is `InvalidActor`.
pub(crate) fn public_key(address: &Address) -> Result<BytesN<32>, AllowitWalletError> {
    match address.to_payload() {
        Some(AddressPayload::AccountIdPublicKeyEd25519(key)) => Ok(key),
        _ => Err(AllowitWalletError::InvalidActor),
    }
}
/// The figure that a canonical rule reads, if any.
fn figure_of(rule: AllowitRule) -> u8 {
    match rule {
        AllowitRule::lifetime_spending_limit => SPENT,
        AllowitRule::call_limit => CALLS,
        AllowitRule::daily_spending_limit => DAY_SPENT,
        AllowitRule::daily_volume_limit => DAY_TOTAL,
        _ => 0,
    }
}
/// The figures that the installed policy reads. A standard rule runs only when its param is set.
fn kept<P: AllowitPolicy>(rules: &Vec<AllowitRule>, params: &Map<Symbol, AllowitValue>) -> u8 {
    if let Some(figures) = P::FIGURES {
        return figures & ALL;
    }
    let mut kept = 0;
    for rule in rules.iter() {
        if params.contains_key(Symbol::new(params.env(), rule.key())) {
            kept |= figure_of(rule);
        }
    }
    kept
}

/// The decoded configuration.
#[derive(Clone)]
struct Config {
    paused: bool,
    owner: Address,
    agent: BytesN<32>,
    server: BytesN<32>,
    asset: Address,
    version: u32,
    source_hash: BytesN<32>,
    gas_cap: i128,
    rules: Vec<AllowitRule>,
    params: Map<Symbol, AllowitValue>,
}

/// The raw configuration value and its fixed header.
struct Header {
    raw: Bytes,
    head: [u8; HEADER],
}
impl Header {
    fn read(env: &Env) -> Result<Self, AllowitWalletError> {
        let raw: Bytes = env
            .storage()
            .instance()
            .get(&CONFIG)
            .ok_or(AllowitWalletError::InvalidState)?;
        if (raw.len() as usize) < HEADER {
            return Err(AllowitWalletError::InvalidState);
        }
        let mut head = [0u8; HEADER];
        raw.slice(0..HEADER as u32).copy_into_slice(&mut head);
        Ok(Self { raw, head })
    }
    fn key(&self, at: usize) -> [u8; 32] {
        let mut key = [0; 32];
        key.copy_from_slice(&self.head[at..at + 32]);
        key
    }
    fn owner(&self, env: &Env) -> Result<Address, AllowitWalletError> {
        let kind = if self.head[H_FLAGS] & OWNER_CONTRACT != 0 {
            5
        } else {
            4
        };
        pack::address(env, kind, &self.key(H_OWNER))
    }
    fn asset(&self, env: &Env) -> Result<Address, AllowitWalletError> {
        pack::address(env, 5, &self.key(H_ASSET))
    }
    fn version(&self) -> u32 {
        let mut v = [0; 4];
        v.copy_from_slice(&self.head[H_VERSION..H_VERSION + 4]);
        u32::from_be_bytes(v)
    }
    fn paused(&self) -> bool {
        self.head[H_FLAGS] & PAUSED != 0
    }
    /// Store the configuration with a new pause flag and version; the rest stays as it is.
    fn store_with(&self, env: &Env, paused: bool, version: u32) -> Result<(), AllowitWalletError> {
        let mut head = self.head;
        head[H_FLAGS] = (head[H_FLAGS] & !PAUSED) | if paused { PAUSED } else { 0 };
        head[H_VERSION..H_VERSION + 4].copy_from_slice(&version.to_be_bytes());
        let mut raw = Bytes::from_slice(env, &head);
        raw.append(&self.raw.slice(HEADER as u32..));
        env.storage().instance().set(&CONFIG, &raw);
        Ok(())
    }
}

/// The next deployment version after `version`.
fn next(version: u32) -> Result<u32, AllowitWalletError> {
    checked(version.checked_add(1))
}

impl Config {
    /// Decode the whole configuration of this layout.
    fn load(env: &Env) -> Result<Self, AllowitWalletError> {
        let header = Header::read(env)?;
        let len = header.raw.len() as usize;
        if header.head[H_LAYOUT] != CONTRACT_VERSION as u8 || len > MAX_CONFIG {
            return Err(AllowitWalletError::InvalidState);
        }
        let mut buf = [0u8; MAX_CONFIG];
        header.raw.copy_into_slice(&mut buf[..len]);
        let mut r = Reader::new(&buf[HEADER..len]);
        let gas_cap = r.amount()?;
        let mut rules = Vec::new(env);
        for _ in 0..r.byte()? {
            let rule = RULES
                .get(r.byte()? as usize)
                .ok_or(AllowitWalletError::InvalidState)?;
            rules.push_back(*rule);
        }
        let mut params = Map::new(env);
        for _ in 0..r.uint()? {
            let key = match r.byte()? {
                0xff => {
                    let n = r.byte()? as usize;
                    let text = core::str::from_utf8(r.take(n)?)
                        .map_err(|_| AllowitWalletError::InvalidState)?;
                    Symbol::new(env, text)
                }
                index => Symbol::new(
                    env,
                    RULES
                        .get(index as usize)
                        .ok_or(AllowitWalletError::InvalidState)?
                        .key(),
                ),
            };
            params.set(key, pack::get_value(env, &mut r)?);
        }
        if !r.done() {
            return Err(AllowitWalletError::InvalidState);
        }
        Ok(Self {
            paused: header.paused(),
            owner: header.owner(env)?,
            agent: BytesN::from_array(env, &header.key(H_AGENT)),
            server: BytesN::from_array(env, &header.key(H_SERVER)),
            asset: header.asset(env)?,
            version: header.version(),
            source_hash: BytesN::from_array(env, &header.key(H_SOURCE)),
            gas_cap,
            rules,
            params,
        })
    }
    /// Pack and store the configuration.
    fn store(&self, env: &Env) -> Result<(), AllowitWalletError> {
        let mut buf = [0u8; MAX_CONFIG];
        let mut w = Writer::new(&mut buf);
        let owner_kind = match self.owner.to_payload() {
            Some(AddressPayload::AccountIdPublicKeyEd25519(_)) => 0,
            Some(AddressPayload::ContractIdHash(_)) => OWNER_CONTRACT,
            None => return Err(AllowitWalletError::InvalidActor),
        };
        let asset = match self.asset.to_payload() {
            Some(AddressPayload::ContractIdHash(hash)) => hash,
            _ => return Err(AllowitWalletError::UnsupportedAsset),
        };
        let owner = match self.owner.to_payload() {
            Some(
                AddressPayload::AccountIdPublicKeyEd25519(k) | AddressPayload::ContractIdHash(k),
            ) => k,
            None => return Err(AllowitWalletError::InvalidActor),
        };
        w.byte(CONTRACT_VERSION as u8)?;
        w.byte(owner_kind | if self.paused { PAUSED } else { 0 })?;
        w.put(&self.version.to_be_bytes())?;
        w.put(&owner.to_array())?;
        w.put(&self.agent.to_array())?;
        w.put(&self.server.to_array())?;
        w.put(&asset.to_array())?;
        w.put(&self.source_hash.to_array())?;
        w.amount(self.gas_cap)
            .map_err(|_| AllowitWalletError::InvalidParam)?;
        w.byte(u8::try_from(self.rules.len()).map_err(|_| AllowitWalletError::InvalidParam)?)?;
        for rule in self.rules.iter() {
            let index = RULES.iter().position(|r| *r == rule);
            w.byte(index.ok_or(AllowitWalletError::InvalidParam)? as u8)?;
        }
        w.uint(u128::from(self.params.len()))?;
        for (key, value) in self.params.iter() {
            match RULES
                .iter()
                .position(|rule| key == Symbol::new(env, rule.key()))
            {
                Some(index) => w.byte(index as u8)?,
                None => {
                    let mut text = [0u8; 32];
                    let n = pack::symbol_text(env, &key, &mut text)?;
                    w.byte(0xff)?;
                    w.byte(n as u8)?;
                    w.put(&text[..n])?;
                }
            }
            pack::put_value(&mut w, &value)?;
        }
        env.storage()
            .instance()
            .set(&CONFIG, &Bytes::from_slice(env, w.bytes()));
        Ok(())
    }
}

/// Standard figures kept by the wallet.
#[derive(Clone, Default, PartialEq)]
struct Figures {
    calls: u64,
    spent: i128,
    unpriced: bool,
    day_spent: i128,
    day_total: i128,
    day_unpriced: bool,
}
/// The stored figures and what is stored.
struct Stored {
    figures: Figures,
    /// The end ledger of an open daily window.
    day_ends: Option<u32>,
    total_exists: bool,
}
/// Read `t` and an open `d`, each only when `kept` names one of its figures. A window whose end
/// ledger has passed is closed even if someone paid to keep the entry alive.
fn read_figures(env: &Env, kept: u8) -> Result<Stored, AllowitWalletError> {
    let mut figures = Figures::default();
    let total: Option<Bytes> = if kept & TOTALS != 0 {
        env.storage().persistent().get(&TOTAL)
    } else {
        None
    };
    if let Some(raw) = &total {
        if raw.len() != TOTAL_BYTES as u32 {
            return Err(AllowitWalletError::InvalidState);
        }
        let mut buf = [0u8; TOTAL_BYTES];
        raw.copy_into_slice(&mut buf);
        let mut spent = [0; 8];
        spent.copy_from_slice(&buf[..8]);
        let mut calls = [0; 4];
        calls.copy_from_slice(&buf[8..]);
        let calls = u32::from_be_bytes(calls);
        if kept & SPENT != 0 {
            figures.spent = i128::from(u64::from_be_bytes(spent));
            figures.unpriced = calls & UNPRICED_BIT != 0;
        }
        if kept & CALLS != 0 {
            figures.calls = u64::from(calls & !UNPRICED_BIT);
        }
    }
    let mut day_ends = None;
    let daily: Option<Bytes> = if kept & DAILIES != 0 {
        env.storage().temporary().get(&DAILY)
    } else {
        None
    };
    if let Some(raw) = daily {
        let mut buf = [0u8; 64];
        let len = raw.len() as usize;
        if len > buf.len() {
            return Err(AllowitWalletError::InvalidState);
        }
        raw.copy_into_slice(&mut buf[..len]);
        let mut r = Reader::new(&buf[..len]);
        let mut end = [0; 4];
        end.copy_from_slice(r.take(4)?);
        let end = u32::from_be_bytes(end);
        if env.ledger().sequence() <= end {
            day_ends = Some(end);
            let mask = r.byte()?;
            figures.day_unpriced = r.byte()? & 1 != 0;
            if mask & DAY_SPENT != 0 {
                figures.day_spent = r.amount()?;
            }
            if mask & DAY_TOTAL != 0 {
                figures.day_total = r.amount()?;
            }
            if !r.done() {
                return Err(AllowitWalletError::InvalidState);
            }
        }
    }
    Ok(Stored {
        figures,
        day_ends,
        total_exists: total.is_some(),
    })
}
/// The total figures that `kept` names; the others are zero. Spent carries the unpriced flag: the
/// lifetime spending limit reads both.
fn totals(kept: u8, f: &Figures) -> (i128, u64, bool) {
    let spent = kept & SPENT != 0;
    (
        if spent { f.spent } else { 0 },
        if kept & CALLS != 0 { f.calls } else { 0 },
        spent && f.unpriced,
    )
}
/// Write `t`: spent as 8 bytes, then calls in 31 bits with the unpriced flag in the top bit. The
/// value has one fixed size, so a payment never grows it: a larger value would pay rent for the
/// whole prepaid lifetime of `t`. A figure that no check reads is written as zero. A figure beyond
/// its width is `Overflow`. A new `t` lives `TOTAL_LEDGERS`.
fn write_total(env: &Env, kept: u8, f: &Figures, exists: bool) -> Result<(), AllowitWalletError> {
    let (spent, calls, unpriced) = totals(kept, f);
    let spent = u64::try_from(spent).map_err(|_| AllowitWalletError::Overflow)?;
    let calls = u32::try_from(calls)
        .ok()
        .filter(|calls| calls & UNPRICED_BIT == 0)
        .ok_or(AllowitWalletError::Overflow)?;
    let mut buf = [0u8; TOTAL_BYTES];
    buf[..8].copy_from_slice(&spent.to_be_bytes());
    let flag = if unpriced { UNPRICED_BIT } else { 0 };
    buf[8..].copy_from_slice(&(calls | flag).to_be_bytes());
    let storage = env.storage().persistent();
    storage.set(&TOTAL, &Bytes::from_slice(env, &buf));
    if !exists {
        storage.extend_ttl(&TOTAL, TOTAL_LEDGERS - 1, TOTAL_LEDGERS - 1);
    }
    Ok(())
}
/// Write `d` with the kept daily figures. A new window ends `DAY_LEDGERS - 1` ledgers from now,
/// and the entry lives at least that long; the wallet never extends it later.
fn write_daily(
    env: &Env,
    kept: u8,
    f: &Figures,
    day_ends: Option<u32>,
) -> Result<(), AllowitWalletError> {
    let seq = env.ledger().sequence();
    let end = match day_ends {
        Some(end) => end,
        None => checked(seq.checked_add(DAY_LEDGERS - 1))?,
    };
    let mut buf = [0u8; 64];
    let mut w = Writer::new(&mut buf);
    w.put(&end.to_be_bytes())?;
    w.byte(kept & DAILIES)?;
    w.byte(u8::from(f.day_unpriced))?;
    if kept & DAY_SPENT != 0 {
        w.amount(f.day_spent)?;
    }
    if kept & DAY_TOTAL != 0 {
        w.amount(f.day_total)?;
    }
    let storage = env.storage().temporary();
    storage.set(&DAILY, &Bytes::from_slice(env, w.bytes()));
    if day_ends.is_none() {
        // Also covers an entry that someone kept alive past its own end ledger.
        storage.extend_ttl(&DAILY, DAY_LEDGERS - 1, DAY_LEDGERS - 1);
    }
    Ok(())
}
/// Make `t` match the figures that a new configuration keeps: rewrite it for a new set, create it
/// at zero for a set that gains totals, remove it for one that keeps none.
fn reshape_total(env: &Env, kept: u8) -> Result<(), AllowitWalletError> {
    let stored = read_figures(env, TOTALS)?;
    if kept & TOTALS != 0 {
        write_total(env, kept, &stored.figures, stored.total_exists)
    } else {
        if stored.total_exists {
            env.storage().persistent().remove(&TOTAL);
        }
        Ok(())
    }
}

/// Soroban decodes vector elements when read. Owner configuration decodes each rule before storing
/// it, so an element that later fails to decode cannot be stored.
fn decoded(list: &Vec<AllowitRule>) -> Result<(), AllowitWalletError> {
    for i in 0..list.len() {
        list.try_get(i)
            .map_err(|_| AllowitWalletError::InvalidParam)?;
    }
    Ok(())
}
/// Check an owner configuration and keep, for Standard, only the params of its rules.
fn validated<P: AllowitPolicy>(
    env: &Env,
    mut config: Config,
) -> Result<Config, AllowitWalletError> {
    let wallet = env.current_contract_address();
    if config.owner == wallet || config.agent == config.server {
        return Err(AllowitWalletError::InvalidActor);
    }
    if let Ok(owner) = public_key(&config.owner)
        && (owner == config.agent || owner == config.server)
    {
        return Err(AllowitWalletError::InvalidActor);
    }
    if config.source_hash == BytesN::from_array(env, &[0; 32])
        || P::source_digest(env).is_some_and(|digest| digest != config.source_hash)
    {
        return Err(AllowitWalletError::InvalidState);
    }
    if config.gas_cap < 0 {
        return Err(AllowitWalletError::InvalidParam);
    }
    allowit::check_params(&config.params, tier::<P>())
        .map_err(|_| AllowitWalletError::InvalidParam)?;
    decoded(&config.rules)?;
    P::validate(&config.rules)?;
    if P::STANDARD_PREFIX {
        let mut kept = Map::new(env);
        for rule in config.rules.iter() {
            let key = Symbol::new(env, rule.key());
            if let Some(value) = config.params.get(key.clone()) {
                kept.set(key, value);
            }
        }
        config.params = kept;
    }
    Ok(config)
}

/// Initialize custody from an owner-signed configuration. The instance and `t` live
/// `TOTAL_LEDGERS`, paid by this transaction.
pub fn construct<P: AllowitPolicy>(
    env: &Env,
    config: AllowitPolicyConfig,
) -> Result<(), AllowitWalletError> {
    // Decoding ignores extra keys. The owner signs the canonical encoding of the decoded packet,
    // so a packet whose meaning differs fails auth.
    config
        .owner
        .require_auth_for_args((config.clone(),).into_val(env));
    if config.asset.executable() != Some(Executable::StellarAsset) {
        return Err(AllowitWalletError::UnsupportedAsset);
    }
    let config = validated::<P>(
        env,
        Config {
            paused: false,
            owner: config.owner,
            agent: config.agent,
            server: config.server,
            asset: config.asset,
            version: 0,
            source_hash: config.source_hash,
            gas_cap: config.gas_cap,
            rules: config.rules,
            params: config.params,
        },
    )?;
    config.store(env)?;
    let kept = kept::<P>(&config.rules, &config.params);
    if kept & TOTALS != 0 {
        write_total(env, kept, &Figures::default(), false)?;
    }
    env.deployer().extend_ttl_for_contract_instance(
        env.current_contract_address(),
        TOTAL_LEDGERS - 1,
        TOTAL_LEDGERS - 1,
    );
    Ok(())
}

/// Read the stored wallet.
pub fn state<P: AllowitPolicy>(env: &Env) -> Result<AllowitState, AllowitWalletError> {
    let config = Config::load(env)?;
    let kept = kept::<P>(&config.rules, &config.params);
    let stored = read_figures(env, kept)?;
    let f = stored.figures;
    Ok(AllowitState {
        contract_version: CONTRACT_VERSION,
        owner: config.owner,
        agent: config.agent,
        server: config.server,
        asset: config.asset,
        deployment_version: config.version,
        paused: config.paused,
        source_hash: config.source_hash,
        gas_cap: config.gas_cap,
        kept: u32::from(kept),
        rules: config.rules,
        params: config.params,
        figures: AllowitFigures {
            calls: f.calls,
            spent: f.spent,
            unpriced: f.unpriced,
            day_spent: f.day_spent,
            day_total: f.day_total,
            day_unpriced: f.day_unpriced,
            day_ends: stored.day_ends.unwrap_or(0),
        },
    })
}

/// Check the request's expense bounds and gas repayment against its operation and the owner's
/// gas cap. External facts remain server-attested.
fn validate_expense(
    env: &Env,
    config: &Config,
    execution: &AllowitExecutionRequest,
    operation: &AllowitOperationArgs,
) -> Result<(), AllowitWalletError> {
    let gas = execution.gas_stroops();
    if gas < 0 {
        return Err(AllowitWalletError::InvalidAmount);
    }
    if gas > config.gas_cap {
        return Err(AllowitWalletError::GasAboveCap);
    }
    if gas > 0 && *execution.gas_payee() == env.current_contract_address() {
        return Err(AllowitWalletError::InvalidRecipient);
    }
    let Some(expense) = execution.expense() else {
        // An unpriced request counts no gas, so it repays none.
        return if gas == 0 {
            Ok(())
        } else {
            Err(AllowitWalletError::InvalidInvocation)
        };
    };
    let (gas_units, conversion, spent) = (
        expense.gas_units,
        expense.conversion_units,
        expense.spent_units,
    );
    if gas_units < 0
        || conversion < 0
        || spent < 0
        || expense.observed_ledger == 0
        || expense.observed_ledger > env.ledger().sequence()
    {
        return Err(AllowitWalletError::InvalidInvocation);
    }
    // The repaid gas is what the limits count. An XLM wallet counts the repaid stroops exactly;
    // for another asset the agent and server attest the conversion.
    if (gas == 0) != (gas_units == 0) || (config.asset == native_asset(env) && gas_units != gas) {
        return Err(AllowitWalletError::InvalidInvocation);
    }
    let principal = match operation {
        AllowitOperationArgs::Transfer(args) => {
            if conversion != 0 {
                return Err(AllowitWalletError::InvalidInvocation);
            }
            args.amount
        }
        AllowitOperationArgs::Deposit(args) => {
            if conversion > args.assets {
                return Err(AllowitWalletError::InvalidInvocation);
            }
            conversion
        }
        // A forward swap pays the asset: its loss cannot exceed the input.
        AllowitOperationArgs::Swap(args) => {
            if args.path.get_unchecked(0) == config.asset && conversion > args.amount_in {
                return Err(AllowitWalletError::InvalidInvocation);
            }
            conversion
        }
        AllowitOperationArgs::Redeem(_) => conversion,
    };
    if spent != checked(principal.checked_add(gas_units))? {
        return Err(AllowitWalletError::InvalidInvocation);
    }
    Ok(())
}

/// Rule input: owner params, the kept figures as the standard state on the request's day, the
/// authenticated request facts and the agent's execution params.
fn rule_input(
    env: &Env,
    config: &Config,
    execution: &AllowitExecutionRequest,
    operation: &AllowitOperationArgs,
    f: &Figures,
) -> Result<AllowitContext, AllowitWalletError> {
    let facts = facts(operation, &config.asset);
    let expense = execution.expense();
    let now = env.ledger().timestamp();
    // The daily window is the life of `d`: the figures of an open window are today's.
    let mut state = Map::new(env);
    AllowitStandardState {
        calls: f.calls,
        spent: f.spent,
        unpriced: f.unpriced,
        day: now / DAY,
        day_spent: f.day_spent,
        day_total: f.day_total,
        day_unpriced: f.day_unpriced,
    }
    .write(&mut state)?;
    Ok(AllowitContext {
        env: env.clone(),
        params: AllowitParams::new(env, config.params.clone())?,
        state,
        request: AllowitRequest {
            operation: execution.operation().to_core(),
            asset: config.asset.clone(),
            recipient: facts.recipient,
            amount: facts.amount,
            token_in: facts.token_in,
            amount_in: facts.amount_in,
            token_out: facts.token_out,
            min_out: facts.min_out,
            now,
            expires_at: execution.expires_at(),
            spent_units: expense.map_or(0, |e| e.spent_units),
            gas_units: expense.map_or(0, |e| e.gas_units),
            unpriced: expense.is_none(),
            args: AllowitArgs(execution.args().clone()),
        },
    })
}

/// Run the policy and update the kept figures before any external call. A later failure in this
/// transaction rolls the writes back.
fn admit<P: AllowitPolicy>(
    env: &Env,
    config: &Config,
    execution: &AllowitExecutionRequest,
    operation: &AllowitOperationArgs,
) -> Result<(), AllowitWalletError> {
    let kept = kept::<P>(&config.rules, &config.params);
    // Simple, and Standard with no rules: no rule runs and nothing is stored.
    if P::STANDARD_PREFIX && config.rules.is_empty() {
        return Ok(());
    }
    // Code changes defer tier validation of the kept rules and params to this admission.
    P::validate(&config.rules)?;
    if P::STANDARD_PREFIX {
        allowit::check_params(&config.params, AllowitTier::Standard)?;
    }
    let stored = if kept == 0 {
        Stored {
            figures: Figures::default(),
            day_ends: None,
            total_exists: false,
        }
    } else {
        read_figures(env, kept)?
    };
    let ctx = rule_input(env, config, execution, operation, &stored.figures)?;
    P::check(&ctx, &config.rules)?;
    // A Standard policy writes nothing but figures. Custom runs the shared post-flight even with
    // none, so a source write fails as `Unsupported` instead of being stored.
    if kept == 0 && P::STANDARD_PREFIX {
        return Ok(());
    }
    let state = allowit::post_flight(&ctx, AllowitTier::Standard)?;
    if kept == 0 {
        return Ok(());
    }
    let s = AllowitStandardState::read(&state)?;
    let after = Figures {
        calls: s.calls,
        spent: s.spent,
        unpriced: s.unpriced,
        day_spent: s.day_spent,
        day_total: s.day_total,
        day_unpriced: s.day_unpriced,
    };
    let before = &stored.figures;
    if kept & TOTALS != 0 && (!stored.total_exists || totals(kept, &after) != totals(kept, before))
    {
        write_total(env, kept, &after, stored.total_exists)?;
    }
    if kept & DAILIES != 0
        && (after.day_spent, after.day_total, after.day_unpriced)
            != (before.day_spent, before.day_total, before.day_unpriced)
    {
        write_daily(env, kept, &after, stored.day_ends)?;
    }
    Ok(())
}

/// Run one agent- and server-authorized operation under the installed policy, repay the signed
/// gas and emit one event.
pub fn execute<P: AllowitPolicy>(
    env: &Env,
    execution: AllowitExecutionRequest,
) -> Result<(), AllowitWalletError> {
    let wallet = env.current_contract_address();
    // The ledger calls `__check_auth`: the agent and the server signed this exact call.
    wallet.require_auth();
    let config = Config::load(env)?;
    if config.paused {
        return Err(AllowitWalletError::Paused);
    }
    if execution.deployment_version() != config.version {
        return Err(AllowitWalletError::StaleRequest);
    }
    if execution.expires_at() <= env.ledger().timestamp() {
        return Err(AllowitWalletError::Expired);
    }
    if P::source_digest(env).is_some_and(|digest| digest != config.source_hash) {
        return Err(AllowitWalletError::InvalidState);
    }
    if *execution.operation_id() == BytesN::from_array(env, &[0; 32])
        || allowit::check_args(execution.args()).is_err()
    {
        return Err(AllowitWalletError::InvalidInvocation);
    }
    if !P::OPERATIONS.contains(&execution.operation().to_core()) {
        return Err(AllowitWalletError::UnsupportedOperation);
    }
    let operation = execution.operation().args();
    validate_operation(env, &operation, execution.expires_at(), &config.asset)?;
    validate_expense(env, &config, &execution, &operation)?;
    admit::<P>(env, &config, &execution, &operation)?;
    let expense = execution.expense();
    let output = match &operation {
        AllowitOperationArgs::Transfer(args) => {
            move_tokens(env, &args.token, &args.to, args.amount)?;
            args.amount
        }
        AllowitOperationArgs::Swap(args) => swap_tokens(env, args)?,
        AllowitOperationArgs::Deposit(args) => {
            deposit_tokens(env, &config.asset, args, expense.as_ref())?
        }
        AllowitOperationArgs::Redeem(args) => {
            redeem_shares(env, &config.asset, args, expense.as_ref())?
        }
    };
    let gas = execution.gas_stroops();
    if gas > 0 {
        token::Client::new(env, &native_asset(env)).transfer(&wallet, execution.gas_payee(), &gas);
    }
    AllowitExecuted {
        operation_id: execution.operation_id().clone(),
        output,
    }
    .publish(env);
    Ok(())
}

/// The wallet's own authorization: only its `execute`, signed by the agent's and the server's
/// stored keys over the ledger's payload. The payload binds the network, this wallet, the call
/// and its arguments, the ledger nonce and the expiration ledger.
pub fn check_auth(
    env: &Env,
    payload: Hash<32>,
    signatures: AllowitCosignatures,
    contexts: Vec<Context>,
) -> Result<(), AllowitWalletError> {
    if contexts.len() != 1 {
        return Err(AllowitWalletError::InvalidInvocation);
    }
    match contexts.get(0) {
        Some(Context::Contract(call))
            if call.contract == env.current_contract_address()
                && call.fn_name == Symbol::new(env, "execute") => {}
        _ => return Err(AllowitWalletError::UnsupportedOperation),
    }
    let header = Header::read(env)?;
    let message: Bytes = payload.to_bytes().into();
    env.crypto().ed25519_verify(
        &BytesN::from_array(env, &header.key(H_AGENT)),
        &message,
        &signatures.0,
    );
    env.crypto().ed25519_verify(
        &BytesN::from_array(env, &header.key(H_SERVER)),
        &message,
        &signatures.1,
    );
    Ok(())
}

/// Apply a complete owner update; the asset, the pause and the figures carry over.
pub fn deploy_policy<P: AllowitPolicy>(
    env: &Env,
    update: AllowitPolicyUpdate,
) -> Result<(), AllowitWalletError> {
    let header = Header::read(env)?;
    let owner = header.owner(env)?;
    // The current and any new owner sign the canonical encoding of the decoded packet.
    let signed: Vec<Val> = (update.clone(),).into_val(env);
    owner.require_auth_for_args(signed.clone());
    if next(header.version())? != update.deployment_version {
        return Err(AllowitWalletError::StaleRequest);
    }
    let config = Config {
        paused: header.paused(),
        owner: update.owner,
        agent: update.agent,
        server: update.server,
        asset: header.asset(env)?,
        version: update.deployment_version,
        source_hash: update.source_hash,
        gas_cap: update.gas_cap,
        rules: update.rules,
        params: update.params,
    };
    // New code validates its own rules and figures on its first call; the owner binds its hash.
    let upgrade = update.wasm_hash.as_ref().is_some_and(|hash| {
        env.current_contract_address().executable() != Some(Executable::Wasm(hash.clone()))
    });
    let config = if upgrade {
        validated::<UpgradeConfig>(env, config)?
    } else {
        validated::<P>(env, config)?
    };
    if config.owner != owner {
        config.owner.require_auth_for_args(signed);
    }
    config.store(env)?;
    if !upgrade {
        reshape_total(env, kept::<P>(&config.rules, &config.params))?;
    }
    if let Some(hash) = update.wasm_hash {
        env.deployer()
            .update_current_contract(soroban_sdk::ContractExecutable::Wasm(hash));
    }
    Ok(())
}
/// Validation of a packet that installs new code: the new code checks its own rules on its next call.
struct UpgradeConfig;
impl AllowitPolicy for UpgradeConfig {
    const KIND: &'static str = "upgrade";
    fn validate(_rules: &Vec<AllowitRule>) -> Result<(), AllowitWalletError> {
        Ok(())
    }
    fn check(_ctx: &AllowitContext, _rules: &Vec<AllowitRule>) -> Result<(), AllowitWalletError> {
        Err(AllowitWalletError::PolicyDenied)
    }
}

/// Pause or resume the agent path; the owner targets the next deployment version.
pub fn set_pause(
    env: &Env,
    paused: bool,
    deployment_version: u32,
) -> Result<(), AllowitWalletError> {
    let header = Header::read(env)?;
    header.owner(env)?.require_auth();
    if next(header.version())? != deployment_version {
        return Err(AllowitWalletError::StaleRequest);
    }
    header.store_with(env, paused, deployment_version)
}
/// The owner's stop: pause at the next deployment version and return the whole balance of the
/// asset and of XLM to the owner, in one call.
pub fn stop(env: &Env, deployment_version: u32) -> Result<(), AllowitWalletError> {
    let header = Header::read(env)?;
    let owner = header.owner(env)?;
    owner.require_auth();
    if next(header.version())? != deployment_version {
        return Err(AllowitWalletError::StaleRequest);
    }
    header.store_with(env, true, deployment_version)?;
    let wallet = env.current_contract_address();
    let asset = header.asset(env)?;
    let native = native_asset(env);
    let return_all = |token: &Address| {
        let client = token::Client::new(env, token);
        let balance = client.balance(&wallet);
        if balance > 0 {
            client.transfer(&wallet, &owner, &balance);
        }
    };
    return_all(&asset);
    if asset != native {
        return_all(&native);
    }
    Ok(())
}
/// Owner transfer of any token the wallet holds.
pub fn recover(
    env: &Env,
    token: Address,
    recipient: Address,
    amount: i128,
) -> Result<(), AllowitWalletError> {
    Header::read(env)?.owner(env)?.require_auth();
    if amount <= 0 {
        return Err(AllowitWalletError::InvalidAmount);
    }
    let wallet = env.current_contract_address();
    if recipient == wallet {
        return Err(AllowitWalletError::InvalidRecipient);
    }
    token::Client::new(env, &token).transfer(&wallet, &recipient, &amount);
    Ok(())
}
/// Owner-signed passthrough. Native authorization binds target, arguments and every nested scope.
pub fn invoke(
    env: &Env,
    contract: Address,
    function: Symbol,
    args: Vec<Val>,
    auth: Vec<InvokerContractAuthEntry>,
) -> Result<Val, AllowitWalletError> {
    Header::read(env)?.owner(env)?.require_auth();
    env.authorize_as_current_contract(auth);
    Ok(env.invoke_contract(&contract, &function, args))
}

/// Every native operation: the SEP-41 transfer, the router swap and the SEP-56 deposit and redeem.
pub const NATIVE_OPERATIONS: &[AllowitOperation] = &[
    AllowitOperation::transfer,
    AllowitOperation::swap,
    AllowitOperation::deposit,
    AllowitOperation::redeem,
];
/// Simple: no rule on chain. The server keeps the account of its limits.
pub struct AllowitSimple;
impl AllowitPolicy for AllowitSimple {
    const KIND: &'static str = "simple_policy_engine";
    const STANDARD_PREFIX: bool = true;
    const OPERATIONS: &'static [AllowitOperation] = NATIVE_OPERATIONS;
    fn check(_ctx: &AllowitContext, _rules: &Vec<AllowitRule>) -> Result<(), AllowitWalletError> {
        Ok(())
    }
}
/// Standard: the owner's ordered canonical rules.
pub struct AllowitCommon;
impl AllowitPolicy for AllowitCommon {
    const KIND: &'static str = "common_policy_engine";
    const STANDARD_PREFIX: bool = true;
    const OPERATIONS: &'static [AllowitOperation] = NATIVE_OPERATIONS;
    fn validate(_rules: &Vec<AllowitRule>) -> Result<(), AllowitWalletError> {
        Ok(())
    }
    /// Run each rule `allowit::<rule>(ctx, &ctx.params[allowit::<RULE>])?;` in owner order. An
    /// absent param skips its rule here only; the server's full policy denies it.
    fn check(ctx: &AllowitContext, rules: &Vec<AllowitRule>) -> Result<(), AllowitWalletError> {
        for rule in rules.iter() {
            allowit::preflight(ctx, rule)?;
        }
        Ok(())
    }
}
/// Rule denials collapse to PolicyDenied. Invalid owner configuration, state and overflow stay distinct.
impl From<allowit::AllowitError> for AllowitWalletError {
    fn from(error: allowit::AllowitError) -> Self {
        match error {
            allowit::AllowitError::MissingParam | allowit::AllowitError::InvalidParam => {
                AllowitWalletError::InvalidParam
            }
            allowit::AllowitError::InvalidState => AllowitWalletError::InvalidState,
            allowit::AllowitError::Overflow => AllowitWalletError::Overflow,
            allowit::AllowitError::Unsupported => AllowitWalletError::UnsupportedOperation,
            _ => AllowitWalletError::PolicyDenied,
        }
    }
}

/// Attach the complete owner and agent interface to a policy implementation.
#[macro_export]
macro_rules! policy_wallet {
    ($name:ident, $policy:ty) => {
        /// Policy wallet contract of one compiled policy.
        #[soroban_sdk::contract]
        pub struct $name;
        #[soroban_sdk::contractimpl]
        impl $name {
            /// Initialize custody from an owner-signed configuration.
            pub fn __constructor(env: soroban_sdk::Env, config: $crate::AllowitPolicyConfig) {
                $crate::construct::<$policy>(&env, config).unwrap();
            }
            /// Read the stored wallet.
            pub fn state(
                env: soroban_sdk::Env,
            ) -> Result<$crate::AllowitState, $crate::AllowitWalletError> {
                $crate::state::<$policy>(&env)
            }
            /// Run one operation that the agent and the server signed, under the installed policy.
            pub fn execute(
                env: soroban_sdk::Env,
                execution: allowit_wallet_protocol::AllowitExecutionRequest,
            ) -> Result<(), $crate::AllowitWalletError> {
                $crate::execute::<$policy>(&env, execution)
            }
            /// Apply a complete owner update at the next deployment version.
            pub fn deploy_policy(
                env: soroban_sdk::Env,
                update: $crate::AllowitPolicyUpdate,
            ) -> Result<(), $crate::AllowitWalletError> {
                $crate::deploy_policy::<$policy>(&env, update)
            }
            /// Pause or resume the agent path at the next deployment version.
            pub fn set_pause(
                env: soroban_sdk::Env,
                paused: bool,
                deployment_version: u32,
            ) -> Result<(), $crate::AllowitWalletError> {
                $crate::set_pause(&env, paused, deployment_version)
            }
            /// Pause and return the asset and XLM to the owner.
            pub fn stop(
                env: soroban_sdk::Env,
                deployment_version: u32,
            ) -> Result<(), $crate::AllowitWalletError> {
                $crate::stop(&env, deployment_version)
            }
            /// Owner transfer of any token the wallet holds.
            pub fn recover(
                env: soroban_sdk::Env,
                token: soroban_sdk::Address,
                recipient: soroban_sdk::Address,
                amount: i128,
            ) -> Result<(), $crate::AllowitWalletError> {
                $crate::recover(&env, token, recipient, amount)
            }
            /// Owner-signed passthrough call with explicit nested authorization.
            pub fn invoke(
                env: soroban_sdk::Env,
                contract: soroban_sdk::Address,
                function: soroban_sdk::Symbol,
                args: soroban_sdk::Vec<soroban_sdk::Val>,
                auth: soroban_sdk::Vec<soroban_sdk::auth::InvokerContractAuthEntry>,
            ) -> Result<soroban_sdk::Val, $crate::AllowitWalletError> {
                $crate::invoke(&env, contract, function, args, auth)
            }
        }
        #[soroban_sdk::contractimpl]
        impl soroban_sdk::auth::CustomAccountInterface for $name {
            type Signature = allowit_wallet_protocol::AllowitCosignatures;
            type Error = $crate::AllowitWalletError;
            /// Authorize this wallet's own `execute` with the agent's and the server's signatures.
            fn __check_auth(
                env: soroban_sdk::Env,
                signature_payload: soroban_sdk::crypto::Hash<32>,
                signatures: allowit_wallet_protocol::AllowitCosignatures,
                contexts: soroban_sdk::Vec<soroban_sdk::auth::Context>,
            ) -> Result<(), $crate::AllowitWalletError> {
                $crate::check_auth(&env, signature_payload, signatures, contexts)
            }
        }
    };
}

#[cfg(test)]
mod core_vectors_tests;
#[cfg(test)]
mod tests;
