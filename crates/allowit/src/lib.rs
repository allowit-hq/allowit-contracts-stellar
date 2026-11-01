#![no_std]
//! Canonical AllowIt policy rules. The offchain server and `AllowitCustomPolicy` compile one authored
//! policy file verbatim:
//!
//! ```ignore
//! use allowit::prelude::*;
//! /// Let my agent pay our invoices. Cap its total spending and pay only vendors I approve.
//! pub fn execute(ctx: &AllowitContext) -> allowit::Result {
//!     // "Cap its total spending"
//!     allowit::spent_cap(ctx, ctx.params.get(allowit::SPENT_CAP))?;
//!     // "pay only vendors I approve"
//!     allowit::recipients(ctx, ctx.params.get(allowit::RECIPIENTS))?;
//!     Ok(())
//! }
//! ```
//!
//! `AllowitContext` is plain data: `env`, `params`, `state` and `request`. `params` holds the
//! owner's constructor params, key => `AllowitValue`; an absent key is unset. `state` is the
//! current policy state, before this operation: one free-form map with standard keys (`spent`,
//! `day_spent`, `day_total`, `calls`, `day`, `unpriced`, `day_unpriced`) and policy-defined keys.
//! `request.args` holds the agent's execution params for this call. Params, state and args share
//! the one value type `AllowitValue`.
//!
//! A rule takes the looked-up param value and decodes it: an unset param is `MissingParam` and a
//! value of the wrong type or range is `InvalidParam`. Rules add the request's own contribution to
//! the current values and return their passing constraint or an `AllowitError`. Only an error that
//! the policy propagates with `?` ends the run. A policy may catch a rule error, read it and
//! continue. `operations` admits the request's op only when the owner's `operations` param names
//! it, and returns the op name, such as `"transfer"`, for a `match`.
//!
//! `param` and `arg` read an owner param or an agent arg as the type of its binding:
//! `let cap: i128 = allowit::param(ctx, "swap_cap");`. They panic when the key is unset
//! (`MissingParam`) or the value has another type or range (`InvalidParam`). A panic, also from
//! `panic!`, `assert!`, `unreachable!` or an integer overflow, is a hard stop: the run denies and
//! its writes are discarded. Onchain the contract call aborts, with the `AllowitError` code for a
//! failed read. On the host `evaluate` catches the panic and returns that error or `Panicked`.
//!
//! After approval, the wallet and the server run the same `post_flight`: it rolls the UTC day
//! over, counts the call, adds spent and gross amounts, marks unpriced operations, then applies
//! the policy's own `set_state` writes, and denies a result whose standard keys do not decode or
//! that holds more than `MAX_STATE_KEYS` keys or `MAX_STATE_BYTES` encoded bytes. Simple and
//! Common run only the canonical prefix onchain and store only standard keys, so their
//! `post_flight` denies any policy write with `Unsupported`, on the host as onchain. The server
//! runs a policy through `evaluate`, which first checks the request's args and, for a standard
//! wallet, its params as the wallet does, and discards the writes of a denied run. The
//! standard contract runs the leading canonical calls, supplied by the owner as `rules`, through
//! `preflight`, which skips absent params.
//!
//! Portable authored code uses rule calls, `param`, `arg`, `get_state` and `set_state`, typed
//! scalar fields and enum comparisons. `scripts/policy_source.py` admits only an allowlist of names,
//! paths and methods that give the same result on both backends.
//!
//! Types and rule logic are written once in `core.rs` and compiled per backend. Each backend binds
//! `Address`, `AllowitEnv`, `Map`, `String`, `Symbol` and `Vec`. Feature `soroban` (default) uses
//! host values, contract types and the Soroban `Env`, and buffers policy writes in contract
//! temporary storage until `post_flight`. Feature `std` uses StrKey addresses, heap maps and
//! vectors, and a host `AllowitEnv` that buffers policy writes. The selected backend backs the
//! crate root, which authored policy names.
//!
//! The server-only enrichment functions (`price`, `fetch`, `internet_search`,
//! `marketplace_search`, `request_screening`, `systemone`, `clear_systemone_context`) exist only
//! in the host backend. A Custom policy that calls one does not compile onchain.
//!
//! The offchain server depends on `allowit = { default-features = false, features = ["std"] }`
//! and must not unify `soroban`: enabling both is a compile error. The server must also build
//! with `overflow-checks = true`, as the contract release profile does, so that integer overflow
//! in authored code panics and denies on both backends instead of wrapping on the host.
//!
//! Crate boundary: `core.rs` with the host backend becomes `sdk/core`; the Soroban backend moves
//! with the policy wallet crates. `core.rs` names only general operations: each rail maps its
//! native operations onto `AllowitOperation`.
//!
//! ```
//! use allowit::prelude::*;
//! /// Control for the test below: the same policy without the server-only call compiles onchain.
//! pub fn execute(ctx: &AllowitContext) -> allowit::Result {
//!     allowit::spent_cap(ctx, ctx.params.get(allowit::SPENT_CAP))?;
//!     Ok(())
//! }
//! ```
//!
//! ```compile_fail,E0425
//! use allowit::prelude::*;
//! /// A Custom policy that calls a server-only function does not build onchain.
//! pub fn execute(ctx: &AllowitContext) -> allowit::Result {
//!     allowit::spent_cap(ctx, ctx.params.get(allowit::SPENT_CAP))?;
//!     allowit::clear_systemone_context(ctx)?;
//!     Ok(())
//! }
//! ```
//!
//! A policy never re-enters the wallet. `reentry_transfer` exists only on rails that implement
//! it; neither backend here has it, so a policy that calls it does not compile:
//!
//! ```compile_fail,E0425
//! use allowit::prelude::*;
//! /// A policy that re-enters the wallet does not build onchain.
//! pub fn execute(ctx: &AllowitContext) -> allowit::Result {
//!     allowit::reentry_transfer(ctx, 1)?;
//!     Ok(())
//! }
//! ```
#[cfg(feature = "std")]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

#[cfg(not(any(feature = "soroban", feature = "std")))]
compile_error!("Enable feature `soroban` or `std`");

#[cfg(all(feature = "soroban", feature = "std"))]
compile_error!(
    "Features `soroban` and `std` select different crate-root types; use `default-features = false`"
);

/// Onchain backend. Params, state, request facts and errors are Soroban contract types.
#[cfg(feature = "soroban")]
pub mod soroban {
    pub use soroban_sdk::{Address, String, Vec};
    use soroban_sdk::{Env as AllowitEnv, Map, Symbol};
    /// Make a `core.rs` value type a Soroban contract type.
    macro_rules! value {
        ($item:item) => {
            #[soroban_sdk::contracttype]
            $item
        };
    }
    /// Make the `core.rs` error enum a Soroban contract error.
    macro_rules! error {
        ($item:item) => {
            #[soroban_sdk::contracterror]
            $item
        };
    }
    /// Make `AllowitParams` a Soroban contract type with a public map, which the wallet builds
    /// from stored params and request args.
    macro_rules! params {
        ($(#[$meta:meta])* $name:ident($($map:tt)*)) => {
            #[soroban_sdk::contracttype]
            $(#[$meta])*
            pub struct $name(
                /// The key => value map.
                pub $($map)*,
            );
        };
    }
    include!("core.rs");

    /// Temporary-storage key of the running operation's policy writes. `post_flight` removes it,
    /// and a failed operation rolls it back, so it never outlives the transaction.
    const WRITES: Symbol = soroban_sdk::symbol_short!("allowit_w");

    /// The value of `key` in `map`, or `None` when it is absent or no map can hold the key.
    fn lookup(map: &AllowitMap, key: &str) -> Option<AllowitValue> {
        key_ok(key)
            .then(|| map.get(Symbol::new(map.env(), key)))
            .flatten()
    }

    /// Set `key` to `value` in `map`. An invalid key is `InvalidParam`.
    fn insert(map: &mut AllowitMap, key: &str, value: AllowitValue) -> Result {
        if !key_ok(key) {
            return Err(AllowitError::InvalidParam);
        }
        let key = Symbol::new(map.env(), key);
        map.set(key, value);
        Ok(())
    }

    /// The number of entries in `map`.
    fn count(map: &AllowitMap) -> u32 {
        map.len()
    }

    /// The byte length of a text value.
    fn text_len(text: &String) -> u32 {
        text.len()
    }

    /// The bytes of a text value, copied into `buf`, or `None` beyond `MAX_TEXT` bytes.
    fn text_bytes<'a>(text: &'a String, buf: &'a mut [u8; MAX_TEXT as usize]) -> Option<&'a [u8]> {
        let bytes = buf.get_mut(..text.len() as usize)?;
        text.copy_into_slice(bytes);
        Some(bytes)
    }

    /// The text of an address: its StrKey.
    fn address_text(address: &Address) -> String {
        address.to_string()
    }

    /// Abort the whole contract call with contract error `error`. Every write of the call rolls back.
    fn fail(env: &AllowitEnv, error: AllowitError, _key: &str) -> ! {
        env.panic_with_error(error)
    }

    /// Run the policy. A panic aborts the whole contract call, which rolls back every write.
    fn guarded(_env: &AllowitEnv, run: impl FnOnce() -> Result) -> Result {
        run()
    }

    /// Read a `List` of `Addr` values as addresses; any other value is `InvalidParam`.
    impl TryFrom<AllowitValue> for Vec<Address> {
        /// A value of another type.
        type Error = AllowitError;
        /// The addresses of a `List` of `Addr`.
        fn try_from(value: AllowitValue) -> Result<Self> {
            let AllowitValue::List(items) = value else {
                return Err(AllowitError::InvalidParam);
            };
            let mut addresses = Vec::new(items.env());
            each_item(&items, |item| {
                addresses.push_back(Address::try_from(item)?);
                Ok(())
            })?;
            Ok(addresses)
        }
    }

    /// Run `check` on each value of `map`. An empty key or a value that does not decode is
    /// `InvalidParam`. A `Symbol` already holds at most 32 ASCII letters, digits or underscores,
    /// so an empty key is the only one that the host rejects and a `Symbol` admits.
    fn each_value(map: &AllowitMap, mut check: impl FnMut(AllowitValue) -> Result) -> Result {
        let empty = Symbol::new(map.env(), "");
        for entry in map.try_iter() {
            let (key, value) = entry.map_err(|_| AllowitError::InvalidParam)?;
            if key == empty {
                return Err(AllowitError::InvalidParam);
            }
            check(value)?;
        }
        Ok(())
    }

    /// Run `check` on each item of a list. An item that does not decode is `InvalidParam`.
    fn each_item(
        items: &Vec<AllowitValue>,
        mut check: impl FnMut(AllowitValue) -> Result,
    ) -> Result {
        for item in items.try_iter() {
            check(item.map_err(|_| AllowitError::InvalidParam)?)?;
        }
        Ok(())
    }

    /// Buffer one policy write for `post_flight`.
    fn record(env: &AllowitEnv, key: &str, value: AllowitValue) -> Result {
        let store = env.storage().temporary();
        let mut writes = store.get(&WRITES).unwrap_or_else(|| Map::new(env));
        insert(&mut writes, key, value)?;
        store.set(&WRITES, &writes);
        Ok(())
    }

    /// Remove and return the buffered policy writes.
    fn take_writes(env: &AllowitEnv) -> AllowitMap {
        let store = env.storage().temporary();
        let writes: AllowitMap = store.get(&WRITES).unwrap_or_else(|| Map::new(env));
        if !writes.is_empty() {
            store.remove(&WRITES);
        }
        writes
    }

    /// Apply `writes` over `state`.
    fn merge(state: &mut AllowitMap, writes: AllowitMap) {
        for (key, value) in writes.iter() {
            state.set(key, value);
        }
    }
}

/// Host backend for the offchain server and SDK evaluator. Addresses are StrKey strings.
#[cfg(feature = "std")]
pub mod host {
    use alloc::collections::BTreeMap;
    pub use alloc::{string::String, vec::Vec};
    use std::sync::{Arc, Mutex, MutexGuard};

    /// Exact account or contract identity, held as its StrKey text. It compares only for
    /// equality. Soroban orders addresses by `ScAddress`, so accounts sort before contracts, while
    /// text would sort by StrKey; `Address` therefore has no order on the host, and authored code
    /// that orders addresses fails the std-only compile.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct Address(String);

    impl Address {
        /// The address with this StrKey text. The server supplies a validated StrKey.
        pub fn new(strkey: impl Into<String>) -> Self {
            Self(strkey.into())
        }

        /// The StrKey text of this address.
        pub fn as_str(&self) -> &str {
            &self.0
        }
    }

    /// Host map: keys are text checked like Soroban `Symbol`s.
    type Map<K, V> = BTreeMap<K, V>;
    /// Host map key.
    type Symbol = String;

    /// Host environment of policy evaluations. It buffers the policy's `set_state` writes for
    /// `post_flight` and records the error of a failed `param` or `arg` read; clones share both.
    /// `evaluate` clears them before a run and the writes on denial.
    #[derive(Clone, Debug)]
    pub struct AllowitEnv {
        writes: Arc<Mutex<AllowitMap>>,
        failure: Arc<Mutex<Option<AllowitError>>>,
    }

    impl AllowitEnv {
        /// The environment of a new evaluation, with no buffered writes.
        #[allow(clippy::new_without_default)]
        pub fn new() -> Self {
            Self {
                writes: Arc::new(Mutex::new(BTreeMap::new())),
                failure: Arc::new(Mutex::new(None)),
            }
        }

        /// The write buffer. A panic while it was held leaves no partial write, so it stays usable.
        fn buffer(&self) -> MutexGuard<'_, AllowitMap> {
            self.writes
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
        }

        /// The error of the last failed `param` or `arg` read.
        fn failure(&self) -> MutexGuard<'_, Option<AllowitError>> {
            self.failure
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
        }
    }

    /// Keep a `core.rs` value type a plain Rust type.
    macro_rules! value {
        ($item:item) => {
            $item
        };
    }
    /// Keep the `core.rs` error enum a plain Rust enum.
    macro_rules! error {
        ($item:item) => {
            $item
        };
    }
    /// Keep the map of `AllowitParams` private to this crate, so the std-only compile of
    /// authored policy rejects any read other than `get`. The server converts with `From`.
    macro_rules! params {
        ($(#[$meta:meta])* $name:ident($($map:tt)*)) => {
            $(#[$meta])*
            pub struct $name(
                /// The key => value map.
                pub(crate) $($map)*,
            );
        };
    }
    include!("core.rs");

    /// The server builds params and args from a key => value map.
    impl From<AllowitMap> for AllowitParams {
        /// Params holding `map`.
        fn from(map: AllowitMap) -> Self {
            Self(map)
        }
    }

    /// The server reads back the key => value map of params or args.
    impl From<AllowitParams> for AllowitMap {
        /// The map of `params`.
        fn from(params: AllowitParams) -> Self {
            params.0
        }
    }

    /// The value of `key` in `map`, or `None` when it is absent or no map can hold the key.
    fn lookup(map: &AllowitMap, key: &str) -> Option<AllowitValue> {
        key_ok(key).then(|| map.get(key).cloned()).flatten()
    }

    /// Set `key` to `value` in `map`. An invalid key is `InvalidParam`.
    fn insert(map: &mut AllowitMap, key: &str, value: AllowitValue) -> Result {
        if !key_ok(key) {
            return Err(AllowitError::InvalidParam);
        }
        map.insert(String::from(key), value);
        Ok(())
    }

    /// The number of entries in `map`.
    fn count(map: &AllowitMap) -> u32 {
        u32::try_from(map.len()).unwrap_or(u32::MAX)
    }

    /// The byte length of a text value.
    fn text_len(text: &String) -> u32 {
        u32::try_from(text.len()).unwrap_or(u32::MAX)
    }

    /// The bytes of a text value, or `None` beyond `MAX_TEXT` bytes.
    fn text_bytes<'a>(text: &'a String, _buf: &'a mut [u8; MAX_TEXT as usize]) -> Option<&'a [u8]> {
        (text.len() <= MAX_TEXT as usize).then_some(text.as_bytes())
    }

    /// The text of an address: its StrKey.
    fn address_text(address: &Address) -> String {
        String::from(address.as_str())
    }

    /// Record `error` for `evaluate` and panic with a message that names it and `key`.
    #[track_caller]
    fn fail(env: &AllowitEnv, error: AllowitError, key: &str) -> ! {
        *env.failure() = Some(error);
        panic!("allowit: {error:?} for `{key}`")
    }

    /// Run the policy and turn a panic into a denial: the recorded error of a failed `param` or
    /// `arg` read, or `Panicked`. The process keeps running.
    fn guarded(env: &AllowitEnv, run: impl FnOnce() -> Result) -> Result {
        env.failure().take();
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(run))
            .unwrap_or_else(|_| Err(env.failure().take().unwrap_or(AllowitError::Panicked)))
    }

    /// Read a `List` of `Addr` values as addresses; any other value is `InvalidParam`.
    impl TryFrom<AllowitValue> for Vec<Address> {
        /// A value of another type.
        type Error = AllowitError;
        /// The addresses of a `List` of `Addr`.
        fn try_from(value: AllowitValue) -> Result<Self> {
            match value {
                AllowitValue::List(items) => items.into_iter().map(Address::try_from).collect(),
                _ => Err(AllowitError::InvalidParam),
            }
        }
    }

    /// Run `check` on each value of `map`. A key that no Soroban map could hold is `InvalidParam`.
    fn each_value(map: &AllowitMap, mut check: impl FnMut(AllowitValue) -> Result) -> Result {
        for (key, value) in map {
            if !key_ok(key) {
                return Err(AllowitError::InvalidParam);
            }
            check(value.clone())?;
        }
        Ok(())
    }

    /// Run `check` on each item of a list.
    fn each_item(
        items: &Vec<AllowitValue>,
        mut check: impl FnMut(AllowitValue) -> Result,
    ) -> Result {
        items.iter().try_for_each(|item| check(item.clone()))
    }

    /// Buffer one policy write for `post_flight`.
    fn record(env: &AllowitEnv, key: &str, value: AllowitValue) -> Result {
        insert(&mut env.buffer(), key, value)
    }

    /// Remove and return the buffered policy writes.
    fn take_writes(env: &AllowitEnv) -> AllowitMap {
        core::mem::take(&mut *env.buffer())
    }

    /// Apply `writes` over `state`.
    fn merge(state: &mut AllowitMap, writes: AllowitMap) {
        state.extend(writes);
    }

    /// Server-only enrichment. Each function takes its owner-written request, returns its passing
    /// constraint or an `AllowitError`, and is an API stub that the offchain server fills; here it
    /// is `Unsupported`. The Soroban backend has none of them, so onchain policy cannot call one.
    pub mod server {
        use super::{Address, AllowitContext, AllowitError, AllowitValue, Result};

        /// Price check: `amount` of `from` priced in `to` must stay within `slip` of `price`.
        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct AllowitPrice {
            /// Asset priced.
            pub from: Address,
            /// Quote asset.
            pub to: Address,
            /// Units of `from` priced.
            pub amount: i128,
            /// Expected price: units of `to` per unit of `from`, scaled by 10^7.
            pub price: i128,
            /// Largest accepted deviation from `price`, in basis points.
            pub slip: u32,
        }
        /// Fetch request: the response must verify under `pubkey`.
        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct AllowitFetch<'a> {
            /// HTTP method, such as `GET`.
            pub method: &'a str,
            /// Requested URL.
            pub url: &'a str,
            /// Request body; empty for none.
            pub data: &'a str,
            /// Key that signs the expected response.
            pub pubkey: &'a str,
        }
        /// Internet search request.
        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct AllowitInternetSearch<'a> {
            /// Search query.
            pub query: &'a str,
        }
        /// Marketplace search request.
        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct AllowitMarketplaceSearch<'a> {
            /// Search query.
            pub query: &'a str,
        }
        /// Request screening: the request must score at least `deny_below`.
        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct AllowitRequestScreening<'a> {
            /// What the screening checks the request for.
            pub query: &'a str,
            /// Lowest passing score, in basis points.
            pub deny_below: u32,
        }
        /// SystemOne question within the evaluation's SystemOne context `id`.
        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct AllowitSystemOne<'a> {
            /// SystemOne context identifier.
            pub id: &'a str,
            /// Question asked.
            pub query: &'a str,
            /// A confidence below this denies, in basis points.
            pub deny_below: u32,
            /// A confidence at or above this passes without review, in basis points.
            pub allow_above: u32,
        }

        /// Check a price; returns the observed price.
        pub fn price(_ctx: &AllowitContext, _request: &AllowitPrice) -> Result<i128> {
            Err(AllowitError::Unsupported)
        }
        /// Fetch a verified response; returns it as a value.
        pub fn fetch(_ctx: &AllowitContext, _request: &AllowitFetch) -> Result<AllowitValue> {
            Err(AllowitError::Unsupported)
        }
        /// Search the internet; returns the results as a value.
        pub fn internet_search(
            _ctx: &AllowitContext,
            _request: &AllowitInternetSearch,
        ) -> Result<AllowitValue> {
            Err(AllowitError::Unsupported)
        }
        /// Search marketplaces; returns the results as a value.
        pub fn marketplace_search(
            _ctx: &AllowitContext,
            _request: &AllowitMarketplaceSearch,
        ) -> Result<AllowitValue> {
            Err(AllowitError::Unsupported)
        }
        /// Screen the request; returns its passing score.
        pub fn request_screening(
            _ctx: &AllowitContext,
            _request: &AllowitRequestScreening,
        ) -> Result<u32> {
            Err(AllowitError::Unsupported)
        }
        /// Ask SystemOne; returns its passing confidence.
        pub fn systemone(_ctx: &AllowitContext, _request: &AllowitSystemOne) -> Result<u32> {
            Err(AllowitError::Unsupported)
        }
        /// Clear the evaluation's SystemOne context.
        pub fn clear_systemone_context(_ctx: &AllowitContext) -> Result {
            Err(AllowitError::Unsupported)
        }
    }
    pub use server::*;
}

#[cfg(feature = "soroban")]
pub use soroban::*;

#[cfg(feature = "std")]
pub use host::*;

#[cfg(all(test, feature = "soroban"))]
mod tests;
