#![no_std]
//! Soroban types, contract codecs, parameter reads and native policy state writes.
//! Shared types and rule algorithms come from the selected Core release's source resource.
//! Native panic and transaction rollback semantics belong to this vendor binding.

/// Native bindings of the shared policy source. The extracted backend retains its original terms.
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
    /// Make `AllowitArgs` a Soroban contract type with a public map, which the wallet builds from
    /// the request args.
    macro_rules! args {
        ($(#[$meta:meta])* $name:ident($($map:tt)*)) => {
            #[soroban_sdk::contracttype]
            $(#[$meta])*
            pub struct $name(
                /// The key => value map.
                pub $($map)*,
            );
        };
    }
    include!(concat!(env!("OUT_DIR"), "/core.rs"));

    /// The owner's params, read by key: `ctx.params[allowit::DESTINATIONS]`. A Soroban map
    /// decodes a value on every read, so `new` decodes the at most `MAX_PARAMS` entries once per
    /// run and indexing returns a reference to the decoded value.
    #[derive(Clone)]
    pub struct AllowitParams {
        env: AllowitEnv,
        map: AllowitMap,
        entries: [Option<(Symbol, AllowitValue)>; MAX_PARAMS as usize],
    }

    impl AllowitParams {
        /// The params of `map`, decoded. More than `MAX_PARAMS` entries or an entry that does
        /// not decode is `InvalidParam`.
        pub fn new(env: &AllowitEnv, map: AllowitMap) -> Result<Self> {
            if count(&map) > MAX_PARAMS {
                return Err(AllowitError::InvalidParam);
            }
            let mut entries = core::array::from_fn(|_| None);
            for (slot, entry) in entries.iter_mut().zip(map.try_iter()) {
                *slot = Some(entry.map_err(|_| AllowitError::InvalidParam)?);
            }
            Ok(Self {
                env: env.clone(),
                map,
                entries,
            })
        }

        /// The key => value map that the wallet stores.
        pub fn map(&self) -> &AllowitMap {
            &self.map
        }
    }

    /// The decoded value of `key` in `params`, or `None` when it is unset or no map can hold the
    /// key.
    fn find<'a>(params: &'a AllowitParams, key: &str) -> Option<&'a AllowitValue> {
        if !key_ok(key) {
            return None;
        }
        let key = Symbol::new(&params.env, key);
        let mut entries = params.entries.iter().flatten();
        entries.find(|(k, _)| *k == key).map(|(_, value)| value)
    }

    /// Abort the whole contract call with `MissingParam` for unset param `key`.
    fn missing(params: &AllowitParams, key: &str) -> ! {
        fail(&params.env, AllowitError::MissingParam, key)
    }

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

    /// Abort the whole contract call: a typed read met a value of another type or range. A value
    /// carries no environment, so the abort is a panic with no contract error code. The host
    /// rolls back every write of the invocation.
    #[track_caller]
    fn mistyped() -> ! {
        panic!("allowit: InvalidParam")
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

pub use soroban::*;

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use soroban_sdk::{Env, Map, Symbol, testutils::Address as _, vec};
    use std::panic::{AssertUnwindSafe, catch_unwind};

    /// The Soroban variant of Core's `ok_reads_a_param_as_the_type_of_its_binding`.
    #[test]
    fn ok_reads_a_param_as_the_type_of_its_binding_and_a_mistyped_read_aborts() {
        let env = Env::default();
        let seller = Address::generate(&env);
        let mut map = Map::new(&env);
        let mut set = |key: &str, value: AllowitValue| map.set(Symbol::new(&env, key), value);
        set("floor", AllowitValue::Int(-7));
        set("zero", AllowitValue::Int(0));
        set("output", AllowitValue::Addr(seller.clone()));
        set(
            "sellers",
            AllowitValue::List(vec![&env, AllowitValue::Addr(seller.clone())]),
        );
        set("flag", AllowitValue::Bool(true));
        let params = AllowitParams::new(&env, map).unwrap();
        let floor: i128 = params["floor"].ok();
        let zero: u64 = params["zero"].ok();
        let output: Address = params["output"].ok();
        let sellers: Vec<Address> = params["sellers"].ok();
        let same: AllowitValue = params["sellers"].ok();
        assert_eq!((floor, zero, output), (-7, 0, seller.clone()));
        assert_eq!(sellers, vec![&env, seller]);
        assert_eq!(same, params["sellers"]);
        // A missing key or a value of another type or range aborts the invocation. Nothing
        // stands in for it.
        let aborts = |read: &dyn Fn()| catch_unwind(AssertUnwindSafe(read)).is_err();
        assert!(aborts(&|| {
            let _: i128 = params["absent"].ok();
        }));
        assert!(aborts(&|| {
            let _: i128 = params["flag"].ok();
        }));
        assert!(aborts(&|| {
            let _: u64 = params["floor"].ok();
        }));
        assert!(aborts(&|| {
            let _: Address = params["sellers"].ok();
        }));
        assert!(aborts(&|| {
            let _: Vec<Address> = params["floor"].ok();
        }));
        assert!(!aborts(&|| {
            let _: i128 = params["floor"].ok();
        }));
    }
}
