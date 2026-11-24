//! The wallet's storage of what Core's derivation names for the compiled part of a Custom policy
//! source (`allowit_core::policy_source::Derived`): the entries of its figures and the storage
//! keys of the state keys that the contract keeps. The contract's build and the rail read the
//! same Core output through these functions; neither reads the source itself, except for the
//! build's text check of the compiled part ([`one_safe_file`]), which the rail runs too.

/// Most state entries of one policy: `allowit_policy_wallet::MAX_POLICY_STATE`.
pub const MAX_POLICY_STATE: usize = 8;
/// Most packed bytes of one state value: `allowit_policy_wallet::MAX_STATE_VALUE`.
pub const MAX_STATE_VALUE: usize = 64;

/// The standard state keys: the figures, and `day`. A policy never writes one.
pub const STANDARD: [&str; 7] = [
    "spent",
    "unpriced",
    "calls",
    "day_spent",
    "day_total",
    "day_unpriced",
    "day",
];

/// The text that the compiled part of a Custom policy must not hold: a policy source is one safe
/// file, which neither runs unsafe code nor reads another file.
pub const FORBIDDEN_TEXT: [&str; 5] = [
    "unsafe",
    "include!",
    "include_str!",
    "include_bytes!",
    "#[path",
];

/// Refuse a compiled part that holds a [`FORBIDDEN_TEXT`], anywhere in its text, comments
/// included. The contract's build refuses it, and the rail refuses it before a build.
pub fn one_safe_file(compiled: &str) -> Result<(), String> {
    match FORBIDDEN_TEXT.iter().find(|text| compiled.contains(*text)) {
        Some(text) => Err(format!(
            "a policy source is one safe file: it must not use `{text}`"
        )),
        None => Ok(()),
    }
}

/// The wallet entries that hold `figures`: the keys of Core's figures of the compiled source
/// (`allowit_core::policy_source::Derived::figures`). `SPENT` (1) holds `spent` and `unpriced`,
/// `CALLS` (2) holds `calls`, and the daily entry holds `day_spent` with `DAY_SPENT` (4),
/// `day_total` with `DAY_TOTAL` (8) and `day_unpriced` beside either. A daily flag without a daily
/// amount opens the entry with `DAY_SPENT`. Another key is refused.
pub fn packed<'a>(figures: impl IntoIterator<Item = &'a str>) -> Result<u8, String> {
    let mut entries = 0u8;
    let mut daily_flag = false;
    for key in figures {
        entries |= match key {
            "spent" | "unpriced" => 1,
            "calls" => 2,
            "day_spent" => 4,
            "day_total" => 8,
            "day_unpriced" => {
                daily_flag = true;
                0
            }
            _ => return Err(format!("{key:?} is no figure of a policy wallet")),
        };
    }
    if daily_flag && entries & (4 | 8) == 0 {
        entries |= 4;
    }
    Ok(entries)
}

/// One state entry that the contract keeps.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateEntry {
    /// The key, as the source names it.
    pub name: String,
    /// The storage key: the first four bytes of the SHA-256 of the name, big-endian.
    pub key: u32,
    /// The value lives one daily window in a temporary entry; any other value is persistent.
    pub daily: bool,
}

/// The state entries of the keys that the contract keeps, sorted by name: Core's keys whose keeper
/// is the chain (`Derived::state`), each with its daily lifetime. Stellar's storage adds a storage
/// key for each, and refuses a key that is no `Symbol` (1 to 32 ASCII letters, digits or `_`), a
/// standard figure, more than [`MAX_POLICY_STATE`] keys and two keys with one storage key.
/// `sha256` hashes a key name.
pub fn entries<'a>(
    keys: impl IntoIterator<Item = (&'a str, bool)>,
    sha256: impl Fn(&[u8]) -> [u8; 32],
) -> Result<Vec<StateEntry>, String> {
    let mut keys: Vec<(&str, bool)> = keys.into_iter().collect();
    keys.sort_unstable();
    keys.dedup();
    if keys.len() > MAX_POLICY_STATE {
        return Err(format!(
            "a policy keeps at most {MAX_POLICY_STATE} state entries; this one names {}",
            keys.len()
        ));
    }
    let mut entries: Vec<StateEntry> = Vec::new();
    for (name, daily) in keys {
        let symbol = (1..=32).contains(&name.len())
            && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
        if !symbol || STANDARD.contains(&name) || entries.iter().any(|entry| entry.name == name) {
            return Err(format!("{name:?} is no state key of a policy's own"));
        }
        let digest = sha256(name.as_bytes());
        let key = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
        if entries.iter().any(|entry| entry.key == key) {
            return Err(format!(
                "two state keys share a storage key; rename {name:?}"
            ));
        }
        entries.push(StateEntry {
            name: name.to_owned(),
            key,
            daily,
        });
    }
    Ok(entries)
}

/// The state keys of a `policy.state` file: one key per line, each followed by `daily` or
/// `lasting`, as the rail's build inputs write them from Core's derivation.
pub fn state_file(text: &str) -> Result<Vec<(&str, bool)>, String> {
    text.lines()
        .map(|line| match line.split_once(' ') {
            Some((key, "daily")) => Ok((key, true)),
            Some((key, "lasting")) => Ok((key, false)),
            _ => Err(format!("{line:?} is no line of a policy state file")),
        })
        .collect()
}
