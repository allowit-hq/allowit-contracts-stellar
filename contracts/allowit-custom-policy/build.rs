//! Bind the contract to its policy source and declare the figures that the policy reads.
//!
//! `SOURCE_HASH` is the SHA-256 of the owner's full source: `policy/source.rs` when it is present
//! (the owner's one source, from which the compiled on-chain policy is derived), else the compiled
//! `policy/policy.rs` itself. The owner's policy signature binds that hash, and the wallet stores it.
//!
//! `FIGURES` lists the cumulated figures that the compiled policy's checks read, so the wallet
//! keeps exactly those. Core's source gate admits rule calls only as `allowit::<rule>`, so a rule
//! name in the compiled source marks its figure; any name that can reach the whole state or every
//! rule marks all figures. The scan reads whole words, leaving out lines that start with `//`;
//! words in a literal or a trailing comment can only add figures.
//!
//! `STATE` lists the policy's own state entries: every key of an `allowit::get_state` and
//! `allowit::set_state` call. A key is a string literal of 1 to 32 ASCII letters, digits or `_`;
//! a `day_` key lives one daily window, any other key the minimum persistent lifetime. The
//! storage key is the first four bytes of the key's SHA-256. The build refuses a key that is not
//! a literal, a write of a standard figure, more than `MAX_POLICY_STATE` keys and two keys with
//! one storage key. Reading a standard figure through `get_state` keeps that figure.
use sha2::{Digest, Sha256};
use std::{env, fs, path::Path};

/// Rule names and the figures they read: `SPENT`, `CALLS`, `DAY_SPENT`, `DAY_TOTAL`.
const RULES: [(&str, u8); 4] = [
    ("lifetime_spending_limit", 1),
    ("call_limit", 2),
    ("daily_spending_limit", 4),
    ("daily_volume_limit", 8),
];
/// Names through which a policy reads the whole state or runs any rule: they keep every figure, as
/// does any other word that contains `state`, such as `ctx.state`.
const ALL: [&str; 5] = [
    "preflight",
    "RULES",
    "AllowitRule",
    "AllowitStandardState",
    "evaluate",
];

/// The standard figures by key, and the figures that a read of each keeps.
const STANDARD: [(&str, u8); 7] = [
    ("spent", 1),
    ("unpriced", 1),
    ("calls", 2),
    ("day_spent", 4),
    ("day_total", 8),
    ("day_unpriced", 4 | 8),
    ("day", 0),
];
/// Most state entries of one policy: `allowit_policy_wallet::MAX_POLICY_STATE`.
const MAX_POLICY_STATE: usize = 8;

/// One state call of the source: whether it writes, and its key.
struct StateCall {
    writes: bool,
    key: String,
}

/// Every `get_state` and `set_state` call of `code`, with its key. A call whose second argument
/// is not a string literal stops the build: the wallet must know each key before it runs.
fn state_calls(code: &str) -> Vec<StateCall> {
    let bytes = code.as_bytes();
    let word = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let mut calls = Vec::new();
    for name in ["get_state", "set_state"] {
        let mut from = 0;
        while let Some(at) = code[from..].find(name).map(|i| i + from) {
            from = at + name.len();
            if (at > 0 && word(bytes[at - 1])) || bytes.get(from).is_some_and(|c| word(*c)) {
                continue;
            }
            let mut i = from;
            let skip = |i: &mut usize| {
                while bytes.get(*i).is_some_and(|c| c.is_ascii_whitespace()) {
                    *i += 1;
                }
            };
            skip(&mut i);
            // An explicit type: `get_state::<u64>(...)`.
            if code[i..].starts_with("::<") {
                let mut depth = 0;
                while let Some(c) = bytes.get(i) {
                    match c {
                        b'<' => depth += 1,
                        b'>' => {
                            depth -= 1;
                            if depth == 0 {
                                i += 1;
                                break;
                            }
                        }
                        _ => {}
                    }
                    i += 1;
                }
                skip(&mut i);
            }
            assert!(
                bytes.get(i) == Some(&b'('),
                "`{name}` is called as allowit::{name}(ctx, \"key\", ...)"
            );
            // The first argument ends at the first comma outside brackets.
            let mut depth = 0;
            i += 1;
            while let Some(c) = bytes.get(i) {
                match c {
                    b'(' | b'[' | b'{' => depth += 1,
                    b')' | b']' | b'}' => depth -= 1,
                    b',' if depth == 0 => break,
                    _ => {}
                }
                i += 1;
            }
            i += 1;
            skip(&mut i);
            assert!(
                bytes.get(i) == Some(&b'"'),
                "a state key is a string literal: the wallet must know each key of `{name}` before it runs"
            );
            let end = code[i + 1..]
                .find('"')
                .map(|n| i + 1 + n)
                .expect("an unterminated state key");
            let key = &code[i + 1..end];
            assert!(
                !key.is_empty()
                    && key.len() <= 32
                    && key.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_'),
                "the state key {key:?} is not 1 to 32 ASCII letters, digits or `_`"
            );
            calls.push(StateCall {
                writes: name == "set_state",
                key: key.to_owned(),
            });
        }
    }
    calls
}

/// The declared state entries, sorted by key, as the `STATE` constant's source; and the figures
/// that `get_state` reads of standard keys keep.
fn declared_state(calls: &[StateCall]) -> (String, u8) {
    let mut figures = 0u8;
    let mut keys: Vec<&str> = Vec::new();
    for call in calls {
        if let Some((_, figure)) = STANDARD.iter().find(|(key, _)| *key == call.key) {
            assert!(
                !call.writes,
                "a policy does not write the standard figure {:?}: the wallet keeps it",
                call.key
            );
            figures |= figure;
        } else if !keys.contains(&call.key.as_str()) {
            keys.push(&call.key);
        }
    }
    keys.sort_unstable();
    assert!(
        keys.len() <= MAX_POLICY_STATE,
        "a policy keeps at most {MAX_POLICY_STATE} state entries; this one names {}",
        keys.len()
    );
    let mut stored: Vec<u32> = Vec::new();
    let mut entries = Vec::new();
    for key in keys {
        let digest = Sha256::digest(key.as_bytes());
        let short = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
        assert!(
            !stored.contains(&short),
            "two state keys share a storage key; rename {key:?}"
        );
        stored.push(short);
        entries.push(format!(
            "allowit_policy_wallet::AllowitStateKey {{ name: {key:?}, key: {short:#010x}, daily: {} }}",
            key.starts_with("day_")
        ));
    }
    (format!("&[{}]", entries.join(", ")), figures)
}

fn main() {
    let manifest = Path::new(&env::var("CARGO_MANIFEST_DIR").unwrap()).to_path_buf();
    // The `test-catching` and `test-daily` fixtures compile their own sources instead.
    let fixture = if env::var_os("CARGO_FEATURE_TEST_CATCHING").is_some() {
        Some("src/catching_policy.rs")
    } else if env::var_os("CARGO_FEATURE_TEST_DAILY").is_some() {
        Some("src/daily_policy.rs")
    } else {
        None
    };
    let policy = manifest.join(fixture.unwrap_or("policy/policy.rs"));
    let owner_source = manifest.join("policy/source.rs");
    println!("cargo:rerun-if-changed={}", policy.display());
    println!("cargo:rerun-if-changed={}", owner_source.display());
    let compiled = fs::read_to_string(&policy).unwrap();
    let code = without_comments(&compiled);
    let words: Vec<&str> = code
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|word| !word.is_empty())
        .collect();
    for forbidden in [
        "unsafe",
        "include!",
        "include_str!",
        "include_bytes!",
        "#[path",
    ] {
        assert!(
            !compiled.contains(forbidden),
            "a policy source is one safe file: it must not use `{forbidden}`"
        );
    }
    let source = if owner_source.exists() && fixture.is_none() {
        fs::read(&owner_source).unwrap()
    } else {
        compiled.clone().into_bytes()
    };
    let digest = Sha256::digest(&source);
    let bytes: Vec<String> = digest.iter().map(u8::to_string).collect();
    let mut figures = 0u8;
    for (name, figure) in RULES {
        if words.contains(&name) {
            figures |= figure;
        }
    }
    let (state, read_figures) = declared_state(&state_calls(&code));
    figures |= read_figures;
    if words.iter().any(|word| {
        ALL.contains(word) || (word.contains("state") && !["get_state", "set_state"].contains(word))
    }) {
        figures = 15;
    }
    let out = Path::new(&env::var("OUT_DIR").unwrap()).to_path_buf();
    fs::write(
        out.join("source_hash.rs"),
        format!("[{}]", bytes.join(", ")),
    )
    .unwrap();
    fs::write(out.join("figures.rs"), format!("{figures}")).unwrap();
    fs::write(out.join("state.rs"), state).unwrap();
}

/// The source without the lines that start with `//`: doc and line comments. Such a line is a
/// comment or the inside of a literal, never code. Trailing and block comments stay in the scan,
/// which can only add figures.
fn without_comments(source: &str) -> String {
    source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}
