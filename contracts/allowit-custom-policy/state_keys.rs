//! The state entries and the figures of a compiled Custom policy source, found the same way by
//! the contract's build and by the rail's server evaluation. A source reads and writes its state with
//! `allowit::get_state(ctx, "key")` and `allowit::set_state(ctx, "key", value)`; the key is a
//! string literal of 1 to 32 ASCII letters, digits or `_`. Comments and the contents of string and
//! character literals are never read as calls.

/// Most state entries of one policy: `allowit_policy_wallet::MAX_POLICY_STATE`.
pub const MAX_POLICY_STATE: usize = 8;
/// Most packed bytes of one state value: `allowit_policy_wallet::MAX_STATE_VALUE`.
pub const MAX_STATE_VALUE: usize = 64;

/// The standard figures by key, and the figures that a `get_state` read of each keeps: `SPENT`
/// (1), `CALLS` (2), `DAY_SPENT` (4), `DAY_TOTAL` (8). A policy never writes one.
pub const STANDARD: [(&str, u8); 7] = [
    ("spent", 1),
    ("unpriced", 1),
    ("calls", 2),
    ("day_spent", 4),
    ("day_total", 8),
    ("day_unpriced", 4 | 8),
    ("day", 0),
];

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

/// The cumulated figures that the checks of the compiled policy source `compiled` read, so the
/// wallet keeps exactly those. `read` are the figures of its `get_state` reads of standard keys,
/// from [`declared`].
///
/// Core's source gate admits rule calls only as `allowit::<rule>`, so a rule name in the compiled
/// source marks its figure; any name that can reach the whole state or every rule marks all
/// figures. The scan reads whole words, leaving out lines that start with `//`; words in a
/// literal or a trailing comment can only add figures.
pub fn figures(compiled: &str, read: u8) -> u8 {
    let code = without_comments(compiled);
    let words: Vec<&str> = code
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|word| !word.is_empty())
        .collect();
    if words.iter().any(|word| {
        ALL.contains(word) || (word.contains("state") && !["get_state", "set_state"].contains(word))
    }) {
        return 15;
    }
    RULES
        .iter()
        .filter(|(name, _)| words.contains(name))
        .fold(read, |figures, (_, figure)| figures | figure)
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

/// One declared state entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateEntry {
    /// The source's key name.
    pub name: String,
    /// The storage key: the first four bytes of the SHA-256 of the name, big-endian.
    pub key: u32,
    /// A `day_` key lives one daily window in a temporary entry; any other key is persistent.
    pub daily: bool,
}

/// The declared entries of a source, sorted by name, and the figures that its `get_state` reads
/// of standard keys keep. `sha256` hashes a key name.
pub fn declared(
    code: &str,
    sha256: impl Fn(&[u8]) -> [u8; 32],
) -> Result<(Vec<StateEntry>, u8), String> {
    let mut figures = 0u8;
    let mut names: Vec<String> = Vec::new();
    for (writes, key) in calls(code)? {
        if let Some((_, figure)) = STANDARD.iter().find(|(name, _)| *name == key) {
            if writes {
                return Err(format!(
                    "a policy does not write the standard figure {key:?}: the wallet keeps it"
                ));
            }
            figures |= figure;
        } else if !names.contains(&key) {
            names.push(key);
        }
    }
    names.sort_unstable();
    if names.len() > MAX_POLICY_STATE {
        return Err(format!(
            "a policy keeps at most {MAX_POLICY_STATE} state entries; this one names {}",
            names.len()
        ));
    }
    let mut entries: Vec<StateEntry> = Vec::new();
    for name in names {
        let digest = sha256(name.as_bytes());
        let key = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
        if entries.iter().any(|entry| entry.key == key) {
            return Err(format!(
                "two state keys share a storage key; rename {name:?}"
            ));
        }
        entries.push(StateEntry {
            daily: name.starts_with("day_"),
            name,
            key,
        });
    }
    Ok((entries, figures))
}

/// One token of Rust source: an identifier or keyword, a string literal's contents, or one
/// punctuation character. Comments, whitespace, numbers and character literals are dropped.
#[derive(Debug, PartialEq, Eq)]
enum Token {
    Ident(String),
    Str(String),
    Punct(char),
}

fn tokens(code: &str) -> Result<Vec<Token>, String> {
    let chars: Vec<char> = code.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    let unterminated = || "an unterminated literal or comment in the policy source".to_owned();
    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        if c.is_whitespace() {
            i += 1;
        } else if c == '/' && next == Some('/') {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
        } else if c == '/' && next == Some('*') {
            // Block comments nest in Rust.
            let mut depth = 0;
            loop {
                match (chars.get(i), chars.get(i + 1)) {
                    (Some('/'), Some('*')) => {
                        depth += 1;
                        i += 2;
                    }
                    (Some('*'), Some('/')) => {
                        depth -= 1;
                        i += 2;
                        if depth == 0 {
                            break;
                        }
                    }
                    (Some(_), _) => i += 1,
                    (None, _) => return Err(unterminated()),
                }
            }
        } else if c == 'r' && matches!(next, Some('"') | Some('#')) && !ident_continues(&chars, i) {
            // A raw string: r"...", r#"..."#; or a raw identifier r#name.
            let mut j = i + 1;
            let mut hashes = 0;
            while chars.get(j) == Some(&'#') {
                hashes += 1;
                j += 1;
            }
            if chars.get(j) == Some(&'"') {
                let start = j + 1;
                let mut k = start;
                loop {
                    if k >= chars.len() {
                        return Err(unterminated());
                    }
                    if chars[k] == '"' && (0..hashes).all(|h| chars.get(k + 1 + h) == Some(&'#')) {
                        break;
                    }
                    k += 1;
                }
                out.push(Token::Str(chars[start..k].iter().collect()));
                i = k + 1 + hashes;
            } else {
                // A raw identifier names the same item as the plain one.
                let start = j;
                while chars
                    .get(j)
                    .is_some_and(|c| c.is_alphanumeric() || *c == '_')
                {
                    j += 1;
                }
                out.push(Token::Ident(chars[start..j].iter().collect()));
                i = j;
            }
        } else if c == 'b' && next == Some('"') {
            i += 1;
        } else if c == '"' {
            let mut text = String::new();
            i += 1;
            loop {
                match chars.get(i) {
                    Some('\\') => {
                        text.push('\\');
                        if let Some(escaped) = chars.get(i + 1) {
                            text.push(*escaped);
                        }
                        i += 2;
                    }
                    Some('"') => {
                        i += 1;
                        break;
                    }
                    Some(c) => {
                        text.push(*c);
                        i += 1;
                    }
                    None => return Err(unterminated()),
                }
            }
            out.push(Token::Str(text));
        } else if c == '\'' {
            // A character literal, or a lifetime: skip `'x'`, `'\n'`, `'\''`; a lifetime is a
            // quote and an identifier.
            if next == Some('\\') {
                let close = (i + 2..chars.len()).find(|&k| chars[k] == '\'' && k > i + 2);
                i = close.map(|k| k + 1).ok_or_else(unterminated)?;
            } else if chars.get(i + 2) == Some(&'\'') {
                i += 3;
            } else {
                i += 1;
            }
        } else if c.is_alphabetic() || c == '_' {
            let start = i;
            while chars
                .get(i)
                .is_some_and(|c| c.is_alphanumeric() || *c == '_')
            {
                i += 1;
            }
            out.push(Token::Ident(chars[start..i].iter().collect()));
        } else if c.is_ascii_digit() {
            while chars
                .get(i)
                .is_some_and(|c| c.is_alphanumeric() || *c == '_' || *c == '.')
            {
                i += 1;
            }
        } else {
            out.push(Token::Punct(c));
            i += 1;
        }
    }
    Ok(out)
}

/// Whether the character before `i` continues an identifier, so `chars[i]` is inside one.
fn ident_continues(chars: &[char], i: usize) -> bool {
    i > 0 && (chars[i - 1].is_alphanumeric() || chars[i - 1] == '_')
}

/// Every `get_state` and `set_state` call of `code`: whether it writes, and its key.
fn calls(code: &str) -> Result<Vec<(bool, String)>, String> {
    let tokens = tokens(code)?;
    let mut found = Vec::new();
    for (at, token) in tokens.iter().enumerate() {
        let Token::Ident(name) = token else {
            continue;
        };
        if name != "get_state" && name != "set_state" {
            continue;
        }
        let mut i = at + 1;
        // An explicit type: `get_state::<u64>(...)`.
        if tokens.get(i) == Some(&Token::Punct(':'))
            && tokens.get(i + 1) == Some(&Token::Punct(':'))
        {
            i += 2;
            if tokens.get(i) == Some(&Token::Punct('<')) {
                let mut depth = 0;
                while let Some(token) = tokens.get(i) {
                    match token {
                        Token::Punct('<') => depth += 1,
                        Token::Punct('>') => {
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
            }
        }
        if tokens.get(i) != Some(&Token::Punct('(')) {
            return Err(format!(
                "`{name}` is called as allowit::{name}(ctx, \"key\", ...)"
            ));
        }
        // The first argument ends at the first comma outside brackets.
        let mut depth = 0;
        i += 1;
        while let Some(token) = tokens.get(i) {
            match token {
                Token::Punct('(' | '[' | '{') => depth += 1,
                Token::Punct(')' | ']' | '}') => depth -= 1,
                Token::Punct(',') if depth == 0 => break,
                _ => {}
            }
            i += 1;
        }
        // The key argument is the literal alone: the next token ends the argument.
        let key = match (tokens.get(i + 1), tokens.get(i + 2)) {
            (Some(Token::Str(key)), Some(Token::Punct(',' | ')'))) => key.clone(),
            _ => {
                return Err(format!(
                    "a state key is a string literal: the wallet must know each key of `{name}` before it runs"
                ));
            }
        };
        if key.is_empty()
            || key.len() > 32
            || !key.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
        {
            return Err(format!(
                "the state key {key:?} is not 1 to 32 ASCII letters, digits or `_`"
            ));
        }
        found.push((name == "set_state", key));
    }
    Ok(found)
}
