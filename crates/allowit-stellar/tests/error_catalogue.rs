//! Every typed error code that this rail gives a refusal has an entry in the error catalogue of
//! Allowit core (`allowit_core::errors`). Hosts show the entry's title with the rail's own message
//! and the help page of the code, so a code without an entry would reach an owner or an agent
//! without a title.
//!
//! `src/provider/diagnostics.rs` gives the rail's own codes: the test reads each string literal
//! there, before its unit tests, that has the form of a code and is no key of a JSON object. The
//! codes that the other files name are listed in `NAMED`, and the test checks that each file still
//! names each of them. The reason codes of the payment protocol that the settlement service returns
//! (`invalidReason`, `errorReason`) belong to that protocol and are not in the catalogue.
use allowit_core::errors;
use std::collections::BTreeSet;

/// The codes that files other than the diagnostics name, with the file's text.
const NAMED: [(&str, &str, &[&str]); 3] = [
    (
        "src/provider/runtime/client.rs",
        include_str!("../src/provider/runtime/client.rs"),
        &[
            "network_unavailable",
            "operation_changed",
            "operation_refused",
            "operation_unresolved",
            "policy_denied",
            "wallet_rejected",
        ],
    ),
    (
        "src/provider/runtime/owner_client/workflow.rs",
        include_str!("../src/provider/runtime/owner_client/workflow.rs"),
        &["owner_transaction_expired", "owner_transaction_pending"],
    ),
    (
        "npm/stellar/src/adk-owner-workflow.ts",
        include_str!("../../../npm/stellar/src/adk-owner-workflow.ts"),
        &["owner_transaction_expired", "owner_transaction_failed"],
    ),
];

/// Each string literal of `text` with the text after it. It reads Rust source: a literal in
/// double quotes with its escapes, a raw literal (`r"…"`, `r#"…"#`) and a byte literal, and it
/// skips line and block comments and character literals, so a quote in a comment or in a
/// character pairs with nothing.
fn literals(text: &str) -> Vec<(&str, &str)> {
    let bytes = text.as_bytes();
    let ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let mut found = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let rest = &text[i..];
        if rest.starts_with("//") {
            i += rest.find('\n').unwrap_or(rest.len());
        } else if rest.starts_with("/*") {
            i += rest.find("*/").map_or(rest.len(), |end| end + 2);
        } else if bytes[i] == b'\'' {
            // A character literal, or a lifetime, which has no closing quote.
            i += match (bytes.get(i + 1), bytes.get(i + 2)) {
                (Some(b'\\'), _) => rest[2..].find('\'').map_or(rest.len(), |end| end + 3),
                (Some(_), Some(b'\'')) => 3,
                _ => 1,
            };
        } else if bytes[i] == b'"'
            || (bytes[i] == b'r'
                && (i == 0 || !ident(bytes[i - 1]))
                && matches!(bytes.get(i + 1), Some(b'"' | b'#')))
        {
            let raw = bytes[i] == b'r';
            let hashes = if raw {
                rest[1..].len() - rest[1..].trim_start_matches('#').len()
            } else {
                0
            };
            let open = i + usize::from(raw) + hashes;
            if bytes.get(open) != Some(&b'"') {
                i += 1;
                continue;
            }
            let start = open + 1;
            let mut end = start;
            if raw {
                let close = format!("\"{}", "#".repeat(hashes));
                end += text[start..]
                    .find(close.as_str())
                    .unwrap_or(text.len() - start);
                i = (end + close.len()).min(text.len());
            } else {
                while end < bytes.len() && bytes[end] != b'"' {
                    end += if bytes[end] == b'\\' { 2 } else { 1 };
                }
                end = end.min(text.len());
                i = (end + 1).min(text.len());
            }
            found.push((&text[start..end], &text[i..]));
        } else {
            i += 1;
        }
    }
    found
}

/// The codes of `text` before its unit tests: each literal with the form of a code that is no key
/// of a JSON object (a literal followed by one colon).
fn codes(text: &str) -> BTreeSet<&str> {
    let text = text
        .find("#[cfg(test)]\nmod tests {")
        .map_or(text, |end| &text[..end]);
    literals(text)
        .into_iter()
        .filter(|(value, after)| {
            let after = after.trim_start();
            errors::is_code(value) && !(after.starts_with(':') && !after.starts_with("::"))
        })
        .map(|(value, _)| value)
        .collect()
}

#[test]
fn every_typed_code_of_the_rail_has_a_catalogue_entry() {
    let codes = codes(include_str!("../src/provider/diagnostics.rs"));
    // The codes of the wallet contract's errors, of a policy denial and of the owner's reads.
    for expected in [
        "policy_denied",
        "wallet_paused",
        "insufficient_funds",
        "stale_request",
        "wallet_rejected",
        "stale_owner_observation",
        "nothing_to_return",
        "params_differ_from_wallet",
    ] {
        assert!(codes.contains(expected), "{expected} was not found");
    }
    let missing: Vec<&str> = codes
        .iter()
        .copied()
        .filter(|code| errors::entry(code).is_none())
        .collect();
    assert!(
        missing.is_empty(),
        "these typed codes have no entry in the error catalogue of allowit-core \
         (typescript/error-catalogue.json): {missing:?}"
    );
    // The codes that the other files name: each file still names each code, and each has an entry.
    for (file, text, named) in NAMED {
        for code in named {
            assert!(
                text.contains(&format!("\"{code}\"")) || text.contains(&format!("'{code}'")),
                "{file} no longer names {code}"
            );
            assert!(
                errors::entry(code).is_some(),
                "{code} of {file} has no entry"
            );
        }
    }
    // The codes that the rail gives as Core's own constants: those of the custom wallet build,
    // and a lapsed contract's.
    use allowit_core::vendor::custom_build::code;
    for defined in [
        code::CODE_HASH_MISMATCH,
        code::TOOLCHAIN_MISSING,
        code::BUILD_FAILED,
        allowit_core::vendor::runtime::CONTRACT_EXPIRED,
    ] {
        assert!(errors::entry(defined).is_some(), "{defined}");
    }
}

#[test]
fn the_scan_reads_rust_literals_and_leaves_out_json_keys_and_tests() {
    let text = concat!(
        "// A comment with one \" quote.\n",
        "let c = '\"'; let d = '\\''; fn f<'a>() {}\n",
        "coded(409, \"wallet_paused\", \"A text.\")\n",
        ".with_details(json!({\"rule\": rule, \"error\":name}))\n",
        "/* a block \" comment */ coded(409, r#\"raw_code\"#, m);\n",
        "\"Paused\" => \"after_an_arm\",\n",
        "path::to::thing(\"before_a_path\")::other\n",
        "#[cfg(test)]\nmod tests {\n \"in_a_test\" }",
    );
    assert_eq!(
        codes(text),
        BTreeSet::from(["wallet_paused", "raw_code", "after_an_arm", "before_a_path"])
    );
}
