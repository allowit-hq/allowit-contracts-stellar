//! Every typed error code that this rail gives a refusal has an entry in the error catalogue of
//! Allowit core (`allowit_core::errors`). Hosts show the entry's title with the rail's own message
//! and the help page of the code, so a code without an entry would reach an owner or an agent
//! without a title.
//!
//! The rail names its codes in `src/provider/diagnostics.rs`. The test reads that file: each
//! string literal there with the form of a code is a code, or is listed in `NOT_CODES`.
use allowit_core::errors;
use std::collections::BTreeSet;

/// Code-shaped literals of the diagnostics module that are not error codes: the keys of a
/// refusal's details.
const NOT_CODES: &[&str] = &["contract", "error", "rule"];

/// The string literals of `text` before its unit tests.
fn literals(text: &str) -> BTreeSet<String> {
    let text = text
        .find("#[cfg(test)]\nmod tests {")
        .map_or(text, |end| &text[..end]);
    let mut found = BTreeSet::new();
    let mut rest = text;
    while let Some(start) = rest.find('"') {
        let after = &rest[start + 1..];
        let Some(end) = after.find('"') else { break };
        found.insert(after[..end].to_owned());
        rest = &after[end + 1..];
    }
    found
}

#[test]
fn every_typed_code_of_the_rail_has_a_catalogue_entry() {
    let source = include_str!("../src/provider/diagnostics.rs");
    let codes: Vec<String> = literals(source)
        .into_iter()
        // Core's own predicate: a code of one word counts too.
        .filter(|text| errors::is_code(text) && !NOT_CODES.contains(&text.as_str()))
        .collect();
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
        assert!(
            codes.iter().any(|code| code == expected),
            "{expected} was not found"
        );
    }
    // A word listed as no code must stay one.
    for word in NOT_CODES {
        assert!(errors::entry(word).is_none(), "{word} has an entry");
    }
    let missing: Vec<&String> = codes
        .iter()
        .filter(|code| errors::entry(code).is_none())
        .collect();
    assert!(
        missing.is_empty(),
        "these typed codes have no entry in the error catalogue of allowit-core \
         (typescript/error-catalogue.json); add the entry there, or list a literal that is no \
         error code in NOT_CODES: {missing:?}"
    );
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
fn a_literal_scan_reads_each_quoted_text_before_the_tests() {
    let text =
        "coded(409, \"wallet_paused\", \"A text.\")\n#[cfg(test)]\nmod tests {\n \"in_a_test\" }";
    assert_eq!(
        literals(text),
        BTreeSet::from(["wallet_paused".to_owned(), "A text.".to_owned()])
    );
}
