#!/usr/bin/env python3
"""Write the vectors that `stellar/core` replays to match the Python admin tools.

`policy-gate-vectors.json` records what `policy_source.py` decides for a fixed corpus of
authored sources: accept or reject, and for an accepted source its standard prefix and whether
it writes state. Each source is an edit of the canonical policy: its first `head` bytes, then
`middle`, then its last `tail` bytes. `params-vectors.json` records what `contract_admin.py` `params` returns for a
fixed set of owner params and tiers. `stellar/core/tests/policy_vectors.rs` replays both files
against the Rust gate and `params_from_json`; `scripts/tests/test_core_vectors.py` checks that
both files equal what the Python tools produce now.

Run `policy-core-vectors.py` to rewrite the files, or `policy-core-vectors.py --check` to compare."""
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
FIXTURES = ROOT / "stellar/core/tests/fixtures"
GATE_FILE = FIXTURES / "policy-gate-vectors.json"
PARAMS_FILE = FIXTURES / "params-vectors.json"
CANONICAL = (ROOT / "crates/custom-policy/policy/policy.rs").read_text()
BODY = "pub fn execute(ctx: &AllowitContext) -> allowit::Result {"

# Top-level items appended to the canonical source. Each exercises one allowlist rule; most of them
# reject. The two from the review are first.
ITEMS = [
    "use std::fs;",
    "fn helper(a: &[i128]) -> bool { a.len() > 0 }",
    "use allowit::AllowitError;",
    "use allowit::{AllowitError, AllowitValue};",
    "use allowit::{prelude::*, AllowitError};",
    "use allowit::{transaction_cap as Ok};",
    "use allowit::Bogus;",
    "const LIMIT: i128 = 5;",
    "const LIMIT: usize = 5;",
    "const LIMIT: f64 = 5.0;",
    "const LIMIT: i128 = 5i128;\nfn helper() -> i128 { LIMIT }",
    "fn helper(a: i128) -> i128 { a.checked_add(1i128).unwrap_or(0i128) }",
    "fn helper(v: Vec<i128>) -> i128 { v[0] }",
    "fn helper() -> i128 { let f = |x: i128| x; f(1i128) }",
    "fn helper() -> fn() -> i128 { helper2 }\nfn helper2() -> i128 { 1i128 }",
    "fn helper() -> i128 { helper2() }\nfn helper2() -> i128 { 1i128 }",
    "fn helper(a: i128) -> i128 { a as i128 }",
    "fn helper() -> i128 { core::mem::size_of::<i128>() }",
    "fn helper() -> i128 { size_of::<u8>() }",
    "fn helper() -> i128 { i128::MAX }",
    "fn helper() -> i128 { i128::from(1u8) }",
    "fn helper() -> i128 { i128::try_from(1u8).unwrap() }",
    "fn helper() -> i128 { let g = i128::from; g(1u8) }",
    "fn helper() -> Option<i128> { Some(1i128) }",
    "fn helper() -> Option<Option<i128>> { Some(Some) }",
    "fn helper() -> Option<i128> { Option::Some(1i128) }",
    "struct S;",
    "impl S {}",
    "mod m {}",
    "static X: i128 = 1i128;",
    "unsafe fn helper() {}",
    "fn helper(ctx: &AllowitContext) -> bool { ctx.params.0.is_some() }",
    "fn helper(ctx: &AllowitContext) -> i128 { ctx.params\n. 1 }",
    "fn helper(ctx: &AllowitContext) -> bool { ctx.state.is_some() }",
    "fn helper(ctx: &AllowitContext) -> bool { ctx.request.amount > 0i128 }",
    "fn helper(ctx: &AllowitContext) -> bool { ctx.request.spent_units > ctx.request.gas_units }",
    "fn helper(ctx: &AllowitContext) -> bool { ctx.params.get(allowit::TRANSACTION_CAP).is_some() }",
    "fn helper(ctx: &AllowitContext) -> bool { ctx.request.args.get(\"x\").is_some() }",
    "fn helper(ctx: &AllowitContext) -> bool { ctx.request.get(\"x\").is_some() }",
    "fn helper(params: i128) -> i128 { params }",
    "fn args() -> i128 { 1i128 }",
    "fn helper(ctx: &AllowitContext) -> AllowitContext { AllowitContext { ..*ctx } }",
    "fn helper(ctx: &AllowitContext) -> i128 { let AllowitContext { env, .. } = ctx; 0i128 }",
    "fn helper(ctx: &'static mut AllowitContext) -> &'static mut AllowitContext { ctx }",
    "fn helper(x: Option<i128>) -> i128 { match x { Some(v) if v > 0i128 => v, Some(w) => w, None => 0i128 } }",
    "fn helper(x: i128) -> i128 { match x { 1i128 | 2i128 => 0i128, _ => 1i128 } }",
    "fn helper() { panic!(\"bad {}\", 1i128) }",
    "fn helper() { panic!(\"bad {:?}\", 1i128) }",
    "fn helper() { panic!(\"bad {:5}\", 1i128) }",
    "fn helper() { panic!(\"bad {0}\", 1i128) }",
    "fn helper() { panic!(\"{{x}}\") }",
    "fn helper() { panic!(\"\\u{7b}:1$}\", 1i128) }",
    "fn helper() { panic!(\"\\x7b:.*}\", 1i128) }",
    "fn helper() { panic!(\"line \\\n   {}\", 1i128) }",
    "fn helper() { panic!(r\"{:1$}\") }",
    "fn helper() { panic!(r#\"{\"#) }",
    "fn helper() { panic!(\"\\u{110000}\") }",
    "fn helper() { panic!(\"\\u{__}\") }",
    "fn helper() { panic!(\"\\u{d800}\") }",
    "fn helper() { panic!(\"\\u{7_b}\") }",
    "fn helper() { panic!(\"\\u{000000007b}\") }",
    "fn helper() { panic!(0) }",
    "fn helper(a: bool) { assert!(a, \"oops {:?}\", a); }",
    "fn helper(a: bool) { assert!(a, concat!(\"x\")); }",
    "fn helper(a: bool) { assert!(a,); }",
    "fn helper(a: i128) { assert_eq!(a, 1i128, \"{:x}\", a); }",
    "fn helper(a: i128) { assert_ne!(a, 1i128, \"{}\", a); }",
    "fn helper() { unreachable!(\"x{}\", 1i128) }",
    "fn helper() { unreachable!(\"x{\") }",
    "fn helper() -> i128 { 1 }",
    "fn helper() -> i128 { 1.5 }",
    "fn helper() -> i128 { 1.max(2) }",
    "fn helper() -> i128 { 0xffi128 }",
    "fn helper() -> i128 { 0b101i128 }",
    "fn helper() -> i128 { 0o17u8 }",
    "fn helper() -> i128 { 0b2 }",
    "fn helper() -> i128 { 1_000i128 }",
    "fn helper() -> i128 { 1e3 }",
    "fn helper() -> i128 { 1usize }",
    "fn helper() -> i128 { let x = [1i128, 2i128]; 0i128 }",
    "fn helper() -> i128 { let r#loop = 1i128; r#loop }",
    "fn r#helper() -> i128 { 1i128 }",
    "fn helper(a: &mut i128) { *a = 1i128; }",
    "fn helper() -> String { String::new() }",
    "fn helper() -> u8 { b'a' }",
    "fn helper() -> char { '\\u{7b}' }",
    "fn helper(ctx: &AllowitContext) -> i128 { ctx.env.clone(); 0i128 }",
    "fn helper(ctx: &AllowitContext) -> bool { ctx.env == ctx.env }",
    "fn helper(ctx: &mut AllowitContext) { ctx.env = ctx.env; }",
    "fn helper() -> i128 { loop { break 1i128; } }",
    "fn helper() -> i128 { 'a: loop { break 'a 1i128; } }",
    "fn helper(x: i128) -> core::cmp::Ordering { x.cmp(&0i128) }",
    "fn helper() -> i128 { core::cmp::max(1i128, 2i128) }",
    "fn helper() -> i128 { let m = core::cmp::max; m(1i128, 2i128) }",
    "fn helper(v: Vec<i128>) -> i128 { for x in v { return x; } 0i128 }",
    "fn helper(v: Vec<i128>) -> i128 { v.iter().count() }",
    "fn helper(ctx: &AllowitContext) -> allowit::Result { allowit::set_state(ctx, \"k\", AllowitValue::Int(1i128)) }",
    "fn helper(ctx: &AllowitContext) -> allowit::Result { allowit::r#set_state(ctx, \"k\", AllowitValue::Int(1i128)) }",
    "fn helper(ctx: &AllowitContext) -> Option<AllowitValue> { allowit::get_state(ctx, \"k\") }",
    "fn helper() -> allowit::Result { Err(allowit::AllowitError::Unsupported) }",
    "fn helper() -> allowit::Result { Err(AllowitError::Bogus) }",
    "fn helper() -> AllowitRule { AllowitRule::expiry }",
    "fn helper() -> AllowitValue { allowit::AllowitValue::Bool(true) }",
    "fn helper() -> fn(bool) -> AllowitValue { AllowitValue::Bool }",
    "#[cfg(test)] fn helper() {}",
    "#[inline] fn helper() {}",
    "#[must_use] fn helper() -> bool { true }",
    "#[path = \"x.rs\"] fn helper() {}",
    "fn helper() { asm!(\"\"); }",
    "fn helper() -> &'static str { include_str!(\"x\") }",
    "fn helper() -> &'static str { env!(\"HOME\") }",
    "fn helper() -> i128 { let x: Box<i128> = 1i128; 0i128 }",
    "fn helper() -> i128 { self::helper2() }\nfn helper2() -> i128 { 1i128 }",
    "fn helper(x: &i128) -> *const i128 { x }",
    "fn helper() -> i128 { let x = 1i128; x.pow(2u32) }",
    "fn helper() -> Option<i128> { Some(1i128).map(|x| x) }",
    "fn helper() -> bool { true || false }",
    "fn helper(a: bool) -> bool { a | false }",
    "fn helper(a: bool) -> bool { a || !a }",
    "fn helper() { let _ = drop; }",
    "fn hélper() {}",
    "// comment with é\nfn helper() {}",
    "fn helper() -> &'static str { \"é {x}\" }",
    "fn helper() -> &'static str { r#\"raw \"{\"# }",
    "fn Ok(_: ()) -> allowit::Result { Err(allowit::AllowitError::MissingParam) }",
    "fn helper(x: (i128, i128)) -> i128 { x.0 }",
    "fn helper<T>(x: T) -> T { x }",
    "fn helper() -> i128 { <i128>::MAX }",
    "fn helper(ctx: &AllowitContext) -> bool { ctx.request.operation == AllowitOperation::transfer }",
    "fn helper(ctx: &AllowitContext) -> bool { ctx.request.operation == allowit::AllowitOperation::redeem }",
    "fn helper(ctx: &AllowitContext) -> bool { matches!(ctx.request.operation, AllowitOperation::custom(..)) }",
    "fn helper(ctx: &AllowitContext) -> bool { let f = AllowitOperation::custom; true }",
    "fn helper(ctx: &AllowitContext) -> bool { ctx.request.amount_in > 0i128 && ctx.request.token_out.is_some() }",
    "fn helper(ctx: &AllowitContext) -> bool { ctx.request.token_in == ctx.request.asset && ctx.request.min_out == 0i128 }",
    "fn helper(ctx: &AllowitContext) -> bool { ctx.request.operation == allowit::AllowitOperation::sep99 }",
    "fn helper() -> AllowitPrice { AllowitPrice { from: 1i128, to: 2i128 } }",
    "fn helper(x: i128) -> i128 { let y = x; y }",
    "fn helper(x: i128) -> i128 { z }",
    "fn helper(ctx: &AllowitContext) -> i128 { ctx.foo }",
    "fn helper(x: Option<i128>) -> i128 { x.get(0i128) }",
    "fn helper(ctx: &AllowitContext) -> bool { ctx.params .get(allowit::TOKENS).is_some() }",
    "fn helper(ctx: &AllowitContext) -> bool { ctx . params . get(allowit::TOKENS).is_some() }",
    "fn helper() -> i128 { $x }",
    "fn helper(a: i128) -> bool { a!=1i128 }",
    "fn helper(a: i128) -> i128 { -a }",
    "fn helper(a: [i128; 2]) -> i128 { 0i128 }",
    "fn helper() -> i128 { ::core::cmp::max(1i128, 2i128) }",
    "fn helper() -> i128 { crate::helper() }",
    "fn helper() -> u64 { allowit::DAY }",
    "fn helper() -> Address { Address::from(1i128) }",
    "fn helper(a: Address) -> Address { a.clone() }",
    "fn helper(a: AllowitValue) -> bool { matches!(a, AllowitValue::Int(_)) }",
    "fn helper(a: AllowitValue) -> bool { match a { AllowitValue::List(items) => items.is_empty(), _ => false } }",
    "fn helper(a: AllowitValue) -> bool { if let AllowitValue::Int(v) = a { v > 0i128 } else { false } }",
    "fn helper(a: i128) -> i128 { let (b, c) = (a, a); b + c }",
    "fn helper(a: i128) -> i128 { while a > 0i128 { return a; } 0i128 }",
    "fn helper(a: i128) -> i128 { a.saturating_sub(1i128).abs() }",
    "fn helper(a: i128) -> i128 { a.wrapping_add(1i128) }",
    "fn helper(a: i128) -> i128 { let ref b = a; *b }",
    "fn helper() -> i128 { let mut a = 0i128; a += 1i128; a }",
    "fn helper() -> i128 { const fn_in: i128 = 1i128; fn_in }",
    "fn helper() -> i128 {\n    // nested /* comment */\n    1i128\n}",
    "/* outer /* nested */ still comment */ fn helper() -> i128 { 1i128 }",
    "fn helper() -> i128 { 1i128 } /* unterminated",
    "fn helper() -> &'static str { \"unterminated }",
    "//! inner doc",
    "#![allow(dead_code)]",
    "fn helper() -> bool { cfg_attr }",
    "fn helper(x: &i128) -> i128 { let p = &raw const x; 0i128 }",
    "macro_rules! m { () => {} }",
    "fn helper() -> i128 { 1i128 }\nfn execute() {}",
    "fn helper() -> i128 { 1i128 }\x1cfn other() {}",
    "fn helper() -> i128 { async { 1i128 } }",
    "fn helper(x: i128) -> i128 { x?; x }",
    "fn helper(x: Option<i128>) -> Option<i128> { let y = x?; Some(y) }",
    "fn helper(x: Option<i128>) -> i128 { x.unwrap_or_default() }",
    "fn helper(x: Option<i128>) -> Result<i128, AllowitError> { x.ok_or(AllowitError::MissingParam) }",
    "fn helper(x: i128) -> i128 { (x)[0] }",
    "fn helper() -> i128 { 1i128 }\nfn other() -> i128 { helper }",
]

# Statements inserted at the start of `execute` or before its final `Ok(())`.
STATEMENTS = [
    "let x = 1i128;",
    "allowit::set_state(ctx, \"k\", AllowitValue::Int(1i128))?;",
    "allowit::transaction_cap(ctx, ctx.params.get(allowit::TRANSACTION_CAP))?;",
    "allowit::spent_cap(ctx, ctx.params.get(allowit::TRANSACTION_CAP))?;",
    "allowit::transaction_cap(ctx, ctx.params.get(allowit::TRANSACTION_CAP,),)?;",
    "if ctx.request.amount > 5i128 { return Err(AllowitError::TransactionCapExceeded); }",
    "assert!(ctx.request.amount >= 0i128);",
    "let n = ctx.request.args.get(\"n\").unwrap().len();",
    "let _ = ctx.request.now;",
    "let _ = ctx.request.expires_at.checked_sub(ctx.request.now);",
]


def gate(source):
    import policy_source
    try:
        prefix = policy_source.standard_prefix(source)
        return {"accepted": True, "prefix": prefix, "writes_state": policy_source.writes_state(source)}
    except Exception as error:  # Any failure of the gate is a rejection.
        return {"accepted": False, "error": type(error).__name__ + ": " + str(error)}


def gate_sources():
    lines = CANONICAL.splitlines(keepends=True)
    rules = [k for k, line in enumerate(lines) if line.strip().startswith("allowit::")]
    sources = [CANONICAL]
    sources += [CANONICAL + "\n" + item + "\n" for item in ITEMS]
    for statement in STATEMENTS:
        sources.append(CANONICAL.replace(BODY, BODY + "\n    " + statement, 1))
        sources.append(CANONICAL.replace("    Ok(())\n}", "    " + statement + "\n    Ok(())\n}", 1))
    # Drop, swap or stop each prefix rule, so the derived prefix changes.
    for k in rules:
        sources.append("".join(lines[:k] + lines[k + 1:]))
        sources.append("".join(lines[:k] + ["    let _ = 0i128;\n"] + lines[k:]))
    for a, b in zip(rules, rules[1:]):
        swapped = list(lines)
        swapped[a], swapped[b] = swapped[b], swapped[a]
        sources.append("".join(swapped))
    # Seeded random combinations: one to three items and statements at random places.
    rng = random.Random(20261031)
    for _ in range(240):
        source = CANONICAL
        for _ in range(rng.randint(1, 3)):
            if rng.random() < 0.6:
                source += "\n" + rng.choice(ITEMS) + "\n"
            else:
                anchor = rng.choice([BODY, "    Ok(())\n}"])
                statement = rng.choice(STATEMENTS)
                source = source.replace(anchor, (anchor + "\n    " + statement) if anchor == BODY
                                        else ("    " + statement + "\n" + anchor), 1)
        sources.append(source)
    return list(dict.fromkeys(sources))


def edit(source):
    """The edit of the ASCII canonical source that gives `source`."""
    head = 0
    while head < min(len(source), len(CANONICAL)) and source[head] == CANONICAL[head]:
        head += 1
    tail = 0
    while tail < min(len(source), len(CANONICAL)) - head and source[-1 - tail] == CANONICAL[-1 - tail]:
        tail += 1
    return {"head": head, "middle": source[head:len(source) - tail], "tail": tail}


def gate_vectors():
    assert CANONICAL.isascii()
    return [dict(edit(source), **gate(source)) for source in gate_sources()]


G = "GAKDNXUGEIRGESAXOPUHU4GOWLVYGQFJVHQOGFXKBXDGZ7AKMPPSDDPV"
C = "CABAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAFNSZ"
VALUES = [
    0, 1, -1, 5, 2**63, 2**64 - 1, 2**64, 2**126, 2**127 - 1, 2**127, -2**127, -2**127 - 1, 1.0, 1.5,
    True, False, None, "", "*", "x", "transfer", "stellar::sep41_transfer", "sep41_transfer",
    "stellar::sep56_deposit", "x" * 256, "x" * 257, "é" * 128, G, C, G[:-1] + "A",
    "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAPCIBQ", [], [G], [G, C], [G, "x"],
    ["*"], ["transfer", "stellar::sep41_transfer"], [1, 2], [[G]], [True], {"Int": "5"}, {"Int": 5},
    {"Str": G}, {"Addr": G}, {"Addr": "x"}, {"Bool": True}, {"Bool": 1}, {"List": [G]},
    {"List": [{"Str": "a"}]}, {"Int": 1, "Str": "a"}, {"Bogus": 1}, {}, ["x"] * 64, ["x"] * 65,
]
KEYS = ["transaction_cap", "spent_cap", "day_spent_cap", "day_total_cap", "call_cap", "recipients",
        "tokens", "expiry", "operations", "custom", "k" * 32, "k" * 33, "bad-key", "", "T1"]
TIERS = [None, "simple", "common", "custom"]


def params_vectors():
    import contract_admin
    rng = random.Random(20261031)
    cases = [({}, tier) for tier in TIERS]
    cases += [({key: value}, tier) for key in KEYS[:10] for value in VALUES for tier in ("common", "custom")]
    cases += [({key: 1}, tier) for key in KEYS[10:] for tier in TIERS]
    cases += [({"k{}".format(n): 1 for n in range(count)}, None) for count in (32, 33)]
    cases += [({"k{}".format(n): "x" * 256 for n in range(count)}, None) for count in (1, 20, 32)]
    cases += [([1], "common"), ("x", "common"), (None, None)]
    for _ in range(400):
        value = {rng.choice(KEYS): rng.choice(VALUES) for _ in range(rng.randint(1, 5))}
        cases.append((value, rng.choice(TIERS)))
    out = []
    for value, tier in cases:
        try:
            out.append({"input": value, "tier": tier, "params": contract_admin.params(value, tier)})
        except Exception as error:
            out.append({"input": value, "tier": tier, "error": type(error).__name__ + ": " + str(error)})
    return out


def dump(vectors):
    """One vector per line, so a change shows as a line diff."""
    return "[\n" + ",\n".join(json.dumps(v, ensure_ascii=False) for v in vectors) + "\n]\n"


def main():
    check = sys.argv[1:] == ["--check"]
    if sys.argv[1:] not in ([], ["--check"]):
        raise SystemExit("usage: policy-core-vectors.py [--check]")
    stale = []
    for path, build in ((GATE_FILE, gate_vectors), (PARAMS_FILE, params_vectors)):
        text = dump(build())
        if check:
            if not path.exists() or path.read_text() != text:
                stale.append(path.name)
        else:
            path.write_text(text)
    if stale:
        raise SystemExit("Stale vectors; run scripts/policy-core-vectors.py: " + ", ".join(stale))


if __name__ == "__main__":
    main()
