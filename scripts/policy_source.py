"""Lex authored AllowIt policy source, derive its standard prefix and compile it against the
std-only `allowit` backend. Standard library only, plus `rustc` for `host_compile`.

`check-policy-bindings.py` and `contract_admin.py` share this module. Comments and literals are
removed with Rust lexing first, so they cannot add, hide or rebind code."""
import atexit
import functools
import hashlib
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ALLOWIT = ROOT / "crates/allowit/src"

# Canonical param keys, which are also the canonical rule names. `allowit::<KEY>` names each key.
PARAM_KEYS = ("transaction_cap", "spent_cap", "day_spent_cap", "day_total_cap", "call_cap", "recipients", "tokens", "expiry",
              "operations")

# One prefix statement after whitespace removal: `allowit::<rule>(ctx,ctx.params.get(allowit::<RULE>))?`.
# rustfmt may add commas.
PREFIX_CALL = re.compile(r"allowit::([a-z_]+)\(ctx,ctx\.params\.get\(allowit::([A-Z_]+),?\),?\)\?")
EXECUTE = re.compile(r"\bpub\s+fn\s+execute\s*\(\s*ctx\s*:\s*&\s*AllowitContext\s*\)\s*->\s*allowit\s*::\s*Result(?:\s*<\s*\(\s*\)\s*>)?\s*\{")

# Rust literals that can hide code from a plain scan: raw, byte, C and plain strings, then char
# literals. A quote that starts no char literal is a lifetime or label.
RAW_STRING = re.compile(r'(?<![A-Za-z0-9_])[bc]?r(#*)"')
STRING = re.compile(r'(?<![A-Za-z0-9_])[bc]?"(?:\\[\s\S]|[^"\\])*"')
CHAR = re.compile(r"(?<![A-Za-z0-9_])b?'(?:\\(?:x[0-9a-fA-F]{2}|u\{[0-9a-fA-F_]{1,8}\}|[^\n])|[^\\'\n])'")

# `allowit` names the canonical crate only as a path root: `allowit::<item>`. Any other use of the
# identifier declares or imports a replacement (`mod allowit`, `use x as allowit`, `fn allowit`,
# `macro_rules! allowit`, `let allowit`) or reaches another module (`self::allowit`).
ALLOWIT_NAME = re.compile(r"\ballowit\b")
# Attributes that read other files or the build environment, and raw pointers, whose addresses
# differ between the contract and the host. Every other construct must pass the allowlist below.
OUTSIDE = (
    (re.compile(r"#\s*\[\s*path\b"), "#[path] attribute"),
    (re.compile(r"\bcfg_attr\b"), "cfg_attr attribute"),
    (re.compile(r"\*\s*(?:const|mut)\b|\braw\s+(?:const|mut)\b"), "a raw pointer"),
)
# File and environment macros. Their names may appear only as the bare context field read
# `ctx.env`: after a single `.` and not followed by `.`, `(` or `!`, so neither `ctx.env.<method>`
# nor a value's `env()` method, such as the Soroban `Address::env`, passes.
MACRO_NAMES = re.compile(r"\b(?:include|include_str|include_bytes|env|option_env)\b")
# Macros that authored code may invoke. Every other `name!` rejects: `core::arch::global_asm!`,
# `asm!` and `naked_asm!` emit native code that would run inside the offchain evaluator process,
# and other built-in macros read the build environment or source location.
MACROS = frozenset(("assert", "assert_eq", "assert_ne", "panic", "matches", "unreachable"))
MACRO_CALL = re.compile(r"(?:r#)?\b([A-Za-z_]\w*)\s*!(?!=)")
# The argument index of each allowed macro's optional message. A message must be one string literal,
# whose placeholders `plain_braces` checks; the format arguments after it are ordinary code. Other
# string literals are data, not format strings, so their braces are not checked.
MESSAGE = {"panic": 0, "unreachable": 0, "assert": 1, "assert_eq": 2, "assert_ne": 2}
# Attributes that authored code may use. Every other attribute rejects, such as `path`, `cfg`,
# `unsafe(...)`, `link_section`, `export_name`, `track_caller` or `doc`.
ATTRIBUTES = frozenset(("allow", "expect", "warn", "deny", "forbid", "inline", "cold", "must_use"))
ATTRIBUTE = re.compile(r"#\s*\[\s*(?:r#)?([A-Za-z_]\w*)")

# The allowlist. Authored code is portable only when every name in it has the same meaning and
# result in `AllowitCustomPolicy` and on the host, where `usize` is 32 and 64 bits wide, backend
# lists differ and code addresses differ. Each identifier is one of: an allowed keyword; a field
# or method after `.`; a path from `PATHS`; a type from `TYPES`, a constant the file defines or a
# type it imports from `allowit`; a lowercase name the file declares; or a fixed-width primitive
# type. Pointer-width types, float and `usize` literals, casts, closures, function values and
# prelude layout functions reject, because each can observe a pointer width, a layout or a code
# address. Onchain resource limits still deny a policy that the host
# evaluates to completion, such as deep recursion; that difference only denies.
RUST_KEYWORDS = frozenset((
    "abstract", "as", "async", "await", "become", "box", "break", "const", "continue", "crate", "do", "dyn",
    "else", "enum", "extern", "false", "final", "fn", "for", "gen", "if", "impl", "in", "let", "loop", "macro",
    "match", "mod", "move", "mut", "override", "priv", "pub", "ref", "return", "self", "Self", "static",
    "struct", "super", "trait", "true", "try", "type", "typeof", "union", "unsafe", "unsized", "use",
    "virtual", "where", "while", "yield"))
# Functions, constants, control flow and `use allowit::...`. No modules, types, traits, impls,
# statics, unsafe code, casts (`as`), paths into the including crate or `move` closures.
ALLOWED_KEYWORDS = frozenset((
    "break", "const", "continue", "else", "false", "fn", "for", "if", "in", "let", "loop", "match", "mut",
    "pub", "ref", "return", "true", "use", "while"))
INTEGERS = tuple(sign + str(bits) for sign in "iu" for bits in (8, 16, 32, 64, 128))
# Primitive types whose width or representation differs between the backends.
NOT_PORTABLE = frozenset(("usize", "isize", "f16", "f32", "f64", "f128"))
# `AllowitError` variants in code order; their contract error codes are 101 onward.
ERRORS = ("MissingParam", "TransactionCapExceeded", "SpentCapExceeded", "DaySpentCapExceeded", "DayTotalCapExceeded",
          "CallCapExceeded", "RecipientNotAllowed", "TokenNotAllowed", "Expired", "Unpriced", "InvalidParam",
          "InvalidState", "Overflow", "Unsupported", "OperationNotAllowed", "Panicked")
VALUES = ("Int", "Bool", "Str", "Addr", "List")
ENUMS = {"AllowitOperation": ("sep41_transfer", "sep56_deposit", "router_swap_exact_in", "sep56_redeem"), "AllowitError": ERRORS, "AllowitRule": PARAM_KEYS,
         "AllowitValue": VALUES}
# Server-only enrichment: allowed offchain; a Custom contract that calls one does not compile. Each
# takes a request struct whose fields `STRUCT_FIELDS` lists.
SERVER_FUNCTIONS = ("price", "fetch", "internet_search", "marketplace_search", "systemone", "request_screening",
                    "clear_systemone_context")
SERVER_TYPES = ("AllowitPrice", "AllowitFetch", "AllowitInternetSearch", "AllowitMarketplaceSearch",
                "AllowitRequestScreening", "AllowitSystemOne")
STRUCT_FIELDS = frozenset(("from", "to", "amount", "price", "slip", "method", "url", "data", "pubkey", "query", "id",
                           "deny_below", "allow_above"))
ALLOWIT_FUNCTIONS = PARAM_KEYS + ("param", "arg", "get_state", "set_state") + SERVER_FUNCTIONS
# `AllowitParams` is absent on purpose: naming it would reach the backend map, whose keys and
# methods differ. Params and args are read only with `.get(key)`; the host backend also keeps that
# map private, so the std-only compile rejects `.0` on any params or args value.
# `String` and `Vec` are the backend text and list types that `param` and `arg` read; like a list from
# `AllowitValue::List`, they admit only comparison, `clone`, matching and `for`.
ALLOWIT_TYPES = ("AllowitContext", "AllowitError", "AllowitOperation", "AllowitRequest", "AllowitRule", "AllowitValue",
                 "Address", "Result", "String", "Vec", "DAY") + tuple(key.upper() for key in PARAM_KEYS) + SERVER_TYPES
TYPES = frozenset(ALLOWIT_TYPES + ("Option", "Some", "None", "Ok", "Err"))
# Tuple constructors, which coerce to function pointers unless called.
CONSTRUCTORS = frozenset(("Some", "Ok", "Err", "Option::Some", "Result::Ok", "Result::Err")
                         + tuple(prefix + "AllowitValue::" + v for v in VALUES for prefix in ("", "allowit::")))
# Undeclared lowercase names that are types with one width and representation on both backends.
PRIMITIVES = frozenset(INTEGERS + ("bool", "char", "str", "_"))
# Prelude functions; the layout ones observe pointer widths and backend type sizes. Never local names.
PRELUDE_FUNCTIONS = frozenset(("drop", "size_of", "size_of_val", "align_of", "align_of_val"))
FUNCTION_PATHS = frozenset(["allowit::" + name for name in ALLOWIT_FUNCTIONS]
                           + [t + "::" + f for t in INTEGERS for f in ("from", "try_from")]
                           + ["core::cmp::min", "core::cmp::max"])
PATHS = FUNCTION_PATHS | frozenset(
    ["allowit::" + name for name in ALLOWIT_TYPES] + ["allowit::prelude"]
    + [prefix + enum + "::" + variant for enum, variants in ENUMS.items() for variant in variants
       for prefix in ("", "allowit::")]
    + ["Option::Some", "Option::None", "Result::Ok", "Result::Err"]
    + [t + "::" + c for t in INTEGERS for c in ("MAX", "MIN")]
    + ["core::cmp::Ordering"] + ["core::cmp::Ordering::" + o for o in ("Less", "Equal", "Greater")])
# Context and request fields. `ctx.state` is read only through `allowit::get_state`.
FIELDS = frozenset(("env", "params", "request", "operation", "asset", "recipient", "amount", "token_in", "amount_in",
                    "token_out", "min_out", "now", "expires_at", "spent_units", "gas_units", "unpriced", "args"))
# Methods allowed only on one receiver field: `get` reads params and args by key, as in
# `ctx.params.get` or `ctx.request.args.get`. The receiver must be that field access, and the file
# must not declare these names: on a list or a string bound to `params` or `args`, `get` would take
# a pointer-width index on the host.
FIELD_METHODS = {"get": ("params", "args")}
FIELD_NAMES = frozenset(name for fields in FIELD_METHODS.values() for name in fields)
# Methods of `Option`, `Result`, fixed-width integers, `bool` and `Ordering` that take and return
# no pointer-width value and no backend list.
METHODS = frozenset((
    "clone", "eq", "ne", "lt", "le", "gt", "ge", "cmp", "partial_cmp", "min", "max", "clamp",
    "is_some", "is_none", "is_some_and", "is_none_or", "is_ok", "is_err", "is_ok_and", "is_err_and", "ok", "err",
    "ok_or", "unwrap", "expect", "unwrap_or", "unwrap_or_default", "copied", "cloned", "as_ref", "xor", "or", "and",
    "checked_add", "checked_sub", "checked_mul", "checked_div", "checked_rem", "checked_neg", "checked_abs",
    "checked_pow", "saturating_add", "saturating_sub", "saturating_mul", "saturating_pow", "pow", "abs", "abs_diff",
    "unsigned_abs", "signum", "is_positive", "is_negative", "div_euclid", "rem_euclid",
    "is_lt", "is_le", "is_gt", "is_ge", "is_eq", "is_ne", "reverse", "then_some")) | frozenset(FIELD_METHODS)
NUMBER = re.compile(r"(?:0x[0-9a-fA-F_]+|0o[0-7_]+|0b[01_]+|[0-9][0-9_]*)(?:" + "|".join(INTEGERS) + r")?")
# A struct expression or pattern of the context, which would reach `state` past `get_state`. A return
# type followed by a block is no struct expression.
CONTEXT_STRUCT = re.compile(r"\bAllowitContext\s*\{")
# A tuple field of params or args, which is the backend map.
MAP_FIELD = re.compile(r"\.\s*(?:params|args)\s*\.\s*\d")
# A call of the only write that standard wallets cannot store, also through a raw identifier.
SET_STATE = re.compile(r"\ballowit\s*::\s*(?:r#)?set_state\b")
# A format placeholder or brace escape in a string literal's value. Only `{}`, `{:?}`, `{{` and
# `}}` pass: a width or precision count, such as `{:1$}`, `{:.*}` or `{:a$}`, is a `usize`, so it
# would infer an unsuffixed binding as `usize` without naming the type.
BRACE = re.compile(r"\{\{|\}\}|\{[^{}]*\}?|\}")
PLACEHOLDERS = frozenset(("{{", "}}", "{}", "{:?}"))
# One escape of a non-raw string literal: a byte, a Unicode scalar, a line continuation or a character.
ESCAPE = re.compile(r"\\(?:x([0-9a-fA-F]{2})|u\{([0-9a-fA-F_]{1,8})\}|\n\s*|([\s\S]))")
SIMPLE_ESCAPES = {"n": "\n", "r": "\r", "t": "\t", "0": "\0"}
TOKEN = re.compile(r"r#[A-Za-z_]\w*|[A-Za-z_]\w*|::|=>|->|\|\||\$\w*|'\w+|\d\w*|\S")
IDENT = re.compile(r"(?:r#)?[A-Za-z_]\w*")
# Tokens that end an operand. `|` and `||` are an operator or a pattern alternative only after one;
# anywhere else, such as after `break`, `return`, `=` or a block's `}`, they start a closure.
OPERAND_END = frozenset((")", "]", "?", "true", "false"))
OPEN, CLOSE = frozenset("([{"), frozenset(")]}")


def reject(what):
    raise ValueError("Policy source must be one self-contained, portable file; it uses " + what)


def unescape(match):
    """Return the character that one string escape denotes."""
    if match[1] or match[2]:
        return chr(int((match[1] or match[2]).replace("_", ""), 16))
    return SIMPLE_ESCAPES.get(match[3], match[3] or "")


def plain_braces(value):
    """Reject a macro message value with a brace other than `{}`, `{:?}`, `{{` or `}}`. The allowed
    macros read their message as a format string, whose width and precision counts are `usize`."""
    for brace in BRACE.finditer(value):
        if brace[0] not in PLACEHOLDERS:
            reject("the format placeholder `{}`; only `{{}}` and `{{:?}}` are portable".format(brace[0]))


def uses(tokens, i):
    """Check the `use` declaration at tokens[i]; return the capitalized names it imports and the index
    after its `;`. Only `use allowit::prelude::*;` and imports of `allowit` types are allowed."""
    end = tokens.index(";", i) if ";" in tokens[i:] else len(tokens)
    tree = "".join(tokens[i + 1:end])
    if tree == "allowit::prelude::*":
        return set(), end + 1
    names = tree[len("allowit::{"):-1].split(",") if tree.startswith("allowit::{") and tree.endswith("}") else (
        [tree[len("allowit::"):]] if tree.startswith("allowit::") else [])
    names = [name for name in names if name]
    if not names or any(name not in ALLOWIT_TYPES for name in names):
        reject("`use " + tree + "`; only `use allowit::prelude::*` and `allowit` types may be imported")
    return set(names), end + 1


def after_generics(tokens, j):
    """Return the index after the generic arguments that start with `<` at tokens[j]."""
    depth = 0
    for k in range(j, len(tokens)):
        depth += (tokens[k] == "<") - (tokens[k] == ">")
        if depth == 0:
            return k + 1
    reject("unterminated generic arguments")


def after_brackets(tokens, j):
    """Return the index after the bracket group that opens at tokens[j]."""
    depth = 0
    for k in range(j, len(tokens)):
        depth += (tokens[k] in OPEN) - (tokens[k] in CLOSE)
        if depth == 0:
            return k + 1
    reject("an unterminated attribute")


def operand(token):
    """True when `token` ends an operand: a non-keyword name, a literal, `)`, `]`, `?` or a boolean."""
    return (token in OPERAND_END or token[:1].isdigit()
            or bool(IDENT.fullmatch(token)) and token not in RUST_KEYWORDS)


def declared(tokens):
    """Return the lowercase names the file declares: function and constant names, function
    parameters and the bindings of `let`, `for` and match-arm patterns. Scope is ignored, so a
    binding the scan misses only rejects; prelude functions reject even when declared."""
    names = set()

    def bind(k):
        token = tokens[k]
        if IDENT.fullmatch(token) and token not in RUST_KEYWORDS and not token[0].isupper() \
                and tokens[k - 1] != "::" and tokens[k + 1:k + 2] not in (["("], ["::"], ["{"], ["!"]):
            names.add(token.removeprefix("r#"))

    def pattern(k, stops):
        # Bind the names of the pattern at tokens[k] up to a stop token at its own depth.
        depth = 0
        while k < len(tokens) and not (depth == 0 and tokens[k] in stops):
            depth += (tokens[k] in OPEN) - (tokens[k] in CLOSE)
            if depth < 0:
                return
            bind(k)
            k += 1

    for k, token in enumerate(tokens[:-1]):
        if token in ("fn", "const"):
            names.add(tokens[k + 1].removeprefix("r#"))
        if token == "let":
            pattern(k + 1, ("=", ";", ":"))
        elif token == "for":
            pattern(k + 1, ("in",))
        elif token == "fn" and "(" in tokens[k:]:
            # Each parameter pattern runs from `(` or a top-level `,` to its `:`.
            depth, start = 0, tokens.index("(", k)
            for j in range(start, len(tokens)):
                depth += (tokens[j] in OPEN) - (tokens[j] in CLOSE)
                if depth == 0:
                    break
                if depth == 1 and tokens[j] in ("(", ","):
                    pattern(j + 1, (":", ",", ")"))
        elif token == "=>":
            # The arm pattern runs back to the previous `,`, `{` or `}`; a guard after `if` binds nothing.
            depth, found = 0, []
            for j in range(k - 1, -1, -1):
                depth += (tokens[j] in (")", "]")) - (tokens[j] in ("(", "["))
                if depth == 0 and tokens[j] in (",", "{", "}"):
                    break
                if depth == 0 and tokens[j] == "if":
                    found = []
                found.append(j)
            for j in found:
                bind(j)
    return names


def allowlisted(code):
    """Raise ValueError unless every identifier, path, method, field and literal of `code` is on the
    allowlist. Comments and literals are already removed."""
    if not code.isascii():
        reject("a non-ASCII identifier")
    tokens = TOKEN.findall(code)
    # Raw identifiers name the same function, so `fn r#f` is the local function `f`.
    local_fns = {tokens[k + 1].removeprefix("r#") for k in range(len(tokens) - 1) if tokens[k] == "fn"}
    local_names = declared(tokens)
    for name in sorted(local_names & FIELD_NAMES):
        reject("the name `{}` for a binding or function; it is reserved for the context field".format(name))
    defined = {tokens[k + 1] for k in range(len(tokens) - 1) if tokens[k] == "const" and IDENT.fullmatch(tokens[k + 1])}
    i = 0
    while i < len(tokens):
        token, before = tokens[i], tokens[i - 1] if i else ""
        after = tokens[i + 1] if i + 1 < len(tokens) else ""
        if token == "#" and after == "[":
            i = after_brackets(tokens, i + 1)  # An attribute; `portable` checks its name.
            continue
        if token == "use":
            imported, i = uses(tokens, i)
            defined |= imported
            continue
        if token[0].isdigit():
            if before != "." and (not NUMBER.fullmatch(token) or after == "." and tokens[i + 2:i + 3] != ["."]
                                  and not IDENT.fullmatch(tokens[i + 2] if i + 2 < len(tokens) else "")):
                reject("the literal `{}`; only integer literals with fixed-width suffixes are portable".format(token))
            i += 1
            continue
        if token == "::":
            reject("a path that does not start at an allowed name")
        if token in ("|", "||"):
            if not operand(before):
                reject("a closure, which can become a function pointer whose address differs between the backends")
            i += 1
            continue
        if not IDENT.fullmatch(token):
            i += 1
            continue
        name = token.removeprefix("r#")
        if token == name and name in RUST_KEYWORDS:
            if name not in ALLOWED_KEYWORDS:
                reject("the keyword `{}`".format(name))
            if name == "fn" and not IDENT.fullmatch(after):
                reject("a function pointer type, whose address differs between the backends")
            i += 1
            continue
        if after == "!" and tokens[i + 2:i + 3] != ["="]:
            i += 1  # A macro name; `portable` checks it.
            continue
        if before == "." and tokens[i - 2:i - 1] != ["."]:
            if after in ("(", "::"):
                if name not in METHODS:
                    reject("the method `{}`, which is not on the portable allowlist".format(name))
                if name in FIELD_METHODS and (i < 3 or tokens[i - 2] not in FIELD_METHODS[name] or tokens[i - 3] != "."):
                    reject("the method `{}` other than on the field {}".format(
                        name, " or ".join("`." + field + "`" for field in FIELD_METHODS[name])))
            elif name not in FIELDS:
                reject("the field `{}`, which is not on the portable allowlist".format(name))
            i += 1
            continue
        segments, j = [name], i + 1
        while tokens[j:j + 1] == ["::"] and j + 1 < len(tokens) and IDENT.fullmatch(tokens[j + 1]):
            segments.append(tokens[j + 1].removeprefix("r#"))
            j += 2
        turbofish = tokens[j:j + 2] == ["::", "<"]
        if len(segments) > 1 or turbofish:
            path = "::".join(segments)
            if path not in PATHS:
                reject("the path `{}`, which is not on the portable allowlist".format(path))
            call = after_generics(tokens, j + 1) if turbofish else j
            if path in FUNCTION_PATHS | CONSTRUCTORS and tokens[call:call + 1] != ["("]:
                reject("the function `{}` as a value, whose address differs between the backends".format(path))
            i = j + 1 if turbofish else j
            continue
        if name in STRUCT_FIELDS and after == ":" and tokens[i + 2:i + 3] != [":"]:
            i += 1  # A field of a server request struct expression.
            continue
        # Every local function, also one whose capitalized name shadows a type such as `String`.
        if name in local_fns and after != "(" and before != "fn":
            reject("the function `{}` as a value, whose address differs between the backends".format(name))
        elif name[0].isupper():
            if name not in TYPES and name not in defined:
                reject("the name `{}`, which is not on the portable allowlist".format(name))
            if name in CONSTRUCTORS and after != "(":
                reject("the constructor `{}` as a value, whose address differs between the backends".format(name))
        elif name in NOT_PORTABLE:
            reject("the type `{}`, whose width or representation differs between the backends".format(name))
        elif name in PRELUDE_FUNCTIONS:
            reject("the prelude function `{}`, which can observe a pointer width or layout".format(name))
        elif name not in local_names and name not in PRIMITIVES:
            reject("the name `{}`, which the file does not declare".format(name))
        i += 1


def macro_args(tokens, i):
    """Return the top-level comma-separated token groups of the macro arguments that open at tokens[i]."""
    groups, depth = [[]], 0
    for token in tokens[i + 1:after_brackets(tokens, i) - 1]:
        depth += (token in OPEN) - (token in CLOSE)
        if depth == 0 and token == ",":
            groups.append([])
        else:
            groups[-1].append(token)
    return groups


def portable(code, strings):
    """Raise ValueError for macros, attributes, context patterns, backend map access, message
    placeholders and indexing that could behave differently in `AllowitCustomPolicy` and on the host,
    then apply the allowlist. `strings` maps the offset of each string literal's `0` to its value."""
    for found in MACRO_CALL.finditer(code):
        if found[1] not in RUST_KEYWORDS and found[1] not in MACROS:
            reject("macro `{}!`; only {} are allowed".format(found[1], ", ".join(m + "!" for m in sorted(MACROS))))
    for found in ATTRIBUTE.finditer(code):
        if found[1] not in ATTRIBUTES:
            reject("attribute `{}`".format(found[1]))
    if re.search(r"[{,]\s*\.\.(?![=.])\s*[^\s}\]),]", code):
        reject("struct update syntax `..`")
    for found in CONTEXT_STRUCT.finditer(code):
        before = re.sub(r"(?:&\s*(?:'\w+\s*)?(?:mut\s+)?)+$", "", code[:found.start()].rstrip()).rstrip()
        if not before.endswith("->"):
            reject("a struct expression or pattern of `AllowitContext`")
    if MAP_FIELD.search(code):
        reject("the map inside params or args; read them with `.get(key)`")
    spans = list(TOKEN.finditer(code))
    tokens = [span[0] for span in spans]
    # Literals are `0` here: a present message must be exactly one of them.
    for k in range(len(tokens) - 2):
        name = tokens[k].removeprefix("r#")
        if name in MESSAGE and tokens[k + 1] == "!" and tokens[k + 2] in OPEN:
            args, index = macro_args(tokens, k + 2), MESSAGE[name]
            message = args[index] if len(args) > index else []
            if message not in ([], ["0"]):
                reject("a `{}!` message that is not one string literal".format(name))
            if message:
                # The message token follows the earlier argument groups and their commas.
                plain_braces(strings.get(spans[k + 3 + sum(len(group) + 1 for group in args[:index])].start(), ""))
    for before, token in zip(tokens, tokens[1:]):
        if token == "[" and (before in (")", "]", "?") or before[:1].isdigit()
                             or IDENT.fullmatch(before) and before not in RUST_KEYWORDS):
            reject("indexing, whose index is a pointer-width `usize`")
    allowlisted(code)


def rust_code(source):
    """Return source with comments blanked and literals replaced by `0`, so only code remains, and
    a map from the offset of each string literal's `0` to its value. Block comments nest as in Rust.
    An unterminated comment or literal is rejected."""
    out, strings, i, n = [], {}, 0, len(source)  # One character per item, so len(out) is an offset.
    while i < n:
        if source.startswith("//", i):
            end = source.find("\n", i)
            i = n if end < 0 else end
            out.append(" ")
        elif source.startswith("/*", i):
            depth, i = 1, i + 2
            while depth:
                if i >= n:
                    raise ValueError("Policy source has an unterminated block comment")
                step = source[i:i + 2]
                depth += (step == "/*") - (step == "*/")
                i += 2 if step in ("/*", "*/") else 1
            out.append(" ")
        elif raw := RAW_STRING.match(source, i):
            end = source.find('"' + raw[1], raw.end())
            if end < 0:
                raise ValueError("Policy source has an unterminated raw string")
            strings[len(out) + 1] = source[raw.end():end]
            i = end + 1 + len(raw[1])
            out.extend(" 0 ")
        elif literal := STRING.match(source, i):
            strings[len(out) + 1] = ESCAPE.sub(unescape, literal[0][literal[0].index('"') + 1:-1])
            i = literal.end()
            out.extend(" 0 ")
        elif literal := CHAR.match(source, i):
            i = literal.end()
            out.extend(" 0 ")
        elif source[i] == '"' or source.startswith(('b"', 'c"'), i):
            raise ValueError("Policy source has an unterminated string")
        else:
            out.append(source[i])
            i += 1
    return "".join(out), strings


def checked_code(source):
    """Return the code of one self-contained policy file that binds `allowit` only to the canonical
    crate. Reject inner attributes and doc comments, which the including module cannot accept."""
    if re.search(r"^\s*(//!|/\*!|#\s*!\s*\[)", source, re.M):
        raise ValueError("Policy source must not use inner attributes or inner doc comments")
    code, strings = rust_code(source)
    for found in ALLOWIT_NAME.finditer(code):
        before, after = code[:found.start()].rstrip(), code[found.end():].lstrip()
        if not after.startswith("::") or before.endswith("::"):
            raise ValueError("Policy source must use `allowit` only as the path root `allowit::`; it must not rebind it")
    for found in MACRO_NAMES.finditer(code):
        before, after = code[:found.start()].rstrip(), code[found.end():].lstrip()
        field = before.endswith(".") and not before.endswith("..")
        if not field or after.startswith((".", "(")) or after.startswith("!") and not after.startswith("!="):
            raise ValueError("Policy source must be one self-contained file; it uses file or environment macro")
        # `ctx.env` is read-only: no assignment and no `&mut` borrow that `core::mem` could replace.
        if after.startswith("=") and not after.startswith("==") or re.search(r"&\s*mut\b[^;,{}]*\.$", before):
            reject("a write to the `env` field")
    for pattern, name in OUTSIDE:
        if pattern.search(code):
            raise ValueError("Policy source must be one self-contained file; it uses " + name)
    portable(code, strings)
    return code


def standard_prefix(source):
    """Return the standard prefix of authored policy source: the consecutive leading statements of
    `execute` of the exact form `allowit::<rule>(ctx, ctx.params.get(allowit::<RULE>))?;`, each rule
    with its own canonical key. Any other statement ends it; a rule may still read any key there."""
    text = checked_code(source)
    found = list(EXECUTE.finditer(text))
    if len(found) != 1 or len(re.findall(r"\bexecute\b", text)) != 1:
        raise ValueError("Policy source must define pub fn execute(ctx: &AllowitContext) -> allowit::Result once")
    rules = []
    for statement in text[found[0].end():].split(";"):
        call = PREFIX_CALL.fullmatch(re.sub(r"\s+", "", statement))
        if not call or call[1].upper() != call[2] or call[1] not in PARAM_KEYS:
            break
        rules.append(call[1])
    return rules


def writes_state(source):
    """True when authored policy source calls `allowit::set_state`, a write that Simple and Common
    cannot store: they run only the canonical prefix onchain, so the server denies every write."""
    return bool(SET_STATE.search(checked_code(source)))


@functools.lru_cache(maxsize=None)
def _host_allowit(rustc, digest):
    """Compile `allowit` with only the `std` feature once per process and sources digest."""
    out = Path(tempfile.mkdtemp(prefix="allowit-host-"))
    atexit.register(shutil.rmtree, out, True)
    lib = out / "liballowit.rlib"
    _rustc(rustc, ["--crate-type=rlib", "--crate-name=allowit", "--cfg", 'feature="std"',
                   str(ALLOWIT / "lib.rs"), "-o", str(lib)], "allowit std backend")
    return lib


def _rustc(rustc, args, what):
    # Function pointer comparisons depend on code layout and optimization. Forbid, so that no
    # source `#[allow]`, `#[expect]` or `#[warn]` can lower the level.
    command = [rustc, "--edition=2024", "-C", "overflow-checks=on", "-F", "unpredictable_function_pointer_comparisons"] + args
    try:
        result = subprocess.run(command, capture_output=True, text=True)
    except FileNotFoundError:
        raise ValueError("The std-only policy compile requires rustc (set RUSTC or PATH)") from None
    if result.returncode:
        raise ValueError("Policy source fails the std-only compile of the " + what + ":\n" + result.stderr.strip())


def host_compile(path):
    """Compile authored policy source as the offchain server does: as a module of a `no_std` crate
    whose only dependency is `allowit` with only the `std` feature, with overflow checks on. Raise
    ValueError when it does not compile, for example when it names `soroban_sdk`, calls a Soroban
    `Env` or `Address` method, orders addresses or uses a host-only `std` prelude item."""
    rustc = os.environ.get("RUSTC") or "rustc"
    digest = hashlib.sha256(b"".join((ALLOWIT / name).read_bytes() for name in ("lib.rs", "core.rs"))).hexdigest()
    lib = _host_allowit(rustc, digest)
    source = str(Path(path).resolve())
    if '"#' in source or "\n" in source:
        raise ValueError("Policy source path cannot be named in a Rust raw string")
    with tempfile.TemporaryDirectory(prefix="allowit-policy-") as out:
        crate = Path(out) / "policy_host.rs"
        crate.write_text("#![no_std]\n#[path = r#\"" + source + "\"#]\nmod policy;\n"
                         "pub const EXECUTE: fn(&allowit::AllowitContext) -> allowit::Result = policy::execute;\n")
        _rustc(rustc, ["--crate-type=rlib", "--crate-name=policy_host", "--extern", "allowit=" + str(lib),
                       str(crate), "-o", str(Path(out) / "libpolicy_host.rlib")], "policy")
