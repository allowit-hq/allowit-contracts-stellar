#!/usr/bin/env python3
"""Check the custom policy's argument-schema bindings and report its source digest.

The contract compiles policy/policy.rs verbatim as a module. build.rs derives SOURCE_HASH from the same
bytes, so the file must be the whole policy: it must not read other files, the environment or crates
other than `allowit` and `core`, and it must bind `allowit` only to the canonical crate. Each authored
source must also pass the std-only compile that the offchain server uses. The host portability test
includes the file, which rejects inner attributes and doc comments."""
import ast
import hashlib
import re
from pathlib import Path

from policy_source import checked_code, host_compile

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = b"allowit.stellar.sep41_transfer.v1:ScValMap(amount:i128,from:Address,to:Address,token:Address)"
# The other native schemas that the custom policy admits; it admits no deposit.
SCHEMAS = {
    "ARGUMENT_SCHEMA_HASH": SCHEMA,
    "SWAP_SCHEMA_HASH": b"allowit.stellar.router_swap_exact_in.v1:ScValMap(amount_in:i128,amount_out_min:i128,deadline:u64,"
                        b"path:Vec<Address>,router:Address,to:Address)",
    "REDEEM_SCHEMA_HASH": b"allowit.stellar.sep56_redeem.v1:ScValMap(min_assets:i128,operator:Address,owner:Address,"
                          b"receiver:Address,shares:i128,vault:Address)",
}


def binding(text, name):
    match = re.search(r"pub\s+const\s+" + name + r"\s*:\s*\[\s*u8\s*;\s*32\s*\]\s*=\s*(\[[\s\S]*?\]);", text)
    if not match:
        raise ValueError("Missing binding: " + name)
    value = bytes(ast.literal_eval(match.group(1)))
    if len(value) != 32:
        raise ValueError("Invalid binding length: " + name)
    return value


source = (ROOT / "crates/custom-policy/policy/policy.rs").read_bytes()
contract = (ROOT / "crates/custom-policy/src/lib.rs").read_text()
protocol = (ROOT / "crates/protocol/src/lib.rs").read_text()
for name, schema in SCHEMAS.items():
    if binding(contract, name) != hashlib.sha256(schema).digest():
        raise SystemExit("Custom policy schema differs: " + name)
    if schema.decode() not in protocol:
        raise SystemExit("Native argument schema differs from the custom policy binding: " + name)
# The only alternative module is the `test-catching` fixture, which deployment tooling rejects.
POLICY_MODULE = ('#[cfg(not(feature = "test-catching"))]\n#[path = "../policy/policy.rs"]\nmod policy;\n'
                 '/// Test fixture only: a policy that catches a rule error, continues and writes its own state.\n'
                 '#[cfg(feature = "test-catching")]\n#[path = "catching_policy.rs"]\nmod policy;\n')
if contract.count("mod policy;") != 2 or POLICY_MODULE not in contract or "/source_hash.rs" not in contract:
    raise SystemExit("Custom policy must compile and hash its authored source verbatim")
for path in ("crates/custom-policy/policy/policy.rs", "crates/custom-policy/src/branch_policy.rs",
             "crates/custom-policy/src/catching_policy.rs"):
    try:
        checked_code((ROOT / path).read_text())
        host_compile(ROOT / path)
    except ValueError as error:
        raise SystemExit(path + ": " + str(error)) from None
print("PASS custom policy source " + hashlib.sha256(source).hexdigest())
