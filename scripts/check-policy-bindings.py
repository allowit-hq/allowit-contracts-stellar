#!/usr/bin/env python3
"""Check that the custom policy binds its exact source and report the source digest.

The contract compiles policy/policy.rs verbatim as a module. build.rs derives SOURCE_HASH from the same
bytes, so the file must be the whole policy: it must not read other files, the environment or crates
other than `allowit` and `core`, and it must bind `allowit` only to the canonical crate. Each authored
source must also pass the std-only compile that the offchain server uses. The host portability test
includes the file, which rejects inner attributes and doc comments."""
import hashlib
from pathlib import Path

from policy_source import checked_code, host_compile

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / "crates/custom-policy/policy/policy.rs").read_bytes()
contract = (ROOT / "crates/custom-policy/src/lib.rs").read_text()
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
