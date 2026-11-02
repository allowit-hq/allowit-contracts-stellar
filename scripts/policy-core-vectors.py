#!/usr/bin/env python3
"""Record native owner-param vectors. Generic source-gate vectors live in Core."""
import json
import random
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
PARAMS_FILE=ROOT/"stellar/core/tests/fixtures/params-vectors.json"

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
KEYS = ["payment_limit", "lifetime_spending_limit", "daily_spending_limit", "daily_volume_limit", "call_limit", "destinations",
        "tokens", "expires_at", "operations", "custom", "k" * 32, "k" * 33, "bad-key", "", "T1"]
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
    for path, build in ((PARAMS_FILE, params_vectors),):
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
