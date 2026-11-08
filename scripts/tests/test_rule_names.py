"""Tracked files use the adopted rule names: no "cap" wording and no retired param key comes back.

The limits are `payment_limit`, `lifetime_spending_limit`, `daily_spending_limit`,
`daily_volume_limit` and `call_limit`; the lists are `destinations`, `tokens` and `operations`;
the deadline is `expires_at`. Words such as capability, capture and capacity do not match. A
transaction fee cap and a Stellar Core Advancement Proposal (CAP-NNNN) are not policy limits."""
import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SKIP = (".lock", ".wasm")
# This file names the patterns it rejects.
SELF = Path(__file__).resolve().relative_to(ROOT).as_posix()
# "cap", "caps", "capped" as a word or an identifier part, in any case or in camel case.
CAP = re.compile(r"(?<![A-Za-z])(?:cap|Cap|CAP)(?:s|S|ped|PED)?(?![a-z])|(?<=[a-z])Cap(?![a-z])")
ALLOWED = re.compile(r"(?i)fee[ _]caps?(?![a-z])|(?<![A-Za-z])cap-\d+")
RETIRED = re.compile(
    r"allowit::(?:RECIPIENTS|EXPIRY|OPS)\b|allowit::(?:recipients|expiry|ops)\s*\(|AllowitRule::(?:recipients|expiry|ops)\b"
    r"|params\[\s*\"(?:recipients|expiry|ops)\"\s*\]|\"(?:recipients|expiry|ops)\"\s*:"
)


def hits(text):
    found = []
    for number, line in enumerate(text.splitlines(), 1):
        stripped = ALLOWED.sub("", line)
        if CAP.search(stripped) or RETIRED.search(line):
            found.append((number, line.strip()[:160]))
    return found


class RuleNameTests(unittest.TestCase):
    def test_patterns(self):
        for bad in ("Cap every payment", "invoice_cap", "INVOICE_CAP", "v.caps[0]", "CallCapExceeded", "classic_caps_keep",
                    "CAPPED", "a capped amount", "allowit::OPS", "ctx.params[\"recipients\"]", "{\"expiry\": 1}"):
            with self.subTest(bad=bad):
                self.assertTrue(hits(bad))
        for good in ("capability", "OwnerCapabilities", "capture", "capacity", "escape", "fee_caps_stroops", "stage fee cap",
                     "CAP-15", "cap-0066.md", "call_limit", "std::ops", "\"expiry\" => changed.expires_at += 1"):
            with self.subTest(good=good):
                self.assertFalse(hits(good))

    def test_tracked_files_use_adopted_rule_names(self):
        files = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, check=True, capture_output=True).stdout.split(b"\0")
        found = []
        for name in filter(None, (f.decode() for f in files)):
            path = ROOT / name
            if name.endswith(SKIP) or name == SELF or not path.is_file():
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            found += ["{}:{}: {}".format(name, number, line) for number, line in hits(text)]
        self.assertEqual(found, [])


if __name__ == "__main__":
    unittest.main()
