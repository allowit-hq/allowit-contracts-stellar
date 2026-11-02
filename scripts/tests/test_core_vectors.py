"""The vectors that `stellar/core` replays must equal what the Python admin tools decide now."""
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("policy_core_vectors", ROOT / "scripts/policy-core-vectors.py")
vectors = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(vectors)


class CoreVectorTests(unittest.TestCase):
    def test_params_vectors_match_contract_admin(self):
        self.assertEqual(vectors.PARAMS_FILE.read_text(), vectors.dump(vectors.params_vectors()))



if __name__ == "__main__":
    unittest.main()
