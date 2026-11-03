"""Release failures must stop before signing or publication; no live network is used."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import testnet_release as release
from stellar_sdk import Account, Address, Keypair, Network, TransactionBuilder, scval, xdr


def wasm():
    key, value = b"allowit_custody_layout", b"4"
    string = lambda data: len(data).to_bytes(4, "big") + data + b"\0" * (-len(data) % 4)
    meta = (0).to_bytes(4, "big") + string(key) + string(value)
    section = bytes([len(b"contractmetav0")]) + b"contractmetav0" + meta
    assert len(section) < 128
    return b"\0asm\x01\0\0\0\0" + bytes([len(section)]) + section


HEADER = 'AAAAHcZUtF0kU/EUPP5rVPxlxXrXJkZACUX7owA2H+03VA2SBYTDT40HB+AoPdOAmvZahm8nLETwKm772EfLg3gA0aoAAAAAaulRZAAAAAAAAAABAAAAALVdELK7fShO1cA6R6XhtZDJD1eDVUccxFB7voIE0jyLAAAAQIwULdseRt+SGg3UVPP2Uxrc17N4FmHi7pn8BpK+Ti8A8T837IwAWSW7dvmXYJB+ygIPmwXf0y2fpW8vcMducA5OL+zh2o752a5vI7tUrIakdaCY1POwPOGDU2/mvc9l5K4nAAZtG3JCSZZ1eeCxVKeLFgh7tnqMpZohzRF5U7keAFRjHA3gtrOnZAAAAAAssvgWS94AAAAAAAAAAAAOUFMAAABkAExLQAAAAMhxyYyFUWF57GaIY/xBq6LJb98hxNe4yeDPavXUhJXd7HkUDjOFVGqdFFv2dUYsj7l9wPt801UBN1Uzuf6cnEUMRMBoDPQBwpeD7Ri4S3ftkKh9f06Ejj/Mx09WJZoMPWi2cm6r8ecN/675yBcoOos0c4aKRh6aDbiou7DptxnL1QAAAAA='

def ledger(sequence):
    header = xdr.LedgerHeader.from_xdr(HEADER)
    header.ledger_seq = xdr.Uint32(sequence)
    return {"sequence": sequence, "hash": hashlib.sha256(header.to_xdr_bytes()).hexdigest(),
        "header_xdr": header.to_xdr(), "closed_at": "2026-11-03T03:00:00Z"}


def make_bundle(root):
    source = b"reviewed policy bytes\n"
    result = {"schema": 1, "repository": release.REPOSITORY, "tag": "v0.2.0", "revision": "a" * 40,
        "tag_object": "b" * 40, "workflow_revision": "c" * 40, "core_source": release.CORE_SOURCE,
        "toolchain": {"rust": "1.98.0", "stellar": "28.1.0"}, "artifacts": {},
        "sample_policy": {"file": "sample-policy.rs", "sha256": release.digest(source), "rules": ["payment_limit"]}}
    for kind, name in release.CONTRACTS.items():
        data = wasm()
        (root / name).write_bytes(data)
        result["artifacts"][kind] = {"file": name, "bytes": len(data), "sha256": release.digest(data)}
    (root / "sample-policy.rs").write_bytes(source)
    release.write(root / "source-manifest.json", result)
    return result


def constructor(config, module, salt):
    def value(item):
        if type(item) is int:
            return scval.to_enum("Int", scval.to_int128(item))
        if isinstance(item, list):
            return scval.to_enum("List", scval.to_vec([value(v) for v in item]))
        if release.ca.is_address(item):
            return scval.to_enum("Addr", scval.to_address(item))
        return scval.to_enum("Str", scval.to_string(item))
    fields = {key: scval.to_address(config[key]) for key in ("owner", "agent", "server", "asset")}
    fields.update(policy_instance=scval.to_bytes(bytes.fromhex(config["policy_instance"])),
        source_digest=scval.to_bytes(bytes.fromhex(config["source_digest"])),
        rules=scval.to_vec([scval.to_enum(rule, None) for rule in config["rules"]]),
        params=scval.to_struct({key: value(item) for key, item in config["params"].items()}),
        x402_enabled=scval.to_bool(config["x402_enabled"]))
    return xdr.CreateContractArgsV2(
        xdr.ContractIDPreimage(xdr.ContractIDPreimageType.CONTRACT_ID_PREIMAGE_FROM_ADDRESS,
            from_address=xdr.ContractIDPreimageFromAddress(Address(config["owner"]).to_xdr_sc_address(), xdr.Uint256(salt))),
        xdr.ContractExecutable(xdr.ContractExecutableType.CONTRACT_EXECUTABLE_WASM, wasm_hash=xdr.Hash(bytes.fromhex(module))),
        [scval.to_struct(fields)])


class ReleaseSafety(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.manifest = make_bundle(self.root)
        self.owner, self.agent, self.server = (Keypair.random() for _ in range(3))
        self.config = release.config_for(self.manifest, "common", self.owner.public_key, self.agent.public_key, self.server.public_key)
        self.module = self.manifest["artifacts"]["common"]["sha256"]
        self.salt = bytes.fromhex("42" * 32)

    def test_exact_bundle_and_native_constructor(self):
        self.assertEqual(release.check_bundle(self.root), self.manifest)
        packet = constructor(self.config, self.module, self.salt)
        release.check_constructor(packet, self.config, self.module, self.salt)
        self.assertEqual(release.contract_id(self.owner.public_key, self.salt),
            Address.from_xdr_sc_address(release.ca.deployment_address(packet, "testnet")).address)

    def test_native_import_does_not_load_authoring_tools(self):
        script = "import sys;sys.path.insert(0,sys.argv[1]);import contract_admin;assert 'policy_source' not in sys.modules;assert 'core_sources' not in sys.modules"
        subprocess.run([sys.executable, "-c", script, str(Path(release.ca.__file__).parent)], check=True, capture_output=True)

    def test_replaced_wasm_rejected_before_network_or_secret(self):
        (self.root / release.CONTRACTS["common"]).write_bytes(wasm() + b"changed")
        with patch.object(release, "SorobanServer") as network:
            with self.assertRaisesRegex(ValueError, "differs"):
                release.Deployment(self.root, self.root / "public.json", self.root / "private", self.owner,
                    self.agent.public_key, self.server.public_key)
            network.assert_not_called()

    def test_bundle_paths_and_source_are_bound(self):
        for target in ("artifacts", "source"):
            with self.subTest(target=target):
                make_bundle(self.root)
                if target == "artifacts":
                    changed = copy.deepcopy(self.manifest)
                    changed["artifacts"]["common"]["file"] = "../outside.wasm"
                    release.write(self.root / "source-manifest.json", changed)
                else:
                    (self.root / "sample-policy.rs").write_bytes(b"other policy")
                with self.assertRaises(ValueError):
                    release.check_bundle(self.root)

    def test_native_constructor_mutations_refuse_before_signing(self):
        # A source-side CLI/spec mismatch is independent of RPC intent checks.
        mutations = {
            "owner": lambda c: c.update(owner=Keypair.random().public_key),
            "agent": lambda c: c.update(agent=self.server.public_key),
            "asset": lambda c: c.update(asset=release.contract_id(self.owner.public_key, b"x" * 32)),
            "amount": lambda c: c["params"].update(payment_limit=20_000_000),
            "rules": lambda c: c.update(rules=[]),
            "instance": lambda c: c.update(policy_instance="11" * 32),
            "source": lambda c: c.update(source_digest="11" * 32),
            "x402": lambda c: c.update(x402_enabled=True),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                changed = copy.deepcopy(self.config)
                mutate(changed)
                with self.assertRaises(ValueError):
                    release.check_constructor(constructor(changed, self.module, self.salt), self.config, self.module, self.salt)
        for module, salt in (("22" * 32, self.salt), (self.module, b"z" * 32)):
            with self.assertRaises(ValueError):
                release.check_constructor(constructor(self.config, module, salt), self.config, self.module, self.salt)

    def test_deterministic_instance_binds_release_and_roles(self):
        first = self.config["policy_instance"]
        self.assertEqual(first, release.config_for(self.manifest, "common", self.owner.public_key,
            self.agent.public_key, self.server.public_key)["policy_instance"])
        other = copy.deepcopy(self.manifest)
        other["revision"] = "d" * 40
        self.assertNotEqual(first, release.config_for(other, "common", self.owner.public_key,
            self.agent.public_key, self.server.public_key)["policy_instance"])

    def test_mainnet_and_shared_role_fail_closed(self):
        network = Mock()
        network.get_network.return_value.passphrase = Network.PUBLIC_NETWORK_PASSPHRASE
        with patch.object(release, "SorobanServer", return_value=network):
            with self.assertRaisesRegex(ValueError, "not Stellar Testnet"):
                release.Deployment(self.root, self.root / "public.json", self.root / "private", self.owner,
                    self.agent.public_key, self.server.public_key)
        with patch.object(release, "SorobanServer") as network:
            with self.assertRaisesRegex(ValueError, "must differ"):
                release.Deployment(self.root, self.root / "public.json", self.root / "private", self.owner,
                    self.owner.public_key, self.server.public_key)
            network.assert_not_called()

    def test_hostile_tag_rejected_without_git_or_network(self):
        for tag in ("main", "v0.2.0; touch bad", "--upload-pack=bad", "v01.2.0", "v0.2.0\nother"):
            with self.subTest(tag=tag), patch.object(release, "git") as git:
                with self.assertRaises(ValueError):
                    release.release_identity(self.root, tag, "c" * 40)
                git.assert_not_called()

    def test_uncertain_submission_retains_original_and_never_resigns(self):
        deployment = release.Deployment.__new__(release.Deployment)
        deployment.key = self.owner
        deployment.private = self.root / "private"
        deployment.private.mkdir(mode=0o700)
        deployment.output = self.root / "public.json"
        deployment.public = {"transactions": []}
        deployment.rpc = Mock()
        envelope = TransactionBuilder(Account(self.owner.public_key, 1), release.PASSPHRASE, base_fee=100).set_timeout(300).append_upload_contract_wasm_op(wasm()).build()
        self.owner.sign = Mock(wraps=self.owner.sign)
        deployment.cli = Mock(side_effect=subprocess.CalledProcessError(1, ["stellar", "tx", "send"]))
        with patch.object(release.ca, "prepare_xdr", return_value=envelope.to_xdr()):
            with self.assertRaisesRegex(ValueError, "Submission uncertain"):
                deployment.submit("upload-common", envelope.to_xdr())
        self.owner.sign.assert_called_once()
        deployment.cli.assert_called_once()
        deployment.rpc.get_transaction.assert_not_called()
        private = json.loads((deployment.private / "upload-common.json").read_text())
        public = json.loads(deployment.output.read_text())
        self.assertEqual(public["transactions"][0]["status"], "unknown")
        self.assertNotIn(private["signed_xdr"], deployment.output.read_text())
        self.assertEqual((deployment.private / "upload-common.json").stat().st_mode & 0o777, 0o600)

    def identity(self):
        return {"network": "stellar:testnet", "network_id": Network(release.PASSPHRASE).network_id().hex(),
            "rpc": release.RPC, "horizon": release.HORIZON, "passphrase": release.PASSPHRASE,
            "generation": {"ledger": 128, "hash": "42" * 32, "source": release.HORIZON + "/ledgers/128",
                "closed_at": "2025-12-17T17:30:12Z", "observed_at": "2026-11-03T00:00:00Z"},
            "genesis_available": False, "observed": {"ledger": 1000, "hash": "43" * 32}}

    def prior(self):
        return {"schema": 1, "network": "stellar:testnet", "source": self.manifest,
            "owner": self.owner.public_key, "agent": self.agent.public_key, "server": self.server.public_key,
            "network_identity": self.identity(), "status": "VERIFIED", "wallets": {}, "transactions": []}

    def test_healthy_driver_rerun_preserves_addresses_roles_and_funding(self):
        identity = self.identity()
        private = tempfile.TemporaryDirectory()
        self.addCleanup(private.cleanup)
        with patch.object(release, "network_identity", return_value=identity), patch.object(release, "SorobanServer"):
            driver = release.Deployment(self.root, self.root / "result.json", Path(private.name) / "packets", self.owner,
                self.agent.public_key, self.server.public_key)
        driver.ensure_account = Mock()
        driver.submit = Mock(side_effect=AssertionError("Healthy reruns must not sign or submit"))
        driver.cli = Mock(side_effect=AssertionError("Healthy reruns must not fund or build replacements"))
        driver.code = Mock(side_effect=lambda value: {"sha256": value, "bytes": len(wasm()), "ledger": 1000})
        driver.instance = Mock(side_effect=lambda address, value: {"contract": address, "wasm_sha256": value, "ledger": 1000})
        def state(wallet):
            for kind in release.KINDS:
                config = release.config_for(self.manifest, kind, self.owner.public_key, self.agent.public_key, self.server.public_key)
                salt = bytes.fromhex(release.digest(release.canonical(["allowit_testnet_release_salt_v1", self.manifest["tag"], config])))
                if release.contract_id(self.owner.public_key, salt) == wallet:
                    return {**config, "params": release.ca.params(config["params"], kind), "contract_version": 4}
            raise AssertionError("Unexpected wallet")
        driver.read_state = state
        with patch.object(release, "network_identity", return_value=identity):
            result = driver.run()
        self.assertEqual(result["status"], "VERIFIED")
        self.assertEqual(set(result["wallets"]), set(release.KINDS))
        self.assertEqual(result["transactions"], [])
        driver.submit.assert_not_called()
        driver.cli.assert_not_called()

    def test_prior_role_or_config_change_stops_before_network_and_mutation(self):
        previous = self.root / "previous"
        previous.mkdir()
        for change in ("role", "config"):
            prior = self.prior()
            if change == "role":
                prior["server"] = self.owner.public_key
            else:
                prior["wallets"] = {"common": {"config": {**self.config, "x402_enabled": True}}}
            release.write(previous / "checkpoint.json", prior)
            with patch.object(release, "SorobanServer") as network:
                with self.assertRaisesRegex(ValueError, "differ"):
                    release.Deployment(self.root, self.root / "result.json", self.root / "private", self.owner,
                        self.agent.public_key, self.server.public_key, previous)
                network.assert_not_called()

    def test_pending_original_hash_blocks_rerun_until_native_expiry(self):
        driver = release.Deployment.__new__(release.Deployment)
        driver.key = self.owner
        driver.public = {"network_identity": self.identity()}
        driver.rpc = Mock()
        driver.rpc.get_transaction.return_value.status = release.GetTransactionStatus.NOT_FOUND
        prior = self.prior()
        prior["status"] = "IN_PROGRESS"
        prior["transactions"] = [{"transaction_hash": "ab" * 32, "expires_at": 4_102_444_800}]
        driver.previous = [prior]
        with self.assertRaisesRegex(ValueError, "remains uncertain"):
            driver.reconcile_previous()
        driver.rpc.get_transaction.assert_called_once_with("ab" * 32)
        prior["transactions"][0]["expires_at"] = 1
        driver.reconcile_previous()

    def test_core_identity_and_native_release_version_are_part_of_bundle(self):
        changed = copy.deepcopy(self.manifest)
        changed["core_source"] = release.CORE_SOURCE.replace("v0.3.1", "v0.2.0")
        release.write(self.root / "source-manifest.json", changed)
        with self.assertRaisesRegex(ValueError, "Core source"):
            release.check_bundle(self.root)

    def test_recorded_generation_stays_fixed_and_reset_or_unavailable_history_is_explicit(self):
        anchor, recent = ledger(128), ledger(1000)
        native = xdr.LedgerHeaderHistoryEntry(xdr.Hash(bytes.fromhex(recent["hash"])),
            xdr.LedgerHeader.from_xdr(recent["header_xdr"]), xdr.LedgerHeaderHistoryEntryExt(0))
        rpc = Mock()
        rpc.get_network.return_value.passphrase = release.PASSPHRASE
        rpc.get_latest_ledger.return_value.sequence = 1000
        rpc.get_ledgers.return_value.ledgers = [SimpleNamespace(sequence=1000, hash=recent["hash"], header_xdr=native.to_xdr())]
        def public(path):
            return {"/": {"network_passphrase": release.PASSPHRASE, "history_elder_ledger": 256,
                "history_latest_ledger": 1000}, "/ledgers/128": anchor, "/ledgers/1000": recent}[path]
        recorded = {**self.identity()["generation"], "hash": anchor["hash"]}
        with patch.object(release, "public_json_url", side_effect=public):
            result = release.network_identity(rpc, recorded)
        self.assertEqual(result["generation"], recorded)
        self.assertFalse(result["genesis_available"])
        self.assertEqual(result["observed"]["horizon_header_xdr"], recent["header_xdr"])
        changed = {**recorded, "hash": "ab" * 32}
        with patch.object(release, "public_json_url", side_effect=public):
            reset = release.network_identity(rpc, changed)
        self.assertNotEqual(reset["generation"]["hash"], changed["hash"])
        def unavailable(path):
            if path == "/ledgers/128":
                raise release.HTTPError(release.HORIZON + path, 404, "unavailable", None, None)
            return public(path)
        with patch.object(release, "public_json_url", side_effect=unavailable):
            with self.assertRaisesRegex(ValueError, "anchor is unavailable"):
                release.network_identity(rpc, recorded)
        rpc.get_ledgers.return_value.ledgers[0].hash = "00" * 32
        with patch.object(release, "public_json_url", side_effect=public):
            with self.assertRaisesRegex(ValueError, "disagree"):
                release.network_identity(rpc, recorded)

    def test_immutable_published_manifest_is_never_replaced_on_healthy_rerun(self):
        prior = self.prior()
        prior["wallets"] = {kind: {"contract": release.contract_id(self.owner.public_key, bytes([index]) * 32),
            "wasm_sha256": self.manifest["artifacts"][kind]["sha256"],
            "config": release.config_for(self.manifest, kind, self.owner.public_key, self.agent.public_key, self.server.public_key)}
            for index, kind in enumerate(release.KINDS)}
        name = release.deployment_filename(self.manifest, prior["network_identity"])
        release.write(self.root / name, prior)
        previous = self.root / "previous" / "published"
        previous.mkdir(parents=True)
        release.write(previous / "source-manifest.json", self.manifest)
        release.write(previous / name, prior)
        ref = "refs/tags/" + self.manifest["tag"]
        remote = self.manifest["tag_object"] + "\t" + ref + "\n" + self.manifest["revision"] + "\t" + ref + "^{}\n"
        with patch.object(release.subprocess, "check_output", return_value=remote), patch.object(release.subprocess, "run") as command:
            release.publish(self.root, previous.parent)
            command.assert_not_called()


if __name__ == "__main__":
    unittest.main()
