"""Release failures must stop before signing or publication; no live network is used."""
import copy
from datetime import datetime, timezone
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
    header.scp_value.close_time = xdr.TimePoint(xdr.Uint64(int(datetime.now(timezone.utc).timestamp()) - 5))
    return {"sequence": sequence, "hash": hashlib.sha256(header.to_xdr_bytes()).hexdigest(),
        "header_xdr": header.to_xdr(), "closed_at": datetime.fromtimestamp(header.scp_value.close_time.time_point.uint64, timezone.utc).isoformat()}


def make_bundle(root):
    source = b"reviewed policy bytes\n"
    result = {"schema": 1, "repository": release.REPOSITORY, "tag": "v0.3.0", "revision": "a" * 40,
        "tag_object": "b" * 40, "workflow_revision": "c" * 40, "core_source": release.CORE_SOURCES["v0.3.0"],
        "toolchain": {"rust": "1.98.0", "stellar": "28.1.0"}, "artifacts": {},
        "sample_policy": {"file": "sample-policy.rs", "sha256": release.digest(source), "rules": ["payment_limit"]}}
    for kind, name in release.CONTRACTS.items():
        data = wasm()
        (root / name).write_bytes(data)
        result["artifacts"][kind] = {"file": name, "bytes": len(data), "sha256": release.digest(data)}
    (root / "sample-policy.rs").write_bytes(source)
    release.write(root / "source-manifest.json", result)
    release.write(root / "release-build.json", release.build_record(result, "90:1"))
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


class ReleaseSourceLayouts(unittest.TestCase):
    layouts = (
        ("stellar/core", "crates/custom-policy/policy/policy.rs"),
        ("crates/allowit-stellar", "contracts/allowit-custom-policy/policy/policy.rs"),
    )

    def create_source(self, root, native_name, policy_name, tag):
        native, policy = root / native_name, root / policy_name
        native.mkdir(parents=True)
        policy.parent.mkdir(parents=True)
        version = tag.removeprefix("v")
        (root / "Cargo.toml").write_text(f'[workspace.package]\nversion = "{version}"\n')
        (native / "Cargo.toml").write_text(f'[package]\nversion = "{version}"\n')
        lock = f'[[package]]\nname = "allowit-core"\nversion = "{version}"\nsource = "{release.CORE_SOURCES[tag]}"\n'
        locks = [root / "Cargo.lock", native / "Cargo.lock"]
        if tag == "v0.4.0":
            bindings = root / "crates/policy-bindings"
            bindings.mkdir(parents=True)
            (bindings / "Cargo.toml").write_text(f'[package]\nversion = "{version}"\n')
            locks.append(bindings / "Cargo.lock")
        for path in locks:
            path.write_text(lock)
        policy.write_bytes(b"exact policy bytes\n")
        return native, policy

    def test_bundle_old_and_new_sources_preserve_exact_artifacts(self):
        for (native_name, policy_name), tag in zip(self.layouts, ("v0.3.0", "v0.4.0")):
            with self.subTest(layout=native_name, tag=tag), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                native, policy = self.create_source(root, native_name, policy_name, tag)
                target = root / "target"
                artifacts = target / "wasm32v1-none/release"
                artifacts.mkdir(parents=True)
                external_target = root / "external-cache"
                external_artifacts = external_target / "wasm32v1-none/release"
                external_artifacts.mkdir(parents=True)
                for filename in release.CONTRACTS.values():
                    (artifacts / filename).write_bytes(wasm())
                    (external_artifacts / filename).write_bytes(b"raw Cargo output, before CLI processing")
                identity = {"tag": tag, "revision": "a" * 40,
                    "tag_object": "b" * 40, "workflow_revision": "c" * 40}
                output = root / "bundle"
                with patch.object(release, "git", side_effect=[identity["revision"], ""]), \
                        patch.object(release, "public_output", return_value=json.dumps(["payment_limit"])) as helper, \
                        patch.object(release, "workflow_attempt", return_value="90:1"):
                    result = release.bundle(root, identity, output)
                self.assertEqual(helper.call_count, 1)
                self.assertEqual(release.source_layout(root), (native, policy))
                self.assertEqual(release.check_bundle(output), result)
                self.assertEqual((output / "sample-policy.rs").read_bytes(), policy.read_bytes())
                for filename in release.CONTRACTS.values():
                    self.assertEqual((output / filename).read_bytes(), (artifacts / filename).read_bytes())

    def test_bundle_rejects_a_mixed_core_release_in_every_lock(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            native, _ = self.create_source(root, *self.layouts[1], "v0.4.0")
            identity = {"tag": "v0.4.0", "revision": "a" * 40,
                "tag_object": "b" * 40, "workflow_revision": "c" * 40}
            locks = [root / "Cargo.lock", native / "Cargo.lock",
                root / "crates/policy-bindings/Cargo.lock"]
            for lock in locks:
                original = lock.read_text()
                lock.write_text(original.replace(release.CORE_SOURCES["v0.4.0"],
                    release.CORE_SOURCES["v0.3.0"]))
                with self.subTest(lock=lock.relative_to(root)), \
                        patch.object(release, "git", side_effect=[identity["revision"], ""]), \
                        self.assertRaisesRegex(ValueError, "single approved"):
                    release.bundle(root, identity, root / "bundle")
                lock.write_text(original)

    def test_missing_partial_and_ambiguous_sources_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(ValueError, "exactly one"):
                release.source_layout(root)
            native, policy = self.create_source(root, *self.layouts[0], "v0.3.0")
            (native / "Cargo.lock").unlink()
            with self.assertRaisesRegex(ValueError, "Incomplete"):
                release.source_layout(root)
            (native / "Cargo.lock").write_text("")
            self.create_source(root, *self.layouts[1], "v0.3.0")
            with self.assertRaisesRegex(ValueError, "exactly one"):
                release.source_layout(root)


class PublicTestnetHeaders(unittest.TestCase):
    """Exact public Horizon/RPC records, including protocol 30 signed millisecond values."""
    def setUp(self):
        path = Path(__file__).with_name("fixtures") / "testnet-protocol-30-ledgers.json"
        self.fixture = json.loads(path.read_text())
        self.recent = self.fixture["horizon_recent"]
        self.rpc = Mock()
        self.rpc.get_network.return_value = SimpleNamespace(passphrase=release.PASSPHRASE)
        self.rpc.get_latest_ledger.return_value = SimpleNamespace(sequence=self.recent["sequence"])
        self.rpc.get_ledgers.return_value = SimpleNamespace(ledgers=[SimpleNamespace(**self.fixture["rpc_recent"])])
        self.clock = datetime.fromisoformat(self.recent["closed_at"].replace("Z", "+00:00")).timestamp() + 5
        self.enterContext(patch.object(release, "utc_seconds", return_value=self.clock))
        self.enterContext(patch.object(release, "public_json_url", side_effect=self.public))

    def public(self, path):
        if path == "/":
            return {"network_passphrase": release.PASSPHRASE, "history_latest_ledger": self.recent["sequence"]}
        if path == "/ledgers/128":
            return self.fixture["horizon_anchor"]
        self.assertEqual(path, "/ledgers/" + str(self.recent["sequence"]))
        return self.recent

    def test_public_protocol_30_headers_preserve_native_identity(self):
        identity = release.network_identity(self.rpc)
        self.assertEqual(identity["generation"]["hash"], self.fixture["horizon_anchor"]["hash"])
        self.assertEqual(identity["observed"]["hash"], self.recent["hash"])
        self.assertEqual(identity["observed"]["horizon_header_xdr"], self.recent["header_xdr"])
        self.assertEqual(identity["observed"]["rpc_header_xdr"], self.fixture["rpc_recent"]["header_xdr"])
        header = xdr.LedgerHeader.from_xdr(self.recent["header_xdr"])
        self.assertEqual(header.ledger_version.uint32, 30)
        self.assertEqual(int(header.scp_value.ext.v), 3)
        self.assertEqual(release.digest(header.to_xdr_bytes()), self.recent["hash"])
        self.assertEqual(release.native_header(self.rpc, self.recent["sequence"]), {
            "ledger": self.recent["sequence"], "hash": self.recent["hash"],
            "header_xdr": self.fixture["rpc_recent"]["header_xdr"]})

    def test_public_protocol_30_hash_time_and_native_wrapper_still_fail_closed(self):
        for field, value in (("hash", "00" * 32), ("closed_at", "2026-01-01T00:00:00Z")):
            with self.subTest(field=field):
                old = self.recent[field]
                self.recent[field] = value
                try:
                    with self.assertRaisesRegex(ValueError, "differs"):
                        release.network_identity(self.rpc)
                finally:
                    self.recent[field] = old
        entry = xdr.LedgerHeaderHistoryEntry.from_xdr(self.fixture["rpc_recent"]["header_xdr"])
        entry.hash = xdr.Hash(bytes(32))
        self.rpc.get_ledgers.return_value.ledgers[0].header_xdr = entry.to_xdr()
        with self.assertRaisesRegex(ValueError, "headers disagree"):
            release.network_identity(self.rpc)
        with self.assertRaisesRegex(ValueError, "differs from its identity"):
            release.native_header(self.rpc, self.recent["sequence"])


class ReleaseSafety(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.manifest = make_bundle(self.root)
        self.owner, self.agent, self.server = (Keypair.random() for _ in range(3))
        self.config, self.salt, self.wallet = release.wallet_intent(self.manifest, 'common', self.owner.public_key, self.agent.public_key, self.server.public_key)
        self.module = self.manifest['artifacts']['common']['sha256']

    def test_bundle_native_constructor_and_stable_identity(self):
        self.assertEqual(release.check_bundle(self.root), self.manifest)
        packet = constructor(self.config, self.module, self.salt)
        release.check_constructor(packet, self.config, self.module, self.salt)
        changed, salt, wallet = release.wallet_intent(self.manifest, 'common', self.owner.public_key, self.server.public_key, self.agent.public_key)
        self.assertEqual((salt, wallet, changed['policy_instance']), (self.salt, self.wallet, self.config['policy_instance']))
        self.assertNotEqual(changed['server'], self.config['server'])
        other = {**self.manifest, 'tag':'v0.4.0'}
        self.assertNotEqual(release.wallet_intent(other, 'common', self.owner.public_key, self.agent.public_key, self.server.public_key)[2], self.wallet)

    def test_bundle_rejects_core_source_from_another_release(self):
        self.manifest["core_source"] = release.CORE_SOURCES["v0.4.0"]
        release.write(self.root / "source-manifest.json", self.manifest)
        with self.assertRaisesRegex(ValueError, "Core source differs"):
            release.check_bundle(self.root)

    def test_strict_constructor_variants_and_intent(self):
        for field, value in [('server',self.agent.public_key),('policy_instance','11'*32),('rules',[]),('x402_enabled',True)]:
            changed=copy.deepcopy(self.config);changed[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):
                release.check_constructor(constructor(changed,self.module,self.salt),self.config,self.module,self.salt)
        packet=constructor(self.config,self.module,self.salt)
        fields=scval.from_struct(packet.constructor_args[0]);params=scval.from_struct(fields['params'])
        params['destinations']=scval.to_enum('List',scval.to_vec([scval.to_enum('Str',scval.to_string(self.agent.public_key))]))
        fields['params']=scval.to_struct(params);packet.constructor_args[0]=scval.to_struct(fields)
        with self.assertRaises(ValueError):release.check_constructor(packet,self.config,self.module,self.salt)

    def test_bundle_provenance_and_paths_fail_before_network(self):
        for mutation in ('wasm','source','core','path'):
            make_bundle(self.root)
            if mutation=='wasm':(self.root/release.CONTRACTS['common']).write_bytes(wasm()+b'wrong')
            elif mutation=='source':(self.root/'sample-policy.rs').write_text('wrong')
            else:
                changed=copy.deepcopy(self.manifest)
                if mutation=='core':changed['core_source']='wrong'
                else:changed['artifacts']['common']['file']='../outside.wasm'
                release.write(self.root/'source-manifest.json',changed)
            with self.subTest(mutation=mutation),patch.object(release,'SorobanServer') as rpc,self.assertRaises(ValueError):
                release.Deployment(self.root,self.root/'out',self.root/'private',self.owner,self.agent.public_key,self.server.public_key)
            rpc.assert_not_called()

    def test_hostile_tags_and_wrong_run_provenance(self):
        for tag in ('main','--option','v01.2.0','v0.3.0; bad'):
            with patch.object(release,'git') as git,self.assertRaises(ValueError):release.release_identity(self.root,tag,'a'*40)
            git.assert_not_called()
        with patch.dict(os.environ,{'GITHUB_RUN_ID':'100','GITHUB_RUN_ATTEMPT':'1','GITHUB_WORKFLOW_SHA':'c'*40}),patch.object(release,'check_canonical_tag'),patch.object(release,'git',return_value='c'*40),patch.object(release,'public_run',return_value=SimpleNamespace(returncode=0)),patch.object(release,'gh_json',return_value={'path':'.github/workflows/untrusted.yml'}),self.assertRaisesRegex(ValueError,'canonical main'):
            release.current_authority(self.manifest)

    def test_public_children_use_explicit_environment(self):
        with patch.dict(os.environ,{'STELLAR_TESTNET_OWNER_SECRET':'synthetic','GEMINI_API_KEY':'synthetic','GH_TOKEN':'scoped','ALLOWIT_AGENT_TOKEN':'synthetic'}):
            env=release.public_env()
            self.assertFalse({'STELLAR_TESTNET_OWNER_SECRET','GEMINI_API_KEY','GH_TOKEN','ALLOWIT_AGENT_TOKEN'}&env.keys())
            self.assertEqual(release.public_env(True)['GH_TOKEN'],'scoped')
            for code in (0,17):
                result=release.public_run([sys.executable,'-c','import os,sys; assert all(k not in os.environ for k in ("STELLAR_TESTNET_OWNER_SECRET","GEMINI_API_KEY","GH_TOKEN","ALLOWIT_AGENT_TOKEN"));sys.exit('+str(code)+')'])
                self.assertEqual(result.returncode,code)

    def test_exact_current_trigger_and_successful_build_attempt_are_rechecked(self):
        event=self.root/'event.json';release.write(event,{'workflow_run':{'id':90,'run_attempt':1}})
        current={'path':'.github/workflows/testnet-release.yml','event':'workflow_run','head_repository':{'full_name':'allowit-hq/allowit-contracts-stellar'},'head_branch':'main','head_sha':'c'*40,'run_attempt':1}
        built={'path':'.github/workflows/release.yml','event':'workflow_dispatch','head_repository':{'full_name':'allowit-hq/allowit-contracts-stellar'},'head_branch':'main','head_sha':'c'*40,'run_attempt':1,'conclusion':'success'}
        env={'GITHUB_RUN_ID':'100','GITHUB_RUN_ATTEMPT':'1','GITHUB_WORKFLOW_SHA':'c'*40,'RELEASE_BUILD_RUN_ID':'90','RELEASE_BUILD_RUN_ATTEMPT':'1','GITHUB_EVENT_PATH':str(event)}
        with patch.dict(os.environ,env),patch.object(release,'check_canonical_tag'),patch.object(release,'git',return_value='c'*40),patch.object(release,'public_run',return_value=SimpleNamespace(returncode=0)):
            for mutation in (None,'head_sha','path','conclusion','run_attempt'):
                selected=copy.deepcopy(built)
                if mutation:selected[mutation]='wrong'
                with patch.object(release,'gh_json',side_effect=[current,selected]):
                    if mutation:
                        with self.assertRaises(ValueError):release.current_authority(self.manifest)
                    else:self.assertEqual(release.current_authority(self.manifest)['build_run'],'90:1')
            release.write(event,{'workflow_run':{'id':89,'run_attempt':1}})
            with patch.object(release,'gh_json',return_value=current),self.assertRaisesRegex(ValueError,'trigger'):release.current_authority(self.manifest)

    def test_controller_rejects_a_native_sdk_that_differs_from_the_pin(self):
        env = {"GITHUB_WORKFLOW_SHA": "c" * 40}
        for sdk_version in ("16.1.0", "17.0.1"):
            with self.subTest(version=sdk_version), patch.dict(os.environ, env), \
                    patch.object(release, "check_canonical_tag"), \
                    patch.object(release, "git", return_value="c" * 40), \
                    patch.object(release, "version", return_value=sdk_version), \
                    patch.object(release, "public_run") as command, \
                    self.assertRaisesRegex(ValueError, "native SDK differ"):
                release.current_authority(self.manifest)
            command.assert_not_called()

    def test_public_stop_message_exposes_only_a_fixed_stage(self):
        error = ValueError("synthetic private exception detail")
        with self.assertRaisesRegex(ValueError, "synthetic private exception detail"):
            release.public_stage("DEPLOYMENT_EXECUTION", release.public_stage,
                "NATIVE_ASSET", Mock(side_effect=error))
        message = release.release_stop_message(error)
        self.assertIn("stage=NATIVE_ASSET", message)
        self.assertNotIn("synthetic private", message)
        error.release_stage = "untrusted exception detail"
        self.assertIn("stage=COMMAND", release.release_stop_message(error))
        self.assertNotIn("untrusted exception", release.release_stop_message(error))

    def test_immutable_run_snapshots_never_clobber(self):
        path=self.root/'snapshot.json';release.immutable(path,b'first');release.immutable(path,b'first')
        with self.assertRaises(ValueError):release.immutable(path,b'second')
        self.assertEqual(path.read_bytes(),b'first')

if __name__=='__main__':unittest.main()
