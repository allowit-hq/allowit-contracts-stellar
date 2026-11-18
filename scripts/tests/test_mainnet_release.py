import hashlib
import copy
import time
import importlib.util
import json
import subprocess
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import mainnet_release as release
from stellar_sdk import Keypair, Asset, scval, Account, TransactionBuilder, Network, Address, TransactionEnvelope, StrKey, xdr


class ContractSourceManifestTests(unittest.TestCase):
    def test_old_and_new_manifests_bind_contract_sources_and_exclude_offchain_sdk(self):
        for contract, native in (("crates/custom-policy", "stellar/core"),
                ("contracts/allowit-custom-policy", "crates/allowit-stellar")):
            with self.subTest(contract=contract), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                scripts = root / "scripts"
                scripts.mkdir()
                (scripts / "artifacts.py").write_bytes((release.ROOT / "scripts/artifacts.py").read_bytes())
                (root / "Cargo.toml").write_text('[workspace]\nmembers = ["crates/policy", "' + contract + '"]\n')
                (root / "Cargo.lock").write_text("lock bytes")
                (root / "rust-toolchain.toml").write_text("toolchain bytes")
                for member in ("crates/policy", contract, native):
                    (root / member / "src").mkdir(parents=True)
                    (root / member / "src/lib.rs").write_text(member + " source")
                    (root / member / "Cargo.toml").write_text(member + " manifest")
                for script in release.BUILD_SCRIPTS:
                    (scripts / script).write_text(script)
                target = root / "target/wasm32v1-none/release"
                target.mkdir(parents=True)
                names = ("allowit_simple_policy_engine", "allowit_common_policy_engine", "allowit_custom_policy", "allowit_wallet_engine", "allowit_engine_parent")
                for name in names:
                    (target / (name + ".wasm")).write_bytes(b"fixture Wasm")
                subprocess.run(["git", "init", "-q", str(root)], check=True, capture_output=True)
                subprocess.run(["git", "-C", str(root), "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", "commit", "--allow-empty", "-qm", "fixture"], check=True, capture_output=True)
                manifest = json.loads(subprocess.check_output([sys.executable, str(scripts / "artifacts.py")], text=True))
                entries = {item["path"]: item["sha256"] for item in manifest["sources"]}
                self.assertEqual(set(entries), {str(path.relative_to(root)) for path in release.contract_build_sources(root)})
                for relative in (contract + "/Cargo.toml", contract + "/src/lib.rs", "crates/policy/Cargo.toml", "crates/policy/src/lib.rs"):
                    self.assertEqual(entries[relative], release.digest((root / relative).read_bytes()))
                self.assertFalse(any(path.startswith(native + "/") for path in entries))
                (root / contract / "src/lib.rs").write_text("changed contract")
                changed = json.loads(subprocess.check_output([sys.executable, str(scripts / "artifacts.py")], text=True))
                changed_entries = {item["path"]: item["sha256"] for item in changed["sources"]}
                self.assertNotEqual(entries[contract + "/src/lib.rs"], changed_entries[contract + "/src/lib.rs"])


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        # Unit fixtures describe this source checkout. Production release pins stay unchanged.
        revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=release.ROOT, text=True).strip()
        revision_patch = patch.object(release, 'DEFAULT_REVISION', revision)
        revision_patch.start()
        self.addCleanup(revision_patch.stop)
        keys = [Keypair.from_raw_ed25519_seed(bytes([n]) * 32).public_key for n in range(1, 10)]
        self.plan = dict(schema=2, network='mainnet', network_passphrase=Network.PUBLIC_NETWORK_PASSPHRASE,
            source_revision=release.DEFAULT_REVISION,
            artifact_manifest='manifest.json',
            owner=keys[0], admin=keys[1], agent=keys[2], recipient=keys[3], admin_members=keys[5:8], server=keys[8], asset=Asset.native().contract_id(Network.PUBLIC_NETWORK_PASSPHRASE),
            params=dict(destinations=[keys[3]], payment_limit=10000, daily_volume_limit=20020000, lifetime_spending_limit=20020000, call_limit=2, expires_at=2000000000),
            fund_stroops=20000, gas_cap_stroops=1000000, fee_caps_stroops=dict.fromkeys(release.STAGES, 10000000), total_fee_cap_stroops=60000000, artifacts={})
        files = release.contract_build_sources(release.ROOT)
        manifest = dict(git_revision=release.DEFAULT_REVISION, sources=[dict(path=str(f.relative_to(release.ROOT)),sha256=release.digest(f.read_bytes())) for f in files], artifacts=[])
        hashes = {}
        for name, filename in release.NAMES.items():
            data = ('fake-wasm-'+name).encode()
            (self.base/filename).write_bytes(data)
            hashes[name] = release.digest(data)
            self.plan['artifacts'][name] = dict(path=filename,sha256=hashes[name])
            manifest['artifacts'].append(dict(name=filename,sha256=hashes[name]))
        self.hashes = hashes
        (self.base/'manifest.json').write_text(json.dumps(manifest))
        self.path = self.base/'plan.json'

    def load(self):
        self.path.write_text(json.dumps(self.plan))
        with patch.object(release,'DEFAULT_HASHES',self.hashes):
            return release.load_plan(self.path)

    def test_offline_valid_plan_and_stable_digest(self):
        with patch.object(release, 'urlopen', side_effect=AssertionError('network forbidden')):
            plan, digest, base = self.load()
            self.assertEqual(digest, release.digest(release.canonical(plan)))
            self.assertEqual(base, self.base.resolve())

    def test_reject_artifact_mutation(self):
        (self.base/release.NAMES['wallet']).write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError,'hash differs'): self.load()

    def test_reject_unpinned_or_stale_release_and_legacy_plan_fields(self):
        self.path.write_text(json.dumps(self.plan))
        with patch.object(release,'DEFAULT_REVISION',None), patch.object(release,'DEFAULT_HASHES',self.hashes):
            with self.assertRaisesRegex(ValueError,'re-pin'): release.load_plan(self.path)
        for legacy, value in (('codegen_revision','00'*20),('policy_source_digest','00'*32),('policy_instance','01'*32),('payment_stroops',10000)):
            self.plan[legacy]=value
            with self.subTest(field=legacy),self.assertRaisesRegex(ValueError,'schema 2'): self.load()
            del self.plan[legacy]
        self.plan['schema']=1
        with self.assertRaisesRegex(ValueError,'schema 2'): self.load()

    def test_reject_legacy_or_partial_param_names(self):
        plan=copy.deepcopy(self.plan);plan['params']['per_transfer']=1
        with self.assertRaisesRegex(ValueError,'canonical rule'): release.smoke_params(plan)
        plan=copy.deepcopy(self.plan);del plan['params']['call_limit']
        with self.assertRaisesRegex(ValueError,'canonical rule'): release.smoke_params(plan)

    def test_deploy_wallet_prepare_binds_the_common_tier_and_smoke_source(self):
        # The release builds the owner packet with the Common tier and the smoke policy source;
        # without them the packet check refuses the stage before any CLI call.
        class Built(Exception):
            pass
        calls=[]
        def cli(args,input_data=None):
            calls.append(args)
            raise Built
        with patch.object(release.wa,'fetch',return_value={}),patch.object(release.wa,'owner_only'),patch.object(release.wa,'admin'),patch.object(release,'require_settled'),patch.object(release.ca,'cli_run',side_effect=cli):
            with self.assertRaises(Built):
                release.prepare(self.plan,self.base,'deploy-wallet')
        self.assertEqual(calls[0][:2],['contract','deploy'])
        config=json.loads(calls[0][calls[0].index('--config')+1])
        self.assertEqual(config['rules'],release.RULES)

    def test_reject_fee_aggregate(self):
        self.plan['total_fee_cap_stroops']=100
        with self.assertRaisesRegex(ValueError,'aggregate'): self.load()

    def test_reject_funding_above_the_lifetime_spending_limit_param(self):
        self.plan['fund_stroops']=20020001
        with self.assertRaisesRegex(ValueError,'inconsistent'): self.load()
        self.plan['fund_stroops']=20000
        self.plan['params']['lifetime_spending_limit']=19999
        with self.assertRaisesRegex(ValueError,'inconsistent'): self.load()

    def test_reject_network_and_signer_overlap(self):
        self.plan['network_passphrase']=Network.TESTNET_NETWORK_PASSPHRASE
        with self.assertRaisesRegex(ValueError,'passphrase'): self.load()
        self.plan['network_passphrase']=Network.PUBLIC_NETWORK_PASSPHRASE
        self.plan['admin_members'][0]=self.plan['owner']
        with self.assertRaisesRegex(ValueError,'differ'): self.load()

    def packet(self):
        tx = TransactionBuilder(Account(self.plan['owner'],1),Network.PUBLIC_NETWORK_PASSPHRASE,100).add_time_bounds(0,2000000000).append_invoke_contract_function_op(self.plan['asset'],'balance',[scval.to_address(self.plan['recipient'])]).build()
        return dict(network='mainnet',plan_digest=release.digest(release.canonical(self.plan)),unsigned_xdr=tx.to_xdr(),transaction_hash=tx.hash_hex(),stage='fund')

    def test_uncertain_settlement_never_becomes_failure(self):
        for status in ('NOT_FOUND','PENDING','UNKNOWN'):
            with patch.object(release,'rpc',return_value=dict(status=status)):
                self.assertEqual(release.settle(self.plan,self.packet())['status'],'unresolved')

    def test_settlement_rejects_changed_plan(self):
        packet=self.packet();packet['plan_digest']='00'*32
        with self.assertRaisesRegex(ValueError,'another plan'):release.settle(self.plan,packet)

    def test_output_cannot_replace_original(self):
        path=self.base/'packet.json';release.write_new(path,{'hash':'original'})
        with self.assertRaises(FileExistsError):release.write_new(path,{'hash':'replacement'})
        self.assertEqual(json.loads(path.read_text()),{'hash':'original'})


    def test_funding_settlement_checks_exact_principal_and_fee(self):
        packet=self.packet()
        packet['expected_effects']=dict(fund_wallet=self.plan['asset'],wallet_balance=0,amount=20000)
        response=dict(status='SUCCESS',envelopeXdr=packet['unsigned_xdr'],resultXdr=xdr.TransactionResult(xdr.Int64(100),xdr.TransactionResultResult(xdr.TransactionResultCode.txSUCCESS,results=[]),xdr.TransactionResultExt(0)).to_xdr())
        with patch.object(release,'rpc',return_value=response),patch.object(release,'balance',return_value=20000):
            self.assertEqual(release.settle(self.plan,packet)['fee_charged_stroops'],100)
        with patch.object(release,'rpc',return_value=response),patch.object(release,'balance',return_value=20001):
            with self.assertRaisesRegex(ValueError,'funding balance'):release.settle(self.plan,packet)
        response['resultXdr']=xdr.TransactionResult(xdr.Int64(101),xdr.TransactionResultResult(xdr.TransactionResultCode.txSUCCESS,results=[]),xdr.TransactionResultExt(0)).to_xdr()
        with patch.object(release,'rpc',return_value=response):
            with self.assertRaisesRegex(ValueError,'Charged fee'):release.settle(self.plan,packet)

    def test_cli_uses_explicit_rpc_and_passphrase(self):
        with patch.object(release, '_ORIGINAL_CLI_RUN', return_value='ok') as run:
            self.assertEqual(release.network_cli(['contract','info','hash','--network','mainnet','--id','PUBLIC']), 'ok')
        command = run.call_args.args[0]
        self.assertNotIn('--network', command)
        self.assertIn(release.RPC['mainnet'], command)
        self.assertIn(Network.PUBLIC_NETWORK_PASSPHRASE, command)

    def test_transaction_write_rpc_is_never_admitted(self):
        with self.assertRaisesRegex(ValueError,'Only read'): release.rpc('mainnet','sendTransaction',{})

    def test_common_config_selects_all_smoke_rules_and_their_params(self):
        config=release.wallet_config(self.plan)
        self.assertEqual(config['rules'],release.RULES)
        self.assertEqual(config['server'],self.plan['server'])
        self.assertEqual(set(config['params']),set(release.RULES))
        self.assertEqual(config['params']['payment_limit'],10000)
        self.assertNotIn('daily_spending_limit',config['params'])
        self.assertNotIn('tokens',config['params'])
        # The wallet stores the SHA-256 of the whole smoke source and the plan's gas cap.
        self.assertEqual(config['source_hash'],hashlib.sha256(release.SMOKE_SOURCE).hexdigest())
        self.assertEqual(config['gas_cap'],1000000)
        self.assertEqual(release.SMOKE_SOURCE.decode().count('(ctx, &ctx.params[allowit::'),len(release.RULES))
        cli=json.loads(release.ca.serialize({'config':config})[1])
        self.assertEqual(cli['params']['destinations'],{'List':[{'Addr':self.plan['recipient']}]})
        self.assertEqual(cli['params']['lifetime_spending_limit'],{'Int':'20020000'})
        self.assertEqual(cli['agent'],StrKey.decode_ed25519_public_key(self.plan['agent']).hex())

    def test_wallet_state_accepts_a_real_encoded_state_and_rejects_other_rules(self):
        wallet=StrKey.encode_contract(bytes([21])*32)
        expected=release.wallet_config(self.plan)
        def value(item):
            # One AllowitValue: a unit enum variant with its single field, as a two-element vector.
            if isinstance(item,list): return scval.to_vec([scval.to_symbol('List'),scval.to_vec([value(i) for i in item])])
            if isinstance(item,bool): return scval.to_vec([scval.to_symbol('Bool'),scval.to_bool(item)])
            if isinstance(item,str): return scval.to_vec([scval.to_symbol('Addr'),scval.to_address(item)])
            return scval.to_vec([scval.to_symbol('Int'),scval.to_int128(item)])
        def state(rules,paused=False):
            params=scval.to_struct({k:value(v) for k,v in expected['params'].items()})
            figures=scval.to_struct(dict(calls=scval.to_uint64(0),spent=scval.to_int128(0),unpriced=scval.to_bool(False),day_spent=scval.to_int128(0),
                day_total=scval.to_int128(0),day_unpriced=scval.to_bool(False),day_ends=scval.to_uint32(0)))
            raw=lambda role: scval.to_bytes(StrKey.decode_ed25519_public_key(self.plan[role]))
            return scval.to_struct(dict(contract_version=scval.to_uint32(release.ca.WALLET_CONTRACT_VERSION),
                owner=scval.to_address(self.plan['owner']),agent=raw('agent'),server=raw('server'),asset=scval.to_address(self.plan['asset']),
                deployment_version=scval.to_uint32(0),paused=scval.to_bool(paused),source_hash=scval.to_bytes(bytes.fromhex(expected['source_hash'])),
                gas_cap=scval.to_int128(expected['gas_cap']),rules=scval.to_vec([scval.to_vec([scval.to_symbol(r)]) for r in rules]),
                params=params,kept=scval.to_uint32(11),figures=figures))
        def run(rules,paused=False):
            def rpc(network,method,params=None):
                self.assertEqual(method,'simulateTransaction')
                call=TransactionEnvelope.from_xdr(params['transaction'],Network.PUBLIC_NETWORK_PASSPHRASE).transaction.operations[0].host_function.invoke_contract
                self.assertEqual((Address.from_xdr_sc_address(call.contract_address).address,call.function_name.sc_symbol.decode()),(wallet,'state'))
                return dict(results=[dict(xdr=state(rules,paused).to_xdr())])
            def cli(args,input_data=None):
                self.assertEqual(args[:3],['contract','info','hash'])
                return self.hashes['wallet']+'\n'
            # Only RPC, account and CLI reads are replaced; decoding runs on the real encoded values.
            with patch.object(release,'rpc',side_effect=rpc),patch.object(release.wa,'fetch',return_value={'sequence':'1'}),patch.object(release.ca,'cli_run',side_effect=cli):
                return release.wallet_state(self.plan,wallet)
        decoded=run(release.RULES)
        self.assertEqual(decoded['rules'],[[r] for r in release.RULES])
        self.assertEqual(release.plain_params(decoded['params']),expected['params'])
        self.assertEqual(release.usage(decoded),(0,0))
        for rules in (release.RULES[::-1],release.RULES[:-1],release.RULES+['tokens']):
            with self.assertRaisesRegex(ValueError,'params differ'): run(rules)
        with self.assertRaisesRegex(ValueError,'paused'): run(release.RULES,paused=True)


if __name__=='__main__': unittest.main()
