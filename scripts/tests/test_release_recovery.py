"""Run the release driver against native XDR and an offline public-service boundary."""
import copy
from datetime import datetime, timezone
import json
import os
import shutil
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import Mock, patch

# This switch also runs these regressions against the frozen pre-fix implementation.
sys.path.insert(0, os.environ.get("ALLOWIT_RELEASE_SCRIPTS", str(Path(__file__).resolve().parents[1])))
import testnet_release as r
from test_testnet_release import constructor, ledger, make_bundle, wasm, history
from stellar_sdk import Account, Address, Keypair, TransactionBuilder, TransactionEnvelope, scval, xdr


class ReleaseRecovery(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.dict(os.environ, {'GITHUB_RUN_ID':'100', 'GITHUB_RUN_ATTEMPT':'1', 'STELLAR_TESTNET_BOOTSTRAP_ATTEMPT':'10:1'}))
        self.temp = self.enterContext(tempfile.TemporaryDirectory())
        self.root = Path(self.temp)
        self.bundle = self.root / "bundle"
        self.bundle.mkdir()
        self.manifest = make_bundle(self.bundle)
        self.owner, self.agent, self.server = (Keypair.random() for _ in range(3))
        self.anchor, self.recent = ledger(128), ledger(1000)
        self.codes = {self.manifest['artifacts'][k]['sha256']: wasm() for k in r.CONTRACTS}
        self.wallets, self.states = {}, {}
        for kind in r.KINDS:
            config = r.config_for(self.manifest, kind, self.owner.public_key, self.agent.public_key, self.server.public_key)
            salt = bytes.fromhex(r.digest(r.canonical(['allowit_testnet_release_salt_v1', self.manifest['tag'], config])))
            address = r.contract_id(self.owner.public_key, salt)
            self.wallets[address] = self.manifest['artifacts'][kind]['sha256']
            self.states[address] = {**config, 'params': r.ca.params(config['params'], kind), 'contract_version': 4}
        self.rpc = Mock()
        self.rpc.get_network.return_value.passphrase = r.PASSPHRASE
        self.rpc.get_latest_ledger.return_value.sequence = 1000
        self.rpc.get_ledgers.side_effect = self.rpc_ledgers
        self.rpc.get_ledger_entries.side_effect = self.entries
        self.rpc.get_transaction.return_value = NS(status=r.GetTransactionStatus.NOT_FOUND)
        self.mutations, self.queries, self.bad_variant, self.send_error = [], [], False, True
        self.enterContext(patch.object(r, 'SorobanServer', return_value=self.rpc))
        self.enterContext(patch.object(r, 'public_json_url', side_effect=self.history))
        self.enterContext(patch.object(r.ca, 'cli_run', side_effect=self.cli))
        self.enterContext(patch.object(r.ca, 'prepare_xdr', side_effect=lambda raw, *args, **kwargs: raw))
        self.remote = self.enterContext(patch.object(r.subprocess, 'check_output', return_value=self.remote_tag()))
        # git(root, rev-parse HEAD) remains a real local call, distinct from the tag query.
        self.enterContext(patch.object(r, 'git', return_value='d' * 40))
        self.sign = self.enterContext(patch.object(self.owner, 'sign', wraps=self.owner.sign))
        self.fixture_histories = set()

    def remote_tag(self):
        ref = 'refs/tags/' + self.manifest['tag']
        return self.manifest['tag_object'] + '\t' + ref + '\n' + self.manifest['revision'] + '\t' + ref + '^{}\n'

    def history(self, path):
        self.queries.append(path)
        return {'/': {'network_passphrase': r.PASSPHRASE, 'history_elder_ledger': 128, 'history_latest_ledger': 1000},
            '/ledgers/128': self.anchor, '/ledgers/1000': self.recent}[path]

    def rpc_ledgers(self, **kwargs):
        item = self.recent
        native = xdr.LedgerHeaderHistoryEntry(xdr.Hash(bytes.fromhex(item['hash'])),
            xdr.LedgerHeader.from_xdr(item['header_xdr']), xdr.LedgerHeaderHistoryEntryExt(0))
        return NS(ledgers=[NS(sequence=item['sequence'], hash=item['hash'], header_xdr=native.to_xdr())])

    def entries(self, keys):
        key = keys[0]
        if key.type == xdr.LedgerEntryType.CONTRACT_CODE:
            module = key.contract_code.hash.hash.hex()
            data = None if module not in self.codes else xdr.LedgerEntryData(key.type,
                contract_code=xdr.ContractCodeEntry(xdr.ContractCodeEntryExt(0), xdr.Hash(bytes.fromhex(module)), self.codes[module]))
        elif key.type == xdr.LedgerEntryType.CONTRACT_DATA:
            address = Address.from_xdr_sc_address(key.contract_data.contract).address
            module = self.wallets.get(address)
            val = None if module is None else xdr.SCVal(xdr.SCValType.SCV_CONTRACT_INSTANCE,
                instance=xdr.SCContractInstance(xdr.ContractExecutable(xdr.ContractExecutableType.CONTRACT_EXECUTABLE_WASM,
                    wasm_hash=xdr.Hash(bytes.fromhex(module))), None))
            data = None if val is None else xdr.LedgerEntryData(key.type, contract_data=xdr.ContractDataEntry(
                xdr.ExtensionPoint(0), key.contract_data.contract, key.contract_data.key, key.contract_data.durability, val))
        else:
            data = xdr.LedgerEntryData(key.type, account=xdr.AccountEntry(self.owner.xdr_account_id(), xdr.Int64(10**10),
                xdr.SequenceNumber(xdr.Int64(1)), xdr.Uint32(0), None, xdr.Uint32(0), xdr.String32(b''),
                xdr.Thresholds(b'\x01\x00\x00\x00'), [], xdr.AccountEntryExt(0)))
        return NS(latest_ledger=1000, entries=[] if data is None else [NS(key=key.to_xdr(), xdr=data.to_xdr(), live_until_ledger_seq=5000)])

    def cli(self, args, input_data=None):
        if 'state' in args:
            return json.dumps(self.states[args[args.index('--id') + 1]])
        if 'upload' in args:
            self.mutations.append('build-upload')
            return TransactionBuilder(Account(self.owner.public_key, 1), r.PASSPHRASE, base_fee=100).set_timeout(300).append_upload_contract_wasm_op(wasm()).build().to_xdr()
        if 'deploy' in args:
            kind = next(k for k, name in r.CONTRACTS.items() if str(self.bundle / name) in args)
            config = r.config_for(self.manifest, kind, self.owner.public_key, self.agent.public_key, self.server.public_key)
            create = constructor(config, self.manifest['artifacts'][kind]['sha256'], bytes.fromhex(args[args.index('--salt') + 1]))
            if self.bad_variant:
                fields = scval.from_struct(create.constructor_args[0])
                params = scval.from_struct(fields['params'])
                params['destinations'] = scval.to_enum('List', scval.to_vec([scval.to_enum('Str', scval.to_string(self.agent.public_key))]))
                fields['params'] = scval.to_struct(params)
                create.constructor_args[0] = scval.to_struct(fields)
            tx = TransactionBuilder(Account(self.owner.public_key, 1), r.PASSPHRASE, base_fee=100).set_timeout(300).append_create_contract_op(
                wasm_id=self.manifest['artifacts'][kind]['sha256'], address=self.owner.public_key, salt=create.contract_id_preimage.from_address.salt.uint256,
                constructor_args=create.constructor_args).build()
            return tx.to_xdr()
        if 'send' in args:
            self.mutations.append('send')
            if self.send_error:
                raise subprocess.CalledProcessError(1, ['stellar', 'tx', 'send'])
            envelope = TransactionEnvelope.from_xdr(input_data, r.PASSPHRASE)
            host = envelope.transaction.operations[0].host_function
            if host.type == xdr.HostFunctionType.HOST_FUNCTION_TYPE_UPLOAD_CONTRACT_WASM:
                self.codes[r.digest(host.wasm)] = host.wasm
            else:
                create = host.create_contract_v2
                wallet = Address.from_xdr_sc_address(r.ca.deployment_address(create, 'testnet')).address
                self.wallets[wallet] = create.executable.wasm_hash.hash.hex()
            self.rpc.get_transaction.return_value = NS(status=r.GetTransactionStatus.SUCCESS, envelope_xdr=input_data, ledger=1000)
            return ''
        raise AssertionError('Unexpected native command: ' + repr(args))

    def driver(self, previous=None, name='run'):
        if previous is None:
            previous = self.root / name / 'history'
            self.fixture_histories.add(previous)
            # Existing native fixture worlds have an explicit authenticated deployment.
            # Fresh worlds have no wallet entries; production never infers their history.
            if self.wallets:
                wallets={}
                for kind in r.KINDS:
                    config=r.config_for(self.manifest,kind,self.owner.public_key,self.agent.public_key,self.server.public_key)
                    salt=bytes.fromhex(r.digest(r.canonical(['allowit_testnet_release_salt_v1',self.manifest['tag'],config])))
                    wallets[kind]={'contract':r.contract_id(self.owner.public_key,salt),'config':config}
                r.write(previous/'testnet-deployment.json',{'source':self.manifest,'owner':self.owner.public_key,
                    'agent':self.agent.public_key,'server':self.server.public_key,'network':'stellar:testnet',
                    'network_identity':r.network_identity(self.rpc),'status':'VERIFIED','wallets':wallets,
                    'transactions':[],'bootstrap_attempt':'10:1','workflow_attempt':'10:1'})
        if previous in self.fixture_histories:
            history(previous, self.manifest, self.owner.public_key, self.agent.public_key, self.server.public_key)
        return r.Deployment(self.bundle, self.root / name / 'testnet-deployment.json', self.root / name / 'private', self.owner,
            self.agent.public_key, self.server.public_key, previous)

    def checkpoint(self, driver, records=None, status='VERIFIED'):
        driver.preflight()  # Public checkpoints are saved after preflight in the real driver.
        prior = copy.deepcopy(driver.public)
        prior['workflow_attempt'] = '10:1'
        prior.update(status=status, transactions=records or [])
        path = self.root / 'previous'
        r.write(path / 'run-1/testnet-deployment.json', prior)
        self.fixture_histories.add(path)
        return path

    def test_wrong_native_variant_stops_whole_driver_before_signing(self):
        self.wallets.clear()
        self.bad_variant = True
        with self.assertRaises(ValueError):
            self.driver().run()
        self.sign.assert_not_called()
        self.assertEqual(self.mutations, [])

    def test_all_existing_wallets_preflight_before_any_upload_or_funding(self):
        self.codes.clear()
        last = list(self.states)[-1]
        self.states[last]['server'] = self.agent.public_key
        with self.assertRaises(ValueError):
            self.driver().run()
        self.assertEqual(self.mutations, [])
        self.sign.assert_not_called()

    def test_verified_missing_code_or_wallet_refuses_recreation(self):
        previous = self.checkpoint(self.driver())
        for missing in ('code', 'wallet'):
            with self.subTest(missing=missing):
                codes, wallets = self.codes.copy(), self.wallets.copy()
                if missing == 'code': self.codes.clear()
                else: self.wallets.clear()
                with self.assertRaises(ValueError): self.driver(previous, missing).run()
                self.assertEqual(self.mutations, [])
                self.codes, self.wallets = codes, wallets

    def test_native_header_freshness_and_endpoint_lag_block_driver(self):
        original = copy.deepcopy(self.recent)
        for close, lag in ((1, 1000), (int(datetime.now(timezone.utc).timestamp()) + 3600, 1000), (None, 1100)):
            with self.subTest(close=close, rpc_tip=lag):
                self.recent = copy.deepcopy(original)
                self.rpc.get_latest_ledger.return_value.sequence = lag
                if close is not None:
                    header = xdr.LedgerHeader.from_xdr(self.recent['header_xdr'])
                    header.scp_value.close_time = xdr.TimePoint(xdr.Uint64(close))
                    self.recent.update(header_xdr=header.to_xdr(), hash=r.digest(header.to_xdr_bytes()),
                        closed_at=datetime.fromtimestamp(close, timezone.utc).isoformat())
                with self.assertRaises(ValueError): self.driver(name=str(lag) + str(close)).run()
                self.assertEqual(self.mutations, [])
                self.sign.assert_not_called()

    def test_inconsistent_metadata_cannot_skip_unresolved_transaction(self):
        driver = self.driver()
        record = {'stage': 'upload-common', 'transaction_hash': 'ab' * 32, 'expires_at': 4102444800, 'status': 'unknown'}
        previous = self.checkpoint(driver, [record], 'IN_PROGRESS')
        path = previous / 'run-1/testnet-deployment.json'
        prior = json.loads(path.read_text())
        prior['network_identity']['genesis_available'] = True
        r.write(path, prior)
        with self.assertRaises(ValueError): self.driver(previous, 'retry').run()
        self.assertEqual(self.mutations, [])

    def test_every_recorded_anchor_must_be_available_before_skipping_pending(self):
        previous = self.checkpoint(self.driver(), [{'stage': 'upload-common', 'transaction_hash': 'ab' * 32,
            'expires_at': 4102444800, 'status': 'unknown'}], 'IN_PROGRESS')
        prior = json.loads((previous / 'run-1/testnet-deployment.json').read_text())
        old = copy.deepcopy(prior)
        old['network_identity']['generation']['hash'] = 'ff' * 32
        old['network_identity']['generation'].update(ledger=64, source=r.HORIZON + '/ledgers/64')
        r.write(previous / 'run-0/testnet-deployment.json', old)
        original = self.history
        def history(path):
            if path == '/ledgers/64':
                self.queries.append(path)
                raise r.HTTPError(r.HORIZON + path, 404, 'unavailable', None, None)
            return original(path)
        with patch.object(r, 'public_json_url', side_effect=history):
            with self.assertRaises(ValueError): self.driver(previous, 'retry').run()
        self.assertIn('/ledgers/64', self.queries)
        self.assertEqual(self.mutations, [])

    def test_first_publication_failure_retains_and_deduplicates_settled_receipts(self):
        tx = TransactionBuilder(Account(self.owner.public_key, 1), r.PASSPHRASE, base_fee=100).set_timeout(300).append_upload_contract_wasm_op(wasm()).build()
        tx.sign(self.owner)
        self.sign.reset_mock()
        record = {'stage': 'upload-common', 'transaction_hash': tx.hash_hex(), 'expires_at': tx.transaction.preconditions.time_bounds.max_time,
            'status': 'SUCCESS', 'ledger': 991}
        self.rpc.get_transaction.return_value = NS(status=r.GetTransactionStatus.SUCCESS, envelope_xdr=tx.to_xdr(), ledger=991)
        previous = self.checkpoint(self.driver(), [record])
        result = self.driver(previous, 'recovery').run()
        self.assertEqual(result['transactions'], [record])
        r.write(self.bundle / r.deployment_filename(self.manifest, result['network_identity']), result)
        with patch.object(r.subprocess, 'run', side_effect=subprocess.CalledProcessError(1, ['gh', 'release', 'create'])):
            with self.assertRaises(subprocess.CalledProcessError): r.publish(self.bundle, previous)
        r.write(previous / 'run-2/testnet-deployment.json', result)
        # A fresh workflow downloads authenticated public Actions artifacts. It does not
        # inherit a runner filesystem or private packets from the failed publication.
        artifacts = [{'name': 'stellar-testnet-checkpoint-' + self.manifest['tag'] + '-' + str(n) + '-1',
            'id': n, 'expired': False, 'workflow_run': {'id': n, 'head_sha': 'd' * 40}} for n in (10, 100)]
        run = lambda n: {'id':n, 'run_attempt':1, 'head_sha':'d'*40, 'path':'.github/workflows/testnet-release.yml',
            'event':'workflow_run', 'head_repository':{'full_name':'allowit-hq/allowit-contracts-stellar'}}
        def api(path, missing=False):
            if '/releases?' in path: return []
            if '/releases/tags/' in path: return None
            if '/actions/artifacts?' in path: return {'artifacts': artifacts}
            if '/actions/workflows/' in path: return {'workflow_runs':[run(n) for n in (10,100,200)]}
            if '/jobs?' in path: return {'jobs':[{'name':'testnet','status':'completed','conclusion':'success'}]}
            return run(int(path.rsplit('/',1)[-1]))
        def download(args, **kwargs):
            if args[:3] == ['git', 'merge-base', '--is-ancestor']:
                self.assertEqual(args[3:], ['d' * 40, 'refs/release/main'])
                return NS(returncode=0)
            self.assertEqual(args[:3], ['gh', 'run', 'download'])
            target = Path(args[args.index('--dir') + 1])
            origin = 'run-1' if args[3]=='10' else 'run-2'
            r.write(target / 'testnet-deployment.json', json.loads((previous / origin / 'testnet-deployment.json').read_text()))
            return NS(returncode=0)
        fetched = self.root / 'fresh-workflow-checkpoints'
        os.environ['GITHUB_RUN_ID'] = '200'
        with patch.object(r, 'gh_json', side_effect=api), patch.object(r.subprocess, 'run', side_effect=download):
            r.fetch_previous(self.manifest, fetched)
        result = self.driver(fetched, 'second-recovery').run()
        self.assertEqual(result['transactions'], [record])
        self.assertEqual(self.mutations, [])
        self.sign.assert_not_called()

    def test_expiry_uses_confirmed_ledger_time_and_retains_unknown_history(self):
        driver = self.driver()
        expires = xdr.LedgerHeader.from_xdr(self.recent['header_xdr']).scp_value.close_time.time_point.uint64 + 1
        record = {'stage': 'upload-common', 'transaction_hash': 'ab' * 32, 'expires_at': expires, 'status': 'unknown'}
        previous = self.checkpoint(driver, [record], 'IN_PROGRESS')
        with self.assertRaises(ValueError): self.driver(previous, 'pending').run()
        self.assertEqual(self.mutations, [])
        # A trusted native close time beyond max_time, rather than runner time, proves expiry.
        self.recent = ledger(1000)
        header = xdr.LedgerHeader.from_xdr(self.recent['header_xdr'])
        header.scp_value.close_time = xdr.TimePoint(xdr.Uint64(expires + 1))
        self.recent.update(header_xdr=header.to_xdr(), hash=r.digest(header.to_xdr_bytes()),
            closed_at=datetime.fromtimestamp(expires + 1, timezone.utc).isoformat())
        result = self.driver(previous, 'expired').run()
        self.assertEqual(result['transactions'][0]['transaction_hash'], record['transaction_hash'])
        self.assertEqual(result['transactions'][0]['status'], 'EXPIRED_UNCONFIRMED')

    def test_native_first_deployment_and_healthy_retry_preserve_exact_receipts(self):
        self.codes.clear()
        self.wallets.clear()
        self.send_error = False
        result = self.driver().run()
        self.assertEqual(result['status'], 'VERIFIED')
        self.assertEqual(len(result['wallets']), 3)
        self.assertEqual(len(result['transactions']), 4)  # The fixture uses one content-addressed Wasm.
        self.assertTrue(all(item['status'] == 'SUCCESS' for item in result['transactions']))
        # Public checkpoints authenticate settled records after the RPC retention window.
        self.rpc.get_transaction.return_value = NS(status=r.GetTransactionStatus.NOT_FOUND)
        previous = self.checkpoint(self.driver(name='snapshot'), result['transactions'], status='IN_PROGRESS')
        self.mutations.clear()
        self.sign.reset_mock()
        retry = self.driver(previous, 'retry').run()
        self.assertEqual(retry['transactions'], result['transactions'])
        self.assertEqual(self.mutations, [])
        self.sign.assert_not_called()

    def test_only_different_retained_native_hash_can_skip_old_pending(self):
        previous = self.checkpoint(self.driver(), [{'stage': 'upload-common', 'transaction_hash': 'ab' * 32,
            'expires_at': 4102444800, 'status': 'unknown'}], status='IN_PROGRESS')
        path = previous / 'run-1/testnet-deployment.json'
        prior = json.loads(path.read_text())
        prior['network_identity']['generation']['hash'] = 'ff' * 32
        r.write(path, prior)
        self.wallets.clear(); self.send_error=False
        result = self.driver(previous, 'new-generation').run()
        self.assertEqual(result['network_identity']['generation']['hash'], self.anchor['hash'])
        self.assertEqual(len(result['transactions']),3)
        self.assertTrue(all(item.args != ('ab'*32,) for item in self.rpc.get_transaction.call_args_list))

    def test_tag_is_rechecked_immediately_before_signing(self):
        self.wallets.clear()
        self.remote.side_effect = [self.remote_tag(), '']
        with self.assertRaisesRegex(ValueError, 'Canonical release tag'):
            self.driver().run()
        self.sign.assert_not_called()
        self.assertEqual(self.mutations, [])

    def test_tag_move_during_environment_wait_stops_before_secret_or_driver(self):
        r.write(self.bundle / 'release-identity.json', {k:self.manifest[k] for k in r.IDENTITY_KEYS})
        self.remote.return_value = 'e' * 40 + '\trefs/tags/' + self.manifest['tag'] + '\n'
        args = ['release', 'deploy', '--bundle', str(self.bundle), '--identity', str(self.bundle / 'release-identity.json'),
            '--output', str(self.root / 'out.json'), '--private', str(self.root / 'packets'), '--owner', self.owner.public_key,
            '--agent', self.agent.public_key, '--server', self.server.public_key, '--previous', str(self.root / 'previous')]
        with patch.object(sys, 'argv', args), patch.dict(os.environ, {'STELLAR_TESTNET_OWNER_SECRET': self.owner.secret}), patch.object(r, 'Deployment') as driver:
            driver.return_value.run.side_effect = ValueError('Deployment reached after moved tag')
            with self.assertRaises(ValueError): r.main()
            driver.assert_not_called()
            self.assertTrue('STELLAR_TESTNET_OWNER_SECRET' not in os.environ)

    def test_deleted_or_never_uploaded_checkpoint_is_detected_from_signing_runs(self):
        self.codes.clear(); self.wallets.clear(); self.send_error = False
        first = self.driver().run()
        self.assertEqual(len(first['transactions']), 4)
        self.mutations.clear(); self.sign.reset_mock()
        os.environ['GITHUB_RUN_ID'] = '200'
        run = lambda n: {'id':n, 'run_attempt':1, 'head_sha':'d'*40, 'path':'.github/workflows/testnet-release.yml',
            'event':'workflow_run', 'head_repository':{'full_name':'allowit-hq/allowit-contracts-stellar'}}
        def api(path, missing=False):
            if '/releases?' in path: return []
            if '/releases/tags/' in path: return None
            if '/actions/artifacts?' in path: return {'artifacts':[]}  # No expired object survives deletion.
            if '/actions/workflows/' in path: return {'workflow_runs':[run(100),run(200)]}
            if '/jobs?' in path: return {'jobs':[{'name':'testnet','status':'completed','conclusion':'failure'}]}
            return run(int(path.rsplit('/',1)[-1]))
        with patch.object(r, 'gh_json', side_effect=api), patch.object(r.subprocess, 'run', return_value=NS(returncode=0)):
            with self.assertRaisesRegex(ValueError, 'no authenticated checkpoint'):
                r.fetch_previous(self.manifest, self.root/'missing-history')
        self.assertEqual(self.mutations, []); self.sign.assert_not_called()

    def test_bootstrap_cannot_adopt_existing_wallets_or_authorize_a_different_attempt(self):
        previous=self.root/'bootstrap'
        history(previous,self.manifest,self.owner.public_key,self.agent.public_key,self.server.public_key,first=True)
        with self.assertRaisesRegex(ValueError,'one-time protected bootstrap'):
            self.driver(previous).run()
        proof=json.loads((previous/'attempt-history.json').read_text()); proof['bootstrap_attempt']='100:1'
        r.write(previous/'attempt-history.json',proof)
        os.environ['STELLAR_TESTNET_BOOTSTRAP_ATTEMPT']='100:1'
        with self.assertRaisesRegex(ValueError,'adopt an existing wallet'):
            self.driver(previous).run()
        self.assertEqual(self.mutations,[]); self.sign.assert_not_called()

    def test_immutable_plan_cannot_recreate_code_or_wallet_that_disappears(self):
        previous = self.checkpoint(self.driver())
        for resource in ('code','wallet'):
            with self.subTest(resource=resource):
                codes, wallets = self.codes.copy(), self.wallets.copy()
                d = self.driver(previous, resource)
                original = d.ensure_account
                def advance(*args):
                    original(*args)
                    if resource == 'code': self.codes.clear()
                    else: self.wallets.pop(next(iter(self.wallets)))
                d.ensure_account = advance
                with self.assertRaisesRegex(ValueError, 'immutable preflight plan'):
                    d.run()
                self.assertEqual(self.mutations, []); self.sign.assert_not_called()
                self.codes, self.wallets = codes, wallets

    def test_creation_eligibility_is_rechecked_after_native_preparation(self):
        self.wallets.clear()
        def concurrent_creation(raw,*args,**kwargs):
            create=TransactionEnvelope.from_xdr(raw,r.PASSPHRASE).transaction.operations[0].host_function.create_contract_v2
            wallet=Address.from_xdr_sc_address(r.ca.deployment_address(create,'testnet')).address
            self.wallets[wallet]=create.executable.wasm_hash.hash.hex()
            return raw
        with patch.object(r.ca,'prepare_xdr',side_effect=concurrent_creation):
            with self.assertRaisesRegex(ValueError,'no longer eligible'): self.driver().run()
        self.assertEqual(self.mutations,[]); self.sign.assert_not_called()

    def test_real_public_children_never_inherit_owner_marker_on_success_or_failure(self):
        popen = subprocess.Popen
        for failure in (False, True):
            def check_env(kwargs):
                child = popen([sys.executable,'-c','import os,sys;sys.exit(47 if "STELLAR_TESTNET_OWNER_SECRET" in os.environ else 0)'], env=kwargs.get('env'))
                self.assertEqual(child.wait(), 0)
            def git_child(args, **kwargs):
                check_env(kwargs)
                if failure: raise subprocess.CalledProcessError(1, args)
                return self.remote_tag()
            def gh_child(args, **kwargs):
                check_env(kwargs)
                return NS(returncode=int(failure),stdout='{}')
            with patch.dict(os.environ, {'STELLAR_TESTNET_OWNER_SECRET':'synthetic-presence-marker'}):
                with patch.object(r.subprocess,'check_output',side_effect=git_child):
                    if failure:
                        with self.assertRaises(subprocess.CalledProcessError): r.check_canonical_tag(self.manifest)
                    else: r.check_canonical_tag(self.manifest)
                with patch.object(r.subprocess,'run',side_effect=gh_child):
                    if failure:
                        with self.assertRaises(ValueError): r.gh_json('public-fixture')
                    else: self.assertEqual(r.gh_json('public-fixture'),{})
                self.assertTrue('STELLAR_TESTNET_OWNER_SECRET' in os.environ)

    def test_published_anchor_covers_deleted_artifacts_and_next_release_without_new_bootstrap(self):
        self.codes.clear(); self.wallets.clear(); self.send_error = False
        first_history = self.root/'first-history'
        history(first_history, self.manifest, self.owner.public_key, self.agent.public_key, self.server.public_key, first=True)
        proof = json.loads((first_history/'attempt-history.json').read_text()); proof['bootstrap_attempt']='100:1'
        r.write(first_history/'attempt-history.json',proof)
        os.environ['STELLAR_TESTNET_BOOTSTRAP_ATTEMPT']='100:1'
        first = self.driver(first_history).run()
        r.write(self.bundle/r.deployment_filename(self.manifest,first['network_identity']),first)
        published = self.root/'immutable-release'; published.mkdir()
        def publish(args, **kwargs):
            self.assertEqual(args[:3],['gh','release','create'])
            for arg in args:
                path=Path(arg)
                if path.is_file() and path.suffix in ('.json','.rs','.wasm'): shutil.copyfile(path,published/path.name)
            return NS(returncode=0)
        with patch.object(r.subprocess,'run',side_effect=publish): r.publish(self.bundle,self.root/'no-prior-release')
        old_manifest=copy.deepcopy(self.manifest)
        name=r.attempt_filename(old_manifest,'100:1')
        self.assertEqual(json.loads((published/name).read_text())['transactions'],first['transactions'])
        self.manifest.update(tag='v0.3.0',revision='f'*40)
        r.write(self.bundle/'source-manifest.json',self.manifest)
        for kind in r.KINDS:
            config=r.config_for(self.manifest,kind,self.owner.public_key,self.agent.public_key,self.server.public_key)
            salt=bytes.fromhex(r.digest(r.canonical(['allowit_testnet_release_salt_v1',self.manifest['tag'],config])))
            self.states[r.contract_id(self.owner.public_key,salt)]={**config,'params':r.ca.params(config['params'],kind),'contract_version':4}
        os.environ['GITHUB_RUN_ID']='200'
        run=lambda n:{'id':n,'run_attempt':1,'head_sha':'d'*40,'path':'.github/workflows/testnet-release.yml',
            'event':'workflow_run','head_repository':{'full_name':'allowit-hq/allowit-contracts-stellar'}}
        def api(path,missing=False):
            if '/releases?' in path: return [{'tag_name':old_manifest['tag'],'assets':[{'name':name}]}]
            if '/releases/tags/' in path: return None
            if '/actions/artifacts?' in path: return {'artifacts':[]}
            if '/actions/workflows/' in path: return {'workflow_runs':[run(100),run(200)]}
            self.assertNotIn('/jobs?',path)  # Published coverage replaces expired transient artifacts.
            return run(int(path.split('/actions/runs/')[1].split('/')[0]))
        def download(args,**kwargs):
            if args[:3]==['git','merge-base','--is-ancestor']: return NS(returncode=0)
            self.assertEqual(args[:3],['gh','release','download'])
            target=Path(args[args.index('--dir')+1])
            for at,arg in enumerate(args):
                if arg=='--pattern':
                    for file in published.glob(args[at+1]): shutil.copyfile(file,target/file.name)
            return NS(returncode=0)
        def remote(args,**kwargs):
            manifest=old_manifest if args[-2]=='refs/tags/'+old_manifest['tag'] else self.manifest
            ref='refs/tags/'+manifest['tag']
            return manifest['tag_object']+'\t'+ref+'\n'+manifest['revision']+'\t'+ref+'^{}\n'
        fetched=self.root/'new-release-history'
        with patch.object(r,'gh_json',side_effect=api),patch.object(r.subprocess,'run',side_effect=download),patch.object(r.subprocess,'check_output',side_effect=remote):
            r.fetch_previous(self.manifest,fetched)
        self.mutations.clear(); self.sign.reset_mock()
        with patch.object(r.subprocess,'check_output',side_effect=remote):
            second=self.driver(fetched,'next-release').run()
        self.assertEqual(second['covered_attempts'],['100:1','200:1'])
        self.assertEqual(second['history_anchor']['sha256'],r.digest((published/name).read_bytes()))
        self.assertEqual(len(second['transactions']),3)
        self.assertEqual(os.environ['STELLAR_TESTNET_BOOTSTRAP_ATTEMPT'],'100:1')


if __name__ == '__main__': unittest.main()
