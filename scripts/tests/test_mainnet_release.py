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
        self.plan = dict(schema=1, network='mainnet', network_passphrase=Network.PUBLIC_NETWORK_PASSPHRASE,
            source_revision=release.DEFAULT_REVISION,
            policy_source_digest=release.digest(release.SMOKE_SOURCE), artifact_manifest='manifest.json',
            owner=keys[0], admin=keys[1], agent=keys[2], recipient=keys[3], forbidden_recipient=keys[4], admin_members=keys[5:8], server=keys[8], asset=Asset.native().contract_id(Network.PUBLIC_NETWORK_PASSPHRASE), policy_instance='01'*32,
            params=dict(recipients=[keys[3]], transaction_cap=10000, day_total_cap=20020000, spent_cap=20020000, call_cap=2, expiry=2000000000),
            fund_stroops=20000, payment_stroops=10000, fee_caps_stroops=dict.fromkeys(release.STAGES, 10000000), total_fee_cap_stroops=70000000, artifacts={})
        files = [release.ROOT/n for n in ('Cargo.toml','Cargo.lock','rust-toolchain.toml')]
        files += list((release.ROOT/'crates').rglob('*.rs')) + list((release.ROOT/'crates').rglob('Cargo.toml'))
        files += [release.ROOT/'scripts'/n for n in release.BUILD_SCRIPTS]
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
        self.plan['codegen_revision']='00'*20
        with self.assertRaisesRegex(ValueError,'schema 1'): self.load()
        del self.plan['codegen_revision']
        self.plan['policy_source_digest']='00'*32
        with self.assertRaisesRegex(ValueError,'source differs'): self.load()

    def test_reject_legacy_or_partial_param_names(self):
        for legacy in ('per_transfer','daily_limit','total_limit','max_calls','expires_at'):
            plan=copy.deepcopy(self.plan);plan['params'][legacy]=1
            with self.assertRaisesRegex(ValueError,'canonical rule'): release.smoke_params(plan)
        plan=copy.deepcopy(self.plan);del plan['params']['call_cap']
        with self.assertRaisesRegex(ValueError,'canonical rule'): release.smoke_params(plan)
        plan=copy.deepcopy(self.plan);plan['params']['day_total_cap']=10009999
        with self.assertRaisesRegex(ValueError,'daily capacity'): release.smoke_params(plan)

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

    def test_reject_funding_above_the_spent_cap_param(self):
        self.plan['fund_stroops']=20020001
        with self.assertRaisesRegex(ValueError,'inconsistent'): self.load()
        self.plan['fund_stroops']=20000
        self.plan['params']['spent_cap']=10009999
        with self.assertRaisesRegex(ValueError,'inconsistent'): self.load()

    def test_reject_network_and_signer_overlap(self):
        self.plan['network_passphrase']=Network.TESTNET_NETWORK_PASSPHRASE
        with self.assertRaisesRegex(ValueError,'passphrase'): self.load()
        self.plan['network_passphrase']=Network.PUBLIC_NETWORK_PASSPHRASE
        self.plan['admin_members'][0]=self.plan['owner']
        with self.assertRaisesRegex(ValueError,'differ'): self.load()

    def test_receipt_uses_plain_addresses(self):
        expected = release.expected_receipt(self.plan,self.plan['asset'],dict(nonce=0,deployment_version=0),'ab'*32)
        value = scval.to_struct({k: scval.to_address(v) if k in ('from','to','token') else scval.to_bytes(bytes.fromhex(v)) if k=='operation_id' else scval.to_int128(v) if k=='amount' else scval.to_uint64(v) for k,v in expected.items()})
        self.assertEqual(release.receipt_json(release.decode_receipt(value)),expected)

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


    def test_successful_v4_receipt_and_exact_effects(self):
        packet=self.packet()
        expected=release.expected_receipt(self.plan,self.plan['asset'],dict(nonce=0,deployment_version=0),'ab'*32)
        value=scval.to_struct({k:scval.to_address(v) if k in ('from','to','token') else scval.to_bytes(bytes.fromhex(v)) if k=='operation_id' else scval.to_int128(v) if k=='amount' else scval.to_uint64(v) for k,v in expected.items()})
        packet.update(expected_receipt=expected,expected_effects=dict(wallet=self.plan['asset'],wallet_balance=20000,recipient_balance=50,calls=0,spent_total=0))
        meta=SimpleNamespace(v=4,v4=SimpleNamespace(soroban_meta=SimpleNamespace(return_value=value)))
        response=dict(status='SUCCESS',envelopeXdr=packet['unsigned_xdr'],resultMetaXdr='mock',resultXdr=xdr.TransactionResult(xdr.Int64(100),xdr.TransactionResultResult(xdr.TransactionResultCode.txSUCCESS,results=[]),xdr.TransactionResultExt(0)).to_xdr())
        with patch.object(release,'rpc',return_value=response), patch.object(release.xdr.TransactionMeta,'from_xdr',return_value=meta), patch.object(release,'read_contract',return_value=dict(policy_state=dict(calls=['Int',1],spent=['Int',10010000]))), patch.object(release,'balance',side_effect=[10000,10050]):
            self.assertEqual(release.settle(self.plan,packet)['status'],'success')
        with patch.object(release,'rpc',return_value=response), patch.object(release.xdr.TransactionMeta,'from_xdr',return_value=meta), patch.object(release,'read_contract',return_value=dict(policy_state=dict(calls=['Int',1],spent=['Int',10010000]))), patch.object(release,'balance',side_effect=[9999]):
            with self.assertRaisesRegex(ValueError,'balances or counters'):release.settle(self.plan,packet)

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

    def execution_packet(self):
        wallet=self.plan['asset']
        state=dict(nonce=0,deployment_version=0)
        binding=dict(module_digest=self.hashes['wallet'],entrypoint='execute',argument_schema_digest=release.digest(release.SCHEMA))
        request=release.execution(self.plan,wallet,state,binding,'ab'*32,90)
        tx=TransactionBuilder(Account(self.plan['agent'],1),Network.PUBLIC_NETWORK_PASSPHRASE,100).add_time_bounds(0,int(time.time())+300).append_invoke_contract_function_op(wallet,'execute',[request]).build()
        root=xdr.SorobanAuthorizedInvocation(xdr.SorobanAuthorizedFunction(xdr.SorobanAuthorizedFunctionType.SOROBAN_AUTHORIZED_FUNCTION_TYPE_CONTRACT_FN,contract_fn=tx.transaction.operations[0].host_function.invoke_contract),[])
        source=xdr.SorobanAuthorizationEntry(xdr.SorobanCredentials(xdr.SorobanCredentialsType.SOROBAN_CREDENTIALS_SOURCE_ACCOUNT),copy.deepcopy(root))
        server=xdr.SorobanAuthorizationEntry(xdr.SorobanCredentials(xdr.SorobanCredentialsType.SOROBAN_CREDENTIALS_ADDRESS,address=xdr.SorobanAddressCredentials(Address(self.plan['server']).to_xdr_sc_address(),xdr.Int64(42),xdr.Uint32(150),scval.to_void())),root)
        tx.transaction.operations[0].auth=[source,server]
        packet=dict(stage='execute',network='mainnet',plan_digest=release.digest(release.canonical(self.plan)),signing_ready=False,parent=wallet,wallet=wallet,operation_id='ab'*32,unsigned_xdr=tx.to_xdr(),transaction_hash=tx.hash_hex(),server_authorization_xdr=server.to_xdr(),expected_receipt=release.expected_receipt(self.plan,wallet,state,'ab'*32),expected_effects=dict(wallet=wallet,wallet_balance=20000,recipient_balance=50,calls=0,spent_total=0))
        signed=copy.deepcopy(server)
        credentials=signed.credentials.address
        payload=xdr.HashIDPreimage(xdr.EnvelopeType.ENVELOPE_TYPE_SOROBAN_AUTHORIZATION,soroban_authorization=xdr.HashIDPreimageSorobanAuthorization(xdr.Hash(Network(Network.PUBLIC_NETWORK_PASSPHRASE).network_id()),credentials.nonce,credentials.signature_expiration_ledger,signed.root_invocation))
        key=Keypair.from_raw_ed25519_seed(bytes([9])*32)
        credentials.signature=scval.to_vec([scval.to_struct(dict(public_key=scval.to_bytes(key.raw_public_key()),signature=scval.to_bytes(key.sign(hashlib.sha256(payload.to_xdr_bytes()).digest()))))])
        return packet,signed,state,binding

    def complete(self,packet,signed,state,binding,mutate=None):
        def simulate(args,input_data=None):
            self.assertEqual(args[-2:],['--auth-mode','enforce'])
            tx=TransactionEnvelope.from_xdr(input_data,Network.PUBLIC_NETWORK_PASSPHRASE)
            self.assertEqual(tx.signatures,[])
            tx.transaction.fee+=123
            tx.transaction.soroban_data=xdr.SorobanTransactionData(xdr.SorobanTransactionDataExt(0),xdr.SorobanResources(xdr.LedgerFootprint([],[]),xdr.Uint32(100),xdr.Uint32(0),xdr.Uint32(0)),xdr.Int64(123))
            if mutate: mutate(tx)
            return tx.to_xdr()
        with patch.object(release,'wallet_state',return_value=(state,binding)),patch.object(release.wa,'fetch',return_value={'sequence':'1'}),patch.object(release.wa,'owner_only'),patch.object(release,'rpc',return_value={'sequence':100}),patch.object(release.ca,'cli_run',side_effect=simulate),patch.object(release,'read_contract',return_value=dict(policy_state=dict(calls=['Int',0],spent=['Int',0]))),patch.object(release,'balance',side_effect=[20000,50]):
            return release.complete_execute(self.plan,packet,signed.to_xdr())

    def test_execute_prepare_retains_unsigned_server_request_and_original_effects(self):
        packet,_,state,binding=self.execution_packet()
        with patch.object(release.wa,'fetch',return_value={}),patch.object(release.wa,'owner_only'),patch.object(release.wa,'admin'),patch.object(release,'require_settled'),patch.object(release,'wallet_state',return_value=(state,binding)),patch.object(release,'raw_invoke',return_value=packet['unsigned_xdr']),patch.object(release.ca,'prepare_xdr',return_value=packet['unsigned_xdr']) as prepare,patch.object(release,'balance',side_effect=[20000,50]),patch.object(release,'read_contract',return_value=dict(policy_state=dict(calls=['Int',0],spent=['Int',0]))),patch.object(release,'rpc',return_value={'sequence':100}):
            result=release.prepare(self.plan,self.base,'execute',parent=self.plan['asset'],wallet=self.plan['asset'],operation_id='ab'*32)
        self.assertFalse(result['signing_ready'])
        self.assertEqual(result['expected_effects']['recipient_balance'],50)
        self.assertEqual(result['expected_receipt']['amount'],10000)
        self.assertEqual(prepare.call_args.kwargs['candidate'],self.plan['server'])
        tx=TransactionEnvelope.from_xdr(result['unsigned_xdr'],Network.PUBLIC_NETWORK_PASSPHRASE)
        self.assertEqual(tx.hash_hex(),result['transaction_hash'])
        self.assertEqual(release.server_entry(tx,self.plan,signed=False).to_xdr(),result['server_authorization_xdr'])

    def test_completion_rejects_changed_original_balance_snapshot(self):
        packet,signed,state,binding=self.execution_packet()
        packet['expected_effects']['wallet_balance']+=1
        with self.assertRaisesRegex(ValueError,'balances or usage'):self.complete(packet,signed,state,binding)

    def test_exact_server_authorization_is_verified_and_enforced_before_unsigned_agent_export(self):
        packet,signed,state,binding=self.execution_packet()
        result=self.complete(packet,signed,state,binding)
        self.assertTrue(result['signing_ready'])
        self.assertEqual(result['authorization_request_hash'],packet['transaction_hash'])
        self.assertEqual(result['fee_bid_stroops'],223)
        self.assertFalse(packet['signing_ready'])
        tx=TransactionEnvelope.from_xdr(result['unsigned_xdr'],Network.PUBLIC_NETWORK_PASSPHRASE)
        self.assertEqual(tx.signatures,[])
        self.assertEqual(release.server_entry(tx,self.plan,signed=True),signed)

    def test_server_entry_rejects_changed_scope_nonce_expiry_key_and_signature(self):
        for field in ['nonce','expiry','scope','key','signature']:
            with self.subTest(field=field):
                packet,signed,state,binding=self.execution_packet()
                cred=signed.credentials.address
                if field=='nonce': cred.nonce=xdr.Int64(43)
                elif field=='expiry': cred.signature_expiration_ledger=xdr.Uint32(151)
                elif field=='scope': signed.root_invocation.function.contract_fn.function_name=xdr.SCSymbol(b'recover')
                else:
                    value=scval.to_native(cred.signature)[0]
                    value['public_key' if field=='key' else 'signature']=bytes([0])*(32 if field=='key' else 64)
                    cred.signature=scval.to_vec([scval.to_struct({k:scval.to_bytes(v) for k,v in value.items()})])
                with self.assertRaises(ValueError):self.complete(packet,signed,state,binding)

    def test_enforce_simulation_cannot_change_principal_authorization_or_exceed_cap(self):
        for field in ['fee','auth','scope']:
            with self.subTest(field=field):
                packet,signed,state,binding=self.execution_packet()
                def mutate(tx):
                    if field=='fee':tx.transaction.fee=self.plan['fee_caps_stroops']['execute']+1
                    elif field=='auth':tx.transaction.operations[0].auth=[]
                    else:tx.transaction.operations[0].host_function.invoke_contract.function_name=xdr.SCSymbol(b'recover')
                with self.assertRaises(ValueError):self.complete(packet,signed,state,binding,mutate)

    def test_unsigned_server_request_is_never_a_settlement_packet(self):
        packet,_,_,_=self.execution_packet()
        with patch.object(release,'rpc',side_effect=AssertionError('must reject before network')):
            with self.assertRaisesRegex(ValueError,'Complete'):release.settle(self.plan,packet)

    def test_common_config_selects_all_smoke_rules_and_their_params(self):
        config=release.wallet_config(self.plan)
        self.assertEqual(config['rules'],release.RULES)
        self.assertEqual(config['server'],self.plan['server'])
        self.assertFalse(config['x402_enabled'])
        self.assertEqual(set(config['params']),set(release.RULES))
        self.assertEqual(config['params']['transaction_cap'],10000)
        self.assertNotIn('day_spent_cap',config['params'])
        self.assertNotIn('tokens',config['params'])
        self.assertEqual(config['source_digest'],release.prefix_digest(release.WALLET_KIND,self.hashes['wallet'],self.plan['asset'],release.RULES))
        self.assertEqual(release.SMOKE_SOURCE.decode().count('(ctx, ctx.params.get(allowit::'),len(release.RULES))
        cli=json.loads(release.ca.serialize({'config':config})[1])['params']
        self.assertEqual(cli['recipients'],{'List':[{'Addr':self.plan['recipient']}]})
        self.assertEqual(cli['spent_cap'],{'Int':'20020000'})

    def test_wallet_state_accepts_a_real_encoded_state_and_rejects_other_rules(self):
        wallet,parent,engine=(StrKey.encode_contract(bytes([n])*32) for n in (21,22,23))
        expected=release.wallet_config(self.plan)
        def value(item):
            # One AllowitValue: a unit enum variant with its single field, as a two-element vector.
            if isinstance(item,list): return scval.to_vec([scval.to_symbol('List'),scval.to_vec([value(i) for i in item])])
            if isinstance(item,bool): return scval.to_vec([scval.to_symbol('Bool'),scval.to_bool(item)])
            if isinstance(item,str): return scval.to_vec([scval.to_symbol('Addr'),scval.to_address(item)])
            return scval.to_vec([scval.to_symbol('Int'),scval.to_int128(item)])
        def state(rules):
            params=scval.to_struct({k:value(v) for k,v in expected['params'].items()})
            policy_state=scval.to_struct({k:value(False) if 'unpriced' in k else value(0) for k in ('calls','spent','unpriced','day','day_spent','day_total','day_unpriced')})
            return scval.to_struct(dict(policy_state=policy_state,contract_version=scval.to_uint32(release.ca.WALLET_CONTRACT_VERSION),
                owner=scval.to_address(self.plan['owner']),agent=scval.to_address(self.plan['agent']),server=scval.to_address(self.plan['server']),
                asset=scval.to_address(self.plan['asset']),policy_instance=scval.to_bytes(bytes.fromhex(self.plan['policy_instance'])),
                source_digest=scval.to_bytes(bytes.fromhex(expected['source_digest'])),
                rules=scval.to_vec([scval.to_vec([scval.to_symbol(r)]) for r in rules]),
                params=params,x402_enabled=scval.to_bool(False),
                token=scval.to_string('XLM'),deployment_version=scval.to_uint64(0),nonce=scval.to_uint64(0),paused=scval.to_bool(False)))
        binding=scval.to_struct(dict(engine_kind=scval.to_symbol(release.WALLET_KIND),contract_version=scval.to_uint32(release.ca.WALLET_CONTRACT_VERSION),
            policy_instance=scval.to_bytes(bytes.fromhex(self.plan['policy_instance'])),module_digest=scval.to_bytes(bytes.fromhex(self.hashes['wallet'])),
            source_digest=scval.to_bytes(bytes.fromhex(expected['source_digest'])),argument_schema_digest=scval.to_bytes(hashlib.sha256(release.SCHEMA).digest()),
            entrypoint=scval.to_symbol('execute')))
        hashes={wallet:self.hashes['wallet'],parent:self.hashes['parent'],engine:self.hashes['engine']}
        def run(rules):
            def rpc(network,method,params=None):
                self.assertEqual(method,'simulateTransaction')
                call=TransactionEnvelope.from_xdr(params['transaction'],Network.PUBLIC_NETWORK_PASSPHRASE).transaction.operations[0].host_function.invoke_contract
                target=Address.from_xdr_sc_address(call.contract_address).address
                name=call.function_name.sc_symbol.decode()
                value={(wallet,'state'):state(rules),(wallet,'policy_binding'):binding,(parent,'engine'):scval.to_address(engine),
                    (parent,'state'):scval.to_struct(dict(owner=scval.to_address(self.plan['admin']),version=scval.to_uint64(0)))}[(target,name)]
                return dict(results=[dict(xdr=value.to_xdr())])
            def cli(args,input_data=None):
                self.assertEqual(args[:3],['contract','info','hash'])
                return hashes[args[args.index('--id')+1]]+'\n'
            # Only RPC, account and CLI reads are replaced; decoding runs on the real encoded values.
            with patch.object(release,'rpc',side_effect=rpc),patch.object(release.wa,'fetch',return_value={'sequence':'1'}),patch.object(release.ca,'cli_run',side_effect=cli):
                return release.wallet_state(self.plan,wallet,parent)
        decoded,_=run(release.RULES)
        self.assertEqual(decoded['rules'],[[r] for r in release.RULES])
        self.assertEqual(release.plain_params(decoded['params']),expected['params'])
        self.assertEqual(release.plain_params(decoded['policy_state'])['calls'],0)
        for rules in (release.RULES[::-1],release.RULES[:-1],release.RULES+['tokens']):
            with self.assertRaisesRegex(ValueError,'params differ'): run(rules)

    def test_prefix_digest_matches_the_contract_vector(self):
        # crates/policy-wallet/src/sep56_tests.rs standard_prefix_digest_matches_independent_xdr_vector_and_binds_context
        asset='CABAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAFNSZ'
        expected=bytes([189,68,199,46,9,31,98,232,188,107,50,209,161,33,85,130,99,159,235,54,236,14,58,68,204,139,83,138,197,114,143,196]).hex()
        self.assertEqual(release.prefix_digest('common_policy_engine','01'*32,asset,['spent_cap','recipients']),expected)
        self.assertNotEqual(release.prefix_digest('common_policy_engine','01'*32,asset,['recipients','spent_cap']),expected)

    def test_execution_binds_full_source_and_conservative_xlm_expense(self):
        state=dict(nonce=3,deployment_version=1)
        binding=dict(module_digest=self.hashes['wallet'],entrypoint='execute',argument_schema_digest=release.digest(release.SCHEMA))
        request=scval.from_struct(release.execution(self.plan,self.plan['asset'],state,binding,'ab'*32,90,day=7))
        self.assertEqual(scval.to_native(request['source_hash']).hex(),self.plan['policy_source_digest'])
        raw=scval.to_native(request['expense'])
        cost={k:scval.to_native(v) for k,v in scval.from_struct(xdr.SCVal.from_xdr_bytes(raw)).items()}
        self.assertEqual(cost['gas_units'],10000000)
        self.assertEqual(cost['max_fee_stroops'],10000000)
        self.assertEqual(cost['spent_units'],10010000)
        self.assertEqual(cost['conversion_units'],0)
        self.assertEqual((cost['decimals'],cost['observed_ledger'],cost['day']),(7,90,7))
        self.assertEqual(xdr.SCVal.from_xdr_bytes(raw).to_xdr_bytes(),raw)


if __name__=='__main__': unittest.main()
