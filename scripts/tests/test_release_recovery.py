"""Native SDK/XDR fault tests for current-state release reconciliation. No live keys or RPC."""
import copy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import testnet_release as r
from test_testnet_release import constructor, ledger, make_bundle, wasm
from stellar_sdk import Address, Keypair, SorobanServer, TransactionEnvelope, scval, xdr
from stellar_sdk.soroban_rpc import SimulateTransactionResponse, GetTransactionResponse, LedgerEntryResult, GetLedgerEntriesResponse

class ReleaseReconciliation(unittest.TestCase):
    def setUp(self):
        self.root=Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.bundle=self.root/'bundle';self.bundle.mkdir();self.manifest=make_bundle(self.bundle)
        self.owner,self.agent,self.server=(Keypair.random() for _ in range(3))
        self.clock=2_000_000_000.0;self.entry_clock=self.clock;self.sequence=10;self.account_present=True
        self.codes={item['sha256']:wasm() for item in self.manifest['artifacts'].values()}
        self.wallets={};self.configs={}
        for kind in r.KINDS:
            config,salt,wallet=r.wallet_intent(self.manifest,kind,self.owner.public_key,self.agent.public_key,self.server.public_key)
            # Independent native constructor encoder from the original CLI/spec tests.
            self.configs[wallet]=constructor(config,self.manifest['artifacts'][kind]['sha256'],salt).constructor_args[0]
            self.wallets[wallet]=self.manifest['artifacts'][kind]['sha256']
        self.archived=False;self.simulation_error=False;self.send_error=False;self.receipt_mode='SUCCESS';self.sent=[];self.simulated=[]
        self.asset_present=True;self.snapshots=0;self.after_snapshot=None;self.after_send=None
        self.rpc=SorobanServer(r.RPC)
        self.enterContext(patch.object(r,'SorobanServer',return_value=self.rpc))
        self.enterContext(patch.object(r,'utc_seconds',side_effect=lambda:self.clock))
        self.enterContext(patch.object(r.time,'sleep',side_effect=self.advance))
        self.authority=self.enterContext(patch.object(r,'current_authority',return_value={'automation':'d'*40,'controller_attempt':'100:1','build_run':'90:1'}))
        self.enterContext(patch.dict(os.environ,{'GITHUB_RUN_ID':'100','GITHUB_RUN_ATTEMPT':'1'}))
        self.enterContext(patch.object(r,'public_json_url',side_effect=self.public))
        self.enterContext(patch.object(self.rpc,'get_network',return_value=NS(passphrase=r.PASSPHRASE)))
        self.enterContext(patch.object(self.rpc,'get_latest_ledger',side_effect=lambda:NS(sequence=1000+int(self.clock-self.entry_clock))))
        self.enterContext(patch.object(self.rpc,'get_ledgers',side_effect=self.headers))
        self.enterContext(patch.object(self.rpc,'get_ledger_entries',side_effect=self.entries))
        self.enterContext(patch.object(self.rpc,'simulate_transaction',side_effect=self.simulate))
        self.enterContext(patch.object(self.rpc,'send_transaction',side_effect=self.send))
        self.enterContext(patch.object(self.rpc,'get_transaction',side_effect=self.receipt))
        self.sign=self.enterContext(patch.object(self.owner,'sign',wraps=self.owner.sign))

    def advance(self,seconds):self.clock+=seconds

    def native_ledger(self,sequence):
        result=ledger(sequence);header=xdr.LedgerHeader.from_xdr(result['header_xdr'])
        header.scp_value.close_time=xdr.TimePoint(xdr.Uint64(1_000_000 if sequence==128 else int(self.clock)-1))
        result.update(header_xdr=header.to_xdr(),hash=r.digest(header.to_xdr_bytes()),closed_at=datetime.fromtimestamp(header.scp_value.close_time.time_point.uint64,timezone.utc).isoformat())
        return result

    def public(self,path):
        if path=='/':return {'network_passphrase':r.PASSPHRASE,'history_latest_ledger':1000+int(self.clock-self.entry_clock)}
        return self.native_ledger(int(path.rsplit('/',1)[1]))

    def headers(self,start_ledger,limit):
        item=self.native_ledger(start_ledger)
        native=xdr.LedgerHeaderHistoryEntry(xdr.Hash(bytes.fromhex(item['hash'])),xdr.LedgerHeader.from_xdr(item['header_xdr']),xdr.LedgerHeaderHistoryEntryExt(0))
        return NS(ledgers=[NS(sequence=start_ledger,hash=item['hash'],header_xdr=native.to_xdr())])

    def state(self,wallet):
        fields=scval.from_struct(self.configs[wallet]);fields.update(policy_state=scval.to_map({}),contract_version=scval.to_uint32(4),token=scval.to_string('XLM'),deployment_version=scval.to_uint64(0),nonce=scval.to_uint64(0),paused=scval.to_bool(False))
        return scval.to_struct(fields)

    def entries(self,keys):
        self.snapshots+=1;items=[];tip=1000+int(self.clock-self.entry_clock)
        for key in keys:
            data=None
            if key.type==xdr.LedgerEntryType.ACCOUNT and self.account_present:
                data=xdr.LedgerEntryData(key.type,account=xdr.AccountEntry(self.owner.xdr_account_id(),xdr.Int64(10**10),xdr.SequenceNumber(xdr.Int64(self.sequence)),xdr.Uint32(0),None,xdr.Uint32(0),xdr.String32(b''),xdr.Thresholds(b'\x01\x00\x00\x00'),[],xdr.AccountEntryExt(0)))
            elif key.type==xdr.LedgerEntryType.CONTRACT_CODE:
                module=key.contract_code.hash.hash.hex()
                if module in self.codes:data=xdr.LedgerEntryData(key.type,contract_code=xdr.ContractCodeEntry(xdr.ContractCodeEntryExt(0),xdr.Hash(bytes.fromhex(module)),self.codes[module]))
            elif key.type==xdr.LedgerEntryType.CONTRACT_DATA:
                address=Address.from_xdr_sc_address(key.contract_data.contract).address
                if address==r.Asset.native().contract_id(r.PASSPHRASE) and self.asset_present:
                    executable=xdr.ContractExecutable(xdr.ContractExecutableType.CONTRACT_EXECUTABLE_STELLAR_ASSET);storage=[]
                elif address in self.wallets:
                    executable=xdr.ContractExecutable(xdr.ContractExecutableType.CONTRACT_EXECUTABLE_WASM,wasm_hash=xdr.Hash(bytes.fromhex(self.wallets[address])));storage=[xdr.SCMapEntry(scval.to_uint32(0),self.state(address))]
                else:continue
                data=xdr.LedgerEntryData(key.type,contract_data=xdr.ContractDataEntry(xdr.ExtensionPoint(0),key.contract_data.contract,key.contract_data.key,key.contract_data.durability,xdr.SCVal(xdr.SCValType.SCV_CONTRACT_INSTANCE,instance=xdr.SCContractInstance(executable,xdr.SCMap(storage)))))
            if data is not None:items.append(LedgerEntryResult(key=key.to_xdr(),xdr=data.to_xdr(),lastModifiedLedgerSeq=tip,liveUntilLedgerSeq=tip+5000))
        if self.after_snapshot:self.after_snapshot(self.snapshots)
        return GetLedgerEntriesResponse(latestLedger=tip,entries=items)

    def simulate(self,envelope,**kwargs):
        self.simulated.append(envelope.to_xdr());host=envelope.transaction.operations[0].host_function;auth=[]
        if self.simulation_error:return SimulateTransactionResponse(latestLedger=1000,error='ambiguous native simulation')
        if host.type==xdr.HostFunctionType.HOST_FUNCTION_TYPE_UPLOAD_CONTRACT_WASM:
            target=r.code_key(r.digest(host.wasm))
        else:
            create=host.create_contract_v2;module=create.executable.wasm_hash.hash.hex()
            if module not in self.codes:raise AssertionError('Constructor simulated before exact Wasm readback')
            target=r.instance_key(Address.from_xdr_sc_address(r.ca.deployment_address(create,'testnet')).address)
            child=xdr.SorobanAuthorizedInvocation(xdr.SorobanAuthorizedFunction(xdr.SorobanAuthorizedFunctionType.SOROBAN_AUTHORIZED_FUNCTION_TYPE_CONTRACT_FN,contract_fn=xdr.InvokeContractArgs(target.contract_data.contract,xdr.SCSymbol(b'__constructor'),create.constructor_args)),[])
            auth=[xdr.SorobanAuthorizationEntry(xdr.SorobanCredentials(xdr.SorobanCredentialsType.SOROBAN_CREDENTIALS_SOURCE_ACCOUNT),xdr.SorobanAuthorizedInvocation(xdr.SorobanAuthorizedFunction(xdr.SorobanAuthorizedFunctionType.SOROBAN_AUTHORIZED_FUNCTION_TYPE_CREATE_CONTRACT_V2_HOST_FN,create_contract_v2_host_fn=create),[child])).to_xdr()]
        ext=xdr.SorobanTransactionDataExt(1,xdr.SorobanResourcesExtV0([xdr.Uint32(0)] if self.archived else []))
        data=xdr.SorobanTransactionData(ext,xdr.SorobanResources(xdr.LedgerFootprint([], [target]),xdr.Uint32(100),xdr.Uint32(0),xdr.Uint32(100)),xdr.Int64(1000))
        return SimulateTransactionResponse(latestLedger=1000+int(self.clock-self.entry_clock),transactionData=data.to_xdr(),minResourceFee=1000,results=[{'auth':auth,'xdr':scval.to_void().to_xdr()}])

    def send(self,signed):
        self.sent.append(signed)
        if self.send_error:raise TimeoutError('synthetic send timeout')
        envelope=TransactionEnvelope.from_xdr(signed,r.PASSPHRASE);self.sequence=envelope.transaction.sequence
        if self.receipt_mode=='SUCCESS':
            host=envelope.transaction.operations[0].host_function
            if host.type==xdr.HostFunctionType.HOST_FUNCTION_TYPE_UPLOAD_CONTRACT_WASM:self.codes[r.digest(host.wasm)]=host.wasm
            else:
                create=host.create_contract_v2;wallet=Address.from_xdr_sc_address(r.ca.deployment_address(create,'testnet')).address
                self.wallets[wallet]=create.executable.wasm_hash.hash.hex();self.configs[wallet]=create.constructor_args[0]
        if self.after_send:self.after_send()
        return NS(hash=envelope.hash_hex(),status='PENDING')

    def receipt(self,tx_hash):
        signed=self.sent[-1];envelope=TransactionEnvelope.from_xdr(signed,r.PASSPHRASE)
        code=xdr.TransactionResultCode.txSUCCESS if self.receipt_mode=='SUCCESS' else xdr.TransactionResultCode.txFAILED
        result=xdr.TransactionResult(xdr.Int64(1100),xdr.TransactionResultResult(code,results=[]),xdr.TransactionResultExt(0))
        tip=1000+int(self.clock-self.entry_clock)
        return GetTransactionResponse(status=self.receipt_mode,txHash=tx_hash,latestLedger=tip,latestLedgerCloseTime=int(self.clock),oldestLedger=1000,oldestLedgerCloseTime=1,ledger=tip,envelopeXdr=signed,resultXdr=result.to_xdr())

    def driver(self,name='run'):
        return r.Deployment(self.bundle,self.root/name/'public.json',self.root/name/'private',self.owner,self.agent.public_key,self.server.public_key)

    def test_read_only_reuse_has_full_coherent_state_without_historical_receipts_or_wait(self):
        driver=self.driver();result=driver.run()
        self.assertEqual(result['status'],'RESOURCE_STATE_VERIFIED');self.assertEqual(result['transactions'],[])
        self.assertEqual(self.clock,self.entry_clock);self.assertFalse(self.sent);self.assertFalse(self.simulated)
        self.assertEqual(result['operator'],{'account':self.owner.public_key,'sequence':self.sequence,
            'ledger':result['resource_observation']['ledger'],'observation':'observed-present','friendbot_requested':False})
        self.assertEqual({v['ledger'] for v in result['wallets'].values()},{result['resource_observation']['ledger']})
        self.assertTrue(all(v['observation']=='observed-existing' for v in result['wallets'].values()))

    def test_native_sdk_resource_ttl_must_be_known_and_after_snapshot(self):
        driver=self.driver();snapshot=driver.snapshot()
        asset_item=snapshot[1][driver.asset_key.to_xdr()][0]
        self.assertIsInstance(asset_item,LedgerEntryResult)
        driver.asset_present(snapshot)
        for expiry in (None,snapshot[0]-1,snapshot[0]):
            with self.subTest(expiry=expiry):
                asset_item.live_until_ledger=expiry
                with self.assertRaisesRegex(ValueError,'lifetime is unavailable'):driver.asset_present(snapshot)
                for key in driver.keys[2:]:
                    item=snapshot[1].get(key.to_xdr())
                    if item is not None:item[0].live_until_ledger=expiry
                action=r.Action('code','common',self.manifest['artifacts']['common']['sha256'],False)
                with self.assertRaisesRegex(ValueError,'lifetime is unknown'):driver.resource(action,snapshot)
        self.sign.assert_not_called();self.assertFalse(self.sent)

    def test_pristine_deployment_and_fresh_run_do_not_fabricate_historical_receipts(self):
        self.codes.clear();self.wallets.clear();driver=self.driver();result=driver.run()
        self.assertEqual(len(result['transactions']),4) # One deduplicated fixture Wasm, three native constructors.
        self.assertGreater(result['quiescence']['barrier_close_time'],self.entry_clock+450)
        self.assertTrue(all(v['status']=='SUCCESS' for v in result['transactions']))
        self.assertEqual(len(self.sent),4);self.sign.reset_mock();self.sent.clear()
        result=self.driver('retry').run();self.assertEqual(result['transactions'],[]);self.sign.assert_not_called()
        self.assertTrue(all(v['observation']=='observed-existing' for v in result['wallets'].values()))

    def test_live_config_drift_blocks_all_prerequisite_mutations(self):
        self.codes.clear();wallet=next(iter(self.wallets));fields=scval.from_struct(self.configs[wallet]);fields['server']=scval.to_address(self.agent.public_key);self.configs[wallet]=scval.to_struct(fields)
        with self.assertRaisesRegex(ValueError,'state differs'):self.driver().run()
        self.sign.assert_not_called();self.assertFalse(self.sent)

    def test_completed_creation_is_guarded_before_later_signature(self):
        self.wallets.clear();driver=self.driver();original=driver.resource;changed=[]
        def drift(action,snapshot):
            result=original(action,snapshot)
            if action.resource=='wallet' and result is not None and not changed:
                changed.append(action.key);fields=scval.from_struct(self.configs[action.key]);fields['server']=scval.to_address(self.agent.public_key);self.configs[action.key]=scval.to_struct(fields)
            return result
        driver.resource=drift
        with self.assertRaisesRegex(ValueError,'state differs'):driver.run()
        self.assertEqual(len(self.sent),1)

    def test_final_readback_rechecks_every_native_field_and_strict_variant(self):
        for field,value in [('paused',scval.to_bool(True)),('nonce',scval.to_uint64(1)),('policy_state',scval.to_map({scval.to_symbol('spent'):scval.to_enum('Int',scval.to_int128(1))})),('contract_version',scval.to_uint64(4))]:
            driver=self.driver(field);original=self.state
            def changed(wallet):
                fields=scval.from_struct(original(wallet));fields[field]=value;return scval.to_struct(fields)
            plan=driver.preflight()
            with patch.object(self,'state',side_effect=changed),self.assertRaisesRegex(ValueError,'state differs'):driver.final_readback(plan)
        self.sign.assert_not_called()

    def test_archived_or_ambiguous_missing_target_never_signs_or_restores(self):
        self.wallets.clear()
        for archived in (True,False):
            self.archived=archived;self.simulation_error=not archived
            with self.subTest(archived=archived),self.assertRaises(ValueError):self.driver(str(archived)).run()
        self.sign.assert_not_called();self.assertFalse(self.sent)

    def test_send_uncertainty_retains_original_signed_bytes_hash_and_sequence(self):
        self.wallets.clear();self.send_error=True;driver=self.driver()
        with self.assertRaisesRegex(ValueError,'preserve original hash'):driver.run()
        self.assertEqual(len(self.sent),1);self.assertEqual(self.sign.call_count,1)
        packet=json.loads(next(driver.private.glob('*.json')).read_text());record=json.loads(driver.output.read_text())['transactions'][0]
        self.assertEqual(packet['signed_xdr'],self.sent[0]);self.assertEqual(packet['hash'],record['transaction_hash'])
        self.assertEqual(record['status'],'unknown');self.assertEqual(record['sequence'],11)
        self.assertNotIn(packet['signed_xdr'],driver.output.read_text())
        self.assertGreater(len(list(driver.output.parent.glob('*snapshot*'))),1)

    def test_failed_transaction_consumes_sequence_and_stops_without_replacement(self):
        self.wallets.clear();self.receipt_mode='FAILED';driver=self.driver()
        with self.assertRaises(ValueError):driver.run()
        self.assertEqual(len(self.sent),1);self.assertEqual(self.sequence,11)
        record=json.loads(driver.output.read_text())['transactions'][0];self.assertEqual(record['status'],'FAILED');self.assertEqual(record['sequence'],11)

    def test_foreign_sequence_change_before_signing_never_replaces_an_old_envelope(self):
        self.wallets.clear();driver=self.driver();original=driver.prepare
        def changed(*args):
            prepared=original(*args);self.sequence+=1;return prepared
        driver.prepare=changed
        with self.assertRaisesRegex(ValueError,'sequence'):driver.run()
        self.sign.assert_not_called();self.assertFalse(self.sent)

    def test_queue_time_does_not_count_toward_exclusive_slot_barrier(self):
        self.clock+=1000;self.wallets.clear();entered=self.clock;driver=self.driver();driver.run()
        self.assertGreater(driver.public['quiescence']['barrier_close_time'],entered+450)
        envelope=TransactionEnvelope.from_xdr(self.sent[0],r.PASSPHRASE)
        self.assertLessEqual(envelope.transaction.preconditions.time_bounds.max_time,int(self.clock)+300)

    def test_an_older_other_tag_envelope_can_settle_only_before_the_new_plan_freezes(self):
        from stellar_sdk import Account, TransactionBuilder
        self.wallets.clear()
        older=TransactionBuilder(Account(self.owner.public_key,self.sequence),r.PASSPHRASE,base_fee=100).add_time_bounds(0,int(self.clock)+300).append_upload_contract_wasm_op(wasm()).build()
        older.sign(self.owner);old_hash=older.hash_hex();self.sign.reset_mock()
        advanced=[]
        def settle_older(seconds):
            self.advance(seconds)
            if not advanced:
                advanced.append(1);self.sequence=older.transaction.sequence
        with patch.object(r.time,'sleep',side_effect=settle_older):result=self.driver().run()
        self.assertGreater(result['quiescence']['barrier_close_time'],older.transaction.preconditions.time_bounds.max_time)
        self.assertEqual(result['transactions'][0]['sequence'],older.transaction.sequence+1)
        self.assertTrue(all(record['transaction_hash']!=old_hash for record in result['transactions']))

    def test_missing_receipt_after_send_stays_unknown_and_keeps_the_original_packet(self):
        self.wallets.clear();driver=self.driver()
        unknown=GetTransactionResponse(status='NOT_FOUND',txHash='00'*32,latestLedger=2000,latestLedgerCloseTime=int(self.clock),oldestLedger=1000,oldestLedgerCloseTime=1)
        with patch.object(self.rpc,'get_transaction',return_value=unknown),self.assertRaisesRegex(ValueError,'preserve original hash'):driver.run()
        self.assertEqual(len(self.sent),1)
        record=json.loads(driver.output.read_text())['transactions'][0]
        self.assertEqual(record['transaction_hash'],TransactionEnvelope.from_xdr(self.sent[0],r.PASSPHRASE).hash_hex())
        self.assertEqual(record['status'],'unknown')

    def test_publication_preserves_existing_assets_and_rechecks_exact_attempt(self):
        result=self.driver().run()
        path=self.bundle/r.deployment_filename(self.manifest,result['network_identity'],'100:1')
        r.immutable(path,r.canonical(result)+b'\n')
        uploads=[]
        def command(args,**kwargs):
            self.assertNotIn('--clobber',args)
            if args[:3]==['gh','release','download']:
                name=args[args.index('--pattern')+1];Path(args[args.index('--dir')+1],name).write_bytes((self.bundle/name).read_bytes())
            else:uploads.append(args)
            return NS(returncode=0)
        names=[p.name for p in self.bundle.iterdir() if p.name!='release-build.json']
        with patch.object(r,'gh_json',return_value={'assets':[{'name':name} for name in names]}),patch.object(r,'public_run',side_effect=command):r.publish(self.bundle)
        self.assertEqual(uploads,[])
        result['build_attempt']='other';path.write_bytes(r.canonical(result))
        with self.assertRaisesRegex(ValueError,'current desired'):r.publish(self.bundle)

    def test_disappeared_reuse_or_changed_generation_stops_instead_of_create(self):
        driver=self.driver();plan=driver.preflight();self.wallets.pop(next(iter(self.wallets)))
        with self.assertRaisesRegex(ValueError,'disappeared'):driver.final_readback(plan)
        self.sign.assert_not_called()
        driver=self.driver('reset');original=self.native_ledger
        def changed(sequence):
            item=original(sequence)
            if sequence==128:
                header=xdr.LedgerHeader.from_xdr(item['header_xdr']);header.previous_ledger_hash=xdr.Hash(b'x'*32)
                item.update(header_xdr=header.to_xdr(),hash=r.digest(header.to_xdr_bytes()))
            return item
        with patch.object(self,'native_ledger',side_effect=changed),self.assertRaisesRegex(ValueError,'generation changed'):driver.run()

    def test_absent_operator_requires_network_then_fixed_friendbot_and_native_readback(self):
        self.account_present=False;self.codes.clear();self.wallets.clear()
        def fund(url,timeout):
            self.assertTrue(url.startswith('https://friendbot.stellar.org?addr='+self.owner.public_key));self.assertGreater(self.clock,self.entry_clock+450)
            self.account_present=True
            response=Mock();response.geturl.return_value=url;response.read.return_value=b'{}';response.__enter__=Mock(return_value=response);response.__exit__=Mock(return_value=False);return response
        driver=self.driver()
        with patch.object(r,'urlopen',side_effect=fund):result=driver.run()
        self.assertEqual(len(self.sent),4)
        self.assertEqual(result['operator'],{'account':self.owner.public_key,'sequence':self.sequence,
            'ledger':result['resource_observation']['ledger'],'observation':'observed-present','friendbot_requested':True})
        snapshots=[json.loads(path.read_text()) for path in driver.output.parent.glob('*snapshot*')]
        self.assertTrue(any(item.get('operator',{}).get('observation')=='request-unresolved' for item in snapshots))

    def test_friendbot_uncertainty_is_reported_without_inventing_account_creation(self):
        self.account_present=False;driver=self.driver()
        with patch.object(r,'urlopen',side_effect=TimeoutError('synthetic Friendbot timeout')),self.assertRaises(TimeoutError):
            driver.run()
        report=json.loads(driver.output.read_text())
        self.assertEqual(report['operator'],{'account':self.owner.public_key,'friendbot_requested':True,
            'observation':'request-unresolved'})
        self.assertFalse(self.sent);self.sign.assert_not_called()

    def test_tag_or_bundle_recheck_after_wait_and_before_every_mutation(self):
        self.wallets.clear();driver=self.driver();calls=[]
        def authority(manifest):
            calls.append(1)
            if self.clock>self.entry_clock+450:raise ValueError('canonical provenance changed')
            return driver.authority
        with patch.object(r,'current_authority',side_effect=authority),self.assertRaisesRegex(ValueError,'provenance'):driver.run()
        self.sign.assert_not_called();self.assertFalse(self.sent)

    def test_missing_asset_mainnet_stale_headers_and_endpoint_lag_fail_closed(self):
        self.asset_present=False
        with self.assertRaisesRegex(ValueError,'asset contract'):self.driver().run()
        self.asset_present=True
        with patch.object(self.rpc,'get_network',return_value=NS(passphrase='Public Global Stellar Network ; September 2015')),self.assertRaisesRegex(ValueError,'not Stellar Testnet'):self.driver('mainnet')
        for tip in (1,999999):
            with patch.object(self.rpc,'get_latest_ledger',return_value=NS(sequence=tip)),self.assertRaises(ValueError):self.driver(str(tip))
        original=self.native_ledger
        for close in (1,int(self.clock)+31):
            def stale(sequence):
                item=original(sequence)
                if sequence!=128:
                    header=xdr.LedgerHeader.from_xdr(item['header_xdr']);header.scp_value.close_time=xdr.TimePoint(xdr.Uint64(close))
                    item.update(header_xdr=header.to_xdr(),hash=r.digest(header.to_xdr_bytes()),closed_at=datetime.fromtimestamp(close,timezone.utc).isoformat())
                return item
            with patch.object(self,'native_ledger',side_effect=stale),self.assertRaisesRegex(ValueError,'stale or in the future'):self.driver(str(close))
        self.sign.assert_not_called()

if __name__=='__main__':unittest.main()
