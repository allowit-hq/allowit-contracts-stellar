import assert from 'node:assert/strict';
import test from 'node:test';
import {Account, Keypair, Networks, Operation, TransactionBuilder} from '@stellar/stellar-sdk/base';
import plugin, {canonicalNetwork, strkey} from '../dist/plugin.js';
import {formatUnits} from '../dist/elements/display.js';
import {ownerStep, payloadHash, signInMessageFor, signedPayloadValid} from '../dist/elements/signing.js';
import {expiry} from '../dist/elements/base.js';

test('plugin identity, networks and element tags follow the SDK contract', () => {
  assert.equal(plugin.id, 'stellar');
  assert.deepEqual(plugin.networks.map(n => n.id), ['stellar:testnet', 'stellar:pubnet']);
  assert.equal(plugin.networks.find(n => n.id === plugin.test.network)?.testnet, true);
  assert.deepEqual(Object.keys(plugin.elements).sort(), ['address', 'amount', 'binding-review', 'explorer-link', 'owner-sign', 'receipt', 'wallet-sign-in']);
  for (const tag of Object.values(plugin.elements)) assert.match(tag, /^allowit-stellar-[a-z-]+$/);
  assert.equal(canonicalNetwork('stellar:mainnet'), 'stellar:pubnet');
  assert.equal(canonicalNetwork('other:testnet'), null);
});

test('define is a no-op without custom elements, so servers and tests can import the plugin', () => {
  assert.equal(typeof globalThis.customElements, 'undefined');
  plugin.define();
});

test('addresses need a valid StrKey checksum', () => {
  const {address, invalidAddress} = plugin.test.fixtures;
  assert.equal(plugin.validateAddress(plugin.test.network, address), true);
  assert.equal(plugin.validateAddress(plugin.test.network, invalidAddress), false);
  assert.equal(plugin.validateAddress('other:testnet', address), false);
  assert.equal(plugin.validateAddress(plugin.test.network, plugin.assets(plugin.test.network)[0].id), true);
  assert.equal(strkey(address.toLowerCase()), null);
  // A valid checksum with an unsupported version byte.
  assert.equal(plugin.validateAddress(plugin.test.network, 'GEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBDI'), false);
});

test('explorer links cover accounts, contracts and transactions', () => {
  const {address, txHash} = plugin.test.fixtures;
  assert.equal(plugin.explorerUrl('stellar:testnet', 'address', address), `https://stellar.expert/explorer/testnet/account/${address}`);
  assert.equal(plugin.explorerUrl('stellar:mainnet', 'tx', txHash), `https://stellar.expert/explorer/public/tx/${txHash}`);
  const xlm = plugin.assets('stellar:testnet')[0].id;
  assert.equal(plugin.explorerUrl('stellar:testnet', 'contract', xlm), `https://stellar.expert/explorer/testnet/contract/${xlm}`);
  assert.equal(plugin.explorerUrl('stellar:testnet', 'tx', 'not-a-hash'), null);
});

test('assets derive their Stellar Asset Contract ids', () => {
  const [xlm, usdc] = plugin.assets('stellar:testnet');
  assert.equal(xlm.id, 'CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC');
  assert.equal(usdc.symbol, plugin.test.fixtures.asset);
  assert.equal(usdc.stablecoin, true);
  assert.equal(plugin.assets('other:testnet').length, 0);
});

test('amounts format integer units without floating point', () => {
  assert.equal(formatUnits('12345678901', 7), '1,234.5678901');
  assert.equal(formatUnits('100', 7), '0.00001');
  assert.equal(formatUnits('-50000000', 7), '-5');
});

test('owner steps admit only the rail-neutral shape and sign only the reviewed hash', async () => {
  const owner = Keypair.fromRawEd25519Seed(Buffer.alloc(32, 1)).publicKey();
  const tx = new TransactionBuilder(new Account(owner, '41'), {fee: '100', networkPassphrase: Networks.TESTNET})
    .addOperation(Operation.bumpSequence({bumpTo: '50'})).setTimeout(300).build();
  const step = ownerStep({action: 'fund', payload: tx.toXDR(), hash: Buffer.from(tx.hash()).toString('hex'), expires_at: 2_000_000_000});
  assert.ok(step);
  assert.equal(await payloadHash(step.payload, 'stellar:testnet'), step.hash);
  assert.notEqual(await payloadHash(step.payload, 'stellar:pubnet'), step.hash);
  assert.equal(ownerStep({...step, hash: 'zz'}), null);
  const key = Keypair.fromRawEd25519Seed(Buffer.alloc(32, 1));
  assert.equal(await signedPayloadValid(tx.toXDR(), 'stellar:testnet', step.hash, owner), false, 'unsigned');
  tx.sign(key);
  assert.equal(await signedPayloadValid(tx.toXDR(), 'stellar:testnet', step.hash, owner), true);
  const other = new TransactionBuilder(new Account(owner, '41'), {fee: '200', networkPassphrase: Networks.TESTNET})
    .addOperation(Operation.bumpSequence({bumpTo: '50'})).setTimeout(300).build();
  other.sign(key);
  assert.equal(await signedPayloadValid(other.toXDR(), 'stellar:testnet', step.hash, owner), false, 'another transaction');
  const stranger = Keypair.fromRawEd25519Seed(Buffer.alloc(32, 2));
  const foreign = TransactionBuilder.fromXDR(step.payload, Networks.TESTNET);
  foreign.sign(stranger);
  assert.equal(await signedPayloadValid(foreign.toXDR(), 'stellar:testnet', step.hash, owner), false, 'another signer');
  assert.equal(ownerStep({...step, payload: '<xml/>'}), null);
});

test('sign-in signs only a CAIP-122 message for this site and account', () => {
  const address = plugin.test.fixtures.address;
  const message = `app.example wants you to sign in with your Stellar Testnet account:\n${address}\n\nSign in.`;
  assert.equal(signInMessageFor(message, address, 'app.example'), true);
  assert.equal(signInMessageFor(message, address, 'evil.example'), false);
  assert.equal(signInMessageFor(message.replace(address, 'G' + 'A'.repeat(55)), address, 'app.example'), false);
});

test('expiry shows local time and the time left', () => {
  assert.match(expiry(1_000 + 7_200, 1_000_000), /2 h 0 min left/);
  assert.match(expiry(1, 10_000), /expired/);
});

test('the asset contract equals the Stellar SDK Asset.contractId for native and one issued asset', async () => {
  const {Asset, Networks} = await import('@stellar/stellar-sdk/base');
  const {stellarAssetContract} = await import('../dist/stellar-asset.js');
  const issuer = 'GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5';
  assert.equal(stellarAssetContract('XLM', null, Networks.TESTNET), Asset.native().contractId(Networks.TESTNET));
  assert.equal(stellarAssetContract('XLM', null, Networks.TESTNET), 'CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC');
  assert.equal(stellarAssetContract('USDC', issuer, Networks.TESTNET), new Asset('USDC', issuer).contractId(Networks.TESTNET));
  assert.equal(stellarAssetContract('USDC', issuer, Networks.TESTNET), 'CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA');
  // An issued XLM is not native XLM, and a native asset has no other code.
  assert.notEqual(stellarAssetContract('XLM', issuer, Networks.TESTNET), stellarAssetContract('XLM', null, Networks.TESTNET));
  assert.throws(() => stellarAssetContract('USDC', null, Networks.TESTNET), /invalid/);
});
