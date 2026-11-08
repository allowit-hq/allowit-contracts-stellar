import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import test, {mock} from 'node:test';
import {Keypair} from '@stellar/stellar-sdk/base';

const passphrase = 'Test SDF Network ; September 2015';
const [owner, agent, server] = [1, 2, 3].map(seed => Keypair.fromRawEd25519Seed(Buffer.alloc(32, seed)).publicKey());
const wallet = 'C' + 'A'.repeat(55);
const signatures = [];
const forged = new Set();
mock.module('@stellar/freighter-api', {defaultExport: {
  getAddress: async () => ({address: owner}),
  getNetworkDetails: async () => ({networkPassphrase: passphrase}),
  signTransaction: async xdr => {
    signatures.push(xdr);
    return {signedTxXdr: `${xdr}signed`, signerAddress: owner};
  },
}});
mock.module(new URL('../dist/owner-verifier.js', import.meta.url).href, {namedExports: {
  deriveAdkOwnerWallet: async () => wallet, verifyAdkOwnerStep: async () => {}, verifyAdkOwnerSignature: async (_step, _expected, signedXdr) => {
    if (forged.has(signedXdr)) throw new Error('The owner signature is invalid.');
  },
}});
mock.module(new URL('../dist/portable-export.js', import.meta.url).href, {namedExports: {
  object: value => value && typeof value === 'object' && !Array.isArray(value) ? value : null,
  portableExport: () => ({top: {language: 'allowit-portable-v1'}, config: {tier: 'common'}}),
}});
const {adkOwnerArchiveKey, adkOwnerKey, deployAdkOwnerDraft} = await import('../dist/adk-owner-workflow.js');
const {stellarAssetContractId} = await import('../dist/stellar-wallet.js');

const network = 'stellar:testnet';
const asset = stellarAssetContractId('XLM', null, network);
const hash = value => createHash('sha256').update(value).digest('hex');
const bytes = value => [...Buffer.from(value, 'hex')];
const policyId = 'policy-id';
const policyInstance = 'c'.repeat(64);
const moduleDigest = 'd'.repeat(64);
const code = '/// Let the agent use XLM within the approved limit.';
const params = {payment_limit: {Int: '20000000'}};
const proposal = {network, revision: 2, title: 'Approve payment', explanation: '', code, params,
  sourceHash: hash(code), paramsHash: hash(JSON.stringify(params))};
const session = {network: 'stellar', address: owner, expiresAt: '2026-11-07T00:00:00Z'};
const binding = {wallet, template: true, route: 'policyWallet', tier: 'common', policyInstance, maxFeeStroops: 1000, portable: {paramsHash: proposal.paramsHash}};
const policy = {id: policyId, revision: 1, network, code, sourceHash: proposal.sourceHash, irHash: '', mint: asset, token: 'XLM', runtime: {instanceBinding: binding}};
const exported = {
  version: 1, profile: 'allowit-stellar-wallet-v1', policyId, network, route: 'policyWallet', wallet,
  sourceHash: proposal.sourceHash, moduleDigest, irHash: '', unexpected: 'ignored',
  config: {wallet, owner, agent, server, network, route: 'policyWallet', policySource: code, asset,
    assetSymbol: 'XLM', assetIssuer: null, maxFeeStroops: 1000, policyInstance: bytes(policyInstance),
    sourceHash: bytes(proposal.sourceHash), moduleDigest: bytes(moduleDigest), sourceDigest: bytes('f'.repeat(64)), unexpected: 'ignored'},
  endpoints: {execute: '/api/native/execute', status: '/api/native/execute/status'},
};
const now = () => Math.floor(Date.now() / 1000);
const fundStep = id => ({network, action: 'fund', transactionXdr: `AAAA${id}`, transactionHash: id.repeat(64), expiresAt: now() + 60});

/** A browser and server model. `submit` answers each owner submission. */
function browser(submit) {
  const entries = new Map();
  globalThis.localStorage = {getItem: key => entries.get(key) ?? null, setItem: (key, value) => entries.set(key, value)};
  Object.defineProperty(globalThis, 'navigator', {configurable: true, value: {locks: {request: async (_key, _options, work) => work({})}}});
  globalThis.fetch = async url => Response.json(url.includes('/accounts/')
    ? {account_id: owner, sequence: '10'} : {hash: url.split('/').pop(), ledger: 42, successful: true});
  const trace = [];
  const state = {walletMissing: false};
  const steps = ['1', '2'];
  const host = {
    admitPortableBuild: () => true,
    verifyInstallation: async () => {trace.push('verified installation');},
    request: async (path, body) => {
      trace.push(path);
      switch (path) {
        case 'authoring/adopt': return {policies: [policy], selectedId: policyId};
        case 'native/templates': return {server, templates: [{network, asset, assetSymbol: 'XLM', assetIssuer: null, maxFeeStroops: 1000, tiers: {common: moduleDigest}}]};
        case 'native/config?network=stellar:testnet': return {enginePublicKey: server};
        case 'native/deploy/prepare': return state.walletMissing
          ? {policyId, wallet, step: {...fundStep('9'), action: 'create_wallet'}}
          : {policyId, installed: true, installation: {wallet}};
        case 'micro/policies': return {policies: [policy]};
        case 'native/owner/prepare': return {policyId, wallet, step: fundStep(steps.shift())};
        case 'native/owner/submit': return submit(body);
        case 'native/export': return exported;
        default: throw new Error(path);
      }
    },
  };
  return {entries, trace, state, input: {host, proposal, session, agent, amount: '2', current: () => true, onStep: () => {}}};
}
const confirmed = body => ({policyId, action: 'fund', status: 'confirmed', transactionHash: body.transactionXdr.slice(4, 5).repeat(64), ledger: 42});

test('verifies the installation, funds once, and exports only a public profile', async () => {
  signatures.length = 0;
  const {entries, trace, state, input} = browser(confirmed);
  const first = await deployAdkOwnerDraft(input);
  assert.equal(first.policyId, policyId);
  assert.equal(first.wallet, wallet);
  assert.doesNotMatch(first.publicProfile, /unexpected/);
  assert.ok(trace.indexOf('verified installation') < trace.indexOf('native/owner/prepare'));
  assert.deepEqual(await deployAdkOwnerDraft(input), first);
  assert.equal(signatures.length, 1);
  assert.equal(trace.filter(path => path === 'native/owner/submit').length, 1);
  // A sent step with an unknown result blocks every new signature.
  const key = adkOwnerKey(owner, proposal);
  const saved = JSON.parse(entries.get(key));
  const pending = JSON.stringify({...saved, pending: {...saved.funded, sent: true}, funded: undefined});
  entries.set(key, pending);
  state.walletMissing = true;
  await assert.rejects(deployAdkOwnerDraft(input), /Check the saved owner transaction/);
  assert.equal(signatures.length, 1);
  assert.equal(entries.get(key), pending);
});

test('a lost send expires, and then the owner signs a new step', async t => {
  signatures.length = 0;
  let lost = true;
  const {entries, input} = browser(body => {
    if (lost) throw Object.assign(new Error('The service could not be reached.'), {code: ''});
    if (body.transactionXdr === 'AAAA1signed') throw Object.assign(new Error('The owner transaction expired.'), {
      code: 'owner_transaction_expired', details: {policyId, action: 'fund', transactionHash: '1'.repeat(64)},
    });
    return confirmed(body);
  });
  await assert.rejects(deployAdkOwnerDraft(input), /could not be reached/);
  const key = adkOwnerKey(owner, proposal);
  assert.equal(JSON.parse(entries.get(key)).pending.sent, true);
  lost = false;
  const late = (now() + 61) * 1000;
  t.mock.method(Date, 'now', () => late);
  const result = await deployAdkOwnerDraft(input);
  assert.equal(result.wallet, wallet);
  assert.deepEqual(signatures, ['AAAA1', 'AAAA2']);
  assert.equal(JSON.parse(entries.get(adkOwnerArchiveKey(owner, '1'.repeat(64)))).signedXdr, 'AAAA1signed');
  const journal = JSON.parse(entries.get(key));
  assert.equal(journal.pending, undefined);
  assert.equal(journal.funded.step.transactionHash, '2'.repeat(64));
});

test('a wrong wallet signature is never saved, so the owner can sign again', async () => {
  signatures.length = 0;
  forged.add('AAAA1signed');
  const {entries, input} = browser(confirmed);
  await assert.rejects(deployAdkOwnerDraft(input), /signature is invalid/);
  assert.equal(entries.get(adkOwnerKey(owner, proposal)), undefined);
  const result = await deployAdkOwnerDraft(input);
  assert.equal(result.wallet, wallet);
  assert.deepEqual(signatures, ['AAAA1', 'AAAA2']);
  forged.clear();
});
