import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import test, {mock} from 'node:test';
import {Keypair} from '@stellar/stellar-sdk/base';

const passphrase = 'Test SDF Network ; September 2015';
const [owner, agent, server] = [1, 2, 3].map(seed => Keypair.fromRawEd25519Seed(Buffer.alloc(32, seed)).publicKey());
const wallet = 'C' + 'A'.repeat(55);
const signatures = [];
const selections = [];
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
  deriveAdkOwnerWallet: async () => wallet,
  verifyAdkOwnerStep: async (step, expected) => {
    selections.push([step.action, expected.maxFeeStroops]);
    // A renewal step carries the sequence that it was prepared with after an S.
    const [, prepared] = step.transactionXdr.split('S');
    if (prepared !== undefined && prepared !== expected.nextSequence) throw new Error('The prepared sequence differs from the owner account.');
  },
  verifyAdkOwnerSignature: async (_step, _expected, signedXdr) => {
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
  version: 1, profile: 'allowit-wallet-v1', policyId, network, route: 'policyWallet', wallet,
  sourceHash: proposal.sourceHash, moduleDigest, irHash: '', unexpected: 'ignored',
  config: {wallet, owner, agent, server, network, route: 'policyWallet', policySource: code, asset,
    assetSymbol: 'XLM', assetIssuer: null, maxFeeStroops: 1000, policyInstance: bytes(policyInstance),
    sourceHash: bytes(proposal.sourceHash), moduleDigest: bytes(moduleDigest), sourceDigest: bytes('f'.repeat(64)), unexpected: 'ignored'},
  endpoints: {execute: '/api/native/execute', status: '/api/native/execute/status'},
};
const now = () => Math.floor(Date.now() / 1000);
const fundStep = id => ({network, action: 'fund', transactionXdr: `AAAA${id}`, transactionHash: id.repeat(64), expiresAt: now() + 60});

/**
 * A browser, server and Horizon model. `submit` answers each owner submission, and each answer uses one owner
 * sequence. Horizon has no record of a hash in `state.missing`.
 */
function browser(submit) {
  const entries = new Map();
  globalThis.localStorage = {getItem: key => entries.get(key) ?? null, setItem: (key, value) => entries.set(key, value)};
  Object.defineProperty(globalThis, 'navigator', {configurable: true, value: {locks: {request: async (_key, _options, work) => work({})}}});
  const trace = [];
  const state = {walletMissing: false, renewalDue: false, sequence: 10, missing: new Set(), closedAt: undefined};
  globalThis.fetch = async url => {
    const path = url.slice('https://horizon-testnet.stellar.org'.length);
    if (path === '/') return Response.json({history_latest_ledger_closed_at: new Date(state.closedAt ?? Date.now()).toISOString()});
    if (path.startsWith('/accounts/')) return Response.json({account_id: owner, sequence: String(state.sequence)});
    const hash = path.split('/').pop();
    if (state.missing.has(hash)) return new Response(null, {status: 404});
    return Response.json({hash, ledger: 42, successful: true});
  };
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
        case 'native/deploy/prepare':
          if (state.walletMissing) return {policyId, wallet, step: {...fundStep('9'), action: 'create_wallet'}};
          if (state.renewalDue) return {policyId, wallet, step: {...fundStep('8'), action: 'extend', transactionXdr: `AAAA8S${state.sequence + 1}`}};
          return {policyId, installed: true, installation: {wallet}};
        case 'micro/policies': return {policies: [policy]};
        case 'native/owner/prepare': return {policyId, wallet, step: fundStep(steps.shift())};
        case 'native/owner/submit': {
          const receipt = await submit(body);
          state.sequence++;
          return receipt;
        }
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
  const {entries, state, input} = browser(body => {
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
  // The lost send never reached the network.
  state.missing.add('1'.repeat(64));
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

test('an installed wallet that needs renewal signs the renewal, then the funding', async () => {
  signatures.length = 0;
  const {trace, state, input} = browser(body => {
    const receipt = confirmed(body);
    if (receipt.transactionHash !== '8'.repeat(64)) return receipt;
    state.renewalDue = false;
    return {...receipt, action: 'extend'};
  });
  state.renewalDue = true;
  const result = await deployAdkOwnerDraft(input);
  assert.equal(result.wallet, wallet);
  assert.deepEqual(signatures, ['AAAA8S11', 'AAAA1']);
  assert.equal(trace.filter(path => path === 'native/deploy/prepare').length, 2);
  // A renewal keeps the installed policy fee ceiling, not the deployment ceiling.
  assert.deepEqual(selections.slice(-2), [['extend', 1000], ['fund', 1000]]);
});

test('a funding result lost before a renewal is due is settled, and then the owner signs the renewal', async () => {
  signatures.length = 0;
  const {entries, state, input} = browser(body => {
    const receipt = confirmed(body);
    if (receipt.transactionHash !== '8'.repeat(64)) return receipt;
    state.renewalDue = false;
    return {...receipt, action: 'extend'};
  });
  await deployAdkOwnerDraft(input);
  const key = adkOwnerKey(owner, proposal);
  const saved = JSON.parse(entries.get(key));
  entries.set(key, JSON.stringify({...saved, pending: {...saved.funded, sent: true}, funded: undefined}));
  // The funding has not reached the network yet, so the first renewal uses the funding's sequence.
  state.sequence = 10;
  state.renewalDue = true;
  const result = await deployAdkOwnerDraft(input);
  assert.equal(result.wallet, wallet);
  assert.deepEqual(signatures, ['AAAA1', 'AAAA8S12']);
  assert.equal(JSON.parse(entries.get(key)).funded.step.transactionHash, '1'.repeat(64));
});

/** A funding send whose reply is lost, then a server expiry reply after its time bound. */
async function expiredFunding(t) {
  signatures.length = 0;
  let lost = true;
  const model = browser(body => {
    if (lost) throw Object.assign(new Error('The service could not be reached.'), {code: ''});
    if (body.transactionXdr === 'AAAA1signed') throw Object.assign(new Error('The owner transaction expired.'), {
      code: 'owner_transaction_expired', details: {policyId, action: 'fund', transactionHash: '1'.repeat(64)},
    });
    return confirmed(body);
  });
  await assert.rejects(deployAdkOwnerDraft(model.input), /could not be reached/);
  lost = false;
  const late = (now() + 61) * 1000;
  t.mock.method(Date, 'now', () => late);
  return model;
}

test('an expiry reply for a funding that Horizon shows applied settles it, so no second funding is signed', async t => {
  const {entries, state, input} = await expiredFunding(t);
  // The send reached the network, and only its reply was lost.
  state.sequence = 11;
  const result = await deployAdkOwnerDraft(input);
  assert.equal(result.wallet, wallet);
  assert.deepEqual(signatures, ['AAAA1']);
  const journal = JSON.parse(entries.get(adkOwnerKey(owner, proposal)));
  assert.equal(journal.pending, undefined);
  assert.equal(journal.funded.step.transactionHash, '1'.repeat(64));
  assert.equal(entries.get(adkOwnerArchiveKey(owner, '1'.repeat(64))), undefined);
});

test('an expiry reply never drops a funding that Horizon cannot exclude', async t => {
  const {entries, state, input} = await expiredFunding(t);
  const key = adkOwnerKey(owner, proposal);
  const saved = entries.get(key);
  state.missing.add('1'.repeat(64));
  // Horizon has not read past the time bound.
  state.closedAt = 0;
  await assert.rejects(deployAdkOwnerDraft(input), /expired Stellar transaction could not be checked/);
  // The owner sequence reached the funding sequence, so another transaction or a lost record can explain the gap.
  state.closedAt = undefined;
  state.sequence = 11;
  await assert.rejects(deployAdkOwnerDraft(input), /expired Stellar transaction could not be checked/);
  assert.deepEqual(signatures, ['AAAA1']);
  assert.equal(entries.get(key), saved);
});
