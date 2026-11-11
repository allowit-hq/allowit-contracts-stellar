import assert from 'node:assert/strict';
import test from 'node:test';
import {installAndFund, ownerArchiveKey, OwnerFlowError} from '../dist/owner-flow.js';

const policyId = 'policy-1', key = 'flow:owner:1', agent = 'GAGENT', amount = '5';
const hash = n => String(n).repeat(64).slice(0, 64);
const step = (action, n) => ({action, payload: `unsigned-${action}-${n}`, transactionHash: hash(n), expiresAt: Math.floor(Date.now() / 1000) + 300});
const savedStep = (action, n) => ({action, payload: `unsigned-${action}-${n}`, hash: hash(n), expiresAt: Math.floor(Date.now() / 1000) - 60});
const refusal = (code, details, status = 409) => Object.assign(new Error(code), {status, code, details});

/** A service that installs after one `create_wallet` step and then prepares one `fund` step. */
function service({submit}) {
  const calls = [], state = {installed: false, prepared: 0};
  const ask = async (path, body) => {
    calls.push([path, body]);
    if (path === 'native/deploy/prepare')
      return state.installed ? {policyId, installed: true, installation: {wallet: 'CWALLET'}} : {policyId, wallet: 'CWALLET', step: step('create_wallet', ++state.prepared)};
    if (path === 'native/owner/prepare') return {policyId, step: step('fund', ++state.prepared)};
    if (path === 'native/owner/submit') {
      const reply = await submit(body, state);
      if (reply.action === 'create_wallet') state.installed = true;
      return reply;
    }
    throw new Error(path);
  };
  return {ask, calls, state};
}
function journalOf(entries = {}) {
  const map = new Map(Object.entries(entries));
  return {map, get: k => map.get(k) ?? null, set: (k, v) => void map.set(k, v), remove: k => void map.delete(k)};
}
const confirmed = body => {
  const [, action, n] = body.payload.split('-');
  return {policyId, action, status: 'confirmed', transactionHash: hash(n), ledger: 7};
};
const signer = signed => async s => (signed.push(s.action), `signed-${s.action}-${s.hash[0]}`);

test('the happy path installs, funds and never signs a confirmed funding again', async () => {
  const signed = [], journal = journalOf();
  const {ask, calls} = service({submit: confirmed});
  const input = {ask, sign: signer(signed), journal, key, policyId, agent, amount, onStep() {}};
  const result = await installAndFund(input);
  assert.equal(result.wallet, 'CWALLET');
  assert.deepEqual(result.receipts.map(r => r.action), ['create_wallet', 'fund']);
  assert.deepEqual(signed, ['create_wallet', 'fund']);
  assert.equal(journal.get(key), null);
  assert.equal(journal.get(`${key}:funded`), 'confirmed');
  assert.deepEqual(calls.find(([path]) => path === 'native/owner/prepare')[1], {policyId, action: 'fund', amount});
  const again = await installAndFund(input);
  assert.deepEqual([again.wallet, again.receipts.length, signed.length], ['CWALLET', 0, 2]);
});

test('a lost send that expired is archived and the owner signs a new step', async () => {
  const lost = {step: savedStep('create_wallet', 9), signedPayload: 'signed-create_wallet-9'};
  const signed = [], journal = journalOf({[key]: JSON.stringify(lost)});
  const {ask} = service({submit: body => {
    if (body.payload === lost.signedPayload) throw refusal('owner_transaction_expired', {policyId, action: 'create_wallet', transactionHash: hash(9)});
    return confirmed(body);
  }});
  const result = await installAndFund({ask, sign: signer(signed), journal, key, policyId, agent, amount, onStep() {}});
  assert.deepEqual(signed, ['create_wallet', 'fund']);
  assert.deepEqual(result.receipts.map(r => r.transactionHash), [hash(1), hash(2)]);
  assert.deepEqual(JSON.parse(journal.get(ownerArchiveKey(key, hash(9)))), lost);
  assert.equal(journal.get(key), null);
});

test('a saved step that already settled is done without a second signature', async () => {
  const saved = {step: savedStep('fund', 5), signedPayload: 'signed-fund-5'};
  const signed = [], journal = journalOf({[key]: JSON.stringify(saved)});
  const {ask, state} = service({submit: () => { throw refusal('owner_transaction_settled', {policyId, action: 'fund', transactionHash: hash(5), ledger: 42}); }});
  state.installed = true;
  const result = await installAndFund({ask, sign: signer(signed), journal, key, policyId, agent, amount, onStep() {}});
  assert.deepEqual(signed, []);
  assert.deepEqual(result.receipts, [{policyId, action: 'fund', status: 'confirmed', transactionHash: hash(5), ledger: 42}]);
  assert.equal(journal.get(`${key}:funded`), 'confirmed');
});

test('pending, unavailable, foreign and untyped replies keep the saved step and sign nothing', async () => {
  const saved = {step: savedStep('fund', 5), signedPayload: 'signed-fund-5'};
  const cases = [
    [refusal('owner_transaction_pending', {policyId, action: 'fund', transactionHash: hash(5)}), 'owner_transaction_pending', true],
    [refusal('network_unavailable', {retry: 'same_request_id'}, 503), 'network_unavailable', true],
    // A network error without the retry promise is not a safe retry signal.
    [refusal('network_unavailable', {}, 503), 'network_unavailable', false],
    // An expiry or settlement that names another transaction settles nothing.
    [refusal('owner_transaction_expired', {policyId, action: 'fund', transactionHash: hash(6)}), 'owner_transaction_expired', false],
    [refusal('owner_transaction_settled', {policyId: 'other', transactionHash: hash(5)}), 'owner_transaction_settled', false],
    [new Error('socket closed'), null, false],
  ];
  for (const [thrown, code, retry] of cases) {
    const signed = [], journal = journalOf({[key]: JSON.stringify(saved)});
    const {ask} = service({submit: () => { throw thrown; }});
    await assert.rejects(installAndFund({ask, sign: signer(signed), journal, key, policyId, agent, amount, onStep() {}}),
      error => error instanceof OwnerFlowError && error.code === code && error.retry === retry);
    assert.deepEqual(signed, []);
    assert.deepEqual(JSON.parse(journal.get(key)), saved);
    assert.equal(journal.get(`${key}:funded`), null);
  }
});

test('signed bytes enter the journal before the send, and a wrong receipt or reply is refused', async () => {
  const signed = [], journal = journalOf();
  const {ask} = service({submit: body => ({...confirmed(body), transactionHash: hash(8)})});
  await assert.rejects(installAndFund({ask, sign: signer(signed), journal, key, policyId, agent, amount, onStep() {}}), /did not confirm/);
  assert.equal(JSON.parse(journal.get(key)).signedPayload, 'signed-create_wallet-1');
  const other = service({submit: confirmed});
  await assert.rejects(installAndFund({ask: async (path, body) => ({...await other.ask(path, body), policyId: 'other'}), sign: signer([]), journal: journalOf(), key, policyId, agent, amount, onStep() {}}), /different policy/);
  await assert.rejects(installAndFund({ask, sign: signer([]), journal: journalOf({[key]: '{bad'}), key, policyId, agent, amount, onStep() {}}), /unreadable/);
});
