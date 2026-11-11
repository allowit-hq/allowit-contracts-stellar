import assert from 'node:assert/strict';
import test from 'node:test';
import {Account, Keypair, Networks, Operation, TransactionBuilder} from '@stellar/stellar-sdk/base';
import {installAndFund as flow, ownerArchiveKey, OwnerFlowError} from '../dist/owner-flow.js';

const network = 'stellar:testnet';
const installAndFund = input => flow({network, ...input});

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
  assert.deepEqual(JSON.parse(journal.get(`${key}:funded`)), {policyId, agent, amount});
  assert.deepEqual(calls.find(([path]) => path === 'native/owner/prepare')[1], {policyId, action: 'fund', amount});
  const again = await installAndFund(input);
  assert.deepEqual([again.wallet, again.receipts.length, signed.length], ['CWALLET', 0, 2]);
});

/** A real signed transaction past its time bound, with the chain replies of one scenario. */
function expired(action) {
  const owner = Keypair.random();
  const transaction = new TransactionBuilder(new Account(owner.publicKey(), '41'), {fee: '100', networkPassphrase: Networks.TESTNET})
    .addOperation(Operation.bumpSequence({bumpTo: '0'})).setTimebounds(0, Math.floor(Date.now() / 1000) - 60).build();
  transaction.sign(owner);
  const txHash = Buffer.from(transaction.hash()).toString('hex');
  const lost = {step: {action, payload: 'unsigned', hash: txHash, expiresAt: Math.floor(Date.now() / 1000) - 60}, signedPayload: transaction.toXDR()};
  const horizon = replies => {
    const seen = [];
    globalThis.fetch = async url => {
      const path = new URL(url).pathname;
      seen.push(path);
      const reply = path === '/' ? replies.root : path.startsWith('/transactions/') ? replies.transaction : replies.account;
      if (reply === undefined) throw new Error('offline');
      return new Response(JSON.stringify(reply.body ?? {}), {status: reply.status ?? 200});
    };
    return seen;
  };
  const past = {body: {history_latest_ledger_closed_at: new Date().toISOString()}};
  const account = sequence => ({body: {account_id: owner.publicKey(), sequence}});
  const refuse = () => { throw refusal('owner_transaction_expired', {policyId, action, transactionHash: txHash}); };
  return {lost, txHash, horizon, past, account, refuse};
}

test('a lost send that expired and never applied is archived, and the owner signs a new step', async () => {
  const {lost, txHash, horizon, past, account, refuse} = expired('create_wallet');
  // Horizon read past the time bound, holds no transaction, and the owner sequence is below the transaction's.
  const seen = horizon({root: past, transaction: {status: 404}, account: account('41')});
  const signed = [], journal = journalOf({[key]: JSON.stringify(lost)});
  const {ask} = service({submit: body => body.payload === lost.signedPayload ? refuse() : confirmed(body)});
  const result = await installAndFund({ask, sign: signer(signed), journal, key, policyId, agent, amount, onStep() {}});
  assert.deepEqual(signed, ['create_wallet', 'fund']);
  assert.deepEqual(result.receipts.map(r => r.transactionHash), [hash(1), hash(2)]);
  assert.deepEqual(JSON.parse(journal.get(ownerArchiveKey(key, txHash))), lost);
  assert.equal(journal.get(key), null);
  assert.equal(seen.length, 3);
});

test('an expired funding that the chain shows applied is done and is never funded again', async () => {
  const {lost, txHash, horizon, past, refuse} = expired('fund');
  horizon({root: past, transaction: {body: {hash: txHash, ledger: 77, successful: true}}});
  const signed = [], journal = journalOf({[key]: JSON.stringify(lost)});
  const {ask, state, calls} = service({submit: refuse});
  state.installed = true;
  const result = await installAndFund({ask, sign: signer(signed), journal, key, policyId, agent, amount, onStep() {}});
  assert.deepEqual(signed, []);
  assert.deepEqual(result.receipts, [{policyId, action: 'fund', status: 'confirmed', transactionHash: txHash, ledger: 77}]);
  assert.deepEqual(JSON.parse(journal.get(`${key}:funded`)), {policyId, agent, amount});
  assert.equal(calls.some(([path]) => path === 'native/owner/prepare'), false);
});

test('an expiry reply without chain proof keeps the saved step and signs nothing', async () => {
  const {lost, txHash, horizon, past, account, refuse} = expired('fund');
  const stale = {body: {history_latest_ledger_closed_at: new Date((lost.step.expiresAt - 10) * 1000).toISOString()}};
  const scenarios = [
    {},                                                                  // Horizon is offline.
    {root: stale, transaction: {status: 404}, account: account('41')},   // Horizon has not read past the time bound.
    {root: past, transaction: {status: 404}, account: account('42')},    // The sequence moved: the transaction may have applied.
    {root: past, transaction: {status: 404}, account: {status: 404}},    // The account cannot be read.
    {root: past, transaction: {status: 500}},                            // The transaction lookup failed.
    {root: past, transaction: {body: {hash: hash(3), ledger: 5, successful: true}}}, // Another transaction.
  ];
  for (const replies of scenarios) {
    horizon(replies);
    const signed = [], journal = journalOf({[key]: JSON.stringify(lost)});
    const {ask, state} = service({submit: refuse});
    state.installed = true;
    await assert.rejects(installAndFund({ask, sign: signer(signed), journal, key, policyId, agent, amount, onStep() {}}),
      error => error instanceof OwnerFlowError && error.code === 'owner_transaction_expired' && error.retry === true);
    assert.deepEqual(signed, []);
    assert.deepEqual(JSON.parse(journal.get(key)), lost);
    assert.equal(journal.get(ownerArchiveKey(key, txHash)), null);
    assert.equal(journal.get(`${key}:funded`), null);
  }
  // A step whose payload is not that transaction, or whose time bound has not passed, is never dropped either.
  horizon({root: past, transaction: {status: 404}, account: account('41')});
  for (const altered of [{...lost, signedPayload: 'not-xdr'}, {...lost, step: {...lost.step, expiresAt: Math.floor(Date.now() / 1000) + 300}}]) {
    const journal = journalOf({[key]: JSON.stringify(altered)});
    const {ask, state} = service({submit: refuse});
    state.installed = true;
    await assert.rejects(installAndFund({ask, sign: signer([]), journal, key, policyId, agent, amount, onStep() {}}), error => error.retry === true);
    assert.deepEqual(JSON.parse(journal.get(key)), altered);
  }
});

test('one workflow runs per journal key, so a second call never signs', async () => {
  const signed = [], journal = journalOf();
  const {ask} = service({submit: confirmed});
  const input = {ask, sign: signer(signed), journal, key, policyId, agent, amount, onStep() {}};
  const [first, second] = await Promise.allSettled([installAndFund(input), installAndFund(input)]);
  assert.equal(first.status, 'fulfilled');
  assert.ok(second.reason instanceof OwnerFlowError && second.reason.retry && /already running/.test(second.reason.message));
  assert.deepEqual(signed, ['create_wallet', 'fund']);
  await assert.rejects(flow({...input, network: 'other:testnet'}), /supported Stellar network/);
});

test('a saved step that already settled is done without a second signature', async () => {
  const saved = {step: savedStep('fund', 5), signedPayload: 'signed-fund-5'};
  const signed = [], journal = journalOf({[key]: JSON.stringify(saved)});
  const {ask, state} = service({submit: () => { throw refusal('owner_transaction_settled', {policyId, action: 'fund', transactionHash: hash(5), ledger: 42}); }});
  state.installed = true;
  const result = await installAndFund({ask, sign: signer(signed), journal, key, policyId, agent, amount, onStep() {}});
  assert.deepEqual(signed, []);
  assert.deepEqual(result.receipts, [{policyId, action: 'fund', status: 'confirmed', transactionHash: hash(5), ledger: 42}]);
  assert.deepEqual(JSON.parse(journal.get(`${key}:funded`)), {policyId, agent, amount});
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
  assert.deepEqual(JSON.parse(journal.get(key)), {step: {action: 'create_wallet', payload: 'unsigned-create_wallet-1', hash: hash(1), expiresAt: JSON.parse(journal.get(key)).step.expiresAt}, signedPayload: 'signed-create_wallet-1', policyId, agent, amount});
  const other = service({submit: confirmed});
  await assert.rejects(installAndFund({ask: async (path, body) => ({...await other.ask(path, body), policyId: 'other'}), sign: signer([]), journal: journalOf(), key, policyId, agent, amount, onStep() {}}), /different policy/);
  await assert.rejects(installAndFund({ask, sign: signer([]), journal: journalOf({[key]: '{bad'}), key, policyId, agent, amount, onStep() {}}), /unreadable/);
});

test('a resume with another amount, agent or policy is refused before anything is sent', async () => {
  const pending = {step: savedStep('fund', 5), signedPayload: 'signed-fund-5', policyId, agent, amount};
  for (const [entries, changed] of [
    [{[key]: JSON.stringify(pending)}, {amount: '10'}],
    [{[key]: JSON.stringify(pending)}, {agent: 'GOTHER'}],
    [{[key]: JSON.stringify({...pending, amount: undefined})}, {}],
    [{[`${key}:funded`]: JSON.stringify({policyId, agent, amount})}, {amount: '10'}],
    [{[`${key}:funded`]: '{bad'}, {}],
  ]) {
    const signed = [], journal = journalOf(entries), before = new Map(journal.map);
    const {ask, calls} = service({submit: confirmed});
    await assert.rejects(installAndFund({ask, sign: signer(signed), journal, key, policyId, agent, amount, onStep() {}, ...changed}),
      error => error instanceof OwnerFlowError && /original wallet setup/.test(error.message));
    assert.deepEqual([signed, calls], [[], []]);
    assert.deepEqual(journal.map, before);
  }
  // A step and a marker saved without inputs predate them; the same inputs resume them.
  const journal = journalOf({[key]: JSON.stringify({step: savedStep('fund', 5), signedPayload: 'signed-fund-5'}), [`${key}:funded`]: 'confirmed'});
  const {ask, state} = service({submit: confirmed});
  state.installed = true;
  const result = await installAndFund({ask, sign: signer([]), journal, key, policyId, agent, amount, onStep() {}});
  assert.deepEqual(result.receipts.map(r => r.action), ['fund']);
});

test('a failed transaction is replaced only when the chain holds that exact failure', async () => {
  const pending = {step: savedStep('create_wallet', 5), signedPayload: 'signed-create_wallet-5', policyId, agent, amount};
  const failed = body => {
    if (body.payload === pending.signedPayload) throw refusal('owner_transaction_failed', {policyId, action: 'create_wallet', transactionHash: hash(5), ledger: 9});
    return confirmed(body);
  };
  const chain = reply => { globalThis.fetch = async () => { if (!reply) throw new Error('offline'); return new Response(JSON.stringify(reply.body), {status: reply.status ?? 200}); }; };
  for (const unproven of [null, {status: 404, body: {}}, {body: {hash: hash(5), ledger: 9, successful: true}}, {body: {hash: hash(5), ledger: 8, successful: false}}, {body: {hash: hash(6), ledger: 9, successful: false}}]) {
    chain(unproven);
    const signed = [], journal = journalOf({[key]: JSON.stringify(pending)});
    const {ask} = service({submit: failed});
    await assert.rejects(installAndFund({ask, sign: signer(signed), journal, key, policyId, agent, amount, onStep() {}}),
      error => error instanceof OwnerFlowError && error.code === 'owner_transaction_failed' && error.retry === false);
    assert.deepEqual(signed, []);
    assert.deepEqual(JSON.parse(journal.get(key)), pending);
  }
  chain({body: {hash: hash(5), ledger: 9, successful: false}});
  const signed = [], journal = journalOf({[key]: JSON.stringify(pending)});
  const {ask} = service({submit: failed});
  const result = await installAndFund({ask, sign: signer(signed), journal, key, policyId, agent, amount, onStep() {}});
  assert.deepEqual(signed, ['create_wallet', 'fund']);
  assert.equal(result.wallet, 'CWALLET');
  assert.deepEqual(JSON.parse(journal.get(ownerArchiveKey(key, hash(5)))), {step: pending.step, signedPayload: pending.signedPayload});
});
