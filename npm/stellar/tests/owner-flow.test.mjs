import assert from 'node:assert/strict';
import test, {beforeEach} from 'node:test';
import {Account, Keypair, Networks, Operation, TransactionBuilder} from '@stellar/stellar-sdk/base';
import {installAndFund as flow, ownerArchiveKey, OwnerFlowError, updateParams as update} from '../dist/owner-flow.js';

const network = 'stellar:testnet';
const installAndFund = input => flow({network, historyPauseMs: 0, ...input});
/** History holds every asked transaction as successful in ledger 7, unless a test replaces it. */
const settledHistory = async url => new Response(JSON.stringify({hash: new URL(url).pathname.split('/').pop(), ledger: 7, successful: true}));
beforeEach(() => { globalThis.fetch = settledHistory; });

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
function expired(action, validUntil = Math.floor(Date.now() / 1000) - 60) {
  const owner = Keypair.random();
  const transaction = new TransactionBuilder(new Account(owner.publicKey(), '41'), {fee: '100', networkPassphrase: Networks.TESTNET})
    .addOperation(Operation.bumpSequence({bumpTo: '0'})).setTimebounds(0, validUntil).build();
  transaction.sign(owner);
  const txHash = Buffer.from(transaction.hash()).toString('hex');
  const lost = {step: {action, payload: 'unsigned', hash: txHash, expiresAt: Math.floor(Date.now() / 1000) - 60}, signedPayload: transaction.toXDR()};
  const horizon = replies => {
    const seen = [];
    globalThis.fetch = async url => {
      const path = new URL(url).pathname;
      if (path.startsWith('/transactions/') && !path.endsWith(txHash)) return settledHistory(url);
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
  // The signed time bound decides, not the step metadata: a transaction that is valid for another hour, or that
  // has no time bound, can still apply, so it is never replaced.
  for (const validUntil of [Math.floor(Date.now() / 1000) + 3_600, 0]) {
    const live = expired('fund', validUntil);
    live.horizon({root: live.past, transaction: {status: 404}, account: live.account('41')});
    const signed = [], journal = journalOf({[key]: JSON.stringify(live.lost)});
    const {ask, state} = service({submit: live.refuse});
    state.installed = true;
    await assert.rejects(installAndFund({ask, sign: signer(signed), journal, key, policyId, agent, amount, onStep() {}}), error => error.retry === true);
    assert.deepEqual(signed, []);
    assert.deepEqual(JSON.parse(journal.get(key)), live.lost);
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
  const {ask, state} = service({submit: () => { throw refusal('owner_transaction_settled', {policyId, action: 'fund', transactionHash: hash(5), ledger: 7}); }});
  state.installed = true;
  const result = await installAndFund({ask, sign: signer(signed), journal, key, policyId, agent, amount, onStep() {}});
  assert.deepEqual(signed, []);
  assert.deepEqual(result.receipts, [{policyId, action: 'fund', status: 'confirmed', transactionHash: hash(5), ledger: 7}]);
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
  const chain = reply => { globalThis.fetch = async url => { if (!url.endsWith(hash(5))) return settledHistory(url); if (!reply) throw new Error('offline'); return new Response(JSON.stringify(reply.body), {status: reply.status ?? 200}); }; };
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

test('a confirmation is trusted only when history holds that successful transaction', async () => {
  const history = replies => { let n = 0; globalThis.fetch = async url => { const reply = replies[Math.min(n++, replies.length - 1)]; if (!reply) throw new Error('offline'); return new Response(JSON.stringify(reply.body ?? {hash: new URL(url).pathname.split('/').pop(), ledger: 7, successful: true}), {status: reply.status ?? 200}); }; };
  for (const unproven of [[null], [{status: 404}], [{status: 500}], [{body: {hash: hash(1), ledger: 7, successful: false}}], [{body: {hash: hash(1), ledger: 8, successful: true}}], [{body: {hash: hash(2), ledger: 7, successful: true}}]]) {
    history(unproven);
    const signed = [], journal = journalOf();
    const {ask} = service({submit: confirmed});
    await assert.rejects(installAndFund({ask, sign: signer(signed), journal, key, policyId, agent, amount, onStep() {}}),
      error => error instanceof OwnerFlowError && error.retry === true && /could not be checked/.test(error.message));
    // The signed bytes stay saved and nothing is marked as funded.
    assert.deepEqual(signed, ['create_wallet']);
    assert.equal(JSON.parse(journal.get(key)).signedPayload, 'signed-create_wallet-1');
    assert.equal(journal.get(`${key}:funded`), null);
  }
  // History that trails the network by one read still settles the step.
  history([{status: 404}, {}]);
  const signed = [], journal = journalOf();
  const {ask} = service({submit: confirmed});
  const result = await installAndFund({ask, sign: signer(signed), journal, key, policyId, agent, amount, onStep() {}});
  assert.deepEqual(result.receipts.map(r => [r.action, r.ledger]), [['create_wallet', 7], ['fund', 7]]);
  // A settled reply that history does not confirm keeps the saved funding and records nothing.
  history([{body: {hash: hash(5), ledger: 7, successful: false}}]);
  const pending = {step: savedStep('fund', 5), signedPayload: 'signed-fund-5', policyId, agent, amount};
  const kept = journalOf({[key]: JSON.stringify(pending)});
  const settled = service({submit: () => { throw refusal('owner_transaction_settled', {policyId, action: 'fund', transactionHash: hash(5), ledger: 7}); }});
  settled.state.installed = true;
  await assert.rejects(installAndFund({ask: settled.ask, sign: signer([]), journal: kept, key, policyId, agent, amount, onStep() {}}), error => error.retry === true);
  assert.deepEqual(JSON.parse(kept.get(key)), pending);
  assert.equal(kept.get(`${key}:funded`), null);
});

const updateParams = input => update({network, historyPauseMs: 0, ...input});
const params = {daily_spending_limit: {Int: '50000000'}};
/** A service that prepares one `update_params` step for each asked change. */
function updates({submit, prepare}) {
  const calls = [], state = {prepared: 0};
  const ask = async (path, body) => {
    calls.push([path, body]);
    if (path === 'native/owner/prepare') return prepare ? prepare(body, state) : {policyId, step: step('update_params', ++state.prepared)};
    if (path === 'native/owner/submit') return submit(body, state);
    throw new Error(path);
  };
  return {ask, calls, state};
}

test('a params update signs one step, sends the typed values and is never signed again under its key', async () => {
  const signed = [], journal = journalOf();
  const {ask, calls} = updates({submit: confirmed});
  const input = {ask, sign: signer(signed), journal, key, policyId, params, expectedRevision: 3, onStep() {}};
  const result = await updateParams(input);
  assert.deepEqual([result.done, result.receipts.map(r => r.action)], [true, ['update_params']]);
  assert.deepEqual(signed, ['update_params']);
  assert.deepEqual(calls[0], ['native/owner/prepare', {policyId, action: 'update_params', params, expectedRevision: 3}]);
  assert.equal(journal.get(key), null);
  // The same change under the same key is done: nothing is prepared or signed.
  const again = await updateParams(input);
  assert.deepEqual([again.done, again.receipts.length, signed.length, calls.length], [true, 0, 1, 2]);
  // Another change under that key is refused before anything is sent.
  await assert.rejects(updateParams({...input, params: {daily_spending_limit: {Int: '1'}}}), error => error instanceof OwnerFlowError && !error.retry);
  assert.equal(calls.length, 2);
});

test('a resumed params update settles the saved signed step first and asks for no second signature', async () => {
  const signed = [], journal = journalOf();
  let lost = true;
  const {ask, calls} = updates({submit: body => {
    if (lost) throw refusal('owner_transaction_pending', {});
    return confirmed(body);
  }});
  const input = {ask, sign: signer(signed), journal, key, policyId, params, onStep() {}};
  await assert.rejects(updateParams(input), error => error.code === 'owner_transaction_pending' && error.retry === true);
  const saved = JSON.parse(journal.get(key));
  assert.equal(saved.signedPayload, 'signed-update_params-1');
  lost = false;
  const result = await updateParams(input);
  assert.deepEqual([result.done, result.receipts.length, signed.length], [true, 1, 1]);
  // The resume sent the saved bytes and prepared nothing new.
  assert.deepEqual(calls.filter(([path]) => path === 'native/owner/prepare').length, 1);
  assert.deepEqual(calls.at(-1), ['native/owner/submit', {policyId, payload: 'signed-update_params-1'}]);
  // A saved wallet setup step under this key belongs to other inputs and is refused.
  const other = journalOf({[key]: JSON.stringify({step: savedStep('fund', 4), signedPayload: 'signed-fund-4', policyId, agent, amount})});
  await assert.rejects(updateParams({...input, journal: other}), error => error instanceof OwnerFlowError && !error.retry);
});

test('a refused params update keeps the typed code of the service and signs nothing', async () => {
  for (const code of ['param_out_of_range', 'param_invalid', 'update_unavailable', 'revision_changed']) {
    const signed = [], journal = journalOf();
    const {ask} = updates({submit: confirmed, prepare: () => { throw refusal(code, {param: 'daily_spending_limit'}, 400); }});
    await assert.rejects(updateParams({ask, sign: signer(signed), journal, key, policyId, params, onStep() {}}),
      error => error instanceof OwnerFlowError && error.code === code && error.retry === false);
    assert.deepEqual([signed.length, journal.map.size], [0, 0]);
  }
  // A reply for another policy or another action is refused before the wallet opens.
  for (const reply of [{policyId: 'other', step: step('update_params', 1)}, {policyId, step: step('fund', 1)}, {policyId}]) {
    const signed = [];
    const {ask} = updates({submit: confirmed, prepare: () => reply});
    await assert.rejects(updateParams({ask, sign: signer(signed), journal: journalOf(), key, policyId, params, onStep() {}}), OwnerFlowError);
    assert.equal(signed.length, 0);
  }
  // No change, or too many, never reaches the service.
  const {ask, calls} = updates({submit: confirmed});
  await assert.rejects(updateParams({ask, sign: signer([]), journal: journalOf(), key, policyId, params: {}, onStep() {}}), error => error.code === 'param_invalid');
  assert.equal(calls.length, 0);
});
