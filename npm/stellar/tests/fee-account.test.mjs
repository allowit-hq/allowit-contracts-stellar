import assert from 'node:assert/strict';
import test, {beforeEach} from 'node:test';
import {Account, Asset, Keypair, Networks, Operation, StrKey, TransactionBuilder} from '@stellar/stellar-sdk/base';
import * as feeAccountModule from '../dist/fee-account.js';
import {
  countersignCreation, CREATE_FEE_ACCOUNT, feeAccount, feeAccountOf, newFeeAccountKey, REFILL_FEES, refillFees, stroops, xlmText,
} from '../dist/fee-account.js';
import {installAndFund as flow, OwnerFlowError} from '../dist/owner-flow.js';

const network = 'stellar:testnet';
const OWNER_SEED = new Uint8Array(32).fill(1);
const AGENT = 'GCATS5YOVB6ROX2WUNKGNQ2MP3GMXDMKSG2O4N5CLX3A6W4PZGZZI55U';
const WALLET = 'CACAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAINCW';
const ACCOUNT = 'GD2YKHPRFRN2IO3WBQKAQ3YRDJYD5VH6CVIY6PME5GJ54UA6NP5KI2W7';
/** The bytes of a decorated signature. XDR opaque values wrap their bytes in `value`. */
const sig = s => { const v = typeof s.signature === 'function' ? s.signature() : s.signature; return Buffer.from(v instanceof Uint8Array ? v : v.value); };

test('each setup key is new, and the package holds no way to derive or recover one', () => {
  const a = newFeeAccountKey(), b = newFeeAccountKey();
  assert.notEqual(a.publicKey(), b.publicKey());
  assert.ok(StrKey.isValidEd25519PublicKey(a.publicKey()));
  for (const name of Object.keys(feeAccountModule)) assert.ok(!/deriv|seed|recover/i.test(name), name);
});

/** The owner-signed creation of the fee account of `key`, as the wallet returns it. */
function creation(owner, key, sign = true) {
  const tx = new TransactionBuilder(new Account(owner.publicKey(), '41'), {fee: '400', networkPassphrase: Networks.TESTNET})
    .addOperation(Operation.createAccount({destination: key.publicKey(), startingBalance: '7.5'}))
    .addOperation(Operation.setOptions({source: key.publicKey(), masterWeight: 0}))
    .setTimeout(300).build();
  const hash = Buffer.from(tx.hash()).toString('hex');
  if (sign) tx.sign(owner);
  return {tx, hash, payload: tx.toXDR()};
}

test('the new account signs its own creation once, and nothing else', () => {
  const owner = Keypair.random(), key = newFeeAccountKey();
  const {hash, payload} = creation(owner, key);
  const both = TransactionBuilder.fromXDR(countersignCreation(network, {hash}, payload, key), Networks.TESTNET);
  assert.equal(both.signatures.length, 2);
  assert.ok(owner.verify(both.hash(), sig(both.signatures[0])));
  assert.ok(key.verify(both.hash(), sig(both.signatures[1])));
  // Another transaction, the creation of another account, or an unsigned or twice-signed envelope is refused.
  assert.throws(() => countersignCreation(network, {hash: '0'.repeat(64)}, payload, key));
  assert.throws(() => countersignCreation(network, {hash}, payload, Keypair.random()));
  assert.throws(() => countersignCreation(network, {hash}, creation(owner, key, false).payload, key));
  assert.throws(() => countersignCreation(network, {hash}, both.toXDR(), key));
});

test('a document names its fee account, and a wallet without one names none', () => {
  assert.deepEqual(feeAccountOf({config: {feeAccount: ACCOUNT, maxFeeStroops: 10_000_000}}), {address: ACCOUNT, maxFeeStroops: 10_000_000});
  assert.deepEqual(feeAccountOf({feeAccount: ACCOUNT}), {address: ACCOUNT, maxFeeStroops: null});
  for (const document of [{config: {agent: AGENT}}, {config: {feeAccount: WALLET}}, {config: {feeAccount: 'G'}}, null, 'text'])
    assert.equal(feeAccountOf(document), null);
});

const horizonAccount = (address, balance, extra = {}) => ({account_id: address, sequence: '41', subentry_count: 3, num_sponsoring: 0, num_sponsored: 0,
  balances: [{asset_type: 'native', balance, selling_liabilities: '0.0000000'}], ...extra});

test('the fee account read shows the XLM above the reserve and says when it runs low', async () => {
  const document = {config: {feeAccount: ACCOUNT, maxFeeStroops: 10_000_000}};
  const read = async (balance, extra) => feeAccount({network, document, fetch: async url => {
    assert.equal(String(url), `https://horizon-testnet.stellar.org/accounts/${ACCOUNT}`);
    return new Response(JSON.stringify(horizonAccount(ACCOUNT, balance, extra)));
  }});
  // The account and its three signers lock 2.5 XLM. A new fee account holds 5 XLM above that.
  assert.deepEqual(await read('7.5000000'), {address: ACCOUNT, exists: true, balance: '75000000', spendable: '50000000', low: false, text: '5 XLM', refill: {amount: '5', text: '5 XLM'}});
  // Less than two operations at the 1 XLM fee ceiling is low; exactly two is not.
  assert.equal((await read('4.5000000')).low, false);
  assert.deepEqual(await read('4.4999999'), {address: ACCOUNT, exists: true, balance: '44999999', spendable: '19999999', low: true, text: '1.9999999 XLM', refill: {amount: '5', text: '5 XLM'}});
  // A balance at or below the reserve pays nothing.
  assert.deepEqual(await read('2.5000000'), {address: ACCOUNT, exists: true, balance: '25000000', spendable: '0', low: true, text: '0 XLM', refill: {amount: '5', text: '5 XLM'}});
  assert.equal((await read('1.0000000')).spendable, '0');
  // An account that the ledger does not hold was closed, or never created.
  const closed = await feeAccount({network, document, fetch: async () => new Response('{}', {status: 404})});
  assert.deepEqual([closed.exists, closed.low, closed.spendable], [false, true, '0']);
  // A document without a fee account has none to read, and an unreadable reply is an error, never a zero.
  assert.equal(await feeAccount({network, document: {config: {agent: AGENT}}, fetch: async () => { throw new Error('no read'); }}), null);
  await assert.rejects(feeAccount({network, document, fetch: async () => new Response('{}', {status: 500})}));
  await assert.rejects(feeAccount({network, document, fetch: async () => new Response(JSON.stringify(horizonAccount(AGENT, '9.0000000')))}));
});

test('amounts convert without floating point', () => {
  assert.equal(stroops('5'), 50_000_000n);
  assert.equal(stroops('0.0000001'), 1n);
  for (const text of ['', '1.', '.5', '1.00000001', '-1', '1e3', ' 1']) assert.equal(stroops(text), null);
  assert.deepEqual([xlmText(50_000_000n), xlmText(1n), xlmText(0n)], ['5 XLM', '0.0000001 XLM', '0 XLM']);
});

test('the refill is one payment of XLM from the owner to the fee account, sent to the network', async () => {
  const owner = Keypair.random();
  const calls = [];
  let step;
  const send = async (url, init = {}) => {
    calls.push([String(url), init.method ?? 'GET']);
    if (String(url).endsWith(`/accounts/${owner.publicKey()}`)) return new Response(JSON.stringify(horizonAccount(owner.publicKey(), '100.0000000')));
    const signed = TransactionBuilder.fromXDR(decodeURIComponent(String(init.body).slice(3)), Networks.TESTNET);
    return new Response(JSON.stringify({hash: Buffer.from(signed.hash()).toString('hex'), successful: true, ledger: 9}));
  };
  const sign = async prepared => {
    step = prepared;
    const tx = TransactionBuilder.fromXDR(prepared.payload, Networks.TESTNET);
    tx.sign(owner);
    return tx.toXDR();
  };
  const result = await refillFees({network, owner: owner.publicKey(), feeAccount: ACCOUNT, amount: '3.5', sign, onStep() {}, fetch: send});
  assert.equal(step.action, REFILL_FEES);
  const tx = TransactionBuilder.fromXDR(step.payload, Networks.TESTNET);
  assert.equal(Buffer.from(tx.hash()).toString('hex'), step.hash);
  assert.deepEqual([tx.source, tx.sequence, tx.fee, tx.operations.length], [owner.publicKey(), '42', '100', 1]);
  const [payment] = tx.operations;
  assert.deepEqual([payment.type, payment.destination, payment.amount, payment.asset.isNative(), payment.source], ['payment', ACCOUNT, '3.5000000', true, undefined]);
  assert.deepEqual(result, {transactionHash: step.hash, ledger: 9});
  assert.deepEqual(calls.map(([, method]) => method), ['GET', 'POST']);
  // Another signed transaction, a failed send or an invalid amount sends or reports nothing as done.
  const other = async () => {
    const tx = new TransactionBuilder(new Account(owner.publicKey(), '41'), {fee: '100', networkPassphrase: Networks.TESTNET})
      .addOperation(Operation.bumpSequence({bumpTo: '0'})).setTimeout(300).build();
    tx.sign(owner);
    return tx.toXDR();
  };
  const input = {network, owner: owner.publicKey(), feeAccount: ACCOUNT, amount: '1', sign, onStep() {}, fetch: send};
  await assert.rejects(refillFees({...input, sign: other}), /another transaction/);
  await assert.rejects(refillFees({...input, fetch: async (url, init) => init?.method === 'POST' ? new Response('{}', {status: 400}) : send(url, init)}), /did not confirm/);
  for (const amount of ['0', '-1', '1.00000001', 'all']) await assert.rejects(refillFees({...input, amount}));
  await assert.rejects(refillFees({...input, feeAccount: owner.publicKey()}));
});

test('a refill whose result is unknown stays saved and is settled before anything is signed again', async () => {
  const owner = Keypair.random();
  const map = new Map(), journal = {get: k => map.get(k) ?? null, set: (k, v) => void map.set(k, v), remove: k => void map.delete(k)};
  const signedSteps = [];
  const sign = async prepared => {
    signedSteps.push(prepared.hash);
    const tx = TransactionBuilder.fromXDR(prepared.payload, Networks.TESTNET);
    tx.sign(owner);
    return tx.toXDR();
  };
  // What the network holds: `ledger` once the payment applied; `lost` drops the reply of a send that applied.
  // `record` replaces the reply of a transaction read; `sequence` is the owner's sequence when a test sets it.
  const chain = {applied: new Set(), lost: true, posts: [], root: new Date().toISOString(), down: false, record: null, sequence: null};
  const send = async (url, init = {}) => {
    const path = new URL(String(url)).pathname;
    if (chain.down) throw new Error('offline');
    if (init.method === 'POST') {
      const tx = TransactionBuilder.fromXDR(decodeURIComponent(String(init.body).slice(3)), Networks.TESTNET);
      const hash = Buffer.from(tx.hash()).toString('hex');
      chain.posts.push(hash);
      chain.applied.add(hash);
      if (chain.lost) throw new Error('the reply was lost');
      return new Response(JSON.stringify({hash, successful: true, ledger: 9}));
    }
    if (path === '/') return new Response(JSON.stringify({history_latest_ledger_closed_at: chain.root}));
    // Each prepared payment takes the next sequence of the owner, so no two payments of this test are the same.
    if (path.startsWith('/accounts/')) return new Response(JSON.stringify(horizonAccount(owner.publicKey(), '100.0000000', {sequence: chain.sequence ?? String(41 + signedSteps.length)})));
    const hash = path.split('/').pop();
    if (chain.record !== null) return new Response(chain.record);
    return chain.applied.has(hash) ? new Response(JSON.stringify({hash, successful: true, ledger: 9})) : new Response('{}', {status: 404});
  };
  const input = {network, owner: owner.publicKey(), feeAccount: ACCOUNT, amount: '5', sign, onStep() {}, journal, key: 'refill', fetch: send};
  // The send applied and its reply was lost: the signed payment stays saved.
  await assert.rejects(refillFees(input), error => error.name === 'RefillPendingError' && error.retry === true);
  assert.equal(signedSteps.length, 1);
  const saved = JSON.parse(journal.get('refill'));
  assert.equal(saved.hash, signedSteps[0]);
  // The next refill finds that payment on the network: it is done, and nothing is signed or sent again.
  chain.lost = false;
  assert.deepEqual(await refillFees(input), {transactionHash: signedSteps[0], ledger: 9});
  assert.deepEqual([signedSteps.length, chain.posts.length, journal.get('refill')], [1, 1, null]);

  // A send that never reached the network: the same bytes go again while their time bound lasts.
  chain.down = true;
  await assert.rejects(refillFees(input), /offline/);
  chain.down = false; chain.lost = true;
  await assert.rejects(refillFees(input), error => error.name === 'RefillPendingError');
  const second = JSON.parse(journal.get('refill'));
  chain.applied.delete(second.hash);
  chain.lost = false;
  assert.deepEqual(await refillFees(input), {transactionHash: second.hash, ledger: 9});
  assert.deepEqual([signedSteps.length, chain.posts.filter(h => h === second.hash).length, journal.get('refill')], [2, 2, null]);

  // An unreachable network keeps the saved payment and signs nothing.
  chain.lost = true;
  await assert.rejects(refillFees(input), error => error.name === 'RefillPendingError');
  const third = JSON.parse(journal.get('refill'));
  chain.applied.delete(third.hash);
  chain.down = true;
  await assert.rejects(refillFees(input), error => error.name === 'RefillPendingError');
  assert.equal(signedSteps.length, 3);
  assert.equal(JSON.parse(journal.get('refill')).hash, third.hash);
  chain.down = false; chain.lost = false;

  // A reply that is cut, incomplete or of another transaction proves nothing: the payment stays saved.
  for (const record of ['{"hash":', JSON.stringify({hash: third.hash}), JSON.stringify({hash: third.hash, successful: true}), JSON.stringify({hash: '0'.repeat(64), successful: false, ledger: 9})]) {
    chain.record = record;
    await assert.rejects(refillFees(input), error => error.name === 'RefillPendingError');
    assert.equal(JSON.parse(journal.get('refill')).hash, third.hash);
  }
  assert.equal(signedSteps.length, 3);
  // The network holds that payment as failed in a ledger: it can never apply, and the owner signs a new one.
  chain.record = JSON.stringify({hash: third.hash, successful: false, ledger: 9});
  const fourth = await refillFees(input);
  chain.record = null;
  assert.equal(signedSteps.length, 4);
  assert.notEqual(fourth.transactionHash, third.hash);

  // A saved payment past its own time bound. The time bound is the one of the signed bytes.
  const past = Math.floor(Date.now() / 1000) - 60;
  const expired = sequence => {
    const tx = new TransactionBuilder(new Account(owner.publicKey(), String(sequence)), {fee: '100', networkPassphrase: Networks.TESTNET})
      .addOperation(Operation.payment({destination: ACCOUNT, asset: Asset.native(), amount: '5'})).setTimebounds(0, past).build();
    tx.sign(owner);
    return {hash: Buffer.from(tx.hash()).toString('hex'), signedPayload: tx.toXDR(), expiresAt: past, owner: owner.publicKey(), feeAccount: ACCOUNT, amount: '5'};
  };
  const old = expired(60);
  journal.set('refill', JSON.stringify(old));
  // The network has not read past the time bound yet: nothing is decided.
  chain.root = new Date((past - 60) * 1000).toISOString();
  chain.sequence = '60';
  await assert.rejects(refillFees(input), error => error.name === 'RefillPendingError');
  // History holds no such payment, but the owner's sequence passed it: it can have applied before history was
  // cut. The payment stays saved and nothing is signed.
  chain.root = new Date().toISOString();
  chain.sequence = '61';
  await assert.rejects(refillFees(input), error => error.name === 'RefillPendingError');
  assert.equal(JSON.parse(journal.get('refill')).hash, old.hash);
  assert.equal(signedSteps.length, 4);
  // The owner's sequence is still below the payment's: it never applied, and only then the owner signs a new one.
  chain.sequence = '60';
  const fifth = await refillFees(input);
  assert.equal(signedSteps.length, 5);
  assert.notEqual(fifth.transactionHash, old.hash);
  assert.equal(journal.get('refill'), null);
  // An expired payment that history holds as successful is done, and nothing is signed.
  const applied = expired(70);
  journal.set('refill', JSON.stringify(applied));
  chain.applied.add(applied.hash);
  assert.deepEqual(await refillFees(input), {transactionHash: applied.hash, ledger: 9});
  assert.equal(signedSteps.length, 5);
  // Saved metadata that differs from the signed bytes, a refill of another account and an unreadable entry
  // settle nothing and sign nothing.
  journal.set('refill', JSON.stringify({...old, hash: '0'.repeat(64)}));
  await assert.rejects(refillFees(input), error => error.name === 'RefillPendingError');
  journal.set('refill', JSON.stringify({...old, feeAccount: owner.publicKey()}));
  await assert.rejects(refillFees(input), error => error.name === 'RefillPendingError');
  journal.set('refill', 'not json');
  await assert.rejects(refillFees(input), error => error.name === 'RefillPendingError');
  assert.equal(signedSteps.length, 5);
});

test('one refill runs per journal key: a second call signs nothing and leaves the journal alone', async () => {
  const owner = Keypair.random();
  const map = new Map(), journal = {get: k => map.get(k) ?? null, set: (k, v) => void map.set(k, v), remove: k => void map.delete(k)};
  let release = () => {}, signs = 0;
  const waiting = new Promise(resolve => {release = resolve;});
  const sign = async prepared => {
    signs++;
    await waiting;
    const tx = TransactionBuilder.fromXDR(prepared.payload, Networks.TESTNET);
    tx.sign(owner);
    return tx.toXDR();
  };
  const send = async (url, init = {}) => {
    if (init.method === 'POST') {
      const tx = TransactionBuilder.fromXDR(decodeURIComponent(String(init.body).slice(3)), Networks.TESTNET);
      return new Response(JSON.stringify({hash: Buffer.from(tx.hash()).toString('hex'), successful: true, ledger: 9}));
    }
    return new Response(JSON.stringify(horizonAccount(owner.publicKey(), '100.0000000')));
  };
  const input = {network, owner: owner.publicKey(), feeAccount: ACCOUNT, amount: '5', sign, onStep() {}, journal, key: 'one', fetch: send};
  const first = refillFees(input);
  // While the first refill waits for its signature, a second one of the same key is refused before it reads anything.
  await assert.rejects(refillFees(input), error => error.name === 'RefillPendingError' && /already running/.test(error.message));
  // Another fee account's key is not held.
  const other = refillFees({...input, key: 'two', sign: async prepared => { const tx = TransactionBuilder.fromXDR(prepared.payload, Networks.TESTNET); tx.sign(owner); return tx.toXDR(); }});
  assert.equal((await other).ledger, 9);
  release();
  assert.equal((await first).ledger, 9);
  assert.equal(signs, 1);
  // The key is free again.
  assert.equal((await refillFees(input)).ledger, 9);
});

// The deployment of a policy wallet through the owner workflow.
const policyId = 'policy-1', key = 'flow:owner:1', amount = '5';
const hash64 = n => String(n).repeat(64).slice(0, 64);
const refusal = (code, details, status = 409) => Object.assign(new Error(code), {status, code, details});
function journalOf() {
  const map = new Map();
  return {map, get: k => map.get(k) ?? null, set: (k, v) => void map.set(k, v), remove: k => void map.delete(k)};
}
beforeEach(() => {
  globalThis.fetch = async url => new Response(JSON.stringify({hash: new URL(url).pathname.split('/').pop(), ledger: 7, successful: true}));
});

/**
 * A service for a new policy wallet: it refuses a creation without a fee account, prepares the creation of the
 * fee account that the owner names, then the wallet, then the funding.
 */
function service(owner) {
  const calls = [], state = {feeAccount: null, created: null, installed: false, submitted: []};
  const ask = async (path, body) => {
    calls.push([path, body]);
    if (path === 'native/deploy/prepare') {
      if (state.installed) return {policyId, installed: true, installation: {wallet: WALLET}};
      const named = body.setup?.feeAccount;
      if (!named) throw refusal('fee_account_required', {wallet: WALLET});
      if (!state.feeAccount) {
        state.created = creation(owner, Keypair.fromPublicKey(named), false);
        return {policyId, wallet: WALLET, step: {action: CREATE_FEE_ACCOUNT, payload: state.created.payload, transactionHash: state.created.hash, expiresAt: Math.floor(Date.now() / 1000) + 300}};
      }
      assert.equal(named, state.feeAccount);
      return {policyId, wallet: WALLET, step: {action: 'create_wallet', payload: 'dW5zaWduZWQ=', transactionHash: hash64(2), expiresAt: Math.floor(Date.now() / 1000) + 300}};
    }
    if (path === 'native/owner/prepare') return {policyId, step: {action: 'fund', payload: 'dW5zaWduZWQ=', transactionHash: hash64(3), expiresAt: Math.floor(Date.now() / 1000) + 300}};
    if (path === 'native/owner/submit') {
      state.submitted.push(body.payload);
      if (body.payload === 'signed-create_wallet') { state.installed = true; return {policyId, action: 'create_wallet', status: 'confirmed', transactionHash: hash64(2), ledger: 7}; }
      if (body.payload === 'signed-fund') return {policyId, action: 'fund', status: 'confirmed', transactionHash: hash64(3), ledger: 7};
      // The creation of the fee account carries the owner's signature, then the new account's own.
      const tx = TransactionBuilder.fromXDR(body.payload, Networks.TESTNET);
      assert.equal(Buffer.from(tx.hash()).toString('hex'), state.created.hash);
      assert.equal(tx.signatures.length, 2);
      const account = Keypair.fromPublicKey(tx.operations[0].destination);
      assert.ok(owner.verify(tx.hash(), sig(tx.signatures[0])));
      assert.ok(account.verify(tx.hash(), sig(tx.signatures[1])));
      state.feeAccount = account.publicKey();
      return {policyId, action: CREATE_FEE_ACCOUNT, status: 'confirmed', transactionHash: state.created.hash, ledger: 7};
    }
    throw new Error(path);
  };
  return {ask, calls, state};
}

/** The owner's wallet: it signs the creation of the fee account, and marks every other step. */
const walletOf = (owner, signed = []) => async step => {
  signed.push(step.action);
  if (step.action !== CREATE_FEE_ACCOUNT) return `signed-${step.action}`;
  const tx = TransactionBuilder.fromXDR(step.payload, Networks.TESTNET);
  tx.sign(owner);
  return tx.toXDR();
};
/** A journal that also keeps everything that was ever written to it. */
function recordingJournal() {
  const journal = journalOf(), written = [];
  return {...journal, written, set: (k, v) => { written.push(String(v)); journal.set(k, v); }};
}
const SECRET = /S[A-Z2-7]{55}/;

test('a deployment takes three owner signatures: the fee account, the wallet and the funding', async () => {
  const owner = Keypair.fromRawEd25519Seed(Buffer.from(OWNER_SEED));
  const {ask, calls, state} = service(owner);
  const signed = [], journal = recordingJournal();
  const result = await flow({network, historyPauseMs: 0, ask, sign: walletOf(owner, signed), journal, key, policyId, agent: AGENT, amount, onStep() {}});
  assert.equal(result.wallet, WALLET);
  // No message is signed: the setup key of the fee account is random and lives in the workflow.
  assert.deepEqual(signed, [CREATE_FEE_ACCOUNT, 'create_wallet', 'fund']);
  assert.deepEqual(result.receipts.map(r => r.action), [CREATE_FEE_ACCOUNT, 'create_wallet', 'fund']);
  // Every preparation after the refusal names the one account that the workflow made.
  assert.ok(StrKey.isValidEd25519PublicKey(state.feeAccount));
  const prepares = calls.filter(([path]) => path === 'native/deploy/prepare').map(([, body]) => body.setup?.feeAccount ?? null);
  assert.deepEqual(prepares, [null, state.feeAccount, state.feeAccount, state.feeAccount]);
  // The journal held the bytes with both signatures before they were sent. It never held a key, and it keeps
  // nothing of the fee account once the wallet is installed.
  assert.equal(journal.get(key), null);
  assert.equal(journal.get(`${key}:fee-account`), null);
  assert.ok(journal.written.some(value => value.includes(state.feeAccount)));
  assert.ok(!journal.written.some(value => SECRET.test(value)));
});

test('a reload after the signed creation names the same account again and signs no second creation', async () => {
  const owner = Keypair.fromRawEd25519Seed(Buffer.from(OWNER_SEED));
  const {ask, state} = service(owner);
  const journal = recordingJournal(), input = {network, historyPauseMs: 0, ask, journal, key, policyId, agent: AGENT, amount, onStep() {}};
  // The owner signs the creation and closes the page at the wallet creation.
  const first = [];
  const closing = async step => {
    if (step.action === 'create_wallet') throw new Error('The page closed.');
    return walletOf(owner, first)(step);
  };
  await assert.rejects(flow({...input, sign: closing}), /The page closed/);
  assert.deepEqual(first, [CREATE_FEE_ACCOUNT]);
  const account = state.feeAccount;
  assert.equal(JSON.parse(journal.get(`${key}:fee-account`)).feeAccount, account);
  // The new page holds no key. It names the saved account, and the owner signs the wallet and the funding.
  const second = [];
  const result = await flow({...input, sign: walletOf(owner, second)});
  assert.equal(result.wallet, WALLET);
  assert.deepEqual(second, ['create_wallet', 'fund']);
  assert.equal(state.feeAccount, account);
  assert.ok(!journal.written.some(value => SECRET.test(value)));
});

test('a saved account whose creation never applied is replaced: nothing holds funds, and a new key signs', async () => {
  const owner = Keypair.fromRawEd25519Seed(Buffer.from(OWNER_SEED));
  const {ask, calls, state} = service(owner);
  const journal = recordingJournal(), lost = Keypair.random().publicKey();
  // The journal names an account, the ledger holds none, and no page holds its key.
  journal.set(`${key}:fee-account`, JSON.stringify({feeAccount: lost, policyId, agent: AGENT, amount}));
  const signed = [];
  const result = await flow({network, historyPauseMs: 0, ask, sign: walletOf(owner, signed), journal, key, policyId, agent: AGENT, amount, onStep() {}});
  assert.equal(result.wallet, WALLET);
  assert.deepEqual(signed, [CREATE_FEE_ACCOUNT, 'create_wallet', 'fund']);
  assert.notEqual(state.feeAccount, lost);
  // The creation of the lost account was prepared and never signed.
  const prepares = calls.filter(([path]) => path === 'native/deploy/prepare').map(([, body]) => body.setup?.feeAccount ?? null);
  assert.deepEqual(prepares, [lost, state.feeAccount, state.feeAccount, state.feeAccount]);
  // A marker of another policy, agent or amount names no account.
  const other = recordingJournal();
  other.set(`${key}:fee-account`, JSON.stringify({feeAccount: lost, policyId: 'policy-2', agent: AGENT, amount}));
  const fresh = service(owner);
  await flow({network, historyPauseMs: 0, ask: fresh.ask, sign: walletOf(owner), journal: other, key, policyId, agent: AGENT, amount, onStep() {}});
  assert.equal(fresh.calls.find(([path]) => path === 'native/deploy/prepare')[1].setup, undefined);
});

test('a fee account that this workflow did not name, or another transaction, is never countersigned', async () => {
  const owner = Keypair.fromRawEd25519Seed(Buffer.from(OWNER_SEED));
  const sign = walletOf(owner);
  const input = {network, historyPauseMs: 0, sign, key, policyId, agent: AGENT, amount, onStep() {}};
  // The service prepares the creation of another account than the named one.
  const stranger = creation(owner, Keypair.random(), false);
  const foreign = async (path, body) => {
    if (path !== 'native/deploy/prepare') throw new Error('nothing may be submitted');
    if (!body.setup) throw refusal('fee_account_required', {wallet: WALLET});
    return {policyId, step: {action: CREATE_FEE_ACCOUNT, payload: stranger.payload, transactionHash: stranger.hash, expiresAt: Math.floor(Date.now() / 1000) + 300}};
  };
  const journal = journalOf();
  await assert.rejects(flow({...input, ask: foreign, journal}), error => error instanceof OwnerFlowError && /does not create the account/.test(error.message));
  assert.equal(journal.get(key), null);
  assert.equal(journal.get(`${key}:fee-account`), null);
  // The service prepares a fee account step although the workflow named none. The workflow names its own
  // account once; the service's step still creates another one, and nothing is signed.
  const unasked = async path => {
    if (path !== 'native/deploy/prepare') throw new Error('nothing may be submitted');
    return {policyId, step: {action: CREATE_FEE_ACCOUNT, payload: stranger.payload, transactionHash: stranger.hash, expiresAt: Math.floor(Date.now() / 1000) + 300}};
  };
  await assert.rejects(flow({...input, ask: unasked, journal: journalOf()}), /does not create the account/);
  // A second refusal after the workflow named its account ends the workflow.
  let asked = 0;
  await assert.rejects(flow({...input, ask: async () => { asked++; throw refusal('fee_account_required', {wallet: WALLET}); }, journal: journalOf()}), /fee_account_required/);
  assert.equal(asked, 2);
});
