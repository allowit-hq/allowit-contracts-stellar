import assert from 'node:assert/strict';
import test, {beforeEach} from 'node:test';
import {ed25519} from '@noble/curves/ed25519';
import {Account, Keypair, Networks, Operation, StrKey, TransactionBuilder} from '@stellar/stellar-sdk/base';
import {
  countersignCreation, CREATE_FEE_ACCOUNT, DERIVE_FEE_ACCOUNT_KEY, derivationStep, feeAccount, feeAccountDerivation,
  feeAccountDerivationMessage, feeAccountKey, feeAccountOf, messageDigest, REFILL_FEES, refillFees, stroops, xlmText,
} from '../dist/fee-account.js';
import {installAndFund as flow, OwnerFlowError} from '../dist/owner-flow.js';

const network = 'stellar:testnet';
const hexBytes = text => Uint8Array.from(text.match(/../g), b => parseInt(b, 16));
// The vector of the rail crate: the owner of seed 01…01, the agent of seed 02…02, the wallet contract 04…04.
const OWNER_SEED = new Uint8Array(32).fill(1);
const AGENT = 'GCATS5YOVB6ROX2WUNKGNQ2MP3GMXDMKSG2O4N5CLX3A6W4PZGZZI55U';
const WALLET = 'CACAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAINCW';
const MESSAGE = "Allowit fee account key v1\nNetwork: Test SDF Network ; September 2015\nAgent: GCATS5YOVB6ROX2WUNKGNQ2MP3GMXDMKSG2O4N5CLX3A6W4PZGZZI55U\nPolicy wallet: CACAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAINCW\nFee account index: 0\n\nThis signature derives the one-time setup key of the account that pays the network fees of this agent's policy wallet. It does not authorize spending or move funds.";
const ACCOUNT = 'GD2YKHPRFRN2IO3WBQKAQ3YRDJYD5VH6CVIY6PME5GJ54UA6NP5KI2W7';
const ownerSignature = message => ed25519.sign(hexBytes(messageDigest(message)), OWNER_SEED);
/** The bytes of a decorated signature. XDR opaque values wrap their bytes in `value`. */
const sig = s => { const v = typeof s.signature === 'function' ? s.signature() : s.signature; return Buffer.from(v instanceof Uint8Array ? v : v.value); };

test('the derivation is the one of the rail crate: the same message, signature and account', () => {
  assert.equal(feeAccountDerivationMessage(network, AGENT, WALLET), MESSAGE);
  assert.equal(feeAccountKey(ownerSignature(MESSAGE)).publicKey(), ACCOUNT);
  // Another network, agent, wallet, index or owner derives another account.
  const other = Keypair.random().publicKey(), contract = StrKey.encodeContract(Buffer.alloc(32, 5));
  const accounts = [
    feeAccountDerivationMessage('stellar:pubnet', AGENT, WALLET),
    feeAccountDerivationMessage(network, other, WALLET),
    feeAccountDerivationMessage(network, AGENT, contract),
    feeAccountDerivationMessage(network, AGENT, WALLET, 1),
  ].map(message => feeAccountKey(ownerSignature(message)).publicKey());
  accounts.push(feeAccountKey(ed25519.sign(hexBytes(messageDigest(MESSAGE)), new Uint8Array(32).fill(9))).publicKey());
  assert.equal(new Set([...accounts, ACCOUNT]).size, 6);
  // A fee account pays for a policy wallet contract, and its key needs a whole signature.
  assert.throws(() => feeAccountDerivationMessage(network, AGENT, other));
  assert.throws(() => feeAccountDerivationMessage(network, WALLET, WALLET));
  assert.throws(() => feeAccountKey(new Uint8Array(63)));
});

test('only the exact derivation message of the network is a derivation message', () => {
  assert.deepEqual(feeAccountDerivation(MESSAGE, network), {agent: AGENT, wallet: WALLET, index: 0});
  for (const changed of [
    MESSAGE.replace('It does not authorize spending or move funds.', 'It authorizes a transfer.'),
    `${MESSAGE}\nextra`,
    MESSAGE.replace('index: 0', 'index: 00'),
    MESSAGE.replace('Allowit fee account key v1', 'Allowit Native wallet key v1'),
    MESSAGE.replace(AGENT, WALLET),
    '', null, 7,
  ]) assert.equal(feeAccountDerivation(changed, network), null);
  // The message of another network is no message of this one.
  assert.equal(feeAccountDerivation(MESSAGE, 'stellar:pubnet'), null);
  const step = derivationStep(network, AGENT, WALLET, 1_800_000_000_000);
  assert.deepEqual(step, {action: DERIVE_FEE_ACCOUNT_KEY, payload: btoa(MESSAGE), hash: messageDigest(MESSAGE), expiresAt: 1_800_000_300});
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
  const owner = Keypair.random(), key = feeAccountKey(ownerSignature(MESSAGE));
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
  assert.deepEqual(await read('7.5000000'), {address: ACCOUNT, exists: true, balance: '75000000', spendable: '50000000', low: false, text: '5 XLM'});
  // Less than two operations at the 1 XLM fee ceiling is low; exactly two is not.
  assert.equal((await read('4.5000000')).low, false);
  assert.deepEqual(await read('4.4999999'), {address: ACCOUNT, exists: true, balance: '44999999', spendable: '19999999', low: true, text: '1.9999999 XLM'});
  // A balance at or below the reserve pays nothing.
  assert.deepEqual(await read('2.5000000'), {address: ACCOUNT, exists: true, balance: '25000000', spendable: '0', low: true, text: '0 XLM'});
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

test('a deployment derives the fee account, creates and funds it, then creates and funds the wallet', async () => {
  const owner = Keypair.fromRawEd25519Seed(Buffer.from(OWNER_SEED));
  const {ask, calls, state} = service(owner);
  const signed = [], journal = journalOf();
  const sign = async step => {
    signed.push(step.action);
    if (step.action === DERIVE_FEE_ACCOUNT_KEY) {
      // The owner's wallet signs the exact derivation message of this agent and wallet.
      assert.deepEqual(feeAccountDerivation(atob(step.payload), network), {agent: AGENT, wallet: WALLET, index: 0});
      return Buffer.from(ownerSignature(atob(step.payload))).toString('base64');
    }
    if (step.action === CREATE_FEE_ACCOUNT) {
      const tx = TransactionBuilder.fromXDR(step.payload, Networks.TESTNET);
      tx.sign(owner);
      return tx.toXDR();
    }
    return `signed-${step.action}`;
  };
  const result = await flow({network, historyPauseMs: 0, ask, sign, journal, key, policyId, agent: AGENT, amount, onStep() {}});
  assert.equal(result.wallet, WALLET);
  assert.deepEqual(signed, [DERIVE_FEE_ACCOUNT_KEY, CREATE_FEE_ACCOUNT, 'create_wallet', 'fund']);
  assert.deepEqual(result.receipts.map(r => r.action), [CREATE_FEE_ACCOUNT, 'create_wallet', 'fund']);
  // The fee account is the one that the owner's key derives, and every later preparation names it.
  assert.equal(state.feeAccount, ACCOUNT);
  const prepares = calls.filter(([path]) => path === 'native/deploy/prepare').map(([, body]) => body.setup?.feeAccount ?? null);
  assert.deepEqual(prepares, [null, ACCOUNT, ACCOUNT, ACCOUNT]);
  // The journal held the bytes with both signatures before they were sent, and holds no key.
  assert.equal(journal.get(key), null);
  assert.ok(![...journal.map.values()].some(value => String(value).includes(owner.secret())));
});

test('a fee account that this owner did not derive, or another transaction, is never countersigned', async () => {
  const owner = Keypair.fromRawEd25519Seed(Buffer.from(OWNER_SEED));
  const sign = async step => {
    if (step.action === DERIVE_FEE_ACCOUNT_KEY) return Buffer.from(ownerSignature(atob(step.payload))).toString('base64');
    const tx = TransactionBuilder.fromXDR(step.payload, Networks.TESTNET);
    tx.sign(owner);
    return tx.toXDR();
  };
  const input = {network, historyPauseMs: 0, sign, key, policyId, agent: AGENT, amount, onStep() {}};
  // The service prepares the creation of another account than the derived one.
  const stranger = creation(owner, Keypair.random(), false);
  const foreign = async (path, body) => {
    if (path !== 'native/deploy/prepare') throw new Error('nothing may be submitted');
    if (!body.setup) throw refusal('fee_account_required', {wallet: WALLET});
    return {policyId, step: {action: CREATE_FEE_ACCOUNT, payload: stranger.payload, transactionHash: stranger.hash, expiresAt: Math.floor(Date.now() / 1000) + 300}};
  };
  const journal = journalOf();
  await assert.rejects(flow({...input, ask: foreign, journal}), error => error instanceof OwnerFlowError && /does not create the account/.test(error.message));
  assert.equal(journal.get(key), null);
  // The service prepares a fee account step although the owner derived no key.
  const unasked = async path => {
    if (path !== 'native/deploy/prepare') throw new Error('nothing may be submitted');
    return {policyId, step: {action: CREATE_FEE_ACCOUNT, payload: stranger.payload, transactionHash: stranger.hash, expiresAt: Math.floor(Date.now() / 1000) + 300}};
  };
  await assert.rejects(flow({...input, ask: unasked, journal: journalOf()}), /did not derive/);
  // A refusal without the wallet, or a second refusal after the derivation, ends the workflow.
  await assert.rejects(flow({...input, ask: async () => { throw refusal('fee_account_required', {}); }, journal: journalOf()}), /fee_account_required/);
  let asked = 0;
  await assert.rejects(flow({...input, ask: async () => { asked++; throw refusal('fee_account_required', {wallet: WALLET}); }, journal: journalOf()}), /fee_account_required/);
  assert.equal(asked, 2);
});
