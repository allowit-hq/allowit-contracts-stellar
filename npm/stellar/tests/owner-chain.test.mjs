import assert from 'node:assert/strict';
import test from 'node:test';
import {Account, Keypair, Networks, Operation, TransactionBuilder} from '@stellar/stellar-sdk/base';
import {ownerChain} from '../dist/owner-chain.js';
import {WalletSetupPendingError} from '../dist/native-wallet.js';

const network = 'stellar:testnet';
const hash = n => String(n).repeat(64).slice(0, 64);
const respond = (body, status = 200) => new Response(JSON.stringify(body), {status});

test('a transaction record is the Horizon record, missing, or null when Horizon gives no clear answer', async () => {
  for (const [reply, expected] of [
    [() => respond({hash: hash(1), ledger: 7, successful: true}), {hash: hash(1), ledger: 7, successful: true}],
    [() => respond({hash: hash(1), ledger: 9, successful: false}), {hash: hash(1), ledger: 9, successful: false}],
    [() => respond({}, 404), 'missing'],
    [() => respond({}, 500), null],
    [() => { throw new Error('offline'); }, null],
    [() => new Response('not json'), null],
    [() => respond({hash: hash(1), ledger: '7', successful: true}), null],
    [() => respond({hash: hash(1), ledger: 7}), null],
  ]) {
    const asked = [];
    globalThis.fetch = async url => (asked.push(url), reply());
    assert.deepEqual(await ownerChain.transaction(network, hash(1)), expected);
    assert.deepEqual(asked, [`https://horizon-testnet.stellar.org/transactions/${hash(1)}`]);
  }
  // A network without Horizon reads nothing.
  globalThis.fetch = async () => assert.fail('no read');
  assert.equal(await ownerChain.transaction('other:testnet', hash(1)), null);
});

/** A real signed transaction past its time bound, with the Horizon replies of one scenario. */
function expired(validUntil = Math.floor(Date.now() / 1000) - 60) {
  const owner = Keypair.random();
  const transaction = new TransactionBuilder(new Account(owner.publicKey(), '41'), {fee: '100', networkPassphrase: Networks.TESTNET})
    .addOperation(Operation.bumpSequence({bumpTo: '0'})).setTimebounds(0, validUntil).build();
  transaction.sign(owner);
  const txHash = Buffer.from(transaction.hash()).toString('hex');
  const horizon = replies => {
    const seen = [];
    globalThis.fetch = async url => {
      const path = new URL(url).pathname;
      seen.push(path);
      const reply = path === '/' ? replies.root : path.startsWith('/transactions/') ? replies.transaction : replies.account;
      if (reply === undefined) throw new Error('offline');
      return respond(reply.body ?? {}, reply.status ?? 200);
    };
    return seen;
  };
  const past = {body: {history_latest_ledger_closed_at: new Date().toISOString()}};
  const account = sequence => ({body: {account_id: owner.publicKey(), sequence}});
  return {signed: transaction.toXDR(), txHash, horizon, past, account, validUntil};
}

test('an expired step never applied when Horizon read past its time bound and the source sequence stayed below it', async () => {
  const {signed, txHash, horizon, past, account} = expired();
  const seen = horizon({root: past, transaction: {status: 404}, account: account('41')});
  assert.equal(await ownerChain.expiredRecord(network, txHash, signed), null);
  assert.equal(seen.length, 3);
  // A transaction that Horizon holds as failed can never apply either.
  horizon({root: past, transaction: {body: {hash: txHash, ledger: 9, successful: false}}});
  assert.equal(await ownerChain.expiredRecord(network, txHash, signed), null);
});

test('an expired step that Horizon holds as successful applied in its ledger', async () => {
  const {signed, txHash, horizon, past} = expired();
  horizon({root: past, transaction: {body: {hash: txHash, ledger: 77, successful: true}}});
  assert.deepEqual(await ownerChain.expiredRecord(network, txHash, signed), {ledger: 77});
});

test('an expired step without Horizon\'s proof rejects, so the SDK keeps it', async () => {
  const {signed, txHash, horizon, past, account, validUntil} = expired();
  const stale = {body: {history_latest_ledger_closed_at: new Date((validUntil - 10) * 1000).toISOString()}};
  for (const replies of [
    {},                                                                  // Horizon is offline.
    {root: stale, transaction: {status: 404}, account: account('41')},   // Horizon has not read past the time bound.
    {root: past, transaction: {status: 404}, account: account('42')},    // The sequence moved: the transaction may have applied.
    {root: past, transaction: {status: 404}, account: {status: 404}},    // The account cannot be read.
    {root: past, transaction: {status: 500}},                            // The transaction lookup failed.
    {root: past, transaction: {body: {hash: hash(3), ledger: 5, successful: true}}}, // Another transaction.
  ]) {
    horizon(replies);
    await assert.rejects(ownerChain.expiredRecord(network, txHash, signed));
  }
  // The signed time bound decides: a transaction that is valid for another hour, or that has no time bound, can
  // still apply.
  for (const until of [Math.floor(Date.now() / 1000) + 3_600, 0]) {
    const live = expired(until);
    live.horizon({root: live.past, transaction: {status: 404}, account: live.account('41')});
    await assert.rejects(ownerChain.expiredRecord(network, live.txHash, live.signed));
  }
  // Bytes that are not the named transaction prove nothing.
  horizon({root: past, transaction: {status: 404}, account: account('41')});
  await assert.rejects(ownerChain.expiredRecord(network, txHash, 'not-xdr'));
  await assert.rejects(ownerChain.expiredRecord(network, hash(4), signed));
});

test('the owner of a wallet account is its one signer of the owner\'s weight', async () => {
  const owner = Keypair.random().publicKey(), other = Keypair.random().publicKey(), wallet = Keypair.random().publicKey();
  const signer = (key, weight) => ({key, weight, type: 'ed25519_public_key'});
  for (const [reply, expected] of [
    [() => respond({account_id: wallet, signers: [signer(owner, 3), signer(other, 1), signer(wallet, 0)]}), owner],
    [() => respond({account_id: wallet, signers: [signer(owner, 3), signer(other, 3)]}), null],
    [() => respond({account_id: wallet, signers: [signer(owner, 1)]}), null],
    [() => respond({account_id: wallet, signers: [{key: owner, weight: 3, type: 'sha256_hash'}]}), null],
    [() => respond({}, 404), null],
    [() => { throw new Error('offline'); }, null],
  ]) {
    globalThis.fetch = async url => (assert.equal(url, `https://horizon-testnet.stellar.org/accounts/${wallet}`), reply());
    assert.equal(await ownerChain.approval.walletOwner(network, wallet), expected);
  }
});

test('an approval signature counts only when the named signer made it over the step digest', () => {
  const owner = Keypair.random(), stranger = Keypair.random();
  const step = ownerChain.approval.step('AllowIt Native policy approval v1\n{}');
  const digest = Buffer.from(step.hash, 'hex');
  const signature = Array.from(owner.sign(digest));
  assert.equal(ownerChain.approval.signedBy(owner.publicKey(), step.hash, signature), true);
  assert.equal(ownerChain.approval.signedBy(stranger.publicKey(), step.hash, signature), false);
  assert.equal(ownerChain.approval.signedBy(owner.publicKey(), hash(5), signature), false);
  assert.equal(ownerChain.approval.signedBy('not a key', step.hash, signature), false);
  assert.equal(ownerChain.approval.signedBy(owner.publicKey(), step.hash, signature.slice(1)), false);
});

test('a setup failure that stays saved is pending; any other failure is not', () => {
  assert.equal(ownerChain.keypairSetup.pending(new WalletSetupPendingError('unknown result')), true);
  assert.equal(ownerChain.keypairSetup.pending(new Error('refused')), false);
  assert.equal(ownerChain.keypairSetup.of('not-xdr', network), null);
});
