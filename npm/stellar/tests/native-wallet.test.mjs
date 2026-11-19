import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import test from 'node:test';
import {Asset, Keypair, Memo, Networks, Operation, TransactionBuilder, Account} from '@stellar/stellar-sdk/base';
import {
  APPROVE_POLICY, SET_UP_WALLET, TRUSTLINE_RESERVE, WALLET_FEE_FLOAT, WALLET_RESERVE, approvalMessage, approvalStep, messageDigest,
  nativeSetupOf, nativeSetupTransaction, nativeWalletConfiguration, policyApproval, prepareNativeSetup, sendNativeSetup, signedNativeSetupOf,
  walletStartingBalance,
} from '../dist/native-wallet.js';
import {ownerChain} from '../dist/owner-chain.js';

const network = 'stellar:testnet';
const owner = Keypair.random(), agent = Keypair.random(), server = Keypair.random();
const roles = {owner: owner.publicKey(), agent: agent.publicKey(), server: server.publicKey()};
const sha = text => createHash('sha256').update(text).digest();
const hex = bytes => Buffer.from(bytes).toString('hex');
/** The memo of a setup is the hash of its request identity: every hand-built setup of these tests carries one. */
const setupMemo = Memo.hash('ab'.repeat(32));
const terms = (wallet, extra = {}) => ({network, ...roles, sequence: '41', wallet, funding: 50_000_000n, requestId: 'wallet-0001', expiresAt: 2_000_000_000, ...extra});
function journalOf(entries = {}) {
  const map = new Map(Object.entries(entries));
  return {map, get: k => map.get(k) ?? null, set: (k, v) => void map.set(k, v), remove: k => void map.delete(k)};
}
/** The owner's wallet: it signs the exact transaction of a step and records the step. */
const ownerSigns = signed => async step => {
  signed.push(step.action);
  if (step.action === APPROVE_POLICY) return Buffer.from(owner.sign(Buffer.from(step.hash, 'hex'))).toString('base64');
  const tx = TransactionBuilder.fromXDR(step.payload, Networks.TESTNET);
  tx.sign(owner);
  return tx.toXDR();
};
/** One setup with the owner's signature: prepared, signed, countersigned and sent. */
async function createWallet(fetch, amount = '0') {
  const prepared = await prepareNativeSetup({network, ...roles, amount, fetch});
  const signedPayload = prepared.complete(await ownerSigns([])(prepared.step));
  const ledger = await sendNativeSetup(network, signedPayload, prepared.step.hash, fetch);
  assert.ok(Number.isSafeInteger(ledger));
  return {wallet: prepared.wallet, signedPayload, hash: prepared.step.hash, ledger};
}
/**
 * The public network: the owner's account, the transactions that it was sent, and each created wallet account
 * with its signers. `send` decides what a submission answers.
 */
function ledger({send = 'ok'} = {}) {
  const state = {posted: [], held: new Map(), send, ledger: 7};
  const json = (body, status = 200) => new Response(JSON.stringify(body), {status});
  const fetch = async (url, init) => {
    const {pathname} = new URL(url);
    if (init?.method === 'POST') {
      const signed = decodeURIComponent(String(init.body).slice(3));
      const tx = TransactionBuilder.fromXDR(signed, Networks.TESTNET), hash = hex(tx.hash());
      state.posted.push(signed);
      if (state.send === 'lost') return json({}, 504);
      state.held.set(hash, {hash, successful: state.send !== 'failed', ledger: ++state.ledger, signed});
      return state.send === 'failed' ? json({}, 400) : json({hash, successful: true, ledger: state.ledger});
    }
    if (pathname === '/') return json({history_latest_ledger_closed_at: new Date().toISOString()});
    if (pathname === `/accounts/${roles.owner}`) return json({account_id: roles.owner, sequence: '41'});
    if (pathname.startsWith('/accounts/')) {
      const account = pathname.split('/').pop();
      const created = [...state.held.values()].find(record => record.successful && nativeSetupOf(record.signed, network)?.wallet === account);
      return created ? json({account_id: account, signers: [
        {key: roles.owner, weight: 3, type: 'ed25519_public_key'}, {key: roles.agent, weight: 1, type: 'ed25519_public_key'},
        {key: roles.server, weight: 1, type: 'ed25519_public_key'}, {key: account, weight: 0, type: 'ed25519_public_key'}]}) : json({}, 404);
    }
    if (pathname.startsWith('/transactions/')) {
      const record = state.held.get(pathname.split('/').pop());
      return record ? json({hash: record.hash, successful: record.successful, ledger: record.ledger}) : json({}, 404);
    }
    return json({}, 404);
  };
  return {state, fetch};
}

test('the setup is one atomic transaction: the account, its three signers, the thresholds and no weight for its own key', () => {
  const wallet = Keypair.random().publicKey();
  const tx = nativeSetupTransaction(terms(wallet));
  assert.equal(tx.source, roles.owner);
  assert.equal(tx.sequence, '42');
  assert.equal(tx.fee, '400');
  assert.equal(tx.timeBounds.maxTime, '2000000000');
  assert.equal(hex(tx.memo.value), hex(sha('wallet-0001')));
  assert.deepEqual(tx.operations.map(op => op.type), ['createAccount', 'setOptions', 'setOptions', 'setOptions']);
  const [create, first, second, last] = tx.operations;
  assert.deepEqual([create.destination, create.startingBalance, create.source], [wallet, '8.0000000', undefined]);
  assert.deepEqual([first.source, first.signer, first.masterWeight], [wallet, {ed25519PublicKey: roles.owner, weight: 3}, undefined]);
  assert.deepEqual([second.source, second.signer], [wallet, {ed25519PublicKey: roles.agent, weight: 1}]);
  assert.deepEqual([last.source, last.signer, last.masterWeight, last.lowThreshold, last.medThreshold, last.highThreshold],
    [wallet, {ed25519PublicKey: roles.server, weight: 1}, 0, 2, 2, 3]);
  assert.deepEqual(nativeSetupOf(tx.toXDR(), network), {...roles, wallet, startingBalance: 80_000_000n, asset: {symbol: 'XLM', issuer: null}, funding: 50_000_000n});
  assert.equal(walletStartingBalance(0n), WALLET_RESERVE + WALLET_FEE_FLOAT);
  assert.throws(() => walletStartingBalance(-1n));
  // The four roles are four accounts, and the request identity and the sequence are bounded.
  assert.throws(() => nativeSetupTransaction(terms(roles.agent)), /four accounts/);
  assert.throws(() => nativeSetupTransaction(terms(wallet, {agent: 'GAGENT'})), /agent account is invalid/);
  assert.throws(() => nativeSetupTransaction(terms(wallet, {requestId: 'short'})));
  assert.throws(() => nativeSetupTransaction(terms(wallet, {sequence: '-1'})));
});

/** Testnet USDC and Mainnet USDC of the rail's token list. */
const usdc = {symbol: 'USDC', issuer: 'GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5'};
const mainnetUsdc = {symbol: 'USDC', issuer: 'GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN'};

test('a wallet of an issued asset adds its trustline and takes its funding in that asset, in the same transaction', () => {
  const wallet = Keypair.random().publicKey();
  const tx = nativeSetupTransaction(terms(wallet, {asset: usdc, funding: 100_000n}));
  assert.equal(tx.source, roles.owner);
  assert.equal(tx.fee, '600');
  assert.deepEqual(tx.operations.map(op => op.type), ['createAccount', 'changeTrust', 'payment', 'setOptions', 'setOptions', 'setOptions']);
  const [create, trust, pay] = tx.operations;
  // The XLM is the reserve of the account and its trustline and the fee float. The funding is the asset.
  assert.equal(walletStartingBalance(100_000n, true), WALLET_RESERVE + TRUSTLINE_RESERVE + WALLET_FEE_FLOAT);
  assert.deepEqual([create.destination, create.startingBalance, create.source], [wallet, '3.5000000', undefined]);
  assert.deepEqual([trust.source, trust.line.getCode(), trust.line.getIssuer(), trust.limit], [wallet, 'USDC', usdc.issuer, '922337203685.4775807']);
  // The owner's account, the transaction source, pays the asset to the new account.
  assert.deepEqual([pay.source, pay.destination, pay.asset.getCode(), pay.asset.getIssuer(), pay.amount], [undefined, wallet, 'USDC', usdc.issuer, '0.0100000']);
  assert.deepEqual(nativeSetupOf(tx.toXDR(), network), {...roles, wallet, startingBalance: 35_000_000n, asset: usdc, funding: 100_000n});
  // Without a funding the setup adds the trustline alone.
  const unfunded = nativeSetupTransaction(terms(wallet, {asset: usdc, funding: 0n}));
  assert.deepEqual(unfunded.operations.map(op => op.type), ['createAccount', 'changeTrust', 'setOptions', 'setOptions', 'setOptions']);
  assert.deepEqual(nativeSetupOf(unfunded.toXDR(), network), {...roles, wallet, startingBalance: 35_000_000n, asset: usdc, funding: 0n});
  // XLM by its name is the wallet of today, with the same bytes.
  assert.equal(nativeSetupTransaction(terms(wallet, {asset: {symbol: 'XLM', issuer: null}})).toXDR(), nativeSetupTransaction(terms(wallet)).toXDR());
  for (const asset of [{symbol: 'USDC', issuer: null}, {symbol: 'USDC', issuer: 'GISSUER'}, {symbol: '', issuer: usdc.issuer}, {symbol: 'US DC', issuer: usdc.issuer}, 'USDC', {issuer: usdc.issuer},
    {symbol: 'XLM', issuer: usdc.issuer}, {symbol: 'USDC'}])
    assert.throws(() => nativeSetupTransaction(terms(wallet, {asset})), /wallet asset is invalid/, JSON.stringify(asset));
});

test('the rail checks that signed setup bytes set up the reviewed asset, and refuses others with asset_mismatch', async () => {
  const {fetch} = ledger();
  const signedOf = async asset => {
    const prepared = await prepareNativeSetup({network, ...roles, amount: '1', asset, fetch});
    return prepared.complete(await ownerSigns([])(prepared.step));
  };
  const xlm = await signedOf(null), issued = await signedOf(usdc);
  const check = ownerChain.keypairSetup.checkAsset;
  // A policy without an asset, or with XLM, pays in XLM.
  for (const asset of [undefined, null, {symbol: 'XLM', issuer: null}]) assert.equal(check(xlm, network, asset), undefined);
  assert.equal(check(issued, network, {...usdc}), undefined);
  const refused = (payload, asset, on = network) => assert.throws(() => check(payload, on, asset), error => error.code === 'asset_mismatch' && error.message.length > 0);
  refused(xlm, usdc);
  for (const asset of [undefined, null, {symbol: 'XLM', issuer: null}, mainnetUsdc, {symbol: 'USDC', issuer: null}, {symbol: 'EURC', issuer: usdc.issuer}, 'USDC'])
    refused(issued, asset);
  // Bytes that are no signed setup of the network have no asset to compare.
  for (const payload of ['not-xdr', nativeSetupTransaction(terms(Keypair.random().publicKey())).toXDR()]) refused(payload, null);
  refused(xlm, null, 'stellar:pubnet');
});

test('a setup that moves another asset, another amount or another XLM balance than its wallet takes is not read as one', () => {
  const wallet = Keypair.random().publicKey();
  const build = ops => {
    const builder = new TransactionBuilder(new Account(roles.owner, '41'), {fee: '100', networkPassphrase: Networks.TESTNET, timebounds: {minTime: 0, maxTime: 2_000_000_000}, memo: setupMemo});
    for (const op of ops) builder.addOperation(op);
    return builder.build().toXDR();
  };
  const signer = (key, weight) => ({ed25519PublicKey: key, weight});
  const asset = new Asset(usdc.symbol, usdc.issuer), other = new Asset('EURC', usdc.issuer);
  const create = (startingBalance = '3.5') => Operation.createAccount({destination: wallet, startingBalance});
  const trust = (extra = {}) => Operation.changeTrust({source: wallet, asset, ...extra});
  const pay = (extra = {}) => Operation.payment({destination: wallet, asset, amount: '0.01', ...extra});
  const signers = [Operation.setOptions({source: wallet, signer: signer(roles.owner, 3)}), Operation.setOptions({source: wallet, signer: signer(roles.agent, 1)}),
    Operation.setOptions({source: wallet, masterWeight: 0, lowThreshold: 2, medThreshold: 2, highThreshold: 3, signer: signer(roles.server, 1)})];
  assert.ok(nativeSetupOf(build([create(), trust(), pay(), ...signers]), network));
  assert.ok(nativeSetupOf(build([create(), trust(), ...signers]), network));
  for (const [name, ops] of Object.entries({
    'a payment of another asset': [create(), trust(), pay({asset: other}), ...signers],
    'a payment of XLM': [create(), trust(), pay({asset: Asset.native()}), ...signers],
    'a payment to another account': [create(), trust(), pay({destination: roles.agent}), ...signers],
    'a payment from the new account': [create(), trust(), pay({source: wallet, destination: roles.owner}), ...signers],
    'two payments': [create(), trust(), pay(), pay(), ...signers],
    'a payment without a trustline': [create('3'), pay(), ...signers],
    'a payment before the trustline': [create(), pay(), trust(), ...signers],
    'a trustline of the owner account': [create(), Operation.changeTrust({asset}), pay(), ...signers],
    'a trustline with a lower limit': [create(), trust({limit: '100'}), pay(), ...signers],
    'two trustlines': [create(), trust(), trust({asset: other}), ...signers],
    'a trustline of an issued asset with the code XLM': [create(), trust({asset: new Asset('XLM', usdc.issuer)}), ...signers],
    'a trustline after the signers': [create(), ...signers, trust()],
    'more XLM than the reserve and the float': [create('8'), trust(), pay(), ...signers],
    'less XLM than the reserve of the trustline': [create('3'), trust(), pay(), ...signers],
    'less XLM than the reserve of the account': [create('2.9'), ...signers],
    'a funding above the most that a setup funds': [create(), trust(), pay({amount: '100000000.0000001'}), ...signers],
  })) assert.equal(nativeSetupOf(build(ops), network), null, name);
  // The fee is the fee of the builder, 100 stroops for each operation: a setup that bids more is not read as one.
  const bid = fee => {
    const builder = new TransactionBuilder(new Account(roles.owner, '41'), {fee, networkPassphrase: Networks.TESTNET, timebounds: {minTime: 0, maxTime: 2_000_000_000}, memo: setupMemo});
    for (const op of [create(), trust(), pay(), ...signers]) builder.addOperation(op);
    return builder.build().toXDR();
  };
  assert.ok(nativeSetupOf(bid('100'), network));
  for (const fee of ['101', '10000000', '99']) assert.equal(nativeSetupOf(bid(fee), network), null, fee);
  // The one condition of a setup is its upper time bound. A setup with another condition is not read as one: the
  // owner's and the new account's signatures could not meet it, or it would apply at another time.
  const conditioned = (change, timebounds = {minTime: 0, maxTime: 2_000_000_000}) => {
    const builder = new TransactionBuilder(new Account(roles.owner, '41'), {fee: '100', networkPassphrase: Networks.TESTNET, timebounds, memo: setupMemo});
    for (const op of [create(), trust(), pay(), ...signers]) builder.addOperation(op);
    change(builder);
    return builder.build().toXDR();
  };
  assert.ok(nativeSetupOf(conditioned(() => {}), network));
  for (const [name, change] of Object.entries({
    'a further signer': b => b.setExtraSigners([roles.agent]),
    'ledger bounds': b => b.setLedgerbounds(1, 1_000_000_000),
    'a minimum account sequence': b => b.setMinAccountSequence('7'),
    'a minimum sequence age': b => b.setMinAccountSequenceAge(60n),
    'a minimum sequence ledger gap': b => b.setMinAccountSequenceLedgerGap(5),
  })) assert.equal(nativeSetupOf(conditioned(change), network), null, name);
  assert.equal(nativeSetupOf(conditioned(() => {}, {minTime: 1_900_000_000, maxTime: 2_000_000_000}), network), null, 'a lower time bound');
  assert.equal(nativeSetupOf(conditioned(() => {}, {minTime: 0, maxTime: 0}), network), null, 'no upper time bound');
  // The memo of a setup is a hash. A setup without one, or with a text, is not read as one.
  const memoed = memo => {
    const builder = new TransactionBuilder(new Account(roles.owner, '41'), {fee: '100', networkPassphrase: Networks.TESTNET, timebounds: {minTime: 0, maxTime: 2_000_000_000}, ...(memo ? {memo} : {})});
    for (const op of [create(), trust(), pay(), ...signers]) builder.addOperation(op);
    return builder.build().toXDR();
  };
  assert.ok(nativeSetupOf(memoed(Memo.hash('cd'.repeat(32))), network));
  assert.equal(nativeSetupOf(memoed(null), network), null, 'no memo');
  assert.equal(nativeSetupOf(memoed(Memo.text('setup')), network), null, 'a text memo');
});

test('a setup is built and read for each network of the rail, and its bytes belong to one network', () => {
  const wallet = Keypair.random().publicKey(), mainnet = 'stellar:pubnet';
  const tx = nativeSetupTransaction(terms(wallet, {network: mainnet, asset: mainnetUsdc, funding: 100_000n}));
  assert.equal(tx.networkPassphrase, Networks.PUBLIC);
  assert.deepEqual(nativeSetupOf(tx.toXDR(), mainnet), {...roles, wallet, startingBalance: 35_000_000n, asset: mainnetUsdc, funding: 100_000n});
  // The alias names the same network.
  assert.equal(nativeSetupTransaction(terms(wallet, {network: 'stellar:mainnet', asset: mainnetUsdc, funding: 100_000n})).toXDR(), tx.toXDR());
  // The same operations on the other network have another hash.
  const testnet = nativeSetupTransaction(terms(wallet, {asset: mainnetUsdc, funding: 100_000n}));
  assert.notEqual(hex(testnet.hash()), hex(tx.hash()));
  assert.throws(() => nativeSetupTransaction(terms(wallet, {network: 'stellar:futurenet'})), /supported Stellar network/);
  // The document of a Mainnet wallet names the asset by the contract of that network.
  const configuration = nativeWalletConfiguration(mainnet, wallet, roles.owner, roles.agent, roles.server, mainnetUsdc);
  assert.deepEqual([configuration.network, configuration.asset, configuration.assetSymbol, configuration.assetIssuer],
    [mainnet, 'CCW67TSZV3SSS2HXMBQ5JFGCKJNXKZM7UQUWUZPUTHXSTZLEO7SJMI75', 'USDC', mainnetUsdc.issuer]);
  assert.deepEqual(configuration.params.tokens, {List: [{Addr: configuration.asset}]});
  assert.notEqual(nativeWalletConfiguration(network, wallet, roles.owner, roles.agent, roles.server, mainnetUsdc).asset, configuration.asset);
  assert.throws(() => nativeWalletConfiguration(mainnet, wallet, roles.owner, roles.agent, roles.server, {symbol: 'USDC', issuer: null}), /wallet asset is invalid/);
});

test('a transaction that is not exactly the setup is not read as one', () => {
  const wallet = Keypair.random().publicKey();
  const build = ops => {
    const builder = new TransactionBuilder(new Account(roles.owner, '41'), {fee: '100', networkPassphrase: Networks.TESTNET, timebounds: {minTime: 0, maxTime: 2_000_000_000}, memo: setupMemo});
    for (const op of ops) builder.addOperation(op);
    return builder.build().toXDR();
  };
  const signer = (key, weight) => ({ed25519PublicKey: key, weight});
  const create = Operation.createAccount({destination: wallet, startingBalance: '8'});
  const ownerOp = Operation.setOptions({source: wallet, signer: signer(roles.owner, 3)});
  const agentOp = Operation.setOptions({source: wallet, signer: signer(roles.agent, 1)});
  const last = (extra = {}) => Operation.setOptions({source: wallet, masterWeight: 0, lowThreshold: 2, medThreshold: 2, highThreshold: 3, signer: signer(roles.server, 1), ...extra});
  assert.ok(nativeSetupOf(build([create, ownerOp, agentOp, last()]), network));
  for (const [name, ops] of Object.entries({
    'no server signer and thresholds': [create, ownerOp, agentOp],
    'no agent signer': [create, ownerOp, last()],
    'another operation beside the setup': [create, ownerOp, agentOp, last(), Operation.bumpSequence({bumpTo: '99'})],
    'an agent that pays alone': [create, ownerOp, Operation.setOptions({source: wallet, signer: signer(roles.agent, 2)}), last()],
    'an owner below every threshold': [create, Operation.setOptions({source: wallet, signer: signer(roles.owner, 2)}), agentOp, last()],
    'a key of its own that keeps a weight': [create, ownerOp, agentOp, last({masterWeight: 1})],
    'a payment threshold of one': [create, ownerOp, agentOp, last({medThreshold: 1})],
    'signers on another account': [create, Operation.setOptions({signer: signer(roles.owner, 3)}), agentOp, last()],
    'a threshold change in a signer step': [create, Operation.setOptions({source: wallet, signer: signer(roles.owner, 3), highThreshold: 1}), agentOp, last()],
    'the agent as its own wallet': [Operation.createAccount({destination: roles.agent, startingBalance: '8'}), Operation.setOptions({source: roles.agent, signer: signer(roles.owner, 3)}),
      Operation.setOptions({source: roles.agent, signer: signer(roles.agent, 1)}), Operation.setOptions({source: roles.agent, masterWeight: 0, lowThreshold: 2, medThreshold: 2, highThreshold: 3, signer: signer(roles.server, 1)})],
  })) assert.equal(nativeSetupOf(build(ops), network), null, name);
  assert.equal(nativeSetupOf('not a transaction', network), null);
});

test('the installation document is the document of the rail setup', () => {
  const wallet = 'GAJZR5RMNUNEK7CRXJVEWXZ5XUXWT7FJGILCDDOITF7EC26RPWJ4UVOE';
  const source = 'use allowit::prelude::*;\n/// Bootstrap: transfers in the installed asset.\npub fn execute(ctx: &AllowitContext) -> allowit::Result {\n    allowit::operations(ctx, &ctx.params[allowit::OPERATIONS])?;\n    allowit::tokens(ctx, &ctx.params[allowit::TOKENS])?;\n    Ok(())\n}\n';
  // The native asset contract of Testnet, as the rail's own installation documents name it.
  const asset = 'CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC';
  assert.deepEqual(nativeWalletConfiguration(network, wallet, roles.owner, roles.agent, roles.server), {
    network, policyInstance: [...sha(`allowit-stellar-native-wallet-v1:${network}:${wallet}`)], wallet, ...roles,
    route: 'native', language: 'portable', params: {operations: {List: [{Str: 'transfer'}]}, tokens: {List: [{Addr: asset}]}},
    asset, assetSymbol: 'XLM', assetIssuer: null, policySource: source, sourceHash: [...sha(source)], moduleDigest: Array(32).fill(0), maxFeeStroops: 100_000,
  });
  assert.throws(() => nativeWalletConfiguration('stellar:other', wallet, roles.owner, roles.agent, roles.server));
  assert.throws(() => nativeWalletConfiguration(network, roles.owner, roles.owner, roles.agent, roles.server), /four accounts/);
});

test('the owner signs once: the new account countersigns and the network takes the setup', async () => {
  const {state, fetch} = ledger(), signed = [];
  const prepared = await prepareNativeSetup({network, ...roles, amount: '5', fetch});
  assert.equal(prepared.step.action, SET_UP_WALLET);
  const signedPayload = prepared.complete(await ownerSigns(signed)(prepared.step));
  assert.deepEqual(signed, [SET_UP_WALLET]);
  const result = await sendNativeSetup(network, signedPayload, prepared.step.hash, fetch);
  assert.equal(state.posted.length, 1);
  const tx = TransactionBuilder.fromXDR(state.posted[0], Networks.TESTNET), setup = nativeSetupOf(state.posted[0], network);
  assert.deepEqual({...setup, startingBalance: undefined}, {...roles, wallet: prepared.wallet, startingBalance: undefined, asset: {symbol: 'XLM', issuer: null}, funding: 50_000_000n});
  assert.equal(setup.startingBalance, WALLET_RESERVE + WALLET_FEE_FLOAT + 50_000_000n);
  // Two signatures over the same hash: the owner's and the new account's own.
  assert.equal(tx.signatures.length, 2);
  for (const key of [owner, Keypair.fromPublicKey(prepared.wallet)])
    assert.ok(tx.signatures.some(s => key.verify(tx.hash(), Buffer.from(s.signature instanceof Uint8Array ? s.signature : s.signature.value))), key.publicKey());
  assert.deepEqual([prepared.step.hash, result], [hex(tx.hash()), 8]);
  // The signed bytes name their hash, roles and own time bound.
  assert.deepEqual(signedNativeSetupOf(signedPayload, network), {hash: prepared.step.hash, ...roles, wallet: prepared.wallet, validUntil: Number(tx.timeBounds.maxTime), asset: {symbol: 'XLM', issuer: null}, amount: '5'});
  for (const other of ['not-xdr', nativeSetupTransaction(terms(Keypair.random().publicKey())).toXDR()])
    assert.equal(signedNativeSetupOf(other, network)?.hash === prepared.step.hash, false);
  // Signed setup bytes carry the owner's and the new account's signatures over their hash on this network. Bytes
  // without both, with another key's signature, or signed for the other network are no signed setup.
  const resigned = keys => {
    const copy = TransactionBuilder.fromXDR(prepared.step.payload, Networks.TESTNET);
    for (const key of keys) copy.sign(key);
    return copy.toXDR();
  };
  const walletSignature = () => {
    // The new account's own key lives in `prepare` only: its signature is taken from the completed bytes.
    const own = tx.signatures.find(s => Keypair.fromPublicKey(prepared.wallet).verify(tx.hash(), Buffer.from(s.signature instanceof Uint8Array ? s.signature : s.signature.value)));
    return copy => { copy.signatures.push(own); return copy.toXDR(); };
  };
  assert.equal(signedNativeSetupOf(prepared.step.payload, network), null, 'unsigned');
  assert.equal(signedNativeSetupOf(resigned([owner]), network), null, 'the owner alone');
  assert.equal(signedNativeSetupOf(resigned([owner, agent]), network), null, 'the owner and another key');
  assert.equal(signedNativeSetupOf(resigned([owner, owner]), network), null, 'the owner twice');
  assert.equal(signedNativeSetupOf(walletSignature()(TransactionBuilder.fromXDR(resigned([agent]), Networks.TESTNET)), network), null, 'another key and the new account');
  assert.equal(signedNativeSetupOf(signedPayload, 'stellar:pubnet'), null, 'the bytes of the other network');
  // The same transaction in the envelope form of earlier protocol versions has the same hash and the same
  // signatures. The builder never makes that form, so it is no setup, signed or not, and `complete` refuses it.
  const earlierForm = payload => {
    const raw = Buffer.from(payload, 'base64');
    // Form 2 names its source as a tagged account; form 0 holds the bare key. The rest is the same bytes.
    return Buffer.concat([Buffer.alloc(4), raw.subarray(8)]).toString('base64');
  };
  const v0 = TransactionBuilder.fromXDR(earlierForm(signedPayload), Networks.TESTNET);
  assert.deepEqual([hex(v0.hash()), v0.signatures.length], [prepared.step.hash, 2]);
  assert.equal(signedNativeSetupOf(earlierForm(signedPayload), network), null, 'the earlier envelope form, signed');
  assert.equal(nativeSetupOf(earlierForm(prepared.step.payload), network), null, 'the earlier envelope form');
  assert.throws(() => prepared.complete(earlierForm(resigned([owner]))), /another transaction/);
  // The network matches a signature to its key by the hint. The owner's signature under another hint is no signature
  // of the owner there, and `complete` does not take it either.
  const rehinted = TransactionBuilder.fromXDR(signedPayload, Networks.TESTNET);
  for (const s of rehinted.signatures) if (owner.verify(rehinted.hash(), Buffer.from(s.signature.value))) s.hint.value = Buffer.alloc(4);
  assert.notEqual(rehinted.toXDR(), signedPayload);
  assert.equal(signedNativeSetupOf(rehinted.toXDR(), network), null, 'the owner signature under another hint');
  const ownerOnly = TransactionBuilder.fromXDR(resigned([owner]), Networks.TESTNET);
  ownerOnly.signatures[0].hint.value = Buffer.alloc(4);
  assert.throws(() => prepared.complete(ownerOnly.toXDR()), /another account than the owner/);
  assert.ok(signedNativeSetupOf(walletSignature()(TransactionBuilder.fromXDR(resigned([owner]), Networks.TESTNET)), network));
  assert.equal(signedNativeSetupOf(signedPayload, 'stellar:other'), null);
  // Each setup makes a new account: the key is random and nothing keeps it.
  const second = await prepareNativeSetup({network, ...roles, amount: '5', fetch});
  assert.notEqual(second.wallet, prepared.wallet);
  // A wallet that returns another transaction, or an unsigned one, is refused before anything is sent.
  assert.throws(() => second.complete(nativeSetupTransaction(terms(Keypair.random().publicKey())).toXDR()), /another transaction/);
  assert.throws(() => second.complete(second.step.payload), /another transaction/);
  for (const amount of ['-1', '1.00000001', 'all']) await assert.rejects(prepareNativeSetup({network, ...roles, amount, fetch}), /at most seven decimals/);
  assert.equal(state.posted.length, 1);
});

test('a send without a certain answer is null: lost, refused or a record of another transaction', async () => {
  for (const send of ['lost', 'failed']) {
    const {state, fetch} = ledger({send});
    const prepared = await prepareNativeSetup({network, ...roles, amount: '5', fetch});
    const signedPayload = prepared.complete(await ownerSigns([])(prepared.step));
    assert.equal(await sendNativeSetup(network, signedPayload, prepared.step.hash, fetch), null, send);
    assert.equal(state.posted.length, 1);
  }
  const {fetch} = ledger();
  const prepared = await prepareNativeSetup({network, ...roles, amount: '5', fetch});
  const signedPayload = prepared.complete(await ownerSigns([])(prepared.step));
  assert.equal(await sendNativeSetup(network, signedPayload, hex(Buffer.alloc(32)), fetch), null);
  assert.equal(await sendNativeSetup('other:testnet', signedPayload, prepared.step.hash, fetch), null);
  // The owner account that the network cannot read prepares nothing.
  await assert.rejects(prepareNativeSetup({network, ...roles, owner: Keypair.random().publicKey(), amount: '5', fetch}), /owner account could not be read/);
});

const canonicalJson = value => Array.isArray(value) ? `[${value.map(canonicalJson).join(',')}]`
  : value && typeof value === 'object' ? `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',')}}` : JSON.stringify(value);
const nativeXlm = Asset.native().contractId(Networks.TESTNET);
const approval = (extra = {}) => {
  const source = 'use allowit::prelude::*;\n// "5 € per day"\n';
  const wallet = extra.wallet ?? Keypair.random().publicKey();
  // A Native wallet's configuration: its policy instance, asset and fee ceiling follow from the wallet and the network.
  const payload = {asset: nativeXlm, assetIssuer: null, assetSymbol: 'XLM', irHash: '', language: 'allowit-portable-v1', maxFeeStroops: 100000, moduleDigest: '00', network,
    params: {payment_limit: {Int: '5'}}, policyId: 'policy-1', policyInstance: hex(sha(`allowit-stellar-native-wallet-v1:${network}:${wallet}`)), revision: 2, route: 'native',
    rules: ['payment_limit'], source, sourceHash: hex(sha(source)), tier: 'standard', version: 1, wallet, ...extra};
  // The values' hash is the SHA-256 of their canonical JSON, unless a test states another one.
  if (!('paramsHash' in extra) && payload.params && typeof payload.params === 'object') payload.paramsHash = hex(sha(canonicalJson(payload.params)));
  const sorted = Object.fromEntries(Object.keys(payload).sort().map(key => [key, payload[key]]));
  return {payload, message: `AllowIt Native policy approval v1\n${JSON.stringify(sorted)}`};
};
/** The policy that the owner reviewed before the deployment's approval: the approval's own source, rules and values. */
const reviewedOf = () => ({source: approval().payload.source, rules: ['payment_limit'], params: {payment_limit: {Int: '5'}}});

/** What the owner reviewed of the installed policy of `wallet`: the approval's source and rules, the old value. */
const installedOf = wallet => ({wallet, source: approval().payload.source, rules: ['payment_limit'], params: {payment_limit: {Int: '1'}}});

test('only the exact approval message of this network is read, and its step carries the message unchanged', () => {
  const {payload, message} = approval();
  assert.deepEqual(policyApproval(message, network), {policyId: 'policy-1', revision: 2, network, wallet: payload.wallet, source: payload.source, sourceHash: payload.sourceHash, paramsHash: payload.paramsHash, params: payload.params, rules: payload.rules, fields: payload});
  const step = approvalStep(message, 1_000_000);
  assert.deepEqual([step.action, step.hash, step.expiresAt], [APPROVE_POLICY, messageDigest(message), 1300]);
  assert.equal(approvalMessage(step), message);
  assert.equal(approvalMessage({...step, hash: '0'.repeat(64)}), null);
  assert.equal(approvalMessage({payload: '%%', hash: step.hash}), null);
  assert.equal(messageDigest('a'), hex(sha('Stellar Signed Message:\na')));
  for (const [name, text] of Object.entries({
    'another title': message.replace('AllowIt Native policy approval v1', 'AllowIt Native policy approval v2'),
    'text that is not canonical': message.replace('{"asset"', '{ "asset"'),
    'a source that differs from its hash': approval({sourceHash: 'cd'.repeat(32)}).message,
    'another network': approval({network: 'stellar:pubnet'}).message,
    'another route': approval({route: 'policyWallet'}).message,
    'no revision': approval({revision: 0}).message,
    'a wallet that is no account': approval({wallet: 'CWALLET'}).message,
    'no JSON': 'AllowIt Native policy approval v1\nhello',
    'no params': approval({params: null}).message,
    'values whose hash differs from the stated hash': approval({params: {payment_limit: {Int: '999'}}, paramsHash: approval().payload.paramsHash}).message,
  })) assert.equal(policyApproval(text, network), null, name);
  assert.equal(policyApproval(message, 'stellar:other'), null);
  assert.equal(policyApproval(null, network), null);
});

/**
 * The hooks that the SDK's owner workflows call for a Native wallet, together: the setup creates and funds the account
 * once and names it again for a resume, and the owner's approval is read, checked and signed by the account's owner.
 */
test('the Native hooks set up the account and accept only its owner\'s approval of the reviewed policy', async () => {
  const {state: chain, fetch} = ledger(), signed = [];
  globalThis.fetch = fetch;
  const prepared = await ownerChain.keypairSetup.prepare({network, ...roles, amount: '5'});
  const signedPayload = prepared.complete(await ownerSigns(signed)(prepared.step));
  const read = ownerChain.keypairSetup.read(signedPayload, network);
  assert.deepEqual([read.hash, read.wallet, read.agent], [prepared.step.hash, prepared.wallet, roles.agent]);
  assert.equal(await ownerChain.keypairSetup.send(network, signedPayload, prepared.step.hash), 8);
  assert.deepEqual(await ownerChain.transaction(network, prepared.step.hash), {hash: prepared.step.hash, ledger: 8, successful: true});
  assert.equal(nativeSetupOf(chain.posted[0], network).startingBalance, WALLET_RESERVE + WALLET_FEE_FLOAT + 50_000_000n);
  assert.deepEqual(ownerChain.keypairSetup.configuration(network, prepared.wallet, roles.owner, roles.agent, roles.server),
    nativeWalletConfiguration(network, prepared.wallet, roles.owner, roles.agent, roles.server));
  // The approval of the reviewed policy for this account holds; its owner signs it, and only that signature counts.
  const {message} = approval({wallet: prepared.wallet});
  const fields = ownerChain.approval.read(message, network);
  assert.equal(ownerChain.approval.holds(fields, prepared.wallet, reviewedOf()), true);
  const step = ownerChain.approval.step(message);
  assert.deepEqual([step.action, step.hash], [APPROVE_POLICY, messageDigest(message)]);
  const walletOwner = await ownerChain.approval.walletOwner(network, prepared.wallet);
  assert.equal(walletOwner, roles.owner);
  const signature = Array.from(Buffer.from(await ownerSigns(signed)(step), 'base64'));
  assert.equal(ownerChain.approval.signedBy(walletOwner, step.hash, signature), true);
  assert.equal(ownerChain.approval.signedBy(walletOwner, step.hash, Array.from(agent.sign(Buffer.from(step.hash, 'hex')))), false);
  assert.deepEqual(signed, [SET_UP_WALLET, APPROVE_POLICY]);
});

test('an approval holds only for the reviewed policy, the wallet\'s own configuration and the requested values', async () => {
  const {fetch} = ledger();
  globalThis.fetch = fetch;
  const setup = await createWallet(fetch);
  const holds = (message, policy) => {
    const fields = ownerChain.approval.read(message, network);
    return fields !== null && ownerChain.approval.holds(fields, setup.wallet, policy);
  };
  // A change: the installed policy with the requested value replaced.
  const installed = installedOf(setup.wallet), change = {payment_limit: {Int: '5'}};
  const changed = {source: installed.source, rules: installed.rules, params: {...installed.params, ...change}};
  const unconditional = 'use allowit::prelude::*;\npub fn execute(_: &AllowitContext) -> allowit::Result { Ok(()) }\n';
  for (const [name, message] of Object.entries({
    'another source': approval({wallet: setup.wallet, source: unconditional, sourceHash: hex(sha(unconditional))}).message,
    'another value beside the requested one': approval({wallet: setup.wallet, params: {daily_spending_limit: {Int: '999999999'}, payment_limit: {Int: '5'}}}).message,
    'other values than the requested ones': approval({wallet: setup.wallet, params: {payment_limit: {Int: '999'}}}).message,
    'other rules': approval({wallet: setup.wallet, rules: []}).message,
    'another wallet': approval({wallet: Keypair.random().publicKey()}).message,
    'a raised fee ceiling': approval({wallet: setup.wallet, maxFeeStroops: 10_000_000}).message,
    'another asset': approval({wallet: setup.wallet, asset: Asset.native().contractId(Networks.PUBLIC)}).message,
    'an added field': approval({wallet: setup.wallet, zfeePayer: 'server'}).message,
  })) assert.equal(holds(message, changed), false, name);
  assert.equal(holds(approval({wallet: setup.wallet}).message, changed), true);
  // A deployment: the reviewed policy, with its rules checked when the host states them.
  assert.equal(holds(approval({wallet: setup.wallet, params: {payment_limit: {Int: '500'}}}).message, reviewedOf()), false);
  assert.equal(holds(approval({wallet: setup.wallet}).message, {...reviewedOf(), rules: []}), false);
  const {source, params} = reviewedOf();
  assert.equal(holds(approval({wallet: setup.wallet}).message, {source, params}), true);
});

test('an approval names the asset of the reviewed policy: XLM without one, and never another asset than the reviewed one', async () => {
  const {fetch} = ledger();
  const wallet = Keypair.random().publicKey();
  const holds = (message, policy) => {
    const fields = ownerChain.approval.read(message, network);
    return fields !== null && ownerChain.approval.holds(fields, wallet, policy);
  };
  const usdcContract = new Asset(usdc.symbol, usdc.issuer).contractId(Networks.TESTNET);
  const inUsdc = approval({wallet, asset: usdcContract, assetSymbol: 'USDC', assetIssuer: usdc.issuer}).message, inXlm = approval({wallet}).message;
  assert.equal(holds(inUsdc, {...reviewedOf(), asset: usdc}), true);
  assert.equal(holds(inXlm, {...reviewedOf(), asset: {symbol: 'XLM', issuer: null}}), true);
  assert.equal(holds(inXlm, {...reviewedOf(), asset: null}), true);
  // The reviewed policy pays in one asset and the approval names another one.
  assert.equal(holds(inUsdc, reviewedOf()), false);
  assert.equal(holds(inXlm, {...reviewedOf(), asset: usdc}), false);
  assert.equal(holds(inUsdc, {...reviewedOf(), asset: mainnetUsdc}), false);
  // The code and the issuer of the reviewed asset with the contract of another asset.
  assert.equal(holds(approval({wallet, asset: nativeXlm, assetSymbol: 'USDC', assetIssuer: usdc.issuer}).message, {...reviewedOf(), asset: usdc}), false);
  // An approval that leaves the asset out and names properties that every object inherits holds for nothing.
  const {payload} = approval({wallet});
  const inherited = Object.fromEntries(Object.entries({...payload, constructor: null, toString: null, valueOf: null}).filter(([key]) => !['asset', 'assetSymbol', 'assetIssuer'].includes(key)).sort(([a], [b]) => (a < b ? -1 : 1)));
  const withoutAsset = `AllowIt Native policy approval v1\n${JSON.stringify(inherited)}`;
  assert.ok(ownerChain.approval.read(withoutAsset, network));
  for (const asset of [usdc, undefined, null]) assert.equal(holds(withoutAsset, {...reviewedOf(), asset}), false, JSON.stringify(asset));
  // A reviewed asset that is no asset holds for nothing.
  for (const asset of [{symbol: 'USDC', issuer: null}, {symbol: 'USDC', issuer: 'GISSUER'}, 'USDC'])
    assert.equal(holds(inUsdc, {...reviewedOf(), asset}), false, JSON.stringify(asset));
  // The hooks of the SDK's workflow carry the asset: the setup, the read of its signed bytes and the document.
  globalThis.fetch = fetch;
  const prepared = await ownerChain.keypairSetup.prepare({network, ...roles, amount: '0.01', asset: usdc});
  const signedPayload = prepared.complete(await ownerSigns([])(prepared.step));
  const signedRead = ownerChain.keypairSetup.read(signedPayload, network);
  // The signed bytes state the asset and the amount that they fund, so a resume checks them and no saved metadata.
  assert.deepEqual([signedRead.asset, signedRead.amount], [usdc, '0.01']);
  assert.deepEqual(nativeSetupOf(signedPayload, network), {...roles, wallet: prepared.wallet, startingBalance: 35_000_000n, asset: usdc, funding: 100_000n});
  const configuration = ownerChain.keypairSetup.configuration(network, prepared.wallet, roles.owner, roles.agent, roles.server, usdc);
  assert.deepEqual([configuration.asset, configuration.assetSymbol, configuration.assetIssuer], [usdcContract, 'USDC', usdc.issuer]);
  await assert.rejects(ownerChain.keypairSetup.prepare({network, ...roles, amount: '0.00000001', asset: usdc}), /Enter an amount of USDC with at most seven decimals/);
  await assert.rejects(prepareNativeSetup({network, ...roles, amount: '1.123456789', fetch}), /Enter an amount of XLM with at most seven decimals/);
});

test('the owner pays every part of a setup: the server\'s account is no source, pays nothing and only becomes a signer', () => {
  const wallet = Keypair.random().publicKey();
  const tx = nativeSetupTransaction(terms(wallet));
  // The owner's account is the source of the transaction: it pays the fee and every operation without a source of its own.
  assert.equal(tx.source, roles.owner);
  const [create, ...rest] = tx.operations;
  // The creation has no source of its own: the owner's account sends the starting balance, which holds every reserve.
  assert.deepEqual([create.type, create.source, create.destination], ['createAccount', undefined, wallet]);
  assert.equal(BigInt(Math.round(Number(create.startingBalance) * 1e7)), walletStartingBalance(50_000_000n));
  assert.ok(walletStartingBalance(0n) >= WALLET_RESERVE + WALLET_FEE_FLOAT);
  // Every other operation is the new account's own: it only names its signers and thresholds and moves no XLM.
  for (const op of rest) assert.deepEqual([op.type, op.source], ['setOptions', wallet]);
  const named = [tx.source, ...tx.operations.map(op => op.source).filter(Boolean)];
  assert.ok(!named.includes(roles.server), 'the server account is the source of nothing');
  assert.equal(tx.operations.filter(op => ['payment', 'createAccount', 'beginSponsoringFutureReserves', 'accountMerge'].includes(op.type)).length, 1);
  assert.equal(rest.at(-1).signer.ed25519PublicKey, roles.server);
});

test('a setup signed by another account than the owner is refused before it is sent', async () => {
  const {state: chain, fetch} = ledger();
  const stranger = Keypair.random();
  const prepared = await prepareNativeSetup({network, ...roles, amount: '5', fetch});
  const tx = TransactionBuilder.fromXDR(prepared.step.payload, Networks.TESTNET);
  tx.sign(stranger);
  assert.throws(() => prepared.complete(tx.toXDR()), /another account than the owner/);
  assert.equal(chain.posted.length, 0);
  // The owner then signs, and the setup goes through.
  const signedPayload = prepared.complete(await ownerSigns([])(prepared.step));
  assert.equal(await sendNativeSetup(network, signedPayload, prepared.step.hash, fetch), 8);
  assert.equal(chain.posted.length, 1);
});
