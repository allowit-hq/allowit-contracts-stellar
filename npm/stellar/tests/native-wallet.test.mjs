import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import test from 'node:test';
import {Keypair, Networks, Operation, TransactionBuilder, Account} from '@stellar/stellar-sdk/base';
import {
  APPROVE_POLICY, SET_UP_WALLET, WALLET_FEE_FLOAT, WALLET_RESERVE, WalletSetupPendingError, approvalMessage, approvalStep, messageDigest,
  nativeSetupOf, nativeSetupTransaction, nativeWalletConfiguration, policyApproval, setUpNativeWallet, walletStartingBalance,
} from '../dist/native-wallet.js';
import {installAndFund, OwnerFlowError, updateParams} from '../dist/owner-flow.js';

const network = 'stellar:testnet';
const owner = Keypair.random(), agent = Keypair.random(), server = Keypair.random();
const roles = {owner: owner.publicKey(), agent: agent.publicKey(), server: server.publicKey()};
const sha = text => createHash('sha256').update(text).digest();
const hex = bytes => Buffer.from(bytes).toString('hex');
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
  assert.deepEqual(nativeSetupOf(tx.toXDR(), network), {...roles, wallet, startingBalance: 80_000_000n});
  assert.equal(walletStartingBalance(0n), WALLET_RESERVE + WALLET_FEE_FLOAT);
  assert.throws(() => walletStartingBalance(-1n));
  // The four roles are four accounts, and the request identity and the sequence are bounded.
  assert.throws(() => nativeSetupTransaction(terms(roles.agent)), /four accounts/);
  assert.throws(() => nativeSetupTransaction(terms(wallet, {agent: 'GAGENT'})), /agent account is invalid/);
  assert.throws(() => nativeSetupTransaction(terms(wallet, {requestId: 'short'})));
  assert.throws(() => nativeSetupTransaction(terms(wallet, {sequence: '-1'})));
});

test('a transaction that is not exactly the setup is not read as one', () => {
  const wallet = Keypair.random().publicKey();
  const build = ops => {
    const builder = new TransactionBuilder(new Account(roles.owner, '41'), {fee: '100', networkPassphrase: Networks.TESTNET, timebounds: {minTime: 0, maxTime: 2_000_000_000}});
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

test('the owner signs once: the new account countersigns, the network takes the setup and the journal is empty', async () => {
  const {state, fetch} = ledger(), signed = [], journal = journalOf(), steps = [];
  const result = await setUpNativeWallet({network, ...roles, amount: '5', sign: ownerSigns(signed), onStep: s => steps.push(s), journal, key: 'k', fetch});
  assert.deepEqual(signed, [SET_UP_WALLET]);
  assert.equal(state.posted.length, 1);
  const tx = TransactionBuilder.fromXDR(state.posted[0], Networks.TESTNET), setup = nativeSetupOf(state.posted[0], network);
  assert.deepEqual({...setup, startingBalance: undefined}, {...roles, wallet: result.wallet, startingBalance: undefined});
  assert.equal(setup.startingBalance, WALLET_RESERVE + WALLET_FEE_FLOAT + 50_000_000n);
  // Two signatures over the same hash: the owner's and the new account's own.
  assert.equal(tx.signatures.length, 2);
  for (const key of [owner, Keypair.fromPublicKey(result.wallet)])
    assert.ok(tx.signatures.some(s => key.verify(tx.hash(), Buffer.from(s.signature instanceof Uint8Array ? s.signature : s.signature.value))), key.publicKey());
  assert.deepEqual([result.transactionHash, result.ledger], [hex(tx.hash()), 8]);
  assert.deepEqual(result.configuration, nativeWalletConfiguration(network, result.wallet, roles.owner, roles.agent, roles.server));
  assert.equal(journal.map.size, 0);
  // Each setup makes a new account: the key is random and nothing keeps it.
  const second = await setUpNativeWallet({network, ...roles, amount: '5', sign: ownerSigns(signed), onStep() {}, journal, key: 'k', fetch});
  assert.notEqual(second.wallet, result.wallet);
  // A wallet that returns another transaction, or an unsigned one, sends nothing.
  const before = state.posted.length;
  await assert.rejects(setUpNativeWallet({network, ...roles, amount: '5', sign: async () => nativeSetupTransaction(terms(Keypair.random().publicKey())).toXDR(), onStep() {}, journal, key: 'k', fetch}), /another transaction/);
  await assert.rejects(setUpNativeWallet({network, ...roles, amount: '5', sign: async step => step.payload, onStep() {}, journal, key: 'k', fetch}), /another transaction/);
  for (const amount of ['-1', '1.00000001', 'all']) await assert.rejects(setUpNativeWallet({network, ...roles, amount, sign: ownerSigns(signed), onStep() {}, journal, key: 'k', fetch}));
  assert.equal(state.posted.length, before);
  assert.equal(journal.map.size, 0);
});

test('a setup whose result is unknown stays saved and is settled before anything is signed again', async () => {
  const {state, fetch} = ledger({send: 'lost'}), signed = [], journal = journalOf();
  const input = {network, ...roles, amount: '5', sign: ownerSigns(signed), onStep() {}, journal, key: 'k', fetch};
  await assert.rejects(setUpNativeWallet(input), error => error instanceof WalletSetupPendingError && error.retry);
  const saved = JSON.parse(journal.get('k'));
  const wallet = nativeSetupOf(saved.signedPayload, network).wallet;
  // The network has no record yet and the time bound lasts: the same bytes go again, and nothing is signed.
  state.send = 'ok';
  const settled = await setUpNativeWallet(input);
  assert.deepEqual([settled.wallet, settled.transactionHash, signed.length, state.posted.length], [wallet, saved.hash, 1, 2]);
  assert.equal(state.posted[0], state.posted[1]);
  assert.equal(journal.map.size, 0);
  // Another agent key or amount never replaces a saved signed setup.
  state.send = 'lost';
  await assert.rejects(setUpNativeWallet(input), WalletSetupPendingError);
  for (const other of [{agent: Keypair.random().publicKey()}, {amount: '6'}])
    await assert.rejects(setUpNativeWallet({...input, ...other}), /another agent key or amount/);
  assert.equal(signed.length, 2);
  // The network holds the setup as failed: it created nothing, and a new setup with a new account is signed.
  state.send = 'failed';
  const failed = JSON.parse(journal.get('k'));
  state.held.set(failed.hash, {hash: failed.hash, successful: false, ledger: 9, signed: failed.signedPayload});
  state.send = 'ok';
  const replaced = await setUpNativeWallet(input);
  assert.notEqual(replaced.wallet, nativeSetupOf(failed.signedPayload, network).wallet);
  assert.equal(signed.length, 3);
  // Unreadable saved bytes are never replaced.
  await assert.rejects(setUpNativeWallet({...input, journal: journalOf({k: '{"hash":"x"}'})}), /unreadable/);
});

test('a retained setup names the same wallet again until its caller drops it', async () => {
  const {state, fetch} = ledger(), signed = [], journal = journalOf();
  const input = {network, ...roles, amount: '0', sign: ownerSigns(signed), onStep() {}, journal, key: 'k', retain: true, fetch};
  const first = await setUpNativeWallet(input);
  assert.ok(journal.get('k'));
  const again = await setUpNativeWallet(input);
  assert.deepEqual([again.wallet, again.transactionHash, signed.length, state.posted.length], [first.wallet, first.transactionHash, 1, 1]);
  assert.equal(nativeSetupOf(state.posted[0], network).startingBalance, WALLET_RESERVE + WALLET_FEE_FLOAT);
});

const approval = (extra = {}) => {
  const source = 'use allowit::prelude::*;\n// "5 € per day"\n';
  const payload = {asset: 'C', assetIssuer: null, assetSymbol: 'XLM', irHash: '', language: 'portable', maxFeeStroops: 100000, moduleDigest: '00', network,
    params: {payment_limit: {Int: '5'}}, paramsHash: 'ab'.repeat(32), policyId: 'policy-1', policyInstance: '07'.repeat(32), revision: 2, route: 'native',
    rules: ['payment_limit'], source, sourceHash: hex(sha(source)), tier: 'standard', version: 1, wallet: Keypair.random().publicKey(), ...extra};
  const sorted = Object.fromEntries(Object.keys(payload).sort().map(key => [key, payload[key]]));
  return {payload, message: `AllowIt Native policy approval v1\n${JSON.stringify(sorted)}`};
};

test('only the exact approval message of this network is read, and its step carries the message unchanged', () => {
  const {payload, message} = approval();
  assert.deepEqual(policyApproval(message, network), {policyId: 'policy-1', revision: 2, network, wallet: payload.wallet, source: payload.source, sourceHash: payload.sourceHash, paramsHash: payload.paramsHash, params: payload.params});
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
  })) assert.equal(policyApproval(text, network), null, name);
  assert.equal(policyApproval(message, 'stellar:other'), null);
  assert.equal(policyApproval(null, network), null);
});

/** A service for one Native policy: the setup requirement, the registration, the approval and its confirmation. */
function nativeService({registerFails = 0} = {}) {
  const calls = [], state = {wallet: null, approved: false, registerFails};
  const refusal = (code, details) => Object.assign(new Error(code), {status: 409, code, details});
  const ask = async (path, body) => {
    calls.push([path, body]);
    if (path === 'native/deploy/prepare') {
      if (!state.wallet) throw refusal('wallet_setup_required', {walletKind: 'native', policyId: 'policy-1', network, owner: roles.owner, agent: roles.agent, server: roles.server});
      return {policyId: 'policy-1', installed: true, approved: state.approved, walletKind: 'native', wallet: state.wallet, installation: {wallet: state.wallet}};
    }
    if (path === 'native/register') {
      if (state.registerFails-- > 0) throw new Error('The service could not be reached.');
      state.wallet = body.configuration.wallet;
      return {registered: true, wallet: state.wallet, policyId: body.policyId};
    }
    if (path === 'native/approval') return {required: !state.approved, message: approval({wallet: state.wallet}).message};
    if (path === 'micro/allocation/confirm') {state.approved = true; return {active: true};}
    throw new Error(path);
  };
  return {ask, calls, state};
}

test('a Native policy deploys with two owner signatures: the wallet setup and the approval of the policy', async () => {
  const {state: chain, fetch} = ledger(), signed = [], journal = journalOf();
  globalThis.fetch = fetch;
  const {ask, calls, state} = nativeService();
  const input = {network, historyPauseMs: 0, ask, sign: ownerSigns(signed), journal, key: 'flow', policyId: 'policy-1', agent: roles.agent, amount: '5', onStep() {}};
  const result = await installAndFund(input);
  assert.deepEqual(signed, [SET_UP_WALLET, APPROVE_POLICY]);
  assert.equal(result.wallet, state.wallet);
  assert.deepEqual(result.receipts.map(r => r.action), [SET_UP_WALLET, APPROVE_POLICY]);
  // One transaction created and funded the account: no fee account, no funding step and no server step.
  assert.equal(chain.posted.length, 1);
  assert.equal(nativeSetupOf(chain.posted[0], network).startingBalance, WALLET_RESERVE + WALLET_FEE_FLOAT + 50_000_000n);
  assert.deepEqual(calls.map(([path]) => path), ['native/deploy/prepare', 'native/register', 'native/deploy/prepare', 'native/approval', 'micro/allocation/confirm']);
  const register = calls[1][1];
  assert.deepEqual(register, {configuration: nativeWalletConfiguration(network, state.wallet, roles.owner, roles.agent, roles.server), policyId: 'policy-1'});
  const confirm = calls[4][1];
  assert.deepEqual([confirm.id, confirm.revision, confirm.sourceApproval.length, confirm.sourceApproval[0].signer], ['policy-1', 2, 1, roles.owner]);
  assert.equal(confirm.sourceApproval[0].signature.length, 64);
  assert.ok(owner.verify(Buffer.from(messageDigest(approval({wallet: state.wallet}).message), 'hex'), Buffer.from(confirm.sourceApproval[0].signature)));
  assert.equal(journal.get('flow:wallet-setup'), null);
  assert.deepEqual(JSON.parse(journal.get('flow:funded')), {policyId: 'policy-1', agent: roles.agent, amount: '5'});
  // The deployed policy signs nothing again.
  const again = await installAndFund(input);
  assert.deepEqual([again.wallet, again.receipts.length, signed.length, chain.posted.length], [state.wallet, 0, 2, 1]);
});

test('a registration that fails keeps the signed setup: the next run registers the same wallet and signs no second one', async () => {
  const {state: chain, fetch} = ledger(), signed = [], journal = journalOf();
  globalThis.fetch = fetch;
  const {ask, state} = nativeService({registerFails: 1});
  const input = {network, historyPauseMs: 0, ask, sign: ownerSigns(signed), journal, key: 'flow', policyId: 'policy-1', agent: roles.agent, amount: '5', onStep() {}};
  await assert.rejects(installAndFund(input), /could not be reached/);
  const created = nativeSetupOf(JSON.parse(journal.get('flow:wallet-setup')).signedPayload, network).wallet;
  const result = await installAndFund(input);
  assert.deepEqual([result.wallet, state.wallet, chain.posted.length], [created, created, 1]);
  assert.deepEqual(signed, [SET_UP_WALLET, APPROVE_POLICY]);
  // Roles that name another agent or policy are refused before anything is signed.
  const {ask: other} = nativeService();
  const wrong = async (path, body) => {
    try {return await other(path, body);} catch (error) {
      if (error.code === 'wallet_setup_required') error.details.agent = Keypair.random().publicKey();
      throw error;
    }
  };
  const before = signed.length;
  await assert.rejects(installAndFund({...input, ask: wrong, journal: journalOf(), key: 'other'}), error => error instanceof OwnerFlowError && /named no roles/.test(error.message));
  assert.equal(signed.length, before);
});

test('a value change of a Native wallet is one approval signature and no transaction', async () => {
  const {state: chain, fetch} = ledger(), signed = [], journal = journalOf();
  globalThis.fetch = fetch;
  const setup = await setUpNativeWallet({network, ...roles, amount: '0', sign: ownerSigns([]), onStep() {}, journal: journalOf(), key: 'k', fetch});
  const {message} = approval({wallet: setup.wallet, revision: 3});
  const calls = [];
  const ask = async (path, body) => {
    calls.push([path, body]);
    if (path === 'native/owner/prepare') return {policyId: 'policy-1', approval: {payload: {}, message, method: 'sep53'}, revision: 3};
    if (path === 'native/owner/submit') return {policyId: 'policy-1', action: 'update_params', status: 'confirmed'};
    throw new Error(path);
  };
  const input = {network, historyPauseMs: 0, ask, sign: ownerSigns(signed), journal, key: 'change', policyId: 'policy-1', params: {payment_limit: {Int: '5'}}, onStep() {}};
  const result = await updateParams(input);
  assert.deepEqual([result.done, result.receipts.map(r => r.action), signed], [true, ['update_params'], [APPROVE_POLICY]]);
  assert.equal(chain.posted.length, 1);
  const submit = calls[1][1];
  assert.deepEqual([submit.policyId, submit.payload, submit.sourceApproval[0].signer, submit.sourceApproval[0].signature.length], ['policy-1', message, roles.owner, 64]);
  // A confirmed change is not prepared or signed again.
  const again = await updateParams(input);
  assert.deepEqual([again.done, again.receipts.length, signed.length, calls.length], [true, 0, 1, 2]);
  // An approval of another policy is never signed.
  const foreign = async path => path === 'native/owner/prepare' ? {policyId: 'policy-1', approval: {message: approval({policyId: 'policy-2', wallet: setup.wallet}).message}} : {};
  await assert.rejects(updateParams({...input, ask: foreign, journal: journalOf(), key: 'other'}), /differs from this change/);
  assert.equal(signed.length, 1);
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

test('an installed Native wallet that this workflow did not fund is funded by the owner', async () => {
  const signed = [], wallet = Keypair.random().publicKey(), calls = [];
  const fund = new TransactionBuilder(new Account(roles.owner, '41'), {fee: '100', networkPassphrase: Networks.TESTNET})
    .addOperation(Operation.payment({destination: wallet, asset: (await import('@stellar/stellar-sdk/base')).Asset.native(), amount: '5'})).setTimeout(300).build();
  const step = {action: 'fund', payload: fund.toXDR(), hash: hex(fund.hash()), expiresAt: Math.floor(Date.now() / 1000) + 300};
  const {state: chain, fetch} = ledger();
  globalThis.fetch = fetch;
  // The service sends the owner's signed funding; the ledger then holds it.
  chain.held.set(step.hash, {hash: step.hash, successful: true, ledger: 9, signed: fund.toXDR()});
  const ask = async (path, body) => {
    calls.push([path, body]);
    if (path === 'native/deploy/prepare') return {policyId: 'policy-1', installed: true, approved: true, walletKind: 'native', wallet, installation: {wallet}};
    if (path === 'native/owner/prepare') return {policyId: 'policy-1', step};
    if (path === 'native/owner/submit') return {policyId: 'policy-1', action: 'fund', status: 'confirmed', transactionHash: step.hash, ledger: 9};
    throw new Error(path);
  };
  const result = await installAndFund({network, historyPauseMs: 0, ask, sign: ownerSigns(signed), journal: journalOf(), key: 'existing', policyId: 'policy-1', agent: roles.agent, amount: '5', onStep() {}});
  assert.equal(result.wallet, wallet);
  // The funding is prepared and signed by the owner; nothing returns before it.
  assert.ok(calls.some(([path, body]) => path === 'native/owner/prepare' && body.action === 'fund' && body.amount === '5'));
  assert.deepEqual(signed, ['fund']);
  assert.deepEqual(result.receipts.map(r => r.action), ['fund']);
});

test('a Native value change signs only the requested values, keeps its signed approval until a confirmed reply, and sends it again', async () => {
  const {fetch} = ledger(), signed = [];
  globalThis.fetch = fetch;
  const setup = await setUpNativeWallet({network, ...roles, amount: '0', sign: ownerSigns([]), onStep() {}, journal: journalOf(), key: 'k', fetch});
  const params = {payment_limit: {Int: '5'}};
  const base = {network, historyPauseMs: 0, sign: ownerSigns(signed), policyId: 'policy-1', params, onStep() {}};
  // Other values than the requested ones are never signed.
  const other = approval({wallet: setup.wallet, params: {payment_limit: {Int: '999'}}}).message;
  await assert.rejects(updateParams({...base, journal: journalOf(), key: 'a', ask: async path => path === 'native/owner/prepare' ? {policyId: 'policy-1', approval: {message: other}} : {}}),
    /other values than this change/);
  assert.equal(signed.length, 0);
  // A reply that is lost, then a pending one: the signed approval stays saved and nothing is signed again.
  const {message} = approval({wallet: setup.wallet});
  const journal = journalOf(), submitted = [];
  let answers = [() => {throw new Error('reply lost');}, () => ({status: 'pending'}), () => ({policyId: 'policy-1', action: 'update_params', status: 'confirmed'})];
  let prepares = 0;
  const ask = async (path, body) => {
    if (path === 'native/owner/prepare') {prepares++; return {policyId: 'policy-1', approval: {message}};}
    if (path === 'native/owner/submit') {submitted.push(body); return answers.shift()();}
    throw new Error(path);
  };
  await assert.rejects(updateParams({...base, journal, key: 'b', ask}), /reply lost/);
  assert.ok(journal.get('b:approval'));
  await assert.rejects(updateParams({...base, journal, key: 'b', ask}), /did not confirm/);
  assert.equal(journal.get('b:updated'), null);
  const done = await updateParams({...base, journal, key: 'b', ask});
  assert.deepEqual([done.done, prepares, signed.length, submitted.length], [true, 1, 1, 3]);
  assert.ok(submitted.every(body => body.payload === message && JSON.stringify(body.sourceApproval) === JSON.stringify(submitted[0].sourceApproval)));
  assert.equal(journal.get('b:approval'), null);
  // A change with other values is refused while a signed approval of this change is saved.
  const held = journalOf();
  answers = [() => {throw new Error('reply lost');}];
  await assert.rejects(updateParams({...base, journal: held, key: 'c', ask}), /reply lost/);
  await assert.rejects(updateParams({...base, journal: held, key: 'c', ask, params: {payment_limit: {Int: '6'}}}), /another change/);
});

test('a registration whose reply is lost funds nothing again: the retained setup records its funding', async () => {
  const {state: chain, fetch} = ledger(), signed = [], journal = journalOf();
  globalThis.fetch = fetch;
  const {ask: service, calls, state} = nativeService();
  let lose = true;
  // The service registers the wallet, and its reply is lost once.
  const ask = async (path, body) => {
    const reply = await service(path, body);
    if (path === 'native/register' && lose) {lose = false; throw new Error('The reply was lost.');}
    return reply;
  };
  const input = {network, historyPauseMs: 0, ask, sign: ownerSigns(signed), journal, key: 'flow', policyId: 'policy-1', agent: roles.agent, amount: '5', onStep() {}};
  await assert.rejects(installAndFund(input), /reply was lost/);
  assert.ok(journal.get('flow:wallet-setup'));
  const result = await installAndFund(input);
  assert.equal(result.wallet, state.wallet);
  assert.deepEqual(signed, [SET_UP_WALLET, APPROVE_POLICY]);
  assert.equal(chain.posted.length, 1);
  assert.ok(!calls.some(([path, body]) => path === 'native/owner/prepare' && body?.action === 'fund'));
  assert.deepEqual(JSON.parse(journal.get('flow:funded')), {policyId: 'policy-1', agent: roles.agent, amount: '5'});
  assert.equal(journal.get('flow:wallet-setup'), null);
});
