import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import test from 'node:test';
import {Asset, Keypair, Networks, Operation, TransactionBuilder, Account} from '@stellar/stellar-sdk/base';
import {
  APPROVE_POLICY, SET_UP_WALLET, WALLET_FEE_FLOAT, WALLET_RESERVE, WalletSetupPendingError, approvalMessage, approvalStep, messageDigest,
  nativeSetupOf, nativeSetupTransaction, nativeWalletConfiguration, policyApproval, setUpNativeWallet, walletStartingBalance,
} from '../dist/native-wallet.js';
import {ownerChain} from '../dist/owner-chain.js';

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
test('the Native hooks set up the account once and accept only its owner\'s approval of the reviewed policy', async () => {
  const {state: chain, fetch} = ledger(), signed = [], journal = journalOf();
  globalThis.fetch = fetch;
  const input = {network, ...roles, amount: '5', sign: ownerSigns(signed), onStep() {}, journal, key: 'flow:wallet-setup', retain: true};
  const setup = await ownerChain.keypairSetup.run(input);
  // The signed setup stays saved for the registration, and names this wallet and agent.
  const saved = JSON.parse(journal.get('flow:wallet-setup'));
  const named = ownerChain.keypairSetup.of(saved.signedPayload, network);
  assert.deepEqual([named.wallet, named.agent], [setup.wallet, roles.agent]);
  assert.equal(nativeSetupOf(chain.posted[0], network).startingBalance, WALLET_RESERVE + WALLET_FEE_FLOAT + 50_000_000n);
  // A resume names the same account and signs no second setup.
  const again = await ownerChain.keypairSetup.run(input);
  assert.deepEqual([again.wallet, signed, chain.posted.length], [setup.wallet, [SET_UP_WALLET], 1]);
  // The approval of the reviewed policy for this account holds; its owner signs it, and only that signature counts.
  const {message} = approval({wallet: setup.wallet});
  const fields = ownerChain.approval.read(message, network);
  assert.equal(ownerChain.approval.holds(fields, setup.wallet, reviewedOf()), true);
  const step = ownerChain.approval.step(message);
  assert.deepEqual([step.action, step.hash], [APPROVE_POLICY, messageDigest(message)]);
  const owner = await ownerChain.approval.walletOwner(network, setup.wallet);
  assert.equal(owner, roles.owner);
  const signature = Array.from(Buffer.from(await ownerSigns(signed)(step), 'base64'));
  assert.equal(ownerChain.approval.signedBy(owner, step.hash, signature), true);
  assert.equal(ownerChain.approval.signedBy(owner, step.hash, Array.from(agent.sign(Buffer.from(step.hash, 'hex')))), false);
});

test('an approval holds only for the reviewed policy, the wallet\'s own configuration and the requested values', async () => {
  const {fetch} = ledger();
  globalThis.fetch = fetch;
  const setup = await setUpNativeWallet({network, ...roles, amount: '0', sign: ownerSigns([]), onStep() {}, journal: journalOf(), key: 'k', fetch});
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

test('a setup signed by another account than the owner is refused before it is saved or sent', async () => {
  const {state: chain, fetch} = ledger(), journal = journalOf();
  globalThis.fetch = fetch;
  const stranger = Keypair.random();
  const strangerSigns = async step => {
    const tx = TransactionBuilder.fromXDR(step.payload, Networks.TESTNET);
    tx.sign(stranger);
    return tx.toXDR();
  };
  await assert.rejects(setUpNativeWallet({network, ...roles, amount: '5', sign: strangerSigns, onStep() {}, journal, key: 'k', fetch}), /another account than the owner/);
  assert.deepEqual([journal.map.size, chain.posted.length], [0, 0]);
  // The owner then signs, and the setup goes through.
  const setup = await setUpNativeWallet({network, ...roles, amount: '5', sign: ownerSigns([]), onStep() {}, journal, key: 'k', fetch});
  assert.equal(chain.posted.length, 1);
  assert.ok(setup.wallet);
});
