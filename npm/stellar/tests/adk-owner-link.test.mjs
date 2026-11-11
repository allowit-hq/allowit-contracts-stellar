import assert from 'node:assert/strict';
import test from 'node:test';
import {ADK_OWNER_FRAGMENT, adkAgentPrompt, adkParamLines, parseAdkOwnerLink} from '../dist/adk-owner-link.js';
import {stellarAssetContractId} from '../dist/stellar-wallet.js';

const proposal = {
  network: 'stellar:testnet', revision: 2, title: 'Pay for access', explanation: 'Use the approved limit.',
  code: '/// Pay €1', sourceHash: 'a'.repeat(64), paramsHash: 'b'.repeat(64), params: {payment_limit: {Int: '1'}},
};
const fragment = value => ADK_OWNER_FRAGMENT + Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');

test('the link keeps the exact proposal and rejects other networks, extra fields and untyped params', () => {
  const workPrompt = 'Run the approved task.';
  assert.deepEqual(parseAdkOwnerLink(fragment({proposal, workPrompt})), {proposal, workPrompt});
  for (const altered of [{...proposal, network: 'stellar:mainnet'}, {...proposal, ownerKey: 'unexpected'},
    {...proposal, paramsHash: 'invalid'}, {...proposal, params: {payment_limit: 1}}]) {
    assert.throws(() => parseAdkOwnerLink(fragment({proposal: altered, workPrompt})), /The agent policy link is invalid/);
  }
});

test('the review shows labelled params and the prompt names the RPC and a non-default origin', () => {
  const xlm = stellarAssetContractId('XLM', null, 'stellar:testnet');
  assert.deepEqual(adkParamLines({
    payment_limit: {Int: '50000000'}, tokens: {List: [{Addr: xlm}]}, operations: {List: [{Str: '*'}]},
    expires_at: {Int: '1800000000'}, call_limit: {Int: '3'},
  }).map(line => `${line.label}: ${line.value}`), [
    'Per operation: 5 XLM', 'Assets: XLM', 'Operations: Any', 'Expires at: 2027-01-15T08:00:00Z', 'Operation count: 3',
  ]);
  const staging = adkAgentPrompt('Run the approved task.', 'https://staging.allowit.ai', 'policy-id', 'policy-wallet', 'agent-key');
  assert.match(staging, /Stellar Testnet policy: policy-id\nPolicy wallet: policy-wallet\nAgent public key: agent-key/);
  assert.match(staging, /`ALLOWIT_URL=https:\/\/staging\.allowit\.ai allowit --rail stellar:testnet --rpc-url <independent Stellar Testnet RPC URL> wallet import allowit-stellar-profile\.json`/);
  assert.doesNotMatch(adkAgentPrompt('Run.', 'https://app.allowit.xyz', 'p', 'w', 'a'), /ALLOWIT_URL/);
});

test('a review link carries the chat-collected agent key and amount and refuses any other key', async () => {
  const {parseReviewLink, reviewAgentPrompt} = await import('../dist/adk-owner-link.js');
  const proposal = {network: 'stellar:testnet', revision: 1, title: 'Pay Sol', explanation: '', code: 'fn policy() {}',
    sourceHash: 'ab'.repeat(32), paramsHash: 'cd'.repeat(32), params: {payment_limit: {Int: '50000000'}}};
  const link = envelope => `#adk-proposal-v1=${Buffer.from(JSON.stringify(envelope)).toString('base64url')}`;
  const full = parseReviewLink(link({proposal, workPrompt: 'Pay Sol 5 XLM.', agent: ' GAGENT ', amount: '5'}));
  assert.deepEqual(full, {proposal, workPrompt: 'Pay Sol 5 XLM.', agent: 'GAGENT', amount: '5'});
  // A missing agent key or amount is null, so the host returns the owner to the conversation.
  const bare = parseReviewLink(link({proposal, workPrompt: 'Pay Sol 5 XLM.'}));
  assert.deepEqual([bare.agent, bare.amount], [null, null]);
  assert.equal(parseReviewLink(link({proposal, workPrompt: 'w', agent: '  ', amount: null})).agent, null);
  for (const bad of [
    {proposal, workPrompt: 'w', agent: 7},
    {proposal, workPrompt: 'w', amount: 'x'.repeat(129)},
    {proposal, workPrompt: 'w', extra: true},
    {proposal: {...proposal, network: 'other:testnet'}, workPrompt: 'w'},
    {proposal: {...proposal, sourceHash: 'zz'}, workPrompt: 'w'},
    {proposal: {...proposal, asset: {symbol: 'X'}}, workPrompt: 'w'},
    {proposal, workPrompt: ''},
  ]) assert.throws(() => parseReviewLink(link(bad)), /agent policy link is invalid/);
  assert.throws(() => parseReviewLink('#other=abc'), /invalid/);
  const prompt = reviewAgentPrompt(full, 'https://app.allowit.xyz', 'policy-1', 'CWALLET', 'GAGENT');
  assert.match(prompt, /^Pay Sol 5 XLM\.\n/);
  assert.match(prompt, /Policy wallet: CWALLET/);
});
