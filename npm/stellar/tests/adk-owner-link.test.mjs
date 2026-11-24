import assert from 'node:assert/strict';
import test from 'node:test';
import {ADK_OWNER_FRAGMENT, adkAgentPrompt, adkParamLines, parseAdkOwnerLink} from '../dist/adk-owner-link.js';
import {stellarAssetContractId} from '../dist/stellar-wallet.js';
import plugin, {assets} from '../dist/plugin.js';

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
  }, assets('stellar:testnet')).map(line => `${line.label}: ${line.value}`), [
    'Per operation: 5 XLM', 'Assets: XLM', 'Operations: Any', 'Expires at: 2027-01-15T08:00:00Z', 'Operation count: 3',
  ]);
  const staging = adkAgentPrompt('Run the approved task.', 'https://staging.allowit.ai', 'policy-id', 'policy-wallet', 'agent-key', 'stellar:testnet');
  assert.match(staging, /Stellar Testnet policy: policy-id\nPolicy wallet: policy-wallet\nAgent public key: agent-key/);
  assert.match(staging, /`ALLOWIT_URL=https:\/\/staging\.allowit\.ai allowit --rail stellar:testnet --rpc-url <independent Stellar Testnet RPC URL> wallet import allowit-stellar-profile\.json`/);
  assert.doesNotMatch(adkAgentPrompt('Run.', 'https://app.allowit.ai', 'p', 'w', 'a', 'stellar:testnet'), /ALLOWIT_URL/);
});

test('a link on each network of the rail opens, in the unit of its own asset, and names its network', async () => {
  const {parseReviewLink, reviewAgentPrompt} = await import('../dist/adk-owner-link.js');
  const usdc = stellarAssetContractId('USDC', 'GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN', 'stellar:pubnet');
  const mainnet = {...proposal, network: 'stellar:pubnet',
    params: {payment_limit: {Int: '20000000'}, tokens: {List: [{Addr: usdc}]}}};
  const link = parseReviewLink(fragment({proposal: mainnet, workPrompt: 'Buy one report.', agent: 'GAGENT', amount: '20', walletKind: 'native'}));
  assert.deepEqual(link, {proposal: mainnet, workPrompt: 'Buy one report.', agent: 'GAGENT', amount: '20', walletKind: 'native'});
  assert.deepEqual(adkParamLines(mainnet.params, assets('stellar:pubnet')).map(line => line.value), ['2 USDC', 'USDC']);
  const prompt = reviewAgentPrompt(link, 'https://app.allowit.ai', 'policy-1', 'GWALLET', 'GAGENT');
  assert.match(prompt, /Stellar Mainnet policy: policy-1/);
  assert.match(prompt, /`allowit --rail stellar:pubnet --rpc-url <independent Stellar Mainnet RPC URL> wallet import/);
  assert.doesNotMatch(prompt, /testnet|Testnet/);
  // The Testnet link keeps its own network and unit.
  const testnet = parseReviewLink(fragment({proposal, workPrompt: 'w'}));
  assert.equal(testnet.proposal.network, 'stellar:testnet');
  assert.deepEqual(adkParamLines(proposal.params, assets('stellar:testnet')).map(line => line.value), ['0.0000001 XLM']);
  assert.match(reviewAgentPrompt(testnet, 'https://app.allowit.ai', 'p', 'w', 'a'), /Stellar Testnet policy: p/);
  // The Mainnet asset is no unit on Testnet: the amount stays in base units. An alias, or a network that the rail
  // does not list, is refused.
  assert.deepEqual(adkParamLines(mainnet.params, assets('stellar:testnet')).map(line => line.value), ['20000000', usdc]);
  // The plugin's hook, which the SDK calls with the link's network, reads the assets of that network.
  assert.deepEqual(plugin.review.paramLines(mainnet.params, 'stellar:pubnet').map(line => line.value), ['2 USDC', 'USDC']);
  assert.deepEqual(plugin.review.paramLines(mainnet.params, 'stellar:testnet').map(line => line.value), ['20000000', usdc]);
  // Only a list of one asset address names the unit, as Core reads the rule: several assets, a text entry or a
  // bare value leave the amount in base units.
  const xlm = stellarAssetContractId('XLM', null, 'stellar:pubnet');
  for (const tokens of [{List: [{Addr: usdc}, {Addr: xlm}]}, {List: [{Str: usdc}]}, {Addr: usdc}]) {
    assert.equal(adkParamLines({payment_limit: {Int: '20000000'}, tokens}, assets('stellar:pubnet'))[0].value, '20000000');
  }
  for (const network of ['stellar:mainnet', 'stellar-testnet', 'other:mainnet', '']) {
    assert.throws(() => parseReviewLink(fragment({proposal: {...mainnet, network}, workPrompt: 'w'})), /agent policy link is invalid/);
  }
});

test('a review link carries the chat-collected agent key and amount and refuses any other key', async () => {
  const {parseReviewLink, reviewAgentPrompt} = await import('../dist/adk-owner-link.js');
  const proposal = {network: 'stellar:testnet', revision: 1, title: 'Pay Sol', explanation: '', code: 'fn policy() {}',
    sourceHash: 'ab'.repeat(32), paramsHash: 'cd'.repeat(32), params: {payment_limit: {Int: '50000000'}}};
  const link = envelope => `#adk-proposal-v1=${Buffer.from(JSON.stringify(envelope)).toString('base64url')}`;
  const full = parseReviewLink(link({proposal, workPrompt: 'Pay Sol 5 XLM.', agent: ' GAGENT ', amount: '5'}));
  assert.deepEqual(full, {proposal, workPrompt: 'Pay Sol 5 XLM.', agent: 'GAGENT', amount: '5', walletKind: null});
  // A missing agent key or amount is null, so the host returns the owner to the conversation.
  const bare = parseReviewLink(link({proposal, workPrompt: 'Pay Sol 5 XLM.'}));
  assert.deepEqual([bare.agent, bare.amount, bare.walletKind], [null, null, null]);
  assert.equal(parseReviewLink(link({proposal, workPrompt: 'w', agent: '  ', amount: null})).agent, null);
  for (const bad of [
    {proposal, workPrompt: 'w', agent: 7},
    {proposal, workPrompt: 'w', amount: 'x'.repeat(129)},
    {proposal, workPrompt: 'w', extra: true},
    {proposal, workPrompt: 'w', walletKind: 7},
    {proposal, workPrompt: 'w', walletKind: ''},
    {proposal, workPrompt: 'w', walletKind: 'Standard'},
    {proposal, workPrompt: 'w', walletKind: 'k'.repeat(33)},
    {proposal: {...proposal, walletKind: 'standard'}, workPrompt: 'w'},
    {proposal: {...proposal, network: 'other:testnet'}, workPrompt: 'w'},
    {proposal: {...proposal, sourceHash: 'zz'}, workPrompt: 'w'},
    {proposal: {...proposal, asset: {symbol: 'X'}}, workPrompt: 'w'},
    {proposal, workPrompt: ''},
  ]) assert.throws(() => parseReviewLink(link(bad)), /agent policy link is invalid/);
  assert.throws(() => parseReviewLink('#other=abc'), /invalid/);
  // The kind that the owner chose in the chat travels beside the proposal. The eight proposal keys stay exact.
  for (const kind of ['native', 'simple', 'standard', 'custom']) {
    const chosen = parseReviewLink(link({proposal, workPrompt: 'w', agent: 'GAGENT', amount: '5', walletKind: kind}));
    assert.deepEqual(chosen, {proposal, workPrompt: 'w', agent: 'GAGENT', amount: '5', walletKind: kind});
  }
  assert.equal(parseReviewLink(link({proposal, workPrompt: 'w', walletKind: null})).walletKind, null);
  // The owner link without a review step carries no kind.
  assert.throws(() => parseAdkOwnerLink(link({proposal, workPrompt: 'w', walletKind: 'standard'})), /invalid/);
  const prompt = reviewAgentPrompt(full, 'https://app.allowit.ai', 'policy-1', 'CWALLET', 'GAGENT');
  assert.match(prompt, /^Pay Sol 5 XLM\.\n/);
  assert.match(prompt, /Policy wallet: CWALLET/);
});
