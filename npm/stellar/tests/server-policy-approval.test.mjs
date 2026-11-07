import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import test, {after} from 'node:test';
import {Keypair, StrKey} from '@stellar/stellar-sdk/base';

const fixture = JSON.parse(readFileSync(new URL('../../../crates/policy-bindings/tests/fixtures/server-policy-approval.json', import.meta.url)));
const nativeFixture = JSON.parse(readFileSync(new URL('../../../crates/allowit-stellar/tests/fixtures/provider/stellar-portable-approval.json', import.meta.url)));
const owner = Keypair.fromRawEd25519Seed(Buffer.alloc(32, 7));
const origin = 'https://staging.allowit.ai';
const passphrase = 'Test SDF Network ; September 2015';
const session = {address: owner.publicKey(), network: 'stellar', expiresAt: '2026-12-31T00:00:00Z'};
const requests = [], listeners = new Set();
let expectedMessage = fixture.message;
const previousWindow = globalThis.window, previousLocation = globalThis.location;
globalThis.window = {
  location: {origin},
  postMessage(request, target) {
    assert.equal(target, origin);
    requests.push(request.type);
    let response;
    switch (request.type) {
      case 'REQUEST_PUBLIC_KEY': response = {publicKey: owner.publicKey()}; break;
      case 'REQUEST_NETWORK_DETAILS': response = {networkDetails: {network: 'TESTNET', networkUrl: '', networkPassphrase: passphrase}}; break;
      case 'REQUEST_ALLOWED_STATUS': response = {isAllowed: true}; break;
      case 'SUBMIT_BLOB': {
        assert.equal(request.blob, expectedMessage);
        assert.equal(request.accountToSign, owner.publicKey());
        assert.equal(request.networkPassphrase, passphrase);
        const signed = owner.sign(stellarMessageDigest(request.blob));
        response = {signedBlob: Buffer.from(signed).toString('base64'), signerAddress: owner.publicKey()};
        break;
      }
      default: assert.fail(`Unexpected wallet request ${request.type}`);
    }
    queueMicrotask(() => {
      for (const listener of [...listeners]) listener({source: window, data: {
        source: 'FREIGHTER_EXTERNAL_MSG_RESPONSE', messagedId: request.messageId, ...response,
      }});
    });
  },
  addEventListener(type, listener) {assert.equal(type, 'message'); listeners.add(listener);},
  removeEventListener(type, listener) {assert.equal(type, 'message'); listeners.delete(listener);},
};
globalThis.location = window.location;
after(() => {
  if (previousWindow === undefined) delete globalThis.window; else globalThis.window = previousWindow;
  if (previousLocation === undefined) delete globalThis.location; else globalThis.location = previousLocation;
});

const {canonicalApprovalJson, signStellarSourceApproval, stellarMessageDigest} = await import('../dist/stellar-wallet.js');
const payload = fixture.payload;
const policy = {
  id: payload.policyId, revision: payload.revision, network: payload.network,
  code: payload.source, sourceHash: payload.sourceHash,
  runtime: {instanceBinding: {
    route: 'policyWallet', wallet: payload.wallet, policyInstance: payload.policyInstance,
    moduleDigest: payload.moduleDigest, installedSourceHash: payload.installedSourceHash,
    portable: {sourceHash: payload.sourceHash, paramsHash: payload.paramsHash,
      params: fixture.params, build: {serverBindings: payload.serverBindings}},
  }},
};
const approval = changed => ({method: 'sep53', payload: changed,
  message: `AllowIt Stellar server policy approval v1\n${canonicalApprovalJson(changed)}`});
const nativePolicy = nativeFixture.policy;
const nativeBinding = nativePolicy.runtime.instanceBinding;
const nativePortable = nativeBinding.portable;
const nativePayload = {
  version: 1, policyId: nativePolicy.id, revision: nativePolicy.revision, network: nativePolicy.network,
  wallet: nativeBinding.wallet, route: nativeBinding.route, policyInstance: nativeBinding.policyInstance,
  source: nativePolicy.code, sourceHash: nativePolicy.sourceHash, irHash: nativePolicy.irHash,
  moduleDigest: nativeBinding.moduleDigest, asset: nativeBinding.asset, assetSymbol: nativeBinding.assetSymbol,
  assetIssuer: nativeBinding.assetIssuer, maxFeeStroops: nativeBinding.maxFeeStroops,
  language: nativePortable.language, tier: nativePortable.tier, rules: nativePortable.rules,
  params: nativePortable.params, paramsHash: nativePortable.paramsHash,
};
const nativeApproval = {method: 'sep53', payload: nativePayload,
  message: `AllowIt Native policy approval v1\n${canonicalApprovalJson(nativePayload)}`};

test('reject substitutions and wrong domains before a wallet request', async () => {
  const wrongOwner = Keypair.fromRawEd25519Seed(Buffer.alloc(32, 8)).publicKey();
  for (const [field, changed] of Object.entries({
    owner: wrongOwner, policyId: 'other-policy', revision: 3,
    wallet: StrKey.encodeContract(Buffer.alloc(32, 8)), network: 'stellar:pubnet',
    policyInstance: '55'.repeat(32), moduleDigest: '55'.repeat(32),
    installedSourceHash: '55'.repeat(32), source: 'changed source', sourceHash: '55'.repeat(32),
    paramsHash: '55'.repeat(32), serverBindings: '55'.repeat(32), route: 'native',
  })) {
    await assert.rejects(signStellarSourceApproval(approval({...payload, [field]: changed}), policy, session), /exact policy/);
  }
  const badDomain = {...approval(payload), message: fixture.message.replace('Stellar server', 'Native')};
  await assert.rejects(signStellarSourceApproval(badDomain, policy, session), /exact policy/);
  const changedPolicy = structuredClone(policy);
  changedPolicy.runtime.instanceBinding.portable.params.payment_limit.Int = '1001';
  await assert.rejects(signStellarSourceApproval(approval(payload), changedPolicy, session), /exact policy/);
  const fakeHash = '55'.repeat(32);
  const forgedLocalHash = structuredClone(policy);
  forgedLocalHash.sourceHash = fakeHash;
  forgedLocalHash.runtime.instanceBinding.portable.sourceHash = fakeHash;
  await assert.rejects(signStellarSourceApproval(approval({...payload, sourceHash: fakeHash}), forgedLocalHash, session), /exact policy/);
  await assert.rejects(signStellarSourceApproval(approval(payload), nativePolicy, session), /exact policy/);
  await assert.rejects(signStellarSourceApproval(nativeApproval, policy, session), /exact policy/);
  assert.deepEqual(requests, []);
});

test('sign the exact SEP-53 server policy message for the current owner', async () => {
  assert.equal(approval(payload).message, fixture.message);
  assert.equal(Buffer.from(stellarMessageDigest(fixture.message)).toString('hex'), fixture.digest);
  const signatures = await signStellarSourceApproval(approval(payload), policy, session);
  assert.deepEqual(signatures, [{signer: owner.publicKey(), signature: [...owner.sign(Buffer.from(fixture.digest, 'hex'))]}]);
  assert.equal(requests.filter(request => request === 'SUBMIT_BLOB').length, 1);
});

test('sign the unchanged Native consent profile for a Native policy', async () => {
  expectedMessage = nativeApproval.message;
  const signatures = await signStellarSourceApproval(nativeApproval, nativePolicy, session);
  assert.deepEqual(signatures, [{signer: owner.publicKey(), signature: [...owner.sign(stellarMessageDigest(expectedMessage))]}]);
});
