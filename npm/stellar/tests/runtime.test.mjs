import assert from 'node:assert/strict';
import test from 'node:test';
import {runtimeProfileValid, installationValid} from '../dist/runtime.js';
import {STELLAR_NATIVE_PROFILE} from '../dist/stellar-profiles.js';
const runtime = profile => ({sourceProfile:'allowit-transfer-v1', operation:'allowit::transfer',wallet:{profile,kind:'owner-wallet'},capabilities:{providerCall:false}});
test('unknown runtime profiles reject without throwing', () => {
  for (const profile of ['unadvertised', '__proto__', 'constructor', '']) assert.equal(runtimeProfileValid(runtime(profile)), false);
  assert.equal(runtimeProfileValid(runtime(STELLAR_NATIVE_PROFILE)), true);
});
test('unknown installation profiles reject without throwing', () => {
  const installation = {state:'installed', policyId:'p', owner:'G'+'A'.repeat(55),wallet:'G'+'A'.repeat(55),network:'stellar:testnet',ledger:1,route:'native',sourceHash:'ab'.repeat(32),moduleDigest:'cd'.repeat(32)};
  for (const profile of ['unadvertised', '__proto__', 'constructor', '']) assert.equal(installationValid(installation,profile,'stellar:testnet'), false);
  assert.equal(installationValid(installation,STELLAR_NATIVE_PROFILE,'stellar:testnet'), true);
});
