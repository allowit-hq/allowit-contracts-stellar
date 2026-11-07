import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import test from 'node:test';
import {
  deriveAdkOwnerWallet, verifyAdkOwnerSignature, verifyAdkOwnerStep,
} from '../dist/owner-verifier.js';

// The fixture uses deterministic test keys and an offline 1.25 XLM funding transaction.
const {step, selection, signed} = JSON.parse(await readFile(
  new URL('./fixtures/owner-funding.json', import.meta.url), 'utf8',
));
const wasmUrl = new URL('../dist/owner-verifier.wasm', import.meta.url);

test('browser verifier authenticates its Wasm and binds exact owner funding', async t => {
  t.mock.method(Date, 'now', () => 1_800_000_000_000);
  const wasm = await readFile(wasmUrl);
  const tampered = Buffer.from(wasm);
  tampered[tampered.length - 1] ^= 1;
  let bytes = tampered;
  t.mock.method(globalThis, 'fetch', async url => {
    assert.equal(url.href, wasmUrl.href);
    return new Response(bytes);
  });

  await assert.rejects(deriveAdkOwnerWallet(selection.owner, selection.policyInstance), /reviewed artifact/);
  bytes = wasm;
  assert.equal(await deriveAdkOwnerWallet(selection.owner, selection.policyInstance), selection.wallet);
  await verifyAdkOwnerStep(step, selection);
  await verifyAdkOwnerSignature(step, selection, signed);

  const invalid = /differs from the reviewed owner action/;
  await assert.rejects(verifyAdkOwnerStep(step, {...selection, amount: '1.26'}), invalid);
  await assert.rejects(verifyAdkOwnerStep(step, {...selection, wallet: selection.asset}), invalid);
  await assert.rejects(verifyAdkOwnerSignature(step, selection, step.transactionXdr), invalid);
  t.mock.method(Date, 'now', () => step.expiresAt * 1000);
  await assert.rejects(verifyAdkOwnerStep(step, selection), invalid);
});
