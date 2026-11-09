import assert from 'node:assert/strict';
import {createHash, createPrivateKey, createPublicKey, sign} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import test from 'node:test';
import {
  deriveAdkOwnerWallet, verifyAdkOwnerSignature, verifyAdkOwnerStep,
} from '../dist/owner-verifier.js';

// The fixture uses deterministic test keys and an offline 1.25 XLM funding transaction.
const fixture = JSON.parse(await readFile(
  new URL('./fixtures/owner-funding.json', import.meta.url), 'utf8',
));
const {step, signed} = fixture;
// scripts/build-contracts.sh builds the Common Wasm. The verifier admits only that Wasm.
const commonWasm = await readFile(new URL(
  '../../../target/wasm32v1-none/release/allowit_common_policy_engine.wasm', import.meta.url,
));
const sha256 = (...parts) => createHash('sha256').update(Buffer.concat(parts)).digest();
const commonHash = sha256(commonWasm);
const selection = {...fixture.selection, wasmHash: commonHash.toString('hex')};
// A transaction hash covers the network ID, the envelope type and the transaction.
const network = sha256(Buffer.from('Test SDF Network ; September 2015'));
const u32 = value => {
  const bytes = Buffer.alloc(4);
  bytes.writeUInt32BE(value);
  return bytes;
};
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
  // After the time bound, a new step is refused, but the saved signature still verifies for recovery.
  t.mock.method(Date, 'now', () => step.expiresAt * 1000);
  await assert.rejects(verifyAdkOwnerStep(step, selection), invalid);
  await verifyAdkOwnerSignature(step, selection, signed);
  await assert.rejects(verifyAdkOwnerSignature(step, selection, step.transactionXdr), invalid);
});

test('browser verifier binds a lifetime renewal to the selected wallet and code', async t => {
  t.mock.method(Date, 'now', () => 1_800_000_000_000);
  const renewal = rebindCommon(JSON.parse(
    await readFile(new URL('./fixtures/owner-renewal.json', import.meta.url), 'utf8'),
  ));
  const wasm = await readFile(wasmUrl);
  t.mock.method(globalThis, 'fetch', async () => new Response(wasm));
  await verifyAdkOwnerStep(renewal.step, renewal.selection);
  await verifyAdkOwnerSignature(renewal.step, renewal.selection, renewal.signed);
  // Another policy instance selects another wallet, so the renewal footprint differs.
  const policyInstance = '05'.repeat(32);
  const other = {...renewal.selection, policyInstance, wallet: await deriveAdkOwnerWallet(renewal.selection.owner, policyInstance)};
  await assert.rejects(verifyAdkOwnerStep(renewal.step, other), /differs from the reviewed owner action/);
});

test('browser verifier admits the built Common Wasm upload', async t => {
  t.mock.method(Date, 'now', () => 1_800_000_000_000);
  t.mock.method(globalThis, 'fetch', async () => new Response(await readFile(wasmUrl)));
  // XDR: the funding envelope type, owner source, fee 100, sequence, time bounds, no memo and
  // one operation; then an upload_wasm operation without auth, empty Soroban data with a zero
  // resource fee, and no signatures.
  const envelope = Buffer.concat([
    Buffer.from(step.transactionXdr, 'base64').subarray(0, 80),
    u32(0), u32(24), u32(2), u32(commonWasm.length), commonWasm, Buffer.alloc(-commonWasm.length & 3), u32(0),
    u32(1), Buffer.alloc(32),
    u32(0),
  ]);
  await verifyAdkOwnerStep({
    ...step,
    action: 'upload_wasm',
    transactionXdr: envelope.toString('base64'),
    transactionHash: sha256(network, envelope.subarray(0, -4)).toString('hex'),
  }, selection);
});

// The renewal footprint names the Common code that the fixture recorded. Put the built Common hash
// there and sign again with the fixture owner test key, whose Ed25519 seed is 32 bytes of 0x01.
function rebindCommon({step, selection, signed}) {
  const owner = createPrivateKey({
    key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, 1)]),
    format: 'der', type: 'pkcs8',
  });
  const unsigned = Buffer.from(step.transactionXdr, 'base64');
  const recorded = Buffer.from(selection.wasmHash, 'hex');
  const at = unsigned.indexOf(recorded);
  assert.ok(at > 0 && unsigned.indexOf(recorded, at + 1) < 0, 'the footprint names the Common code once');
  // Drop the empty signature list, then append one signature: its hint is the key's last 4 bytes.
  const body = Buffer.concat([unsigned.subarray(0, at), commonHash, unsigned.subarray(at + 32, -4)]);
  const hash = sha256(network, body);
  const hint = createPublicKey(owner).export({format: 'der', type: 'spki'}).subarray(-4);
  const rebound = {
    step: {...step, transactionXdr: Buffer.concat([body, u32(0)]).toString('base64'), transactionHash: hash.toString('hex')},
    selection: {...selection, wasmHash: commonHash.toString('hex')},
    signed: Buffer.concat([body, u32(1), hint, u32(64), sign(null, hash, owner)]).toString('base64'),
  };
  if (recorded.equals(commonHash)) assert.deepEqual(rebound, {step, selection, signed});
  return rebound;
}
