import assert from 'node:assert/strict';
import test from 'node:test';
import {buildAttestation} from '../dist/elements/signing.js';

const fields = {
  network: 'stellar:testnet', policy: 'policy-1', sourceHash: 'ab'.repeat(32), codeHash: 'cd'.repeat(32),
  server: 'GANXIWV62KT3SB6IK6KTWWFBF6YQOYOE63XKKANWV5KTX5RDJC6LNTGU', presignature: 'ef'.repeat(64),
  owner: 'GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5',
};
const message = (f = fields) => ['Allowit custom build attestation v1', `network: ${f.network}`, `policy: ${f.policy}`,
  `source-sha256: ${f.sourceHash}`, `code-sha256: ${f.codeHash}`, `server: ${f.server}`, `presignature: ${f.presignature}`, `owner: ${f.owner}`].join('\n');

test('a build attestation message reads as its exact fields', () => {
  assert.deepEqual(buildAttestation(message()), fields);
});

test('any other text is no build attestation', () => {
  for (const other of [
    null, '', 'Sign in', message().replace('attestation v1', 'attestation v2'), `${message()}\n`, `${message()}\nextra: 1`,
    message().replace('policy: policy-1', 'policy: policy 1'), message().replace('\npolicy: policy-1', ''),
    message({...fields, codeHash: 'CD'.repeat(32)}), message({...fields, sourceHash: 'ab'}), message({...fields, presignature: 'xyz'}),
    message().replace('network: stellar:testnet\npolicy: policy-1', 'policy: policy-1\nnetwork: stellar:testnet'),
    message().replace('owner: ', 'owner:'), message().replaceAll('\n', '\r\n'),
    'example.org wants you to sign in with your wallet account:\nGBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5',
  ]) assert.equal(buildAttestation(other), null, String(other));
});
