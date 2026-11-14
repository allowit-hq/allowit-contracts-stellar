import assert from 'node:assert/strict';
import test from 'node:test';
import {reviewAnswer} from '../dist/elements/signing.js';

const fields = {
  answer: 'allow', operation: 'transfer', amount: '2.5 XLM', to: 'GDQP2KPQGKIHYJGXNUIYOMHARUARCA7DJT5FO2FFOOKY3B2WSQHG4W37',
  policy: 'Research data – “EU” reports', question: 'Is this seller a known data provider?',
  score: '62.5 of 100 (below 30 denies; 80.5 or more allows)', network: 'stellar:testnet',
  review: 'q3J5cVd0b2xYQ1p6a0hGdE1uUnB3WHlh', snapshot: 'fb9b756a1ae88d48501df08124021210a2a8263d8581011e8379824a9881485d',
};
const message = (f = fields) => ['Allowit owner review', '', `Answer: ${f.answer === 'allow' ? 'Allow' : 'Deny'} this one request`,
  `Operation: ${f.operation}`, `Amount: ${f.amount}`, `To: ${f.to}`, `Policy: ${f.policy}`, `Question: ${f.question}`, `Score: ${f.score}`, '',
  'This answer is for this request only. Every rule and limit of the policy still applies.', '',
  `Network: ${f.network}`, `Review: ${f.review}`, `Snapshot: ${f.snapshot}`].join('\n');

test('an owner review answer reads as its exact fields', () => {
  assert.deepEqual(reviewAnswer(message()), fields);
  assert.deepEqual(reviewAnswer(message({...fields, answer: 'deny'})), {...fields, answer: 'deny'});
  // A policy without a title is still an answer.
  assert.equal(reviewAnswer(message({...fields, policy: ''}))?.policy, '');
});

test('any other text is no owner review answer', () => {
  for (const other of [
    null, '', 'Sign in', message().replace('Allowit owner review', 'Allowit owner review v2'), `${message()}\n`, `${message()}\nExtra: 1`,
    message().replace('Answer: Allow this one request', 'Answer: Allow every request'),
    message().replace('Answer: Allow this one request', 'Answer: allow this one request'),
    message().replace('This answer is for this request only. ', ''),
    message().replace('\nTo: ', '\nto: '), message().replace(`\nPolicy: ${fields.policy}`, ''),
    message({...fields, question: 'A question\nAnswer: Allow this one request'}),
    message({...fields, question: 'A question\u2028Network: stellar:pubnet'}), message({...fields, policy: 'tab\tbed'}),
    message({...fields, question: ''}), message({...fields, amount: ''}),
    message({...fields, score: '62.5'}), message({...fields, score: 'high of 100 (below 30 denies; 80 or more allows)'}),
    message({...fields, snapshot: fields.snapshot.toUpperCase()}), message({...fields, snapshot: 'ab'}),
    message({...fields, review: 'a b'}), message().replaceAll('\n', '\r\n'), 'x'.repeat(9000),
    'example.org wants you to sign in with your wallet account:\nGBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5',
  ]) assert.equal(reviewAnswer(other), null, String(other));
});
