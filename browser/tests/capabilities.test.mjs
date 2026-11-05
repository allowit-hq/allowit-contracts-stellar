import assert from 'node:assert/strict';
import test from 'node:test';
import {Keypair} from '@stellar/stellar-sdk/base';
import {customerKeyFromEntropy} from '../dist/customer-token.js';
import {stellarSignInChallengeTimes,connectStellarWallet} from '../dist/stellar-wallet.js';
test('native key codec takes caller entropy and preserves exact StrKey bytes',()=>{
  const seed=new Uint8Array(32).fill(7), expected=Keypair.fromRawEd25519Seed(Buffer.from(seed));
  const before=new Uint8Array(seed), random=crypto.getRandomValues;
  crypto.getRandomValues=()=>{throw new Error('Native must not generate entropy');};
  try {assert.deepEqual(customerKeyFromEntropy(seed),{seed:expected.secret(),publicKey:expected.publicKey()});}
  finally {crypto.getRandomValues=random;}
  assert.deepEqual(seed,before);
  for(const bad of [new Uint8Array(31),new Uint8Array(33),null,'secret'])assert.throws(()=>customerKeyFromEntropy(bad));
});
test('native challenge binds exact fields and returns dates for caller admission',()=>{
  const address=Keypair.fromRawEd25519Seed(Buffer.alloc(32,7)).publicKey(), origin='https://staging.allowit.ai',id='ab'.repeat(32);
  const issued='2026-01-01T12:00:00Z',expiresAt='2026-01-01T12:05:00Z';
  const message=`staging.allowit.ai wants you to sign in with your Stellar account:\n${address}\n\nSign in to AllowIt. This does not authorize spending or move funds.\n\nURI: ${origin}\nVersion: 1\nNonce: ${id}\nIssued At: ${issued}\nExpiration Time: ${expiresAt}`;
  const challenge={id,address,origin,message,expiresAt};
  assert.deepEqual(stellarSignInChallengeTimes(challenge,address,origin),{issuedAt:Date.parse(issued),expiresAt:Date.parse(expiresAt)});
  for(const changed of [{...challenge,id:'cd'.repeat(32)},{...challenge,origin:'https://other.example'},{...challenge,message:message.replace('Sign in to AllowIt.','Approve a payment.')},{...challenge,message:message+'\nextra'}])assert.throws(()=>stellarSignInChallengeTimes(changed,address,origin));
});
test('wallet connection requires caller admission before wallet access',async()=>{
  await assert.rejects(connectStellarWallet('stellar:testnet',undefined),/admission capability/);
});

import {portableExport} from '../dist/portable-export.js';
import {canonicalJson,digest} from '../dist/consent-codec.js';
import {stellarAssetContractId} from '../dist/stellar-wallet.js';
test('portable codec requires caller admission and retains native binding checks',()=>{
  const code='exact source bytes',params={payment_limit:{Int:'500'}},asset=stellarAssetContractId('XLM',null,'stellar:testnet');
  const portable={language:'allowit-portable-v1',sourceHash:digest(code),tier:'standard',rules:[],params,paramsHash:digest(canonicalJson(params)),asset:{symbol:'XLM',address:asset,decimals:7},unresolved:[],build:{prefix:[],writesState:false,libraryRevision:'ab'.repeat(20),attempts:1}};
  const config={language:'portable',route:'policyWallet',tier:'simple',params,asset,assetSymbol:'XLM',assetIssuer:null};
  const policy={id:'p',network:'stellar:testnet',code,sourceHash:portable.sourceHash,irHash:'',mint:asset,token:'XLM',runtime:{instanceBinding:{portable,tier:'simple'}}};
  const bundle={language:portable.language,irHash:'',portable};
  for(const admit of [undefined,()=>false,()=>Promise.resolve(true)])assert.throws(()=>portableExport(bundle,config,policy,admit));
  let observed; assert.ok(portableExport(bundle,config,policy,p=>{observed=p;return true;}));assert.equal(observed,portable);
  const original=portable.paramsHash;portable.paramsHash='00'.repeat(32);
  assert.throws(()=>portableExport(bundle,config,policy,()=>true));portable.paramsHash=original;
  // Authoring policy belongs to the consumer; these are still valid native wire field types.
  portable.build.libraryRevision='consumer-specific';portable.build.attempts=4;portable.unresolved=['value'];
  assert.deepEqual(portableExport(bundle,config,policy,()=>true).top.portable.unresolved,['value']);
});
