import assert from 'node:assert/strict';
import test,{after} from 'node:test';
import {Keypair} from '@stellar/stellar-sdk/base';
const owner=Keypair.fromRawEd25519Seed(Buffer.alloc(32,7)).publicKey();
const origin='https://staging.allowit.ai',listeners=new Set(),requests=[];
const previousWindow=globalThis.window,previousLocation=globalThis.location;
globalThis.window={location:{origin},postMessage(request,target){
  assert.equal(target,origin);requests.push(request.type);
  const value=request.type==='REQUEST_ACCESS'?{publicKey:owner}:request.type==='REQUEST_NETWORK_DETAILS'?{networkDetails:{network:'TESTNET',networkUrl:'',networkPassphrase:'Test SDF Network ; September 2015'}}:assert.fail('Unexpected wallet request');
  queueMicrotask(()=>{for(const listener of [...listeners])listener({source:window,data:{source:'FREIGHTER_EXTERNAL_MSG_RESPONSE',messagedId:request.messageId,...value}});});
},addEventListener(type,listener){assert.equal(type,'message');listeners.add(listener);},removeEventListener(type,listener){assert.equal(type,'message');listeners.delete(listener);}};
globalThis.location=window.location;
after(()=>{if(previousWindow===undefined)delete globalThis.window;else globalThis.window=previousWindow;if(previousLocation===undefined)delete globalThis.location;else globalThis.location=previousLocation;});
const {connectStellarWallet}=await import('../dist/stellar-wallet.js');
const issuedAt=Date.parse('2026-01-01T12:00:00Z'),expiresAt=issuedAt+300000;
function challenge(expiry=expiresAt){
  const issued=new Date(issuedAt).toISOString().replace('.000Z','Z'),expires=new Date(expiry).toISOString().replace('.000Z','Z'),id='ab'.repeat(32);
  return {id,address:owner,origin,expiresAt:expires,message:`staging.allowit.ai wants you to sign in with your Stellar account:\n${owner}\n\nSign in to AllowIt. This does not authorize spending or move funds.\n\nURI: ${origin}\nVersion: 1\nNonce: ${id}\nIssued At: ${issued}\nExpiration Time: ${expires}`};
}
test('caller false, undefined and asynchronous admission reject before signing',async()=>{
  for(const admit of [()=>false,()=>undefined,()=>Promise.resolve(true)]){
    const wallet=await connectStellarWallet('stellar:testnet',admit);
    assert.throws(()=>wallet.validateChallenge(challenge()),/invalid or expired/);
  }
  assert.ok(requests.every(type=>['REQUEST_ACCESS','REQUEST_NETWORK_DETAILS'].includes(type)));
});
test('only explicit true admits exact native challenge fields',async()=>{
  let observed;const wallet=await connectStellarWallet('stellar:testnet',times=>{observed=times;return true;});
  assert.doesNotThrow(()=>wallet.validateChallenge(challenge()));assert.deepEqual(observed,{issuedAt,expiresAt});
  observed=null;const changed=challenge();changed.message=changed.message.replace('Sign in to AllowIt.','Approve payment.');
  assert.throws(()=>wallet.validateChallenge(changed));assert.equal(observed,null);
});
test('caller time policy retains inclusive skew and exclusive expiry boundaries',async()=>{
  const admit=now=>times=>times.expiresAt-times.issuedAt===300000&&times.issuedAt<=now+30000&&now-times.issuedAt<=300000&&times.expiresAt>now;
  for(const now of [issuedAt-30000,issuedAt,expiresAt-1]){
    const wallet=await connectStellarWallet('stellar:testnet',admit(now));assert.doesNotThrow(()=>wallet.validateChallenge(challenge()));
  }
  for(const now of [issuedAt-30001,expiresAt,expiresAt+1]){
    const wallet=await connectStellarWallet('stellar:testnet',admit(now));assert.throws(()=>wallet.validateChallenge(challenge()));
  }
  const wallet=await connectStellarWallet('stellar:testnet',admit(issuedAt));assert.throws(()=>wallet.validateChallenge(challenge(expiresAt-1000)));
});
