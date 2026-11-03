import {Account, FeeBumpTransaction, Keypair, Memo, Operation, Transaction, TransactionBuilder, Networks, xdr} from '@stellar/stellar-sdk/base';
import {sha256} from '@noble/hashes/sha256';

import {STELLAR_OWNER_FRAGMENT} from './stellar-fragments';
export {STELLAR_OWNER_FRAGMENT} from './stellar-fragments';
export const STELLAR_OWNER_PROFILE = 'allowit-stellar-owner-v1';
export interface StellarOwnerIntent {
  version: 1; profile: typeof STELLAR_OWNER_PROFILE; requestId: string; network: 'stellar:testnet';
  owner: string; agent: string; engine: string; sequence: string; feeStroops: number;
  expiresAt: number; transactionXdr: string; transactionHash: string; intentDigest: string;
}
const keys = ['version','profile','requestId','network','owner','agent','engine','sequence','feeStroops','expiresAt','transactionXdr','transactionHash','intentDigest'];
const hex = (v: Uint8Array) => Array.from(v, b=>b.toString(16).padStart(2,'0')).join('');
const digest = (v: string) => hex(sha256(new TextEncoder().encode(v)));
export const stellarOwnerDigest = (v: StellarOwnerIntent) => digest(JSON.stringify([STELLAR_OWNER_PROFILE,v.requestId,v.network,v.owner,v.agent,v.engine,v.sequence,v.feeStroops,v.expiresAt,v.transactionHash]));
export function decodePublicFragment(fragment: string, prefix: string): unknown {
  if (!fragment.startsWith(prefix)||fragment.length>65_536) throw new Error('The owner signing link is invalid or too large.');
  const encoded=fragment.slice(prefix.length);
  if (!/^[A-Za-z0-9_-]+$/.test(encoded)) throw new Error('The owner signing link is invalid.');
  try {
    const raw=atob(encoded.replace(/-/g,'+').replace(/_/g,'/'));
    if (btoa(raw).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'')!==encoded) throw new Error();
    return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(Uint8Array.from(raw,c=>c.charCodeAt(0))));
  } catch {throw new Error('The owner signing link is invalid.');}
}
export function nativeSetupTransaction(v: StellarOwnerIntent): Transaction {
  return new TransactionBuilder(new Account(v.owner,(BigInt(v.sequence)-1n).toString()),{fee:String(v.feeStroops/3),networkPassphrase:Networks.TESTNET})
    .addOperation(Operation.setOptions({signer:{ed25519PublicKey:v.agent,weight:1}}))
    .addOperation(Operation.setOptions({signer:{ed25519PublicKey:v.engine,weight:1}}))
    .addOperation(Operation.setOptions({masterWeight:3,lowThreshold:2,medThreshold:2,highThreshold:3}))
    .addMemo(Memo.hash(sha256(new TextEncoder().encode(v.requestId))))
    .setTimebounds(0,v.expiresAt).build();
}
export function checkStellarOwnerIntent(v: unknown): asserts v is StellarOwnerIntent {
  if (!v||typeof v!=='object'||Array.isArray(v)||Object.keys(v).length!==keys.length||Object.keys(v).some(k=>!keys.includes(k))) throw new Error('The native setup fields are invalid.');
  const value=v as StellarOwnerIntent;
  if (value.version!==1||value.profile!==STELLAR_OWNER_PROFILE||value.network!=='stellar:testnet'
    ||typeof value.requestId!=='string'||!/^[A-Za-z0-9._:-]{8,100}$/.test(value.requestId)
    ||typeof value.sequence!=='string'||!/^[1-9][0-9]*$/.test(value.sequence)||BigInt(value.sequence)>9_223_372_036_854_775_807n
    ||!Number.isInteger(value.feeStroops)||value.feeStroops<300||value.feeStroops>300_000||value.feeStroops%3!==0
    ||!Number.isSafeInteger(value.expiresAt)||value.expiresAt<=0
    ||typeof value.transactionHash!=='string'||!/^[0-9a-f]{64}$/.test(value.transactionHash)
    ||typeof value.transactionXdr!=='string'||value.transactionXdr.length>4096
    ||typeof value.intentDigest!=='string'||!/^[0-9a-f]{64}$/.test(value.intentDigest)) throw new Error('The native setup link does not contain a supported Testnet request.');
  try {
    for(const address of [value.owner,value.agent,value.engine]) if(Keypair.fromPublicKey(address).publicKey()!==address) throw new Error();
    if(new Set([value.owner,value.agent,value.engine]).size!==3) throw new Error();
    const expected=nativeSetupTransaction(value);
    if(expected.toXDR()!==value.transactionXdr||hex(expected.hash())!==value.transactionHash||stellarOwnerDigest(value)!==value.intentDigest) throw new Error();
  } catch {throw new Error('The owner, signer roles or exact native setup transaction changed. Nothing was signed.');}
}
export function parseStellarOwnerIntent(fragment: string): StellarOwnerIntent {
  const v=decodePublicFragment(fragment,STELLAR_OWNER_FRAGMENT);checkStellarOwnerIntent(v);return v;
}
export function checkStellarEngineIdentity(v:StellarOwnerIntent,config:unknown):void {
  if(!config||typeof config!=='object')throw new Error('The configured Stellar engine identity is unavailable.');
  const c=config as Record<string,unknown>;
  if(c.profile!=='allowit-stellar-wallet-v1'||!Array.isArray(c.networks)||!c.networks.includes(v.network)||c.enginePublicKey!==v.engine)throw new Error('The native setup engine differs from the configured Stellar service. Nothing was signed.');
}
export function verifyStellarOwnerSignature(v: StellarOwnerIntent, signed: string): void {
  checkStellarOwnerIntent(v);
  if(typeof signed!=='string'||signed.length>8192) throw new Error('The signed native setup exceeds its bounds.');
  const tx=TransactionBuilder.fromXDR(signed,Networks.TESTNET);
  if(!(tx instanceof Transaction)||hex(tx.hash())!==v.transactionHash||tx.signatures.length!==1) throw new Error('The wallet changed the native setup transaction.');
  const sig=tx.signatures[0],key=Keypair.fromPublicKey(v.owner);
  if(hex(sig.hint.value)!==hex(key.signatureHint())||!key.verify(tx.hash(),sig.signature.value)) throw new Error('The native setup signature does not belong to its owner.');
  tx.signatures.splice(0);
  if(tx.toXDR()!==v.transactionXdr) throw new Error('The signed transaction differs from the reviewed native setup.');
}

const HORIZON='https://horizon-testnet.stellar.org';
export interface OwnerRecord {intent:StellarOwnerIntent;signedXdr?:string;status:'unsigned'|'unknown'|'confirmed'|'failed';ledger?:number}
export type OwnerTransport=(path:string,init?:RequestInit)=>Promise<Response>;
export const stellarOwnerTransport:OwnerTransport=(path,init)=>fetch(HORIZON+path,{...init,credentials:'omit',redirect:'error'});
async function json(response:Response):Promise<Record<string,unknown>> {
  const text=await response.text();if(text.length>1_048_576)throw new Error('Stellar returned too much data.');
  const v:unknown=JSON.parse(text);if(!v||typeof v!=='object'||Array.isArray(v))throw new Error('Stellar returned invalid data.');return v as Record<string,unknown>;
}
/** The SDK issues 300 s links; 30 s more absorbs browser and CLI clock skew. Signed proofs stay recoverable after expiry. */
export const STELLAR_OWNER_UNSIGNED_WINDOW=330;
/** An unsigned entry carries no authority. Only one inside its admissible window reserves the owner sequence. */
export const unsignedStellarOwnerOpen=(v:StellarOwnerIntent,now=Math.floor(Date.now()/1000))=>v.expiresAt>now&&v.expiresAt<=now+STELLAR_OWNER_UNSIGNED_WINDOW;
/** Unsigned admissibility only. A too-far expiry is reported apart from an expired one; it usually means a wrong clock. */
export function checkUnsignedStellarOwnerWindow(v:StellarOwnerIntent,now=Math.floor(Date.now()/1000)):void {
  if(v.expiresAt<=now)throw new Error('This unsigned setup expired. Prepare a new request in the CLI.');
  if(v.expiresAt>now+STELLAR_OWNER_UNSIGNED_WINDOW)throw new Error('This setup expires too far ahead. Check this device’s clock, then prepare a new request in the CLI.');
}
/** Verify current native authority immediately before requesting a wallet signature. */
export async function verifyFreshStellarOwner(v:StellarOwnerIntent,transport:OwnerTransport=stellarOwnerTransport,now=Math.floor(Date.now()/1000)):Promise<void> {
  checkStellarOwnerIntent(v);
  checkUnsignedStellarOwnerWindow(v,now);
  const root=await transport('/');if(!root.ok||(await json(root)).network_passphrase!==Networks.TESTNET)throw new Error('The Stellar endpoint uses another network.');
  const response=await transport('/accounts/'+v.owner);if(!response.ok)throw new Error('The owner account is unavailable.');
  const a=await json(response),t=a.thresholds as Record<string,unknown>|undefined,s=a.signers as Array<Record<string,unknown>>|undefined;
  if(a.account_id!==v.owner||a.sequence!==(BigInt(v.sequence)-1n).toString()||a.subentry_count!==0
    ||!t||t.low_threshold!==0||t.med_threshold!==0||t.high_threshold!==0||!Array.isArray(s)||s.length!==1
    ||s[0].key!==v.owner||s[0].type!=='ed25519_public_key'||s[0].weight!==1) throw new Error('Current owner authority, account sequence or entries differ. Nothing was signed.');
}
const plain=(v:unknown)=>v&&typeof v==='object'&&!Array.isArray(v)?v as Record<string,unknown>:null;
/**
 * Binds a settled envelope and result to the exact inner owner bytes. Horizon serves a third-party fee bump under the
 * inner hash with the outer envelope (CAP-15); only the inner owner transaction is returned for saving and replay.
 */
function settledOwnerProof(v:StellarOwnerIntent,receipt:Record<string,unknown>):{signedXdr:string;successful:boolean} {
  const mismatch=()=>new Error('The Stellar receipt does not match this request.');
  const envelopeXdr=receipt.envelope_xdr,resultXdr=receipt.result_xdr,successful=receipt.successful;
  if(typeof envelopeXdr!=='string'||envelopeXdr.length>16_384||typeof resultXdr!=='string'||resultXdr.length>16_384||typeof successful!=='boolean')throw mismatch();
  const {envelope,result}=(()=>{
    try{return {envelope:TransactionBuilder.fromXDR(envelopeXdr,Networks.TESTNET),result:xdr.TransactionResult.fromXDR(resultXdr,'base64')};}
    catch{throw mismatch();}
  })();
  const outcome=result.result;
  if(!(envelope instanceof FeeBumpTransaction)){
    if(receipt.fee_bump_transaction!==undefined||receipt.inner_transaction!==undefined
      ||outcome.type==='txFeeBumpInnerSuccess'||outcome.type==='txFeeBumpInnerFailed'||(outcome.type==='txSuccess')!==successful)throw mismatch();
    return {signedXdr:envelopeXdr,successful};
  }
  const inner=plain(receipt.inner_transaction),outer=plain(receipt.fee_bump_transaction),outerHash=hex(envelope.hash());
  if(!inner||!outer||inner.hash!==v.transactionHash||outer.hash!==outerHash||outerHash===v.transactionHash
    ||hex(envelope.innerTransaction.hash())!==v.transactionHash)throw mismatch();
  if(outcome.type!=='txFeeBumpInnerSuccess'&&outcome.type!=='txFeeBumpInnerFailed')throw mismatch();
  const pair=outcome.innerResultPair;
  // Outer INNER_SUCCESS needs inner txSUCCESS; outer INNER_FAILED needs a failing inner result.
  if(hex(pair.transactionHash.value)!==v.transactionHash
    ||(outcome.type==='txFeeBumpInnerSuccess')!==successful||(pair.result.result.type==='txSuccess')!==successful)throw mismatch();
  return {signedXdr:envelope.innerTransaction.toXDR(),successful};
}
/** A receipt must name the exact original hash, owner bytes and result. Unknown status retains its signed proof. */
export async function stellarOwnerStatus(record:OwnerRecord,transport:OwnerTransport=stellarOwnerTransport):Promise<OwnerRecord> {
  checkStellarOwnerIntent(record.intent);
  if(record.signedXdr)verifyStellarOwnerSignature(record.intent,record.signedXdr);
  const response=await transport('/transactions/'+record.intent.transactionHash);
  // A fresh 404 cannot prove absence: a signed proof stays unknown and keeps blocking.
  if(response.status===404)return record.signedXdr?{intent:record.intent,signedXdr:record.signedXdr,status:'unknown'}:{intent:record.intent,status:'unsigned'};
  if(!response.ok)throw new Error('Stellar status is unavailable. Keep the original signed transaction.');
  const receipt=await json(response);
  if(receipt.hash!==record.intent.transactionHash||(receipt.id!==undefined&&receipt.id!==receipt.hash)||!Number.isSafeInteger(receipt.ledger)||Number(receipt.ledger)<=0)throw new Error('The Stellar receipt does not match this request.');
  const settled=settledOwnerProof(record.intent,receipt);
  verifyStellarOwnerSignature(record.intent,settled.signedXdr);
  if(record.signedXdr&&settled.signedXdr!==record.signedXdr)throw new Error('The settled envelope differs from the saved signed proof.');
  return {intent:record.intent,signedXdr:settled.signedXdr,status:settled.successful?'confirmed':'failed',ledger:Number(receipt.ledger)};
}
export async function submitSavedStellarOwner(record:OwnerRecord,transport:OwnerTransport=stellarOwnerTransport):Promise<OwnerRecord> {
  if(!record.signedXdr)throw new Error('There is no saved signed transaction.');
  verifyStellarOwnerSignature(record.intent,record.signedXdr);
  const checked=await stellarOwnerStatus(record,transport);
  if(checked.status==='confirmed'||checked.status==='failed')return checked;
  // A rejection can follow an earlier accepted broadcast. Only lookup establishes a final result.
  await transport('/transactions',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({tx:record.signedXdr}).toString()});
  return stellarOwnerStatus({...record,status:'unknown'},transport);
}
export function ownerRecordKey(v:StellarOwnerIntent):string{return `allowit.stellar.owner.v1:${v.network}:${v.owner}:${v.requestId}`;}
export function readOwnerRecord(v:StellarOwnerIntent,storage:Storage=localStorage):OwnerRecord|null {
  const raw=storage.getItem(ownerRecordKey(v));if(raw===null)return null;
  if(raw.length>16_384)throw new Error('The saved native setup proof exceeds its bounds.');
  const record=JSON.parse(raw) as OwnerRecord;
  checkStellarOwnerIntent(record.intent);
  if(JSON.stringify(record.intent)!==JSON.stringify(v)||!['unsigned','unknown','confirmed','failed'].includes(record.status))throw new Error('This request ID already binds another native setup.');
  if(record.signedXdr)verifyStellarOwnerSignature(v,record.signedXdr);
  else if(record.status!=='unsigned')throw new Error('The saved signed proof is missing. Keep this journal.');
  return record;
}
const sameIntent=(a:StellarOwnerIntent,b:StellarOwnerIntent)=>JSON.stringify(a)===JSON.stringify(b);
/**
 * Verified signed proofs this page could not yet save, by journal key. A copy outlives a closed dialog or remount until
 * its exact bytes are saved and read back. Public signed transaction bytes only: no key material, no status authority.
 */
const unsavedProofs=new Map<string,OwnerRecord>();
function holdUnsavedProof(proof:OwnerRecord):void {
  const key=ownerRecordKey(proof.intent),prior=unsavedProofs.get(key);
  if(prior){
    if(!sameIntent(prior.intent,proof.intent)||prior.signedXdr!==proof.signedXdr)throw new Error('The saved native setup signature cannot be replaced.');
    return;
  }
  const copy:OwnerRecord={intent:Object.freeze({...proof.intent}),signedXdr:proof.signedXdr,status:'unknown'};
  unsavedProofs.set(key,Object.freeze(copy));
}
/** This request's proof from the caller, or the page copy once the caller has let it go. */
function memoryProof(v:StellarOwnerIntent,held:OwnerRecord|null):OwnerRecord|null {
  if(held?.signedXdr&&sameIntent(held.intent,v))return held;
  const kept=unsavedProofs.get(ownerRecordKey(v));
  return kept&&sameIntent(kept.intent,v)?kept:null;
}
export function saveOwnerRecord(record:OwnerRecord,storage:Storage=localStorage):void {
  checkStellarOwnerIntent(record.intent);
  const prior=readOwnerRecord(record.intent,storage);
  if(prior?.signedXdr&&prior.signedXdr!==record.signedXdr)throw new Error('The saved native setup signature cannot be replaced.');
  if(record.signedXdr)verifyStellarOwnerSignature(record.intent,record.signedXdr);
  const key=ownerRecordKey(record.intent),raw=JSON.stringify(record);
  const failed=record.signedXdr?'The signed transaction could not be saved in this browser. It was not sent.':'This browser could not save the setup journal. Nothing was signed.';
  try{storage.setItem(key,raw);}catch{throw new Error(failed);}
  if(storage.getItem(key)!==raw)throw new Error(failed);
  // Only the exact proof, saved and read back, releases its page copy.
  const kept=unsavedProofs.get(key);
  if(kept&&kept.signedXdr===record.signedXdr&&sameIntent(kept.intent,record.intent))unsavedProofs.delete(key);
}
const signedNotSaved='Your wallet signed the setup, but this browser could not save it. It was not sent. Keep this page open, then retry the signed transaction.';
/**
 * Keeps a wallet-returned signature before any further wallet or network step. The verified proof reaches page memory,
 * then the caller, then the durable journal. A failed save keeps it in memory, sends nothing and still blocks another signature.
 */
export function retainStellarOwnerProof(v:StellarOwnerIntent,signedXdr:string,keep:(proof:OwnerRecord)=>void,storage:Storage=localStorage):OwnerRecord {
  verifyStellarOwnerSignature(v,signedXdr);
  const proof:OwnerRecord={intent:v,signedXdr,status:'unknown'};
  holdUnsavedProof(proof);
  keep(proof);
  try{saveOwnerRecord(proof,storage);}catch{throw new Error(signedNotSaved);}
  return proof;
}
const recoverEarlier=(requestId:string)=>`Recover the earlier native setup ${requestId} before authorizing another request.`;
/**
 * Signed proof for this exact request: the durable journal first, then one kept in memory after a failed save, by the
 * caller or by this page. A proof kept only in memory for another request blocks this one regardless of expiry or owner,
 * since replacing it would lose its only copy. Once that exact proof is durable, the per-owner admission scan reconciles
 * it before any new signature.
 */
export function heldStellarOwnerProof(v:StellarOwnerIntent,held:OwnerRecord|null,storage:Storage=localStorage):OwnerRecord|null {
  for(const kept of [...unsavedProofs.values(),...(held?.signedXdr?[held]:[])]){
    if(sameIntent(kept.intent,v))continue;
    let durable=false;
    try{durable=readOwnerRecord(kept.intent,storage)?.signedXdr===kept.signedXdr;}catch{/* an unreadable original journal leaves the proof in memory only */}
    if(!durable)throw new Error(recoverEarlier(kept.intent.requestId));
  }
  const saved=readOwnerRecord(v,storage);
  if(saved?.signedXdr)return saved;
  return memoryProof(v,held);
}
/** Display recovery never lets an unsigned or unreadable journal entry hide a known signed proof. */
export function keptStellarOwnerRecord(v:StellarOwnerIntent,held:OwnerRecord|null,storage:Storage=localStorage):OwnerRecord|null {
  let saved:OwnerRecord|null=null;
  try{saved=readOwnerRecord(v,storage);}catch{/* an unreadable journal still blocks signing in heldStellarOwnerProof */}
  if(saved?.signedXdr)return saved;
  return memoryProof(v,held)??saved;
}
/** Retry durably saves the same kept proof before any send. It never asks the wallet again. */
export function durableStellarOwnerProof(v:StellarOwnerIntent,held:OwnerRecord|null,storage:Storage=localStorage):OwnerRecord {
  const proof=heldStellarOwnerProof(v,held,storage);
  if(!proof?.signedXdr)throw new Error('There is no saved signed transaction.');
  if(readOwnerRecord(v,storage)?.signedXdr!==proof.signedXdr){
    try{saveOwnerRecord(proof,storage);}catch{throw new Error(signedNotSaved);}
  }
  return proof;
}
const ownerLock=(v:StellarOwnerIntent)=>`allowit.stellar.owner:${v.network}:${v.owner}`;
/** The raw per-owner Web Lock, without the admission scan. Callers that already hold it use the direct status functions. */
export async function withRawStellarOwnerLock<T>(v:StellarOwnerIntent,run:()=>Promise<T>):Promise<T> {
  if(!navigator.locks)throw new Error('This browser cannot safely lock native setup. Use a browser with Web Locks support.');
  return navigator.locks.request(ownerLock(v),async()=>run());
}
/** Opening or checking a link reads, looks up and saves inside the owner lock, so an older lookup never overwrites a newer one. */
export async function observeStellarOwnerRecord(v:StellarOwnerIntent,held:OwnerRecord|null,transport:OwnerTransport=stellarOwnerTransport,storage:Storage=localStorage):Promise<OwnerRecord|null> {
  return withRawStellarOwnerLock(v,async()=>{
    const proof=heldStellarOwnerProof(v,held,storage);
    if(!proof)return readOwnerRecord(v,storage);
    const checked=await stellarOwnerStatus(proof,transport);
    saveOwnerRecord(checked,storage);
    return checked;
  });
}
/**
 * An expired proof can have a pruned receipt. Fresh owner-only authority resolves the current authority risk, not the
 * historical transaction outcome. Keep both the original journal and an immutable archive; never label this failed.
 */
async function archiveSupersededOwnerAuthority(prior:OwnerRecord,next:StellarOwnerIntent,transport:OwnerTransport,storage:Storage):Promise<boolean> {
  if(!prior.signedXdr||prior.intent.expiresAt>=Math.floor(Date.now()/1000))return false;
  try {
    const response=await transport('/ledgers?order=desc&limit=1',{cache:'no-store'});
    if(!response.ok)return false;
    const embedded=plain((await json(response))._embedded),records=embedded?.records;
    if(!Array.isArray(records)||records.length!==1)return false;
    const ledger=plain(records[0]),closedAt=ledger?.closed_at,sequence=ledger?.sequence;
    if(typeof closedAt!=='string'||!Number.isSafeInteger(sequence)||Number(sequence)<=0
      ||!Number.isFinite(Date.parse(closedAt))||Date.parse(closedAt)<=prior.intent.expiresAt*1000)return false;
    // Read account authority after the finalized expiry boundary, and bind it to this new request's sequence.
    await verifyFreshStellarOwner(next,async(path,init)=>transport(path,{...init,cache:'no-store'}));
    const key=`allowit.stellar.owner.archive.v1:${prior.intent.network}:${prior.intent.owner}:${prior.intent.transactionHash}`;
    const existing=storage.getItem(key);
    if(existing!==null){
      const archived=plain(JSON.parse(existing)),proof=archived?.record as OwnerRecord|undefined;
      if(!proof||!sameIntent(proof.intent,prior.intent)||proof.signedXdr!==prior.signedXdr)return false;
    }else{
      const raw=JSON.stringify({record:prior,authority:{ledger:sequence,closedAt,owner:next.owner,sequence:(BigInt(next.sequence)-1n).toString(),requestId:next.requestId}});
      storage.setItem(key,raw);
      if(storage.getItem(key)!==raw)return false;
    }
    return true;
  }catch{return false;}
}
/** Serialize signing across all tabs that share the same owner account sequence. Every earlier signed proof is looked up again; a saved terminal label is not chain evidence. */
export async function withStellarOwnerLock<T>(v:StellarOwnerIntent,run:()=>Promise<T>,transport:OwnerTransport=stellarOwnerTransport,storage:Storage=localStorage):Promise<T> {
  return withRawStellarOwnerLock(v,async()=>{
    const prefix=`allowit.stellar.owner.v1:${v.network}:${v.owner}:`,now=Math.floor(Date.now()/1000),current=ownerRecordKey(v);
    // Snapshot before the first lookup: another tab can remove any key during an await and shift live indices.
    const earlier=Array.from({length:storage.length},(_,i)=>storage.key(i)).filter((key):key is string=>!!key?.startsWith(prefix)&&key!==current);
    for(const key of earlier){
      const raw=storage.getItem(key);if(raw===null)throw new Error('The native setup journal changed.');
      const candidate=JSON.parse(raw) as OwnerRecord;checkStellarOwnerIntent(candidate.intent);
      const prior=readOwnerRecord(candidate.intent,storage);
      if(!prior||ownerRecordKey(candidate.intent)!==key)throw new Error('The saved native setup binding is invalid.');
      const blocked=recoverEarlier(prior.intent.requestId);
      if(prior.signedXdr){
        const checked=await stellarOwnerStatus(prior,transport);saveOwnerRecord(checked,storage);
        if(checked.status==='unknown'&&!await archiveSupersededOwnerAuthority(checked,v,transport,storage))throw new Error(blocked);
      }else if(unsignedStellarOwnerOpen(prior.intent,now))throw new Error(blocked);
    }
    return run();
  });
}
