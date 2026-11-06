import {portableExport,canonicalJson,digest,object,hexHash,type PortableAdmission} from './portable-export.js';
import {StrKey} from '@stellar/stellar-sdk/base';
export interface ApprovalPolicy {id: string; revision: number; network: string; code: string; sourceHash: string; irHash: string; mint: string; token: string; runtime?: {wallet: {profile: string}; instanceBinding?: Record<string, unknown>}}
import {stellarAccountKey, stellarAssetContractId} from './stellar-wallet.js';
import {decodePublicFragment} from './owner-handoff.js';
import {STELLAR_APPROVAL_FRAGMENT} from './stellar-fragments.js';
export {STELLAR_APPROVAL_FRAGMENT} from './stellar-fragments.js';
export interface ApprovalBinding {wallet:string;route:'native';policyInstance:string;moduleDigest:string;asset:string;assetSymbol:string;assetIssuer:string|null;maxFeeStroops:number;deploymentId:string|null;language?:string;tier?:string;rules?:string[];params?:Record<string,unknown>;paramsHash?:string}
export interface StellarApprovalIntent {version:1|2;profile:'allowit-stellar-approval-v1'|'allowit-stellar-approval-v2';requestId:string;network:'stellar:testnet';owner:string;policyId:string;revision:number;source:string;sourceHash:string;irHash:string;binding:ApprovalBinding;intentDigest:string}
const hash=digest;
const canonical=canonicalJson;
export const stellarApprovalDigest=(v:StellarApprovalIntent)=>hash(JSON.stringify([v.profile,v.requestId,v.network,v.owner,v.policyId,v.revision,v.sourceHash,v.irHash,hash(canonical(v.binding))]));
function exact(v:unknown,keys:string[]):v is Record<string,unknown>{return !!v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).length===keys.length&&Object.keys(v).every(k=>keys.includes(k));}
export function parseStellarApprovalIntent(fragment:string):StellarApprovalIntent {
 const value=decodePublicFragment(fragment,STELLAR_APPROVAL_FRAGMENT);
 if(!exact(value,['version','profile','requestId','network','owner','policyId','revision','source','sourceHash','irHash','binding','intentDigest'])||!((value.version===1&&value.profile==='allowit-stellar-approval-v1')||(value.version===2&&value.profile==='allowit-stellar-approval-v2'))||value.network!=='stellar:testnet'
  ||typeof value.requestId!=='string'||!/^[A-Za-z0-9._:-]{8,100}$/.test(value.requestId)||typeof value.owner!=='string'
  ||typeof value.policyId!=='string'||!/^[A-Za-z0-9._:-]{1,128}$/.test(value.policyId)
  ||!Number.isInteger(value.revision)||Number(value.revision)<=0||Number(value.revision)>0xffffffff
  ||typeof value.source!=='string'||new TextEncoder().encode(value.source).length>32_768
  ||typeof value.sourceHash!=='string'||value.sourceHash!==hash(value.source)||typeof value.irHash!=='string'||(value.version===1?!hexHash(value.irHash):value.irHash!=='')
  ||!exact(value.binding,['wallet','route','policyInstance','moduleDigest','asset','assetSymbol','assetIssuer','maxFeeStroops','deploymentId',...(value.version===2?['language','tier','rules','params','paramsHash']:[])])||typeof value.intentDigest!=='string')throw new Error('This link does not contain a supported Native Stellar policy approval.');
 const v=value as unknown as StellarApprovalIntent,b=v.binding;
 if(b.route!=='native'||typeof b.wallet!=='string'||typeof b.policyInstance!=='string'||!/^[0-9a-f]{64}$/.test(b.policyInstance)||typeof b.moduleDigest!=='string'||!/^[0-9a-f]{64}$/.test(b.moduleDigest)
  ||typeof b.asset!=='string'||!StrKey.isValidContract(b.asset)||typeof b.assetSymbol!=='string'||!/^[A-Za-z0-9]{1,12}$/.test(b.assetSymbol)
  ||(b.assetIssuer!==null&&typeof b.assetIssuer!=='string')||!Number.isInteger(b.maxFeeStroops)||b.maxFeeStroops<100||b.maxFeeStroops>1_000_000
  ||(b.deploymentId!==null&&(typeof b.deploymentId!=='string'||!/^[0-9a-f]{64}$/.test(b.deploymentId))))throw new Error('The installed Stellar policy binding is invalid.');
 if(v.version===2){const p=object(b.params);if(b.language!=='allowit-portable-v1'||!['standard','custom'].includes(String(b.tier))||!Array.isArray(b.rules)||!b.rules.every(r=>typeof r==='string')||(b.tier==='custom'&&b.rules.length!==0)||!p||!hexHash(b.paramsHash)||digest(canonical(p))!==b.paramsHash||digest(canonical({language:b.language,tier:b.tier,rules:b.rules,sourceHash:v.sourceHash,paramsHash:b.paramsHash}))!==b.moduleDigest)throw new Error('The portable Stellar policy binding is invalid.');}
 stellarAccountKey(v.owner);stellarAccountKey(b.wallet);if(b.assetIssuer!==null)stellarAccountKey(b.assetIssuer);
 if(b.assetIssuer===null&&b.assetSymbol!=='XLM')throw new Error('The Stellar asset needs its exact issuer.');
 if(stellarAssetContractId(b.assetSymbol,b.assetIssuer,'stellar:testnet')!==b.asset)throw new Error('The Stellar asset contract differs from its code, issuer or network.');
 if(stellarApprovalDigest(v)!==v.intentDigest)throw new Error('The Stellar policy approval changed. Return to the original CLI link.');
 return v;
}
/** Only the original owner-stored policy can continue. Handoff source never creates or replaces policy. */
export function matchStellarApproval<P extends ApprovalPolicy>(v:StellarApprovalIntent,policy:P|undefined,owner:string,network:string):P {
 const b=policy?.runtime?.instanceBinding;
 if(owner!==v.owner||network!==v.network||!policy||policy.id!==v.policyId||policy.revision!==v.revision||policy.network!==v.network
  ||policy.code!==v.source||policy.sourceHash!==v.sourceHash||policy.irHash!==v.irHash||policy.mint!==v.binding.asset||policy.token!==v.binding.assetSymbol
  ||policy.runtime?.wallet.profile!=='allowit-stellar-native-v1'||!b
  ||b.wallet!==v.binding.wallet||b.route!=='native'||b.policyInstance!==v.binding.policyInstance||b.moduleDigest!==v.binding.moduleDigest
  ||b.asset!==v.binding.asset||b.assetSymbol!==v.binding.assetSymbol||(b.assetIssuer??null)!==v.binding.assetIssuer||b.maxFeeStroops!==v.binding.maxFeeStroops
  ||(b.deploymentId??null)!==v.binding.deploymentId)throw new Error('This link differs from the owner’s stored policy or installed wallet. Nothing was signed.');
 if(v.version===2){const p=object(b?.portable);if(!p||p.language!==v.binding.language||p.tier!==v.binding.tier||!((p.rules??[]) instanceof Array)||canonical(p.rules??[])!==canonical(v.binding.rules)||canonical(p.params)!==canonical(v.binding.params)||p.paramsHash!==v.binding.paramsHash)throw new Error('The portable approval differs from the stored policy. Nothing was signed.');}
 return policy;
}

const bytesHex = (value: unknown) => Array.isArray(value) && value.length === 32 && value.every(b => Number.isInteger(b) && b >= 0 && b <= 255) ? value.map((b: number) => b.toString(16).padStart(2, '0')).join('') : '';
const plainObject = (value: unknown) => value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : null;
/** Rebuilds the export from checked public fields only. Unexpected response fields never reach the file. */
export function publicStellarBundle(value: unknown, policy: ApprovalPolicy, owner: string, service: unknown, admit:PortableAdmission) {
  const b = plainObject(value), c = plainObject(b?.config), e = plainObject(b?.endpoints), binding = policy.runtime?.instanceBinding;
  const server = typeof c?.server === 'string' ? c.server : '';
  const agent = typeof c?.agent === 'string' ? c.agent : '';
  try {stellarAccountKey(owner); stellarAccountKey(server); stellarAccountKey(agent);} catch {throw new Error('The public agent bundle names an invalid signer. Nothing was saved.');}
  if (new Set([owner, agent, server]).size !== 3) throw new Error('The public agent bundle must name distinct owner, agent and server signers. Nothing was saved.');
  // The server signer must match the independently configured same-origin service (native/config).
  const s = plainObject(service);
  if (!s || s.profile !== 'allowit-stellar-wallet-v1' || !Array.isArray(s.networks) || !s.networks.includes(policy.network) || s.enginePublicKey !== server) throw new Error('The public agent bundle server differs from the configured Stellar service. Nothing was saved.');
  if (!b || !c || !e || !binding || b.version !== 1 || b.profile !== 'allowit-stellar-wallet-v1' || b.policyId !== policy.id || b.network !== policy.network
    || b.sourceHash !== policy.sourceHash || b.irHash !== policy.irHash || b.wallet !== binding.wallet || b.route !== 'native' || b.moduleDigest !== binding.moduleDigest
    || c.owner !== owner || c.network !== policy.network || c.wallet !== b.wallet || c.route !== 'native' || c.asset !== policy.mint || c.assetSymbol !== policy.token
    || (c.assetIssuer ?? null) !== (binding.assetIssuer ?? null) || c.policySource !== policy.code || c.maxFeeStroops !== binding.maxFeeStroops
    || bytesHex(c.policyInstance) !== binding.policyInstance || bytesHex(c.sourceHash) !== policy.sourceHash || bytesHex(c.moduleDigest) !== binding.moduleDigest
    || e.execute !== '/api/native/execute' || e.status !== '/api/native/execute/status') throw new Error('The public agent bundle does not match this policy. Nothing was saved.');
  const portable=portableExport(b,c,policy,admit);
  const bytes = (v: unknown) => [...(v as number[])];
  return {
    ...portable.top, version: 1, profile: 'allowit-stellar-wallet-v1', network: policy.network, policyId: policy.id, sourceHash: policy.sourceHash, irHash: policy.irHash,
    moduleDigest: binding.moduleDigest, wallet: binding.wallet, route: 'native',
    config: {network: policy.network, policyInstance: bytes(c.policyInstance), wallet: binding.wallet, owner, agent, server, route: 'native', ...portable.config, asset: policy.mint, assetSymbol: policy.token,
      assetIssuer: binding.assetIssuer ?? null, policySource: policy.code, sourceHash: bytes(c.sourceHash), moduleDigest: bytes(c.moduleDigest), maxFeeStroops: binding.maxFeeStroops},
    endpoints: {execute: '/api/native/execute', status: '/api/native/execute/status'},
  };
}
