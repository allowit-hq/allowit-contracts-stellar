import {canonicalJson,digest} from './consent-codec.js';
export {canonicalJson,digest} from './consent-codec.js';
import {ed25519} from '@noble/curves/ed25519';
import {stellarAccountKey, stellarAssetContractId, stellarMessageDigest, type StellarNetwork} from './stellar-wallet.js';
export const object = (value: unknown): Record<string, unknown> | null => value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : null;
export const hexHash = (value: unknown): value is string => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
function reject(): never {throw new Error('The portable Stellar source or consent differs from the selected policy. Nothing was saved.');}
const same = (a: unknown, b: unknown) => canonicalJson(a) === canonicalJson(b);
export type PortableAdmission = (portable:Readonly<Record<string,unknown>>)=>boolean;
export type PortablePolicy = {id: string; revision?: number; network: string; code: string; sourceHash: string; irHash: string; mint: string; token: string; runtime?: {instanceBinding?: Record<string, unknown>}};
/** Validate portable identity without rewriting its signed values or claiming current RPC authority. */
export function portableExport(bundle: Record<string, unknown>, config: Record<string, unknown>, policy: PortablePolicy, admit:PortableAdmission): {top: Record<string, unknown>; config: Record<string, unknown>} {
  if(typeof admit!=='function')reject();
  const binding = policy.runtime?.instanceBinding;
  const expected = object(binding?.portable);
  const claimsPortable = bundle.language !== undefined || bundle.portable !== undefined || config.language === 'portable' || binding?.language === 'allowit-portable-v1' || expected !== null;
  if (!claimsPortable) {
    if (!hexHash(bundle.irHash)) reject();
    return {top: {}, config: {}};
  }
  const p = object(bundle.portable), rules = p?.rules ?? [], asset = object(p?.asset), build = object(p?.build), params = object(p?.params);
  if(!p||admit(p)!==true)reject();
  if (!expected || !p || !params || !asset || !build || bundle.language !== 'allowit-portable-v1' || p.language !== bundle.language || config.language !== 'portable'
      || policy.irHash !== '' || bundle.irHash !== '' || p.sourceHash !== policy.sourceHash || digest(policy.code) !== policy.sourceHash
      || !['standard','custom'].includes(String(p.tier)) || !Array.isArray(rules) || !rules.every(v => typeof v === 'string')
      || (p.tier === 'custom' && rules.length !== 0) || !hexHash(p.paramsHash) || digest(canonicalJson(params)) !== p.paramsHash
      || !same(p, expected) || !same(config.params ?? {}, params)
      || asset.address !== config.asset || asset.symbol !== config.assetSymbol || asset.decimals !== 7
      || !Array.isArray(p.unresolved) || !p.unresolved.every(v=>typeof v==='string') || !Array.isArray(build.prefix) || !build.prefix.every(v => typeof v === 'string')
      || typeof build.writesState !== 'boolean' || !(typeof build.libraryRevision === 'string') || !Number.isInteger(build.attempts)) reject();
  if (stellarAssetContractId(String(config.assetSymbol), config.assetIssuer == null ? null : String(config.assetIssuer), policy.network as StellarNetwork) !== config.asset) reject();
  const kinds = p.kinds === undefined ? undefined : object(p.kinds);
  if (p.kinds !== undefined && (!kinds || Object.values(kinds).some(v => typeof v !== 'string'))) reject();
  if (config.route === 'native') {
    if (config.tier != null || !same(config.rules ?? [], []) || !same(config.sourceDigest ?? Array(32).fill(0), Array(32).fill(0))
        || digest(canonicalJson({language:p.language,tier:p.tier,rules,sourceHash:p.sourceHash,paramsHash:p.paramsHash})) !== bundle.moduleDigest) reject();
  } else if (!['simple','common','custom'].includes(String(config.tier)) || config.tier !== binding?.tier) reject();
  // Whitelist metadata shapes. Params are owner-signed data, not arbitrary server response metadata.
  const portable = {language:p.language,sourceHash:p.sourceHash,tier:p.tier,...(rules.length ? {rules} : {}),params,paramsHash:p.paramsHash,
    asset:{symbol:asset.symbol,address:asset.address,decimals:asset.decimals},unresolved:[...p.unresolved],build:{prefix:build.prefix,writesState:build.writesState,libraryRevision:build.libraryRevision,attempts:build.attempts},...(kinds ? {kinds} : {})};
  // Omitted empty rules have their native serde default; preserve a supplied empty array literally.
  if (Object.hasOwn(p,'rules')) Object.assign(portable,{rules});
  const top: Record<string, unknown> = {language:bundle.language,portable};
  if (config.route === 'native') {
    const consent = object(bundle.sourceApproval);
    if (!consent || Object.keys(consent).length !== 2 || !Object.hasOwn(consent,'revision') || !Object.hasOwn(consent,'signatures')
        || !Number.isInteger(consent.revision) || Number(consent.revision) < 1 || Number(consent.revision) > 0xffffffff || consent.revision !== policy.revision
        || !Array.isArray(consent.signatures) || consent.signatures.length < 1 || consent.signatures.length > 20) reject();
    const message = `AllowIt Native policy approval v1\n${canonicalJson({version:1,policyId:policy.id,revision:consent.revision,network:bundle.network,wallet:bundle.wallet,route:bundle.route,policyInstance:binding?.policyInstance,source:policy.code,sourceHash:policy.sourceHash,irHash:policy.irHash,moduleDigest:bundle.moduleDigest,asset:config.asset,assetSymbol:config.assetSymbol,assetIssuer:config.assetIssuer??null,maxFeeStroops:config.maxFeeStroops,language:p.language,tier:p.tier,rules,params,paramsHash:p.paramsHash})}`;
    const seen = new Set<string>();
    const signatures = consent.signatures.map(value => {
      const s = object(value);
      if (!s || Object.keys(s).length !== 2 || typeof s.signer !== 'string' || seen.has(s.signer) || !Array.isArray(s.signature) || s.signature.length !== 64 || !s.signature.every(v => Number.isInteger(v) && v >= 0 && v <= 255)) reject();
      const signer = s.signer as string, signature = s.signature as number[]; seen.add(signer);
      if (!ed25519.verify(new Uint8Array(signature), stellarMessageDigest(message), stellarAccountKey(signer), {zip215:false})) reject();
      return {signer,signature:[...signature]};
    });
    top.sourceApproval = {revision:consent.revision,signatures};
  } else if (bundle.sourceApproval !== undefined) reject();
  const extra: Record<string, unknown> = {language:config.language};
  for (const key of ['tier','rules','params','sourceDigest']) if (Object.hasOwn(config,key)) extra[key] = config[key];
  return {top,config:extra};
}
