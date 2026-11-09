import {portableExport,type PortableAdmission} from './portable-export.js';
import {stellarAccountKey} from './stellar-wallet.js';
import {ed25519} from '@noble/curves/ed25519';

const alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function crc(bytes:Uint8Array):number{let value=0;for(const byte of bytes){value^=byte<<8;for(let i=0;i<8;i++)value=((value&0x8000)?(value<<1)^0x1021:value<<1)&0xffff;}return value;}
function encodeKey(version:number,key:Uint8Array):string{
 const bytes=new Uint8Array(35);bytes[0]=version;bytes.set(key,1);const check=crc(bytes.subarray(0,33));bytes[33]=check&255;bytes[34]=check>>>8;
 let value=0,bits=0,text='';for(const byte of bytes){value=(value<<8)|byte;bits+=8;while(bits>=5){bits-=5;text+=alphabet[(value>>>bits)&31];}}return text;
}
function decodeSeed(text:string):Uint8Array{
 if(!/^S[A-Z2-7]{55}$/.test(text))throw new Error('Enter the customer signing key as a Stellar S seed.');
 const bytes:number[]=[];let value=0,bits=0;for(const char of text){value=(value<<5)|alphabet.indexOf(char);bits+=5;if(bits>=8){bits-=8;bytes.push((value>>>bits)&255);}}
 const seed=new Uint8Array(bytes.slice(1,33));if(bytes[0]!==144||encodeKey(144,seed)!==text)throw new Error('The customer signing key checksum is invalid.');return seed;
}
export function customerPublicKey(seedText:string):string{const seed=decodeSeed(seedText);try{return encodeKey(48,ed25519.getPublicKey(seed));}finally{seed.fill(0);}}
/** Encode native keys from caller-owned entropy. The caller owns generation and secret retention. */
export function customerKeyFromEntropy(entropy:Uint8Array):{seed:string;publicKey:string}{if(!(entropy instanceof Uint8Array)||entropy.length!==32)throw new Error('Provide exactly 32 bytes of customer key entropy.');const seed=new Uint8Array(entropy);try{return{seed:encodeKey(144,seed),publicKey:encodeKey(48,ed25519.getPublicKey(seed))};}finally{seed.fill(0);}}
export type PublicStellarBundle={version:number;profile:string;network:string;policyId:string;sourceHash:string;irHash:string;language?:string;portable?:Record<string,unknown>;sourceApproval?:unknown;moduleDigest:string;wallet:string;route:'native'|'policyWallet';config:Record<string,unknown>;endpoints:{execute:string;status:string}};
export type TokenPolicy={id:string;revision?:number;network:string;sourceHash:string;irHash:string;code:string;mint:string;token:string;runtime?:{instanceBinding?:Record<string,unknown>;authorization?:unknown}};
function bytesHex(value:unknown):string{return Array.isArray(value)&&value.length===32&&value.every(b=>Number.isInteger(b)&&b>=0&&b<=255)?value.map(b=>b.toString(16).padStart(2,'0')).join(''):'';}
/** Local-only encoding. Never pass its return value to an API, storage, URL, or analytics. */
export function customerToken(bundle:PublicStellarBundle,seedText:string,policy:TokenPolicy,owner:string,service:unknown,admit:PortableAdmission):string{
 const binding=policy.runtime?.instanceBinding;
 const c=bundle.config;
 if(!binding||!['native','policyWallet'].includes(bundle.route)||bundle.version!==1||bundle.profile!=='allowit-wallet-v1'||bundle.policyId!==policy.id||bundle.network!==policy.network||bundle.sourceHash!==policy.sourceHash||bundle.irHash!==policy.irHash||c.policySource!==policy.code||bundle.wallet!==binding.wallet||bundle.route!==binding.route||bundle.moduleDigest!==binding.moduleDigest||bytesHex(c.policyInstance)!==binding.policyInstance||bytesHex(c.sourceHash)!==policy.sourceHash||bytesHex(c.moduleDigest)!==binding.moduleDigest||c.owner!==owner||c.network!==policy.network||c.wallet!==bundle.wallet||c.route!==bundle.route||c.asset!==policy.mint||c.assetSymbol!==policy.token||(binding.maxFeeStroops!==undefined&&c.maxFeeStroops!==binding.maxFeeStroops)||(binding.assetIssuer!==undefined&&c.assetIssuer!==binding.assetIssuer)||bundle.endpoints.execute!=='/api/native/execute'||bundle.endpoints.status!=='/api/native/execute/status'||!['sourceHash','moduleDigest'].every(k=>/^[a-f0-9]{64}$/.test(bundle[k as 'sourceHash'])))throw new Error('The public deployment metadata does not match the selected Stellar policy.');
 const portable=portableExport(bundle as unknown as Record<string,unknown>,c,policy,admit);
 if(bundle.route==='policyWallet'&&portable.top.language===undefined&&(!['simple_policy_engine','common_policy_engine','custom_policy'].includes(String(c.policyEngine))||c.policyEngine!==binding.policyEngine))throw new Error('The policy engine differs from the selected wallet.');
 const agent=customerPublicKey(seedText);
 const server=typeof c.server==='string'?c.server:'';
 try{stellarAccountKey(owner);stellarAccountKey(agent);stellarAccountKey(server);}catch{throw new Error('The public deployment names an invalid signer. Nothing was saved.');}
 if(new Set([owner,agent,server]).size!==3)throw new Error('Owner, customer and server signers must be distinct. Nothing was saved.');
 const configured=service as {profile?:unknown;networks?:unknown;enginePublicKey?:unknown}|null;
 if(!configured||configured.profile!=='allowit-wallet-v1'||!Array.isArray(configured.networks)||!configured.networks.includes(policy.network)||configured.enginePublicKey!==server)throw new Error('The server differs from the configured Stellar service. Nothing was saved.');
 if(bundle.route==='native'&&c.policyEngine!==undefined)throw new Error('A native wallet cannot select a policy engine. Nothing was saved.');
 if(bundle.route==='policyWallet'&&agent!==c.agent)throw new Error('The customer key differs from the agent installed in this policy wallet.');
 // Copy only the public wallet contract. Unexpected response fields never enter the token.
 const config={network:c.network,policyInstance:c.policyInstance,wallet:c.wallet,owner:c.owner,agent,server:c.server,route:c.route,...(c.policyEngine===undefined?{}:{policyEngine:c.policyEngine}),...portable.config,asset:c.asset,assetSymbol:c.assetSymbol,assetIssuer:c.assetIssuer??null,policySource:c.policySource,sourceHash:c.sourceHash,moduleDigest:c.moduleDigest,maxFeeStroops:c.maxFeeStroops};
 const token={...portable.top,version:bundle.version,profile:bundle.profile,network:bundle.network,policyId:bundle.policyId,sourceHash:bundle.sourceHash,irHash:bundle.irHash,moduleDigest:bundle.moduleDigest,wallet:bundle.wallet,route:bundle.route,config,endpoints:bundle.endpoints,signingSeed:seedText};
 const bytes=new TextEncoder().encode(JSON.stringify(token));try{return'allowit-stellar-v1.'+Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join('');}finally{bytes.fill(0);}
}
