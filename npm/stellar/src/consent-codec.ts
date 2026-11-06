/** Canonical bytes used by the native consent and handoff wire protocols. */
import {sha256} from '@noble/hashes/sha256';
export const hex = (value:Uint8Array):string=>Array.from(value,byte=>byte.toString(16).padStart(2,'0')).join('');
export const canonicalJson = (value:unknown):string=>JSON.stringify(value,(_key,item)=>item&&typeof item==='object'&&!Array.isArray(item)?Object.fromEntries(Object.keys(item).sort().map(key=>[key,item[key]])):item);
export const digest = (value:string):string=>hex(sha256(new TextEncoder().encode(value)));
