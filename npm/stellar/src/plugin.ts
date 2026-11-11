/**
 * The Stellar rail plugin for the AllowIt SDK registry. Hosts never import this module directly: the SDK
 * registration imports it, and hosts render its elements through `<allowit-rail kind network>`.
 * Importing it touches no DOM; `define()` registers the elements on first use.
 */
import {stellarExplorerUrl, type ExplorerKind} from './explorer.js';
import {StrKey} from '@stellar/stellar-sdk/base';
import {STELLAR_NETWORKS, stellarAssetContract} from './stellar-asset.js';
import {defineElements, ELEMENTS} from './elements/index.js';
import {ADK_OWNER_FRAGMENT, adkParamLines, parseReviewLink, reviewAgentPrompt} from './adk-owner-link.js';
import {installAndFund} from './owner-flow.js';

export type ElementKind = 'address'|'explorer-link'|'amount'|'wallet-sign-in'|'owner-sign'|'receipt'|'binding-review';
export type Feature = 'transfer'|'swap'|'deposit'|'redeem'|'owner-setup'|'deploy'|'fund'|'activate'|'binding-review'|'explorer-links';
export interface RailNetwork {id: string; label: string; testnet: boolean; aliases: readonly string[]}
export interface AssetInfo {network: string; id: string; symbol: string; decimals: number; stablecoin: boolean; label: string}

const TESTNET = 'stellar:testnet', PUBNET = 'stellar:pubnet';
export const NETWORKS: readonly RailNetwork[] = Object.freeze([
  {id: TESTNET, label: 'Stellar Testnet', testnet: true, aliases: Object.freeze(['stellar-testnet'])},
  {id: PUBNET, label: 'Stellar Mainnet', testnet: false, aliases: Object.freeze(['stellar:mainnet', 'stellar-mainnet'])},
]);
/** The canonical network id for an id or alias, or null. */
export function canonicalNetwork(network: unknown): string | null {
  if (typeof network !== 'string') return null;
  return NETWORKS.find(n => n.id === network || n.aliases.includes(network))?.id ?? null;
}
export function networkPassphrase(network: string): string {
  const id = canonicalNetwork(network);
  if (!id) throw new Error('Select a supported Stellar network.');
  return STELLAR_NETWORKS[id as keyof typeof STELLAR_NETWORKS].passphrase;
}

/** StrKey decoding with its checksum, through the Stellar SDK. Returns the version byte and the 32-byte key, or null. */
export function strkey(text: unknown): {version: number; key: Uint8Array} | null {
  if (typeof text !== 'string') return null;
  // Version bytes: 6 << 3 for an account (G), 2 << 3 for a contract (C).
  if (StrKey.isValidEd25519PublicKey(text)) return {version: 48, key: new Uint8Array(StrKey.decodeEd25519PublicKey(text))};
  if (StrKey.isValidContract(text)) return {version: 16, key: new Uint8Array(StrKey.decodeContract(text))};
  return null;
}

const USDC_ISSUER: Readonly<Record<string, string>> = {
  [TESTNET]: 'GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5',
  [PUBNET]: 'GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN',
};
const ASSETS = new Map<string, readonly AssetInfo[]>();
export function assets(network: string): readonly AssetInfo[] {
  const id = canonicalNetwork(network);
  if (!id) return [];
  let list = ASSETS.get(id);
  if (!list) {
    const passphrase = networkPassphrase(id);
    const usdc = USDC_ISSUER[id];
    list = Object.freeze([
      {network: id, id: stellarAssetContract('XLM', null, passphrase), symbol: 'XLM', decimals: 7, stablecoin: false, label: 'Lumens'},
      {network: id, id: stellarAssetContract('USDC', usdc, passphrase), symbol: 'USDC', decimals: 7, stablecoin: true, label: 'USD Coin'},
    ]);
    ASSETS.set(id, list);
  }
  return list;
}

/** The selection ids of the wallet kinds. `standard` is the tier that technical names call Common. */
export type WalletKindId = 'native' | 'simple' | 'standard' | 'custom';
export interface AssetDisplay {symbol: string; decimals: number; name: string; native: boolean}
const KINDS: readonly WalletKindId[] = Object.freeze(['native', 'simple', 'standard', 'custom']);
/** Every Stellar network offers the four kinds: a native account and the three policy wallet tiers. */
export function walletKinds(network: string): readonly WalletKindId[] {
  return canonicalNetwork(network) ? KINDS : [];
}
const record = (value: unknown): Record<string, unknown> | null =>
  value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : null;
/**
 * The wallet kind that a policy, draft, wallet profile or installation binds, or null when it binds none yet.
 * It reads the route and tier of `runtime.instanceBinding`, of `config` or of the document itself.
 */
export function walletKind(document: unknown): WalletKindId | null {
  const top = record(document);
  const binding = record(record(top?.runtime)?.instanceBinding) ?? record(top?.config) ?? top;
  const route = binding?.route ?? top?.route, tier = binding?.tier;
  if (route === 'native') return tier === undefined || tier === null ? 'native' : null;
  if (route !== 'policyWallet') return null;
  return tier === 'simple' ? 'simple' : tier === 'common' ? 'standard' : tier === 'custom' ? 'custom' : null;
}
const display = (asset: AssetInfo): AssetDisplay => ({symbol: asset.symbol, decimals: asset.decimals, name: asset.label, native: asset.symbol === 'XLM'});
/** XLM: the native asset and the fee asset of every Stellar network. */
export function nativeAsset(network: string): AssetDisplay | null {
  const native = assets(network)[0];
  return native ? display(native) : null;
}
/**
 * Display metadata of an asset reference: `native`, a listed code, `CODE:ISSUER`, or the asset contract id of a
 * listed asset. Another classic asset shows its code with the seven classic decimals. An unlisted contract has no
 * known unit, so the result is null and never a placeholder.
 */
export function assetDisplay(network: string, asset: string): AssetDisplay | null {
  const id = canonicalNetwork(network);
  if (!id || typeof asset !== 'string') return null;
  const list = assets(id);
  if (asset === 'native') return display(list[0]);
  const [code, issuer, ...rest] = asset.split(':');
  if (rest.length) return null;
  if (issuer === undefined) {
    const listed = list.find(item => item.symbol === asset || item.id === asset);
    return listed ? display(listed) : null;
  }
  if (!/^[A-Za-z0-9]{1,12}$/.test(code) || !StrKey.isValidEd25519PublicKey(issuer)) return null;
  const contract = stellarAssetContract(code, issuer, networkPassphrase(id));
  const listed = list.find(item => item.id === contract);
  if (listed) return display(listed);
  return {symbol: code, decimals: 7, name: code, native: false};
}

export function validateAddress(network: string, text: string): boolean {
  return canonicalNetwork(network) !== null && strkey(text) !== null;
}
export function explorerUrl(network: string, kind: ExplorerKind, id: string): string | null {
  const canonical = canonicalNetwork(network);
  return canonical ? stellarExplorerUrl(kind, id, canonical) : null;
}

const plugin = Object.freeze({
  id: 'stellar',
  networks: NETWORKS,
  elements: ELEMENTS,
  define: defineElements,
  validateAddress,
  explorerUrl,
  assets,
  walletKinds,
  walletKind,
  nativeAsset,
  assetDisplay,
  /** Review and sign links: the fragment, its parser, the agent prompt and the owner-readable params. */
  review: Object.freeze({fragment: ADK_OWNER_FRAGMENT, parseLink: parseReviewLink, agentPrompt: reviewAgentPrompt, paramLines: adkParamLines}),
  /** The owner workflow that a host runs after the review. */
  ownerWorkflow: Object.freeze({installAndFund}),
  test: Object.freeze({
    network: TESTNET,
    skips: Object.freeze({swap: 'Stellar has no swap venue in the minimal path'} as Partial<Record<Feature, string>>),
    fixtures: Object.freeze({
      address: 'GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5',
      invalidAddress: 'GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA6',
      txHash: 'ab'.repeat(32),
      asset: 'USDC',
    }),
  }),
});
export default plugin;
