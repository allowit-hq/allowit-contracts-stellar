import {STELLAR_PROFILES, stellarProfile} from './stellar-profiles.js';
export const isStellarNetwork = (network: unknown): network is 'stellar:testnet'|'stellar:mainnet'|'stellar:pubnet' => network === 'stellar:testnet' || network === 'stellar:mainnet' || network === 'stellar:pubnet';
export const isStellarPublicNetwork = (network: unknown): boolean => network === 'stellar:mainnet' || network === 'stellar:pubnet';
export const isStellarPolicy = (policy: {runtime?: {wallet?: {profile?: unknown}}; network: string}) => stellarProfile(policy.runtime?.wallet?.profile) && isStellarNetwork(policy.network);
export const STELLAR_FUNDING_MODE = 'stellar-installed';
export const STELLAR_SOURCE_PROFILE = 'allowit-stellar-transfer-v1';
export const STELLAR_OPERATION = 'stellar::sep41_transfer';
export function registryProfileValid(profile: string, kind: string, sources: string[], operations: string[]): boolean {
  return !stellarProfile(profile) || (kind === (STELLAR_PROFILES[profile].route === 'native' ? 'owner-wallet' : 'contract-wallet') && sources.length === 1 && sources[0] === STELLAR_SOURCE_PROFILE && operations.length === 1 && operations[0] === STELLAR_OPERATION);
}
export const paymentAssetValid = (asset: {decimals: number}, mint: unknown) => asset.decimals === 7 && typeof mint === 'string' && /^C[A-Z2-7]{55}$/.test(mint);
export const runtimeProfileValid = (runtime: {sourceProfile: string; operation: string|null; wallet: {kind: string; profile: string}; capabilities: {providerCall: boolean}}) => runtime.sourceProfile === STELLAR_SOURCE_PROFILE && runtime.operation === STELLAR_OPERATION && runtime.wallet.kind === (STELLAR_PROFILES[runtime.wallet.profile].route === 'native' ? 'owner-wallet' : 'contract-wallet') && !runtime.capabilities.providerCall;
export interface StellarInstallation {policyId: string; owner: string; wallet: string; network: string; sourceHash: string; moduleDigest: string; route: 'native'|'policyWallet'; ledger: number; state: 'installed'}
export function installationValid(a: Record<string, unknown>, profile: string, network: string): boolean {
  return a.state === 'installed' && a.policyId !== undefined && a.owner !== undefined && a.wallet !== undefined && a.network === network && typeof a.ledger === 'number' && Number.isSafeInteger(a.ledger) && a.ledger > 0 && a.route === STELLAR_PROFILES[profile].route && /^G[A-Z2-7]{55}$/.test(a.owner as string) && (a.route === 'native' ? /^G[A-Z2-7]{55}$/ : /^C[A-Z2-7]{55}$/).test(a.wallet as string) && /^[a-f0-9]{64}$/.test(a.sourceHash as string) && /^[a-f0-9]{64}$/.test(a.moduleDigest as string);
}
export function installationReady(policy: {id?: string; status?: string; network: string; sourceHash?: string}, installation: StellarInstallation|undefined, owner: string): boolean {
  return policy.status === 'active' && !!installation && installation.state === 'installed' && installation.owner === owner && installation.policyId === policy.id && installation.network === policy.network && installation.sourceHash === policy.sourceHash && installation.ledger > 0;
}
