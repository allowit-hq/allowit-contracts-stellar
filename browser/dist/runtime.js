import { STELLAR_PROFILES, stellarProfile } from './stellar-profiles.js';
export const isStellarNetwork = (network) => network === 'stellar:testnet' || network === 'stellar:mainnet';
export const isStellarPolicy = (policy) => stellarProfile(policy.runtime?.wallet?.profile) && isStellarNetwork(policy.network);
export const STELLAR_FUNDING_MODE = 'stellar-installed';
export const STELLAR_SOURCE_PROFILE = 'allowit-stellar-transfer-v1';
export const STELLAR_OPERATION = 'stellar::sep41_transfer';
export function registryProfileValid(profile, kind, sources, operations) {
    return !stellarProfile(profile) || (kind === (STELLAR_PROFILES[profile].route === 'native' ? 'owner-wallet' : 'contract-wallet') && sources.length === 1 && sources[0] === STELLAR_SOURCE_PROFILE && operations.length === 1 && operations[0] === STELLAR_OPERATION);
}
export const paymentAssetValid = (asset, mint) => asset.decimals === 7 && typeof mint === 'string' && /^C[A-Z2-7]{55}$/.test(mint);
export const runtimeProfileValid = (runtime) => runtime.sourceProfile === STELLAR_SOURCE_PROFILE && runtime.operation === STELLAR_OPERATION && runtime.wallet.kind === (STELLAR_PROFILES[runtime.wallet.profile].route === 'native' ? 'owner-wallet' : 'contract-wallet') && !runtime.capabilities.providerCall;
export function installationValid(a, profile, network) {
    return a.state === 'installed' && a.policyId !== undefined && a.owner !== undefined && a.wallet !== undefined && a.network === network && typeof a.ledger === 'number' && Number.isSafeInteger(a.ledger) && a.ledger > 0 && a.route === STELLAR_PROFILES[profile].route && /^G[A-Z2-7]{55}$/.test(a.owner) && (a.route === 'native' ? /^G[A-Z2-7]{55}$/ : /^C[A-Z2-7]{55}$/).test(a.wallet) && /^[a-f0-9]{64}$/.test(a.sourceHash) && /^[a-f0-9]{64}$/.test(a.moduleDigest);
}
export function installationReady(policy, installation, owner) {
    return policy.status === 'active' && !!installation && installation.state === 'installed' && installation.owner === owner && installation.policyId === policy.id && installation.network === policy.network && installation.sourceHash === policy.sourceHash && installation.ledger > 0;
}
