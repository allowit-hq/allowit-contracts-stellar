/**
 * The Stellar rail plugin for the AllowIt SDK registry. Hosts never import this module directly: the SDK
 * registration imports it, and hosts render its elements through `<allowit-rail kind network>`.
 * Importing it touches no DOM; `define()` registers the elements on first use.
 */
import { stellarExplorerUrl } from './explorer.js';
import { StrKey } from '@stellar/stellar-sdk/base';
import { STELLAR_NETWORKS, stellarAssetContract } from './stellar-asset.js';
import { defineElements, ELEMENTS } from './elements/index.js';
const TESTNET = 'stellar:testnet', PUBNET = 'stellar:pubnet';
export const NETWORKS = Object.freeze([
    { id: TESTNET, label: 'Stellar Testnet', testnet: true, aliases: Object.freeze(['stellar-testnet']) },
    { id: PUBNET, label: 'Stellar Mainnet', testnet: false, aliases: Object.freeze(['stellar:mainnet', 'stellar-mainnet']) },
]);
/** The canonical network id for an id or alias, or null. */
export function canonicalNetwork(network) {
    if (typeof network !== 'string')
        return null;
    return NETWORKS.find(n => n.id === network || n.aliases.includes(network))?.id ?? null;
}
export function networkPassphrase(network) {
    const id = canonicalNetwork(network);
    if (!id)
        throw new Error('Select a supported Stellar network.');
    return STELLAR_NETWORKS[id].passphrase;
}
/** StrKey decoding with its checksum, through the Stellar SDK. Returns the version byte and the 32-byte key, or null. */
export function strkey(text) {
    if (typeof text !== 'string')
        return null;
    // Version bytes: 6 << 3 for an account (G), 2 << 3 for a contract (C).
    if (StrKey.isValidEd25519PublicKey(text))
        return { version: 48, key: new Uint8Array(StrKey.decodeEd25519PublicKey(text)) };
    if (StrKey.isValidContract(text))
        return { version: 16, key: new Uint8Array(StrKey.decodeContract(text)) };
    return null;
}
const USDC_ISSUER = {
    [TESTNET]: 'GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5',
    [PUBNET]: 'GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN',
};
const ASSETS = new Map();
export function assets(network) {
    const id = canonicalNetwork(network);
    if (!id)
        return [];
    let list = ASSETS.get(id);
    if (!list) {
        const passphrase = networkPassphrase(id);
        const usdc = USDC_ISSUER[id];
        list = Object.freeze([
            { network: id, id: stellarAssetContract('XLM', null, passphrase), symbol: 'XLM', decimals: 7, stablecoin: false, label: 'Lumens' },
            { network: id, id: stellarAssetContract('USDC', usdc, passphrase), symbol: 'USDC', decimals: 7, stablecoin: true, label: 'USD Coin' },
        ]);
        ASSETS.set(id, list);
    }
    return list;
}
export function validateAddress(network, text) {
    return canonicalNetwork(network) !== null && strkey(text) !== null;
}
export function explorerUrl(network, kind, id) {
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
    test: Object.freeze({
        network: TESTNET,
        skips: Object.freeze({ swap: 'Stellar has no swap venue in the minimal path' }),
        fixtures: Object.freeze({
            address: 'GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5',
            invalidAddress: 'GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA6',
            txHash: 'ab'.repeat(32),
            asset: 'USDC',
        }),
    }),
});
export default plugin;
