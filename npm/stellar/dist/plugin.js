/**
 * The Stellar rail plugin for the AllowIt SDK registry. Hosts never import this module directly: the SDK
 * registration imports it, and hosts render its elements through `<allowit-rail kind network>`.
 * Importing it touches no DOM; `define()` registers the elements on first use.
 */
import { stellarExplorerUrl } from './explorer.js';
import { stellarAssetContract } from './stellar-asset.js';
import { defineElements, ELEMENTS } from './elements/index.js';
const TESTNET = 'stellar:testnet', PUBNET = 'stellar:pubnet';
const PASSPHRASES = {
    [TESTNET]: 'Test SDF Network ; September 2015',
    [PUBNET]: 'Public Global Stellar Network ; September 2015',
};
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
    return PASSPHRASES[id];
}
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
/** StrKey decoding with its checksum. Returns the version byte and the 32-byte key, or null. */
export function strkey(text) {
    if (typeof text !== 'string' || !/^[GC][A-Z2-7]{55}$/.test(text))
        return null;
    const bytes = [];
    let value = 0, bits = 0;
    for (const char of text) {
        value = (value << 5) | ALPHABET.indexOf(char);
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            bytes.push((value >>> bits) & 255);
        }
    }
    if (bytes.length !== 35 || (value & ((1 << bits) - 1)) !== 0)
        return null;
    let crc = 0;
    for (const byte of bytes.slice(0, 33)) {
        crc ^= byte << 8;
        for (let i = 0; i < 8; i++)
            crc = ((crc & 0x8000) ? (crc << 1) ^ 0x1021 : crc << 1) & 0xffff;
    }
    if (bytes[33] !== (crc & 255) || bytes[34] !== (crc >>> 8))
        return null;
    // Version bytes: 6 << 3 for an account (G), 2 << 3 for a contract (C).
    if (bytes[0] !== (text[0] === 'G' ? 48 : 16))
        return null;
    return { version: bytes[0], key: new Uint8Array(bytes.slice(1, 33)) };
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
        const passphrase = PASSPHRASES[id];
        const usdc = strkey(USDC_ISSUER[id]).key;
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
