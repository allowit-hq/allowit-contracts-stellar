/**
 * The Stellar networks of the rail. It imports only the network table, so every module of the package reads the
 * networks without an import cycle through the plugin.
 */
import { STELLAR_NETWORKS } from './stellar-asset.js';
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
