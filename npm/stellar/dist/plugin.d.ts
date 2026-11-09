/**
 * The Stellar rail plugin for the AllowIt SDK registry. Hosts never import this module directly: the SDK
 * registration imports it, and hosts render its elements through `<allowit-rail kind network>`.
 * Importing it touches no DOM; `define()` registers the elements on first use.
 */
import { type ExplorerKind } from './explorer.js';
import { defineElements } from './elements/index.js';
export type ElementKind = 'address' | 'explorer-link' | 'amount' | 'wallet-sign-in' | 'owner-sign' | 'receipt' | 'binding-review';
export type Feature = 'transfer' | 'swap' | 'deposit' | 'redeem' | 'owner-setup' | 'deploy' | 'fund' | 'activate' | 'binding-review' | 'explorer-links';
export interface RailNetwork {
    id: string;
    label: string;
    testnet: boolean;
    aliases: readonly string[];
}
export interface AssetInfo {
    network: string;
    id: string;
    symbol: string;
    decimals: number;
    stablecoin: boolean;
    label: string;
}
export declare const NETWORKS: readonly RailNetwork[];
/** The canonical network id for an id or alias, or null. */
export declare function canonicalNetwork(network: unknown): string | null;
export declare function networkPassphrase(network: string): string;
/** StrKey decoding with its checksum. Returns the version byte and the 32-byte key, or null. */
export declare function strkey(text: unknown): {
    version: number;
    key: Uint8Array;
} | null;
export declare function assets(network: string): readonly AssetInfo[];
export declare function validateAddress(network: string, text: string): boolean;
export declare function explorerUrl(network: string, kind: ExplorerKind, id: string): string | null;
declare const plugin: Readonly<{
    id: "stellar";
    networks: readonly RailNetwork[];
    elements: Readonly<{
        readonly address: "allowit-stellar-address";
        readonly 'explorer-link': "allowit-stellar-explorer-link";
        readonly amount: "allowit-stellar-amount";
        readonly 'wallet-sign-in': "allowit-stellar-wallet-sign-in";
        readonly 'owner-sign': "allowit-stellar-owner-sign";
        readonly receipt: "allowit-stellar-receipt";
        readonly 'binding-review': "allowit-stellar-binding-review";
    }>;
    define: typeof defineElements;
    validateAddress: typeof validateAddress;
    explorerUrl: typeof explorerUrl;
    assets: typeof assets;
    test: Readonly<{
        network: "stellar:testnet";
        skips: Readonly<Partial<Record<Feature, string>>>;
        fixtures: Readonly<{
            address: "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";
            invalidAddress: "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA6";
            txHash: string;
            asset: "USDC";
        }>;
    }>;
}>;
export default plugin;
