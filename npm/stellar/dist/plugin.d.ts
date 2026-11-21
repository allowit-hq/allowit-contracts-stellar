/**
 * The Stellar rail plugin for the AllowIt SDK registry. Hosts never import this module directly: the SDK
 * registration imports it, and hosts render its elements through `<allowit-rail kind network>`.
 * Importing it touches no DOM; `define()` registers the elements on first use.
 */
import { type ExplorerKind } from './explorer.js';
import { defineElements } from './elements/index.js';
import { parseReviewLink, reviewAgentPrompt, type AdkProposal } from './adk-owner-link.js';
import type { AssetDisplay, WalletKindId } from '@allowit/core';
export type ElementKind = 'address' | 'explorer-link' | 'amount' | 'wallet-sign-in' | 'owner-sign' | 'owner-answer' | 'receipt' | 'binding-review';
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
export { NETWORKS, canonicalNetwork, networkPassphrase } from './networks.js';
/** StrKey decoding with its checksum, through the Stellar SDK. Returns the version byte and the 32-byte key, or null. */
export declare function strkey(text: unknown): {
    version: number;
    key: Uint8Array;
} | null;
export declare function assets(network: string): readonly AssetInfo[];
/** Every Stellar network offers the four kinds: a native account and the three policy wallet tiers. */
export declare function walletKinds(network: string): readonly WalletKindId[];
/**
 * The wallet kind that a policy, draft, wallet profile or installation binds, or null when it binds none yet.
 * It reads the route and tier of `runtime.instanceBinding`, of `config` or of the document itself.
 */
export declare function walletKind(document: unknown): WalletKindId | null;
/** XLM: the native asset and the fee asset of every Stellar network. */
export declare function nativeAsset(network: string): AssetDisplay | null;
/**
 * Display metadata of an asset reference: `native`, a listed code, `CODE:ISSUER`, or the asset contract id of a
 * listed asset. Another classic asset shows its code with the seven classic decimals. An unlisted contract has no
 * known unit, so the result is null and never a placeholder.
 */
export declare function assetDisplay(network: string, asset: string): AssetDisplay | null;
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
        readonly 'owner-answer': "allowit-stellar-owner-answer";
        readonly receipt: "allowit-stellar-receipt";
        readonly 'binding-review': "allowit-stellar-binding-review";
    }>;
    define: typeof defineElements;
    validateAddress: typeof validateAddress;
    explorerUrl: typeof explorerUrl;
    assets: typeof assets;
    walletKinds: typeof walletKinds;
    walletKind: typeof walletKind;
    nativeAsset: typeof nativeAsset;
    assetDisplay: typeof assetDisplay;
    /** Review and sign links: the fragment, its parser, the agent prompt and the owner-readable params. */
    review: Readonly<{
        fragment: "#adk-proposal-v1=";
        parseLink: typeof parseReviewLink;
        agentPrompt: typeof reviewAgentPrompt;
        paramLines: (params: AdkProposal["params"], network: string) => import("./adk-owner-link.js").AdkParamLine[];
    }>;
    /**
     * What the SDK's owner workflows read from Stellar and check with its keys: transaction records, the record of an
     * expired step, the Native wallet's setup and the owner's approval. The SDK holds the workflows and their journal.
     */
    ownerChain: import("@allowit/core").OwnerChain;
    test: Readonly<{
        network: "stellar:testnet";
        skips: Readonly<Partial<Record<Feature, string>>>;
        fixtures: Readonly<{
            address: "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";
            /** Two more accounts, each distinct from `address`, for a test that needs several roles, such as a wallet setup. */
            accounts: readonly string[];
            invalidAddress: "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA6";
            txHash: string;
            asset: "USDC";
        }>;
    }>;
}>;
export default plugin;
