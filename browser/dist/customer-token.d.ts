import { type PortableAdmission } from './portable-export.js';
export declare function customerPublicKey(seedText: string): string;
/** Encode native keys from caller-owned entropy. The caller owns generation and secret retention. */
export declare function customerKeyFromEntropy(entropy: Uint8Array): {
    seed: string;
    publicKey: string;
};
export type PublicStellarBundle = {
    version: number;
    profile: string;
    network: string;
    policyId: string;
    sourceHash: string;
    irHash: string;
    language?: string;
    portable?: Record<string, unknown>;
    sourceApproval?: unknown;
    moduleDigest: string;
    wallet: string;
    route: 'native' | 'policyWallet';
    config: Record<string, unknown>;
    endpoints: {
        execute: string;
        status: string;
    };
};
export type TokenPolicy = {
    id: string;
    revision?: number;
    network: string;
    sourceHash: string;
    irHash: string;
    code: string;
    mint: string;
    token: string;
    runtime?: {
        instanceBinding?: Record<string, unknown>;
        authorization?: unknown;
    };
};
/** Local-only encoding. Never pass its return value to an API, storage, URL, or analytics. */
export declare function customerToken(bundle: PublicStellarBundle, seedText: string, policy: TokenPolicy, owner: string, service: unknown, admit: PortableAdmission): string;
