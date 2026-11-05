import { type PortableAdmission } from './portable-export.js';
export interface ApprovalPolicy {
    id: string;
    revision: number;
    network: string;
    code: string;
    sourceHash: string;
    irHash: string;
    mint: string;
    token: string;
    runtime?: {
        wallet: {
            profile: string;
        };
        instanceBinding?: Record<string, unknown>;
    };
}
export { STELLAR_APPROVAL_FRAGMENT } from './stellar-fragments.js';
export interface ApprovalBinding {
    wallet: string;
    route: 'native';
    policyInstance: string;
    moduleDigest: string;
    asset: string;
    assetSymbol: string;
    assetIssuer: string | null;
    maxFeeStroops: number;
    deploymentId: string | null;
    language?: string;
    tier?: string;
    rules?: string[];
    params?: Record<string, unknown>;
    paramsHash?: string;
}
export interface StellarApprovalIntent {
    version: 1 | 2;
    profile: 'allowit-stellar-approval-v1' | 'allowit-stellar-approval-v2';
    requestId: string;
    network: 'stellar:testnet';
    owner: string;
    policyId: string;
    revision: number;
    source: string;
    sourceHash: string;
    irHash: string;
    binding: ApprovalBinding;
    intentDigest: string;
}
export declare const stellarApprovalDigest: (v: StellarApprovalIntent) => string;
export declare function parseStellarApprovalIntent(fragment: string): StellarApprovalIntent;
/** Only the original owner-stored policy can continue. Handoff source never creates or replaces policy. */
export declare function matchStellarApproval<P extends ApprovalPolicy>(v: StellarApprovalIntent, policy: P | undefined, owner: string, network: string): P;
/** Rebuilds the export from checked public fields only. Unexpected response fields never reach the file. */
export declare function publicStellarBundle(value: unknown, policy: ApprovalPolicy, owner: string, service: unknown, admit: PortableAdmission): {
    version: number;
    profile: string;
    network: string;
    policyId: string;
    sourceHash: string;
    irHash: string;
    moduleDigest: string;
    wallet: unknown;
    route: string;
    config: {
        asset: string;
        assetSymbol: string;
        assetIssuer: {} | null;
        policySource: string;
        sourceHash: number[];
        moduleDigest: number[];
        maxFeeStroops: unknown;
        network: string;
        policyInstance: number[];
        wallet: unknown;
        owner: string;
        agent: string;
        server: string;
        route: string;
    };
    endpoints: {
        execute: string;
        status: string;
    };
};
