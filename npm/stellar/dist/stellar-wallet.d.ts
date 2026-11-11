export interface Session {
    address: string;
    network: string;
    expiresAt: string;
}
import { STELLAR_NETWORKS, stellarAccountKey, stellarAssetContractId, type StellarNetwork } from './stellar-asset.js';
export { STELLAR_NETWORKS, stellarAccountKey, stellarAssetContractId, type StellarNetwork };
/** SEP-53 signs the prefixed digest. It never signs a transaction or authorizes spending. */
export declare function stellarMessageDigest(message: string): Uint8Array;
export declare function freighterAvailable(): Promise<boolean>;
export interface StellarSignInChallenge {
    id: string;
    message: string;
    address: string;
    origin: string;
    expiresAt: string;
}
/** Bind the exact sign-in purpose, account, Origin and nonce. The caller admits timestamp freshness. */
export declare function stellarSignInChallengeTimes(challenge: StellarSignInChallenge, owner: string, origin: string): {
    issuedAt: number;
    expiresAt: number;
};
/** A native wallet capability. HTTP sessions and their admission stay with the app. */
export declare function connectStellarWallet(network: StellarNetwork, admitTimes: (times: {
    issuedAt: number;
    expiresAt: number;
}) => boolean, signal?: AbortSignal): Promise<{
    address: string;
    network: 'wallet';
    validateChallenge(challenge: StellarSignInChallenge): void;
    signMessage(message: string): Promise<string>;
}>;
/**
 * Freighter signs only. Returned bytes are the authority: an optional retain hook receives bounded bytes before the
 * provider error, signer metadata or any further wallet or network await, so a valid proof survives stale metadata or a
 * failed post-sign check. The hook rejects altered bytes. Any metadata error still rejects. Nothing is broadcast here.
 */
export declare function signStellarTransaction(transactionXdr: string, owner: string, network: StellarNetwork, retain?: (signedXdr: string) => void | Promise<void>): Promise<string>;
export declare function watchStellarAccount(owner: string, changed: () => void): () => void;
export declare const canonicalApprovalJson: (value: unknown) => string;
/** The owner approves an exact Native source against current account administration authority. */
export declare function signStellarSourceApproval(approval: {
    payload: Record<string, unknown>;
    message: string;
    method: string;
}, policy: {
    id: string;
    revision: number;
    language?: string;
    network?: string;
    sourceHash?: string;
    irHash?: string;
    code?: string;
    mint?: string;
    token?: string;
    runtime?: {
        instanceBinding?: Record<string, unknown>;
    };
}, session: Session, stillCurrent?: () => boolean): Promise<{
    signer: string;
    signature: number[];
}[]>;
