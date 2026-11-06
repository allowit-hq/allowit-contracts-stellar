import { Transaction } from '@stellar/stellar-sdk/base';
export { STELLAR_OWNER_FRAGMENT } from './stellar-fragments.js';
export declare const STELLAR_OWNER_PROFILE = "allowit-stellar-owner-v1";
export interface StellarOwnerIntent {
    version: 1;
    profile: typeof STELLAR_OWNER_PROFILE;
    requestId: string;
    network: 'stellar:testnet';
    owner: string;
    agent: string;
    engine: string;
    sequence: string;
    feeStroops: number;
    expiresAt: number;
    transactionXdr: string;
    transactionHash: string;
    intentDigest: string;
}
export declare const stellarOwnerDigest: (v: StellarOwnerIntent) => string;
export declare function decodePublicFragment(fragment: string, prefix: string): unknown;
export declare function nativeSetupTransaction(v: StellarOwnerIntent): Transaction;
export declare function checkStellarOwnerIntent(v: unknown): asserts v is StellarOwnerIntent;
export declare function parseStellarOwnerIntent(fragment: string): StellarOwnerIntent;
export declare function checkStellarEngineIdentity(v: StellarOwnerIntent, config: unknown): void;
export declare function verifyStellarOwnerSignature(v: StellarOwnerIntent, signed: string): void;
export interface OwnerRecord {
    intent: StellarOwnerIntent;
    signedXdr?: string;
    status: 'unsigned' | 'unknown' | 'confirmed' | 'failed';
    ledger?: number;
}
export type OwnerTransport = (path: string, init?: RequestInit) => Promise<Response>;
export declare const stellarOwnerTransport: OwnerTransport;
/** The SDK issues 300 s links; 30 s more absorbs browser and CLI clock skew. Signed proofs stay recoverable after expiry. */
export declare const STELLAR_OWNER_UNSIGNED_WINDOW = 330;
/** An unsigned entry carries no authority. Only one inside its admissible window reserves the owner sequence. */
export declare const unsignedStellarOwnerOpen: (v: StellarOwnerIntent, now?: number) => boolean;
/** Unsigned admissibility only. A too-far expiry is reported apart from an expired one; it usually means a wrong clock. */
export declare function checkUnsignedStellarOwnerWindow(v: StellarOwnerIntent, now?: number): void;
/** Verify current native authority immediately before requesting a wallet signature. */
export declare function verifyFreshStellarOwner(v: StellarOwnerIntent, transport?: OwnerTransport, now?: number): Promise<void>;
/** A receipt must name the exact original hash, owner bytes and result. Unknown status retains its signed proof. */
export declare function stellarOwnerStatus(record: OwnerRecord, transport?: OwnerTransport): Promise<OwnerRecord>;
/** Broadcast only the exact retained native envelope. Callers own retention and recovery sequencing. */
export declare function broadcastStellarOwner(record: OwnerRecord, transport?: OwnerTransport): Promise<void>;
export declare function decodeStellarOwnerRecord(raw: string, v: StellarOwnerIntent): OwnerRecord;
export declare function stellarOwnerSupersessionProof(prior: OwnerRecord, next: StellarOwnerIntent, transport?: OwnerTransport): Promise<unknown | null>;
