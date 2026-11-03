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
export declare function submitSavedStellarOwner(record: OwnerRecord, transport?: OwnerTransport): Promise<OwnerRecord>;
export declare function ownerRecordKey(v: StellarOwnerIntent): string;
export declare function readOwnerRecord(v: StellarOwnerIntent, storage?: Storage): OwnerRecord | null;
export declare function saveOwnerRecord(record: OwnerRecord, storage?: Storage): void;
/**
 * Keeps a wallet-returned signature before any further wallet or network step. The verified proof reaches page memory,
 * then the caller, then the durable journal. A failed save keeps it in memory, sends nothing and still blocks another signature.
 */
export declare function retainStellarOwnerProof(v: StellarOwnerIntent, signedXdr: string, keep: (proof: OwnerRecord) => void, storage?: Storage): OwnerRecord;
/**
 * Signed proof for this exact request: the durable journal first, then one kept in memory after a failed save, by the
 * caller or by this page. A proof kept only in memory for another request blocks this one regardless of expiry or owner,
 * since replacing it would lose its only copy. Once that exact proof is durable, the per-owner admission scan reconciles
 * it before any new signature.
 */
export declare function heldStellarOwnerProof(v: StellarOwnerIntent, held: OwnerRecord | null, storage?: Storage): OwnerRecord | null;
/** Display recovery never lets an unsigned or unreadable journal entry hide a known signed proof. */
export declare function keptStellarOwnerRecord(v: StellarOwnerIntent, held: OwnerRecord | null, storage?: Storage): OwnerRecord | null;
/** Retry durably saves the same kept proof before any send. It never asks the wallet again. */
export declare function durableStellarOwnerProof(v: StellarOwnerIntent, held: OwnerRecord | null, storage?: Storage): OwnerRecord;
/** The raw per-owner Web Lock, without the admission scan. Callers that already hold it use the direct status functions. */
export declare function withRawStellarOwnerLock<T>(v: StellarOwnerIntent, run: () => Promise<T>): Promise<T>;
/** Opening or checking a link reads, looks up and saves inside the owner lock, so an older lookup never overwrites a newer one. */
export declare function observeStellarOwnerRecord(v: StellarOwnerIntent, held: OwnerRecord | null, transport?: OwnerTransport, storage?: Storage): Promise<OwnerRecord | null>;
/** Serialize signing across all tabs that share the same owner account sequence. Every earlier signed proof is looked up again; a saved terminal label is not chain evidence. */
export declare function withStellarOwnerLock<T>(v: StellarOwnerIntent, run: () => Promise<T>, transport?: OwnerTransport, storage?: Storage): Promise<T>;
