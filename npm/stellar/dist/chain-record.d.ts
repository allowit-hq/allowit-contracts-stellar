/** The Horizon origin of a network, or null. */
export declare const horizonOrigin: (network: string) => string | null;
/** A read of the public ledger history. A failed or stalled read is null. */
export declare function horizonGet(network: string, path: string, send?: typeof fetch): Promise<Response | null>;
/** The chain could not be read, or its answer proves nothing: the signed bytes stay saved. */
export declare class ChainUnchecked extends Error {
    constructor();
}
/**
 * What the chain holds for a signed transaction past its time bound: its ledger when it applied, or null when it
 * can never apply. Expiry stops a later application, not an earlier one, so a missing record alone proves nothing.
 * The time bound is the maximum time of the signed transaction itself; a transaction without one never expires.
 * The transaction never applied only when Horizon has read past the time bound and either holds the failed
 * transaction or holds none while the source account sequence is still below the transaction's sequence.
 * Anything else throws `ChainUnchecked`.
 */
export declare function expiredRecord(network: string, hash: string, signedPayload: string, send?: typeof fetch): Promise<{
    ledger: number;
} | null>;
