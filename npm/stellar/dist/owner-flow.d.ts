/**
 * The owner workflow that the SDK exposes through the rail plugin: install the reviewed policy wallet, then fund it.
 * The host supplies its authenticated transport, the signing of one step and a journal. This module holds the rules
 * for a saved signed step and for the typed replies of the service.
 */
/** Rail-neutral owner step. `payload` is opaque text that only this package signs and reads. */
export interface OwnerStep {
    action: string;
    payload: string;
    hash: string;
    expiresAt: number;
    explorer?: string | null;
}
/** The owner's authenticated transport. A rejection carries the server `code` and `details`. */
export type Ask = <T>(path: string, body?: unknown) => Promise<T>;
/** Shows one owner step in the `owner-sign` element and resolves with the exact signed payload. */
export type SignStep = (step: OwnerStep) => Promise<string>;
export interface OwnerJournal {
    get(key: string): string | null;
    set(key: string, value: string): void;
    remove(key: string): void;
}
export type OwnerReceipt = {
    policyId: string;
    action: string;
    status: string;
    transactionHash: string;
    ledger?: number;
};
export interface InstallAndFundInput {
    ask: Ask;
    sign: SignStep;
    journal: OwnerJournal;
    key: string;
    policyId: string;
    agent: string;
    amount: string;
    onStep: (text: string) => void;
}
/** Typed codes of a refused `native/owner/submit`. The reply body is `{error, code, details}`. */
export declare const OWNER_TRANSACTION_EXPIRED = "owner_transaction_expired";
export declare const OWNER_TRANSACTION_PENDING = "owner_transaction_pending";
export declare const OWNER_TRANSACTION_SETTLED = "owner_transaction_settled";
/** HTTP 503 with `details.retry = "same_request_id"`: the service sent nothing. */
export declare const NETWORK_UNAVAILABLE = "network_unavailable";
/** An owner workflow failure with the typed server code, when the service sent one. */
export declare class OwnerFlowError extends Error {
    readonly code: string | null;
    /** True when the same saved step can be sent again without a new signature. */
    readonly retry: boolean;
    constructor(message: string, code: string | null, retry: boolean, cause?: unknown);
}
/** The key that keeps the signed bytes of an expired step after the journal drops it. */
export declare function ownerArchiveKey(key: string, hash: string): string;
/**
 * Install the reviewed policy wallet, then fund it. The service prepares each owner step and the host signs it.
 * Signed bytes enter the journal before they are sent, so a reload sends the same signature and never signs a step
 * twice. A saved step is settled first:
 * - confirmed, or `owner_transaction_settled` for the same hash: the step is done;
 * - `owner_transaction_expired`: the step can never apply. Its signed bytes move to the archive key and the owner
 *   signs a new step;
 * - `owner_transaction_pending` or `network_unavailable`: the step stays saved and the error has `retry` set.
 * Any other failure keeps the saved step, so no second signature exists while the first can still apply.
 */
export declare function installAndFund({ ask, sign, journal, key, policyId, agent, amount, onStep }: InstallAndFundInput): Promise<{
    wallet: string;
    receipts: OwnerReceipt[];
}>;
