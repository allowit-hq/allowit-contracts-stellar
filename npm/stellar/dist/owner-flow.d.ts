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
    /** The network of the policy. */
    network: string;
    /** Milliseconds between reads of a transaction that history does not hold yet. The default is 1500. */
    historyPauseMs?: number;
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
/** The transaction is in a ledger and failed. `details.ledger` names that ledger. */
export declare const OWNER_TRANSACTION_FAILED = "owner_transaction_failed";
/** HTTP 503 with `details.retry = "same_request_id"`: the service sent nothing. */
export declare const NETWORK_UNAVAILABLE = "network_unavailable";
/** Typed codes of a refused params update. `details.param` names the param of a refused value. */
export declare const PARAM_INVALID = "param_invalid";
export declare const PARAM_OUT_OF_RANGE = "param_out_of_range";
/** The policy is not active, or its wallet kind takes no owner-signed update. */
export declare const UPDATE_UNAVAILABLE = "update_unavailable";
/** The wallet is at another configuration revision than the update expects. */
export declare const REVISION_CHANGED = "revision_changed";
/** The action name of the owner step of a params update. */
export declare const UPDATE_PARAMS = "update_params";
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
 * - confirmed, or `owner_transaction_settled` for the same hash: the step is done once the chain holds that
 *   successful transaction. Until then it stays saved and the error has `retry` set;
 * - `owner_transaction_expired`: the chain decides. When the transaction applied before its time bound, the step is
 *   done. When the chain proves that it never applied, its signed bytes move to the archive key and the owner signs
 *   a new step. When the chain cannot be read, the step stays saved and the error has `retry` set;
 * - `owner_transaction_failed`: when the chain holds that failed transaction, its signed bytes move to the archive
 *   key and the owner signs a new step;
 * - `owner_transaction_pending` or `network_unavailable`: the step stays saved and the error has `retry` set.
 * Any other failure keeps the saved step, so no second signature exists while the first can still apply.
 * A saved step and the funded marker name the policy, agent key and amount. A resume with other inputs is refused.
 * One workflow runs per journal key: a second call in this page or, where the browser has Web Locks, in another tab
 * is refused before it reads the journal.
 */
export declare function installAndFund(input: InstallAndFundInput): Promise<{
    wallet: string;
    receipts: OwnerReceipt[];
}>;
export interface UpdateParamsInput {
    /** The network of the policy. */
    network: string;
    /** Milliseconds between reads of a transaction that history does not hold yet. The default is 1500. */
    historyPauseMs?: number;
    /** One journal key per change: a confirmed change is never prepared or signed again under its key. */
    ask: Ask;
    sign: SignStep;
    journal: OwnerJournal;
    key: string;
    policyId: string;
    /** Each changed param with its complete new typed value, such as `{daily_spending_limit: {Int: '50000000'}}`. */
    params: Record<string, unknown>;
    /** The configuration revision that the owner reviewed, when the host shows one. */
    expectedRevision?: number;
    onStep: (text: string) => void;
}
/**
 * Change installed params on an active wallet with one owner signature. The service checks each value, prepares
 * the owner step and, when the network confirms it, saves the new params of the installation and of the policy in
 * one write. The wallet keeps its recorded usage and its request nonce.
 * The workflow resumes as `installAndFund` does: a saved signed step is settled first, an expired step that never
 * applied moves to the archive key, and the owner then signs a new step. A confirmed change is never prepared or
 * signed again under its journal key; `done` is then true and `receipts` is empty.
 * A refusal of the service keeps its typed code in `OwnerFlowError.code`: `param_invalid`, `param_out_of_range`,
 * `update_unavailable` or `revision_changed`, and the codes of a refused submission.
 */
export declare function updateParams(input: UpdateParamsInput): Promise<{
    receipts: OwnerReceipt[];
    done: boolean;
}>;
