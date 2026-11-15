/**
 * The fee account of a policy wallet: the account that sends the agent's operations on the wallet and pays their
 * network fees. The owner's deployment creates and funds it. It has the signers of a wallet account: the owner alone
 * reaches every threshold, and the agent key and the server pay from it only together. The agent holds no account.
 *
 * This module derives the account's one-time key from the owner's signature, reads the account from the public
 * ledger history and prepares the owner's refill. The server takes no part in the read or the refill.
 */
import { Keypair } from '@stellar/stellar-sdk/base';
/** The action of the step that signs the derivation message. Its payload is the base64 text of the message. */
export declare const DERIVE_FEE_ACCOUNT_KEY = "derive_fee_account_key";
/** The action of the owner step that creates the fee account. */
export declare const CREATE_FEE_ACCOUNT = "create_fee_account";
/** The action of the owner step that refills the fee account. */
export declare const REFILL_FEES = "refill_fees";
/** The typed refusal of a wallet creation that names no fee account. `details.wallet` is the policy wallet. */
export declare const FEE_ACCOUNT_REQUIRED = "fee_account_required";
/** The index of the first fee account of a policy wallet. */
export declare const FEE_ACCOUNT_INDEX = 0;
/** The SEP-53 digest of a wallet message, as lowercase hexadecimal. */
export declare function messageDigest(message: string): string;
/**
 * The message whose owner signature derives the one-time key of a fee account. It names the network, the agent,
 * the policy wallet and an index, so each policy wallet of one owner gets its own account and the owner can
 * compute the address again.
 */
export declare function feeAccountDerivationMessage(network: string, agent: string, wallet: string, index?: number): string;
/** The fields of a derivation message of `network`, or null for any other text. */
export declare function feeAccountDerivation(message: unknown, network: string): {
    agent: string;
    wallet: string;
    index: number;
} | null;
/** The step that asks the owner's wallet for the derivation signature. It signs a message and moves nothing. */
export declare function derivationStep(network: string, agent: string, wallet: string, now?: number): {
    action: string;
    payload: string;
    hash: string;
    expiresAt: number;
};
/** The one-time key of a fee account, from the owner's 64-byte signature over the derivation message. */
export declare function feeAccountKey(signature: Uint8Array): Keypair;
/**
 * Adds the one signature of the new account's own key to the owner-signed creation of a fee account. The signed
 * bytes must be the reviewed step, and its first operation must create exactly the account of `key`.
 */
export declare function countersignCreation(network: string, step: {
    hash: string;
}, signedPayload: string, key: Keypair): string;
/** The fee account that an installation, a wallet profile or a policy document names, or null. */
export declare function feeAccountOf(document: unknown): {
    address: string;
    maxFeeStroops: number | null;
} | null;
/** What the ledger holds for a fee account. Amounts are stroops as decimal text; `text` is the spendable XLM. */
export interface FeeAccountState {
    address: string;
    /** False when the ledger holds no such account: its owner closed it, or never created it. */
    exists: boolean;
    balance: string;
    /** The XLM above the reserve: what pays network fees. */
    spendable: string;
    /** True when less than two operations at the wallet's fee ceiling remain. */
    low: boolean;
    text: string;
    /** The refill that the page offers: the float of a new fee account, as a decimal amount and with its unit. */
    refill: {
        amount: string;
        text: string;
    };
}
/** Stroops of a decimal XLM amount with at most seven decimals, or null. */
export declare function stroops(amount: string): bigint | null;
/** XLM text of stroops, without trailing zeros. */
export declare function xlmText(units: bigint): string;
/**
 * Reads the fee account of `document` from the public ledger history. Null when the document names none: a Native
 * wallet pays its own fees, and a policy wallet of an earlier release has the agent's own account pay them.
 */
export declare function feeAccount(input: {
    network: string;
    document: unknown;
    fetch?: typeof fetch;
}): Promise<FeeAccountState | null>;
/** Storage for a signed refill until the network settles it. */
export interface RefillJournal {
    get(key: string): string | null;
    set(key: string, value: string): void;
    remove(key: string): void;
}
export interface RefillFeesInput {
    network: string;
    /** The owner's account: the source of the payment. */
    owner: string;
    /** The fee account that receives it. */
    feeAccount: string;
    /** XLM, as decimal text with at most seven decimals. */
    amount: string;
    /** Shows the payment in the `owner-sign` element and resolves with the exact signed payload. */
    sign: (step: {
        action: string;
        payload: string;
        hash: string;
        expiresAt: number;
    }) => Promise<string>;
    onStep: (text: string) => void;
    /** Keeps the signed payment until the network settles it, so an uncertain send never leads to a second payment. */
    journal?: RefillJournal;
    /** The journal key of this fee account's refill. */
    key?: string;
    fetch?: typeof fetch;
}
/** An uncertain refill: the signed payment stays saved, and the next call settles it before it signs anything. */
export declare class RefillPendingError extends Error {
    readonly retry = true;
    constructor(message: string, cause?: unknown);
}
/**
 * Refills a fee account: one payment of XLM from the owner's account, which the owner's wallet signs. This module
 * builds the payment from the owner's own sequence and sends the signed bytes to the public network itself.
 *
 * With a journal, the signed bytes are saved before they are sent. A send whose result is unknown keeps them, and
 * the next call settles that payment first: it is done when the network holds it as successful, it is sent again
 * while its time bound lasts, and it is dropped only when the network holds it as failed or has read past its time
 * bound without it. Only then is a new payment prepared, so one refill is never paid twice.
 */
export declare function refillFees(input: RefillFeesInput): Promise<{
    transactionHash: string;
    ledger: number;
}>;
