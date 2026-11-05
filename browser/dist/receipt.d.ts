export interface StellarOperationReceipt {
    chain: 'stellar';
    network: 'stellar:testnet' | 'stellar:mainnet' | 'stellar:pubnet';
    signature: string;
    requestHash: string;
    invocationIndex: 0;
    finalizedLedger: string;
    result: 'success' | 'failed';
    action: {
        type: 'stellar-transfer';
        amountUnits: string;
        asset: string;
        recipient: string;
    };
}
export declare const isStellarReceipt: (value: {
    chain?: unknown;
}) => boolean;
export declare function parseStellarReceipt(q: Record<string, unknown>, field: string, u64: (value: unknown, field: string) => string, fail: (field: string, what?: string) => Error): StellarOperationReceipt;
/** Native receipt projection. It grants no settlement authority beyond the admitted receipt. */
export declare function stellarTransfer(receipt: {
    action: unknown;
}): {
    units: string;
    recipient: string;
} | null;
export declare const stellarReceiptSucceeded: (receipt: {
    action: unknown;
    result?: unknown;
}) => boolean;
export declare const stellarReceiptFailed: (receipt: {
    chain?: unknown;
    result?: unknown;
    action?: unknown;
}) => boolean;
export declare const stellarReceiptIdentityMismatch: (receipt: {
    chain?: unknown;
    requestHash: string;
    signature: string;
}, request: {
    requestHash?: string;
    signature?: string;
}) => boolean;
export declare const stellarReceiptHeight: (receipt: {
    chain?: unknown;
    finalizedLedger?: string;
    finalizedSlot?: string;
}) => {
    label: string;
    value: string | undefined;
} | null;
