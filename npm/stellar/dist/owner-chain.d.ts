import { expiredRecord } from './chain-record.js';
import { nativeWalletConfiguration, prepareNativeSetup, signedNativeSetupOf, type PolicyApproval, type ReviewedPolicy } from './native-wallet.js';
/** What history holds for a transaction: `'missing'`, its record, or null when the read gave no clear answer. */
export type TransactionRecord = 'missing' | {
    hash: string;
    ledger: number;
    successful: boolean;
} | null;
/** The record of a transaction in the public ledger history. */
declare function transaction(network: string, hash: string): Promise<TransactionRecord>;
/** The owner of a wallet account: its one signer of the owner's weight, read from the public ledger, or null. */
declare function walletOwner(network: string, account: string): Promise<string | null>;
/** Whether `signature` is the signature of `signer` over the hexadecimal digest of an approval step. */
declare function signedBy(signer: string, hash: string, signature: number[]): boolean;
/** The hooks of the SDK's owner workflows. */
export declare const ownerChain: Readonly<{
    transaction: typeof transaction;
    /** Its ledger when the signed step applied before its time bound, null when it can never apply; throws when unknown. */
    expiredRecord: typeof expiredRecord;
    /**
     * A Native wallet account: one owner signature creates and funds it. The SDK keeps the signed setup in its journal
     * and decides when to send it again or replace it; these steps only build, read and send Stellar transactions.
     */
    keypairSetup: Readonly<{
        prepare: typeof prepareNativeSetup;
        read: typeof signedNativeSetupOf;
        send: (network: string, signedPayload: string, hash: string) => Promise<number | null>;
        configuration: typeof nativeWalletConfiguration;
    }>;
    /** The owner's approval of a Native policy: one message signature, and no transaction. */
    approval: Readonly<{
        read: (message: unknown, network: string) => PolicyApproval | null;
        holds: (fields: PolicyApproval, wallet: string, reviewed: ReviewedPolicy) => boolean;
        step: (message: string) => {
            action: string;
            payload: string;
            hash: string;
            expiresAt: number;
        };
        walletOwner: typeof walletOwner;
        signedBy: typeof signedBy;
    }>;
}>;
export {};
