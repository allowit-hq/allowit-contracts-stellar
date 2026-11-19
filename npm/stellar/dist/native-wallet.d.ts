/**
 * The Native wallet of an agent: a new classic account, one for each agent. The owner creates and funds it with one
 * signed transaction. That transaction also sets its signers: the owner alone reaches every threshold, and the agent
 * key and the server pay from it only together. The account's own key is random, signs the creation once and then
 * has weight 0. The agent holds a key and no account.
 *
 * This module builds the setup from the owner's own sequence, reads and sends the signed bytes, and returns the
 * installation document that the server registers. The SDK's owner workflow keeps the signed setup and decides when to
 * send it again or replace it. The server takes no part in the setup.
 */
import { type Transaction } from '@stellar/stellar-sdk/base';
/** The action of the owner step that creates the agent's wallet account. */
export declare const SET_UP_WALLET = "set_up_wallet";
/**
 * The action of the owner step that approves the policy of a wallet account. It signs a message and moves nothing.
 * Its payload is the base64 text of the message, as UTF-8, and its hash is the SEP-53 digest of the message.
 */
export declare const APPROVE_POLICY = "approve_policy";
/** The typed refusal of a deployment whose policy needs the wallet account of its agent. `details` names the roles. */
export declare const WALLET_SETUP_REQUIRED = "wallet_setup_required";
/** The weight of the owner signer: every threshold, alone. */
export declare const OWNER_WEIGHT = 3;
/** The weight of the agent signer and of the server signer. */
export declare const AUTOMATED_WEIGHT = 1;
/** The low and medium thresholds: the agent and the server together. */
export declare const PAYMENT_THRESHOLD = 2;
/** The high threshold: the owner alone. */
export declare const OWNER_THRESHOLD = 3;
/** What the network locks in a wallet account, in stroops: the account and its three signers. */
export declare const WALLET_RESERVE: bigint;
/** The XLM that a new wallet holds above its reserve and its funding, in stroops. It pays the fees of the owner's own steps. */
export declare const WALLET_FEE_FLOAT = 5000000n;
/** The balance that a new wallet starts with, in stroops: its reserve, its fee float and the owner's funding. */
export declare function walletStartingBalance(funding: bigint): bigint;
/**
 * The installation document of a wallet account, as the server registers it. It is the document of the rail's own
 * setup: the same identity, the bootstrap source and the native asset. The server reads the roles from the ledger
 * and refuses a document that the account does not match.
 */
export declare function nativeWalletConfiguration(network: string, wallet: string, owner: string, agent: string, server: string): Record<string, unknown>;
/** The terms of one wallet setup. `sequence` is the owner's current account sequence, and `expiresAt` a Unix time. */
export interface NativeSetupTerms {
    network: string;
    owner: string;
    sequence: string;
    wallet: string;
    agent: string;
    server: string;
    funding: bigint;
    requestId: string;
    expiresAt: number;
}
/**
 * The setup transaction of a wallet account. Its operations are one atomic unit: the creation with the starting
 * balance, the owner signer, the agent signer, and last the server signer with the thresholds and weight 0 for the
 * account's own key. The owner's account is the source and pays the fee.
 */
export declare function nativeSetupTransaction({ network, owner, sequence, wallet, agent, server, funding, requestId, expiresAt }: NativeSetupTerms): Transaction;
/**
 * What a setup transaction does, read from its bytes: the wallet account that it creates, its roles and its
 * starting balance. Null for any other transaction: one that lacks an operation, adds another, names another
 * signer weight or threshold, or leaves the account's own key a weight.
 */
export declare function nativeSetupOf(payload: string, network: string): {
    owner: string;
    wallet: string;
    agent: string;
    server: string;
    startingBalance: bigint;
} | null;
/**
 * A setup that the owner's account cannot pay for, found before any signature. `code` is the typed code of the
 * refusal, whose title is in Allowit's error catalogue; the message says what happened and what the owner does next.
 */
export declare class SetupRefusal extends Error {
    readonly code: 'owner_account_unfunded' | 'owner_balance_low';
    constructor(code: 'owner_account_unfunded' | 'owner_balance_low', message: string);
}
/** The whole fee of the setup transaction, in stroops: the owner's account pays it. The owner's approval that follows is a message signature and costs nothing. */
export declare const NATIVE_SETUP_FEE: bigint;
/**
 * What an account can spend now, in stroops: its XLM above its own reserve and its selling liabilities. Null when the
 * account record lacks one of the fields that the reserve and the liabilities need: a partial record could refuse an
 * owner who can pay, or pass one who cannot, so the caller stops as for a failed read.
 */
export declare function spendableXlm(account: Record<string, unknown>): bigint | null;
/** The roles and funding of a Native wallet account's setup. */
export interface NativeSetupInput {
    network: string;
    /** The owner's account. It pays for the setup and signs it. */
    owner: string;
    /** The agent's public key. */
    agent: string;
    /** The server's signer account. */
    server: string;
    /** The XLM that the wallet holds for the agent's payments, as decimal text with at most seven decimals. */
    amount: string;
    fetch?: typeof fetch;
}
/** A setup prepared for the owner's signature. */
export interface PreparedNativeSetup {
    /** The account that the setup creates. */
    wallet: string;
    /** The step that the owner's wallet signs: the exact setup transaction. */
    step: {
        action: string;
        payload: string;
        hash: string;
        expiresAt: number;
    };
    /**
     * Checks that `ownerSigned` is this transaction with the owner's one signature, and adds the new account's own
     * signature. Returns the signed bytes to send. The account's key lives in this object only and is never stored.
     */
    complete(ownerSigned: string): string;
}
export declare function prepareNativeSetup({ network, owner, agent, server, amount, fetch: send }: NativeSetupInput): Promise<PreparedNativeSetup>;
/**
 * What signed setup bytes are: their hash, their roles and their own time bound. Null for bytes that are no setup of
 * this network. The signed bytes decide; saved metadata is unsigned.
 */
export declare function signedNativeSetupOf(signedPayload: string, network: string): {
    hash: string;
    owner: string;
    wallet: string;
    agent: string;
    server: string;
    validUntil: number;
} | null;
/** Sends signed setup bytes to Horizon. The ledger of the successful transaction, or null without a certain answer. */
export declare function sendNativeSetup(network: string, signedPayload: string, hash: string, send?: typeof fetch): Promise<number | null>;
/** The SEP-53 digest of a wallet message, as lowercase hexadecimal. */
export declare function messageDigest(message: string): string;
/** What a policy approval message approves: the policy and its revision, the wallet account, the source and the values. */
export interface PolicyApproval {
    policyId: string;
    revision: number;
    network: string;
    wallet: string;
    source: string;
    sourceHash: string;
    paramsHash: string;
    /** Every value that the owner approves, by param. */
    params: Record<string, unknown>;
    /** The ordered rules of the policy, as the message states them. */
    rules: unknown;
    /** Every field of the message, as the owner's wallet signs it. */
    fields: Record<string, unknown>;
}
/**
 * Reads the exact text of a policy approval of `network`: its title line, then the canonical JSON of the approval.
 * Any other text is null: another title, a text that is not the canonical form of its own content, another
 * network or route, or a source or values whose hash differs from the hash that the message states.
 */
export declare function policyApproval(message: unknown, network: string): PolicyApproval | null;
/**
 * The policy that the owner reviewed before an approval: its exact source and every value. Its ordered rules and its
 * tier, which the service derives from the source, are checked too when the host states them.
 */
export interface ReviewedPolicy {
    source: string;
    params: Record<string, unknown>;
    rules?: unknown;
    tier?: unknown;
}
/**
 * Whether a policy approval of `wallet` is exactly what the owner reviewed. Every field that the wallet signs is
 * checked: the policy and its revision come from the service; the source, rules, values and tier must be the
 * reviewed ones; the network, wallet, route, asset and fee ceiling must be the wallet account's own configuration,
 * as its setup made it. The server's digests of the source and the name of its installation are left to the server.
 * Any other field, or any other value, is refused.
 */
export declare function nativeApprovalHolds(approval: PolicyApproval, wallet: string, reviewed: ReviewedPolicy): boolean;
/** The step that asks the owner's wallet to approve a policy. It signs the message and moves nothing. */
export declare function approvalStep(message: string, now?: number): {
    action: string;
    payload: string;
    hash: string;
    expiresAt: number;
};
/** The message of an approval step, or null when the payload is no UTF-8 text or differs from the step's hash. */
export declare function approvalMessage(step: {
    payload: string;
    hash: string;
}): string | null;
