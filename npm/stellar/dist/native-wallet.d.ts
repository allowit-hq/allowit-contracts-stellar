/**
 * The Native wallet of an agent: a new classic account, one for each agent. The owner creates and funds it with one
 * signed transaction. The wallet holds one asset: XLM, or an issued asset whose trustline the same transaction adds.
 * That transaction also sets its signers: the owner alone reaches every threshold, and the agent
 * key and the server pay from it only together. The account's own key is random, signs the creation once and then
 * has weight 0. The agent holds a key and no account.
 *
 * This module builds the setup from the owner's own sequence, reads and sends the signed bytes, and returns the
 * installation document that the server registers. The SDK's owner workflow keeps the signed setup and decides when to
 * send it again or replace it. The server takes no part in the setup.
 */
import { type Transaction } from '@stellar/stellar-sdk/base';
import type { ReviewedPolicy, WalletAsset } from '@allowit/core';
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
/** What the network locks in a wallet account that holds XLM, in stroops: the account and its three signers. */
export declare const WALLET_RESERVE: bigint;
/** What the network locks for the trustline of a wallet that holds an issued asset, in stroops. */
export declare const TRUSTLINE_RESERVE = 5000000n;
/** The XLM that a new wallet holds above its reserve and its funding, in stroops. It pays the fees of the owner's own steps. */
export declare const WALLET_FEE_FLOAT = 5000000n;
/**
 * The asset that a wallet holds, by its code and its issuer: Core's `WalletAsset`, under the name of this rail's
 * wallet. XLM has no issuer. A policy names its asset this way, and the server's template of a network decides it.
 * This module validates it as a Stellar asset and converts it.
 */
export type NativeWalletAsset = WalletAsset;
/**
 * The XLM that a new wallet starts with, in stroops. A wallet that holds XLM starts with its reserve, its fee float and
 * the owner's funding. A wallet that holds an issued asset (`issued`) starts with its reserve, the reserve of its
 * trustline and its fee float: its funding is a payment of that asset.
 */
export declare function walletStartingBalance(funding: bigint, issued?: boolean): bigint;
/**
 * The installation document of a wallet account, as the server registers it. It is the document of the rail's own
 * setup: the same identity, the bootstrap source and the wallet's asset, which is `asset` or XLM. The server reads the
 * roles from the ledger and refuses a document that the account does not match.
 */
export declare function nativeWalletConfiguration(network: string, wallet: string, owner: string, agent: string, server: string, asset?: NativeWalletAsset | null | undefined): Record<string, unknown>;
/**
 * The terms of one wallet setup. `sequence` is the owner's current account sequence, and `expiresAt` a Unix time.
 * `funding` is in base units of the wallet's asset, which is `asset` or XLM.
 */
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
    asset?: NativeWalletAsset | null | undefined;
}
/**
 * The setup transaction of a wallet account. Its operations are one atomic unit: the creation with the starting
 * balance, the owner signer, the agent signer, and last the server signer with the thresholds and weight 0 for the
 * account's own key. A wallet that holds an issued asset adds its trustline after the creation, and the owner's
 * account then pays the funding in that asset. The owner's account is the source and pays the fee.
 */
export declare function nativeSetupTransaction(terms: NativeSetupTerms): Transaction;
/**
 * What a setup transaction does, read from its bytes: the wallet account that it creates, its roles, its XLM starting
 * balance, the asset that it holds and the funding in that asset. Null for any other transaction. The bytes are a
 * setup only when the setup builder makes exactly them from what was read: the same operations in the same encoding,
 * the same fee, sequence, memo and time bound, and nothing else. So a transaction that lacks an operation, adds
 * another, names another signer weight, threshold, source, destination, asset or balance, bids another fee or
 * carries another condition or extension is no setup.
 */
export interface NativeSetupFacts {
    owner: string;
    wallet: string;
    agent: string;
    server: string;
    /** The XLM that the owner's account sends at the creation, in stroops. */
    startingBalance: bigint;
    /** The asset that the wallet holds. */
    asset: NativeWalletAsset;
    /** The owner's funding for the agent's payments, in base units of `asset`. */
    funding: bigint;
}
export declare function nativeSetupOf(payload: string, network: string): NativeSetupFacts | null;
/** The roles and funding of a Native wallet account's setup. */
export interface NativeSetupInput {
    network: string;
    /** The owner's account. It pays for the setup and signs it. */
    owner: string;
    /** The agent's public key. */
    agent: string;
    /** The server's signer account. */
    server: string;
    /** The amount of the wallet's asset that the wallet holds for the agent's payments, as decimal text with at most seven decimals. */
    amount: string;
    /** The asset that the wallet holds, from the policy that the owner reviewed. Without one the wallet holds XLM. */
    asset?: NativeWalletAsset | null | undefined;
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
/**
 * Prepares the setup of the wallet account of an agent: one transaction from the owner's own sequence. The account's
 * own key is random; it signs the creation once, beside the owner, in `complete`.
 */
export declare function prepareNativeSetup({ network, owner, agent, server, amount, asset, fetch: send }: NativeSetupInput): Promise<PreparedNativeSetup>;
/**
 * What signed setup bytes are: their hash, their roles, the asset of their wallet, the amount of that asset that they
 * fund it with, as decimal text, and their own time bound. Null for bytes that are no setup of this network. The
 * signed bytes decide; saved metadata is unsigned.
 */
export declare function signedNativeSetupOf(signedPayload: string, network: string): {
    hash: string;
    owner: string;
    wallet: string;
    agent: string;
    server: string;
    validUntil: number;
    asset: NativeWalletAsset;
    amount: string;
} | null;
/**
 * Checks the asset of a Native wallet's bytes against `asset`, the asset of the reviewed policy, or XLM without one:
 * Core's `keypairSetup.checkAsset`. `payload` is signed setup bytes, which must set up a wallet of that asset, or the
 * funding step that the server prepared, which must pay the wallet in it. Throws an error whose `code` is
 * `asset_mismatch` otherwise, for a payload that is neither, and when `asset` is no Stellar asset.
 */
export declare function checkNativeAsset(payload: string, network: string, asset?: NativeWalletAsset | null | undefined): void;
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
 * The policy that the owner reviewed before an approval is Core's `ReviewedPolicy`: its exact source and every value,
 * its ordered rules and its tier when the host states them, and the asset that it pays in, which is XLM without one.
 */
export type { ReviewedPolicy };
/**
 * Whether a policy approval of `wallet` is exactly what the owner reviewed. Every field that the wallet signs is
 * checked: the policy and its revision come from the service; the source, rules, values and tier must be the
 * reviewed ones; the network, wallet, route, asset and fee ceiling must be the wallet account's own configuration,
 * as its setup made it for the asset of the reviewed policy. The server's digests of the source and the name of its
 * installation are left to the server. Any other field, or any other value, is refused, and so is a reviewed policy
 * whose asset is no asset.
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
