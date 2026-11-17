/**
 * The Native wallet of an agent: a new classic account, one for each agent. The owner creates and funds it with one
 * signed transaction. That transaction also sets its signers: the owner alone reaches every threshold, and the agent
 * key and the server pay from it only together. The account's own key is random, signs the creation once and then
 * has weight 0. The agent holds a key and no account.
 *
 * This module builds the setup from the owner's own sequence, sends the signed bytes to the public network itself
 * and returns the installation document that the server registers. The server takes no part in the setup.
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
export interface SetupJournal {
    get(key: string): string | null;
    set(key: string, value: string): void;
    remove(key: string): void;
}
export interface NativeWalletSetupInput {
    network: string;
    /** The owner's account. It pays for the setup and signs it. */
    owner: string;
    /** The agent's public key. */
    agent: string;
    /** The server's signer account. */
    server: string;
    /** The XLM that the wallet holds for the agent's payments, as decimal text with at most seven decimals. */
    amount: string;
    /** Shows the setup in the `owner-sign` element and resolves with the exact signed payload. */
    sign: (step: {
        action: string;
        payload: string;
        hash: string;
        expiresAt: number;
    }) => Promise<string>;
    onStep: (text: string) => void;
    /** Keeps the signed setup until the network settles it, so an uncertain send never creates a second wallet. */
    journal: SetupJournal;
    /** The journal key of this wallet setup. */
    key: string;
    /**
     * Keeps the signed setup in the journal after the network confirmed it. The caller removes it when the server
     * has registered the wallet, so a run that stops in between finds the same wallet again and creates no second one.
     */
    retain?: boolean;
    fetch?: typeof fetch;
}
/** A wallet account that the network holds, with its installation document for the server. */
export interface NativeWalletSetup {
    wallet: string;
    transactionHash: string;
    ledger: number;
    configuration: Record<string, unknown>;
}
/** An uncertain setup: the signed transaction stays saved, and the next call settles it before it signs anything. */
export declare class WalletSetupPendingError extends Error {
    readonly retry = true;
    constructor(message: string, cause?: unknown);
}
/**
 * Sets up the wallet account of an agent: one transaction that the owner's wallet signs. The account's own key is
 * random and lives in this call only; it signs the creation once, beside the owner.
 *
 * The signed bytes are saved before they are sent. A send whose result is unknown keeps them, and the next call
 * settles that setup first: it is done when the network holds it as successful, it is sent again while its time
 * bound lasts, and it is dropped only when the network holds it as failed or has read past its time bound without
 * it. Only then is a new setup prepared, so one call never creates two wallets. A setup that stopped before the
 * owner signed names a new account on its next run: nothing was signed for the earlier one.
 */
export declare function setUpNativeWallet(input: NativeWalletSetupInput): Promise<NativeWalletSetup>;
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
}
/**
 * Reads the exact text of a policy approval of `network`: its title line, then the canonical JSON of the approval.
 * Any other text is null: another title, a text that is not the canonical form of its own content, another
 * network or route, or a source whose hash differs from the hash that the message states.
 */
export declare function policyApproval(message: unknown, network: string): PolicyApproval | null;
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
