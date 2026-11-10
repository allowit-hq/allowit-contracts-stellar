import type { AdkProposal } from './adk-owner-link.js';
import { type AdkOwnerSelection, type AdkOwnerStep } from './owner-verifier.js';
import { type PortableAdmission, type PortablePolicy } from './portable-export.js';
import { type Session } from './stellar-wallet.js';
type Signed = {
    step: AdkOwnerStep;
    expected: AdkOwnerSelection;
    signedXdr: string;
    sent?: boolean;
};
type Journal = {
    agent: string;
    amount: string;
    wallet?: string;
    pending?: Signed;
    funded?: Signed;
};
export type AdkPolicy = PortablePolicy & {
    revision: number;
};
/**
 * Typed engine codes of `native/owner/submit` rejections. Each rejection carries
 * `details: {policyId, action, transactionHash}`; a failed one also carries `ledger`.
 */
export declare const OWNER_TRANSACTION_EXPIRED = "owner_transaction_expired";
export declare const OWNER_TRANSACTION_FAILED = "owner_transaction_failed";
/**
 * Capabilities that the consumer supplies. `request` is its authenticated REST transport; a rejection carries the
 * server `code` and `details`. `verifyInstallation` confirms the installed wallet with the owner. `admitPortableBuild`
 * is the common portable build admission.
 */
export interface AdkOwnerHost {
    request<T>(path: string, body?: unknown, options?: {
        expectedOwner?: string;
    }): Promise<T>;
    verifyInstallation(policy: AdkPolicy, session: Session & {
        network: 'wallet';
    }, current: () => boolean): Promise<void>;
    admitPortableBuild: PortableAdmission;
}
export declare function adkOwnerKey(owner: string, p: AdkProposal): string;
/** Signed bytes of an expired owner transaction, kept after the journal drops it. */
export declare function adkOwnerArchiveKey(owner: string, transactionHash: string): string;
export declare function readAdkOwnerJournal(key: string): Journal | null;
export declare function deployAdkOwnerDraft({ host, proposal, session, agent, amount, current, onStep, }: {
    host: AdkOwnerHost;
    proposal: AdkProposal;
    session: Session;
    agent: string;
    amount: string;
    current: () => boolean;
    onStep: (step: string) => void;
}): Promise<{
    policyId: string;
    wallet: string;
    publicProfile: string;
}>;
export {};
