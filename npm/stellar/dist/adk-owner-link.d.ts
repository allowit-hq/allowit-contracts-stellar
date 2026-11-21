export { ADK_OWNER_FRAGMENT } from './stellar-fragments.js';
/** An asset that the rail lists for a network: its contract, its code and its decimals. */
export type ListedAsset = {
    id: string;
    symbol: string;
    decimals: number;
};
export type AdkProposal = {
    /** A canonical network id of the rail's registry ([`NETWORKS`]). */
    network: string;
    revision: number;
    title: string;
    explanation: string;
    code: string;
    sourceHash: string;
    paramsHash: string;
    params: Record<string, unknown>;
};
export type AdkOwnerLink = {
    proposal: AdkProposal;
    workPrompt: string;
};
/** The prompt that the owner gives the agent after signing, for a policy on `network`. */
export declare function adkAgentPrompt(workPrompt: string, origin: string, policyId: string, wallet: string, agent: string, network: string): string;
export declare function parseAdkOwnerLink(fragment: string): AdkOwnerLink;
/**
 * A review link: the proposal, the work prompt and the agent key, funding amount and wallet kind that the chat
 * collected.
 */
export type ReviewLink = AdkOwnerLink & {
    agent: string | null;
    amount: string | null;
    walletKind: string | null;
};
/**
 * Decode and check a Review and sign link. The envelope may also carry `agent`, `amount` and `walletKind`. A missing
 * agent key or amount is null and returns the owner to the conversation. `walletKind` is the id of the kind that the
 * owner chose in the chat, or null when the owner chose none; the host offers it only when the rail lists that id.
 * Any other key, type or size is refused.
 */
export declare function parseReviewLink(fragment: string): ReviewLink;
/** The prompt that the owner gives the agent after signing. */
export declare function reviewAgentPrompt(link: Pick<ReviewLink, 'workPrompt' | 'proposal'>, origin: string, policyId: string, wallet: string, agent: string): string;
export type AdkParamLine = {
    key: string;
    label: string;
    value: string;
};
/**
 * Owner-readable lines for the params of a parsed proposal, with the assets that the rail lists for its network.
 * Canonical keys use the Core registry label. Amounts use the unit of the proposal's asset and stay in base units
 * when it is not known, an expiry is a UTC time, and a listed asset contract shows as its code. Other keys keep
 * their name.
 */
export declare function adkParamLines(params: AdkProposal['params'], listed: readonly ListedAsset[]): AdkParamLine[];
