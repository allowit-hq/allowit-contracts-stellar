export { ADK_OWNER_FRAGMENT } from './stellar-fragments.js';
export type AdkProposal = {
    network: 'stellar:testnet';
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
export declare function adkAgentPrompt(workPrompt: string, origin: string, policyId: string, wallet: string, agent: string): string;
export declare function parseAdkOwnerLink(fragment: string): AdkOwnerLink;
/** A review link: the proposal, the work prompt and the agent key and funding amount that the chat collected. */
export type ReviewLink = AdkOwnerLink & {
    agent: string | null;
    amount: string | null;
};
/**
 * Decode and check a Review and sign link. The envelope may also carry `agent` and `amount`; a missing one is null
 * and returns the owner to the conversation. Any other key, type or size is refused.
 */
export declare function parseReviewLink(fragment: string): ReviewLink;
/** The prompt that the owner gives the agent after signing. */
export declare function reviewAgentPrompt(link: Pick<ReviewLink, 'workPrompt'>, origin: string, policyId: string, wallet: string, agent: string): string;
export type AdkParamLine = {
    key: string;
    label: string;
    value: string;
};
/**
 * Owner-readable lines for the params of a parsed proposal. Canonical keys use the Core registry label. Amounts use
 * the XLM decimals, an expiry is a UTC time, and the XLM asset contract shows as XLM. Other keys keep their name.
 */
export declare function adkParamLines(params: AdkProposal['params']): AdkParamLine[];
