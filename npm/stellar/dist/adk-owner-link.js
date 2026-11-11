import { canonicalFunctions } from '@allowit/core';
import { ADK_OWNER_FRAGMENT } from './stellar-fragments.js';
import { stellarAssetContractId } from './stellar-wallet.js';
export { ADK_OWNER_FRAGMENT } from './stellar-fragments.js';
const MAX_ENCODED_LENGTH = 87_000;
const hashPattern = /^[0-9a-f]{64}$/;
/** The CLI uses this origin when `ALLOWIT_URL` is not set. */
const CLI_DEFAULT_ORIGIN = 'https://app.allowit.xyz';
/** The ADK owner flow funds native XLM on Stellar Testnet. */
const XLM = { symbol: 'XLM', decimals: 7, address: stellarAssetContractId('XLM', null, 'stellar:testnet') };
export function adkAgentPrompt(workPrompt, origin, policyId, wallet, agent) {
    const cli = origin === CLI_DEFAULT_ORIGIN ? 'allowit' : `ALLOWIT_URL=${origin} allowit`;
    return [
        workPrompt,
        '',
        `Allowit origin: ${origin}`,
        `Stellar Testnet policy: ${policyId}`,
        `Policy wallet: ${wallet}`,
        `Agent public key: ${agent}`,
        `Verify the server public key independently using trusted operator configuration. If this origin is not already trusted, run \`${cli} --rail stellar:testnet rail trust ${origin} <independently verified server public key>\`.`,
        `Import the attached public profile with \`${cli} --rail stellar:testnet --rpc-url <independent Stellar Testnet RPC URL> wallet import allowit-stellar-profile.json\`. Use your own matching agent key locally.`,
    ].join('\n');
}
function object(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
}
/** One storage tag with a value of its type. */
function policyValue(value, depth = 0) {
    if (!object(value) || Object.keys(value).length !== 1 || depth > 4)
        return false;
    const [[tag, item]] = Object.entries(value);
    if (tag === 'Int')
        return typeof item === 'string' && /^-?(?:0|[1-9][0-9]{0,38})$/.test(item);
    if (tag === 'Bool')
        return typeof item === 'boolean';
    if (tag === 'Str' || tag === 'Addr')
        return typeof item === 'string';
    return tag === 'List' && Array.isArray(item) && item.length <= 64 && item.every(entry => policyValue(entry, depth + 1));
}
export function parseAdkOwnerLink(fragment) {
    const { proposal, workPrompt } = parseLink(fragment, false);
    return { proposal, workPrompt };
}
/**
 * Decode and check a Review and sign link. The envelope may also carry `agent` and `amount`; a missing one is null
 * and returns the owner to the conversation. Any other key, type or size is refused.
 */
export function parseReviewLink(fragment) {
    return parseLink(fragment, true);
}
/** The prompt that the owner gives the agent after signing. */
export function reviewAgentPrompt(link, origin, policyId, wallet, agent) {
    return adkAgentPrompt(link.workPrompt, origin, policyId, wallet, agent);
}
function parseLink(fragment, review) {
    const invalid = () => new Error('The agent policy link is invalid.');
    if (!fragment.startsWith(ADK_OWNER_FRAGMENT))
        throw invalid();
    const payload = fragment.slice(ADK_OWNER_FRAGMENT.length);
    if (!payload || payload.length > MAX_ENCODED_LENGTH || !/^[A-Za-z0-9_-]+$/.test(payload))
        throw invalid();
    let envelope;
    try {
        const bytes = Uint8Array.from(atob(payload.replace(/-/g, '+').replace(/_/g, '/')), byte => byte.charCodeAt(0));
        envelope = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    }
    catch {
        throw invalid();
    }
    if (!object(envelope) || typeof envelope.workPrompt !== 'string'
        || !envelope.workPrompt.trim() || envelope.workPrompt.length > 12_000 || !object(envelope.proposal))
        throw invalid();
    const extra = review ? ['agent', 'amount'] : [];
    if (!Object.keys(envelope).every(key => key === 'proposal' || key === 'workPrompt' || extra.includes(key)))
        throw invalid();
    const optional = (value) => {
        if (value === undefined || value === null)
            return null;
        if (typeof value !== 'string' || value.length > 128)
            throw invalid();
        return value.trim() || null;
    };
    const agent = optional(envelope.agent), amount = optional(envelope.amount);
    const { network, revision, title, explanation, code, sourceHash, paramsHash, params } = envelope.proposal;
    if (Object.keys(envelope.proposal).length !== 8 || network !== 'stellar:testnet'
        || typeof revision !== 'number' || !Number.isSafeInteger(revision) || revision < 1 || revision > 0xffffffff
        || typeof title !== 'string' || !title.trim() || title.length > 160
        || typeof explanation !== 'string' || explanation.length > 8_000
        || typeof code !== 'string' || !code.trim() || new TextEncoder().encode(code).length > 16_000
        || typeof sourceHash !== 'string' || !hashPattern.test(sourceHash)
        || typeof paramsHash !== 'string' || !hashPattern.test(paramsHash)
        || !object(params) || Object.keys(params).length > 64 || !Object.values(params).every(value => policyValue(value)))
        throw invalid();
    return { proposal: { network, revision, title, explanation, code, sourceHash, paramsHash, params }, workPrompt: envelope.workPrompt, agent, amount };
}
/** Base units as a decimal, without floating-point rounding. */
function decimal(units, decimals) {
    const negative = units.startsWith('-');
    const digits = (negative ? units.slice(1) : units).padStart(decimals + 1, '0');
    const fraction = digits.slice(-decimals).replace(/0+$/, '');
    return `${negative ? '-' : ''}${digits.slice(0, -decimals)}${fraction ? `.${fraction}` : ''}`;
}
const integer = /^-?[0-9]+$/;
function leaf(semantic) {
    switch (semantic) {
        case 'amount': return units => integer.test(units) ? `${decimal(units, XLM.decimals)} ${XLM.symbol}` : units;
        case 'timestamp': return seconds => integer.test(seconds) && Math.abs(Number(seconds)) <= 8.64e12
            ? new Date(Number(seconds) * 1000).toISOString().replace(/\.000Z$/, 'Z') : seconds;
        case 'assets': return asset => asset === XLM.address ? XLM.symbol : asset;
        case 'operations': return operation => operation === '*' ? 'Any' : operation;
        default: return item => item;
    }
}
function text(value, format) {
    const [[tag, item]] = Object.entries(value);
    if (tag === 'List')
        return item.map(entry => text(entry, format)).join(', ');
    if (tag === 'Bool')
        return item ? 'Yes' : 'No';
    return format(String(item));
}
/**
 * Owner-readable lines for the params of a parsed proposal. Canonical keys use the Core registry label. Amounts use
 * the XLM decimals, an expiry is a UTC time, and the XLM asset contract shows as XLM. Other keys keep their name.
 */
export function adkParamLines(params) {
    return Object.entries(params).map(([key, value]) => {
        const canonical = canonicalFunctions.find(item => item.name === key);
        return { key, label: canonical?.label ?? key, value: text(value, leaf(canonical?.parameter.semanticType)) };
    });
}
