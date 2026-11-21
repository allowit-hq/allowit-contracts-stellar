import {canonicalFunctions, type ParameterSemanticType} from '@allowit/core';
import {ADK_OWNER_FRAGMENT} from './stellar-fragments.js';
import {NETWORKS} from './networks.js';
export {ADK_OWNER_FRAGMENT} from './stellar-fragments.js';

const MAX_ENCODED_LENGTH = 87_000;
const hashPattern = /^[0-9a-f]{64}$/;
/** A wallet kind id, as the catalogue of the server names it. */
const kindPattern = /^[a-z]{1,32}$/;
/** The CLI uses this origin when `ALLOWIT_URL` is not set. */
const CLI_DEFAULT_ORIGIN = 'https://app.allowit.ai';
/** An asset that the rail lists for a network: its contract, its code and its decimals. */
export type ListedAsset = {id: string; symbol: string; decimals: number};

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

export type AdkOwnerLink = {proposal: AdkProposal; workPrompt: string};

/** The prompt that the owner gives the agent after signing, for a policy on `network`. */
export function adkAgentPrompt(workPrompt: string, origin: string, policyId: string, wallet: string, agent: string, network: string): string {
  const label = NETWORKS.find(n => n.id === network)?.label;
  if (!label) throw new Error('The agent policy link is invalid.');
  const cli = origin === CLI_DEFAULT_ORIGIN ? 'allowit' : `ALLOWIT_URL=${origin} allowit`;
  return [
    workPrompt,
    '',
    `Allowit origin: ${origin}`,
    `${label} policy: ${policyId}`,
    `Policy wallet: ${wallet}`,
    `Agent public key: ${agent}`,
    `Verify the server public key independently using trusted operator configuration. If this origin is not already trusted, run \`${cli} --rail ${network} rail trust ${origin} <independently verified server public key>\`.`,
    `Import the attached public profile with \`${cli} --rail ${network} --rpc-url <independent ${label} RPC URL> wallet import allowit-stellar-profile.json\`. Use your own matching agent key locally.`,
  ].join('\n');
}

function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/** One storage tag with a value of its type. */
function policyValue(value: unknown, depth = 0): boolean {
  if (!object(value) || Object.keys(value).length !== 1 || depth > 4) return false;
  const [[tag, item]] = Object.entries(value);
  if (tag === 'Int') return typeof item === 'string' && /^-?(?:0|[1-9][0-9]{0,38})$/.test(item);
  if (tag === 'Bool') return typeof item === 'boolean';
  if (tag === 'Str' || tag === 'Addr') return typeof item === 'string';
  return tag === 'List' && Array.isArray(item) && item.length <= 64 && item.every(entry => policyValue(entry, depth + 1));
}

export function parseAdkOwnerLink(fragment: string): AdkOwnerLink {
  const {proposal, workPrompt} = parseLink(fragment, false);
  return {proposal, workPrompt};
}

/**
 * A review link: the proposal, the work prompt and the agent key, funding amount and wallet kind that the chat
 * collected.
 */
export type ReviewLink = AdkOwnerLink & {agent: string | null; amount: string | null; walletKind: string | null};

/**
 * Decode and check a Review and sign link. The envelope may also carry `agent`, `amount` and `walletKind`. A missing
 * agent key or amount is null and returns the owner to the conversation. `walletKind` is the id of the kind that the
 * owner chose in the chat, or null when the owner chose none; the host offers it only when the rail lists that id.
 * Any other key, type or size is refused.
 */
export function parseReviewLink(fragment: string): ReviewLink {
  return parseLink(fragment, true);
}

/** The prompt that the owner gives the agent after signing. */
export function reviewAgentPrompt(link: Pick<ReviewLink, 'workPrompt' | 'proposal'>, origin: string, policyId: string, wallet: string, agent: string): string {
  return adkAgentPrompt(link.workPrompt, origin, policyId, wallet, agent, link.proposal.network);
}

function parseLink(fragment: string, review: boolean): ReviewLink {
  const invalid = () => new Error('The agent policy link is invalid.');
  if (!fragment.startsWith(ADK_OWNER_FRAGMENT)) throw invalid();
  const payload = fragment.slice(ADK_OWNER_FRAGMENT.length);
  if (!payload || payload.length > MAX_ENCODED_LENGTH || !/^[A-Za-z0-9_-]+$/.test(payload)) throw invalid();
  let envelope: unknown;
  try {
    const bytes = Uint8Array.from(atob(payload.replace(/-/g, '+').replace(/_/g, '/')), byte => byte.charCodeAt(0));
    envelope = JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(bytes));
  } catch {
    throw invalid();
  }
  if (!object(envelope) || typeof envelope.workPrompt !== 'string'
    || !envelope.workPrompt.trim() || envelope.workPrompt.length > 12_000 || !object(envelope.proposal)) throw invalid();
  const extra = review ? ['agent', 'amount', 'walletKind'] : [];
  if (!Object.keys(envelope).every(key => key === 'proposal' || key === 'workPrompt' || extra.includes(key))) throw invalid();
  const optional = (value: unknown) => {
    if (value === undefined || value === null) return null;
    if (typeof value !== 'string' || value.length > 128) throw invalid();
    return value.trim() || null;
  };
  const agent = optional(envelope.agent), amount = optional(envelope.amount);
  const walletKind = envelope.walletKind ?? null;
  if (walletKind !== null && (typeof walletKind !== 'string' || !kindPattern.test(walletKind))) throw invalid();
  const {network, revision, title, explanation, code, sourceHash, paramsHash, params} = envelope.proposal;
  if (Object.keys(envelope.proposal).length !== 8 || !NETWORKS.some(n => n.id === network)
    || typeof revision !== 'number' || !Number.isSafeInteger(revision) || revision < 1 || revision > 0xffffffff
    || typeof title !== 'string' || !title.trim() || title.length > 160
    || typeof explanation !== 'string' || explanation.length > 8_000
    || typeof code !== 'string' || !code.trim() || new TextEncoder().encode(code).length > 16_000
    || typeof sourceHash !== 'string' || !hashPattern.test(sourceHash)
    || typeof paramsHash !== 'string' || !hashPattern.test(paramsHash)
    || !object(params) || Object.keys(params).length > 64 || !Object.values(params).every(value => policyValue(value))) throw invalid();
  return {proposal: {network: network as string, revision, title, explanation, code, sourceHash, paramsHash, params}, workPrompt: envelope.workPrompt, agent, amount, walletKind};
}

/** Base units as a decimal, without floating-point rounding. */
function decimal(units: string, decimals: number): string {
  const negative = units.startsWith('-');
  const digits = (negative ? units.slice(1) : units).padStart(decimals + 1, '0');
  const fraction = digits.slice(-decimals).replace(/0+$/, '');
  return `${negative ? '-' : ''}${digits.slice(0, -decimals)}${fraction ? `.${fraction}` : ''}`;
}

const integer = /^-?[0-9]+$/;
/**
 * The unit of a proposal's amounts: the one listed asset that its `tokens` rule admits, a list of one `Addr` as Core
 * reads it, else, for a proposal without that rule, the network's native asset (the first listed). Any other rule
 * gives null.
 */
function unitOf(params: AdkProposal['params'], listed: readonly ListedAsset[]): ListedAsset | null {
  const rule = params.tokens as {List?: {Addr?: unknown}[]} | undefined;
  if (rule === undefined) return listed[0] ?? null;
  const only = Array.isArray(rule.List) && rule.List.length === 1 ? rule.List[0].Addr : null;
  return listed.find(asset => asset.id === only) ?? null;
}
function leaf(semantic: ParameterSemanticType | undefined, unit: ListedAsset | null, listed: readonly ListedAsset[]): (item: string) => string {
  switch (semantic) {
    case 'amount': return units => integer.test(units) && unit ? `${decimal(units, unit.decimals)} ${unit.symbol}` : units;
    case 'timestamp': return seconds => integer.test(seconds) && Math.abs(Number(seconds)) <= 8.64e12
      ? new Date(Number(seconds) * 1000).toISOString().replace(/\.000Z$/, 'Z') : seconds;
    case 'assets': return asset => listed.find(item => item.id === asset)?.symbol ?? asset;
    case 'operations': return operation => operation === '*' ? 'Any' : operation;
    default: return item => item;
  }
}

function text(value: unknown, format: (item: string) => string): string {
  const [[tag, item]] = Object.entries(value as Record<string, unknown>);
  if (tag === 'List') return (item as unknown[]).map(entry => text(entry, format)).join(', ');
  if (tag === 'Bool') return item ? 'Yes' : 'No';
  return format(String(item));
}

export type AdkParamLine = {key: string; label: string; value: string};

/**
 * Owner-readable lines for the params of a parsed proposal, with the assets that the rail lists for its network.
 * Canonical keys use the Core registry label. Amounts use the unit of the proposal's asset and stay in base units
 * when it is not known, an expiry is a UTC time, and a listed asset contract shows as its code. Other keys keep
 * their name.
 */
export function adkParamLines(params: AdkProposal['params'], listed: readonly ListedAsset[]): AdkParamLine[] {
  const unit = unitOf(params, listed);
  return Object.entries(params).map(([key, value]) => {
    const canonical = canonicalFunctions.find(item => item.name === key);
    return {key, label: canonical?.label ?? key, value: text(value, leaf(canonical?.parameter.semanticType, unit, listed))};
  });
}
