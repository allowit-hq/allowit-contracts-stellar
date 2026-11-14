/**
 * The owner workflows that the SDK exposes through the rail plugin: install the reviewed policy wallet and fund it,
 * and change installed params on an active wallet.
 * The host supplies its authenticated transport, the signing of one step and a journal. This module holds the rules
 * for a saved signed step and for the typed replies of the service.
 */
import {TransactionBuilder} from '@stellar/stellar-sdk/base';
import {canonicalNetwork, networkPassphrase} from './plugin.js';

/** Rail-neutral owner step. `payload` is opaque text that only this package signs and reads. */
export interface OwnerStep {action: string; payload: string; hash: string; expiresAt: number; explorer?: string | null}
/** The owner's authenticated transport. A rejection carries the server `code` and `details`. */
export type Ask = <T>(path: string, body?: unknown) => Promise<T>;
/** Shows one owner step in the `owner-sign` element and resolves with the exact signed payload. */
export type SignStep = (step: OwnerStep) => Promise<string>;
export interface OwnerJournal {get(key: string): string | null; set(key: string, value: string): void; remove(key: string): void}
export type OwnerReceipt = {policyId: string; action: string; status: string; transactionHash: string; ledger?: number};
export interface InstallAndFundInput {
  /** The network of the policy. */
  network: string;
  /** Milliseconds between reads of a transaction that history does not hold yet. The default is 1500. */
  historyPauseMs?: number;
  ask: Ask; sign: SignStep; journal: OwnerJournal; key: string; policyId: string;
  agent: string; amount: string; onStep: (text: string) => void;
}

/** Typed codes of a refused `native/owner/submit`. The reply body is `{error, code, details}`. */
export const OWNER_TRANSACTION_EXPIRED = 'owner_transaction_expired';
export const OWNER_TRANSACTION_PENDING = 'owner_transaction_pending';
export const OWNER_TRANSACTION_SETTLED = 'owner_transaction_settled';
/** The transaction is in a ledger and failed. `details.ledger` names that ledger. */
export const OWNER_TRANSACTION_FAILED = 'owner_transaction_failed';
/** HTTP 503 with `details.retry = "same_request_id"`: the service sent nothing. */
export const NETWORK_UNAVAILABLE = 'network_unavailable';
/** Typed codes of a refused params update. `details.param` names the param of a refused value. */
export const PARAM_INVALID = 'param_invalid';
export const PARAM_OUT_OF_RANGE = 'param_out_of_range';
/** The policy is not active, or its wallet kind takes no owner-signed update. */
export const UPDATE_UNAVAILABLE = 'update_unavailable';
/** The wallet is at another configuration revision than the update expects. */
export const REVISION_CHANGED = 'revision_changed';
/** The action name of the owner step of a params update. */
export const UPDATE_PARAMS = 'update_params';

/** An owner workflow failure with the typed server code, when the service sent one. */
export class OwnerFlowError extends Error {
  readonly code: string | null;
  /** True when the same saved step can be sent again without a new signature. */
  readonly retry: boolean;
  constructor(message: string, code: string | null, retry: boolean, cause?: unknown) {
    super(message, {cause});
    this.name = 'OwnerFlowError';
    this.code = code;
    this.retry = retry;
  }
}

type Prepared = {policyId: string; step?: Partial<OwnerStep> & {transactionHash?: string}; wallet?: string; installed?: boolean; installation?: {wallet?: string}};
const HASH = /^[0-9a-f]{64}$/;
const object = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);

/** The rail-neutral step of a reply. The server reports its hash as `transactionHash`. */
function stepOf(step: Prepared['step']): OwnerStep | null {
  if (!step || typeof step.action !== 'string' || typeof step.payload !== 'string' || typeof step.expiresAt !== 'number') return null;
  const hash = typeof step.hash === 'string' ? step.hash : step.transactionHash;
  return typeof hash === 'string' && HASH.test(hash)
    ? {action: step.action, payload: step.payload, hash, expiresAt: step.expiresAt, ...(step.explorer ? {explorer: step.explorer} : {})} : null;
}
const installedWallet = (reply: Prepared) => reply.installed ? reply.installation?.wallet ?? reply.wallet : undefined;

/** The key that keeps the signed bytes of an expired step after the journal drops it. */
export function ownerArchiveKey(key: string, hash: string): string {
  return `${key}:expired:${hash}`;
}

const HORIZON: Readonly<Record<string, string>> = {
  'stellar:testnet': 'https://horizon-testnet.stellar.org',
  'stellar:pubnet': 'https://horizon.stellar.org',
};
/** Every Horizon read ends after this time, so a stalled read never holds the workflow lock. */
const HORIZON_TIMEOUT_MS = 15_000;
/** A read of the public ledger history. A failed or stalled read is null. */
async function horizonGet(network: string, path: string): Promise<Response | null> {
  const base = HORIZON[canonicalNetwork(network) ?? ''];
  if (!base) return null;
  try {
    return await fetch(`${base}${path}`, {headers: {Accept: 'application/json'}, signal: AbortSignal.timeout(HORIZON_TIMEOUT_MS)});
  } catch {
    return null;
  }
}
const unverified = () => new OwnerFlowError('The network record of the signed step could not be checked. It stays saved; resume to check it again.', null, true);
/**
 * The ledger in which the chain holds this transaction as successful. The service's word alone never clears a
 * signed step or records a funding. History can trail the network by a few seconds, so a missing record is read again.
 */
async function settledLedger(network: string, step: OwnerStep, ledger: unknown, pause: number): Promise<number> {
  for (let attempt = 0; attempt < 5; attempt++) {
    if (attempt) await new Promise(resolve => setTimeout(resolve, pause));
    const response = await horizonGet(network, `/transactions/${step.hash}`);
    if (response?.status === 404) continue;
    const chain: unknown = response?.ok ? await response.json().catch(() => null) : null;
    if (!object(chain) || chain.hash !== step.hash || chain.successful !== true || !Number.isSafeInteger(chain.ledger)
      || (chain.ledger as number) <= 0 || ledger !== undefined && chain.ledger !== ledger) break;
    return chain.ledger as number;
  }
  throw unverified();
}
const unchecked = () => new OwnerFlowError('The expired signed step could not be checked on the network. It stays saved; resume to check it again.', OWNER_TRANSACTION_EXPIRED, true);

/**
 * What the chain holds for a signed step past its time bound: its ledger when it applied, or null when it can
 * never apply. Expiry stops a later application, not an earlier one, so an expiry reply alone proves nothing.
 * The time bound is the maximum time of the signed transaction itself; a transaction without one never expires.
 * The step never applied only when Horizon has read past the time bound and either holds the failed transaction or
 * holds none while the source account sequence is still below the transaction's sequence. Anything else throws.
 */
async function expiredRecord(network: string, step: OwnerStep, signedPayload: string): Promise<{ledger: number} | null> {
  let source: string, sequence: bigint, validUntil: number;
  try {
    const envelope = TransactionBuilder.fromXDR(signedPayload, networkPassphrase(network));
    const transaction = 'innerTransaction' in envelope ? envelope.innerTransaction : envelope;
    if (Array.from(transaction.hash(), byte => byte.toString(16).padStart(2, '0')).join('') !== step.hash) throw new Error();
    source = transaction.source;
    sequence = BigInt(transaction.sequence);
    // The signed bytes decide when the transaction can no longer apply. The step metadata is unsigned.
    const maxTime = transaction.timeBounds?.maxTime;
    if (typeof maxTime !== 'string' || !/^[1-9][0-9]{0,11}$/.test(maxTime)) throw new Error();
    validUntil = Number(maxTime);
  } catch {
    throw unchecked();
  }
  const read = async (path: string) => {
    const response = await horizonGet(network, path);
    if (!response) throw unchecked();
    return response;
  };
  const json = async (response: Response): Promise<Record<string, unknown>> => {
    const value: unknown = await response.json().catch(() => null);
    if (!response.ok || !object(value)) throw unchecked();
    return value;
  };
  const root = await json(await read('/'));
  const closedAt = typeof root.history_latest_ledger_closed_at === 'string' ? Date.parse(root.history_latest_ledger_closed_at) / 1000 : NaN;
  // Every ledger that can include the transaction closes at or before its signed time bound. The clock and Horizon
  // must both be past it.
  if (!(Date.now() / 1000 > validUntil) || !(closedAt > validUntil)) throw unchecked();
  const found = await read(`/transactions/${step.hash}`);
  if (found.status !== 404) {
    const chain = await json(found);
    if (chain.hash !== step.hash || typeof chain.successful !== 'boolean' || !Number.isSafeInteger(chain.ledger) || (chain.ledger as number) <= 0) throw unchecked();
    return chain.successful ? {ledger: chain.ledger as number} : null;
  }
  // A missing record alone proves nothing. A source sequence below the transaction's sequence proves it never applied.
  const account = await json(await read(`/accounts/${source}`));
  if (account.account_id !== source || typeof account.sequence !== 'string' || !/^[0-9]{1,19}$/.test(account.sequence)
    || BigInt(account.sequence) >= sequence) throw unchecked();
  return null;
}

/** Workflows that run in this page, by journal key. */
const running = new Set<string>();
const busy = () => new OwnerFlowError('This wallet setup is already running in this or another tab.', null, true);

/** The inputs that a saved step and a completion marker belong to: the wallet setup or one params update. */
type Identity = {policyId: string; agent: string; amount: string} | {policyId: string; update: string};
const FIELDS = ['policyId', 'agent', 'amount', 'update'] as const;
const changed = (identity: Identity) => new OwnerFlowError('update' in identity
  ? 'The saved signed step belongs to another change. It stays saved; resume that change first.'
  : 'Use the agent key and amount from the original wallet setup. The saved signed step stays saved.', null, false);
/** True when a saved value names these inputs. A value saved without inputs predates them and names none. */
function sameInputs(value: Record<string, unknown>, identity: Identity): boolean {
  const named = FIELDS.filter(field => value[field] !== undefined);
  const inputs = identity as Record<string, string>;
  return named.length === 0 || named.length === Object.keys(inputs).length && named.every(field => value[field] === inputs[field]);
}

function saved(journal: OwnerJournal, key: string, identity: Identity): {step: OwnerStep; signedPayload: string} | null {
  const raw = journal.get(key);
  if (raw === null) return null;
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch { /* fall through */ }
  const step = object(value) ? stepOf(value.step as Prepared['step']) : null;
  if (!object(value) || !step || typeof value.signedPayload !== 'string' || !value.signedPayload)
    throw new OwnerFlowError('The saved signed step is unreadable. It stays saved; contact support before signing again.', null, false);
  if (!sameInputs(value, identity)) throw changed(identity);
  return {step, signedPayload: value.signedPayload};
}

/** True when the funding or the update of these inputs is confirmed. A marker of other inputs is refused. */
function funded(journal: OwnerJournal, fundedKey: string, identity: Identity): boolean {
  const raw = journal.get(fundedKey);
  if (raw === null) return false;
  if (raw === 'confirmed') return true;
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch { /* fall through */ }
  if (!object(value) || !sameInputs(value, identity)) throw changed(identity);
  return true;
}

/** True when Horizon holds this transaction as failed in the ledger that the service named. */
async function failedOnChain(network: string, step: OwnerStep, ledger: unknown): Promise<boolean> {
  if (!Number.isSafeInteger(ledger)) return false;
  const response = await horizonGet(network, `/transactions/${step.hash}`);
  const chain: unknown = response?.ok ? await response.json().catch(() => null) : null;
  return object(chain) && chain.hash === step.hash && chain.ledger === ledger && chain.successful === false;
}

/**
 * Install the reviewed policy wallet, then fund it. The service prepares each owner step and the host signs it.
 * Signed bytes enter the journal before they are sent, so a reload sends the same signature and never signs a step
 * twice. A saved step is settled first:
 * - confirmed, or `owner_transaction_settled` for the same hash: the step is done once the chain holds that
 *   successful transaction. Until then it stays saved and the error has `retry` set;
 * - `owner_transaction_expired`: the chain decides. When the transaction applied before its time bound, the step is
 *   done. When the chain proves that it never applied, its signed bytes move to the archive key and the owner signs
 *   a new step. When the chain cannot be read, the step stays saved and the error has `retry` set;
 * - `owner_transaction_failed`: when the chain holds that failed transaction, its signed bytes move to the archive
 *   key and the owner signs a new step;
 * - `owner_transaction_pending` or `network_unavailable`: the step stays saved and the error has `retry` set.
 * Any other failure keeps the saved step, so no second signature exists while the first can still apply.
 * A saved step and the funded marker name the policy, agent key and amount. A resume with other inputs is refused.
 * One workflow runs per journal key: a second call in this page or, where the browser has Web Locks, in another tab
 * is refused before it reads the journal.
 */
export async function installAndFund(input: InstallAndFundInput): Promise<{wallet: string; receipts: OwnerReceipt[]}> {
  const name = `allowit.owner-flow:${input.key}`;
  if (running.has(name)) throw busy();
  running.add(name);
  try {
    const locks = globalThis.navigator?.locks;
    if (!locks) return await run(input);
    return await locks.request(name, {ifAvailable: true}, async lock => {
      if (!lock) throw busy();
      return run(input);
    });
  } finally {
    running.delete(name);
  }
}

/** The parts of one workflow that send, settle and sign its owner steps. */
interface StepperInput {
  network: string; historyPauseMs: number; ask: Ask; sign: SignStep; journal: OwnerJournal; key: string; policyId: string;
  onStep: (text: string) => void; identity: Identity;
  /** Records a confirmed step before its signed bytes leave the journal. */
  confirmed: (step: OwnerStep) => void;
}
function stepper({network, historyPauseMs, ask, sign, journal, key, policyId, onStep, identity, confirmed}: StepperInput) {
  const receipts: OwnerReceipt[] = [];
  const done = (step: OwnerStep, receipt: OwnerReceipt) => {
    confirmed(step);
    journal.remove(key);
    receipts.push(receipt);
  };
  /** Send a saved step. False means that it expired and the journal dropped it. */
  const submit = async (step: OwnerStep, signedPayload: string): Promise<boolean> => {
    let receipt: OwnerReceipt;
    try {
      receipt = await ask<OwnerReceipt>('native/owner/submit', {policyId, payload: signedPayload});
    } catch (error) {
      const {code, details} = (object(error) ? error : {}) as {code?: unknown; details?: unknown};
      const about = object(details) ? details : {};
      // A typed refusal settles the saved step only when it names that exact transaction.
      const same = about.transactionHash === step.hash && (about.policyId === undefined || about.policyId === policyId);
      if (code === OWNER_TRANSACTION_SETTLED && same) {
        const ledger = await settledLedger(network, step, Number.isSafeInteger(about.ledger) ? about.ledger : undefined, historyPauseMs);
        done(step, {policyId, action: step.action, status: 'confirmed', transactionHash: step.hash, ledger});
        return true;
      }
      if (code === OWNER_TRANSACTION_EXPIRED && same) {
        if (step.expiresAt >= Math.floor(Date.now() / 1000)) throw unchecked();
        const chain = await expiredRecord(network, step, signedPayload);
        if (chain) {
          // The transaction applied before its time bound, so the step is done and is never signed again.
          done(step, {policyId, action: step.action, status: 'confirmed', transactionHash: step.hash, ledger: chain.ledger});
          return true;
        }
        journal.set(ownerArchiveKey(key, step.hash), JSON.stringify({step, signedPayload}));
        journal.remove(key);
        return false;
      }
      // A failed transaction used its sequence and can never apply. The chain must hold that exact failure.
      if (code === OWNER_TRANSACTION_FAILED && same && await failedOnChain(network, step, about.ledger)) {
        journal.set(ownerArchiveKey(key, step.hash), JSON.stringify({step, signedPayload}));
        journal.remove(key);
        return false;
      }
      if (code === OWNER_TRANSACTION_PENDING)
        throw new OwnerFlowError('The network has not settled the signed step yet. Resume in a moment; do not sign again.', code, true, error);
      if (code === NETWORK_UNAVAILABLE && about.retry === 'same_request_id')
        throw new OwnerFlowError('The network is unavailable. Nothing was sent; resume to send the same signed step.', code, true, error);
      throw new OwnerFlowError(error instanceof Error && error.message ? error.message : 'The signed owner step was not confirmed.',
        typeof code === 'string' ? code : null, false, error);
    }
    if (!object(receipt) || receipt.policyId !== policyId || receipt.action !== step.action || receipt.status !== 'confirmed'
      || receipt.transactionHash !== step.hash)
      throw new OwnerFlowError('The network did not confirm the signed owner step.', null, false);
    const ledger = await settledLedger(network, step, receipt.ledger, historyPauseMs);
    done(step, {...receipt, ledger});
    return true;
  };
  /** Settle the saved signed step, if the journal holds one, before anything else is prepared. */
  const settleSaved = async () => {
    const pending = saved(journal, key, identity);
    if (pending) {
      onStep('Checking the saved signed step…');
      if (!await submit(pending.step, pending.signedPayload)) onStep('The saved step can never apply. Preparing a new one…');
    }
  };
  const signAndSubmit = async (step: OwnerStep) => {
    if (step.expiresAt <= Math.floor(Date.now() / 1000)) throw new OwnerFlowError('The prepared owner step already expired. Resume to prepare a new one.', null, true);
    onStep(`Sign ${step.action.replace(/_/g, ' ')} in your wallet…`);
    const signedPayload = await sign(step);
    if (typeof signedPayload !== 'string' || !signedPayload) throw new OwnerFlowError('Your wallet did not return the signed step.', null, false);
    journal.set(key, JSON.stringify({step, signedPayload, ...identity}));
    onStep('Waiting for the network to confirm…');
    if (!await submit(step, signedPayload)) throw new OwnerFlowError('The network did not take the signed step. Resume to prepare a new one.', null, true);
  };
  return {receipts, settleSaved, signAndSubmit};
}

async function run({network, ask, sign, journal, key, policyId, agent, amount, onStep, historyPauseMs = 1_500}: InstallAndFundInput): Promise<{wallet: string; receipts: OwnerReceipt[]}> {
  if (!canonicalNetwork(network)) throw new OwnerFlowError('Select a supported Stellar network.', null, false);
  const fundedKey = `${key}:funded`;
  const identity: Identity = {policyId, agent, amount};
  const {receipts, settleSaved, signAndSubmit} = stepper({network, historyPauseMs, ask, sign, journal, key, policyId, onStep, identity,
    // A confirmed funding is recorded before its signed bytes leave the journal.
    confirmed: step => {if (step.action === 'fund') journal.set(fundedKey, JSON.stringify(identity));}});
  // A saved step or a funded marker of other inputs is refused before anything is sent.
  saved(journal, key, identity);
  funded(journal, fundedKey, identity);
  await settleSaved();
  let wallet: string | undefined;
  for (let i = 0; i < 4 && !wallet; i++) {
    onStep('Preparing the wallet…');
    const reply = await ask<Prepared>('native/deploy/prepare', {policyId, agent});
    if (!object(reply) || reply.policyId !== policyId) throw new OwnerFlowError('The deployment reply names a different policy.', null, false);
    wallet = installedWallet(reply);
    if (wallet) break;
    const step = stepOf(reply.step);
    if (!step) throw new OwnerFlowError('The service did not prepare an owner step for this policy.', null, false);
    await signAndSubmit(step);
  }
  if (!wallet) throw new OwnerFlowError('The wallet installation could not be confirmed.', null, true);
  // A confirmed funding is never prepared or signed again, including after a reload or a failed export.
  if (!funded(journal, fundedKey, identity)) {
    onStep('Preparing the funding…');
    const funding = await ask<Prepared>('native/owner/prepare', {policyId, action: 'fund', amount});
    const step = stepOf(funding?.step);
    if (!object(funding) || funding.policyId !== policyId || !step || step.action !== 'fund') throw new OwnerFlowError('The funding reply differs from this policy.', null, false);
    await signAndSubmit(step);
  }
  return {wallet, receipts};
}

export interface UpdateParamsInput {
  /** The network of the policy. */
  network: string;
  /** Milliseconds between reads of a transaction that history does not hold yet. The default is 1500. */
  historyPauseMs?: number;
  /** One journal key per change: a confirmed change is never prepared or signed again under its key. */
  ask: Ask; sign: SignStep; journal: OwnerJournal; key: string; policyId: string;
  /** Each changed param with its complete new typed value, such as `{daily_spending_limit: {Int: '50000000'}}`. */
  params: Record<string, unknown>;
  /** The configuration revision that the owner reviewed, when the host shows one. */
  expectedRevision?: number;
  onStep: (text: string) => void;
}

/** Canonical text of a JSON value: object keys in code-unit order at every level. */
function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (object(value)) return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
  return JSON.stringify(value) ?? 'null';
}

/**
 * Change installed params on an active wallet with one owner signature. The service checks each value, prepares
 * the owner step and, when the network confirms it, saves the new params of the installation and of the policy in
 * one write. The wallet keeps its recorded usage and its request nonce.
 * The workflow resumes as `installAndFund` does: a saved signed step is settled first, an expired step that never
 * applied moves to the archive key, and the owner then signs a new step. A confirmed change is never prepared or
 * signed again under its journal key; `done` is then true and `receipts` is empty.
 * A refusal of the service keeps its typed code in `OwnerFlowError.code`: `param_invalid`, `param_out_of_range`,
 * `update_unavailable` or `revision_changed`, and the codes of a refused submission.
 */
export async function updateParams(input: UpdateParamsInput): Promise<{receipts: OwnerReceipt[]; done: boolean}> {
  const name = `allowit.owner-flow:${input.key}`;
  if (running.has(name)) throw busy();
  running.add(name);
  try {
    const locks = globalThis.navigator?.locks;
    if (!locks) return await runUpdate(input);
    return await locks.request(name, {ifAvailable: true}, async lock => {
      if (!lock) throw busy();
      return runUpdate(input);
    });
  } finally {
    running.delete(name);
  }
}

async function runUpdate({network, ask, sign, journal, key, policyId, params, expectedRevision, onStep, historyPauseMs = 1_500}: UpdateParamsInput): Promise<{receipts: OwnerReceipt[]; done: boolean}> {
  if (!canonicalNetwork(network)) throw new OwnerFlowError('Select a supported Stellar network.', null, false);
  if (!object(params) || Object.keys(params).length === 0 || Object.keys(params).length > 32)
    throw new OwnerFlowError('Change one to 32 params.', PARAM_INVALID, false);
  if (expectedRevision !== undefined && !(Number.isSafeInteger(expectedRevision) && expectedRevision >= 0))
    throw new OwnerFlowError('The expected revision is invalid.', REVISION_CHANGED, false);
  const updatedKey = `${key}:updated`;
  const identity: Identity = {policyId, update: canonical({params, ...(expectedRevision === undefined ? {} : {expectedRevision})})};
  const {receipts, settleSaved, signAndSubmit} = stepper({network, historyPauseMs, ask, sign, journal, key, policyId, onStep, identity,
    // A confirmed update is recorded before its signed bytes leave the journal.
    confirmed: step => {if (step.action === UPDATE_PARAMS) journal.set(updatedKey, JSON.stringify(identity));}});
  // A saved step or a marker of another change is refused before anything is sent.
  saved(journal, key, identity);
  if (funded(journal, updatedKey, identity)) return {receipts, done: true};
  await settleSaved();
  if (funded(journal, updatedKey, identity)) return {receipts, done: true};
  onStep('Preparing the change…');
  let prepared: Prepared;
  try {
    prepared = await ask<Prepared>('native/owner/prepare', {policyId, action: UPDATE_PARAMS, params, ...(expectedRevision === undefined ? {} : {expectedRevision})});
  } catch (error) {
    // The service's reason and typed code reach the owner unchanged.
    const code = object(error) && typeof error.code === 'string' ? error.code : null;
    throw new OwnerFlowError(error instanceof Error && error.message ? error.message : 'The change could not be prepared.', code, code === NETWORK_UNAVAILABLE, error);
  }
  const step = stepOf(prepared?.step);
  if (!object(prepared) || prepared.policyId !== policyId || !step || step.action !== UPDATE_PARAMS)
    throw new OwnerFlowError('The reply differs from this change.', null, false);
  await signAndSubmit(step);
  return {receipts, done: true};
}
