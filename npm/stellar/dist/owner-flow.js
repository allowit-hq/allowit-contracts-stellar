/**
 * The owner workflow that the SDK exposes through the rail plugin: install the reviewed policy wallet, then fund it.
 * The host supplies its authenticated transport, the signing of one step and a journal. This module holds the rules
 * for a saved signed step and for the typed replies of the service.
 */
import { TransactionBuilder } from '@stellar/stellar-sdk/base';
import { canonicalNetwork, networkPassphrase } from './plugin.js';
/** Typed codes of a refused `native/owner/submit`. The reply body is `{error, code, details}`. */
export const OWNER_TRANSACTION_EXPIRED = 'owner_transaction_expired';
export const OWNER_TRANSACTION_PENDING = 'owner_transaction_pending';
export const OWNER_TRANSACTION_SETTLED = 'owner_transaction_settled';
/** The transaction is in a ledger and failed. `details.ledger` names that ledger. */
export const OWNER_TRANSACTION_FAILED = 'owner_transaction_failed';
/** HTTP 503 with `details.retry = "same_request_id"`: the service sent nothing. */
export const NETWORK_UNAVAILABLE = 'network_unavailable';
/** An owner workflow failure with the typed server code, when the service sent one. */
export class OwnerFlowError extends Error {
    code;
    /** True when the same saved step can be sent again without a new signature. */
    retry;
    constructor(message, code, retry, cause) {
        super(message, { cause });
        this.name = 'OwnerFlowError';
        this.code = code;
        this.retry = retry;
    }
}
const HASH = /^[0-9a-f]{64}$/;
const object = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
/** The rail-neutral step of a reply. The server reports its hash as `transactionHash`. */
function stepOf(step) {
    if (!step || typeof step.action !== 'string' || typeof step.payload !== 'string' || typeof step.expiresAt !== 'number')
        return null;
    const hash = typeof step.hash === 'string' ? step.hash : step.transactionHash;
    return typeof hash === 'string' && HASH.test(hash)
        ? { action: step.action, payload: step.payload, hash, expiresAt: step.expiresAt, ...(step.explorer ? { explorer: step.explorer } : {}) } : null;
}
const installedWallet = (reply) => reply.installed ? reply.installation?.wallet ?? reply.wallet : undefined;
/** The key that keeps the signed bytes of an expired step after the journal drops it. */
export function ownerArchiveKey(key, hash) {
    return `${key}:expired:${hash}`;
}
const HORIZON = {
    'stellar:testnet': 'https://horizon-testnet.stellar.org',
    'stellar:pubnet': 'https://horizon.stellar.org',
};
/** Every Horizon read ends after this time, so a stalled read never holds the workflow lock. */
const HORIZON_TIMEOUT_MS = 15_000;
/** A read of the public ledger history. A failed or stalled read is null. */
async function horizonGet(network, path) {
    const base = HORIZON[canonicalNetwork(network) ?? ''];
    if (!base)
        return null;
    try {
        return await fetch(`${base}${path}`, { headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(HORIZON_TIMEOUT_MS) });
    }
    catch {
        return null;
    }
}
const unverified = () => new OwnerFlowError('The network record of the signed step could not be checked. It stays saved; resume to check it again.', null, true);
/**
 * The ledger in which the chain holds this transaction as successful. The service's word alone never clears a
 * signed step or records a funding. History can trail the network by a few seconds, so a missing record is read again.
 */
async function settledLedger(network, step, ledger, pause) {
    for (let attempt = 0; attempt < 5; attempt++) {
        if (attempt)
            await new Promise(resolve => setTimeout(resolve, pause));
        const response = await horizonGet(network, `/transactions/${step.hash}`);
        if (response?.status === 404)
            continue;
        const chain = response?.ok ? await response.json().catch(() => null) : null;
        if (!object(chain) || chain.hash !== step.hash || chain.successful !== true || !Number.isSafeInteger(chain.ledger)
            || chain.ledger <= 0 || ledger !== undefined && chain.ledger !== ledger)
            break;
        return chain.ledger;
    }
    throw unverified();
}
const unchecked = () => new OwnerFlowError('The expired signed step could not be checked on the network. It stays saved; resume to check it again.', OWNER_TRANSACTION_EXPIRED, true);
/**
 * What the chain holds for a signed step past its time bound: its ledger when it applied, or null when it can
 * never apply. Expiry stops a later application, not an earlier one, so an expiry reply alone proves nothing.
 * The step never applied only when Horizon has read past the time bound and either holds the failed transaction or
 * holds none while the source account sequence is still below the transaction's sequence. Anything else throws.
 */
async function expiredRecord(network, step, signedPayload) {
    let source, sequence;
    try {
        const envelope = TransactionBuilder.fromXDR(signedPayload, networkPassphrase(network));
        const transaction = 'innerTransaction' in envelope ? envelope.innerTransaction : envelope;
        if (Array.from(transaction.hash(), byte => byte.toString(16).padStart(2, '0')).join('') !== step.hash)
            throw new Error();
        source = transaction.source;
        sequence = BigInt(transaction.sequence);
    }
    catch {
        throw unchecked();
    }
    const read = async (path) => {
        const response = await horizonGet(network, path);
        if (!response)
            throw unchecked();
        return response;
    };
    const json = async (response) => {
        const value = await response.json().catch(() => null);
        if (!response.ok || !object(value))
            throw unchecked();
        return value;
    };
    const root = await json(await read('/'));
    const closedAt = typeof root.history_latest_ledger_closed_at === 'string' ? Date.parse(root.history_latest_ledger_closed_at) / 1000 : NaN;
    // Every ledger that can include the transaction closes at or before its time bound. Horizon must have read past it.
    if (!(closedAt > step.expiresAt))
        throw unchecked();
    const found = await read(`/transactions/${step.hash}`);
    if (found.status !== 404) {
        const chain = await json(found);
        if (chain.hash !== step.hash || typeof chain.successful !== 'boolean' || !Number.isSafeInteger(chain.ledger) || chain.ledger <= 0)
            throw unchecked();
        return chain.successful ? { ledger: chain.ledger } : null;
    }
    // A missing record alone proves nothing. A source sequence below the transaction's sequence proves it never applied.
    const account = await json(await read(`/accounts/${source}`));
    if (account.account_id !== source || typeof account.sequence !== 'string' || !/^[0-9]{1,19}$/.test(account.sequence)
        || BigInt(account.sequence) >= sequence)
        throw unchecked();
    return null;
}
/** Workflows that run in this page, by journal key. */
const running = new Set();
const busy = () => new OwnerFlowError('This wallet setup is already running in this or another tab.', null, true);
const changed = () => new OwnerFlowError('Use the agent key and amount from the original wallet setup. The saved signed step stays saved.', null, false);
/** True when a saved value names these inputs. A value saved without inputs predates them and names none. */
function sameInputs(value, identity) {
    const named = ['policyId', 'agent', 'amount'].filter(field => value[field] !== undefined);
    return named.length === 0 || named.length === 3 && named.every(field => value[field] === identity[field]);
}
function saved(journal, key, identity) {
    const raw = journal.get(key);
    if (raw === null)
        return null;
    let value;
    try {
        value = JSON.parse(raw);
    }
    catch { /* fall through */ }
    const step = object(value) ? stepOf(value.step) : null;
    if (!object(value) || !step || typeof value.signedPayload !== 'string' || !value.signedPayload)
        throw new OwnerFlowError('The saved signed step is unreadable. It stays saved; contact support before signing again.', null, false);
    if (!sameInputs(value, identity))
        throw changed();
    return { step, signedPayload: value.signedPayload };
}
/** True when the funding of these inputs is confirmed. A marker of other inputs is refused. */
function funded(journal, fundedKey, identity) {
    const raw = journal.get(fundedKey);
    if (raw === null)
        return false;
    if (raw === 'confirmed')
        return true;
    let value;
    try {
        value = JSON.parse(raw);
    }
    catch { /* fall through */ }
    if (!object(value) || !sameInputs(value, identity))
        throw changed();
    return true;
}
/** True when Horizon holds this transaction as failed in the ledger that the service named. */
async function failedOnChain(network, step, ledger) {
    if (!Number.isSafeInteger(ledger))
        return false;
    const response = await horizonGet(network, `/transactions/${step.hash}`);
    const chain = response?.ok ? await response.json().catch(() => null) : null;
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
export async function installAndFund(input) {
    const name = `allowit.owner-flow:${input.key}`;
    if (running.has(name))
        throw busy();
    running.add(name);
    try {
        const locks = globalThis.navigator?.locks;
        if (!locks)
            return await run(input);
        return await locks.request(name, { ifAvailable: true }, async (lock) => {
            if (!lock)
                throw busy();
            return run(input);
        });
    }
    finally {
        running.delete(name);
    }
}
async function run({ network, ask, sign, journal, key, policyId, agent, amount, onStep, historyPauseMs = 1_500 }) {
    if (!canonicalNetwork(network))
        throw new OwnerFlowError('Select a supported Stellar network.', null, false);
    const receipts = [];
    const fundedKey = `${key}:funded`;
    const identity = { policyId, agent, amount };
    const done = (step, receipt) => {
        // A confirmed funding is recorded before its signed bytes leave the journal.
        if (step.action === 'fund')
            journal.set(fundedKey, JSON.stringify(identity));
        journal.remove(key);
        receipts.push(receipt);
    };
    /** Send a saved step. False means that it expired and the journal dropped it. */
    const submit = async (step, signedPayload) => {
        let receipt;
        try {
            receipt = await ask('native/owner/submit', { policyId, payload: signedPayload });
        }
        catch (error) {
            const { code, details } = (object(error) ? error : {});
            const about = object(details) ? details : {};
            // A typed refusal settles the saved step only when it names that exact transaction.
            const same = about.transactionHash === step.hash && (about.policyId === undefined || about.policyId === policyId);
            if (code === OWNER_TRANSACTION_SETTLED && same) {
                const ledger = await settledLedger(network, step, Number.isSafeInteger(about.ledger) ? about.ledger : undefined, historyPauseMs);
                done(step, { policyId, action: step.action, status: 'confirmed', transactionHash: step.hash, ledger });
                return true;
            }
            if (code === OWNER_TRANSACTION_EXPIRED && same) {
                if (step.expiresAt >= Math.floor(Date.now() / 1000))
                    throw unchecked();
                const chain = await expiredRecord(network, step, signedPayload);
                if (chain) {
                    // The transaction applied before its time bound, so the step is done and is never signed again.
                    done(step, { policyId, action: step.action, status: 'confirmed', transactionHash: step.hash, ledger: chain.ledger });
                    return true;
                }
                journal.set(ownerArchiveKey(key, step.hash), JSON.stringify({ step, signedPayload }));
                journal.remove(key);
                return false;
            }
            // A failed transaction used its sequence and can never apply. The chain must hold that exact failure.
            if (code === OWNER_TRANSACTION_FAILED && same && await failedOnChain(network, step, about.ledger)) {
                journal.set(ownerArchiveKey(key, step.hash), JSON.stringify({ step, signedPayload }));
                journal.remove(key);
                return false;
            }
            if (code === OWNER_TRANSACTION_PENDING)
                throw new OwnerFlowError('The network has not settled the signed step yet. Resume in a moment; do not sign again.', code, true, error);
            if (code === NETWORK_UNAVAILABLE && about.retry === 'same_request_id')
                throw new OwnerFlowError('The network is unavailable. Nothing was sent; resume to send the same signed step.', code, true, error);
            throw new OwnerFlowError(error instanceof Error && error.message ? error.message : 'The signed owner step was not confirmed.', typeof code === 'string' ? code : null, false, error);
        }
        if (!object(receipt) || receipt.policyId !== policyId || receipt.action !== step.action || receipt.status !== 'confirmed'
            || receipt.transactionHash !== step.hash)
            throw new OwnerFlowError('The network did not confirm the signed owner step.', null, false);
        const ledger = await settledLedger(network, step, receipt.ledger, historyPauseMs);
        done(step, { ...receipt, ledger });
        return true;
    };
    const pending = saved(journal, key, identity);
    // A funded marker of other inputs is refused before anything is sent.
    funded(journal, fundedKey, identity);
    if (pending) {
        onStep('Checking the saved signed step…');
        if (!await submit(pending.step, pending.signedPayload))
            onStep('The saved step can never apply. Preparing a new one…');
    }
    const signAndSubmit = async (step) => {
        if (step.expiresAt <= Math.floor(Date.now() / 1000))
            throw new OwnerFlowError('The prepared owner step already expired. Resume to prepare a new one.', null, true);
        onStep(`Sign ${step.action.replace(/_/g, ' ')} in your wallet…`);
        const signedPayload = await sign(step);
        if (typeof signedPayload !== 'string' || !signedPayload)
            throw new OwnerFlowError('Your wallet did not return the signed step.', null, false);
        journal.set(key, JSON.stringify({ step, signedPayload, ...identity }));
        onStep('Waiting for the network to confirm…');
        if (!await submit(step, signedPayload))
            throw new OwnerFlowError('The network did not take the signed step. Resume to prepare a new one.', null, true);
    };
    let wallet;
    for (let i = 0; i < 4 && !wallet; i++) {
        onStep('Preparing the wallet…');
        const reply = await ask('native/deploy/prepare', { policyId, agent });
        if (!object(reply) || reply.policyId !== policyId)
            throw new OwnerFlowError('The deployment reply names a different policy.', null, false);
        wallet = installedWallet(reply);
        if (wallet)
            break;
        const step = stepOf(reply.step);
        if (!step)
            throw new OwnerFlowError('The service did not prepare an owner step for this policy.', null, false);
        await signAndSubmit(step);
    }
    if (!wallet)
        throw new OwnerFlowError('The wallet installation could not be confirmed.', null, true);
    // A confirmed funding is never prepared or signed again, including after a reload or a failed export.
    if (!funded(journal, fundedKey, identity)) {
        onStep('Preparing the funding…');
        const funding = await ask('native/owner/prepare', { policyId, action: 'fund', amount });
        const step = stepOf(funding?.step);
        if (!object(funding) || funding.policyId !== policyId || !step || step.action !== 'fund')
            throw new OwnerFlowError('The funding reply differs from this policy.', null, false);
        await signAndSubmit(step);
    }
    return { wallet, receipts };
}
