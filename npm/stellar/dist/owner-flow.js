/**
 * The owner workflow that the SDK exposes through the rail plugin: install the reviewed policy wallet, then fund it.
 * The host supplies its authenticated transport, the signing of one step and a journal. This module holds the rules
 * for a saved signed step and for the typed replies of the service.
 */
/** Typed codes of a refused `native/owner/submit`. The reply body is `{error, code, details}`. */
export const OWNER_TRANSACTION_EXPIRED = 'owner_transaction_expired';
export const OWNER_TRANSACTION_PENDING = 'owner_transaction_pending';
export const OWNER_TRANSACTION_SETTLED = 'owner_transaction_settled';
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
function saved(journal, key) {
    const raw = journal.get(key);
    if (raw === null)
        return null;
    try {
        const value = JSON.parse(raw);
        const step = stepOf(value?.step);
        if (step && typeof value.signedPayload === 'string' && value.signedPayload)
            return { step, signedPayload: value.signedPayload };
    }
    catch { /* fall through */ }
    throw new OwnerFlowError('The saved signed step is unreadable. It stays saved; contact support before signing again.', null, false);
}
/**
 * Install the reviewed policy wallet, then fund it. The service prepares each owner step and the host signs it.
 * Signed bytes enter the journal before they are sent, so a reload sends the same signature and never signs a step
 * twice. A saved step is settled first:
 * - confirmed, or `owner_transaction_settled` for the same hash: the step is done;
 * - `owner_transaction_expired`: the step can never apply. Its signed bytes move to the archive key and the owner
 *   signs a new step;
 * - `owner_transaction_pending` or `network_unavailable`: the step stays saved and the error has `retry` set.
 * Any other failure keeps the saved step, so no second signature exists while the first can still apply.
 */
export async function installAndFund({ ask, sign, journal, key, policyId, agent, amount, onStep }) {
    const receipts = [];
    const fundedKey = `${key}:funded`;
    const done = (step, receipt) => {
        // A confirmed funding is recorded before its signed bytes leave the journal.
        if (step.action === 'fund')
            journal.set(fundedKey, 'confirmed');
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
                done(step, { policyId, action: step.action, status: 'confirmed', transactionHash: step.hash,
                    ...(Number.isSafeInteger(about.ledger) ? { ledger: about.ledger } : {}) });
                return true;
            }
            if (code === OWNER_TRANSACTION_EXPIRED && same) {
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
        done(step, receipt);
        return true;
    };
    const pending = saved(journal, key);
    if (pending) {
        onStep('Checking the saved signed step…');
        if (!await submit(pending.step, pending.signedPayload))
            onStep('The saved step expired. Preparing a new one…');
    }
    const signAndSubmit = async (step) => {
        if (step.expiresAt <= Math.floor(Date.now() / 1000))
            throw new OwnerFlowError('The prepared owner step already expired. Resume to prepare a new one.', null, true);
        onStep(`Sign ${step.action.replace(/_/g, ' ')} in your wallet…`);
        const signedPayload = await sign(step);
        if (typeof signedPayload !== 'string' || !signedPayload)
            throw new OwnerFlowError('Your wallet did not return the signed step.', null, false);
        journal.set(key, JSON.stringify({ step, signedPayload }));
        onStep('Waiting for the network to confirm…');
        if (!await submit(step, signedPayload))
            throw new OwnerFlowError('The signed step expired before the network took it. Resume to prepare a new one.', OWNER_TRANSACTION_EXPIRED, true);
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
    if (!journal.get(fundedKey)) {
        onStep('Preparing the funding…');
        const funding = await ask('native/owner/prepare', { policyId, action: 'fund', amount });
        const step = stepOf(funding?.step);
        if (!object(funding) || funding.policyId !== policyId || !step || step.action !== 'fund')
            throw new OwnerFlowError('The funding reply differs from this policy.', null, false);
        await signAndSubmit(step);
    }
    return { wallet, receipts };
}
