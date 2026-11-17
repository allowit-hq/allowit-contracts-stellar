import { canonicalNetwork } from './plugin.js';
import { expiredRecord as chainExpiredRecord, horizonGet } from './chain-record.js';
import { countersignCreation, CREATE_FEE_ACCOUNT, FEE_ACCOUNT_REQUIRED, newFeeAccountKey } from './fee-account.js';
import { APPROVE_POLICY, SET_UP_WALLET, WALLET_SETUP_REQUIRED, WalletSetupPendingError, approvalStep, policyApproval, setUpNativeWallet } from './native-wallet.js';
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
 * never apply. `chain-record.ts` holds the rule. A chain that cannot be read keeps the step saved.
 */
const expiredRecord = (network, step, signedPayload) => chainExpiredRecord(network, step.hash, signedPayload).catch(() => { throw unchecked(); });
/** The 64 bytes of a wallet's message signature, which the wallet returns as base64 text. */
function signatureBytes(signature) {
    let bytes = [];
    try {
        bytes = typeof signature === 'string' ? Array.from(atob(signature), c => c.charCodeAt(0)) : [];
    }
    catch { /* refused below */ }
    if (bytes.length !== 64)
        throw new OwnerFlowError('Your wallet did not return a message signature.', null, false);
    return bytes;
}
/** Workflows that run in this page, by journal key. */
const running = new Set();
const busy = () => new OwnerFlowError('This wallet setup is already running in this or another tab.', null, true);
const FIELDS = ['policyId', 'agent', 'amount', 'update'];
const changed = (identity) => new OwnerFlowError('update' in identity
    ? 'The saved signed step belongs to another change. It stays saved; resume that change first.'
    : 'Use the agent key and amount from the original wallet setup. The saved signed step stays saved.', null, false);
/** True when a saved value names these inputs. A value saved without inputs predates them and names none. */
function sameInputs(value, identity) {
    const named = FIELDS.filter(field => value[field] !== undefined);
    const inputs = identity;
    return named.length === 0 || named.length === Object.keys(inputs).length && named.every(field => value[field] === inputs[field]);
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
        throw changed(identity);
    return { step, signedPayload: value.signedPayload };
}
/** True when the funding or the update of these inputs is confirmed. A marker of other inputs is refused. */
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
        throw changed(identity);
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
function stepper({ network, historyPauseMs, ask, sign, journal, key, policyId, onStep, identity, confirmed }) {
    const receipts = [];
    const done = (step, receipt) => {
        confirmed(step);
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
    /** Settle the saved signed step, if the journal holds one, before anything else is prepared. */
    const settleSaved = async () => {
        const pending = saved(journal, key, identity);
        if (pending) {
            onStep('Checking the saved signed step…');
            if (!await submit(pending.step, pending.signedPayload))
                onStep('The saved step can never apply. Preparing a new one…');
        }
    };
    /** `complete` adds what the step needs beside the owner's signature, before the bytes enter the journal. */
    const signAndSubmit = async (step, complete) => {
        if (step.expiresAt <= Math.floor(Date.now() / 1000))
            throw new OwnerFlowError('The prepared owner step already expired. Resume to prepare a new one.', null, true);
        onStep(`Sign ${step.action.replace(/_/g, ' ')} in your wallet…`);
        const ownerSigned = await sign(step);
        if (typeof ownerSigned !== 'string' || !ownerSigned)
            throw new OwnerFlowError('Your wallet did not return the signed step.', null, false);
        const signedPayload = complete ? complete(ownerSigned) : ownerSigned;
        journal.set(key, JSON.stringify({ step, signedPayload, ...identity }));
        onStep('Waiting for the network to confirm…');
        if (!await submit(step, signedPayload))
            throw new OwnerFlowError('The network did not take the signed step. Resume to prepare a new one.', null, true);
    };
    return { receipts, settleSaved, signAndSubmit };
}
/** Whether the ledger holds `account`: true or false, or null when Horizon gives no clear answer. */
async function accountOnLedger(network, account) {
    const response = await horizonGet(network, `/accounts/${account}`);
    if (!response)
        return null;
    if (response.status === 404)
        return false;
    if (!response.ok)
        return null;
    try {
        const body = await response.json();
        return object(body) && body.account_id === account ? true : null;
    }
    catch {
        return null;
    }
}
/**
 * The fee account whose creation this journal signed for this policy and agent, and whether the journal saw that
 * creation confirmed, or undefined. The account can hold
 * the owner's XLM, so a marker is never dropped for other inputs: another funding amount keeps the account, and a
 * marker of another policy or agent, or one that cannot be read, is refused before anything is prepared.
 */
function savedFeeAccount(journal, key, identity) {
    const raw = journal.get(key);
    if (raw === null)
        return undefined;
    let value;
    try {
        value = JSON.parse(raw);
    }
    catch { /* refused below */ }
    // The server and the rail check the address.
    if (!object(value) || typeof value.feeAccount !== 'string' || !/^G[A-Z2-7]{55}$/.test(value.feeAccount)
        || value.policyId !== identity.policyId || value.agent !== identity.agent)
        throw changed({ ...identity, amount: '' });
    return { account: value.feeAccount, created: value.created === true };
}
async function run({ network, ask, sign, journal, key, policyId, agent, amount, onStep, historyPauseMs = 1_500 }) {
    if (!canonicalNetwork(network))
        throw new OwnerFlowError('Select a supported Stellar network.', null, false);
    const fundedKey = `${key}:funded`, feeAccountKey = `${key}:fee-account`;
    const identity = { policyId, agent, amount };
    const { receipts, settleSaved, signAndSubmit } = stepper({ network, historyPauseMs, ask, sign, journal, key, policyId, onStep, identity,
        // A confirmed funding is recorded before its signed bytes leave the journal. So is a confirmed creation of
        // the fee account: from then on the account exists, and nothing ever replaces it.
        confirmed: step => {
            if (step.action === 'fund')
                journal.set(fundedKey, JSON.stringify(identity));
            const named = step.action === CREATE_FEE_ACCOUNT ? savedFeeAccount(journal, feeAccountKey, { policyId, agent }) : undefined;
            if (named)
                journal.set(feeAccountKey, JSON.stringify({ feeAccount: named.account, policyId, agent, created: true }));
        } });
    // A saved step or a funded marker of other inputs is refused before anything is sent.
    saved(journal, key, identity);
    funded(journal, fundedKey, identity);
    await settleSaved();
    let wallet;
    // The setup key of the fee account is random and lives in this call only. It signs the creation once. The
    // journal keeps the address of an account whose creation was signed, never a key: after a reload the saved
    // signed step settles first, and the workflow names that account again.
    let feeKey;
    const named = savedFeeAccount(journal, feeAccountKey, { policyId, agent });
    let feeAccount = named?.account;
    // True once this journal saw the creation confirmed on the network.
    let created = named?.created ?? false;
    let replaced = false;
    // True once this run set up the wallet account of a Native policy: the deployment then names the wallet.
    let nativeSetUp = false;
    const walletSetupKey = `${key}:wallet-setup`;
    /** Creates and funds the agent's wallet account with one owner signature, and registers it for this policy. */
    const setUpWallet = async (details) => {
        const roles = object(details) ? details : {};
        if (typeof roles.owner !== 'string' || typeof roles.server !== 'string' || roles.agent !== agent || roles.policyId !== policyId)
            throw new OwnerFlowError('The service named no roles for the wallet account of this policy.', null, false);
        let setup;
        try {
            // The signed setup stays in the journal until the server has registered the wallet, so a run that
            // stops in between finds the same account again.
            setup = await setUpNativeWallet({ network, owner: roles.owner, agent, server: roles.server, amount, sign, onStep, journal, key: walletSetupKey, retain: true });
        }
        catch (cause) {
            if (cause instanceof OwnerFlowError)
                throw cause;
            throw new OwnerFlowError(cause instanceof Error ? cause.message : 'The wallet account could not be set up.', null, cause instanceof WalletSetupPendingError, cause);
        }
        receipts.push({ policyId, action: SET_UP_WALLET, status: 'confirmed', transactionHash: setup.transactionHash, ledger: setup.ledger });
        onStep('Registering the wallet…');
        const registered = await ask('native/register', { configuration: setup.configuration, policyId });
        if (!object(registered) || registered.registered !== true || registered.wallet !== setup.wallet || registered.policyId !== policyId)
            throw new OwnerFlowError('The service did not register the wallet account for this policy. Resume to register it; nothing is signed again.', null, true);
        // The setup funded the wallet: no funding step follows.
        journal.set(fundedKey, JSON.stringify(identity));
    };
    /** The owner's approval of the policy of a Native wallet: one message signature, and no transaction. */
    const approvePolicy = async (account) => {
        onStep('Preparing the approval…');
        const approval = await ask('native/approval', { policyId });
        if (!object(approval) || approval.required !== true)
            return;
        const fields = policyApproval(approval.message, network);
        if (!fields || fields.policyId !== policyId || fields.wallet !== account)
            throw new OwnerFlowError('The approval differs from this policy and its wallet account. Nothing was signed.', null, false);
        const signer = await ownerOf(account);
        onStep('Sign the approval of the policy in your wallet…');
        const signature = await sign(approvalStep(approval.message));
        await ask('micro/allocation/confirm', { id: policyId, revision: fields.revision, sourceApproval: [{ signer, signature: signatureBytes(signature) }] });
        receipts.push({ policyId, action: APPROVE_POLICY, status: 'confirmed', transactionHash: '' });
    };
    /** The owner of a wallet account: its signer of the owner's weight, read from the public ledger history. */
    const ownerOf = async (account) => {
        const response = await horizonGet(network, `/accounts/${account}`);
        const body = response?.ok ? await response.json().catch(() => null) : null;
        const signers = object(body) && Array.isArray(body.signers) ? body.signers : [];
        const owners = signers.filter(s => object(s) && s.weight === 3 && s.type === 'ed25519_public_key' && typeof s.key === 'string');
        if (owners.length !== 1)
            throw new OwnerFlowError('The owner of the wallet account could not be read from the network. Resume to read it again.', null, true);
        return owners[0].key;
    };
    // A deployment takes at most the fee account, the code upload, the wallet creation and a lifetime renewal.
    for (let i = 0; i < 5 && !wallet; i++) {
        onStep('Preparing the wallet…');
        let reply;
        try {
            reply = await ask('native/deploy/prepare', { policyId, agent, ...(feeAccount ? { setup: { feeAccount } } : {}) });
        }
        catch (error) {
            const { code, details } = (object(error) ? error : {});
            // A Native policy needs the wallet account of its agent. This workflow sets the account up from the
            // owner's own account, the server registers it, and the deployment then answers with the wallet.
            if (code === WALLET_SETUP_REQUIRED && !nativeSetUp) {
                await setUpWallet(details);
                nativeSetUp = true;
                i--;
                continue;
            }
            // A new policy wallet needs a fee account: this workflow makes its key, and the deployment creates and
            // funds the account. The agent holds a key and no account.
            // Boundary: a journal without a saved address names no account. That is the state of a new deployment,
            // and also of one that an earlier release (or another browser) took past its fee account and not to its
            // wallet. Neither the journal nor the ledger says which existing account no wallet uses, so this workflow
            // never adopts one: it makes a new account. An account of such an earlier run stays under the owner's key
            // alone, and the owner closes it; Horizon lists it under `accounts?signer=<owner>`.
            if (code !== FEE_ACCOUNT_REQUIRED || feeAccount)
                throw error;
            feeKey = newFeeAccountKey();
            feeAccount = feeKey.publicKey();
            i--;
            continue;
        }
        if (!object(reply) || reply.policyId !== policyId)
            throw new OwnerFlowError('The deployment reply names a different policy.', null, false);
        wallet = installedWallet(reply);
        if (wallet && reply.walletKind === 'native') {
            // The setup created and funded the wallet account. What remains is the owner's approval of the policy.
            journal.remove(walletSetupKey);
            if (reply.approved !== true)
                await approvePolicy(wallet);
            journal.remove(feeAccountKey);
            return { wallet, receipts };
        }
        if (wallet)
            break;
        const step = stepOf(reply.step);
        if (!step)
            throw new OwnerFlowError('The service did not prepare an owner step for this policy.', null, false);
        if (step.action === CREATE_FEE_ACCOUNT) {
            const setupKey = feeKey;
            if (!setupKey || setupKey.publicKey() !== feeAccount) {
                // This page holds no key for the account of this step. The ledger decides what that means. A saved
                // account that the ledger holds is created already: the service's step is stale, and the account stays.
                // Only an account that the ledger does not hold is replaced: its signed creation never applied, or
                // none was signed, so nothing holds funds. The workflow then makes a new key and names its account.
                if (replaced)
                    throw new OwnerFlowError('The service prepared a fee account that this workflow did not name.', null, false);
                if (feeAccount) {
                    const held = created ? true : await accountOnLedger(network, feeAccount);
                    if (held === true)
                        throw new OwnerFlowError('The service prepared the creation of a fee account that the network already holds. Nothing was signed; resume in a moment.', null, true);
                    if (held === null)
                        throw new OwnerFlowError('The fee account of this deployment could not be checked on the network. Nothing was signed; resume to check again.', null, true);
                }
                replaced = true;
                journal.remove(feeAccountKey);
                feeKey = newFeeAccountKey();
                feeAccount = feeKey.publicKey();
                i--;
                continue;
            }
            const account = feeAccount;
            // The new account's own key signs its creation once, beside the owner. The address enters the journal with
            // the signed bytes; the key is dropped.
            feeKey = undefined;
            await signAndSubmit(step, signedPayload => {
                try {
                    const signed = countersignCreation(network, step, signedPayload, setupKey);
                    journal.set(feeAccountKey, JSON.stringify({ feeAccount: account, policyId, agent }));
                    return signed;
                }
                catch (cause) {
                    throw new OwnerFlowError(cause instanceof Error ? cause.message : 'The fee account step could not be signed.', null, false, cause);
                }
            });
            created = true;
        }
        else
            await signAndSubmit(step);
    }
    if (wallet)
        journal.remove(feeAccountKey);
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
/** Canonical text of a JSON value: object keys in code-unit order at every level. */
function canonical(value) {
    if (Array.isArray(value))
        return `[${value.map(canonical).join(',')}]`;
    if (object(value))
        return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
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
export async function updateParams(input) {
    const name = `allowit.owner-flow:${input.key}`;
    if (running.has(name))
        throw busy();
    running.add(name);
    try {
        const locks = globalThis.navigator?.locks;
        if (!locks)
            return await runUpdate(input);
        return await locks.request(name, { ifAvailable: true }, async (lock) => {
            if (!lock)
                throw busy();
            return runUpdate(input);
        });
    }
    finally {
        running.delete(name);
    }
}
async function runUpdate({ network, ask, sign, journal, key, policyId, params, expectedRevision, onStep, historyPauseMs = 1_500 }) {
    if (!canonicalNetwork(network))
        throw new OwnerFlowError('Select a supported Stellar network.', null, false);
    if (!object(params) || Object.keys(params).length === 0 || Object.keys(params).length > 32)
        throw new OwnerFlowError('Change one to 32 params.', PARAM_INVALID, false);
    if (expectedRevision !== undefined && !(Number.isSafeInteger(expectedRevision) && expectedRevision >= 0))
        throw new OwnerFlowError('The expected revision is invalid.', REVISION_CHANGED, false);
    const updatedKey = `${key}:updated`;
    const identity = { policyId, update: canonical({ params, ...(expectedRevision === undefined ? {} : { expectedRevision }) }) };
    const { receipts, settleSaved, signAndSubmit } = stepper({ network, historyPauseMs, ask, sign, journal, key, policyId, onStep, identity,
        // A confirmed update is recorded before its signed bytes leave the journal.
        confirmed: step => { if (step.action === UPDATE_PARAMS)
            journal.set(updatedKey, JSON.stringify(identity)); } });
    // A saved step or a marker of another change is refused before anything is sent.
    saved(journal, key, identity);
    if (funded(journal, updatedKey, identity))
        return { receipts, done: true };
    await settleSaved();
    if (funded(journal, updatedKey, identity))
        return { receipts, done: true };
    onStep('Preparing the change…');
    let prepared;
    try {
        prepared = await ask('native/owner/prepare', { policyId, action: UPDATE_PARAMS, params, ...(expectedRevision === undefined ? {} : { expectedRevision }) });
    }
    catch (error) {
        // The service's reason and typed code reach the owner unchanged.
        const code = object(error) && typeof error.code === 'string' ? error.code : null;
        throw new OwnerFlowError(error instanceof Error && error.message ? error.message : 'The change could not be prepared.', code, code === NETWORK_UNAVAILABLE, error);
    }
    // A Native wallet holds no values on chain: its change is a new approval of the policy, with no transaction.
    if (object(prepared) && prepared.policyId === policyId && object(prepared.approval) && !prepared.step) {
        const message = prepared.approval.message, fields = policyApproval(message, network);
        if (!fields || fields.policyId !== policyId)
            throw new OwnerFlowError('The approval differs from this change. Nothing was signed.', null, false);
        onStep('Sign the approval of the new values in your wallet…');
        const signature = await sign(approvalStep(message));
        const response = await horizonGet(network, `/accounts/${fields.wallet}`);
        const body = response?.ok ? await response.json().catch(() => null) : null;
        const owners = (object(body) && Array.isArray(body.signers) ? body.signers : []).filter(s => object(s) && s.weight === 3 && s.type === 'ed25519_public_key' && typeof s.key === 'string');
        if (owners.length !== 1)
            throw new OwnerFlowError('The owner of the wallet account could not be read from the network. Nothing was saved; try again.', null, true);
        let receipt;
        try {
            receipt = await ask('native/owner/submit', { policyId, payload: message, sourceApproval: [{ signer: owners[0].key, signature: signatureBytes(signature) }] });
        }
        catch (error) {
            const code = object(error) && typeof error.code === 'string' ? error.code : null;
            throw new OwnerFlowError(error instanceof Error && error.message ? error.message : 'The change could not be saved.', code, code === NETWORK_UNAVAILABLE, error);
        }
        journal.set(updatedKey, JSON.stringify(identity));
        receipts.push({ policyId, action: UPDATE_PARAMS, status: 'confirmed', transactionHash: object(receipt) && typeof receipt.transactionHash === 'string' ? receipt.transactionHash : '' });
        return { receipts, done: true };
    }
    const step = stepOf(prepared?.step);
    if (!object(prepared) || prepared.policyId !== policyId || !step || step.action !== UPDATE_PARAMS)
        throw new OwnerFlowError('The reply differs from this change.', null, false);
    await signAndSubmit(step);
    return { receipts, done: true };
}
