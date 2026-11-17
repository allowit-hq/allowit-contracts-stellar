/**
 * The fee account of a policy wallet: the account that sends the agent's operations on the wallet and pays their
 * network fees. The owner's deployment creates and funds it. It has the signers of a wallet account: the owner alone
 * reaches every threshold, and the agent key and the server pay from it only together. The agent holds no account.
 *
 * This module adds the one signature of the account's random setup key to its creation, reads the account from
 * the public ledger history and prepares the owner's refill. The server takes no part in the read or the refill.
 */
import { Account, Asset, Keypair, Operation, StrKey, TransactionBuilder } from '@stellar/stellar-sdk/base';
import { sha256 } from '@noble/hashes/sha256';
import { networkPassphrase } from './plugin.js';
import { expiredRecord, horizonGet, horizonOrigin } from './chain-record.js';
/** The action of the owner step that creates the fee account. */
export const CREATE_FEE_ACCOUNT = 'create_fee_account';
/** The action of the owner step that refills the fee account. */
export const REFILL_FEES = 'refill_fees';
/** The typed refusal of a wallet creation that names no fee account. `details.wallet` is the policy wallet. */
export const FEE_ACCOUNT_REQUIRED = 'fee_account_required';
const BASE_RESERVE = 5000000n;
/** The float of a new fee account, in stroops: what the owner's deployment funds above the reserve. */
const FEE_FLOAT = 50000000n;
const hex = (bytes) => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
const object = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
/** The SEP-53 digest of a wallet message, as lowercase hexadecimal. */
export function messageDigest(message) {
    return hex(sha256(new TextEncoder().encode(`Stellar Signed Message:\n${message}`)));
}
/**
 * The setup key of a new fee account: random, held in memory by the caller and used once. Nothing stores, derives
 * or recovers it. The creation sets its weight to 0 and makes the owner a signer that reaches every threshold alone.
 */
export function newFeeAccountKey() {
    return Keypair.random();
}
/**
 * Adds the one signature of the new account's own key to the owner-signed creation of a fee account. The signed
 * bytes must be the reviewed step, and its first operation must create exactly the account of `key`.
 */
export function countersignCreation(network, step, signedPayload, key) {
    const tx = TransactionBuilder.fromXDR(signedPayload, networkPassphrase(network));
    if ('innerTransaction' in tx || hex(tx.hash()) !== step.hash)
        throw new Error('The wallet returned another transaction. Nothing was sent.');
    const first = tx.operations[0];
    if (first?.type !== 'createAccount' || first.destination !== key.publicKey() || tx.signatures.length !== 1)
        throw new Error('The fee account step does not create the account of this owner and agent. Nothing was sent.');
    tx.sign(key);
    return tx.toXDR();
}
/** The fee account that an installation, a wallet profile or a policy document names, or null. */
export function feeAccountOf(document) {
    const top = object(document) ? document : null;
    const config = top && (object(top.config) ? top.config : object(top.installation) ? top.installation : top);
    const address = config?.feeAccount;
    if (typeof address !== 'string' || !StrKey.isValidEd25519PublicKey(address))
        return null;
    const fee = config?.maxFeeStroops;
    return { address, maxFeeStroops: Number.isSafeInteger(fee) && fee > 0 ? fee : null };
}
function horizon(network) {
    const base = horizonOrigin(network);
    if (!base)
        throw new Error('Select a supported Stellar network.');
    return base;
}
/** Stroops of a decimal XLM amount with at most seven decimals, or null. */
export function stroops(amount) {
    const match = /^([0-9]{1,12})(?:\.([0-9]{1,7}))?$/.exec(amount);
    return match ? BigInt(match[1]) * 10000000n + BigInt((match[2] ?? '').padEnd(7, '0')) : null;
}
/** XLM text of stroops, without trailing zeros. */
export function xlmText(units) {
    const whole = units / 10000000n, fraction = (units % 10000000n).toString().padStart(7, '0').replace(/0+$/, '');
    return `${whole}${fraction ? `.${fraction}` : ''} XLM`;
}
/**
 * Reads the fee account of `document` from the public ledger history. Null when the document names none: a Native
 * wallet pays its own fees, and a policy wallet of an earlier release has the agent's own account pay them.
 */
export async function feeAccount(input) {
    const named = feeAccountOf(input.document);
    if (!named)
        return null;
    const response = await (input.fetch ?? fetch)(`${horizon(input.network)}/accounts/${named.address}`, { headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(15_000) });
    const refill = { amount: xlmText(FEE_FLOAT).replace(' XLM', ''), text: xlmText(FEE_FLOAT) };
    if (response.status === 404)
        return { address: named.address, exists: false, balance: '0', spendable: '0', low: true, text: xlmText(0n), refill };
    const account = response.ok ? await response.json().catch(() => null) : null;
    const native = object(account) && Array.isArray(account.balances) ? account.balances.find(b => object(b) && b.asset_type === 'native') : null;
    const balance = object(native) && typeof native.balance === 'string' ? stroops(native.balance) : null;
    const selling = object(native) && typeof native.selling_liabilities === 'string' ? stroops(native.selling_liabilities) ?? 0n : 0n;
    if (!object(account) || account.account_id !== named.address || balance === null || !Number.isSafeInteger(account.subentry_count))
        throw new Error('The fee account could not be read from the network.');
    const count = (v) => Number.isSafeInteger(v) ? BigInt(v) : 0n;
    const entries = 2n + BigInt(account.subentry_count) + count(account.num_sponsoring) - count(account.num_sponsored);
    const above = balance - selling - entries * BASE_RESERVE;
    const spendable = above > 0n ? above : 0n;
    // Two operations at the fee ceiling of the wallet; a 1 XLM ceiling when the document names none.
    const low = spendable < 2n * BigInt(named.maxFeeStroops ?? 10_000_000);
    return { address: named.address, exists: true, balance: balance.toString(), spendable: spendable.toString(), low, text: xlmText(spendable), refill };
}
/** An uncertain refill: the signed payment stays saved, and the next call settles it before it signs anything. */
export class RefillPendingError extends Error {
    retry = true;
    constructor(message, cause) {
        super(message, { cause });
        this.name = 'RefillPendingError';
    }
}
function savedRefill(journal, key) {
    if (!journal || !key)
        return null;
    const raw = journal.get(key);
    if (raw === null)
        return null;
    let value;
    try {
        value = JSON.parse(raw);
    }
    catch { /* unreadable below */ }
    if (!object(value) || typeof value.hash !== 'string' || !/^[0-9a-f]{64}$/.test(value.hash) || typeof value.signedPayload !== 'string'
        || !Number.isSafeInteger(value.expiresAt) || typeof value.owner !== 'string' || typeof value.feeAccount !== 'string' || typeof value.amount !== 'string')
        throw new RefillPendingError('The saved signed refill is unreadable. It stays saved; nothing was signed.');
    return value;
}
/**
 * Refills a fee account: one payment of XLM from the owner's account, which the owner's wallet signs. This module
 * builds the payment from the owner's own sequence and sends the signed bytes to the public network itself.
 *
 * With a journal, the signed bytes are saved before they are sent. A send whose result is unknown keeps them, and
 * the next call settles that payment first: it is done when the network holds it as successful, it is sent again
 * while its time bound lasts, and it is dropped only when the network holds it as failed or has read past its time
 * bound without it. Only then is a new payment prepared, so one refill is never paid twice.
 */
export async function refillFees(input) {
    // One refill runs per journal key: a second call in this page or, where the browser has Web Locks, in another
    // tab is refused before it reads the journal. So no call reads an empty journal while another one signs, and
    // no call removes the saved payment of another.
    if (!input.journal || !input.key)
        return refill(input);
    const name = `allowit.refill:${input.key}`;
    const busy = () => new RefillPendingError('A refill of this fee account is already running in this or another tab. Nothing was signed.');
    if (refilling.has(name))
        throw busy();
    refilling.add(name);
    try {
        const locks = globalThis.navigator?.locks;
        if (!locks)
            return await refill(input);
        return await locks.request(name, { ifAvailable: true }, async (lock) => {
            if (!lock)
                throw busy();
            return refill(input);
        });
    }
    finally {
        refilling.delete(name);
    }
}
/** Refills that run in this page, by lock name. */
const refilling = new Set();
async function refill({ network, owner, feeAccount: destination, amount, sign, onStep, journal, key, fetch: send = fetch }) {
    const units = stroops(amount);
    if (!StrKey.isValidEd25519PublicKey(owner) || !StrKey.isValidEd25519PublicKey(destination) || owner === destination)
        throw new Error('The refill needs the owner account and the fee account.');
    if (units === null || units <= 0n)
        throw new Error('Enter an amount of XLM with at most seven decimals.');
    const base = horizon(network), passphrase = networkPassphrase(network);
    const json = async (response) => response.json().catch(() => null);
    const get = (path) => send(`${base}${path}`, { headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(15_000) });
    const settled = (result, hash) => object(result) && result.hash === hash && result.successful === true && Number.isSafeInteger(result.ledger)
        ? { transactionHash: hash, ledger: result.ledger } : null;
    /** Sends signed bytes. Null means that the network gave no certain answer. */
    const submit = async (signedPayload, hash) => {
        const sent = await send(`${base}/transactions`, {
            method: 'POST', headers: { Accept: 'application/json', 'Content-Type': 'application/x-www-form-urlencoded' },
            body: `tx=${encodeURIComponent(signedPayload)}`, signal: AbortSignal.timeout(60_000),
        }).catch(() => null);
        return sent?.ok ? settled(await json(sent), hash) : null;
    };
    const pending = (cause) => new RefillPendingError('The network did not confirm the refill. The signed payment stays saved: refill again to check it. Nothing is signed twice.', cause);
    const saved = savedRefill(journal, key);
    if (saved && journal && key) {
        if (saved.owner !== owner || saved.feeAccount !== destination)
            throw new RefillPendingError('A signed refill of another account is saved under this key. It stays saved.');
        onStep('Checking the saved refill…');
        // The saved bytes decide: their hash and their own time bound, never the saved metadata.
        let validUntil;
        try {
            const tx = TransactionBuilder.fromXDR(saved.signedPayload, passphrase);
            if ('innerTransaction' in tx || hex(tx.hash()) !== saved.hash)
                throw new Error();
            validUntil = Number(tx.timeBounds?.maxTime);
            if (!Number.isSafeInteger(validUntil) || validUntil <= 0)
                throw new Error();
        }
        catch (cause) {
            throw new RefillPendingError('The saved signed refill is unreadable. It stays saved; nothing was signed.', cause);
        }
        const found = await horizonGet(network, `/transactions/${saved.hash}`, send);
        if (!found)
            throw pending();
        let replace = false;
        if (found.ok) {
            // Only the record of this exact payment settles it: successful, or failed in a ledger. Any other answer,
            // such as a cut or incomplete reply, proves nothing and keeps the payment saved.
            const record = await json(found);
            const done = settled(record, saved.hash);
            if (done) {
                journal.remove(key);
                return done;
            }
            if (!object(record) || record.hash !== saved.hash || record.successful !== false || !Number.isSafeInteger(record.ledger))
                throw pending();
            // The network holds the payment as failed: it used its sequence and can never apply.
            replace = true;
        }
        else if (found.status !== 404)
            throw pending();
        else if (validUntil >= Math.floor(Date.now() / 1000)) {
            // The same signed bytes go again while their time bound lasts.
            const done = await submit(saved.signedPayload, saved.hash);
            if (!done)
                throw pending();
            journal.remove(key);
            return done;
        }
        else {
            // Past its time bound a missing record proves nothing: history can lack an applied payment. The payment
            // never applied only when the owner's sequence is still below the payment's sequence.
            const record = await expiredRecord(network, saved.hash, saved.signedPayload, send).catch(cause => { throw pending(cause); });
            if (record) {
                journal.remove(key);
                return { transactionHash: saved.hash, ledger: record.ledger };
            }
            replace = true;
        }
        if (replace)
            journal.remove(key);
    }
    onStep('Preparing the refill…');
    const read = await get(`/accounts/${owner}`);
    const account = read.ok ? await json(read) : null;
    if (!object(account) || account.account_id !== owner || typeof account.sequence !== 'string' || !/^[0-9]{1,19}$/.test(account.sequence))
        throw new Error('The owner account could not be read from the network.');
    const tx = new TransactionBuilder(new Account(owner, account.sequence), { fee: '100', networkPassphrase: passphrase })
        .addOperation(Operation.payment({ destination, asset: Asset.native(), amount }))
        .setTimeout(300)
        .build();
    const hash = hex(tx.hash()), expiresAt = Number(tx.timeBounds?.maxTime);
    onStep('Sign the refill in your wallet…');
    const signedPayload = await sign({ action: REFILL_FEES, payload: tx.toXDR(), hash, expiresAt });
    const signed = TransactionBuilder.fromXDR(signedPayload, passphrase);
    if ('innerTransaction' in signed || hex(signed.hash()) !== hash || signed.signatures.length !== 1)
        throw new Error('The wallet returned another transaction. Nothing was sent.');
    // The signed bytes are saved before they leave: an unknown result is settled from them, never signed again.
    if (journal && key)
        journal.set(key, JSON.stringify({ hash, signedPayload, expiresAt, owner, feeAccount: destination, amount }));
    onStep('Waiting for the network to confirm…');
    const done = await submit(signedPayload, hash);
    if (!done) {
        if (journal && key)
            throw pending();
        throw new Error('The network did not confirm the refill. Check the fee account balance before you sign again.');
    }
    if (journal && key)
        journal.remove(key);
    return done;
}
