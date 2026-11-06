import { Account, FeeBumpTransaction, Keypair, Memo, Operation, Transaction, TransactionBuilder, Networks, xdr } from '@stellar/stellar-sdk/base';
import { sha256 } from '@noble/hashes/sha256';
import { STELLAR_OWNER_FRAGMENT } from './stellar-fragments.js';
export { STELLAR_OWNER_FRAGMENT } from './stellar-fragments.js';
export const STELLAR_OWNER_PROFILE = 'allowit-stellar-owner-v1';
const keys = ['version', 'profile', 'requestId', 'network', 'owner', 'agent', 'engine', 'sequence', 'feeStroops', 'expiresAt', 'transactionXdr', 'transactionHash', 'intentDigest'];
import { hex, digest } from './consent-codec.js';
export const stellarOwnerDigest = (v) => digest(JSON.stringify([STELLAR_OWNER_PROFILE, v.requestId, v.network, v.owner, v.agent, v.engine, v.sequence, v.feeStroops, v.expiresAt, v.transactionHash]));
export function decodePublicFragment(fragment, prefix) {
    if (!fragment.startsWith(prefix) || fragment.length > 65_536)
        throw new Error('The owner signing link is invalid or too large.');
    const encoded = fragment.slice(prefix.length);
    if (!/^[A-Za-z0-9_-]+$/.test(encoded))
        throw new Error('The owner signing link is invalid.');
    try {
        const raw = atob(encoded.replace(/-/g, '+').replace(/_/g, '/'));
        if (btoa(raw).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') !== encoded)
            throw new Error();
        return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Uint8Array.from(raw, c => c.charCodeAt(0))));
    }
    catch {
        throw new Error('The owner signing link is invalid.');
    }
}
export function nativeSetupTransaction(v) {
    return new TransactionBuilder(new Account(v.owner, (BigInt(v.sequence) - 1n).toString()), { fee: String(v.feeStroops / 3), networkPassphrase: Networks.TESTNET })
        .addOperation(Operation.setOptions({ signer: { ed25519PublicKey: v.agent, weight: 1 } }))
        .addOperation(Operation.setOptions({ signer: { ed25519PublicKey: v.engine, weight: 1 } }))
        .addOperation(Operation.setOptions({ masterWeight: 3, lowThreshold: 2, medThreshold: 2, highThreshold: 3 }))
        .addMemo(Memo.hash(sha256(new TextEncoder().encode(v.requestId))))
        .setTimebounds(0, v.expiresAt).build();
}
export function checkStellarOwnerIntent(v) {
    if (!v || typeof v !== 'object' || Array.isArray(v) || Object.keys(v).length !== keys.length || Object.keys(v).some(k => !keys.includes(k)))
        throw new Error('The native setup fields are invalid.');
    const value = v;
    if (value.version !== 1 || value.profile !== STELLAR_OWNER_PROFILE || value.network !== 'stellar:testnet'
        || typeof value.requestId !== 'string' || !/^[A-Za-z0-9._:-]{8,100}$/.test(value.requestId)
        || typeof value.sequence !== 'string' || !/^[1-9][0-9]*$/.test(value.sequence) || BigInt(value.sequence) > 9223372036854775807n
        || !Number.isInteger(value.feeStroops) || value.feeStroops < 300 || value.feeStroops > 300_000 || value.feeStroops % 3 !== 0
        || !Number.isSafeInteger(value.expiresAt) || value.expiresAt <= 0
        || typeof value.transactionHash !== 'string' || !/^[0-9a-f]{64}$/.test(value.transactionHash)
        || typeof value.transactionXdr !== 'string' || value.transactionXdr.length > 4096
        || typeof value.intentDigest !== 'string' || !/^[0-9a-f]{64}$/.test(value.intentDigest))
        throw new Error('The native setup link does not contain a supported Testnet request.');
    try {
        for (const address of [value.owner, value.agent, value.engine])
            if (Keypair.fromPublicKey(address).publicKey() !== address)
                throw new Error();
        if (new Set([value.owner, value.agent, value.engine]).size !== 3)
            throw new Error();
        const expected = nativeSetupTransaction(value);
        if (expected.toXDR() !== value.transactionXdr || hex(expected.hash()) !== value.transactionHash || stellarOwnerDigest(value) !== value.intentDigest)
            throw new Error();
    }
    catch {
        throw new Error('The owner, signer roles or exact native setup transaction changed. Nothing was signed.');
    }
}
export function parseStellarOwnerIntent(fragment) {
    const v = decodePublicFragment(fragment, STELLAR_OWNER_FRAGMENT);
    checkStellarOwnerIntent(v);
    return v;
}
export function checkStellarEngineIdentity(v, config) {
    if (!config || typeof config !== 'object')
        throw new Error('The configured Stellar engine identity is unavailable.');
    const c = config;
    if (c.profile !== 'allowit-stellar-wallet-v1' || !Array.isArray(c.networks) || !c.networks.includes(v.network) || c.enginePublicKey !== v.engine)
        throw new Error('The native setup engine differs from the configured Stellar service. Nothing was signed.');
}
export function verifyStellarOwnerSignature(v, signed) {
    checkStellarOwnerIntent(v);
    if (typeof signed !== 'string' || signed.length > 8192)
        throw new Error('The signed native setup exceeds its bounds.');
    const tx = TransactionBuilder.fromXDR(signed, Networks.TESTNET);
    if (!(tx instanceof Transaction) || hex(tx.hash()) !== v.transactionHash || tx.signatures.length !== 1)
        throw new Error('The wallet changed the native setup transaction.');
    const sig = tx.signatures[0], key = Keypair.fromPublicKey(v.owner);
    if (hex(sig.hint.value) !== hex(key.signatureHint()) || !key.verify(tx.hash(), sig.signature.value))
        throw new Error('The native setup signature does not belong to its owner.');
    tx.signatures.splice(0);
    if (tx.toXDR() !== v.transactionXdr)
        throw new Error('The signed transaction differs from the reviewed native setup.');
}
const HORIZON = 'https://horizon-testnet.stellar.org';
export const stellarOwnerTransport = (path, init) => fetch(HORIZON + path, { ...init, credentials: 'omit', redirect: 'error' });
async function json(response) {
    const text = await response.text();
    if (text.length > 1_048_576)
        throw new Error('Stellar returned too much data.');
    const v = JSON.parse(text);
    if (!v || typeof v !== 'object' || Array.isArray(v))
        throw new Error('Stellar returned invalid data.');
    return v;
}
/** The SDK issues 300 s links; 30 s more absorbs browser and CLI clock skew. Signed proofs stay recoverable after expiry. */
export const STELLAR_OWNER_UNSIGNED_WINDOW = 330;
/** An unsigned entry carries no authority. Only one inside its admissible window reserves the owner sequence. */
export const unsignedStellarOwnerOpen = (v, now = Math.floor(Date.now() / 1000)) => v.expiresAt > now && v.expiresAt <= now + STELLAR_OWNER_UNSIGNED_WINDOW;
/** Unsigned admissibility only. A too-far expiry is reported apart from an expired one; it usually means a wrong clock. */
export function checkUnsignedStellarOwnerWindow(v, now = Math.floor(Date.now() / 1000)) {
    if (v.expiresAt <= now)
        throw new Error('This unsigned setup expired. Prepare a new request in the CLI.');
    if (v.expiresAt > now + STELLAR_OWNER_UNSIGNED_WINDOW)
        throw new Error('This setup expires too far ahead. Check this device’s clock, then prepare a new request in the CLI.');
}
/** Verify current native authority immediately before requesting a wallet signature. */
export async function verifyFreshStellarOwner(v, transport = stellarOwnerTransport, now = Math.floor(Date.now() / 1000)) {
    checkStellarOwnerIntent(v);
    checkUnsignedStellarOwnerWindow(v, now);
    const root = await transport('/');
    if (!root.ok || (await json(root)).network_passphrase !== Networks.TESTNET)
        throw new Error('The Stellar endpoint uses another network.');
    const response = await transport('/accounts/' + v.owner);
    if (!response.ok)
        throw new Error('The owner account is unavailable.');
    const a = await json(response), t = a.thresholds, s = a.signers;
    if (a.account_id !== v.owner || a.sequence !== (BigInt(v.sequence) - 1n).toString() || a.subentry_count !== 0
        || !t || t.low_threshold !== 0 || t.med_threshold !== 0 || t.high_threshold !== 0 || !Array.isArray(s) || s.length !== 1
        || s[0].key !== v.owner || s[0].type !== 'ed25519_public_key' || s[0].weight !== 1)
        throw new Error('Current owner authority, account sequence or entries differ. Nothing was signed.');
}
const plain = (v) => v && typeof v === 'object' && !Array.isArray(v) ? v : null;
/**
 * Binds a settled envelope and result to the exact inner owner bytes. Horizon serves a third-party fee bump under the
 * inner hash with the outer envelope (CAP-15); only the inner owner transaction is returned for saving and replay.
 */
function settledOwnerProof(v, receipt) {
    const mismatch = () => new Error('The Stellar receipt does not match this request.');
    const envelopeXdr = receipt.envelope_xdr, resultXdr = receipt.result_xdr, successful = receipt.successful;
    if (typeof envelopeXdr !== 'string' || envelopeXdr.length > 16_384 || typeof resultXdr !== 'string' || resultXdr.length > 16_384 || typeof successful !== 'boolean')
        throw mismatch();
    const { envelope, result } = (() => {
        try {
            return { envelope: TransactionBuilder.fromXDR(envelopeXdr, Networks.TESTNET), result: xdr.TransactionResult.fromXDR(resultXdr, 'base64') };
        }
        catch {
            throw mismatch();
        }
    })();
    const outcome = result.result;
    if (!(envelope instanceof FeeBumpTransaction)) {
        if (receipt.fee_bump_transaction !== undefined || receipt.inner_transaction !== undefined
            || outcome.type === 'txFeeBumpInnerSuccess' || outcome.type === 'txFeeBumpInnerFailed' || (outcome.type === 'txSuccess') !== successful)
            throw mismatch();
        return { signedXdr: envelopeXdr, successful };
    }
    const inner = plain(receipt.inner_transaction), outer = plain(receipt.fee_bump_transaction), outerHash = hex(envelope.hash());
    if (!inner || !outer || inner.hash !== v.transactionHash || outer.hash !== outerHash || outerHash === v.transactionHash
        || hex(envelope.innerTransaction.hash()) !== v.transactionHash)
        throw mismatch();
    if (outcome.type !== 'txFeeBumpInnerSuccess' && outcome.type !== 'txFeeBumpInnerFailed')
        throw mismatch();
    const pair = outcome.innerResultPair;
    // Outer INNER_SUCCESS needs inner txSUCCESS; outer INNER_FAILED needs a failing inner result.
    if (hex(pair.transactionHash.value) !== v.transactionHash
        || (outcome.type === 'txFeeBumpInnerSuccess') !== successful || (pair.result.result.type === 'txSuccess') !== successful)
        throw mismatch();
    return { signedXdr: envelope.innerTransaction.toXDR(), successful };
}
/** A receipt must name the exact original hash, owner bytes and result. Unknown status retains its signed proof. */
export async function stellarOwnerStatus(record, transport = stellarOwnerTransport) {
    checkStellarOwnerIntent(record.intent);
    if (record.signedXdr)
        verifyStellarOwnerSignature(record.intent, record.signedXdr);
    const response = await transport('/transactions/' + record.intent.transactionHash);
    // A fresh 404 cannot prove absence: a signed proof stays unknown and keeps blocking.
    if (response.status === 404)
        return record.signedXdr ? { intent: record.intent, signedXdr: record.signedXdr, status: 'unknown' } : { intent: record.intent, status: 'unsigned' };
    if (!response.ok)
        throw new Error('Stellar status is unavailable. Keep the original signed transaction.');
    const receipt = await json(response);
    if (receipt.hash !== record.intent.transactionHash || (receipt.id !== undefined && receipt.id !== receipt.hash) || !Number.isSafeInteger(receipt.ledger) || Number(receipt.ledger) <= 0)
        throw new Error('The Stellar receipt does not match this request.');
    const settled = settledOwnerProof(record.intent, receipt);
    verifyStellarOwnerSignature(record.intent, settled.signedXdr);
    if (record.signedXdr && settled.signedXdr !== record.signedXdr)
        throw new Error('The settled envelope differs from the saved signed proof.');
    return { intent: record.intent, signedXdr: settled.signedXdr, status: settled.successful ? 'confirmed' : 'failed', ledger: Number(receipt.ledger) };
}
/** Broadcast only the exact retained native envelope. Callers own retention and recovery sequencing. */
export async function broadcastStellarOwner(record, transport = stellarOwnerTransport) {
    if (!record.signedXdr)
        throw new Error('There is no saved signed transaction.');
    verifyStellarOwnerSignature(record.intent, record.signedXdr);
    await transport('/transactions', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ tx: record.signedXdr }).toString() });
}
export function decodeStellarOwnerRecord(raw, v) {
    if (raw.length > 16_384)
        throw new Error('The saved native setup proof exceeds its bounds.');
    const record = JSON.parse(raw);
    checkStellarOwnerIntent(record.intent);
    if (JSON.stringify(record.intent) !== JSON.stringify(v) || !['unsigned', 'unknown', 'confirmed', 'failed'].includes(record.status))
        throw new Error('This request ID already binds another native setup.');
    if (record.signedXdr)
        verifyStellarOwnerSignature(v, record.signedXdr);
    else if (record.status !== 'unsigned')
        throw new Error('The saved signed proof is missing. Keep this journal.');
    return record;
}
export async function stellarOwnerSupersessionProof(prior, next, transport = stellarOwnerTransport) {
    if (!prior.signedXdr || prior.intent.expiresAt >= Math.floor(Date.now() / 1000))
        return null;
    try {
        const response = await transport('/ledgers?order=desc&limit=1', { cache: 'no-store' });
        if (!response.ok)
            return null;
        const embedded = plain((await json(response))._embedded), records = embedded?.records;
        if (!Array.isArray(records) || records.length !== 1)
            return null;
        const ledger = plain(records[0]), closedAt = ledger?.closed_at, sequence = ledger?.sequence;
        if (typeof closedAt !== 'string' || !Number.isSafeInteger(sequence) || Number(sequence) <= 0
            || !Number.isFinite(Date.parse(closedAt)) || Date.parse(closedAt) <= prior.intent.expiresAt * 1000)
            return null;
        // Read account authority after the finalized expiry boundary, and bind it to this new request's sequence.
        await verifyFreshStellarOwner(next, async (path, init) => transport(path, { ...init, cache: 'no-store' }));
        return { ledger: sequence, closedAt, owner: next.owner, sequence: (BigInt(next.sequence) - 1n).toString(), requestId: next.requestId };
    }
    catch {
        return null;
    }
}
