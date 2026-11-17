/**
 * The Native wallet of an agent: a new classic account, one for each agent. The owner creates and funds it with one
 * signed transaction. That transaction also sets its signers: the owner alone reaches every threshold, and the agent
 * key and the server pay from it only together. The account's own key is random, signs the creation once and then
 * has weight 0. The agent holds a key and no account.
 *
 * This module builds the setup from the owner's own sequence, sends the signed bytes to the public network itself
 * and returns the installation document that the server registers. The server takes no part in the setup.
 */
import { Account, Keypair, Memo, Operation, StrKey, TransactionBuilder } from '@stellar/stellar-sdk/base';
import { sha256 } from '@noble/hashes/sha256';
import { canonicalNetwork, networkPassphrase } from './plugin.js';
import { ChainUnchecked, expiredRecord, horizonGet, horizonOrigin } from './chain-record.js';
import { stellarAssetContract } from './stellar-asset.js';
/** The action of the owner step that creates the agent's wallet account. */
export const SET_UP_WALLET = 'set_up_wallet';
/**
 * The action of the owner step that approves the policy of a wallet account. It signs a message and moves nothing.
 * Its payload is the base64 text of the message, as UTF-8, and its hash is the SEP-53 digest of the message.
 */
export const APPROVE_POLICY = 'approve_policy';
/** The typed refusal of a deployment whose policy needs the wallet account of its agent. `details` names the roles. */
export const WALLET_SETUP_REQUIRED = 'wallet_setup_required';
/** The weight of the owner signer: every threshold, alone. */
export const OWNER_WEIGHT = 3;
/** The weight of the agent signer and of the server signer. */
export const AUTOMATED_WEIGHT = 1;
/** The low and medium thresholds: the agent and the server together. */
export const PAYMENT_THRESHOLD = 2;
/** The high threshold: the owner alone. */
export const OWNER_THRESHOLD = 3;
const BASE_RESERVE = 5000000n;
/** What the network locks in a wallet account, in stroops: the account and its three signers. */
export const WALLET_RESERVE = 5n * BASE_RESERVE;
/** The XLM that a new wallet holds above its reserve and its funding, in stroops. It pays the fees of the owner's own steps. */
export const WALLET_FEE_FLOAT = 5000000n;
/** The most that one setup funds, in stroops. */
const MAX_FUNDING = 1000000000000000n;
/** The policy source of a wallet account before its owner approves a policy: transfers in the installed asset. */
const BOOTSTRAP_SOURCE = 'use allowit::prelude::*;\n/// Bootstrap: transfers in the installed asset.\npub fn execute(ctx: &AllowitContext) -> allowit::Result {\n    allowit::operations(ctx, &ctx.params[allowit::OPERATIONS])?;\n    allowit::tokens(ctx, &ctx.params[allowit::TOKENS])?;\n    Ok(())\n}\n';
const hex = (bytes) => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
const digest = (text) => sha256(new TextEncoder().encode(text));
const object = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
/** Stroops of a decimal XLM amount with at most seven decimals, or null. */
function stroops(amount) {
    const match = /^([0-9]{1,12})(?:\.([0-9]{1,7}))?$/.exec(amount);
    return match ? BigInt(match[1]) * 10000000n + BigInt((match[2] ?? '').padEnd(7, '0')) : null;
}
/** Decimal XLM text of stroops, as an operation amount takes it. */
function decimal(units) {
    return `${units / 10000000n}.${(units % 10000000n).toString().padStart(7, '0')}`;
}
function roles(owner, wallet, agent, server) {
    for (const [name, address] of [['owner', owner], ['wallet', wallet], ['agent', agent], ['server', server]])
        if (!StrKey.isValidEd25519PublicKey(address))
            throw new Error(`The ${name} account is invalid.`);
    if (new Set([owner, wallet, agent, server]).size !== 4)
        throw new Error('The owner, the wallet, the agent and the server must be four accounts.');
}
/** The balance that a new wallet starts with, in stroops: its reserve, its fee float and the owner's funding. */
export function walletStartingBalance(funding) {
    if (funding < 0n || funding > MAX_FUNDING)
        throw new Error('The funding amount is out of range.');
    return WALLET_RESERVE + WALLET_FEE_FLOAT + funding;
}
/**
 * The installation document of a wallet account, as the server registers it. It is the document of the rail's own
 * setup: the same identity, the bootstrap source and the native asset. The server reads the roles from the ledger
 * and refuses a document that the account does not match.
 */
export function nativeWalletConfiguration(network, wallet, owner, agent, server) {
    const id = canonicalNetwork(network);
    if (!id)
        throw new Error('Select a supported Stellar network.');
    roles(owner, wallet, agent, server);
    const asset = stellarAssetContract('XLM', null, networkPassphrase(id));
    return {
        network: id, policyInstance: Array.from(digest(`allowit-stellar-native-wallet-v1:${id}:${wallet}`)), wallet, owner, agent, server,
        route: 'native', language: 'portable',
        params: { operations: { List: [{ Str: 'transfer' }] }, tokens: { List: [{ Addr: asset }] } },
        asset, assetSymbol: 'XLM', assetIssuer: null, policySource: BOOTSTRAP_SOURCE, sourceHash: Array.from(digest(BOOTSTRAP_SOURCE)),
        moduleDigest: Array.from(new Uint8Array(32)), maxFeeStroops: 100_000,
    };
}
/**
 * The setup transaction of a wallet account. Its operations are one atomic unit: the creation with the starting
 * balance, the owner signer, the agent signer, and last the server signer with the thresholds and weight 0 for the
 * account's own key. The owner's account is the source and pays the fee.
 */
export function nativeSetupTransaction({ network, owner, sequence, wallet, agent, server, funding, requestId, expiresAt }) {
    roles(owner, wallet, agent, server);
    if (!/^[0-9]{1,19}$/.test(sequence))
        throw new Error('The owner account sequence is invalid.');
    if (!/^[A-Za-z0-9._:-]{8,100}$/.test(requestId))
        throw new Error('The setup request identity is invalid.');
    if (!Number.isSafeInteger(expiresAt) || expiresAt <= 0)
        throw new Error('The setup time bound is invalid.');
    const signer = (ed25519PublicKey, weight) => ({ ed25519PublicKey, weight });
    return new TransactionBuilder(new Account(owner, sequence), {
        fee: '100', networkPassphrase: networkPassphrase(network), timebounds: { minTime: 0, maxTime: expiresAt }, memo: Memo.hash(hex(digest(requestId))),
    })
        .addOperation(Operation.createAccount({ destination: wallet, startingBalance: decimal(walletStartingBalance(funding)) }))
        .addOperation(Operation.setOptions({ source: wallet, signer: signer(owner, OWNER_WEIGHT) }))
        .addOperation(Operation.setOptions({ source: wallet, signer: signer(agent, AUTOMATED_WEIGHT) }))
        .addOperation(Operation.setOptions({
        source: wallet, masterWeight: 0, lowThreshold: PAYMENT_THRESHOLD, medThreshold: PAYMENT_THRESHOLD, highThreshold: OWNER_THRESHOLD,
        signer: signer(server, AUTOMATED_WEIGHT),
    }))
        .build();
}
/**
 * What a setup transaction does, read from its bytes: the wallet account that it creates, its roles and its
 * starting balance. Null for any other transaction: one that lacks an operation, adds another, names another
 * signer weight or threshold, or leaves the account's own key a weight.
 */
export function nativeSetupOf(payload, network) {
    let tx;
    try {
        const parsed = TransactionBuilder.fromXDR(payload, networkPassphrase(network));
        if ('innerTransaction' in parsed)
            return null;
        tx = parsed;
    }
    catch {
        return null;
    }
    const [create, first, second, last, ...rest] = tx.operations;
    if (rest.length || create?.type !== 'createAccount' || create.source !== undefined)
        return null;
    const wallet = create.destination, starting = stroops(create.startingBalance);
    if (starting === null)
        return null;
    const plain = (op, weight) => {
        if (op?.type !== 'setOptions' || op.source !== wallet || !op.signer || !('ed25519PublicKey' in op.signer) || op.signer.weight !== weight)
            return null;
        const other = [op.masterWeight, op.lowThreshold, op.medThreshold, op.highThreshold, op.inflationDest, op.clearFlags, op.setFlags, op.homeDomain];
        const key = op.signer.ed25519PublicKey;
        return typeof key === 'string' && other.every(value => value === undefined) ? key : null;
    };
    const owner = plain(first, OWNER_WEIGHT), agent = plain(second, AUTOMATED_WEIGHT);
    if (owner === null || agent === null || tx.source !== owner)
        return null;
    if (last?.type !== 'setOptions' || last.source !== wallet || !last.signer || !('ed25519PublicKey' in last.signer) || last.signer.weight !== AUTOMATED_WEIGHT
        || last.masterWeight !== 0 || last.lowThreshold !== PAYMENT_THRESHOLD || last.medThreshold !== PAYMENT_THRESHOLD || last.highThreshold !== OWNER_THRESHOLD
        || [last.inflationDest, last.clearFlags, last.setFlags, last.homeDomain].some(value => value !== undefined))
        return null;
    const server = last.signer.ed25519PublicKey;
    if (typeof server !== 'string')
        return null;
    try {
        roles(owner, wallet, agent, server);
    }
    catch {
        return null;
    }
    return { owner, wallet, agent, server, startingBalance: starting };
}
/** An uncertain setup: the signed transaction stays saved, and the next call settles it before it signs anything. */
export class WalletSetupPendingError extends Error {
    retry = true;
    constructor(message, cause) {
        super(message, { cause });
        this.name = 'WalletSetupPendingError';
    }
}
function savedSetup(journal, key) {
    const raw = journal.get(key);
    if (raw === null)
        return null;
    let value;
    try {
        value = JSON.parse(raw);
    }
    catch { /* unreadable below */ }
    if (!object(value) || typeof value.hash !== 'string' || !/^[0-9a-f]{64}$/.test(value.hash) || typeof value.signedPayload !== 'string'
        || typeof value.owner !== 'string' || typeof value.agent !== 'string' || typeof value.server !== 'string' || typeof value.amount !== 'string')
        throw new WalletSetupPendingError('The saved signed wallet setup is unreadable. It stays saved; nothing was signed.');
    return value;
}
/** Setups that run in this page, by lock name. */
const running = new Set();
/**
 * Sets up the wallet account of an agent: one transaction that the owner's wallet signs. The account's own key is
 * random and lives in this call only; it signs the creation once, beside the owner.
 *
 * The signed bytes are saved before they are sent. A send whose result is unknown keeps them, and the next call
 * settles that setup first: it is done when the network holds it as successful, it is sent again while its time
 * bound lasts, and it is dropped only when the network holds it as failed or has read past its time bound without
 * it. Only then is a new setup prepared, so one call never creates two wallets. A setup that stopped before the
 * owner signed names a new account on its next run: nothing was signed for the earlier one.
 */
export async function setUpNativeWallet(input) {
    const name = `allowit.wallet-setup:${input.key}`;
    const busy = () => new WalletSetupPendingError('This wallet setup is already running in this or another tab. Nothing was signed.');
    if (running.has(name))
        throw busy();
    running.add(name);
    try {
        const locks = globalThis.navigator?.locks;
        if (!locks)
            return await setUp(input);
        return await locks.request(name, { ifAvailable: true }, async (lock) => {
            if (!lock)
                throw busy();
            return setUp(input);
        });
    }
    finally {
        running.delete(name);
    }
}
async function setUp({ network, owner, agent, server, amount, sign, onStep, journal, key, retain = false, fetch: send = fetch }) {
    const id = canonicalNetwork(network), base = horizonOrigin(network);
    if (!id || !base)
        throw new Error('Select a supported Stellar network.');
    const funding = stroops(amount);
    if (funding === null)
        throw new Error('Enter an amount of XLM with at most seven decimals.');
    const passphrase = networkPassphrase(id);
    const json = async (response) => response.json().catch(() => null);
    const pending = (cause) => new WalletSetupPendingError('The network did not confirm the wallet setup. The signed setup stays saved: resume to check it. Nothing is signed twice.', cause);
    const result = (wallet, hash, ledger) => ({ wallet, transactionHash: hash, ledger, configuration: nativeWalletConfiguration(id, wallet, owner, agent, server) });
    const settled = (record, hash) => object(record) && record.hash === hash && record.successful === true && Number.isSafeInteger(record.ledger)
        ? record.ledger : null;
    /** Sends signed bytes. Null means that the network gave no certain answer. */
    const submit = async (signedPayload, hash) => {
        const sent = await send(`${base}/transactions`, {
            method: 'POST', headers: { Accept: 'application/json', 'Content-Type': 'application/x-www-form-urlencoded' },
            body: `tx=${encodeURIComponent(signedPayload)}`, signal: AbortSignal.timeout(60_000),
        }).catch(() => null);
        return sent?.ok ? settled(await json(sent), hash) : null;
    };
    const saved = savedSetup(journal, key);
    if (saved) {
        if (saved.owner !== owner || saved.agent !== agent || saved.server !== server || saved.amount !== amount)
            throw new WalletSetupPendingError('A signed wallet setup with another agent key or amount is saved. It stays saved; use the agent key and amount of that setup.');
        onStep('Checking the saved wallet setup…');
        // The saved bytes decide: their hash, the account that they create and their own time bound.
        const setup = nativeSetupOf(saved.signedPayload, id);
        let validUntil = NaN;
        try {
            const tx = TransactionBuilder.fromXDR(saved.signedPayload, passphrase);
            if (!('innerTransaction' in tx) && hex(tx.hash()) === saved.hash)
                validUntil = Number(tx.timeBounds?.maxTime);
        }
        catch { /* unreadable below */ }
        if (!setup || setup.owner !== owner || setup.agent !== agent || setup.server !== server || !Number.isSafeInteger(validUntil) || validUntil <= 0)
            throw new WalletSetupPendingError('The saved signed wallet setup is unreadable. It stays saved; nothing was signed.');
        const found = await horizonGet(id, `/transactions/${saved.hash}`, send);
        if (!found)
            throw pending();
        if (found.ok) {
            // Only the record of this exact transaction settles it: successful, or failed in a ledger.
            const record = await json(found);
            const ledger = settled(record, saved.hash);
            if (ledger !== null) {
                if (!retain)
                    journal.remove(key);
                return result(setup.wallet, saved.hash, ledger);
            }
            if (!object(record) || record.hash !== saved.hash || record.successful !== false || !Number.isSafeInteger(record.ledger))
                throw pending();
            // The network holds the setup as failed: it used its sequence, created nothing and can never apply.
        }
        else if (found.status !== 404)
            throw pending();
        else if (validUntil >= Math.floor(Date.now() / 1000)) {
            // The same signed bytes go again while their time bound lasts.
            const ledger = await submit(saved.signedPayload, saved.hash);
            if (ledger === null)
                throw pending();
            if (!retain)
                journal.remove(key);
            return result(setup.wallet, saved.hash, ledger);
        }
        else {
            // Past its time bound a missing record proves nothing: history can lack an applied setup.
            const record = await expiredRecord(id, saved.hash, saved.signedPayload, send).catch(cause => { throw pending(cause instanceof ChainUnchecked ? cause : undefined); });
            if (record) {
                if (!retain)
                    journal.remove(key);
                return result(setup.wallet, saved.hash, record.ledger);
            }
        }
        journal.remove(key);
    }
    onStep('Preparing the wallet…');
    const read = await send(`${base}/accounts/${owner}`, { headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(15_000) }).catch(() => null);
    const account = read?.ok ? await json(read) : null;
    if (!object(account) || account.account_id !== owner || typeof account.sequence !== 'string' || !/^[0-9]{1,19}$/.test(account.sequence))
        throw new Error('The owner account could not be read from the network.');
    // The setup key is random and lives in this call only. Nothing stores, derives or recovers it.
    const setupKey = Keypair.random(), wallet = setupKey.publicKey();
    const requestId = `wallet-${hex(setupKey.rawPublicKey()).slice(0, 32)}`;
    const tx = nativeSetupTransaction({ network: id, owner, sequence: account.sequence, wallet, agent, server, funding, requestId, expiresAt: Math.floor(Date.now() / 1000) + 300 });
    const hash = hex(tx.hash()), expiresAt = Number(tx.timeBounds?.maxTime);
    onStep('Sign the wallet setup in your wallet…');
    const ownerSigned = await sign({ action: SET_UP_WALLET, payload: tx.toXDR(), hash, expiresAt });
    const signed = TransactionBuilder.fromXDR(ownerSigned, passphrase);
    if ('innerTransaction' in signed || hex(signed.hash()) !== hash || signed.signatures.length !== 1)
        throw new Error('The wallet returned another transaction. Nothing was sent.');
    // The one signature must be the owner's: the transaction hash leaves signatures out, so another key's signature
    // would pass the check above and the network would refuse the setup.
    if (!Keypair.fromPublicKey(owner).verify(signed.hash(), signed.signatures[0].signature.value))
        throw new Error('The wallet signed with another account than the owner. Nothing was saved or sent; sign with the owner account.');
    // The new account's own key signs its creation once, beside the owner. Then the key is dropped.
    signed.sign(setupKey);
    const signedPayload = signed.toXDR();
    // The signed bytes are saved before they leave: an unknown result is settled from them, never signed again.
    journal.set(key, JSON.stringify({ hash, signedPayload, owner, agent, server, amount }));
    onStep('Waiting for the network to confirm…');
    const ledger = await submit(signedPayload, hash);
    if (ledger === null)
        throw pending();
    if (!retain)
        journal.remove(key);
    return result(wallet, hash, ledger);
}
/** The SEP-53 digest of a wallet message, as lowercase hexadecimal. */
export function messageDigest(message) {
    return hex(digest(`Stellar Signed Message:\n${message}`));
}
/** Canonical text of a JSON value: object keys in code-unit order at every level. */
function canonical(value) {
    if (Array.isArray(value))
        return `[${value.map(canonical).join(',')}]`;
    if (object(value))
        return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
    return JSON.stringify(value) ?? 'null';
}
const APPROVAL_TITLE = 'AllowIt Native policy approval v1';
/**
 * Reads the exact text of a policy approval of `network`: its title line, then the canonical JSON of the approval.
 * Any other text is null: another title, a text that is not the canonical form of its own content, another
 * network or route, or a source or values whose hash differs from the hash that the message states.
 */
export function policyApproval(message, network) {
    const id = canonicalNetwork(network);
    if (typeof message !== 'string' || !id || message.length > 262_144)
        return null;
    const at = message.indexOf('\n');
    if (at < 0 || message.slice(0, at) !== APPROVAL_TITLE)
        return null;
    const text = message.slice(at + 1);
    let value;
    try {
        value = JSON.parse(text);
    }
    catch {
        return null;
    }
    if (!object(value) || canonical(value) !== text)
        return null;
    const { policyId, revision, wallet, source, sourceHash, paramsHash, params } = value;
    if (value.version !== 1 || value.route !== 'native' || value.network !== id || typeof policyId !== 'string' || !policyId || policyId.length > 128
        || !Number.isSafeInteger(revision) || revision <= 0 || typeof wallet !== 'string' || !StrKey.isValidEd25519PublicKey(wallet)
        || typeof source !== 'string' || typeof sourceHash !== 'string' || hex(digest(source)) !== sourceHash
        || typeof paramsHash !== 'string' || !object(params) || hex(digest(canonical(params))) !== paramsHash)
        return null;
    return { policyId, revision: revision, network: id, wallet, source, sourceHash, paramsHash, params };
}
/** The step that asks the owner's wallet to approve a policy. It signs the message and moves nothing. */
export function approvalStep(message, now = Date.now()) {
    const bytes = new TextEncoder().encode(message);
    let binary = '';
    for (let i = 0; i < bytes.length; i += 0x8000)
        binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
    return { action: APPROVE_POLICY, payload: btoa(binary), hash: messageDigest(message), expiresAt: Math.floor(now / 1000) + 300 };
}
/** The message of an approval step, or null when the payload is no UTF-8 text or differs from the step's hash. */
export function approvalMessage(step) {
    try {
        const message = new TextDecoder('utf-8', { fatal: true }).decode(Uint8Array.from(atob(step.payload), c => c.charCodeAt(0)));
        return messageDigest(message) === step.hash ? message : null;
    }
    catch {
        return null;
    }
}
