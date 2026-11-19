/**
 * The Native wallet of an agent: a new classic account, one for each agent. The owner creates and funds it with one
 * signed transaction. The wallet holds one asset: XLM, or an issued asset whose trustline the same transaction adds.
 * That transaction also sets its signers: the owner alone reaches every threshold, and the agent
 * key and the server pay from it only together. The account's own key is random, signs the creation once and then
 * has weight 0. The agent holds a key and no account.
 *
 * This module builds the setup from the owner's own sequence, reads and sends the signed bytes, and returns the
 * installation document that the server registers. The SDK's owner workflow keeps the signed setup and decides when to
 * send it again or replace it. The server takes no part in the setup.
 */
import { Account, Asset, Keypair, Memo, Operation, StrKey, TransactionBuilder } from '@stellar/stellar-sdk/base';
import { sha256 } from '@noble/hashes/sha256';
import { canonicalNetwork, networkPassphrase } from './networks.js';
import { horizonOrigin } from './chain-record.js';
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
/** What the network locks in a wallet account that holds XLM, in stroops: the account and its three signers. */
export const WALLET_RESERVE = 5n * BASE_RESERVE;
/** What the network locks for the trustline of a wallet that holds an issued asset, in stroops. */
export const TRUSTLINE_RESERVE = BASE_RESERVE;
/** The XLM that a new wallet holds above its reserve and its funding, in stroops. It pays the fees of the owner's own steps. */
export const WALLET_FEE_FLOAT = 5000000n;
/** The most that one setup funds, in base units of the wallet's asset. */
const MAX_FUNDING = 1000000000000000n;
/** The limit of a wallet's trustline: the most that the network holds on one line. */
const TRUSTLINE_LIMIT = '922337203685.4775807';
/** The policy source of a wallet account before its owner approves a policy: transfers in the installed asset. */
const BOOTSTRAP_SOURCE = 'use allowit::prelude::*;\n/// Bootstrap: transfers in the installed asset.\npub fn execute(ctx: &AllowitContext) -> allowit::Result {\n    allowit::operations(ctx, &ctx.params[allowit::OPERATIONS])?;\n    allowit::tokens(ctx, &ctx.params[allowit::TOKENS])?;\n    Ok(())\n}\n';
const hex = (bytes) => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
const digest = (text) => sha256(new TextEncoder().encode(text));
const object = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
/**
 * The issued asset of `asset`, or null for XLM and for no asset. Any other value is refused, and so is an issued
 * asset with the code XLM: every amount of it would read as XLM.
 */
function issuedAsset(asset) {
    if (asset === undefined || asset === null)
        return null;
    if (!object(asset) || typeof asset.symbol !== 'string' || !/^[A-Za-z0-9]{1,12}$/.test(asset.symbol)
        || (asset.symbol === 'XLM') !== (asset.issuer === null) || (asset.issuer !== null && (typeof asset.issuer !== 'string' || !StrKey.isValidEd25519PublicKey(asset.issuer))))
        throw new Error('The wallet asset is invalid.');
    return asset.issuer === null ? null : new Asset(asset.symbol, asset.issuer);
}
/** The asset of a wallet as its code and issuer. */
const assetOf = (issued) => issued ? { symbol: issued.getCode(), issuer: issued.getIssuer() ?? null } : { symbol: 'XLM', issuer: null };
/** Base units of a decimal amount with at most seven decimals, or null. XLM and every issued asset have seven. */
function stroops(amount) {
    const match = /^([0-9]{1,12})(?:\.([0-9]{1,7}))?$/.exec(amount);
    return match ? BigInt(match[1]) * 10000000n + BigInt((match[2] ?? '').padEnd(7, '0')) : null;
}
/** Decimal text of base units as a person writes it: no trailing zeros. */
const plainDecimal = (units) => `${units / 10000000n}${units % 10000000n ? `.${(units % 10000000n).toString().padStart(7, '0').replace(/0+$/, '')}` : ''}`;
/** Decimal text of base units, as an operation amount takes it. */
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
/**
 * The XLM that a new wallet starts with, in stroops. A wallet that holds XLM starts with its reserve, its fee float and
 * the owner's funding. A wallet that holds an issued asset (`issued`) starts with its reserve, the reserve of its
 * trustline and its fee float: its funding is a payment of that asset.
 */
export function walletStartingBalance(funding, issued = false) {
    if (funding < 0n || funding > MAX_FUNDING)
        throw new Error('The funding amount is out of range.');
    return issued ? WALLET_RESERVE + TRUSTLINE_RESERVE + WALLET_FEE_FLOAT : WALLET_RESERVE + WALLET_FEE_FLOAT + funding;
}
/**
 * The installation document of a wallet account, as the server registers it. It is the document of the rail's own
 * setup: the same identity, the bootstrap source and the wallet's asset, which is `asset` or XLM. The server reads the
 * roles from the ledger and refuses a document that the account does not match.
 */
export function nativeWalletConfiguration(network, wallet, owner, agent, server, asset) {
    const id = canonicalNetwork(network);
    if (!id)
        throw new Error('Select a supported Stellar network.');
    roles(owner, wallet, agent, server);
    const facts = walletFacts(id, wallet, asset);
    return {
        network: id, policyInstance: Array.from(facts.policyInstance), wallet, owner, agent, server,
        route: 'native', language: 'portable',
        params: { operations: { List: [{ Str: 'transfer' }] }, tokens: { List: [{ Addr: facts.asset }] } },
        asset: facts.asset, assetSymbol: facts.assetSymbol, assetIssuer: facts.assetIssuer, policySource: BOOTSTRAP_SOURCE,
        sourceHash: Array.from(digest(BOOTSTRAP_SOURCE)), moduleDigest: Array.from(new Uint8Array(32)), maxFeeStroops: facts.maxFeeStroops,
    };
}
/** What a wallet account's configuration states of itself: its policy instance, its asset and its fee ceiling. */
function walletFacts(network, wallet, asset) {
    const { symbol, issuer } = assetOf(issuedAsset(asset));
    return {
        policyInstance: digest(`allowit-stellar-native-wallet-v1:${network}:${wallet}`),
        asset: stellarAssetContract(symbol, issuer, networkPassphrase(network)), assetSymbol: symbol, assetIssuer: issuer, maxFeeStroops: 100_000,
    };
}
/**
 * The setup transaction of a wallet account. Its operations are one atomic unit: the creation with the starting
 * balance, the owner signer, the agent signer, and last the server signer with the thresholds and weight 0 for the
 * account's own key. A wallet that holds an issued asset adds its trustline after the creation, and the owner's
 * account then pays the funding in that asset. The owner's account is the source and pays the fee.
 */
export function nativeSetupTransaction({ network, owner, sequence, wallet, agent, server, funding, requestId, expiresAt, asset }) {
    const issued = issuedAsset(asset);
    roles(owner, wallet, agent, server);
    if (!/^[0-9]{1,19}$/.test(sequence))
        throw new Error('The owner account sequence is invalid.');
    if (!/^[A-Za-z0-9._:-]{8,100}$/.test(requestId))
        throw new Error('The setup request identity is invalid.');
    if (!Number.isSafeInteger(expiresAt) || expiresAt <= 0)
        throw new Error('The setup time bound is invalid.');
    const signer = (ed25519PublicKey, weight) => ({ ed25519PublicKey, weight });
    const builder = new TransactionBuilder(new Account(owner, sequence), {
        fee: '100', networkPassphrase: networkPassphrase(network), timebounds: { minTime: 0, maxTime: expiresAt }, memo: Memo.hash(hex(digest(requestId))),
    })
        .addOperation(Operation.createAccount({ destination: wallet, startingBalance: decimal(walletStartingBalance(funding, issued !== null)) }));
    if (issued) {
        builder.addOperation(Operation.changeTrust({ source: wallet, asset: issued, limit: TRUSTLINE_LIMIT }));
        // The owner's account, the transaction source, pays the asset once the trustline exists.
        if (funding > 0n)
            builder.addOperation(Operation.payment({ destination: wallet, asset: issued, amount: decimal(funding) }));
    }
    return builder
        .addOperation(Operation.setOptions({ source: wallet, signer: signer(owner, OWNER_WEIGHT) }))
        .addOperation(Operation.setOptions({ source: wallet, signer: signer(agent, AUTOMATED_WEIGHT) }))
        .addOperation(Operation.setOptions({
        source: wallet, masterWeight: 0, lowThreshold: PAYMENT_THRESHOLD, medThreshold: PAYMENT_THRESHOLD, highThreshold: OWNER_THRESHOLD,
        signer: signer(server, AUTOMATED_WEIGHT),
    }))
        .build();
}
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
    const [create, ...after] = tx.operations;
    // The setup pays the fee that `nativeSetupTransaction` sets: 100 stroops for each operation. Its one condition is
    // its upper time bound: no lower time bound, ledger bounds, sequence condition or further signer.
    if (tx.fee !== String(100 * tx.operations.length))
        return null;
    if (!tx.timeBounds || Number(tx.timeBounds.minTime) !== 0 || !(Number(tx.timeBounds.maxTime) > 0) || tx.ledgerBounds || tx.minAccountSequence
        || Number(tx.minAccountSequenceAge ?? 0) !== 0 || Number(tx.minAccountSequenceLedgerGap ?? 0) !== 0 || (tx.extraSigners?.length ?? 0) !== 0)
        return null;
    if (create?.type !== 'createAccount' || create.source !== undefined)
        return null;
    const wallet = create.destination, starting = stroops(create.startingBalance);
    if (starting === null)
        return null;
    // A wallet of an issued asset: the new account's trustline, with the full limit, and then at most one payment of
    // that asset from the owner's account, the transaction source, to the new account.
    let issued = null, funding = null;
    const trust = after[0];
    if (trust?.type === 'changeTrust') {
        if (trust.source !== wallet || !(trust.line instanceof Asset) || trust.line.isNative() || trust.line.getCode() === 'XLM' || trust.limit !== TRUSTLINE_LIMIT)
            return null;
        issued = trust.line;
        after.shift();
        const pay = after[0];
        if (pay?.type === 'payment') {
            funding = stroops(pay.amount);
            if (pay.source !== undefined || pay.destination !== wallet || !pay.asset.equals(issued) || funding === null || funding <= 0n || funding > MAX_FUNDING)
                return null;
            after.shift();
        }
        if (starting !== walletStartingBalance(0n, true))
            return null;
    }
    else if (starting < walletStartingBalance(0n) || starting > walletStartingBalance(MAX_FUNDING))
        return null;
    const [first, second, last, ...rest] = after;
    if (rest.length)
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
    return { owner, wallet, agent, server, startingBalance: starting, asset: assetOf(issued), funding: issued ? funding ?? 0n : starting - walletStartingBalance(0n) };
}
/**
 * Prepares the setup of the wallet account of an agent: one transaction from the owner's own sequence. The account's
 * own key is random; it signs the creation once, beside the owner, in `complete`.
 */
export async function prepareNativeSetup({ network, owner, agent, server, amount, asset, fetch: send = fetch }) {
    const id = canonicalNetwork(network), base = horizonOrigin(network);
    if (!id || !base)
        throw new Error('Select a supported Stellar network.');
    const funding = stroops(amount);
    if (funding === null)
        throw new Error(`Enter an amount of ${assetOf(issuedAsset(asset)).symbol} with at most seven decimals.`);
    const passphrase = networkPassphrase(id);
    const read = await send(`${base}/accounts/${owner}`, { headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(15_000) }).catch(() => null);
    const account = read?.ok ? await read.json().catch(() => null) : null;
    if (!object(account) || account.account_id !== owner || typeof account.sequence !== 'string' || !/^[0-9]{1,19}$/.test(account.sequence))
        throw new Error('The owner account could not be read from the network.');
    // The setup key is random and lives in this object only. Nothing stores, derives or recovers it.
    const setupKey = Keypair.random(), wallet = setupKey.publicKey();
    const requestId = `wallet-${hex(setupKey.rawPublicKey()).slice(0, 32)}`;
    const tx = nativeSetupTransaction({ network: id, owner, sequence: account.sequence, wallet, agent, server, funding, requestId, expiresAt: Math.floor(Date.now() / 1000) + 300, asset });
    const hash = hex(tx.hash()), expiresAt = Number(tx.timeBounds?.maxTime);
    return {
        wallet,
        step: { action: SET_UP_WALLET, payload: tx.toXDR(), hash, expiresAt },
        complete(ownerSigned) {
            const signed = TransactionBuilder.fromXDR(ownerSigned, passphrase);
            if ('innerTransaction' in signed || hex(signed.hash()) !== hash || signed.signatures.length !== 1)
                throw new Error('The wallet returned another transaction. Nothing was sent.');
            // The one signature must be the owner's: the transaction hash leaves signatures out, so another key's signature
            // would pass the check above and the network would refuse the setup.
            if (!Keypair.fromPublicKey(owner).verify(signed.hash(), signed.signatures[0].signature.value))
                throw new Error('The wallet signed with another account than the owner. Nothing was saved or sent; sign with the owner account.');
            signed.sign(setupKey);
            return signed.toXDR();
        },
    };
}
/**
 * What signed setup bytes are: their hash, their roles, the asset of their wallet, the amount of that asset that they
 * fund it with, as decimal text, and their own time bound. Null for bytes that are no setup of this network. The
 * signed bytes decide; saved metadata is unsigned.
 */
export function signedNativeSetupOf(signedPayload, network) {
    const id = canonicalNetwork(network);
    const setup = id ? nativeSetupOf(signedPayload, id) : null;
    if (!id || !setup)
        return null;
    try {
        const tx = TransactionBuilder.fromXDR(signedPayload, networkPassphrase(id));
        if ('innerTransaction' in tx)
            return null;
        const validUntil = Number(tx.timeBounds?.maxTime);
        if (!Number.isSafeInteger(validUntil) || validUntil <= 0)
            return null;
        // Signed setup bytes carry exactly two signatures over their hash on this network: the owner's and the new
        // account's own. Bytes without them, or signed for another network, are no signed setup of this network.
        const digest = tx.hash(), signedBy = (account) => tx.signatures.filter(s => Keypair.fromPublicKey(account).verify(digest, s.signature.value)).length === 1;
        if (tx.signatures.length !== 2 || !signedBy(setup.owner) || !signedBy(setup.wallet))
            return null;
        return { hash: hex(tx.hash()), owner: setup.owner, wallet: setup.wallet, agent: setup.agent, server: setup.server, validUntil, asset: setup.asset, amount: plainDecimal(setup.funding) };
    }
    catch {
        return null;
    }
}
/** Sends signed setup bytes to Horizon. The ledger of the successful transaction, or null without a certain answer. */
export async function sendNativeSetup(network, signedPayload, hash, send = fetch) {
    const base = horizonOrigin(network);
    if (!base)
        return null;
    const sent = await send(`${base}/transactions`, {
        method: 'POST', headers: { Accept: 'application/json', 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `tx=${encodeURIComponent(signedPayload)}`, signal: AbortSignal.timeout(60_000),
    }).catch(() => null);
    const record = sent?.ok ? await sent.json().catch(() => null) : null;
    return object(record) && record.hash === hash && record.successful === true && Number.isSafeInteger(record.ledger) ? record.ledger : null;
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
    const { policyId, revision, wallet, source, sourceHash, paramsHash, params, rules } = value;
    if (value.version !== 1 || value.route !== 'native' || value.network !== id || typeof policyId !== 'string' || !policyId || policyId.length > 128
        || !Number.isSafeInteger(revision) || revision <= 0 || typeof wallet !== 'string' || !StrKey.isValidEd25519PublicKey(wallet)
        || typeof source !== 'string' || typeof sourceHash !== 'string' || hex(digest(source)) !== sourceHash
        || typeof paramsHash !== 'string' || !object(params) || hex(digest(canonical(params))) !== paramsHash)
        return null;
    return { policyId, revision: revision, network: id, wallet, source, sourceHash, paramsHash, params, rules, fields: value };
}
/**
 * The fields of an approval that the server derives for its own records: its digests of the source and the name of
 * its installation. A Native wallet enforces none of them.
 */
const SERVER_FIELDS = new Set(['irHash', 'moduleDigest', 'policyInstance']);
/**
 * Whether a policy approval of `wallet` is exactly what the owner reviewed. Every field that the wallet signs is
 * checked: the policy and its revision come from the service; the source, rules, values and tier must be the
 * reviewed ones; the network, wallet, route, asset and fee ceiling must be the wallet account's own configuration,
 * as its setup made it for the asset of the reviewed policy. The server's digests of the source and the name of its
 * installation are left to the server. Any other field, or any other value, is refused, and so is a reviewed policy
 * whose asset is no asset.
 */
export function nativeApprovalHolds(approval, wallet, reviewed) {
    let own;
    try {
        own = walletFacts(approval.network, wallet, reviewed.asset);
    }
    catch {
        return false;
    }
    const expected = {
        version: 1, policyId: approval.policyId, revision: approval.revision, network: approval.network, wallet, route: 'native',
        asset: own.asset, assetSymbol: own.assetSymbol, assetIssuer: own.assetIssuer, maxFeeStroops: own.maxFeeStroops,
        source: reviewed.source, sourceHash: hex(digest(reviewed.source)), params: reviewed.params,
        rules: reviewed.rules === undefined ? approval.fields.rules : reviewed.rules,
        paramsHash: hex(digest(canonical(reviewed.params))), language: approval.fields.language,
        tier: reviewed.tier === undefined ? approval.fields.tier : reviewed.tier,
    };
    const keys = Object.keys(approval.fields).filter(key => !SERVER_FIELDS.has(key));
    // Only the fields of `expected` itself count: a name that every object inherits is no field of an approval.
    return keys.length === Object.keys(expected).length && keys.every(key => Object.hasOwn(expected, key) && canonical(approval.fields[key]) === canonical(expected[key]))
        && typeof approval.fields.language === 'string' && /^[a-z0-9-]{1,64}$/.test(approval.fields.language);
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
