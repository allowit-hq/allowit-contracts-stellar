import * as freighter from '@stellar/freighter-api';
import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { stellarAssetContract } from './stellar-asset.js';
export const STELLAR_NETWORKS = {
    'stellar:testnet': { label: 'Testnet', passphrase: 'Test SDF Network ; September 2015' },
    'stellar:mainnet': { label: 'Mainnet', passphrase: 'Public Global Stellar Network ; September 2015' },
};
/** A checksummed G address proves a key identity. Account thresholds are checked by the SDK/RPC adapter. */
export function stellarAccountKey(address) {
    if (!/^G[A-Z2-7]{55}$/.test(address))
        throw new Error('Use a valid Stellar account.');
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    const bytes = [];
    let value = 0, bits = 0;
    for (const char of address) {
        value = (value << 5) | alphabet.indexOf(char);
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            bytes.push((value >>> bits) & 255);
        }
    }
    if (bytes.length !== 35 || bytes[0] !== 48 || bits !== 0)
        throw new Error('Use a valid Stellar account.');
    let crc = 0;
    for (const byte of bytes.slice(0, 33)) {
        crc ^= byte << 8;
        for (let i = 0; i < 8; i++)
            crc = ((crc & 0x8000) ? (crc << 1) ^ 0x1021 : crc << 1) & 0xffff;
    }
    if (bytes[33] !== (crc & 255) || bytes[34] !== (crc >>> 8))
        throw new Error('Use a valid Stellar account.');
    return new Uint8Array(bytes.slice(1, 33));
}
/** SEP-53 signs the prefixed digest. It never signs a transaction or authorizes spending. */
export function stellarMessageDigest(message) {
    return sha256(new TextEncoder().encode(`Stellar Signed Message:\n${message}`));
}
function base64Bytes(value) {
    if (value instanceof Uint8Array)
        return new Uint8Array(value);
    try {
        const bytes = Uint8Array.from(atob(value), char => char.charCodeAt(0));
        if (btoa(String.fromCharCode(...bytes)) !== value)
            throw new Error();
        return bytes;
    }
    catch {
        throw new Error('Freighter returned invalid signed bytes.');
    }
}
function base64(bytes) { return btoa(String.fromCharCode(...bytes)); }
function failed(error) {
    if (!error)
        return;
    const detail = error;
    throw Object.assign(new Error(detail.message || 'Freighter could not complete the request.'), { code: detail.code });
}
export async function freighterAvailable() {
    const result = await freighter.isConnected();
    return !result.error && result.isConnected;
}
async function currentAddress(expected) {
    const value = await freighter.getAddress();
    failed(value.error);
    stellarAccountKey(value.address);
    if (expected !== undefined && value.address !== expected)
        throw new Error('The Freighter account changed. Sign in again.');
    return value.address;
}
async function checkNetwork(network) {
    const value = await freighter.getNetworkDetails();
    failed(value.error);
    if (value.networkPassphrase !== STELLAR_NETWORKS[network].passphrase)
        throw new Error(`Select ${STELLAR_NETWORKS[network].label} in Freighter, then try again.`);
}
export async function signInStellar(request, network, signal) {
    const access = await freighter.requestAccess();
    failed(access.error);
    stellarAccountKey(access.address);
    signal?.throwIfAborted();
    await checkNetwork(network);
    signal?.throwIfAborted();
    const challenge = await request('auth/challenge', { address: access.address });
    if (challenge.address !== access.address || challenge.origin !== location.origin || typeof challenge.message !== 'string')
        throw new Error('The sign-in challenge belongs to another account or site. Nothing was signed.');
    signal?.throwIfAborted();
    const signed = await freighter.signMessage(challenge.message, { address: access.address, networkPassphrase: STELLAR_NETWORKS[network].passphrase });
    failed(signed.error);
    if (!signed.signedMessage || signed.signerAddress !== access.address)
        throw new Error('Freighter signed with another account. Sign in again.');
    const signature = base64Bytes(signed.signedMessage);
    if (signature.length !== 64 || !ed25519.verify(signature, stellarMessageDigest(challenge.message), stellarAccountKey(access.address), { zip215: false }))
        throw new Error('The Stellar wallet signature could not be verified.');
    await currentAddress(access.address);
    signal?.throwIfAborted();
    let result;
    try {
        result = await request('auth/verify', { id: challenge.id, address: challenge.address, message: challenge.message, signature: base64(signature) });
    }
    catch (error) {
        if (signal?.aborted)
            await request('auth/logout', {}).catch(() => { });
        throw error;
    }
    if (signal?.aborted || result.session?.address !== access.address || result.session?.network !== 'stellar') {
        await request('auth/logout', {}).catch(() => { });
        signal?.throwIfAborted();
        throw new Error('The server returned a session for another account. Sign in again.');
    }
    return result.session;
}
/**
 * Freighter signs only. Returned bytes are the authority: an optional retain hook receives bounded bytes before the
 * provider error, signer metadata or any further wallet or network await, so a valid proof survives stale metadata or a
 * failed post-sign check. The hook rejects altered bytes. Any metadata error still rejects. Nothing is broadcast here.
 */
export async function signStellarTransaction(transactionXdr, owner, network, retain) {
    if (!transactionXdr || transactionXdr.length > 1_398_104 || !/^[A-Za-z0-9+/]+={0,2}$/.test(transactionXdr))
        throw new Error('The prepared Stellar transaction is invalid.');
    stellarAccountKey(owner);
    await currentAddress(owner);
    await checkNetwork(network);
    const result = await freighter.signTransaction(transactionXdr, { address: owner, networkPassphrase: STELLAR_NETWORKS[network].passphrase });
    const signedXdr = result.signedTxXdr, bounded = typeof signedXdr === 'string' && !!signedXdr && signedXdr.length <= 1_398_104 && /^[A-Za-z0-9+/]+={0,2}$/.test(signedXdr);
    if (retain && bounded)
        await retain(signedXdr);
    failed(result.error);
    if (result.signerAddress !== owner || !bounded)
        throw new Error('Freighter returned a transaction for another account.');
    await currentAddress(owner);
    await checkNetwork(network);
    return signedXdr;
}
export function watchStellarAccount(owner, changed) {
    const watcher = new freighter.WatchWalletChanges();
    watcher.watch(value => { if (value.error || value.address !== owner)
        changed(); });
    return () => watcher.stop();
}
function canonicalObject(value) { return JSON.stringify(Object.fromEntries(Object.keys(value).sort().map(key => [key, value[key]]))); }
const APPROVAL_PAYLOAD_KEYS = ['version', 'policyId', 'revision', 'network', 'wallet', 'route', 'policyInstance', 'source', 'sourceHash', 'irHash', 'moduleDigest', 'asset', 'assetSymbol', 'assetIssuer', 'maxFeeStroops'];
/** The owner signs only reviewed fields. Any added or missing payload field rejects before the wallet prompt. */
const exactPayload = (value) => !!value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length === APPROVAL_PAYLOAD_KEYS.length && Object.keys(value).every(key => APPROVAL_PAYLOAD_KEYS.includes(key));
/** Stellar Asset Contract for an exact asset code, issuer and network. A null issuer means native XLM; issued XLM keeps its issuer. */
export function stellarAssetContractId(code, issuer, network) {
    return stellarAssetContract(code, issuer === null ? null : stellarAccountKey(issuer), STELLAR_NETWORKS[network].passphrase);
}
/** The owner approves an exact Native source against current account administration authority. */
export async function verifyStellarInstallation(request, policy, session, stillCurrent = () => true) {
    const current = () => { if (!stillCurrent())
        throw new Error('The owner, network or policy changed. Nothing was activated.'); };
    current();
    if (session?.network !== 'stellar')
        throw new Error('Sign in with the Stellar owner before verifying the wallet.');
    const expectedOwner = `stellar:${session.address}`;
    const approval = await request('native/approval', { policyId: policy.id }, { expectedOwner });
    current();
    let signatures;
    if (approval.required) {
        const payload = approval.payload, binding = policy.runtime?.instanceBinding;
        if (!exactPayload(payload) || payload.version !== 1 || !binding || (binding.assetIssuer ?? null) !== payload.assetIssuer || (payload.assetIssuer !== null && typeof payload.assetIssuer !== 'string') || typeof payload.assetSymbol !== 'string' || payload.wallet !== binding.wallet || payload.route !== 'native' || payload.route !== binding.route || payload.moduleDigest !== binding.moduleDigest || payload.policyInstance !== binding.policyInstance || payload.asset !== policy.mint || payload.assetSymbol !== policy.token || payload.maxFeeStroops !== binding.maxFeeStroops || approval.method !== 'sep53' || payload.policyId !== policy.id || payload.revision !== policy.revision || payload.network !== policy.network || payload.sourceHash !== policy.sourceHash || payload.irHash !== policy.irHash || payload.source !== policy.code || approval.message !== `AllowIt Native policy approval v1\n${canonicalObject(payload)}` || !['stellar:testnet', 'stellar:mainnet'].includes(String(payload.network)))
            throw new Error('The source approval does not match this exact policy. Nothing was signed.');
        const network = payload.network;
        stellarAccountKey(String(payload.wallet));
        // The signed asset contract must derive from the exact code, issuer and network.
        let contract = '';
        try {
            contract = stellarAssetContractId(payload.assetSymbol, payload.assetIssuer, network);
        }
        catch { /* rejected below */ }
        if (contract !== payload.asset)
            throw new Error('The source approval does not match this exact policy. Nothing was signed.');
        await currentAddress(session.address);
        current();
        await checkNetwork(network);
        current();
        const signed = await freighter.signMessage(approval.message, { address: session.address, networkPassphrase: STELLAR_NETWORKS[network].passphrase });
        failed(signed.error);
        if (signed.signerAddress !== session.address || !signed.signedMessage)
            throw new Error('Freighter signed with another administrator. Nothing was activated.');
        const signature = base64Bytes(signed.signedMessage);
        if (signature.length !== 64 || !ed25519.verify(signature, stellarMessageDigest(approval.message), stellarAccountKey(session.address), { zip215: false }))
            throw new Error('The policy approval signature could not be verified.');
        await currentAddress(session.address);
        current();
        await checkNetwork(network);
        current();
        signatures = [{ signer: session.address, signature: Array.from(signature) }];
    }
    current();
    await request('micro/allocation/confirm', { id: policy.id, revision: policy.revision, ...(signatures ? { stellarSourceApproval: signatures } : {}) }, { expectedOwner });
}
