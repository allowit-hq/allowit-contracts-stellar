import { canonicalJson, digest } from './consent-codec.js';
import freighter from '@stellar/freighter-api';
import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { StrKey } from '@stellar/stellar-sdk/base';
import { stellarAssetContract } from './stellar-asset.js';
export const STELLAR_NETWORKS = {
    'stellar:testnet': { label: 'Testnet', passphrase: 'Test SDF Network ; September 2015' },
    'stellar:mainnet': { label: 'Mainnet', passphrase: 'Public Global Stellar Network ; September 2015' },
    'stellar:pubnet': { label: 'Mainnet', passphrase: 'Public Global Stellar Network ; September 2015' },
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
/** Bind the exact sign-in purpose, account, Origin and nonce. The caller admits timestamp freshness. */
export function stellarSignInChallengeTimes(challenge, owner, origin) {
    const invalid = () => new Error('The sign-in challenge is invalid or expired. Nothing was signed.');
    let site;
    try {
        site = new URL(origin);
        stellarAccountKey(owner);
    }
    catch {
        throw invalid();
    }
    if (site.origin !== origin || !['http:', 'https:'].includes(site.protocol) || !/^[0-9a-f]{64}$/.test(challenge.id)
        || challenge.address !== owner || challenge.origin !== origin || typeof challenge.message !== 'string')
        throw invalid();
    const prefix = `${site.host} wants you to sign in with your Stellar account:\n${owner}\n\nSign in to AllowIt. This does not authorize spending or move funds.\n\nURI: ${origin}\nVersion: 1\nNonce: ${challenge.id}\nIssued At: `;
    if (!challenge.message.startsWith(prefix))
        throw invalid();
    const times = challenge.message.slice(prefix.length).split('\nExpiration Time: ');
    const timestamp = (value) => {
        if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value))
            throw invalid();
        const time = Date.parse(value);
        if (!Number.isFinite(time) || new Date(time).toISOString().replace('.000Z', 'Z') !== value)
            throw invalid();
        return time;
    };
    if (times.length !== 2 || times[1] !== challenge.expiresAt)
        throw invalid();
    const issued = timestamp(times[0]), expiry = timestamp(times[1]);
    return { issuedAt: issued, expiresAt: expiry };
}
/** A native wallet capability. HTTP sessions and their admission stay with the app. */
export async function connectStellarWallet(network, admitTimes, signal) {
    if (typeof admitTimes !== 'function')
        throw new Error('Provide the app sign-in admission capability.');
    const access = await freighter.requestAccess();
    failed(access.error);
    stellarAccountKey(access.address);
    signal?.throwIfAborted();
    await checkNetwork(network);
    signal?.throwIfAborted();
    return {
        address: access.address,
        network: 'stellar',
        validateChallenge(challenge) { if (admitTimes(stellarSignInChallengeTimes(challenge, access.address, location.origin)) !== true)
            throw new Error('The sign-in challenge is invalid or expired. Nothing was signed.'); },
        async signMessage(message) {
            signal?.throwIfAborted();
            const signed = await freighter.signMessage(message, { address: access.address, networkPassphrase: STELLAR_NETWORKS[network].passphrase });
            failed(signed.error);
            if (!signed.signedMessage || signed.signerAddress !== access.address)
                throw new Error('Freighter signed with another account. Sign in again.');
            const signature = base64Bytes(signed.signedMessage);
            if (signature.length !== 64 || !ed25519.verify(signature, stellarMessageDigest(message), stellarAccountKey(access.address), { zip215: false }))
                throw new Error('The Stellar wallet signature could not be verified.');
            await currentAddress(access.address);
            signal?.throwIfAborted();
            return base64(signature);
        },
    };
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
export const canonicalApprovalJson = canonicalJson;
const APPROVAL_PAYLOAD_KEYS = ['version', 'policyId', 'revision', 'network', 'wallet', 'route', 'policyInstance', 'source', 'sourceHash', 'irHash', 'moduleDigest', 'asset', 'assetSymbol', 'assetIssuer', 'maxFeeStroops'];
/** The owner signs only reviewed fields. Any added or missing payload field rejects before the wallet prompt. */
const PORTABLE_APPROVAL_KEYS = [...APPROVAL_PAYLOAD_KEYS, 'language', 'tier', 'rules', 'params', 'paramsHash'];
const exactPayload = (value, keys) => !!value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length === keys.length && Object.keys(value).every(key => keys.includes(key));
const SERVER_POLICY_APPROVAL_PROFILE = 'allowit-stellar-server-policy-approval-v1';
const SERVER_POLICY_APPROVAL_KEYS = [
    'profile', 'network', 'wallet', 'owner', 'policyId', 'revision', 'policyInstance',
    'moduleDigest', 'installedSourceHash', 'source', 'sourceHash', 'paramsHash', 'serverBindings',
];
const hashIdentity = (value) => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
function serverPolicyApprovalNetwork(approval, policy, owner) {
    const { payload, message, method } = approval;
    const binding = policy.runtime?.instanceBinding;
    const portable = binding?.portable;
    const build = portable?.build;
    const invalid = () => new Error('The server policy approval does not match this exact policy and wallet. Nothing was signed.');
    if (!exactPayload(payload, SERVER_POLICY_APPROVAL_KEYS) || payload.profile !== SERVER_POLICY_APPROVAL_PROFILE
        || method !== 'sep53' || payload.owner !== owner || payload.policyId !== policy.id
        || !/^[A-Za-z0-9._:-]{1,128}$/.test(policy.id) || payload.revision !== policy.revision
        || !Number.isInteger(policy.revision) || policy.revision < 1 || policy.revision > 0xffffffff
        || typeof payload.network !== 'string' || !Object.hasOwn(STELLAR_NETWORKS, payload.network)
        || payload.network !== policy.network || binding?.route !== 'policyWallet'
        || typeof payload.wallet !== 'string' || !StrKey.isValidContract(payload.wallet) || payload.wallet !== binding.wallet
        || !hashIdentity(payload.policyInstance) || payload.policyInstance !== binding.policyInstance
        || !hashIdentity(payload.moduleDigest) || payload.moduleDigest !== binding.moduleDigest
        || !hashIdentity(payload.installedSourceHash) || payload.installedSourceHash !== binding.installedSourceHash
        || typeof policy.code !== 'string' || policy.code.length === 0 || new TextEncoder().encode(policy.code).length > 32_768
        || payload.source !== policy.code || payload.sourceHash !== policy.sourceHash || digest(policy.code) !== payload.sourceHash
        || portable?.sourceHash !== payload.sourceHash || !hashIdentity(payload.paramsHash) || payload.paramsHash !== portable.paramsHash
        || !portable.params || typeof portable.params !== 'object' || Array.isArray(portable.params)
        || digest(canonicalApprovalJson(portable.params)) !== payload.paramsHash
        || !hashIdentity(payload.serverBindings) || payload.serverBindings !== build?.serverBindings
        || message !== `AllowIt Stellar server policy approval v1\n${canonicalApprovalJson(payload)}`)
        throw invalid();
    stellarAccountKey(owner);
    return payload.network;
}
async function signSourceApproval(message, owner, network, current) {
    await currentAddress(owner);
    current();
    await checkNetwork(network);
    current();
    const signed = await freighter.signMessage(message, { address: owner, networkPassphrase: STELLAR_NETWORKS[network].passphrase });
    failed(signed.error);
    if (signed.signerAddress !== owner || !signed.signedMessage)
        throw new Error('Freighter signed with another administrator. Nothing was activated.');
    const signature = base64Bytes(signed.signedMessage);
    if (signature.length !== 64 || !ed25519.verify(signature, stellarMessageDigest(message), stellarAccountKey(owner), { zip215: false }))
        throw new Error('The policy approval signature could not be verified.');
    await currentAddress(owner);
    current();
    await checkNetwork(network);
    current();
    return [{ signer: owner, signature: Array.from(signature) }];
}
/** Stellar Asset Contract for an exact asset code, issuer and network. A null issuer means native XLM; issued XLM keeps its issuer. */
export function stellarAssetContractId(code, issuer, network) {
    return stellarAssetContract(code, issuer === null ? null : stellarAccountKey(issuer), STELLAR_NETWORKS[network].passphrase);
}
/** Bind the exact reviewed source and sign with the selected Stellar owner. */
export async function signStellarSourceApproval(approval, policy, session, stillCurrent = () => true) {
    const current = () => { if (!stillCurrent())
        throw new Error('The owner, network or policy changed. Nothing was activated.'); };
    current();
    if (session?.network !== 'stellar')
        throw new Error('Sign in with the Stellar owner before verifying the wallet.');
    if (approval.payload?.profile === SERVER_POLICY_APPROVAL_PROFILE) {
        const network = serverPolicyApprovalNetwork(approval, policy, session.address);
        return signSourceApproval(approval.message, session.address, network, current);
    }
    {
        const payload = approval.payload, binding = policy.runtime?.instanceBinding;
        const portable = binding?.portable;
        const portableExpected = portable !== undefined || binding?.language === 'allowit-portable-v1' || policy.language === 'allowit-portable-v1';
        const keys = portableExpected ? PORTABLE_APPROVAL_KEYS : APPROVAL_PAYLOAD_KEYS;
        const hash = digest;
        const portableMatches = !portableExpected || !!portable && portable.language === 'allowit-portable-v1'
            && ['standard', 'custom'].includes(String(portable.tier)) && Array.isArray(portable.rules) && portable.rules.every(rule => typeof rule === 'string')
            && !!portable.params && typeof portable.params === 'object' && !Array.isArray(portable.params)
            && typeof policy.code === 'string' && hash(policy.code) === policy.sourceHash
            && portable.sourceHash === policy.sourceHash && payload.language === portable.language
            && payload.tier === portable.tier && canonicalApprovalJson(payload.rules) === canonicalApprovalJson(portable.rules)
            && canonicalApprovalJson(payload.params) === canonicalApprovalJson(portable.params)
            && typeof portable.paramsHash === 'string' && /^[0-9a-f]{64}$/.test(portable.paramsHash)
            && payload.paramsHash === portable.paramsHash
            && hash(canonicalApprovalJson(portable.params)) === portable.paramsHash
            && hash(canonicalApprovalJson({ language: portable.language, tier: portable.tier, rules: portable.rules, sourceHash: portable.sourceHash, paramsHash: portable.paramsHash })) === binding?.moduleDigest;
        if (!exactPayload(payload, keys) || !portableMatches || payload.version !== 1 || !binding || (binding.assetIssuer ?? null) !== payload.assetIssuer || (payload.assetIssuer !== null && typeof payload.assetIssuer !== 'string') || typeof payload.assetSymbol !== 'string' || payload.wallet !== binding.wallet || payload.route !== 'native' || payload.route !== binding.route || payload.moduleDigest !== binding.moduleDigest || payload.policyInstance !== binding.policyInstance || payload.asset !== policy.mint || payload.assetSymbol !== policy.token || payload.maxFeeStroops !== binding.maxFeeStroops || approval.method !== 'sep53' || payload.policyId !== policy.id || payload.revision !== policy.revision || payload.network !== policy.network || payload.sourceHash !== policy.sourceHash || payload.irHash !== policy.irHash || payload.source !== policy.code || approval.message !== `AllowIt Native policy approval v1\n${canonicalApprovalJson(payload)}` || !['stellar:testnet', 'stellar:mainnet', 'stellar:pubnet'].includes(String(payload.network)))
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
        return signSourceApproval(approval.message, session.address, network, current);
    }
}
