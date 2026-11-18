/**
 * What the SDK's owner workflows need from Stellar: the network's record of a transaction, the record of an expired
 * signed step, the steps of a Native wallet account's setup and the owner's approval of a Native policy. The SDK holds
 * the workflows, their journal and their recovery rules; these hooks build, send and read Stellar transactions and
 * check Stellar signatures.
 */
import { Keypair } from '@stellar/stellar-sdk/base';
import { expiredRecord, horizonGet } from './chain-record.js';
import { OWNER_WEIGHT, approvalStep, nativeApprovalHolds, nativeWalletConfiguration, policyApproval, prepareNativeSetup, sendNativeSetup, signedNativeSetupOf } from './native-wallet.js';
const object = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
/** The record of a transaction in the public ledger history. */
async function transaction(network, hash) {
    const response = await horizonGet(network, `/transactions/${hash}`);
    if (response?.status === 404)
        return 'missing';
    const body = response?.ok ? await response.json().catch(() => null) : null;
    if (!object(body) || typeof body.hash !== 'string' || typeof body.successful !== 'boolean' || !Number.isSafeInteger(body.ledger))
        return null;
    return { hash: body.hash, ledger: body.ledger, successful: body.successful };
}
/** The owner of a wallet account: its one signer of the owner's weight, read from the public ledger, or null. */
async function walletOwner(network, account) {
    const response = await horizonGet(network, `/accounts/${account}`);
    const body = response?.ok ? await response.json().catch(() => null) : null;
    const owners = (object(body) && Array.isArray(body.signers) ? body.signers : [])
        .filter(s => object(s) && s.weight === OWNER_WEIGHT && s.type === 'ed25519_public_key' && typeof s.key === 'string');
    return owners.length === 1 ? owners[0].key : null;
}
/** Whether `signature` is the signature of `signer` over the hexadecimal digest of an approval step. */
function signedBy(signer, hash, signature) {
    try {
        return Keypair.fromPublicKey(signer).verify(Uint8Array.from(hash.match(/../g) ?? [], byte => parseInt(byte, 16)), Uint8Array.from(signature));
    }
    catch {
        return false;
    }
}
/** The hooks of the SDK's owner workflows. */
export const ownerChain = Object.freeze({
    transaction,
    /** Its ledger when the signed step applied before its time bound, null when it can never apply; throws when unknown. */
    expiredRecord,
    /**
     * A Native wallet account: one owner signature creates and funds it. The SDK keeps the signed setup in its journal
     * and decides when to send it again or replace it; these steps only build, read and send Stellar transactions.
     */
    keypairSetup: Object.freeze({
        prepare: prepareNativeSetup,
        read: signedNativeSetupOf,
        send: (network, signedPayload, hash) => sendNativeSetup(network, signedPayload, hash),
        configuration: nativeWalletConfiguration,
    }),
    /** The owner's approval of a Native policy: one message signature, and no transaction. */
    approval: Object.freeze({
        read: (message, network) => policyApproval(message, network),
        holds: (fields, wallet, reviewed) => nativeApprovalHolds(fields, wallet, reviewed),
        step: (message) => approvalStep(message),
        walletOwner,
        signedBy,
    }),
});
