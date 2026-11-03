export const isStellarReceipt = (value) => value.chain === 'stellar';
export function parseStellarReceipt(q, field, u64, fail) {
    const record = (value, field) => { if (!value || typeof value !== 'object' || Array.isArray(value))
        throw fail(field); return value; };
    const action = record(q.action, `${field}.action`);
    if (!['stellar:testnet', 'stellar:mainnet'].includes(q.network) || !['success', 'failed'].includes(q.result) || q.invocationIndex !== 0 || !/^([a-f0-9]{64})$/.test(q.signature) || !/^([a-f0-9]{64})$/.test(q.requestHash) || action.type !== 'stellar-transfer' || !/^C[A-Z2-7]{55}$/.test(action.asset) || !/^([GC])[A-Z2-7]{55}$/.test(action.recipient) || typeof action.amountUnits !== 'string' || !/^[1-9][0-9]*$/.test(action.amountUnits) || BigInt(action.amountUnits) > ((1n << 127n) - 1n))
        throw fail(field, 'is not an admitted Stellar transaction receipt');
    return { chain: 'stellar', network: q.network, signature: q.signature, requestHash: q.requestHash, invocationIndex: 0, finalizedLedger: u64(q.finalizedLedger, `${field}.finalizedLedger`), result: q.result, action: { type: 'stellar-transfer', amountUnits: action.amountUnits, asset: action.asset, recipient: action.recipient } };
}
/** Native receipt projection. It grants no settlement authority beyond the admitted receipt. */
export function stellarTransfer(receipt) {
    const action = receipt.action;
    return action.type === 'stellar-transfer' ? { units: action.amountUnits, recipient: action.recipient } : null;
}
export const stellarReceiptSucceeded = (receipt) => !!stellarTransfer(receipt) && receipt.result === 'success';
export const stellarReceiptFailed = (receipt) => isStellarReceipt(receipt) && receipt.result === 'failed';
export const stellarReceiptIdentityMismatch = (receipt, request) => isStellarReceipt(receipt) && (receipt.requestHash !== request.requestHash || receipt.signature !== request.signature);
export const stellarReceiptHeight = (receipt) => isStellarReceipt(receipt) ? { label: 'ledger', value: receipt.finalizedLedger } : null;
