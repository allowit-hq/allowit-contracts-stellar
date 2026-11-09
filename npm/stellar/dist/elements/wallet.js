/** Wallet access for the signing elements. Loaded on demand, so importing the plugin never loads the wallet API. */
import { connectStellarWallet, signStellarTransaction } from '../stellar-wallet.js';
const open = new Map();
/** Asks the wallet for access on `network` and returns the account. */
export async function connectWallet(network) {
    const wallet = await connectStellarWallet(network, () => true);
    open.set(wallet.address, wallet);
    return wallet.address;
}
/** A SEP-53 message signature, checked against the account. */
export async function signWalletMessage(message, address, network) {
    const wallet = open.get(address) ?? await connectStellarWallet(network, () => true);
    if (wallet.address !== address)
        throw new Error('The wallet account changed. Sign in again.');
    return wallet.signMessage(message);
}
export function signWalletTransaction(payload, owner, network) {
    return signStellarTransaction(payload, owner, network);
}
