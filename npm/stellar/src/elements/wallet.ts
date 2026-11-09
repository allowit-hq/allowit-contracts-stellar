/** Wallet access for the signing elements. Loaded on demand, so importing the plugin never loads the wallet API. */
import {connectStellarWallet, signStellarTransaction, type StellarNetwork} from '../stellar-wallet.js';

const open = new Map<string, Awaited<ReturnType<typeof connectStellarWallet>>>();

/** Asks the wallet for access on `network` and returns the account. */
export async function connectWallet(network: string): Promise<string> {
  const wallet = await connectStellarWallet(network as StellarNetwork, () => true);
  open.set(wallet.address, wallet);
  return wallet.address;
}
/** A SEP-53 message signature, checked against the account. */
export async function signWalletMessage(message: string, address: string, network: string): Promise<string> {
  const wallet = open.get(address) ?? await connectStellarWallet(network as StellarNetwork, () => true);
  if (wallet.address !== address) throw new Error('The wallet account changed. Sign in again.');
  return wallet.signMessage(message);
}
export function signWalletTransaction(payload: string, owner: string, network: string): Promise<string> {
  return signStellarTransaction(payload, owner, network as StellarNetwork);
}
