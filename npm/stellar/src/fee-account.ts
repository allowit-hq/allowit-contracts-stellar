/**
 * The fee account of a policy wallet: the account that sends the agent's operations on the wallet and pays their
 * network fees. The owner's deployment creates and funds it. It has the signers of a wallet account: the owner alone
 * reaches every threshold, and the agent key and the server pay from it only together. The agent holds no account.
 *
 * This module derives the account's one-time key from the owner's signature, reads the account from the public
 * ledger history and prepares the owner's refill. The server takes no part in the read or the refill.
 */
import {Account, Asset, Keypair, Operation, StrKey, TransactionBuilder} from '@stellar/stellar-sdk/base';
import {sha256} from '@noble/hashes/sha256';
import {canonicalNetwork, networkPassphrase} from './plugin.js';

/** The action of the step that signs the derivation message. Its payload is the base64 text of the message. */
export const DERIVE_FEE_ACCOUNT_KEY = 'derive_fee_account_key';
/** The action of the owner step that creates the fee account. */
export const CREATE_FEE_ACCOUNT = 'create_fee_account';
/** The action of the owner step that refills the fee account. */
export const REFILL_FEES = 'refill_fees';
/** The typed refusal of a wallet creation that names no fee account. `details.wallet` is the policy wallet. */
export const FEE_ACCOUNT_REQUIRED = 'fee_account_required';
/** The index of the first fee account of a policy wallet. */
export const FEE_ACCOUNT_INDEX = 0;
const TITLE = 'Allowit fee account key v1';
const PURPOSE = "This signature derives the one-time setup key of the account that pays the network fees of this agent's policy wallet. It does not authorize spending or move funds.";
const SEED_DOMAIN = new TextEncoder().encode('allowit-stellar-native-wallet-seed-v1');
const BASE_RESERVE = 5_000_000n;
/** The float of a new fee account, in stroops: what the owner's deployment funds above the reserve. */
const FEE_FLOAT = 50_000_000n;

const hex = (bytes: Uint8Array) => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
const object = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);

/** The SEP-53 digest of a wallet message, as lowercase hexadecimal. */
export function messageDigest(message: string): string {
  return hex(sha256(new TextEncoder().encode(`Stellar Signed Message:\n${message}`)));
}

/**
 * The message whose owner signature derives the one-time key of a fee account. It names the network, the agent,
 * the policy wallet and an index, so each policy wallet of one owner gets its own account and the owner can
 * compute the address again.
 */
export function feeAccountDerivationMessage(network: string, agent: string, wallet: string, index = FEE_ACCOUNT_INDEX): string {
  if (!StrKey.isValidEd25519PublicKey(agent)) throw new Error('The agent public key is invalid.');
  if (!StrKey.isValidContract(wallet)) throw new Error('A fee account pays for a policy wallet contract.');
  if (!Number.isSafeInteger(index) || index < 0 || index > 0xffff_ffff) throw new Error('The fee account index is invalid.');
  return `${TITLE}\nNetwork: ${networkPassphrase(network)}\nAgent: ${agent}\nPolicy wallet: ${wallet}\nFee account index: ${index}\n\n${PURPOSE}`;
}

/** The fields of a derivation message of `network`, or null for any other text. */
export function feeAccountDerivation(message: unknown, network: string): {agent: string; wallet: string; index: number} | null {
  if (typeof message !== 'string' || !canonicalNetwork(network)) return null;
  const lines = message.split('\n');
  if (lines.length !== 7 || lines[0] !== TITLE || lines[5] !== '' || lines[6] !== PURPOSE) return null;
  const value = (line: string, key: string) => line.startsWith(`${key}: `) ? line.slice(key.length + 2) : null;
  const agent = value(lines[2], 'Agent'), wallet = value(lines[3], 'Policy wallet'), index = value(lines[4], 'Fee account index');
  if (value(lines[1], 'Network') !== networkPassphrase(network) || agent === null || wallet === null || index === null
    || !/^(0|[1-9][0-9]{0,9})$/.test(index)) return null;
  try {
    return feeAccountDerivationMessage(network, agent, wallet, Number(index)) === message ? {agent, wallet, index: Number(index)} : null;
  } catch {
    return null;
  }
}

/** The step that asks the owner's wallet for the derivation signature. It signs a message and moves nothing. */
export function derivationStep(network: string, agent: string, wallet: string, now = Date.now()): {action: string; payload: string; hash: string; expiresAt: number} {
  const message = feeAccountDerivationMessage(network, agent, wallet);
  return {action: DERIVE_FEE_ACCOUNT_KEY, payload: btoa(message), hash: messageDigest(message), expiresAt: Math.floor(now / 1000) + 300};
}

/** The one-time key of a fee account, from the owner's 64-byte signature over the derivation message. */
export function feeAccountKey(signature: Uint8Array): Keypair {
  if (signature.length !== 64) throw new Error('The wallet did not return a message signature.');
  const seed = new Uint8Array(SEED_DOMAIN.length + 64);
  seed.set(SEED_DOMAIN);
  seed.set(signature, SEED_DOMAIN.length);
  return Keypair.fromRawEd25519Seed(sha256(seed) as never);
}

/**
 * Adds the one signature of the new account's own key to the owner-signed creation of a fee account. The signed
 * bytes must be the reviewed step, and its first operation must create exactly the account of `key`.
 */
export function countersignCreation(network: string, step: {hash: string}, signedPayload: string, key: Keypair): string {
  const tx = TransactionBuilder.fromXDR(signedPayload, networkPassphrase(network));
  if ('innerTransaction' in tx || hex(tx.hash()) !== step.hash) throw new Error('The wallet returned another transaction. Nothing was sent.');
  const first = tx.operations[0];
  if (first?.type !== 'createAccount' || first.destination !== key.publicKey() || tx.signatures.length !== 1)
    throw new Error('The fee account step does not create the account of this owner and agent. Nothing was sent.');
  tx.sign(key);
  return tx.toXDR();
}

/** The fee account that an installation, a wallet profile or a policy document names, or null. */
export function feeAccountOf(document: unknown): {address: string; maxFeeStroops: number | null} | null {
  const top = object(document) ? document : null;
  const config = top && (object(top.config) ? top.config : object(top.installation) ? top.installation : top);
  const address = config?.feeAccount;
  if (typeof address !== 'string' || !StrKey.isValidEd25519PublicKey(address)) return null;
  const fee = config?.maxFeeStroops;
  return {address, maxFeeStroops: Number.isSafeInteger(fee) && (fee as number) > 0 ? fee as number : null};
}

/** What the ledger holds for a fee account. Amounts are stroops as decimal text; `text` is the spendable XLM. */
export interface FeeAccountState {
  address: string;
  /** False when the ledger holds no such account: its owner closed it, or never created it. */
  exists: boolean;
  balance: string;
  /** The XLM above the reserve: what pays network fees. */
  spendable: string;
  /** True when less than two operations at the wallet's fee ceiling remain. */
  low: boolean;
  text: string;
  /** The refill that the page offers: the float of a new fee account, as a decimal amount and with its unit. */
  refill: {amount: string; text: string};
}

const HORIZON: Readonly<Record<string, string>> = {
  'stellar:testnet': 'https://horizon-testnet.stellar.org',
  'stellar:pubnet': 'https://horizon.stellar.org',
};
function horizon(network: string): string {
  const base = HORIZON[canonicalNetwork(network) ?? ''];
  if (!base) throw new Error('Select a supported Stellar network.');
  return base;
}
/** Stroops of a decimal XLM amount with at most seven decimals, or null. */
export function stroops(amount: string): bigint | null {
  const match = /^([0-9]{1,12})(?:\.([0-9]{1,7}))?$/.exec(amount);
  return match ? BigInt(match[1]) * 10_000_000n + BigInt((match[2] ?? '').padEnd(7, '0')) : null;
}
/** XLM text of stroops, without trailing zeros. */
export function xlmText(units: bigint): string {
  const whole = units / 10_000_000n, fraction = (units % 10_000_000n).toString().padStart(7, '0').replace(/0+$/, '');
  return `${whole}${fraction ? `.${fraction}` : ''} XLM`;
}

/**
 * Reads the fee account of `document` from the public ledger history. Null when the document names none: a Native
 * wallet pays its own fees, and a policy wallet of an earlier release has the agent's own account pay them.
 */
export async function feeAccount(input: {network: string; document: unknown; fetch?: typeof fetch}): Promise<FeeAccountState | null> {
  const named = feeAccountOf(input.document);
  if (!named) return null;
  const response = await (input.fetch ?? fetch)(`${horizon(input.network)}/accounts/${named.address}`, {headers: {Accept: 'application/json'}, signal: AbortSignal.timeout(15_000)});
  const refill = {amount: xlmText(FEE_FLOAT).replace(' XLM', ''), text: xlmText(FEE_FLOAT)};
  if (response.status === 404) return {address: named.address, exists: false, balance: '0', spendable: '0', low: true, text: xlmText(0n), refill};
  const account: unknown = response.ok ? await response.json().catch(() => null) : null;
  const native = object(account) && Array.isArray(account.balances) ? account.balances.find(b => object(b) && b.asset_type === 'native') : null;
  const balance = object(native) && typeof native.balance === 'string' ? stroops(native.balance) : null;
  const selling = object(native) && typeof native.selling_liabilities === 'string' ? stroops(native.selling_liabilities) ?? 0n : 0n;
  if (!object(account) || account.account_id !== named.address || balance === null || !Number.isSafeInteger(account.subentry_count))
    throw new Error('The fee account could not be read from the network.');
  const count = (v: unknown) => Number.isSafeInteger(v) ? BigInt(v as number) : 0n;
  const entries = 2n + BigInt(account.subentry_count as number) + count(account.num_sponsoring) - count(account.num_sponsored);
  const above = balance - selling - entries * BASE_RESERVE;
  const spendable = above > 0n ? above : 0n;
  // Two operations at the fee ceiling of the wallet; a 1 XLM ceiling when the document names none.
  const low = spendable < 2n * BigInt(named.maxFeeStroops ?? 10_000_000);
  return {address: named.address, exists: true, balance: balance.toString(), spendable: spendable.toString(), low, text: xlmText(spendable), refill};
}

export interface RefillFeesInput {
  network: string;
  /** The owner's account: the source of the payment. */
  owner: string;
  /** The fee account that receives it. */
  feeAccount: string;
  /** XLM, as decimal text with at most seven decimals. */
  amount: string;
  /** Shows the payment in the `owner-sign` element and resolves with the exact signed payload. */
  sign: (step: {action: string; payload: string; hash: string; expiresAt: number}) => Promise<string>;
  onStep: (text: string) => void;
  fetch?: typeof fetch;
}

/**
 * Refills a fee account: one payment of XLM from the owner's account, which the owner's wallet signs. This module
 * builds the payment from the owner's own sequence and sends the signed bytes to the public network itself.
 */
export async function refillFees({network, owner, feeAccount: destination, amount, sign, onStep, fetch: send = fetch}: RefillFeesInput): Promise<{transactionHash: string; ledger: number}> {
  const units = stroops(amount);
  if (!StrKey.isValidEd25519PublicKey(owner) || !StrKey.isValidEd25519PublicKey(destination) || owner === destination)
    throw new Error('The refill needs the owner account and the fee account.');
  if (units === null || units <= 0n) throw new Error('Enter an amount of XLM with at most seven decimals.');
  const base = horizon(network), passphrase = networkPassphrase(network);
  onStep('Preparing the refill…');
  const read = await send(`${base}/accounts/${owner}`, {headers: {Accept: 'application/json'}, signal: AbortSignal.timeout(15_000)});
  const account: unknown = read.ok ? await read.json().catch(() => null) : null;
  if (!object(account) || account.account_id !== owner || typeof account.sequence !== 'string' || !/^[0-9]{1,19}$/.test(account.sequence))
    throw new Error('The owner account could not be read from the network.');
  const tx = new TransactionBuilder(new Account(owner, account.sequence), {fee: '100', networkPassphrase: passphrase})
    .addOperation(Operation.payment({destination, asset: Asset.native(), amount}))
    .setTimeout(300)
    .build();
  const hash = hex(tx.hash());
  onStep('Sign the refill in your wallet…');
  const signedPayload = await sign({action: REFILL_FEES, payload: tx.toXDR(), hash, expiresAt: Number(tx.timeBounds?.maxTime)});
  const signed = TransactionBuilder.fromXDR(signedPayload, passphrase);
  if ('innerTransaction' in signed || hex(signed.hash()) !== hash || signed.signatures.length !== 1) throw new Error('The wallet returned another transaction. Nothing was sent.');
  onStep('Waiting for the network to confirm…');
  const sent = await send(`${base}/transactions`, {
    method: 'POST', headers: {Accept: 'application/json', 'Content-Type': 'application/x-www-form-urlencoded'},
    body: `tx=${encodeURIComponent(signedPayload)}`, signal: AbortSignal.timeout(60_000),
  });
  const result: unknown = await sent.json().catch(() => null);
  if (!sent.ok || !object(result) || result.hash !== hash || result.successful !== true || !Number.isSafeInteger(result.ledger))
    throw new Error('The network did not confirm the refill. Check the fee account balance before you sign again.');
  return {transactionHash: hash, ledger: result.ledger as number};
}
