/**
 * What the public ledger history holds for a signed transaction. The owner workflows use it to settle a signed step
 * whose result they do not know: a signed step is replaced only when the chain proves that it can never apply.
 */
import {TransactionBuilder} from '@stellar/stellar-sdk/base';
import {canonicalNetwork, networkPassphrase} from './networks.js';

const HORIZON: Readonly<Record<string, string>> = {
  'stellar:testnet': 'https://horizon-testnet.stellar.org',
  'stellar:pubnet': 'https://horizon.stellar.org',
};
/** The Horizon origin of a network, or null. */
export const horizonOrigin = (network: string): string | null => HORIZON[canonicalNetwork(network) ?? ''] ?? null;
/** Every Horizon read ends after this time, so a stalled read never holds a workflow lock. */
const HORIZON_TIMEOUT_MS = 15_000;
/** A read of the public ledger history. A failed or stalled read is null. */
export async function horizonGet(network: string, path: string, send: typeof fetch = fetch): Promise<Response | null> {
  const base = horizonOrigin(network);
  if (!base) return null;
  try {
    return await send(`${base}${path}`, {headers: {Accept: 'application/json'}, signal: AbortSignal.timeout(HORIZON_TIMEOUT_MS)});
  } catch {
    return null;
  }
}
const object = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);

/** The chain could not be read, or its answer proves nothing: the signed bytes stay saved. */
export class ChainUnchecked extends Error {
  constructor() {
    super('The network record of the signed transaction could not be checked.');
    this.name = 'ChainUnchecked';
  }
}

/**
 * What the chain holds for a signed transaction past its time bound: its ledger when it applied, or null when it
 * can never apply. Expiry stops a later application, not an earlier one, so a missing record alone proves nothing.
 * The time bound is the maximum time of the signed transaction itself; a transaction without one never expires.
 * The transaction never applied only when Horizon has read past the time bound and either holds the failed
 * transaction or holds none while the source account sequence is still below the transaction's sequence.
 * Anything else throws `ChainUnchecked`.
 */
export async function expiredRecord(network: string, hash: string, signedPayload: string, send: typeof fetch = fetch): Promise<{ledger: number} | null> {
  let source: string, sequence: bigint, validUntil: number;
  try {
    const envelope = TransactionBuilder.fromXDR(signedPayload, networkPassphrase(network));
    const transaction = 'innerTransaction' in envelope ? envelope.innerTransaction : envelope;
    if (Array.from(transaction.hash(), byte => byte.toString(16).padStart(2, '0')).join('') !== hash) throw new Error();
    source = transaction.source;
    sequence = BigInt(transaction.sequence);
    // The signed bytes decide when the transaction can no longer apply. Saved metadata is unsigned.
    const maxTime = transaction.timeBounds?.maxTime;
    if (typeof maxTime !== 'string' || !/^[1-9][0-9]{0,11}$/.test(maxTime)) throw new Error();
    validUntil = Number(maxTime);
  } catch {
    throw new ChainUnchecked();
  }
  const read = async (path: string) => {
    const response = await horizonGet(network, path, send);
    if (!response) throw new ChainUnchecked();
    return response;
  };
  const json = async (response: Response): Promise<Record<string, unknown>> => {
    const value: unknown = await response.json().catch(() => null);
    if (!response.ok || !object(value)) throw new ChainUnchecked();
    return value;
  };
  const root = await json(await read('/'));
  const closedAt = typeof root.history_latest_ledger_closed_at === 'string' ? Date.parse(root.history_latest_ledger_closed_at) / 1000 : NaN;
  // Every ledger that can include the transaction closes at or before its signed time bound. The clock and Horizon
  // must both be past it.
  if (!(Date.now() / 1000 > validUntil) || !(closedAt > validUntil)) throw new ChainUnchecked();
  const found = await read(`/transactions/${hash}`);
  if (found.status !== 404) {
    const chain = await json(found);
    if (chain.hash !== hash || typeof chain.successful !== 'boolean' || !Number.isSafeInteger(chain.ledger) || (chain.ledger as number) <= 0) throw new ChainUnchecked();
    return chain.successful ? {ledger: chain.ledger as number} : null;
  }
  // A missing record alone proves nothing. A source sequence below the transaction's sequence proves it never applied.
  const account = await json(await read(`/accounts/${source}`));
  if (account.account_id !== source || typeof account.sequence !== 'string' || !/^[0-9]{1,19}$/.test(account.sequence)
    || BigInt(account.sequence) >= sequence) throw new ChainUnchecked();
  return null;
}
