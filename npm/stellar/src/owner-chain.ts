/**
 * What the SDK's owner workflows need from Stellar: the network's record of a transaction, the record of an expired
 * signed step, the setup of a Native wallet account and the owner's approval of a Native policy. The SDK holds the
 * workflows, their journal and their recovery rules; these hooks only read the network and check Stellar signatures.
 */
import {Keypair} from '@stellar/stellar-sdk/base';
import {expiredRecord, horizonGet} from './chain-record.js';
import {OWNER_WEIGHT, WalletSetupPendingError, approvalStep, nativeApprovalHolds, nativeSetupOf, policyApproval, setUpNativeWallet,
  type NativeWalletSetup, type NativeWalletSetupInput, type PolicyApproval, type ReviewedPolicy} from './native-wallet.js';

const object = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);

/** What history holds for a transaction: `'missing'`, its record, or null when the read gave no clear answer. */
export type TransactionRecord = 'missing' | {hash: string; ledger: number; successful: boolean} | null;

/** The record of a transaction in the public ledger history. */
async function transaction(network: string, hash: string): Promise<TransactionRecord> {
  const response = await horizonGet(network, `/transactions/${hash}`);
  if (response?.status === 404) return 'missing';
  const body: unknown = response?.ok ? await response.json().catch(() => null) : null;
  if (!object(body) || typeof body.hash !== 'string' || typeof body.successful !== 'boolean' || !Number.isSafeInteger(body.ledger)) return null;
  return {hash: body.hash, ledger: body.ledger as number, successful: body.successful};
}

/** The owner of a wallet account: its one signer of the owner's weight, read from the public ledger, or null. */
async function walletOwner(network: string, account: string): Promise<string | null> {
  const response = await horizonGet(network, `/accounts/${account}`);
  const body: unknown = response?.ok ? await response.json().catch(() => null) : null;
  const owners = (object(body) && Array.isArray(body.signers) ? body.signers : [])
    .filter(s => object(s) && s.weight === OWNER_WEIGHT && s.type === 'ed25519_public_key' && typeof s.key === 'string');
  return owners.length === 1 ? (owners[0] as {key: string}).key : null;
}

/** Whether `signature` is the signature of `signer` over the hexadecimal digest of an approval step. */
function signedBy(signer: string, hash: string, signature: number[]): boolean {
  try {
    return Keypair.fromPublicKey(signer).verify(Uint8Array.from(hash.match(/../g) ?? [], byte => parseInt(byte, 16)), Uint8Array.from(signature));
  } catch {
    return false;
  }
}

/** The hooks of the SDK's owner workflows. */
export const ownerChain = Object.freeze({
  transaction,
  /** Its ledger when the signed step applied before its time bound, null when it can never apply; throws when unknown. */
  expiredRecord,
  /** A Native wallet account: one owner signature creates and funds it. */
  keypairSetup: Object.freeze({
    run: (input: NativeWalletSetupInput): Promise<NativeWalletSetup> => setUpNativeWallet(input),
    /** The wallet and agent of a signed setup, or null. */
    of: (signedPayload: string, network: string): {wallet: string; agent: string} | null => nativeSetupOf(signedPayload, network),
    /** True when a failed setup stays saved and the same run can resume it without a new signature. */
    pending: (error: unknown): boolean => error instanceof WalletSetupPendingError,
  }),
  /** The owner's approval of a Native policy: one message signature, and no transaction. */
  approval: Object.freeze({
    read: (message: unknown, network: string): PolicyApproval | null => policyApproval(message, network),
    holds: (fields: PolicyApproval, wallet: string, reviewed: ReviewedPolicy): boolean => nativeApprovalHolds(fields, wallet, reviewed),
    step: (message: string) => approvalStep(message),
    walletOwner,
    signedBy,
  }),
});
