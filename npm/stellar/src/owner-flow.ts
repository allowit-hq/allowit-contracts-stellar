/**
 * The owner workflows that the SDK exposes through the rail plugin: install the reviewed policy wallet and fund it,
 * and change installed params on an active wallet.
 * The host supplies its authenticated transport, the signing of one step and a journal. This module holds the rules
 * for a saved signed step and for the typed replies of the service.
 */
import {Keypair} from '@stellar/stellar-sdk/base';
import {canonicalNetwork} from './plugin.js';
import {expiredRecord as chainExpiredRecord, horizonGet} from './chain-record.js';
import {APPROVE_POLICY, SET_UP_WALLET, WALLET_SETUP_REQUIRED, WalletSetupPendingError, approvalStep, nativeApprovalHolds, nativeSetupOf, policyApproval, setUpNativeWallet, type ReviewedPolicy} from './native-wallet.js';

/** Rail-neutral owner step. `payload` is opaque text that only this package signs and reads. */
export interface OwnerStep {action: string; payload: string; hash: string; expiresAt: number; explorer?: string | null}
/** The owner's authenticated transport. A rejection carries the server `code` and `details`. */
export type Ask = <T>(path: string, body?: unknown) => Promise<T>;
/** Shows one owner step in the `owner-sign` element and resolves with the exact signed payload. */
export type SignStep = (step: OwnerStep) => Promise<string>;
export interface OwnerJournal {get(key: string): string | null; set(key: string, value: string): void; remove(key: string): void}
export type OwnerReceipt = {policyId: string; action: string; status: string; transactionHash: string; ledger?: number};
export interface InstallAndFundInput {
  /** The network of the policy. */
  network: string;
  /** Milliseconds between reads of a transaction that history does not hold yet. The default is 1500. */
  historyPauseMs?: number;
  ask: Ask; sign: SignStep; journal: OwnerJournal; key: string; policyId: string;
  agent: string; amount: string; onStep: (text: string) => void;
  /**
   * The policy that the owner reviewed: its exact source and every value, and its ordered rules and tier when the
   * host shows them. A Native policy's approval is signed only when it states exactly this policy for the agent's
   * wallet account. Required for Native.
   */
  reviewed?: ReviewedPolicy;
}

/** Typed codes of a refused `native/owner/submit`. The reply body is `{error, code, details}`. */
export const OWNER_TRANSACTION_EXPIRED = 'owner_transaction_expired';
export const OWNER_TRANSACTION_PENDING = 'owner_transaction_pending';
export const OWNER_TRANSACTION_SETTLED = 'owner_transaction_settled';
/** The transaction is in a ledger and failed. `details.ledger` names that ledger. */
export const OWNER_TRANSACTION_FAILED = 'owner_transaction_failed';
/** HTTP 503 with `details.retry = "same_request_id"`: the service sent nothing. */
export const NETWORK_UNAVAILABLE = 'network_unavailable';
/** Typed codes of a refused params update. `details.param` names the param of a refused value. */
export const PARAM_INVALID = 'param_invalid';
export const PARAM_OUT_OF_RANGE = 'param_out_of_range';
/** The policy is not active, or its wallet kind takes no owner-signed update. */
export const UPDATE_UNAVAILABLE = 'update_unavailable';
/** The wallet is at another configuration revision than the update expects. */
export const REVISION_CHANGED = 'revision_changed';
/** The action name of the owner step of a params update. */
export const UPDATE_PARAMS = 'update_params';

/** An owner workflow failure with the typed server code, when the service sent one. */
export class OwnerFlowError extends Error {
  readonly code: string | null;
  /** True when the same saved step can be sent again without a new signature. */
  readonly retry: boolean;
  constructor(message: string, code: string | null, retry: boolean, cause?: unknown) {
    super(message, {cause});
    this.name = 'OwnerFlowError';
    this.code = code;
    this.retry = retry;
  }
}

type Prepared = {policyId: string; step?: Partial<OwnerStep> & {transactionHash?: string}; wallet?: string; installed?: boolean; installation?: {wallet?: string};
  /** The kind of the wallet, and for a Native wallet whether its owner approved the policy. */
  walletKind?: string; approved?: boolean;
  /** A value change of a Native wallet: the approval message in place of a step. */
  approval?: {message?: unknown}; revision?: unknown};
const HASH = /^[0-9a-f]{64}$/;
const object = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);

/** The rail-neutral step of a reply. The server reports its hash as `transactionHash`. */
function stepOf(step: Prepared['step']): OwnerStep | null {
  if (!step || typeof step.action !== 'string' || typeof step.payload !== 'string' || typeof step.expiresAt !== 'number') return null;
  const hash = typeof step.hash === 'string' ? step.hash : step.transactionHash;
  return typeof hash === 'string' && HASH.test(hash)
    ? {action: step.action, payload: step.payload, hash, expiresAt: step.expiresAt, ...(step.explorer ? {explorer: step.explorer} : {})} : null;
}
const installedWallet = (reply: Prepared) => reply.installed ? reply.installation?.wallet ?? reply.wallet : undefined;

/** The key that keeps the signed bytes of an expired step after the journal drops it. */
export function ownerArchiveKey(key: string, hash: string): string {
  return `${key}:expired:${hash}`;
}

const unverified = () => new OwnerFlowError('The network record of the signed step could not be checked. It stays saved; resume to check it again.', null, true);
/**
 * The ledger in which the chain holds this transaction as successful. The service's word alone never clears a
 * signed step or records a funding. History can trail the network by a few seconds, so a missing record is read again.
 */
async function settledLedger(network: string, step: OwnerStep, ledger: unknown, pause: number): Promise<number> {
  for (let attempt = 0; attempt < 5; attempt++) {
    if (attempt) await new Promise(resolve => setTimeout(resolve, pause));
    const response = await horizonGet(network, `/transactions/${step.hash}`);
    if (response?.status === 404) continue;
    const chain: unknown = response?.ok ? await response.json().catch(() => null) : null;
    if (!object(chain) || chain.hash !== step.hash || chain.successful !== true || !Number.isSafeInteger(chain.ledger)
      || (chain.ledger as number) <= 0 || ledger !== undefined && chain.ledger !== ledger) break;
    return chain.ledger as number;
  }
  throw unverified();
}
const unchecked = () => new OwnerFlowError('The expired signed step could not be checked on the network. It stays saved; resume to check it again.', OWNER_TRANSACTION_EXPIRED, true);

/**
 * What the chain holds for a signed step past its time bound: its ledger when it applied, or null when it can
 * never apply. `chain-record.ts` holds the rule. A chain that cannot be read keeps the step saved.
 */
const expiredRecord = (network: string, step: OwnerStep, signedPayload: string): Promise<{ledger: number} | null> =>
  chainExpiredRecord(network, step.hash, signedPayload).catch(() => {throw unchecked();});

/** The 64 bytes of a wallet's message signature, which the wallet returns as base64 text. */
function signatureBytes(signature: unknown): number[] {
  let bytes: number[] = [];
  try {
    bytes = typeof signature === 'string' ? Array.from(atob(signature), c => c.charCodeAt(0)) : [];
  } catch { /* refused below */ }
  if (bytes.length !== 64) throw new OwnerFlowError('Your wallet did not return a message signature.', null, false);
  return bytes;
}

/**
 * Reads a retained signed setup when the service reports the Native wallet installed. True when the setup created
 * `wallet` for this agent with this funding amount: the server registers a wallet only after the network confirmed its
 * setup, so that setup funded it. False when nothing is retained. Any other retained setup stays saved and is
 * refused: it names other inputs, and funding again under them could move the owner's funds twice.
 */
function retainedSetup(raw: string | null, network: string, wallet: string, identity: Identity): boolean {
  if (raw === null) return false;
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch { /* refused below */ }
  const setup = object(value) && typeof value.signedPayload === 'string' ? nativeSetupOf(value.signedPayload, network) : null;
  const inputs = identity as {agent?: string; amount?: string};
  if (!object(value) || !setup || setup.wallet !== wallet || value.agent !== inputs.agent || setup.agent !== inputs.agent || value.amount !== inputs.amount)
    throw changed(identity);
  return true;
}

/** A signed approval of a Native wallet's new values, saved before it is sent. */
type SavedApproval = Identity & {message: string; signer: string; signature: number[]};
function savedApproval(journal: OwnerJournal, key: string, identity: Identity): SavedApproval | null {
  const raw = journal.get(key);
  if (raw === null) return null;
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch { /* refused below */ }
  if (!object(value) || typeof value.message !== 'string' || typeof value.signer !== 'string' || !Array.isArray(value.signature)
    || value.signature.length !== 64 || !value.signature.every(b => Number.isInteger(b) && b >= 0 && b <= 255))
    throw new OwnerFlowError('The saved signed approval is unreadable. It stays saved; contact support before signing again.', null, false);
  if (!sameInputs(value, identity)) throw changed(identity);
  return value as SavedApproval;
}

/** The owner of a wallet account: its one signer of the owner's weight, read from the public ledger. */
async function walletOwner(network: string, account: string, then: string): Promise<string> {
  const response = await horizonGet(network, `/accounts/${account}`);
  const body: unknown = response?.ok ? await response.json().catch(() => null) : null;
  const owners = (object(body) && Array.isArray(body.signers) ? body.signers : []).filter(s => object(s) && s.weight === 3 && s.type === 'ed25519_public_key' && typeof s.key === 'string');
  if (owners.length !== 1) throw new OwnerFlowError(`The owner of the wallet account could not be read from the network. ${then}`, null, true);
  return (owners[0] as {key: string}).key;
}

/** Whether `signature` is the signature of `signer` over the hexadecimal digest of an approval step. */
function ownerSigned(signer: string, hash: string, signature: number[]): boolean {
  return Keypair.fromPublicKey(signer).verify(Uint8Array.from(hash.match(/../g) ?? [], byte => parseInt(byte, 16)), Uint8Array.from(signature));
}

/** Workflows that run in this page, by journal key. */
const running = new Set<string>();
const busy = () => new OwnerFlowError('This wallet setup is already running in this or another tab.', null, true);

/** The inputs that a saved step and a completion marker belong to: the wallet setup or one params update. */
type Identity = {policyId: string; agent: string; amount: string} | {policyId: string; update: string};
const FIELDS = ['policyId', 'agent', 'amount', 'update'] as const;
const changed = (identity: Identity) => new OwnerFlowError('update' in identity
  ? 'The saved signed step belongs to another change. It stays saved; resume that change first.'
  : 'Use the agent key and amount from the original wallet setup. The saved signed step stays saved.', null, false);
/** True when a saved value names these inputs. A value saved without inputs predates them and names none. */
function sameInputs(value: Record<string, unknown>, identity: Identity): boolean {
  const named = FIELDS.filter(field => value[field] !== undefined);
  const inputs = identity as Record<string, string>;
  return named.length === 0 || named.length === Object.keys(inputs).length && named.every(field => value[field] === inputs[field]);
}

function saved(journal: OwnerJournal, key: string, identity: Identity): {step: OwnerStep; signedPayload: string} | null {
  const raw = journal.get(key);
  if (raw === null) return null;
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch { /* fall through */ }
  const step = object(value) ? stepOf(value.step as Prepared['step']) : null;
  if (!object(value) || !step || typeof value.signedPayload !== 'string' || !value.signedPayload)
    throw new OwnerFlowError('The saved signed step is unreadable. It stays saved; contact support before signing again.', null, false);
  if (!sameInputs(value, identity)) throw changed(identity);
  return {step, signedPayload: value.signedPayload};
}

/** True when the funding or the update of these inputs is confirmed. A marker of other inputs is refused. */
function funded(journal: OwnerJournal, fundedKey: string, identity: Identity): boolean {
  const raw = journal.get(fundedKey);
  if (raw === null) return false;
  if (raw === 'confirmed') return true;
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch { /* fall through */ }
  if (!object(value) || !sameInputs(value, identity)) throw changed(identity);
  return true;
}

/** True when Horizon holds this transaction as failed in the ledger that the service named. */
async function failedOnChain(network: string, step: OwnerStep, ledger: unknown): Promise<boolean> {
  if (!Number.isSafeInteger(ledger)) return false;
  const response = await horizonGet(network, `/transactions/${step.hash}`);
  const chain: unknown = response?.ok ? await response.json().catch(() => null) : null;
  return object(chain) && chain.hash === step.hash && chain.ledger === ledger && chain.successful === false;
}

/**
 * Install the reviewed policy wallet, then fund it. The service prepares each owner step and the host signs it.
 * Signed bytes enter the journal before they are sent, so a reload sends the same signature and never signs a step
 * twice. A saved step is settled first:
 * - confirmed, or `owner_transaction_settled` for the same hash: the step is done once the chain holds that
 *   successful transaction. Until then it stays saved and the error has `retry` set;
 * - `owner_transaction_expired`: the chain decides. When the transaction applied before its time bound, the step is
 *   done. When the chain proves that it never applied, its signed bytes move to the archive key and the owner signs
 *   a new step. When the chain cannot be read, the step stays saved and the error has `retry` set;
 * - `owner_transaction_failed`: when the chain holds that failed transaction, its signed bytes move to the archive
 *   key and the owner signs a new step;
 * - `owner_transaction_pending` or `network_unavailable`: the step stays saved and the error has `retry` set.
 * Any other failure keeps the saved step, so no second signature exists while the first can still apply.
 * A saved step and the funded marker name the policy, agent key and amount. A resume with other inputs is refused.
 * One workflow runs per journal key: a second call in this page or, where the browser has Web Locks, in another tab
 * is refused before it reads the journal.
 */
export async function installAndFund(input: InstallAndFundInput): Promise<{wallet: string; receipts: OwnerReceipt[]}> {
  const name = `allowit.owner-flow:${input.key}`;
  if (running.has(name)) throw busy();
  running.add(name);
  try {
    const locks = globalThis.navigator?.locks;
    if (!locks) return await run(input);
    return await locks.request(name, {ifAvailable: true}, async lock => {
      if (!lock) throw busy();
      return run(input);
    });
  } finally {
    running.delete(name);
  }
}

/** The parts of one workflow that send, settle and sign its owner steps. */
interface StepperInput {
  network: string; historyPauseMs: number; ask: Ask; sign: SignStep; journal: OwnerJournal; key: string; policyId: string;
  onStep: (text: string) => void; identity: Identity;
  /** Records a confirmed step before its signed bytes leave the journal. */
  confirmed: (step: OwnerStep) => void;
}
function stepper({network, historyPauseMs, ask, sign, journal, key, policyId, onStep, identity, confirmed}: StepperInput) {
  const receipts: OwnerReceipt[] = [];
  const done = (step: OwnerStep, receipt: OwnerReceipt) => {
    confirmed(step);
    journal.remove(key);
    receipts.push(receipt);
  };
  /** Send a saved step. False means that it expired and the journal dropped it. */
  const submit = async (step: OwnerStep, signedPayload: string): Promise<boolean> => {
    let receipt: OwnerReceipt;
    try {
      receipt = await ask<OwnerReceipt>('native/owner/submit', {policyId, payload: signedPayload});
    } catch (error) {
      const {code, details} = (object(error) ? error : {}) as {code?: unknown; details?: unknown};
      const about = object(details) ? details : {};
      // A typed refusal settles the saved step only when it names that exact transaction.
      const same = about.transactionHash === step.hash && (about.policyId === undefined || about.policyId === policyId);
      if (code === OWNER_TRANSACTION_SETTLED && same) {
        const ledger = await settledLedger(network, step, Number.isSafeInteger(about.ledger) ? about.ledger : undefined, historyPauseMs);
        done(step, {policyId, action: step.action, status: 'confirmed', transactionHash: step.hash, ledger});
        return true;
      }
      if (code === OWNER_TRANSACTION_EXPIRED && same) {
        if (step.expiresAt >= Math.floor(Date.now() / 1000)) throw unchecked();
        const chain = await expiredRecord(network, step, signedPayload);
        if (chain) {
          // The transaction applied before its time bound, so the step is done and is never signed again.
          done(step, {policyId, action: step.action, status: 'confirmed', transactionHash: step.hash, ledger: chain.ledger});
          return true;
        }
        journal.set(ownerArchiveKey(key, step.hash), JSON.stringify({step, signedPayload}));
        journal.remove(key);
        return false;
      }
      // A failed transaction used its sequence and can never apply. The chain must hold that exact failure.
      if (code === OWNER_TRANSACTION_FAILED && same && await failedOnChain(network, step, about.ledger)) {
        journal.set(ownerArchiveKey(key, step.hash), JSON.stringify({step, signedPayload}));
        journal.remove(key);
        return false;
      }
      if (code === OWNER_TRANSACTION_PENDING)
        throw new OwnerFlowError('The network has not settled the signed step yet. Resume in a moment; do not sign again.', code, true, error);
      if (code === NETWORK_UNAVAILABLE && about.retry === 'same_request_id')
        throw new OwnerFlowError('The network is unavailable. Nothing was sent; resume to send the same signed step.', code, true, error);
      throw new OwnerFlowError(error instanceof Error && error.message ? error.message : 'The signed owner step was not confirmed.',
        typeof code === 'string' ? code : null, false, error);
    }
    if (!object(receipt) || receipt.policyId !== policyId || receipt.action !== step.action || receipt.status !== 'confirmed'
      || receipt.transactionHash !== step.hash)
      throw new OwnerFlowError('The network did not confirm the signed owner step.', null, false);
    const ledger = await settledLedger(network, step, receipt.ledger, historyPauseMs);
    done(step, {...receipt, ledger});
    return true;
  };
  /** Settle the saved signed step, if the journal holds one, before anything else is prepared. */
  const settleSaved = async () => {
    const pending = saved(journal, key, identity);
    if (pending) {
      onStep('Checking the saved signed step…');
      if (!await submit(pending.step, pending.signedPayload)) onStep('The saved step can never apply. Preparing a new one…');
    }
  };
  /** `complete` adds what the step needs beside the owner's signature, before the bytes enter the journal. */
  const signAndSubmit = async (step: OwnerStep, complete?: (signedPayload: string) => string) => {
    if (step.expiresAt <= Math.floor(Date.now() / 1000)) throw new OwnerFlowError('The prepared owner step already expired. Resume to prepare a new one.', null, true);
    onStep(`Sign ${step.action.replace(/_/g, ' ')} in your wallet…`);
    const ownerSigned = await sign(step);
    if (typeof ownerSigned !== 'string' || !ownerSigned) throw new OwnerFlowError('Your wallet did not return the signed step.', null, false);
    const signedPayload = complete ? complete(ownerSigned) : ownerSigned;
    journal.set(key, JSON.stringify({step, signedPayload, ...identity}));
    onStep('Waiting for the network to confirm…');
    if (!await submit(step, signedPayload)) throw new OwnerFlowError('The network did not take the signed step. Resume to prepare a new one.', null, true);
  };
  return {receipts, settleSaved, signAndSubmit};
}

/** Whether the ledger holds `account`: true or false, or null when Horizon gives no clear answer. */
async function accountOnLedger(network: string, account: string): Promise<boolean | null> {
  const response = await horizonGet(network, `/accounts/${account}`);
  if (!response) return null;
  if (response.status === 404) return false;
  if (!response.ok) return null;
  try {
    const body: unknown = await response.json();
    return object(body) && body.account_id === account ? true : null;
  } catch {
    return null;
  }
}

async function run({network, ask, sign, journal, key, policyId, agent, amount, reviewed, onStep, historyPauseMs = 1_500}: InstallAndFundInput): Promise<{wallet: string; receipts: OwnerReceipt[]}> {
  if (!canonicalNetwork(network)) throw new OwnerFlowError('Select a supported Stellar network.', null, false);
  const fundedKey = `${key}:funded`;
  const identity: Identity = {policyId, agent, amount};
  const {receipts, settleSaved, signAndSubmit} = stepper({network, historyPauseMs, ask, sign, journal, key, policyId, onStep, identity,
    // A confirmed funding is recorded before its signed bytes leave the journal. A contract wallet's creation funds
    // it in the same transaction.
    confirmed: step => {
      if (step.action === 'fund' || step.action === 'create_wallet') journal.set(fundedKey, JSON.stringify(identity));
    }});
  // A saved step or a funded marker of other inputs is refused before anything is sent.
  saved(journal, key, identity);
  funded(journal, fundedKey, identity);
  await settleSaved();
  let wallet: string | undefined;
  // True once this run set up the wallet account of a Native policy: the deployment then names the wallet.
  let nativeSetUp = false;
  const walletSetupKey = `${key}:wallet-setup`;
  /** Creates and funds the agent's wallet account with one owner signature, and registers it for this policy. */
  const setUpWallet = async (details: unknown) => {
    const roles = object(details) ? details : {};
    if (typeof roles.owner !== 'string' || typeof roles.server !== 'string' || roles.agent !== agent || roles.policyId !== policyId)
      throw new OwnerFlowError('The service named no roles for the wallet account of this policy.', null, false);
    let setup;
    try {
      // The signed setup stays in the journal until the server has registered the wallet, so a run that
      // stops in between finds the same account again.
      setup = await setUpNativeWallet({network, owner: roles.owner, agent, server: roles.server, amount, sign, onStep, journal, key: walletSetupKey, retain: true});
    } catch (cause) {
      if (cause instanceof OwnerFlowError) throw cause;
      throw new OwnerFlowError(cause instanceof Error ? cause.message : 'The wallet account could not be set up.', null, cause instanceof WalletSetupPendingError, cause);
    }
    receipts.push({policyId, action: SET_UP_WALLET, status: 'confirmed', transactionHash: setup.transactionHash, ledger: setup.ledger});
    onStep('Registering the wallet…');
    const registered = await ask<{registered?: unknown; wallet?: unknown; policyId?: unknown}>('native/register', {configuration: setup.configuration, policyId});
    if (!object(registered) || registered.registered !== true || registered.wallet !== setup.wallet || registered.policyId !== policyId)
      throw new OwnerFlowError('The service did not register the wallet account for this policy. Resume to register it; nothing is signed again.', null, true);
    // The setup funded the wallet: no funding step follows.
    journal.set(fundedKey, JSON.stringify(identity));
  };
  /** The owner's approval of the policy of a Native wallet: one message signature, and no transaction. */
  const approvePolicy = async (account: string) => {
    onStep('Preparing the approval…');
    const approval = await ask<{required?: unknown; message?: unknown}>('native/approval', {policyId});
    if (!object(approval) || approval.required !== true) return;
    const fields = policyApproval(approval.message, network);
    if (!reviewed) throw new OwnerFlowError('The policy that you reviewed is missing. Nothing was signed.', null, false);
    if (!fields || fields.policyId !== policyId || fields.wallet !== account || !nativeApprovalHolds(fields, account, reviewed))
      throw new OwnerFlowError('The approval differs from the policy that you reviewed or from its wallet account. Nothing was signed.', null, false);
    const signer = await walletOwner(network, account, 'Resume to read it again.');
    onStep('Sign the approval of the policy in your wallet…');
    const step = approvalStep(approval.message as string), signature = signatureBytes(await sign(step));
    if (!ownerSigned(signer, step.hash, signature))
      throw new OwnerFlowError('Your wallet signed with another account than the owner. Nothing was sent; sign with the owner account.', null, false);
    await ask('micro/allocation/confirm', {id: policyId, revision: fields.revision, sourceApproval: [{signer, signature}]});
    receipts.push({policyId, action: APPROVE_POLICY, status: 'confirmed', transactionHash: ''});
  };

  // A deployment takes at most the wallet creation, which funds it, and a lifetime renewal. The server uploads the
  // code itself.
  for (let i = 0; i < 4 && !wallet; i++) {
    onStep('Preparing the wallet…');
    let reply: Prepared;
    try {
      reply = await ask<Prepared>('native/deploy/prepare', {policyId, agent, amount});
    } catch (error) {
      const {code, details} = (object(error) ? error : {}) as {code?: unknown; details?: unknown};
      // A Native policy needs the wallet account of its agent. This workflow sets the account up from the
      // owner's own account, the server registers it, and the deployment then answers with the wallet.
      if (code === WALLET_SETUP_REQUIRED && !nativeSetUp) {
        await setUpWallet(details);
        nativeSetUp = true;
        i--;
        continue;
      }
      throw error;
    }
    if (!object(reply) || reply.policyId !== policyId) throw new OwnerFlowError('The deployment reply names a different policy.', null, false);
    wallet = installedWallet(reply);
    if (wallet && reply.walletKind === 'native') {
      // A setup of this workflow created and funded the wallet account. A run that stopped after the registration
      // and before its reply kept the signed setup: when it names this wallet, agent and amount, the setup funded
      // it, and that funding is recorded before the setup leaves the journal. What remains is the owner's approval
      // of the policy. A wallet account that this workflow did not fund is funded below.
      if (retainedSetup(journal.get(walletSetupKey), network, wallet, identity)) journal.set(fundedKey, JSON.stringify(identity));
      journal.remove(walletSetupKey);
      if (reply.approved !== true) await approvePolicy(wallet);
      break;
    }
    if (wallet) break;
    const step = stepOf(reply.step);
    if (!step) throw new OwnerFlowError('The service did not prepare an owner step for this policy.', null, false);
    await signAndSubmit(step);
  }
  if (!wallet) throw new OwnerFlowError('The wallet installation could not be confirmed.', null, true);
  // A confirmed funding is never prepared or signed again, including after a reload or a failed export.
  if (!funded(journal, fundedKey, identity)) {
    onStep('Preparing the funding…');
    const funding = await ask<Prepared>('native/owner/prepare', {policyId, action: 'fund', amount});
    const step = stepOf(funding?.step);
    if (!object(funding) || funding.policyId !== policyId || !step || step.action !== 'fund') throw new OwnerFlowError('The funding reply differs from this policy.', null, false);
    await signAndSubmit(step);
  }
  return {wallet, receipts};
}

export interface UpdateParamsInput {
  /** The network of the policy. */
  network: string;
  /** Milliseconds between reads of a transaction that history does not hold yet. The default is 1500. */
  historyPauseMs?: number;
  /** One journal key per change: a confirmed change is never prepared or signed again under its key. */
  ask: Ask; sign: SignStep; journal: OwnerJournal; key: string; policyId: string;
  /** Each changed param with its complete new typed value, such as `{daily_spending_limit: {Int: '50000000'}}`. */
  params: Record<string, unknown>;
  /** The configuration revision that the owner reviewed, when the host shows one. */
  expectedRevision?: number;
  /**
   * What the owner reviewed of the installed policy: its wallet, its exact source, its ordered rules and every value.
   * A Native wallet's change is an approval of the whole policy, so the owner signs it only when it is exactly this
   * policy with the changed params replaced. Required for a Native wallet.
   */
  installed?: {wallet: string; source: string; rules: unknown; params: Record<string, unknown>; tier?: unknown};
  onStep: (text: string) => void;
}

/** Canonical text of a JSON value: object keys in code-unit order at every level. */
function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (object(value)) return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
  return JSON.stringify(value) ?? 'null';
}

/**
 * Change installed params on an active wallet with one owner signature. The service checks each value, prepares
 * the owner step and, when the network confirms it, saves the new params of the installation and of the policy in
 * one write. The wallet keeps its recorded usage and its request nonce.
 * The workflow resumes as `installAndFund` does: a saved signed step is settled first, an expired step that never
 * applied moves to the archive key, and the owner then signs a new step. A confirmed change is never prepared or
 * signed again under its journal key; `done` is then true and `receipts` is empty.
 * A refusal of the service keeps its typed code in `OwnerFlowError.code`: `param_invalid`, `param_out_of_range`,
 * `update_unavailable` or `revision_changed`, and the codes of a refused submission.
 */
export async function updateParams(input: UpdateParamsInput): Promise<{receipts: OwnerReceipt[]; done: boolean}> {
  const name = `allowit.owner-flow:${input.key}`;
  if (running.has(name)) throw busy();
  running.add(name);
  try {
    const locks = globalThis.navigator?.locks;
    if (!locks) return await runUpdate(input);
    return await locks.request(name, {ifAvailable: true}, async lock => {
      if (!lock) throw busy();
      return runUpdate(input);
    });
  } finally {
    running.delete(name);
  }
}

async function runUpdate({network, ask, sign, journal, key, policyId, params, expectedRevision, installed, onStep, historyPauseMs = 1_500}: UpdateParamsInput): Promise<{receipts: OwnerReceipt[]; done: boolean}> {
  if (!canonicalNetwork(network)) throw new OwnerFlowError('Select a supported Stellar network.', null, false);
  if (!object(params) || Object.keys(params).length === 0 || Object.keys(params).length > 32)
    throw new OwnerFlowError('Change one to 32 params.', PARAM_INVALID, false);
  if (expectedRevision !== undefined && !(Number.isSafeInteger(expectedRevision) && expectedRevision >= 0))
    throw new OwnerFlowError('The expected revision is invalid.', REVISION_CHANGED, false);
  const updatedKey = `${key}:updated`;
  const identity: Identity = {policyId, update: canonical({params, ...(expectedRevision === undefined ? {} : {expectedRevision})})};
  const {receipts, settleSaved, signAndSubmit} = stepper({network, historyPauseMs, ask, sign, journal, key, policyId, onStep, identity,
    // A confirmed update is recorded before its signed bytes leave the journal.
    confirmed: step => {if (step.action === UPDATE_PARAMS) journal.set(updatedKey, JSON.stringify(identity));}});
  // A saved step or a marker of another change is refused before anything is sent.
  saved(journal, key, identity);
  if (funded(journal, updatedKey, identity)) return {receipts, done: true};
  await settleSaved();
  if (funded(journal, updatedKey, identity)) return {receipts, done: true};
  const approvalKey = `${key}:approval`;
  const prepare = async (): Promise<Prepared> => {
    onStep('Preparing the change…');
    try {
      return await ask<Prepared>('native/owner/prepare', {policyId, action: UPDATE_PARAMS, params, ...(expectedRevision === undefined ? {} : {expectedRevision})});
    } catch (error) {
      // The service's reason and typed code reach the owner unchanged.
      const code = object(error) && typeof error.code === 'string' ? error.code : null;
      throw new OwnerFlowError(error instanceof Error && error.message ? error.message : 'The change could not be prepared.', code, code === NETWORK_UNAVAILABLE, error);
    }
  };
  /** The approval message of a Native wallet's change, or null for a reply that prepares a transaction. */
  const approvalOf = (prepared: Prepared): string | null =>
    object(prepared) && prepared.policyId === policyId && object(prepared.approval) && !prepared.step ? prepared.approval.message as string : null;
  /**
   * Sends a signed approval of a Native wallet's values. Only a confirmed reply for this policy and change ends the
   * change. Null means that the service no longer holds the preparation of this approval (it expired, or another
   * instance prepared it): the approval never applied, because the service answers a settled approval as confirmed.
   * Any other answer keeps the signed approval saved, and the next call sends the same bytes again.
   */
  const submitApproval = async ({message, signer, signature}: SavedApproval): Promise<{receipts: OwnerReceipt[]; done: boolean} | null> => {
    onStep('Saving the change…');
    let reply: unknown;
    try {
      reply = await ask('native/owner/submit', {policyId, payload: message, sourceApproval: [{signer, signature}]});
    } catch (error) {
      const code = object(error) && typeof error.code === 'string' ? error.code : null;
      if (code === OWNER_TRANSACTION_EXPIRED || (object(error) && error.status === 404)) return null;
      throw new OwnerFlowError(error instanceof Error && error.message ? error.message : 'The change could not be saved.', code, true, error);
    }
    if (!object(reply) || reply.policyId !== policyId || reply.action !== UPDATE_PARAMS || reply.status !== 'confirmed')
      throw new OwnerFlowError('The service did not confirm the change. The signed approval stays saved: resume to send it again.', null, true);
    journal.set(updatedKey, JSON.stringify(identity));
    journal.remove(approvalKey);
    receipts.push({policyId, action: UPDATE_PARAMS, status: 'confirmed', transactionHash: ''});
    return {receipts, done: true};
  };
  const lapsed = () => new OwnerFlowError('The approval lapsed before the service took it. Resume to prepare the same change again.', OWNER_TRANSACTION_EXPIRED, true);
  let prepared: Prepared;
  // A signed approval that a lost reply left saved is sent again before anything new is signed. When the service no
  // longer holds its preparation, the same change is prepared again: the same values give the same message, and the
  // saved signature applies. A message that differs needs the owner's signature again.
  const pendingApproval = savedApproval(journal, approvalKey, identity);
  if (pendingApproval) {
    const settled = await submitApproval(pendingApproval);
    if (settled) return settled;
    prepared = await prepare();
    if (approvalOf(prepared) === pendingApproval.message) return (await submitApproval(pendingApproval)) ?? Promise.reject(lapsed());
    journal.remove(approvalKey);
  } else prepared = await prepare();
  // A Native wallet holds no values on chain: its change is a new approval of the policy, with no transaction.
  const message = approvalOf(prepared);
  if (message !== null) {
    const fields = policyApproval(message, network);
    if (!fields || fields.policyId !== policyId) throw new OwnerFlowError('The approval differs from this change. Nothing was signed.', null, false);
    // The owner signs only the reviewed policy with this change: the same wallet, source and rules, each changed
    // param at exactly its requested value, and every other value as it is installed.
    if (!installed || !object(installed.params))
      throw new OwnerFlowError('The installed policy that you reviewed is missing. Nothing was signed.', null, false);
    if (!nativeApprovalHolds(fields, installed.wallet, {source: installed.source, rules: installed.rules, params: {...installed.params, ...params}, tier: installed.tier}))
      throw new OwnerFlowError('The approval names another policy or other values than this change. Nothing was signed.', null, false);
    const signer = await walletOwner(network, fields.wallet, 'Nothing was signed; try again.');
    onStep('Sign the approval of the new values in your wallet…');
    const step = approvalStep(message), signature = signatureBytes(await sign(step));
    // Only the owner's own signature is kept: another account's signature would be refused and resent forever.
    if (!ownerSigned(signer, step.hash, signature))
      throw new OwnerFlowError('Your wallet signed with another account than the owner. Nothing was saved; sign with the owner account.', null, false);
    // The signed approval is saved before it leaves: a lost reply is settled from it, never signed again.
    const approval: SavedApproval = {...identity, message, signer, signature};
    journal.set(approvalKey, JSON.stringify(approval));
    return (await submitApproval(approval)) ?? Promise.reject(lapsed());
  }
  const step = stepOf(prepared?.step);
  if (!object(prepared) || prepared.policyId !== policyId || !step || step.action !== UPDATE_PARAMS)
    throw new OwnerFlowError('The reply differs from this change.', null, false);
  await signAndSubmit(step);
  return {receipts, done: true};
}
