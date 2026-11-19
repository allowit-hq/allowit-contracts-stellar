/**
 * The Native wallet of an agent: a new classic account, one for each agent. The owner creates and funds it with one
 * signed transaction. That transaction also sets its signers: the owner alone reaches every threshold, and the agent
 * key and the server pay from it only together. The account's own key is random, signs the creation once and then
 * has weight 0. The agent holds a key and no account.
 *
 * This module builds the setup from the owner's own sequence, reads and sends the signed bytes, and returns the
 * installation document that the server registers. The SDK's owner workflow keeps the signed setup and decides when to
 * send it again or replace it. The server takes no part in the setup.
 */
import {Account, Keypair, Memo, Operation, StrKey, TransactionBuilder, type Transaction} from '@stellar/stellar-sdk/base';
import {sha256} from '@noble/hashes/sha256';
import {canonicalNetwork, networkPassphrase} from './networks.js';
import {horizonOrigin} from './chain-record.js';
import {stellarAssetContract} from './stellar-asset.js';

/** The action of the owner step that creates the agent's wallet account. */
export const SET_UP_WALLET = 'set_up_wallet';
/**
 * The action of the owner step that approves the policy of a wallet account. It signs a message and moves nothing.
 * Its payload is the base64 text of the message, as UTF-8, and its hash is the SEP-53 digest of the message.
 */
export const APPROVE_POLICY = 'approve_policy';
/** The typed refusal of a deployment whose policy needs the wallet account of its agent. `details` names the roles. */
export const WALLET_SETUP_REQUIRED = 'wallet_setup_required';
/** The weight of the owner signer: every threshold, alone. */
export const OWNER_WEIGHT = 3;
/** The weight of the agent signer and of the server signer. */
export const AUTOMATED_WEIGHT = 1;
/** The low and medium thresholds: the agent and the server together. */
export const PAYMENT_THRESHOLD = 2;
/** The high threshold: the owner alone. */
export const OWNER_THRESHOLD = 3;
const BASE_RESERVE = 5_000_000n;
/** What the network locks in a wallet account, in stroops: the account and its three signers. */
export const WALLET_RESERVE = 5n * BASE_RESERVE;
/** The XLM that a new wallet holds above its reserve and its funding, in stroops. It pays the fees of the owner's own steps. */
export const WALLET_FEE_FLOAT = 5_000_000n;
/** The most that one setup funds, in stroops. */
const MAX_FUNDING = 1_000_000_000_000_000n;
/** The policy source of a wallet account before its owner approves a policy: transfers in the installed asset. */
const BOOTSTRAP_SOURCE = 'use allowit::prelude::*;\n/// Bootstrap: transfers in the installed asset.\npub fn execute(ctx: &AllowitContext) -> allowit::Result {\n    allowit::operations(ctx, &ctx.params[allowit::OPERATIONS])?;\n    allowit::tokens(ctx, &ctx.params[allowit::TOKENS])?;\n    Ok(())\n}\n';

const hex = (bytes: Uint8Array) => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
const digest = (text: string) => sha256(new TextEncoder().encode(text));
const object = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);

/** Stroops of a decimal XLM amount with at most seven decimals, or null. */
function stroops(amount: string): bigint | null {
  const match = /^([0-9]{1,12})(?:\.([0-9]{1,7}))?$/.exec(amount);
  return match ? BigInt(match[1]) * 10_000_000n + BigInt((match[2] ?? '').padEnd(7, '0')) : null;
}
/** Decimal XLM text of stroops, as an operation amount takes it. */
function decimal(units: bigint): string {
  return `${units / 10_000_000n}.${(units % 10_000_000n).toString().padStart(7, '0')}`;
}

function roles(owner: string, wallet: string, agent: string, server: string): void {
  for (const [name, address] of [['owner', owner], ['wallet', wallet], ['agent', agent], ['server', server]] as const)
    if (!StrKey.isValidEd25519PublicKey(address)) throw new Error(`The ${name} account is invalid.`);
  if (new Set([owner, wallet, agent, server]).size !== 4) throw new Error('The owner, the wallet, the agent and the server must be four accounts.');
}

/** The balance that a new wallet starts with, in stroops: its reserve, its fee float and the owner's funding. */
export function walletStartingBalance(funding: bigint): bigint {
  if (funding < 0n || funding > MAX_FUNDING) throw new Error('The funding amount is out of range.');
  return WALLET_RESERVE + WALLET_FEE_FLOAT + funding;
}

/**
 * The installation document of a wallet account, as the server registers it. It is the document of the rail's own
 * setup: the same identity, the bootstrap source and the native asset. The server reads the roles from the ledger
 * and refuses a document that the account does not match.
 */
export function nativeWalletConfiguration(network: string, wallet: string, owner: string, agent: string, server: string): Record<string, unknown> {
  const id = canonicalNetwork(network);
  if (!id) throw new Error('Select a supported Stellar network.');
  roles(owner, wallet, agent, server);
  const facts = walletFacts(id, wallet);
  return {
    network: id, policyInstance: Array.from(facts.policyInstance), wallet, owner, agent, server,
    route: 'native', language: 'portable',
    params: {operations: {List: [{Str: 'transfer'}]}, tokens: {List: [{Addr: facts.asset}]}},
    asset: facts.asset, assetSymbol: facts.assetSymbol, assetIssuer: facts.assetIssuer, policySource: BOOTSTRAP_SOURCE,
    sourceHash: Array.from(digest(BOOTSTRAP_SOURCE)), moduleDigest: Array.from(new Uint8Array(32)), maxFeeStroops: facts.maxFeeStroops,
  };
}

/** What a wallet account's configuration states of itself: its policy instance, its asset and its fee ceiling. */
function walletFacts(network: string, wallet: string) {
  return {
    policyInstance: digest(`allowit-stellar-native-wallet-v1:${network}:${wallet}`),
    asset: stellarAssetContract('XLM', null, networkPassphrase(network)), assetSymbol: 'XLM', assetIssuer: null, maxFeeStroops: 100_000,
  };
}

/** The terms of one wallet setup. `sequence` is the owner's current account sequence, and `expiresAt` a Unix time. */
export interface NativeSetupTerms {network: string; owner: string; sequence: string; wallet: string; agent: string; server: string; funding: bigint; requestId: string; expiresAt: number}

/**
 * The setup transaction of a wallet account. Its operations are one atomic unit: the creation with the starting
 * balance, the owner signer, the agent signer, and last the server signer with the thresholds and weight 0 for the
 * account's own key. The owner's account is the source and pays the fee.
 */
export function nativeSetupTransaction({network, owner, sequence, wallet, agent, server, funding, requestId, expiresAt}: NativeSetupTerms): Transaction {
  roles(owner, wallet, agent, server);
  if (!/^[0-9]{1,19}$/.test(sequence)) throw new Error('The owner account sequence is invalid.');
  if (!/^[A-Za-z0-9._:-]{8,100}$/.test(requestId)) throw new Error('The setup request identity is invalid.');
  if (!Number.isSafeInteger(expiresAt) || expiresAt <= 0) throw new Error('The setup time bound is invalid.');
  const signer = (ed25519PublicKey: string, weight: number) => ({ed25519PublicKey, weight});
  return new TransactionBuilder(new Account(owner, sequence), {
    fee: String(SETUP_OPERATION_FEE), networkPassphrase: networkPassphrase(network), timebounds: {minTime: 0, maxTime: expiresAt}, memo: Memo.hash(hex(digest(requestId))),
  })
    .addOperation(Operation.createAccount({destination: wallet, startingBalance: decimal(walletStartingBalance(funding))}))
    .addOperation(Operation.setOptions({source: wallet, signer: signer(owner, OWNER_WEIGHT)}))
    .addOperation(Operation.setOptions({source: wallet, signer: signer(agent, AUTOMATED_WEIGHT)}))
    .addOperation(Operation.setOptions({
      source: wallet, masterWeight: 0, lowThreshold: PAYMENT_THRESHOLD, medThreshold: PAYMENT_THRESHOLD, highThreshold: OWNER_THRESHOLD,
      signer: signer(server, AUTOMATED_WEIGHT),
    }))
    .build();
}

/**
 * What a setup transaction does, read from its bytes: the wallet account that it creates, its roles and its
 * starting balance. Null for any other transaction: one that lacks an operation, adds another, names another
 * signer weight or threshold, or leaves the account's own key a weight.
 */
export function nativeSetupOf(payload: string, network: string): {owner: string; wallet: string; agent: string; server: string; startingBalance: bigint} | null {
  let tx: Transaction;
  try {
    const parsed = TransactionBuilder.fromXDR(payload, networkPassphrase(network));
    if ('innerTransaction' in parsed) return null;
    tx = parsed;
  } catch {
    return null;
  }
  const [create, first, second, last, ...rest] = tx.operations;
  if (rest.length || create?.type !== 'createAccount' || create.source !== undefined) return null;
  const wallet = create.destination, starting = stroops(create.startingBalance);
  if (starting === null) return null;
  const plain = (op: typeof first, weight: number): string | null => {
    if (op?.type !== 'setOptions' || op.source !== wallet || !op.signer || !('ed25519PublicKey' in op.signer) || op.signer.weight !== weight) return null;
    const other = [op.masterWeight, op.lowThreshold, op.medThreshold, op.highThreshold, op.inflationDest, op.clearFlags, op.setFlags, op.homeDomain];
    const key = op.signer.ed25519PublicKey;
    return typeof key === 'string' && other.every(value => value === undefined) ? key : null;
  };
  const owner = plain(first, OWNER_WEIGHT), agent = plain(second, AUTOMATED_WEIGHT);
  if (owner === null || agent === null || tx.source !== owner) return null;
  if (last?.type !== 'setOptions' || last.source !== wallet || !last.signer || !('ed25519PublicKey' in last.signer) || last.signer.weight !== AUTOMATED_WEIGHT
    || last.masterWeight !== 0 || last.lowThreshold !== PAYMENT_THRESHOLD || last.medThreshold !== PAYMENT_THRESHOLD || last.highThreshold !== OWNER_THRESHOLD
    || [last.inflationDest, last.clearFlags, last.setFlags, last.homeDomain].some(value => value !== undefined)) return null;
  const server = last.signer.ed25519PublicKey;
  if (typeof server !== 'string') return null;
  try {
    roles(owner, wallet, agent, server);
  } catch {
    return null;
  }
  return {owner, wallet, agent, server, startingBalance: starting};
}

/**
 * A setup that the owner's account cannot pay for, found before any signature. `code` is the typed code of the
 * refusal, whose title is in Allowit's error catalogue; the message says what happened and what the owner does next.
 */
export class SetupRefusal extends Error {
  constructor(public readonly code: 'owner_account_unfunded' | 'owner_balance_low', message: string) {
    super(message);
    this.name = 'SetupRefusal';
  }
}
/** The fee of each operation of the setup transaction, in stroops. */
const SETUP_OPERATION_FEE = 100;
/** The operations of the setup transaction: the creation and three signer changes. */
const SETUP_OPERATIONS = 4;
/** The whole fee of the setup transaction, in stroops: the owner's account pays it. The owner's approval that follows is a message signature and costs nothing. */
export const NATIVE_SETUP_FEE = BigInt(SETUP_OPERATION_FEE * SETUP_OPERATIONS);
/**
 * What an account can spend now, in stroops: its XLM above its own reserve and its selling liabilities. Null when the
 * account record lacks one of the fields that the reserve and the liabilities need: a partial record could refuse an
 * owner who can pay, or pass one who cannot, so the caller stops as for a failed read.
 */
export function spendableXlm(account: Record<string, unknown>): bigint | null {
  const native = Array.isArray(account.balances) ? account.balances.find(b => object(b) && b.asset_type === 'native') as Record<string, unknown> | undefined : undefined;
  const amount = (value: unknown) => typeof value === 'string' ? stroops(value) : null;
  const count = (value: unknown) => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? BigInt(value) : null;
  const balance = amount(native?.balance), selling = amount(native?.selling_liabilities);
  const subentries = count(account.subentry_count), sponsoring = count(account.num_sponsoring), sponsored = count(account.num_sponsored);
  if (balance === null || selling === null || subentries === null || sponsoring === null || sponsored === null) return null;
  const entries = 2n + subentries + sponsoring - sponsored;
  const spendable = balance - selling - (entries > 0n ? entries : 0n) * BASE_RESERVE;
  return spendable > 0n ? spendable : 0n;
}

/** The roles and funding of a Native wallet account's setup. */
export interface NativeSetupInput {
  network: string;
  /** The owner's account. It pays for the setup and signs it. */
  owner: string;
  /** The agent's public key. */
  agent: string;
  /** The server's signer account. */
  server: string;
  /** The XLM that the wallet holds for the agent's payments, as decimal text with at most seven decimals. */
  amount: string;
  fetch?: typeof fetch;
}
/** A setup prepared for the owner's signature. */
export interface PreparedNativeSetup {
  /** The account that the setup creates. */
  wallet: string;
  /** The step that the owner's wallet signs: the exact setup transaction. */
  step: {action: string; payload: string; hash: string; expiresAt: number};
  /**
   * Checks that `ownerSigned` is this transaction with the owner's one signature, and adds the new account's own
   * signature. Returns the signed bytes to send. The account's key lives in this object only and is never stored.
   */
  complete(ownerSigned: string): string;
}

/**
 * Prepares the setup of the wallet account of an agent: one transaction from the owner's own sequence. The account's
 * own key is random; it signs the creation once, beside the owner, in `complete`.
 */
/** The problem type of Horizon's answer for a resource that it does not hold. */
const HORIZON_NOT_FOUND = 'https://stellar.org/horizon-errors/not_found';
export async function prepareNativeSetup({network, owner, agent, server, amount, fetch: send = fetch}: NativeSetupInput): Promise<PreparedNativeSetup> {
  const id = canonicalNetwork(network), base = horizonOrigin(network);
  if (!id || !base) throw new Error('Select a supported Stellar network.');
  const funding = stroops(amount);
  if (funding === null) throw new Error('Enter an amount of XLM with at most seven decimals.');
  const passphrase = networkPassphrase(id);
  // The roles are checked before the network is asked about the owner's address.
  roles(owner, Keypair.random().publicKey(), agent, server);
  const read = await send(`${base}/accounts/${owner}`, {headers: {Accept: 'application/json'}, signal: AbortSignal.timeout(15_000)}).catch(() => null);
  // The network holds no account for an address that never received funds: Horizon answers 404 with its own
  // not_found problem type. Any other 404, such as a proxy's, is a failed read. Nothing is prepared or signed.
  if (read?.status === 404) {
    const problem: unknown = await read.clone().json().catch(() => null);
    if (object(problem) && problem.status === 404 && problem.type === HORIZON_NOT_FOUND)
      throw new SetupRefusal('owner_account_unfunded', 'The network holds no account for the owner address. Send XLM to it, then set up the wallet again.');
    throw new Error('The owner account could not be read from the network.');
  }
  const account: unknown = read?.ok ? await read.json().catch(() => null) : null;
  if (!object(account) || account.account_id !== owner || typeof account.sequence !== 'string' || !/^[0-9]{1,19}$/.test(account.sequence))
    throw new Error('The owner account could not be read from the network.');
  // The owner's account pays the starting balance of the wallet and the fee, and keeps its own reserve.
  // A record without every field that the reserve and the liabilities need establishes nothing: the setup stops as a
  // failed read, before anything is prepared or signed.
  const spendable = spendableXlm(account), needed = walletStartingBalance(funding) + NATIVE_SETUP_FEE;
  if (spendable === null) throw new Error('The balance of the owner account could not be read from the network. Nothing was prepared.');
  if (spendable < needed)
    throw new SetupRefusal('owner_balance_low', `The owner account can spend ${decimal(spendable)} XLM, and this setup needs ${decimal(needed)} XLM: ${decimal(funding)} XLM of funding, ${decimal(WALLET_RESERVE)} XLM that the network locks in the wallet, ${decimal(WALLET_FEE_FLOAT)} XLM for the fees of the owner's own steps and ${decimal(NATIVE_SETUP_FEE)} XLM of setup fee.`);
  // The setup key is random and lives in this object only. Nothing stores, derives or recovers it.
  const setupKey = Keypair.random(), wallet = setupKey.publicKey();
  const requestId = `wallet-${hex(setupKey.rawPublicKey()).slice(0, 32)}`;
  const tx = nativeSetupTransaction({network: id, owner, sequence: account.sequence, wallet, agent, server, funding, requestId, expiresAt: Math.floor(Date.now() / 1000) + 300});
  const hash = hex(tx.hash()), expiresAt = Number(tx.timeBounds?.maxTime);
  return {
    wallet,
    step: {action: SET_UP_WALLET, payload: tx.toXDR(), hash, expiresAt},
    complete(ownerSigned: string): string {
      const signed = TransactionBuilder.fromXDR(ownerSigned, passphrase);
      if ('innerTransaction' in signed || hex(signed.hash()) !== hash || signed.signatures.length !== 1) throw new Error('The wallet returned another transaction. Nothing was sent.');
      // The one signature must be the owner's: the transaction hash leaves signatures out, so another key's signature
      // would pass the check above and the network would refuse the setup.
      if (!Keypair.fromPublicKey(owner).verify(signed.hash(), signed.signatures[0].signature.value))
        throw new Error('The wallet signed with another account than the owner. Nothing was saved or sent; sign with the owner account.');
      signed.sign(setupKey);
      return signed.toXDR();
    },
  };
}

/**
 * What signed setup bytes are: their hash, their roles and their own time bound. Null for bytes that are no setup of
 * this network. The signed bytes decide; saved metadata is unsigned.
 */
export function signedNativeSetupOf(signedPayload: string, network: string): {hash: string; owner: string; wallet: string; agent: string; server: string; validUntil: number} | null {
  const id = canonicalNetwork(network);
  const setup = id ? nativeSetupOf(signedPayload, id) : null;
  if (!id || !setup) return null;
  try {
    const tx = TransactionBuilder.fromXDR(signedPayload, networkPassphrase(id));
    if ('innerTransaction' in tx) return null;
    const validUntil = Number(tx.timeBounds?.maxTime);
    if (!Number.isSafeInteger(validUntil) || validUntil <= 0) return null;
    return {hash: hex(tx.hash()), owner: setup.owner, wallet: setup.wallet, agent: setup.agent, server: setup.server, validUntil};
  } catch {
    return null;
  }
}

/** Sends signed setup bytes to Horizon. The ledger of the successful transaction, or null without a certain answer. */
export async function sendNativeSetup(network: string, signedPayload: string, hash: string, send: typeof fetch = fetch): Promise<number | null> {
  const base = horizonOrigin(network);
  if (!base) return null;
  const sent = await send(`${base}/transactions`, {
    method: 'POST', headers: {Accept: 'application/json', 'Content-Type': 'application/x-www-form-urlencoded'},
    body: `tx=${encodeURIComponent(signedPayload)}`, signal: AbortSignal.timeout(60_000),
  }).catch(() => null);
  const record: unknown = sent?.ok ? await sent.json().catch(() => null) : null;
  return object(record) && record.hash === hash && record.successful === true && Number.isSafeInteger(record.ledger) ? record.ledger as number : null;
}

/** The SEP-53 digest of a wallet message, as lowercase hexadecimal. */
export function messageDigest(message: string): string {
  return hex(digest(`Stellar Signed Message:\n${message}`));
}

/** Canonical text of a JSON value: object keys in code-unit order at every level. */
function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (object(value)) return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
  return JSON.stringify(value) ?? 'null';
}

const APPROVAL_TITLE = 'AllowIt Native policy approval v1';
/** What a policy approval message approves: the policy and its revision, the wallet account, the source and the values. */
export interface PolicyApproval {policyId: string; revision: number; network: string; wallet: string; source: string; sourceHash: string; paramsHash: string;
  /** Every value that the owner approves, by param. */
  params: Record<string, unknown>;
  /** The ordered rules of the policy, as the message states them. */
  rules: unknown;
  /** Every field of the message, as the owner's wallet signs it. */
  fields: Record<string, unknown>}
/**
 * Reads the exact text of a policy approval of `network`: its title line, then the canonical JSON of the approval.
 * Any other text is null: another title, a text that is not the canonical form of its own content, another
 * network or route, or a source or values whose hash differs from the hash that the message states.
 */
export function policyApproval(message: unknown, network: string): PolicyApproval | null {
  const id = canonicalNetwork(network);
  if (typeof message !== 'string' || !id || message.length > 262_144) return null;
  const at = message.indexOf('\n');
  if (at < 0 || message.slice(0, at) !== APPROVAL_TITLE) return null;
  const text = message.slice(at + 1);
  let value: unknown;
  try {value = JSON.parse(text);} catch {return null;}
  if (!object(value) || canonical(value) !== text) return null;
  const {policyId, revision, wallet, source, sourceHash, paramsHash, params, rules} = value;
  if (value.version !== 1 || value.route !== 'native' || value.network !== id || typeof policyId !== 'string' || !policyId || policyId.length > 128
    || !Number.isSafeInteger(revision) || (revision as number) <= 0 || typeof wallet !== 'string' || !StrKey.isValidEd25519PublicKey(wallet)
    || typeof source !== 'string' || typeof sourceHash !== 'string' || hex(digest(source)) !== sourceHash
    || typeof paramsHash !== 'string' || !object(params) || hex(digest(canonical(params))) !== paramsHash) return null;
  return {policyId, revision: revision as number, network: id, wallet, source, sourceHash, paramsHash, params, rules, fields: value};
}

/**
 * The policy that the owner reviewed before an approval: its exact source and every value. Its ordered rules and its
 * tier, which the service derives from the source, are checked too when the host states them.
 */
export interface ReviewedPolicy {source: string; params: Record<string, unknown>; rules?: unknown; tier?: unknown}
/**
 * The fields of an approval that the server derives for its own records: its digests of the source and the name of
 * its installation. A Native wallet enforces none of them.
 */
const SERVER_FIELDS = new Set(['irHash', 'moduleDigest', 'policyInstance']);
/**
 * Whether a policy approval of `wallet` is exactly what the owner reviewed. Every field that the wallet signs is
 * checked: the policy and its revision come from the service; the source, rules, values and tier must be the
 * reviewed ones; the network, wallet, route, asset and fee ceiling must be the wallet account's own configuration,
 * as its setup made it. The server's digests of the source and the name of its installation are left to the server.
 * Any other field, or any other value, is refused.
 */
export function nativeApprovalHolds(approval: PolicyApproval, wallet: string, reviewed: ReviewedPolicy): boolean {
  const own = walletFacts(approval.network, wallet);
  const expected: Record<string, unknown> = {
    version: 1, policyId: approval.policyId, revision: approval.revision, network: approval.network, wallet, route: 'native',
    asset: own.asset, assetSymbol: own.assetSymbol, assetIssuer: own.assetIssuer, maxFeeStroops: own.maxFeeStroops,
    source: reviewed.source, sourceHash: hex(digest(reviewed.source)), params: reviewed.params,
    rules: reviewed.rules === undefined ? approval.fields.rules : reviewed.rules,
    paramsHash: hex(digest(canonical(reviewed.params))), language: approval.fields.language,
    tier: reviewed.tier === undefined ? approval.fields.tier : reviewed.tier,
  };
  const keys = Object.keys(approval.fields).filter(key => !SERVER_FIELDS.has(key));
  return keys.length === Object.keys(expected).length && keys.every(key => key in expected && canonical(approval.fields[key]) === canonical(expected[key]))
    && typeof approval.fields.language === 'string' && /^[a-z0-9-]{1,64}$/.test(approval.fields.language);
}
/** The step that asks the owner's wallet to approve a policy. It signs the message and moves nothing. */
export function approvalStep(message: string, now = Date.now()): {action: string; payload: string; hash: string; expiresAt: number} {
  const bytes = new TextEncoder().encode(message);
  let binary = '';
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return {action: APPROVE_POLICY, payload: btoa(binary), hash: messageDigest(message), expiresAt: Math.floor(now / 1000) + 300};
}
/** The message of an approval step, or null when the payload is no UTF-8 text or differs from the step's hash. */
export function approvalMessage(step: {payload: string; hash: string}): string | null {
  try {
    const message = new TextDecoder('utf-8', {fatal: true}).decode(Uint8Array.from(atob(step.payload), c => c.charCodeAt(0)));
    return messageDigest(message) === step.hash ? message : null;
  } catch {
    return null;
  }
}
