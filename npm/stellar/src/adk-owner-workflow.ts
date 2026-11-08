import type {AdkProposal} from './adk-owner-link.js';
import {deriveAdkOwnerWallet, verifyAdkOwnerSignature, verifyAdkOwnerStep, type AdkOwnerSelection, type AdkOwnerStep} from './owner-verifier.js';
import {object, portableExport, type PortableAdmission, type PortablePolicy} from './portable-export.js';
import {canonicalApprovalJson, signStellarTransaction, stellarAccountKey, stellarAssetContractId, type Session} from './stellar-wallet.js';

const network = 'stellar:testnet';
const horizon = 'https://horizon-testnet.stellar.org';
const hashPattern = /^[0-9a-f]{64}$/;
const walletPattern = /^C[A-Z2-7]{55}$/;
const deploymentFee = 2_000_000_000;
const bytesHex = (value: unknown) => Array.isArray(value) && value.length === 32
  && value.every(byte => Number.isInteger(byte) && byte >= 0 && byte <= 255)
  ? value.map(byte => byte.toString(16).padStart(2, '0')).join('') : '';
type Signed = {step: AdkOwnerStep; expected: AdkOwnerSelection; signedXdr: string; sent?: boolean};
type Journal = {agent: string; amount: string; wallet?: string; pending?: Signed; funded?: Signed};
type Reply = {policyId: string; step?: AdkOwnerStep; wallet?: string; installed?: boolean; installation?: {wallet?: string}};
type Receipt = {policyId: string; action: AdkOwnerStep['action']; status: string; transactionHash: string; ledger: number};
type Template = {network: string; asset: string; assetSymbol: string; assetIssuer: string | null; maxFeeStroops: number; tiers: {common?: string}};
export type AdkPolicy = PortablePolicy & {revision: number};

/**
 * Capabilities that the consumer supplies. `request` is its authenticated REST transport; a rejection carries the
 * server `code` and `details`. `verifyInstallation` confirms the installed wallet with the owner. `admitPortableBuild`
 * is the common portable build admission.
 */
export interface AdkOwnerHost {
  request<T>(path: string, body?: unknown, options?: {expectedOwner?: string}): Promise<T>;
  verifyInstallation(policy: AdkPolicy, session: Session & {network: 'stellar'}, current: () => boolean): Promise<void>;
  admitPortableBuild: PortableAdmission;
}

export function adkOwnerKey(owner: string, p: AdkProposal): string {
  return `allowit.stellar.adk.v1:${owner}:${p.revision}:${p.sourceHash}:${p.paramsHash}`;
}

/** Signed bytes of an expired owner transaction, kept after the journal drops it. */
export function adkOwnerArchiveKey(owner: string, transactionHash: string): string {
  return `allowit.stellar.adk.archive.v1:${owner}:${transactionHash}`;
}

export function readAdkOwnerJournal(key: string): Journal | null {
  const raw = localStorage.getItem(key);
  if (raw === null) return null;
  const step = (value: Signed | undefined) => value === undefined || !!value?.step && !!value.expected
    && typeof value.signedXdr === 'string' && typeof value.step.transactionHash === 'string'
    && hashPattern.test(value.step.transactionHash);
  try {
    const saved = JSON.parse(raw) as Journal;
    if (typeof saved?.agent !== 'string' || typeof saved.amount !== 'string' || !step(saved.pending)
      || !step(saved.funded) || saved.wallet !== undefined && !walletPattern.test(saved.wallet)) throw new Error();
    return saved.pending || saved.funded || saved.wallet ? saved : null;
  } catch {
    throw new Error('The saved wallet setup could not be read.');
  }
}

async function hash(source: string): Promise<string> {
  const bytes = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(source));
  return [...new Uint8Array(bytes)].map(byte => byte.toString(16).padStart(2, '0')).join('');
}

async function horizonRead<T>(path: string): Promise<T> {
  const response = await fetch(horizon + path, {credentials: 'omit', redirect: 'error', signal: AbortSignal.timeout(15_000)});
  if (!response.ok) throw new Error('The Stellar transaction could not be checked. Retry with the original signed transaction.');
  return response.json() as Promise<T>;
}

async function sequence(owner: string): Promise<string> {
  const account = await horizonRead<{account_id: string; sequence: string}>(`/accounts/${owner}`);
  if (account.account_id !== owner || !/^[0-9]{1,19}$/.test(account.sequence)) throw new Error('The Stellar owner sequence could not be checked.');
  return (BigInt(account.sequence) + 1n).toString();
}

function policyFrom(policies: AdkPolicy[], policyId: string, proposal: AdkProposal): AdkPolicy {
  const policy = policies.find(item => item.id === policyId);
  const binding = policy?.runtime?.instanceBinding;
  const portable = object(binding?.portable);
  if (!policy || policy.network !== network || policy.code !== proposal.code || policy.sourceHash !== proposal.sourceHash
    || binding?.template !== true || binding.route !== 'policyWallet' || binding.tier !== 'common'
    || portable?.paramsHash !== proposal.paramsHash) throw new Error('The saved policy differs from the reviewed agent draft.');
  return policy;
}

export async function deployAdkOwnerDraft({
  host, proposal, session, agent, amount, current, onStep,
}: {
  host: AdkOwnerHost; proposal: AdkProposal; session: Session; agent: string; amount: string;
  current: () => boolean; onStep: (step: string) => void;
}): Promise<{policyId: string; wallet: string; publicProfile: string}> {
  const owner = session.address;
  if (session.network !== 'stellar') throw new Error('Sign in with the Stellar owner account.');
  stellarAccountKey(owner);
  stellarAccountKey(agent);
  if (agent === owner || !/^(?:0|[1-9][0-9]{0,9})(?:\.[0-9]{1,7})?$/.test(amount) || !/[1-9]/.test(amount))
    throw new Error('Enter your agent’s public key and a positive XLM funding amount.');
  if (!navigator.locks) throw new Error('This browser cannot lock the Stellar signing journal.');
  if (await hash(proposal.code) !== proposal.sourceHash) throw new Error('The agent draft source hash differs.');
  if (await hash(canonicalApprovalJson(proposal.params)) !== proposal.paramsHash) throw new Error('The agent draft parameters differ.');
  const key = adkOwnerKey(owner, proposal);
  const options = {expectedOwner: `stellar:${owner}`};
  const ensureCurrent = () => {
    if (!current()) throw new Error('The owner or draft changed. Any signed transaction remains saved.');
  };
  return navigator.locks.request(key, {ifAvailable: true}, async lock => {
    if (!lock) throw new Error('This wallet setup is already open in another tab.');
    ensureCurrent();
    let journal = readAdkOwnerJournal(key) ?? {agent, amount};
    if (journal.agent !== agent || journal.amount !== amount) throw new Error('Use the agent key and amount from the original wallet setup.');
    const save = (next: Journal) => {
      localStorage.setItem(key, JSON.stringify(next));
      journal = next;
    };
    onStep('Opening policy…');
    const adopted = await host.request<{policies: AdkPolicy[]; selectedId: string}>('authoring/adopt', proposal, options);
    const policy = policyFrom(adopted.policies, adopted.selectedId, proposal);
    const binding = policy.runtime!.instanceBinding!;
    const policyId = policy.id;
    const policyInstance = binding.policyInstance;
    if (typeof policyInstance !== 'string' || !hashPattern.test(policyInstance)) throw new Error('The policy instance is invalid.');
    const expectedWallet = await deriveAdkOwnerWallet(owner, policyInstance);
    if (!walletPattern.test(expectedWallet) || journal.wallet && journal.wallet !== expectedWallet)
      throw new Error('The saved wallet does not match the reviewed policy.');
    const [registry, service] = await Promise.all([
      host.request<{templates: Template[]; server: string}>('native/templates', {}, options),
      host.request<{enginePublicKey: string}>('native/config?network=stellar:testnet', undefined, options),
    ]);
    const template = registry.templates.find(item => item.network === network);
    const wasmHash = template?.tiers.common;
    const server = registry.server;
    const asset = template?.asset;
    if (!template || !wasmHash || !hashPattern.test(wasmHash) || !asset
      || asset !== stellarAssetContractId('XLM', null, network)
      || template.assetSymbol !== 'XLM' || template.assetIssuer !== null || template.maxFeeStroops !== binding.maxFeeStroops
      || !Number.isSafeInteger(template.maxFeeStroops) || template.maxFeeStroops < 100
      || server !== service.enginePublicKey || server === owner || server === agent)
      throw new Error('The Stellar Testnet wallet template does not match the reviewed policy.');
    stellarAccountKey(server);
    const ask = <T,>(path: string, body: unknown) => {
      ensureCurrent();
      return host.request<T>(path, body, options);
    };
    const verifySaved = async (signed: Signed) => {
      ensureCurrent();
      const expected = signed.expected;
      if (expected.owner !== owner || expected.agent !== agent || expected.server !== server || expected.wallet !== expectedWallet
        || expected.policyInstance !== policyInstance || expected.sourceHash !== proposal.sourceHash
        || expected.code !== proposal.code || canonicalApprovalJson(expected.params) !== canonicalApprovalJson(proposal.params)
        || expected.wasmHash !== wasmHash || expected.asset !== asset || expected.amount !== amount)
        throw new Error('The saved owner transaction differs from this policy and funding request.');
      await verifyAdkOwnerSignature(signed.step, signed.expected, signed.signedXdr);
    };
    /** Settle a signed step. False means the step can never apply and the journal dropped it. */
    const confirm = async (signed: Signed): Promise<boolean> => {
      await verifySaved(signed);
      const expired = () => Math.floor(Date.now() / 1000) > signed.step.expiresAt;
      if (signed.sent === false && expired()) {
        save({...journal, pending: undefined});
        return false;
      }
      ensureCurrent();
      save({...journal, pending: {...signed, sent: true}});
      let receipt: Receipt;
      try {
        // After its time bound, the server only reads the original result. It never sends the step again.
        receipt = await ask<Receipt>('native/owner/submit', {policyId, transactionXdr: signed.signedXdr});
      } catch (error) {
        const {code, details} = error as {code?: unknown; details?: unknown};
        const failed = object(details);
        if (failed?.policyId === policyId && failed.action === signed.step.action && failed.transactionHash === signed.step.transactionHash) {
          if (code === 'owner_transaction_expired' && expired()) {
            localStorage.setItem(adkOwnerArchiveKey(owner, signed.step.transactionHash), JSON.stringify(signed));
            save({...journal, pending: undefined});
            return false;
          }
          if (code === 'owner_transaction_failed') {
            const chain = await horizonRead<{hash: string; ledger: number; successful: boolean}>(`/transactions/${signed.step.transactionHash}`);
            if (chain.hash === signed.step.transactionHash && chain.ledger === failed.ledger && chain.successful === false)
              save({...journal, pending: undefined});
          }
        }
        throw error;
      }
      if (receipt.policyId !== policyId || receipt.action !== signed.step.action || receipt.status !== 'confirmed'
        || receipt.transactionHash !== signed.step.transactionHash || !Number.isSafeInteger(receipt.ledger) || receipt.ledger <= 0)
        throw new Error('The Stellar reply did not confirm the saved owner transaction.');
      const chain = await horizonRead<{hash: string; ledger: number; successful: boolean}>(`/transactions/${receipt.transactionHash}`);
      if (chain.hash !== receipt.transactionHash || chain.ledger !== receipt.ledger || chain.successful !== true)
        throw new Error('Stellar did not confirm the saved owner transaction.');
      save({...journal, pending: undefined, ...(signed.step.action === 'create_wallet' ? {wallet: expectedWallet} : {}),
        ...(signed.step.action === 'fund' ? {funded: signed} : {})});
      return true;
    };
    if (journal.pending && journal.pending.step.action !== 'fund') {
      onStep('Checking the saved transaction…');
      await confirm(journal.pending);
    }
    const sign = async ({network: stepNetwork, action, transactionXdr, transactionHash, expiresAt}: AdkOwnerStep, wallet: string) => {
      if (journal.pending) throw new Error('Check the saved owner transaction before signing another one.');
      const step = {network: stepNetwork, action, transactionXdr, transactionHash, expiresAt};
      const now = Math.floor(Date.now() / 1000);
      const expected: AdkOwnerSelection = {
        owner, agent, server, policyInstance, code: proposal.code, sourceHash: proposal.sourceHash,
        params: proposal.params, wasmHash, wallet, asset, policyMaxFeeStroops: template.maxFeeStroops,
        maxFeeStroops: step.action === 'fund' ? template.maxFeeStroops : deploymentFee,
        amount, nextSequence: await sequence(owner), validUntil: now + 300,
      };
      ensureCurrent();
      await verifyAdkOwnerStep(step, expected);
      ensureCurrent();
      onStep(step.action === 'fund' ? 'Sign the XLM funding in your wallet…'
        : step.action === 'extend' ? 'Sign the wallet renewal in your wallet…' : 'Sign the deployment in your wallet…');
      let signed: Signed | undefined;
      // Only verified bytes enter the journal. Invalid bytes there would block every later Resume.
      await signStellarTransaction(step.transactionXdr, owner, network, async signedXdr => {
        await verifyAdkOwnerSignature(step, expected, signedXdr);
        signed = {step, expected, signedXdr, sent: false};
        save({...journal, pending: signed});
      });
      if (!signed) throw new Error('Your wallet did not return the signed transaction.');
      if (!await confirm(signed)) throw new Error('The unsent signature expired. Resume to prepare the next transaction.');
    };

    onStep('Preparing the Stellar wallet…');
    let installed: string | undefined;
    // Upload, creation and a lifetime renewal each take one step before the installation reply.
    for (let index = 0; index < 4; index++) {
      const reply = await ask<Reply>('native/deploy/prepare', {policyId, agent});
      if (reply.policyId !== policyId) throw new Error('The deployment reply names a different policy.');
      if (reply.installed === true && reply.installation?.wallet === expectedWallet) {
        installed = expectedWallet;
        break;
      }
      if (!reply.step || reply.wallet !== expectedWallet
        || !['upload_wasm', 'create_wallet', 'extend'].includes(reply.step.action))
        throw new Error('The Stellar service did not prepare this wallet for deployment.');
      await sign(reply.step, reply.wallet);
    }
    if (!installed) throw new Error('The Stellar wallet installation could not be confirmed.');
    onStep('Verifying the deployed wallet…');
    const workspace = await host.request<{policies: AdkPolicy[]}>('micro/policies', undefined, options);
    const bound = policyFrom(workspace.policies, policyId, proposal);
    if (bound.runtime?.instanceBinding?.wallet !== installed) throw new Error('The policy did not retain this deployed wallet.');
    await host.verifyInstallation(bound, {...session, network: 'stellar'}, current);
    ensureCurrent();
    if (journal.pending) {
      if (journal.pending.step.action !== 'fund') throw new Error('The saved owner transaction is not a funding transaction.');
      onStep('Checking the saved funding transaction…');
      await confirm(journal.pending);
    }
    if (journal.funded) {
      if (journal.funded.step.action !== 'fund' || journal.funded.expected.wallet !== installed)
        throw new Error('The saved funding names a different wallet.');
      await verifySaved(journal.funded);
      const chain = await horizonRead<{hash: string; successful: boolean}>(`/transactions/${journal.funded.step.transactionHash}`);
      if (chain.hash !== journal.funded.step.transactionHash || chain.successful !== true)
        throw new Error('Stellar did not confirm the saved funding transaction.');
    } else {
      onStep('Preparing XLM funding…');
      const funding = await ask<Reply>('native/owner/prepare', {policyId, action: 'fund', amount});
      if (funding.policyId !== policyId || funding.wallet !== installed || funding.step?.action !== 'fund')
        throw new Error('The funding reply differs from this installed policy.');
      await sign(funding.step, installed);
    }
    ensureCurrent();
    onStep('Preparing agent access…');
    const profile = await ask<Record<string, unknown>>('native/export', {policyId});
    const config = object(profile.config);
    const endpoints = object(profile.endpoints);
    const reviewed = object(bound.runtime?.instanceBinding?.portable);
    if (profile.version !== 1 || profile.profile !== 'allowit-stellar-wallet-v1'
      || profile.policyId !== policyId || profile.network !== network || profile.route !== 'policyWallet'
      || profile.wallet !== installed || profile.sourceHash !== proposal.sourceHash || profile.moduleDigest !== wasmHash || profile.irHash !== bound.irHash
      || config?.wallet !== installed || config.owner !== owner || config.agent !== agent || config.server !== server
      || config.network !== network || config.route !== 'policyWallet' || config.policySource !== proposal.code
      || config.asset !== asset || config.assetSymbol !== 'XLM' || config.assetIssuer !== null
      || config.maxFeeStroops !== template.maxFeeStroops || bytesHex(config.policyInstance) !== policyInstance
      || bytesHex(config.sourceHash) !== proposal.sourceHash || bytesHex(config.moduleDigest) !== wasmHash
      || !bytesHex(config.sourceDigest) || canonicalApprovalJson(config.rules ?? []) !== canonicalApprovalJson(reviewed?.rules ?? [])
      || endpoints?.execute !== '/api/native/execute' || endpoints.status !== '/api/native/execute/status')
      throw new Error('The public agent profile differs from the funded policy.');
    const portable = portableExport(profile, config, bound, host.admitPortableBuild);
    const publicProfile = {
      ...portable.top, version: 1, profile: profile.profile, policyId, network, route: profile.route, wallet: installed,
      sourceHash: proposal.sourceHash, irHash: profile.irHash, moduleDigest: wasmHash,
      config: {
        ...portable.config, network, policyInstance: config.policyInstance, wallet: installed, owner, agent, server,
        route: 'policyWallet', asset, assetSymbol: 'XLM', assetIssuer: null, policySource: proposal.code,
        sourceHash: config.sourceHash, moduleDigest: config.moduleDigest, maxFeeStroops: template.maxFeeStroops,
      },
      endpoints: {execute: endpoints.execute, status: endpoints.status},
    };
    return {policyId, wallet: installed, publicProfile: JSON.stringify(publicProfile, null, 2)};
  });
}
