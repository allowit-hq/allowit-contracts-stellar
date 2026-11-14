export interface AdkOwnerStep {
  network: string;
  action: 'upload_wasm' | 'create_wallet' | 'extend' | 'fund' | 'update_params';
  transactionXdr: string;
  transactionHash: string;
  expiresAt: number;
}

export interface AdkOwnerSelection {
  owner: string;
  agent: string;
  server: string;
  policyInstance: string;
  code: string;
  sourceHash: string;
  params: Record<string, unknown>;
  wasmHash: string;
  wallet?: string;
  asset: string;
  maxFeeStroops: number;
  policyMaxFeeStroops: number;
  amount: string;
  nextSequence: string;
  validUntil: number;
  /**
   * The params update that the owner reviewed, for an `update_params` step. `params` then holds the complete new
   * params. `deploymentVersion` is the configuration revision that the update writes, in canonical decimal text,
   * and `x402Enabled` is the installed x402 choice, which the update keeps.
   */
  update?: {deploymentVersion: string; x402Enabled: boolean};
}

type Verifier = {
  memory: WebAssembly.Memory;
  owner_input: () => number;
  owner_verify: (length: number) => number;
  owner_wallet: (length: number) => number;
};

const inputLimit = 512 * 1024;
const verifierHash = 'c37525ef8de5a3b037d033896aebb7edc45ae32299e6f863041fa5f4b9085690';
let verifier: Promise<Verifier> | undefined;

async function loadVerifier(): Promise<Verifier> {
  const response = await fetch(new URL('./owner-verifier.wasm', import.meta.url));
  if (!response.ok) throw new Error('The Stellar owner verifier is unavailable.');
  const wasm = await response.arrayBuffer();
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', wasm));
  if (Array.from(digest, byte => byte.toString(16).padStart(2, '0')).join('') !== verifierHash) {
    throw new Error('The Stellar owner verifier differs from the reviewed artifact.');
  }
  const { instance } = await WebAssembly.instantiate(wasm);
  const { memory, owner_input, owner_verify, owner_wallet } = instance.exports;
  if (!(memory instanceof WebAssembly.Memory) ||
      typeof owner_input !== 'function' || typeof owner_verify !== 'function' || typeof owner_wallet !== 'function') {
    throw new Error('Invalid Stellar owner verifier.');
  }
  return {
    memory,
    owner_input: () => Number(owner_input()),
    owner_verify: length => Number(owner_verify(length)),
    owner_wallet: length => Number(owner_wallet(length)),
  };
}

async function invoke<T>(payload: object, operation: (module: Verifier, length: number, address: number) => T) {
  verifier ??= loadVerifier().catch(error => {
    verifier = undefined;
    throw error;
  });
  const module = await verifier;
  const { memory, owner_input } = module;
  const bytes = new TextEncoder().encode(JSON.stringify(payload));
  if (bytes.length > inputLimit) throw new Error('The Stellar owner transaction exceeds its size limit.');
  let address: number | undefined;
  try {
    address = owner_input();
    new Uint8Array(memory.buffer, address, bytes.length).set(bytes);
    return operation(module, bytes.length, address);
  } catch (error) {
    if (error instanceof WebAssembly.RuntimeError) verifier = undefined;
    throw error;
  } finally {
    if (address !== undefined) new Uint8Array(memory.buffer, address, Math.max(56, bytes.length)).fill(0);
  }
}

function verify(step: AdkOwnerStep, expected: AdkOwnerSelection, now: number, signedXdr?: string) {
  return invoke({ step, expected, now, signedXdr }, (module, length) => {
    if (module.owner_verify(length) !== 1) {
      throw new Error('The Stellar transaction differs from the reviewed owner action.');
    }
  });
}

/** Check a step before the owner signs it. The step must be fresh now. */
export function verifyAdkOwnerStep(step: AdkOwnerStep, expected: AdkOwnerSelection) {
  return verify(step, expected, Math.floor(Date.now() / 1000));
}

/**
 * Check a saved signed step at the last second of its time bound, not at the present time. The time bound already
 * limits where it can apply, so an expired step still verifies for recovery and receipts.
 */
export function verifyAdkOwnerSignature(step: AdkOwnerStep, expected: AdkOwnerSelection, signedXdr: string) {
  return verify(step, expected, step.expiresAt - 1, signedXdr);
}

export function deriveAdkOwnerWallet(owner: string, policyInstance: string) {
  return invoke({ owner, policyInstance }, (module, length, address) => {
    const size = module.owner_wallet(length);
    if (size !== 56) throw new Error('The Stellar wallet selection is invalid.');
    return new TextDecoder().decode(new Uint8Array(module.memory.buffer, address, size));
  });
}
