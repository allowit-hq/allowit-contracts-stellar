export interface AdkOwnerStep {
  network: string;
  action: 'upload_wasm' | 'create_wallet' | 'fund';
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
}

type Verifier = {
  memory: WebAssembly.Memory;
  owner_input: () => number;
  owner_verify: (length: number) => number;
};

const inputLimit = 512 * 1024;
const verifierHash = '96619ffac55a01cb18767ff4d9846d4636824c09071ca6e6ddb0e2c1e76befee';
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
  const { memory, owner_input, owner_verify } = instance.exports;
  if (!(memory instanceof WebAssembly.Memory) ||
      typeof owner_input !== 'function' || typeof owner_verify !== 'function') {
    throw new Error('Invalid Stellar owner verifier.');
  }
  return {
    memory,
    owner_input: () => Number(owner_input()),
    owner_verify: length => Number(owner_verify(length)),
  };
}

async function verify(step: AdkOwnerStep, expected: AdkOwnerSelection, signedXdr?: string) {
  verifier ??= loadVerifier().catch(error => {
    verifier = undefined;
    throw error;
  });
  const { memory, owner_input, owner_verify } = await verifier;
  const now = Math.floor(Date.now() / 1000);
  const bytes = new TextEncoder().encode(JSON.stringify({ step, expected, now, signedXdr }));
  if (bytes.length > inputLimit) throw new Error('The Stellar owner transaction exceeds its size limit.');
  let address: number | undefined;
  try {
    address = owner_input();
    new Uint8Array(memory.buffer, address, bytes.length).set(bytes);
    if (owner_verify(bytes.length) !== 1) {
      throw new Error('The Stellar transaction differs from the reviewed owner action.');
    }
  } catch (error) {
    if (error instanceof WebAssembly.RuntimeError) verifier = undefined;
    throw error;
  } finally {
    if (address !== undefined) new Uint8Array(memory.buffer, address, bytes.length).fill(0);
  }
}

export function verifyAdkOwnerStep(step: AdkOwnerStep, expected: AdkOwnerSelection) {
  return verify(step, expected);
}

export function verifyAdkOwnerSignature(step: AdkOwnerStep, expected: AdkOwnerSelection, signedXdr: string) {
  return verify(step, expected, signedXdr);
}
