const inputLimit = 512 * 1024;
const verifierHash = '7a5775f7e37b412d4f876b8688f8ce136158ee60797a6c8f1a8f3c072a4a6ffe';
let verifier;
async function loadVerifier() {
    const response = await fetch(new URL('./owner-verifier.wasm', import.meta.url));
    if (!response.ok)
        throw new Error('The Stellar owner verifier is unavailable.');
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
async function invoke(payload, operation) {
    verifier ??= loadVerifier().catch(error => {
        verifier = undefined;
        throw error;
    });
    const module = await verifier;
    const { memory, owner_input } = module;
    const bytes = new TextEncoder().encode(JSON.stringify(payload));
    if (bytes.length > inputLimit)
        throw new Error('The Stellar owner transaction exceeds its size limit.');
    let address;
    try {
        address = owner_input();
        new Uint8Array(memory.buffer, address, bytes.length).set(bytes);
        return operation(module, bytes.length, address);
    }
    catch (error) {
        if (error instanceof WebAssembly.RuntimeError)
            verifier = undefined;
        throw error;
    }
    finally {
        if (address !== undefined)
            new Uint8Array(memory.buffer, address, Math.max(56, bytes.length)).fill(0);
    }
}
function verify(step, expected, signedXdr) {
    const now = Math.floor(Date.now() / 1000);
    return invoke({ step, expected, now, signedXdr }, (module, length) => {
        if (module.owner_verify(length) !== 1) {
            throw new Error('The Stellar transaction differs from the reviewed owner action.');
        }
    });
}
export function verifyAdkOwnerStep(step, expected) {
    return verify(step, expected);
}
export function verifyAdkOwnerSignature(step, expected, signedXdr) {
    return verify(step, expected, signedXdr);
}
export function deriveAdkOwnerWallet(owner, policyInstance) {
    return invoke({ owner, policyInstance }, (module, length, address) => {
        const size = module.owner_wallet(length);
        if (size !== 56)
            throw new Error('The Stellar wallet selection is invalid.');
        return new TextDecoder().decode(new Uint8Array(module.memory.buffer, address, size));
    });
}
