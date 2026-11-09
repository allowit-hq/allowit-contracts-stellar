import { canonicalNetwork, networkPassphrase, strkey } from '../plugin.js';
import { base, emit, expiry, h } from './base.js';
import { link } from './display.js';
const failure = (error, code) => ({ code: String(error?.code ?? code), message: error instanceof Error ? error.message : String(error) });
const hex = (bytes) => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
export function ownerStep(value) {
    if (!value || typeof value !== 'object')
        return null;
    const v = value;
    const expiresAt = Number(v.expiresAt ?? v.expires_at);
    if (typeof v.action !== 'string' || typeof v.payload !== 'string' || typeof v.hash !== 'string' || !/^[0-9a-f]{64}$/.test(v.hash)
        || !Number.isSafeInteger(expiresAt) || expiresAt <= 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(v.payload) || v.payload.length > 1_398_104)
        return null;
    return { action: v.action, payload: v.payload, hash: v.hash, expiresAt, explorer: typeof v.explorer === 'string' ? v.explorer : null };
}
/** The transaction hash of `payload` on `network`. The owner signs nothing whose hash differs from the reviewed step. */
export async function payloadHash(payload, network) {
    const { TransactionBuilder } = await import('@stellar/stellar-sdk/base');
    return hex(TransactionBuilder.fromXDR(payload, networkPassphrase(network)).hash());
}
/**
 * The wallet's signed envelope is the reviewed transaction (same hash on `network`) and carries a valid
 * signature by `owner` over that hash.
 */
export async function signedPayloadValid(signed, network, hash, owner) {
    try {
        const { Keypair, TransactionBuilder } = await import('@stellar/stellar-sdk/base');
        const tx = TransactionBuilder.fromXDR(signed, networkPassphrase(network));
        const digest = tx.hash();
        if (hex(digest) !== hash)
            return false;
        const key = Keypair.fromPublicKey(owner);
        // XDR opaque values wrap their bytes in `value`.
        const bytes = (v) => Uint8Array.from((v instanceof Uint8Array ? v : v.value));
        const hint = hex(bytes(key.signatureHint()));
        return tx.signatures.some(s => hex(bytes(s.hint)) === hint && key.verify(digest, bytes(s.signature)));
    }
    catch {
        return false;
    }
}
/** CAIP-122 sign-in text: the first line names this site, the second line is the signing account. */
export function signInMessageFor(message, address, host) {
    const lines = message.split('\n');
    return lines.length > 2 && lines[0].startsWith(`${host} wants you to sign in with your `) && lines[0].endsWith(' account:') && lines[1] === address;
}
function button(text, onClick) {
    const node = h('button', { type: 'button' }, text);
    node.addEventListener('click', onClick);
    return node;
}
export function walletSignInElement() {
    return class extends base() {
        render() {
            const { network } = (this.data ?? {});
            const id = canonicalNetwork(network);
            const status = h('p', { class: 'status', role: 'status' });
            const pending = this.data?.message;
            // Two phases: without a message the element only connects and reports the address; with the
            // server's address-bound message it signs that message.
            const go = button(typeof pending === 'string' ? 'Approve the sign-in message' : 'Sign in with a Stellar wallet', async () => {
                const message = this.data?.message;
                go.disabled = true;
                status.textContent = 'Waiting for the wallet…';
                try {
                    if (!id || (message != null && typeof message !== 'string'))
                        throw Object.assign(new Error('The sign-in request is invalid.'), { code: 'invalid' });
                    const { connectWallet, signWalletMessage } = await import('./wallet.js');
                    const address = await connectWallet(id);
                    if (message == null) {
                        status.textContent = '';
                        emit(this, 'allowit-signed-in', { address });
                        return;
                    }
                    if (!signInMessageFor(message, address, location.host))
                        throw Object.assign(new Error('The sign-in message does not match this site and account. Nothing was signed.'), { code: 'invalid' });
                    const signature = await signWalletMessage(message, address, id);
                    status.textContent = '';
                    emit(this, 'allowit-signed-in', { address, signature });
                }
                catch (error) {
                    status.textContent = error instanceof Error ? error.message : String(error);
                    emit(this, 'allowit-error', failure(error, 'wallet'));
                }
                finally {
                    go.disabled = false;
                }
            });
            go.disabled = !id;
            this.replaceChildren(go, status);
        }
    };
}
export function ownerSignElement() {
    return class extends base() {
        render() {
            const data = (this.data ?? {});
            const id = canonicalNetwork(data.network), step = ownerStep(data.step);
            const summary = Array.isArray(data.summary) ? data.summary : [];
            if (!id || !step) {
                this.replaceChildren(h('p', { class: 'invalid' }, 'This owner step is invalid.'));
                return;
            }
            const rows = summary.flatMap(row => [h('dt', {}, String(row.label ?? '')), h('dd', {}, String(row.value ?? ''))]);
            rows.push(h('dt', {}, 'Transaction'), h('dd', {}, link(id, 'tx', step.hash, `${step.hash.slice(0, 8)}…`)));
            rows.push(h('dt', {}, 'Expires'), h('dd', {}, expiry(step.expiresAt)));
            const status = h('p', { class: 'status', role: 'status' });
            const sign = button('Sign in wallet', async () => {
                sign.disabled = true;
                status.textContent = 'Checking the transaction…';
                try {
                    if (step.expiresAt <= Date.now() / 1000)
                        throw Object.assign(new Error('This owner step expired. Prepare it again.'), { code: 'expired' });
                    if (await payloadHash(step.payload, id) !== step.hash)
                        throw Object.assign(new Error('The transaction differs from the reviewed step. Nothing was signed.'), { code: 'mismatch' });
                    const expected = data.expected;
                    if (expected && typeof expected === 'object') {
                        const { verifyAdkOwnerStep } = await import('../owner-verifier.js');
                        await verifyAdkOwnerStep({ network: id, action: step.action, transactionXdr: step.payload, transactionHash: step.hash, expiresAt: step.expiresAt }, expected);
                    }
                    const { connectWallet, signWalletTransaction } = await import('./wallet.js');
                    const owner = typeof data.owner === 'string' && strkey(data.owner) ? data.owner : await connectWallet(id);
                    status.textContent = 'Waiting for the wallet…';
                    const signedPayload = await signWalletTransaction(step.payload, owner, id);
                    if (!await signedPayloadValid(signedPayload, id, step.hash, owner))
                        throw Object.assign(new Error('The wallet returned another transaction or no owner signature. Nothing was sent.'), { code: 'mismatch' });
                    status.textContent = 'Signed.';
                    emit(this, 'allowit-signed', { signedPayload, hash: step.hash });
                }
                catch (error) {
                    status.textContent = error instanceof Error ? error.message : String(error);
                    emit(this, 'allowit-error', failure(error, 'sign'));
                }
                finally {
                    sign.disabled = false;
                }
            });
            const cancel = button('Cancel', () => emit(this, 'allowit-cancel'));
            this.replaceChildren(h('dl', { class: 'owner-step' }, ...rows), h('div', { class: 'actions' }, sign, cancel), status);
        }
    };
}
/** Checks an installation's shape and identities, and reports the result. The host keeps the server checks. */
export function bindingReviewElement() {
    return class extends base() {
        render() {
            const data = (this.data ?? {});
            const id = canonicalNetwork(data.network);
            const installation = (data.installation ?? {});
            const owner = typeof installation.owner === 'string' ? installation.owner : '';
            const wallet = typeof installation.wallet === 'string' ? installation.wallet : '';
            const ok = !!id && installation.network === id && !!strkey(owner) && !!strkey(wallet)
                && /^[a-f0-9]{64}$/.test(String(installation.sourceHash)) && installation.state === 'installed';
            const rows = [
                h('dt', {}, 'Wallet'), h('dd', {}, id && wallet ? link(id, wallet.startsWith('C') ? 'contract' : 'address', wallet, wallet) : wallet),
                h('dt', {}, 'Owner'), h('dd', {}, id && owner ? link(id, 'address', owner, owner) : owner),
                h('dt', {}, 'Result'), h('dd', {}, ok ? 'The installation matches this network and policy source.' : 'The installation does not match.'),
            ];
            this.replaceChildren(h('dl', { class: 'binding-review' }, ...rows));
            queueMicrotask(() => emit(this, 'allowit-verified', { ok, detail: ok ? 'installed' : 'mismatch' }));
        }
    };
}
