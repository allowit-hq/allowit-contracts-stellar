import { canonicalNetwork, networkPassphrase, strkey } from '../plugin.js';
import { base, emit, expiry, h } from './base.js';
import { link } from './display.js';
import { CREATE_FEE_ACCOUNT, DERIVE_FEE_ACCOUNT_KEY, feeAccountDerivation, messageDigest } from '../fee-account.js';
/**
 * What the creation of a fee account does, read from the transaction itself: the new account and the XLM that the
 * owner's account sends to it. Null when the first operation creates no account.
 */
export async function feeAccountCreation(payload, network) {
    try {
        const { TransactionBuilder } = await import('@stellar/stellar-sdk/base');
        const tx = TransactionBuilder.fromXDR(payload, networkPassphrase(network));
        const first = 'innerTransaction' in tx ? undefined : tx.operations[0];
        return first?.type === 'createAccount' ? { account: first.destination, funding: `${first.startingBalance.replace(/\.?0+$/, '')} XLM` } : null;
    }
    catch {
        return null;
    }
}
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
            const cancel = button('Cancel', () => emit(this, 'allowit-cancel'));
            if (step.action === DERIVE_FEE_ACCOUNT_KEY) {
                // This step signs a message, never a transaction: the signature derives the one-time key of the fee
                // account. Only the exact derivation message of this network is signed, and the owner reads what it names.
                let message = null;
                try {
                    message = atob(step.payload);
                }
                catch { /* invalid below */ }
                const fields = feeAccountDerivation(message, id);
                if (message === null || !fields || messageDigest(message) !== step.hash) {
                    this.replaceChildren(h('p', { class: 'invalid' }, 'This owner step is invalid.'));
                    return;
                }
                const text = message;
                rows.push(h('dt', {}, 'Fee account for agent'), h('dd', {}, link(id, 'address', fields.agent, fields.agent)));
                rows.push(h('dt', {}, 'Fee account for wallet'), h('dd', {}, link(id, 'contract', fields.wallet, fields.wallet)));
                rows.push(h('dt', {}, 'What you sign'), h('dd', {}, 'A message that derives the setup key of the fee account. It moves no funds.'));
                const status = h('p', { class: 'status', role: 'status' });
                const sign = button('Sign the message', async () => {
                    sign.disabled = true;
                    status.textContent = 'Waiting for the wallet…';
                    try {
                        if (step.expiresAt <= Date.now() / 1000)
                            throw Object.assign(new Error('This owner step expired. Prepare it again.'), { code: 'expired' });
                        const { connectWallet, signWalletMessage } = await import('./wallet.js');
                        const owner = typeof data.owner === 'string' && strkey(data.owner) ? data.owner : await connectWallet(id);
                        const signedPayload = await signWalletMessage(text, owner, id);
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
                this.replaceChildren(h('dl', { class: 'owner-step' }, ...rows), h('div', { class: 'actions' }, sign, cancel), status);
                return;
            }
            rows.push(h('dt', {}, 'Transaction'), h('dd', {}, link(id, 'tx', step.hash, `${step.hash.slice(0, 8)}…`)));
            rows.push(h('dt', {}, 'Expires'), h('dd', {}, expiry(step.expiresAt)));
            const list = h('dl', { class: 'owner-step' }, ...rows);
            if (step.action === CREATE_FEE_ACCOUNT) {
                // The owner reads what this step funds before the wallet opens: the account that pays the agent's
                // network fees, and the XLM that it starts with.
                void feeAccountCreation(step.payload, id).then(created => {
                    if (!created || !list.isConnected)
                        return;
                    list.append(h('dt', {}, 'Fee account'), h('dd', {}, link(id, 'address', created.account, created.account)), h('dt', {}, 'You fund it with'), h('dd', {}, `${created.funding}: its reserve and the float that pays your agent's network fees. Only you can take it back.`));
                });
            }
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
            this.replaceChildren(list, h('div', { class: 'actions' }, sign, cancel), status);
        }
    };
}
const ATTESTATION_TITLE = 'Allowit custom build attestation v1';
const ATTESTATION_KEYS = ['network', 'policy', 'source-sha256', 'code-sha256', 'server', 'presignature', 'owner'];
/**
 * Reads the exact text of a custom build attestation: its title line, then one `key: value` line for each field in
 * order. Any other text is null. A value is printable ASCII without a space; hashes and the presignature are
 * lowercase hexadecimal.
 */
export function buildAttestation(message) {
    if (typeof message !== 'string')
        return null;
    const lines = message.split('\n');
    if (lines.length !== ATTESTATION_KEYS.length + 1 || lines[0] !== ATTESTATION_TITLE)
        return null;
    const values = [];
    for (const [index, key] of ATTESTATION_KEYS.entries()) {
        const prefix = `${key}: `, line = lines[index + 1];
        if (!line.startsWith(prefix))
            return null;
        const value = line.slice(prefix.length);
        if (!/^[\x21-\x7e]{1,128}$/.test(value) && key !== 'presignature')
            return null;
        values.push(value);
    }
    const [network, policy, sourceHash, codeHash, server, presignature, owner] = values;
    if (!/^[0-9a-f]{64}$/.test(sourceHash) || !/^[0-9a-f]{64}$/.test(codeHash) || !/^([0-9a-f]{2}){1,512}$/.test(presignature))
        return null;
    return { network, policy, sourceHash, codeHash, server, presignature, owner };
}
/**
 * Signs the owner's attestation of a custom wallet build with the wallet's message signature. It signs only an
 * attestation message of this network whose owner is the wallet account, and shows what the owner attests.
 */
export function buildAttestElement() {
    return class extends base() {
        render() {
            const data = (this.data ?? {});
            // The text that was validated and shown is the text that the wallet signs: a later change of `data` is not.
            const message = typeof data.message === 'string' ? data.message : null;
            const id = canonicalNetwork(data.network), fields = buildAttestation(message);
            if (!id || message === null || !fields || fields.network !== id || !strkey(fields.owner) || !strkey(fields.server)) {
                this.replaceChildren(h('p', { class: 'invalid' }, 'This build attestation is invalid.'));
                return;
            }
            const summary = Array.isArray(data.summary) ? data.summary : [];
            const rows = summary.flatMap(row => [h('dt', {}, String(row.label ?? '')), h('dd', {}, String(row.value ?? ''))]);
            rows.push(h('dt', {}, 'Policy source hash'), h('dd', { class: 'mono' }, fields.sourceHash));
            rows.push(h('dt', {}, 'Wallet code hash'), h('dd', { class: 'mono' }, fields.codeHash));
            rows.push(h('dt', {}, 'Server'), h('dd', {}, link(id, 'address', fields.server, fields.server)));
            const status = h('p', { class: 'status', role: 'status' });
            const sign = button('Sign the build attestation', async () => {
                sign.disabled = true;
                status.textContent = 'Waiting for the wallet…';
                try {
                    const { connectWallet, signWalletMessage } = await import('./wallet.js');
                    const address = await connectWallet(id);
                    if (address !== fields.owner)
                        throw Object.assign(new Error('The wallet account is not the owner of this policy. Nothing was signed.'), { code: 'mismatch' });
                    const signature = await signWalletMessage(message, address, id);
                    status.textContent = 'Signed.';
                    emit(this, 'allowit-signed', { signature: hex(Uint8Array.from(atob(signature), c => c.charCodeAt(0))), codeHash: fields.codeHash });
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
const REVIEW_TITLE = 'Allowit owner review';
const REVIEW_NOTE = 'This answer is for this request only. Every rule and limit of the policy still applies.';
const REVIEW_ANSWERS = { 'Allow this one request': 'allow', 'Deny this one request': 'deny' };
const REVIEW_SCORE = /^[0-9.]+ of 100 \(below [0-9.]+ denies; [0-9.]+ or more allows\)$/;
const REVIEW_NOT_SCORED = 'none. A lookup failed, so nothing was scored';
const REVIEW_LOOKUP = /^[\x21-\x7e]{1,128} failed \([\x21-\x7e]{1,128}\)$/;
/**
 * Reads the exact text of an owner review answer: the title, the answer, what is answered in `Key: value` lines, the
 * note, then the network, the review and the snapshot hash. Line 8 is the decision `Question` with a numeric `Score`
 * on line 9, or the failed `Lookup` with the score line that says that nothing was scored. Any other text is null.
 * Each value is one line without a control character; the snapshot is 64 lowercase hexadecimal characters.
 */
export function reviewAnswer(message) {
    if (typeof message !== 'string' || message.length > 8192)
        return null;
    const lines = message.split('\n');
    if (lines.length !== 15 || lines[0] !== REVIEW_TITLE || lines[1] !== '' || lines[9] !== '' || lines[10] !== REVIEW_NOTE || lines[11] !== '')
        return null;
    const value = (index, key) => {
        const prefix = `${key}: `, line = lines[index];
        // No control character and no line or paragraph separator: one value is one visible line.
        return line.startsWith(prefix) && !/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/.test(line) ? line.slice(prefix.length) : null;
    };
    const keys = [[2, 'Answer'], [3, 'Operation'], [4, 'Amount'], [5, 'To'], [6, 'Policy'], [8, 'Score'], [12, 'Network'], [13, 'Review'], [14, 'Snapshot']];
    const values = keys.map(([index, key]) => value(index, key));
    if (values.some(v => v === null))
        return null;
    const [answerText, operation, amount, to, policy, score, network, review, snapshot] = values;
    if (!Object.hasOwn(REVIEW_ANSWERS, answerText))
        return null;
    if (!operation || !amount || !to)
        return null;
    // A question goes with a numeric score, and a failed lookup with the line that nothing was scored. Never mixed.
    const question = value(7, 'Question'), lookup = value(7, 'Lookup');
    const cause = question ? (REVIEW_SCORE.test(score) ? { question } : null) : lookup !== null && REVIEW_LOOKUP.test(lookup) && score === REVIEW_NOT_SCORED ? { lookup } : null;
    if (!cause)
        return null;
    if (!/^[A-Za-z0-9_-]{1,128}$/.test(review) || !/^[0-9a-f]{64}$/.test(snapshot))
        return null;
    return { answer: REVIEW_ANSWERS[answerText], operation, amount, to, policy, ...cause, score, network, review, snapshot };
}
/**
 * Signs the owner's answer to a held request with the wallet's message signature. It signs only an owner review
 * answer message of this network, with the account `owner`, and shows the fields of the message that it signs.
 */
export function ownerAnswerElement() {
    return class extends base() {
        render() {
            const data = (this.data ?? {});
            // The text that was validated and shown is the text that the wallet signs: a later change of `data` is not.
            const message = typeof data.message === 'string' ? data.message : null;
            const owner = typeof data.owner === 'string' ? data.owner : '';
            const id = canonicalNetwork(data.network), fields = reviewAnswer(message);
            if (!id || message === null || !fields || fields.network !== id || !strkey(owner)) {
                this.replaceChildren(h('p', { class: 'invalid' }, 'This answer is invalid.'));
                return;
            }
            const rows = [
                h('dt', {}, 'Answer'), h('dd', {}, fields.answer === 'allow' ? 'Allow this one request' : 'Deny this one request'),
                h('dt', {}, 'Request'), h('dd', {}, `${fields.operation} ${fields.amount}`),
                h('dt', {}, 'To'), h('dd', { class: 'mono' }, fields.to),
                h('dt', {}, 'Policy'), h('dd', {}, fields.policy),
                ...(fields.question !== undefined ? [h('dt', {}, 'Question'), h('dd', {}, fields.question)] : [h('dt', {}, 'Lookup'), h('dd', {}, fields.lookup ?? '')]),
                h('dt', {}, 'Score'), h('dd', {}, fields.score),
                h('dt', {}, 'Snapshot'), h('dd', { class: 'mono' }, fields.snapshot),
            ];
            const status = h('p', { class: 'status', role: 'status' });
            const sign = button('Sign the answer', async () => {
                sign.disabled = true;
                status.textContent = 'Waiting for the wallet…';
                try {
                    const { connectWallet, signWalletMessage } = await import('./wallet.js');
                    const address = await connectWallet(id);
                    if (address !== owner)
                        throw Object.assign(new Error('The wallet account is not the owner of this policy. Nothing was signed.'), { code: 'mismatch' });
                    const signature = await signWalletMessage(message, address, id);
                    status.textContent = 'Signed.';
                    emit(this, 'allowit-signed', { signature, answer: fields.answer, snapshot: fields.snapshot });
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
