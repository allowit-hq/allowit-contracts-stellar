import { canonicalNetwork, networkPassphrase, strkey } from '../plugin.js';
import { base, emit, expiry, h } from './base.js';
import { link } from './display.js';
import { APPROVE_POLICY, SET_UP_WALLET, TRUSTLINE_RESERVE, WALLET_FEE_FLOAT, WALLET_RESERVE, approvalMessage, nativeSetupOf, policyApproval } from '../native-wallet.js';
/** XLM text of stroops, without trailing zeros. */
/** Base units as a decimal amount with its unit. XLM and every issued asset have seven decimals. */
const units = (value, symbol) => `${value / 10000000n}${value % 10000000n ? `.${(value % 10000000n).toString().padStart(7, '0').replace(/0+$/, '')}` : ''} ${symbol}`;
const xlm = (value) => units(value, 'XLM');
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
            if (step.action === APPROVE_POLICY) {
                // This step signs a message, never a transaction: the owner's approval of the exact source and values of
                // one policy on one wallet account. Only an approval message of this network is signed, and the owner
                // reads what it names. `data.expected` binds it to the policy that the page reviewed.
                const message = approvalMessage(step), fields = policyApproval(message, id);
                const expected = data.expected && typeof data.expected === 'object' ? data.expected : null;
                const differs = (key) => expected?.[key] !== undefined && expected[key] !== fields?.[key];
                if (message === null || !fields || differs('policyId') || differs('sourceHash') || differs('paramsHash') || differs('wallet')) {
                    this.replaceChildren(h('p', { class: 'invalid' }, 'This owner step is invalid.'));
                    return;
                }
                rows.push(h('dt', {}, 'Wallet account'), h('dd', {}, link(id, 'address', fields.wallet, fields.wallet)));
                rows.push(h('dt', {}, 'Policy source hash'), h('dd', { class: 'mono' }, fields.sourceHash));
                rows.push(h('dt', {}, 'Values hash'), h('dd', { class: 'mono' }, fields.paramsHash));
                rows.push(h('dt', {}, 'What you sign'), h('dd', {}, 'A message that approves this policy for the wallet account. The server then checks every payment of your agent against it. It moves no funds.'));
                const status = h('p', { class: 'status', role: 'status' });
                const sign = button('Sign the approval', async () => {
                    sign.disabled = true;
                    status.textContent = 'Waiting for the wallet…';
                    try {
                        if (step.expiresAt <= Date.now() / 1000)
                            throw Object.assign(new Error('This owner step expired. Prepare it again.'), { code: 'expired' });
                        const { connectWallet, signWalletMessage } = await import('./wallet.js');
                        const owner = typeof data.owner === 'string' && strkey(data.owner) ? data.owner : await connectWallet(id);
                        const signedPayload = await signWalletMessage(message, owner, id);
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
            if (step.action === SET_UP_WALLET) {
                // The owner reads what this step creates before the wallet opens: the agent's wallet account, its
                // signers, the asset that it holds and what it starts with. Any other transaction under this action is refused.
                const setup = nativeSetupOf(step.payload, id);
                if (!setup || (typeof data.owner === 'string' && data.owner !== setup.owner)) {
                    this.replaceChildren(h('p', { class: 'invalid' }, 'This owner step is invalid.'));
                    return;
                }
                const { funding, asset } = setup;
                rows.push(h('dt', {}, 'Wallet account'), h('dd', {}, link(id, 'address', setup.wallet, setup.wallet)));
                rows.push(h('dt', {}, 'Agent'), h('dd', {}, link(id, 'address', setup.agent, setup.agent)));
                if (asset.issuer === null) {
                    rows.push(h('dt', {}, 'You fund it with'), h('dd', {}, `${xlm(setup.startingBalance)}: ${funding > 0n ? `${xlm(funding)} for your agent's payments, ` : ''}${xlm(WALLET_RESERVE)} that the network locks in the account and ${xlm(WALLET_FEE_FLOAT)} for the fees of your own steps. Only you can take it back.`));
                }
                else {
                    // A wallet of an issued asset: the asset by its code and its issuer, the funding in that asset, and the
                    // XLM that the account, its trustline and the owner's own steps need.
                    rows.push(h('dt', {}, 'Asset'), h('dd', {}, `${asset.symbol}, issued by `, link(id, 'address', asset.issuer, asset.issuer)));
                    rows.push(h('dt', {}, 'You fund it with'), h('dd', {}, `${funding > 0n ? `${units(funding, asset.symbol)} for your agent's payments, and ` : ''}${xlm(setup.startingBalance)}: ${xlm(WALLET_RESERVE + TRUSTLINE_RESERVE)} that the network locks in the account and its ${asset.symbol} trustline, and ${xlm(WALLET_FEE_FLOAT)} for network fees. Only you can close the wallet, which returns its XLM to you. The ${asset.symbol} follows the rules of its issuer.`));
                }
                rows.push(h('dt', {}, 'Who can pay'), h('dd', {}, 'Your agent and the server, only together. You can do everything alone.'));
            }
            rows.push(h('dt', {}, 'Transaction'), h('dd', {}, link(id, 'tx', step.hash, `${step.hash.slice(0, 8)}…`)));
            rows.push(h('dt', {}, 'Expires'), h('dd', {}, expiry(step.expiresAt)));
            const list = h('dl', { class: 'owner-step' }, ...rows);
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
