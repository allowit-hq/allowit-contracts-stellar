import { addressElement, amountElement, explorerLinkElement, receiptElement } from './display.js';
import { bindingReviewElement, ownerSignElement, walletSignInElement } from './signing.js';
/** Element tags by kind. Every tag has the `allowit-stellar-` prefix. */
export const ELEMENTS = Object.freeze({
    address: 'allowit-stellar-address',
    'explorer-link': 'allowit-stellar-explorer-link',
    amount: 'allowit-stellar-amount',
    'wallet-sign-in': 'allowit-stellar-wallet-sign-in',
    'owner-sign': 'allowit-stellar-owner-sign',
    receipt: 'allowit-stellar-receipt',
    'binding-review': 'allowit-stellar-binding-review',
});
const FACTORIES = {
    address: addressElement,
    'explorer-link': explorerLinkElement,
    amount: amountElement,
    'wallet-sign-in': walletSignInElement,
    'owner-sign': ownerSignElement,
    receipt: receiptElement,
    'binding-review': bindingReviewElement,
};
/** Registers every element once. A host without custom elements (a server or a test) gets no change. */
export function defineElements() {
    if (typeof customElements === 'undefined')
        return;
    for (const [kind, tag] of Object.entries(ELEMENTS)) {
        if (!customElements.get(tag))
            customElements.define(tag, FACTORIES[kind]());
    }
}
