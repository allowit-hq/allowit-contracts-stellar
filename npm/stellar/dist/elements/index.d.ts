/** Element tags by kind. Every tag has the `allowit-stellar-` prefix. */
export declare const ELEMENTS: Readonly<{
    readonly address: "allowit-stellar-address";
    readonly 'explorer-link': "allowit-stellar-explorer-link";
    readonly amount: "allowit-stellar-amount";
    readonly 'wallet-sign-in': "allowit-stellar-wallet-sign-in";
    readonly 'owner-sign': "allowit-stellar-owner-sign";
    readonly receipt: "allowit-stellar-receipt";
    readonly 'binding-review': "allowit-stellar-binding-review";
}>;
/** Registers every element once. A host without custom elements (a server or a test) gets no change. */
export declare function defineElements(): void;
