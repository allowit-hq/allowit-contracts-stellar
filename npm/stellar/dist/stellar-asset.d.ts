/**
 * Stellar Asset Contract address for an exact asset code, issuer key and network passphrase. A null issuer means native
 * XLM. Codes are byte-exact, so an issued `XLM` differs from native XLM. Pure: no SDK, wallet or network dependency.
 */
export declare function stellarAssetContract(code: string, issuerKey: Uint8Array | null, passphrase: string): string;
