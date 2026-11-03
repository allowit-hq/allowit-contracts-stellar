export interface Session {
    address: string;
    network: string;
    expiresAt: string;
}
export type BrowserRequest = <T = unknown>(path: string, body?: unknown, options?: {
    expectedOwner?: string;
}) => Promise<T>;
export type StellarNetwork = 'stellar:testnet' | 'stellar:mainnet';
export declare const STELLAR_NETWORKS: {
    readonly 'stellar:testnet': {
        readonly label: "Testnet";
        readonly passphrase: "Test SDF Network ; September 2015";
    };
    readonly 'stellar:mainnet': {
        readonly label: "Mainnet";
        readonly passphrase: "Public Global Stellar Network ; September 2015";
    };
};
/** A checksummed G address proves a key identity. Account thresholds are checked by the SDK/RPC adapter. */
export declare function stellarAccountKey(address: string): Uint8Array;
/** SEP-53 signs the prefixed digest. It never signs a transaction or authorizes spending. */
export declare function stellarMessageDigest(message: string): Uint8Array;
export declare function freighterAvailable(): Promise<boolean>;
export declare function signInStellar<S extends Session>(request: BrowserRequest, network: StellarNetwork, signal?: AbortSignal): Promise<S>;
/**
 * Freighter signs only. Returned bytes are the authority: an optional retain hook receives bounded bytes before the
 * provider error, signer metadata or any further wallet or network await, so a valid proof survives stale metadata or a
 * failed post-sign check. The hook rejects altered bytes. Any metadata error still rejects. Nothing is broadcast here.
 */
export declare function signStellarTransaction(transactionXdr: string, owner: string, network: StellarNetwork, retain?: (signedXdr: string) => void | Promise<void>): Promise<string>;
export declare function watchStellarAccount(owner: string, changed: () => void): () => void;
/** Stellar Asset Contract for an exact asset code, issuer and network. A null issuer means native XLM; issued XLM keeps its issuer. */
export declare function stellarAssetContractId(code: string, issuer: string | null, network: StellarNetwork): string;
/** The owner approves an exact Native source against current account administration authority. */
export declare function verifyStellarInstallation(request: BrowserRequest, policy: {
    id: string;
    revision: number;
    network?: string;
    sourceHash?: string;
    irHash?: string;
    code?: string;
    mint?: string;
    token?: string;
    runtime?: {
        instanceBinding?: Record<string, unknown>;
    };
}, session: Session | null | undefined, stillCurrent?: () => boolean): Promise<void>;
