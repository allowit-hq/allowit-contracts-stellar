export declare const isStellarNetwork: (network: unknown) => network is "stellar:testnet" | "stellar:mainnet" | "stellar:pubnet";
export declare const isStellarPublicNetwork: (network: unknown) => boolean;
export declare const isStellarPolicy: (policy: {
    runtime?: {
        wallet?: {
            profile?: unknown;
        };
    };
    network: string;
}) => boolean;
export declare const STELLAR_FUNDING_MODE = "stellar-installed";
export declare const STELLAR_SOURCE_PROFILE = "allowit-stellar-transfer-v1";
export declare const STELLAR_OPERATION = "stellar::sep41_transfer";
export declare function registryProfileValid(profile: string, kind: string, sources: string[], operations: string[]): boolean;
export declare const paymentAssetValid: (asset: {
    decimals: number;
}, mint: unknown) => boolean;
export declare const runtimeProfileValid: (runtime: {
    sourceProfile: string;
    operation: string | null;
    wallet: {
        kind: string;
        profile: string;
    };
    capabilities: {
        providerCall: boolean;
    };
}) => boolean;
export interface StellarInstallation {
    policyId: string;
    owner: string;
    wallet: string;
    network: string;
    sourceHash: string;
    moduleDigest: string;
    route: 'native' | 'policyWallet';
    ledger: number;
    state: 'installed';
}
export declare function installationValid(a: Record<string, unknown>, profile: string, network: string): boolean;
export declare function installationReady(policy: {
    id?: string;
    status?: string;
    network: string;
    sourceHash?: string;
}, installation: StellarInstallation | undefined, owner: string): boolean;
