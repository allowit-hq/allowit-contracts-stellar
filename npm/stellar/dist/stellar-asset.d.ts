import { Networks } from '@stellar/stellar-sdk/base';
export type StellarNetwork = 'stellar:testnet' | 'stellar:mainnet' | 'stellar:pubnet';
/** The one Stellar network table. Passphrases come from the Stellar SDK. `stellar:pubnet` is the canonical Mainnet id. */
export declare const STELLAR_NETWORKS: Readonly<{
    readonly 'stellar:testnet': {
        readonly label: "Testnet";
        readonly passphrase: Networks.TESTNET;
    };
    readonly 'stellar:mainnet': {
        readonly label: "Mainnet";
        readonly passphrase: Networks.PUBLIC;
    };
    readonly 'stellar:pubnet': {
        readonly label: "Mainnet";
        readonly passphrase: Networks.PUBLIC;
    };
}>;
/** A checksummed G address proves a key identity. Account thresholds are checked by the SDK/RPC adapter. */
export declare function stellarAccountKey(address: string): Uint8Array;
/**
 * Stellar Asset Contract address for an exact asset code, issuer account and network passphrase. A null issuer means
 * native XLM. Codes are byte-exact, so an issued `XLM` differs from native XLM.
 */
export declare function stellarAssetContract(code: string, issuer: string | null, passphrase: string): string;
/** Stellar Asset Contract for an exact asset code, issuer and network. A null issuer means native XLM; issued XLM keeps its issuer. */
export declare function stellarAssetContractId(code: string, issuer: string | null, network: StellarNetwork): string;
