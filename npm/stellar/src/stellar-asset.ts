import {Asset, Networks, StrKey} from '@stellar/stellar-sdk/base';

export type StellarNetwork = 'stellar:testnet' | 'stellar:mainnet' | 'stellar:pubnet';
/** The one Stellar network table. Passphrases come from the Stellar SDK. `stellar:pubnet` is the canonical Mainnet id. */
export const STELLAR_NETWORKS = Object.freeze({
  'stellar:testnet': {label: 'Testnet', passphrase: Networks.TESTNET},
  'stellar:mainnet': {label: 'Mainnet', passphrase: Networks.PUBLIC},
  'stellar:pubnet': {label: 'Mainnet', passphrase: Networks.PUBLIC},
} as const);

/** A checksummed G address proves a key identity. Account thresholds are checked by the SDK/RPC adapter. */
export function stellarAccountKey(address: string): Uint8Array {
  if (typeof address !== 'string' || !StrKey.isValidEd25519PublicKey(address)) throw new Error('Use a valid Stellar account.');
  return new Uint8Array(StrKey.decodeEd25519PublicKey(address));
}

/**
 * Stellar Asset Contract address for an exact asset code, issuer account and network passphrase. A null issuer means
 * native XLM. Codes are byte-exact, so an issued `XLM` differs from native XLM.
 */
export function stellarAssetContract(code: string, issuer: string | null, passphrase: string): string {
  if (typeof code !== 'string' || !/^[A-Za-z0-9]{1,12}$/.test(code) || (issuer === null ? code !== 'XLM' : !StrKey.isValidEd25519PublicKey(issuer)))
    throw new Error('The Stellar asset code or issuer is invalid.');
  return (issuer === null ? Asset.native() : new Asset(code, issuer)).contractId(passphrase);
}
/** Stellar Asset Contract for an exact asset code, issuer and network. A null issuer means native XLM; issued XLM keeps its issuer. */
export function stellarAssetContractId(code: string, issuer: string | null, network: StellarNetwork): string {
  return stellarAssetContract(code, issuer, STELLAR_NETWORKS[network].passphrase);
}
