/** Asks the wallet for access on `network` and returns the account. */
export declare function connectWallet(network: string): Promise<string>;
/** A SEP-53 message signature, checked against the account. */
export declare function signWalletMessage(message: string, address: string, network: string): Promise<string>;
export declare function signWalletTransaction(payload: string, owner: string, network: string): Promise<string>;
