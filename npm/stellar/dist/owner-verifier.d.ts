export interface AdkOwnerStep {
    network: string;
    action: 'upload_wasm' | 'create_wallet' | 'fund';
    transactionXdr: string;
    transactionHash: string;
    expiresAt: number;
}
export interface AdkOwnerSelection {
    owner: string;
    agent: string;
    server: string;
    policyInstance: string;
    code: string;
    sourceHash: string;
    params: Record<string, unknown>;
    wasmHash: string;
    wallet?: string;
    asset: string;
    maxFeeStroops: number;
    policyMaxFeeStroops: number;
    amount: string;
    nextSequence: string;
    validUntil: number;
}
export declare function verifyAdkOwnerStep(step: AdkOwnerStep, expected: AdkOwnerSelection): Promise<void>;
export declare function verifyAdkOwnerSignature(step: AdkOwnerStep, expected: AdkOwnerSelection, signedXdr: string): Promise<void>;
export declare function deriveAdkOwnerWallet(owner: string, policyInstance: string): Promise<string>;
