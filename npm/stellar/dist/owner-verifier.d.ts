export interface AdkOwnerStep {
    network: string;
    action: 'upload_wasm' | 'create_wallet' | 'extend' | 'fund' | 'update_params';
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
    /**
     * The params update that the owner reviewed, for an `update_params` step. `params` then holds the complete new
     * params. `deploymentVersion` is the configuration revision that the update writes, in canonical decimal text,
     * and `x402Enabled` is the installed x402 choice, which the update keeps.
     */
    update?: {
        deploymentVersion: string;
        x402Enabled: boolean;
    };
}
/** Check a step before the owner signs it. The step must be fresh now. */
export declare function verifyAdkOwnerStep(step: AdkOwnerStep, expected: AdkOwnerSelection): Promise<void>;
/**
 * Check a saved signed step at the last second of its time bound, not at the present time. The time bound already
 * limits where it can apply, so an expired step still verifies for recovery and receipts.
 */
export declare function verifyAdkOwnerSignature(step: AdkOwnerStep, expected: AdkOwnerSelection, signedXdr: string): Promise<void>;
export declare function deriveAdkOwnerWallet(owner: string, policyInstance: string): Promise<string>;
