export { canonicalJson, digest } from './consent-codec.js';
export declare const object: (value: unknown) => Record<string, unknown> | null;
export declare const hexHash: (value: unknown) => value is string;
export type PortablePolicy = {
    id: string;
    revision?: number;
    network: string;
    code: string;
    sourceHash: string;
    irHash: string;
    mint: string;
    token: string;
    runtime?: {
        instanceBinding?: Record<string, unknown>;
    };
};
/** Validate portable identity without rewriting its signed values or claiming current RPC authority. */
export declare function portableExport(bundle: Record<string, unknown>, config: Record<string, unknown>, policy: PortablePolicy): {
    top: Record<string, unknown>;
    config: Record<string, unknown>;
};
