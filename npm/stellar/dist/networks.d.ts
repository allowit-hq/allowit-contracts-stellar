import type { RailNetwork } from './plugin.js';
export declare const NETWORKS: readonly RailNetwork[];
/** The canonical network id for an id or alias, or null. */
export declare function canonicalNetwork(network: unknown): string | null;
export declare function networkPassphrase(network: string): string;
