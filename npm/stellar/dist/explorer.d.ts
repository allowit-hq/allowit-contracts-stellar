export type ExplorerKind = 'address' | 'tx' | 'contract';
export declare function stellarExplorerUrl(kind: ExplorerKind, value: string, network: string): string | null;
/** Builds the historical display URL. Validation belongs to stellarExplorerUrl when admitting untrusted values. */
export declare function stellarDisplayUrl(kind: 'address' | 'tx', value: string, network: string): string;
