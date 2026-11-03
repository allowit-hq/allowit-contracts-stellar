export type ExplorerKind = 'address'|'tx'|'contract';
const NETWORKS = new Map<string, string>([['stellar:testnet', 'testnet'], ['stellar:mainnet', 'public']]);
const ACCOUNT = /^G[A-Z2-7]{55}$/, CONTRACT = /^C[A-Z2-7]{55}$/, TRANSACTION = /^[\da-fA-F]{64}$/;
export function stellarExplorerUrl(kind: ExplorerKind, value: string, network: string): string|null {
  if (typeof value !== 'string' || typeof network !== 'string' || value.length > 128) return null;
  const name = NETWORKS.get(network);
  if (!name) return null;
  const path = kind === 'tx' ? TRANSACTION.test(value) ? 'tx' : null : CONTRACT.test(value) ? 'contract' : kind === 'address' && ACCOUNT.test(value) ? 'account' : null;
  return path ? `https://stellar.expert/explorer/${name}/${path}/${path === 'tx' ? value.toLowerCase() : value}` : null;
}
/** Builds the historical display URL. Validation belongs to stellarExplorerUrl when admitting untrusted values. */
export function stellarDisplayUrl(kind: 'address'|'tx', value: string, network: string): string {
  return `https://stellar.expert/explorer/${network === 'stellar:testnet' ? 'testnet' : 'public'}/${kind === 'address' ? 'account' : 'tx'}/${encodeURIComponent(value)}`;
}
