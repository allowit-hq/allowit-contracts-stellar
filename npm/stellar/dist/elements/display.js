import { assets, explorerUrl, validateAddress } from '../plugin.js';
import { base, h, shortAddress } from './base.js';
export function link(network, kind, id, text) {
    const url = explorerUrl(network, kind, id);
    if (!url)
        return h('span', { title: id }, text);
    return h('a', { href: url, target: '_blank', rel: 'noopener noreferrer', title: id }, text);
}
export function addressElement() {
    return class extends base() {
        render() {
            const { network, address, label } = (this.data ?? {});
            if (typeof network !== 'string' || typeof address !== 'string' || !validateAddress(network, address)) {
                this.replaceChildren(h('span', { class: 'invalid' }, typeof address === 'string' ? address : ''));
                return;
            }
            this.replaceChildren(link(network, address.startsWith('C') ? 'contract' : 'address', address, label || shortAddress(address)));
        }
    };
}
export function explorerLinkElement() {
    return class extends base() {
        render() {
            const { network, kind, id, text } = (this.data ?? {});
            if (typeof network !== 'string' || typeof id !== 'string' || !['address', 'tx', 'contract'].includes(String(kind))) {
                this.replaceChildren();
                return;
            }
            this.replaceChildren(link(network, kind, id, text || shortAddress(id)));
        }
    };
}
/** Integer units in the asset's decimals, without floating point. */
export function formatUnits(units, decimals) {
    if (!/^-?\d+$/.test(units))
        return units;
    const negative = units.startsWith('-'), digits = (negative ? units.slice(1) : units).padStart(decimals + 1, '0');
    const whole = digits.slice(0, digits.length - decimals), fraction = digits.slice(digits.length - decimals).replace(/0+$/, '');
    return `${negative ? '-' : ''}${whole.replace(/\B(?=(\d{3})+(?!\d))/g, ',')}${fraction ? `.${fraction}` : ''}`;
}
export function amountElement() {
    return class extends base() {
        render() {
            const { network, asset, units } = (this.data ?? {});
            const info = typeof network === 'string' ? assets(network).find(a => a.id === asset || a.symbol === asset) : undefined;
            const text = typeof units === 'string' ? formatUnits(units, info?.decimals ?? 7) : '';
            this.replaceChildren(h('span', {}, `${text} ${info?.symbol ?? asset ?? ''}`.trim()));
        }
    };
}
export function receiptElement() {
    return class extends base() {
        render() {
            const { network, receipt } = (this.data ?? {});
            if (typeof network !== 'string' || !receipt) {
                this.replaceChildren();
                return;
            }
            const rows = [h('dt', {}, 'Status'), h('dd', {}, String(receipt.status ?? 'unknown'))];
            if (typeof receipt.hash === 'string')
                rows.push(h('dt', {}, 'Transaction'), h('dd', {}, link(network, 'tx', receipt.hash, shortAddress(receipt.hash))));
            if (receipt.fee?.native !== undefined)
                rows.push(h('dt', {}, 'Network fee'), h('dd', {}, `${formatUnits(String(receipt.fee.native), 7)} XLM`));
            if (receipt.fee?.charged !== undefined)
                rows.push(h('dt', {}, 'Fee charged to the budget'), h('dd', {}, String(receipt.fee.charged)));
            for (const debit of receipt.debits ?? []) {
                const info = assets(network).find(a => a.id === debit.asset || a.symbol === debit.asset);
                rows.push(h('dt', {}, 'Debit'), h('dd', {}, `${formatUnits(String(debit.units ?? ''), info?.decimals ?? 7)} ${info?.symbol ?? debit.asset ?? ''}`.trim()));
            }
            this.replaceChildren(h('dl', { class: 'receipt' }, ...rows));
        }
    };
}
