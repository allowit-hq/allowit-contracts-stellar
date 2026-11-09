export function h(tag, attrs = {}, ...children) {
    const node = document.createElement(tag);
    for (const [name, value] of Object.entries(attrs))
        node.setAttribute(name, value);
    for (const child of children)
        if (child !== null && child !== undefined)
            node.append(child);
    return node;
}
export function emit(target, type, detail) {
    target.dispatchEvent(new CustomEvent(type, { detail, bubbles: true, composed: true }));
}
export function shortAddress(address) {
    return address.length > 12 ? `${address.slice(0, 4)}…${address.slice(-4)}` : address;
}
/** Local date and time, and the time left until `seconds` (Unix time). */
export function expiry(seconds, now = Date.now()) {
    const left = Math.max(0, Math.floor(seconds - now / 1000));
    const parts = left >= 3600 ? `${Math.floor(left / 3600)} h ${Math.floor(left % 3600 / 60)} min` : left >= 60 ? `${Math.floor(left / 60)} min` : `${left} s`;
    return `${new Date(seconds * 1000).toLocaleString()} (${left > 0 ? `${parts} left` : 'expired'})`;
}
/** A base class whose subclasses render from `data`. Created only inside `defineElements`. */
export function base() {
    return class extends HTMLElement {
        #data;
        get data() { return this.#data; }
        set data(value) { this.#data = value; if (this.isConnected)
            this.render(); }
        connectedCallback() { this.render(); }
        render() { }
    };
}
