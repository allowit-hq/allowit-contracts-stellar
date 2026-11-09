/** Shared helpers for the Stellar custom elements. Data goes in through `.data`; events bubble out composed. */
export type Data = Record<string, unknown>;

export function h(tag: string, attrs: Record<string, string> = {}, ...children: (Node | string | null | undefined)[]): HTMLElement {
  const node = document.createElement(tag);
  for (const [name, value] of Object.entries(attrs)) node.setAttribute(name, value);
  for (const child of children) if (child !== null && child !== undefined) node.append(child);
  return node;
}

export function emit(target: EventTarget, type: string, detail?: unknown): void {
  target.dispatchEvent(new CustomEvent(type, {detail, bubbles: true, composed: true}));
}

export function shortAddress(address: string): string {
  return address.length > 12 ? `${address.slice(0, 4)}…${address.slice(-4)}` : address;
}

/** Local date and time, and the time left until `seconds` (Unix time). */
export function expiry(seconds: number, now = Date.now()): string {
  const left = Math.max(0, Math.floor(seconds - now / 1000));
  const parts = left >= 3600 ? `${Math.floor(left / 3600)} h ${Math.floor(left % 3600 / 60)} min` : left >= 60 ? `${Math.floor(left / 60)} min` : `${left} s`;
  return `${new Date(seconds * 1000).toLocaleString()} (${left > 0 ? `${parts} left` : 'expired'})`;
}

/** A base class whose subclasses render from `data`. Created only inside `defineElements`. */
export function base(): {new (): HTMLElement & {data: Data | undefined; render(): void}} {
  return class extends HTMLElement {
    #data: Data | undefined;
    get data(): Data | undefined {return this.#data;}
    set data(value: Data | undefined) {this.#data = value; if (this.isConnected) this.render();}
    connectedCallback(): void {this.render();}
    render(): void {}
  } as never;
}
