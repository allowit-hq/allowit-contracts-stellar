/** Shared helpers for the Stellar custom elements. Data goes in through `.data`; events bubble out composed. */
export type Data = Record<string, unknown>;
export declare function h(tag: string, attrs?: Record<string, string>, ...children: (Node | string | null | undefined)[]): HTMLElement;
export declare function emit(target: EventTarget, type: string, detail?: unknown): void;
export declare function shortAddress(address: string): string;
/** Local date and time, and the time left until `seconds` (Unix time). */
export declare function expiry(seconds: number, now?: number): string;
/** A base class whose subclasses render from `data`. Created only inside `defineElements`. */
export declare function base(): {
    new (): HTMLElement & {
        data: Data | undefined;
        render(): void;
    };
};
