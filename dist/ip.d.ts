export interface Addr {
    version: 4 | 6;
    bytes: Uint8Array;
}
export interface Network {
    version: 4 | 6;
    bytes: Uint8Array;
    prefix: number;
}
export declare function isV4Mapped(bytes: Uint8Array): boolean;
export declare function parseNormalized(input: string): Addr | null;
export declare function formatAddr(addr: Addr): string;
export declare function parseNetwork(entry: string): Network | null;
export declare function compileTrusted(entries: readonly unknown[]): Network[];
export declare function contains(net: Network, addr: Addr): boolean;
export declare function inAny(addr: Addr, nets: readonly Network[]): boolean;
