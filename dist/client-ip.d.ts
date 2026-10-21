export type HeaderKind = "forwarded" | "x-forwarded-for";
export interface ClientIpOptions {
    peer: string;
    header?: string;
    trusted?: readonly string[];
    headerKind?: HeaderKind;
}
export declare function clientIp(options: ClientIpOptions): string | null;
