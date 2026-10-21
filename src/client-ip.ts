import {
  compileTrusted,
  formatAddr,
  inAny,
  parseNormalized,
  type Addr,
  type Network,
} from "./ip.js";

export type HeaderKind = "forwarded" | "x-forwarded-for";

export interface ClientIpOptions {
  peer: string;
  header?: string;
  trusted?: readonly string[];
  headerKind?: HeaderKind;
}

interface IpHop {
  kind: "ip";
  addr: Addr;
}

interface StopHop {
  kind: "stop";
}

type Hop = IpHop | StopHop;

function splitOutsideQuotes(input: string, separator: string): string[] {
  const parts: string[] = [];
  let start = 0;
  let quoted = false;
  let escape = false;
  for (let i = 0; i < input.length; i += 1) {
    const c = input.charAt(i);
    if (escape) {
      escape = false;
      continue;
    }
    if (quoted && c === "\\") {
      escape = true;
      continue;
    }
    if (c === '"') {
      quoted = !quoted;
      continue;
    }
    if (!quoted && c === separator) {
      parts.push(input.slice(start, i));
      start = i + 1;
    }
  }
  parts.push(input.slice(start));
  return parts;
}

function unquote(value: string): string | null {
  const trimmed = value.trim();
  if (!trimmed.startsWith('"')) return trimmed;
  if (trimmed.length < 2 || !trimmed.endsWith('"')) return null;
  let out = "";
  let escape = false;
  for (let i = 1; i < trimmed.length - 1; i += 1) {
    const c = trimmed.charAt(i);
    if (escape) {
      out += c;
      escape = false;
      continue;
    }
    if (c === "\\") {
      escape = true;
      continue;
    }
    if (c === '"') return null;
    out += c;
  }
  if (escape) return null;
  return out;
}

function addressHop(token: string | null): Hop {
  if (token === null) return { kind: "stop" };
  const addr = parseNormalized(token);
  if (!addr) return { kind: "stop" };
  return { kind: "ip", addr };
}

function forwardedForValue(element: string): string | null {
  const pairs = splitOutsideQuotes(element, ";");
  for (const pair of pairs) {
    const trimmed = pair.trim();
    if (trimmed.length === 0) continue;
    let quoted = false;
    let escape = false;
    let eq = -1;
    for (let i = 0; i < trimmed.length; i += 1) {
      const c = trimmed.charAt(i);
      if (escape) {
        escape = false;
        continue;
      }
      if (quoted && c === "\\") {
        escape = true;
        continue;
      }
      if (c === '"') {
        quoted = !quoted;
        continue;
      }
      if (!quoted && c === "=") {
        eq = i;
        break;
      }
    }
    if (eq <= 0) continue;
    const name = trimmed.slice(0, eq).trim().toLowerCase();
    if (name !== "for") continue;
    return unquote(trimmed.slice(eq + 1));
  }
  return null;
}

function parseForwarded(header: string): Hop[] {
  const hops: Hop[] = [];
  for (const element of splitOutsideQuotes(header, ",")) {
    hops.push(addressHop(forwardedForValue(element)));
  }
  return hops;
}

function parseXForwardedFor(header: string): Hop[] {
  const hops: Hop[] = [];
  for (const element of splitOutsideQuotes(header, ",")) {
    hops.push(addressHop(unquote(element)));
  }
  return hops;
}

function selectVisitor(hops: readonly Hop[], nets: readonly Network[]): string | null {
  for (let i = hops.length - 1; i >= 0; i -= 1) {
    const hop = hops[i];
    if (hop === undefined || hop.kind === "stop") return null;
    if (!inAny(hop.addr, nets)) return formatAddr(hop.addr);
  }
  const first = hops[0];
  if (first && first.kind === "ip") return formatAddr(first.addr);
  return null;
}

function peerResult(peer: unknown): string | null {
  if (typeof peer !== "string") return null;
  const addr = parseNormalized(peer);
  if (!addr) return null;
  return formatAddr(addr);
}

export function clientIp(options: ClientIpOptions): string | null {
  let peerText: string | null = null;
  try {
    if (options === null || typeof options !== "object") return null;
    peerText = peerResult(options.peer);
    if (peerText === null) return null;

    const trusted = options.trusted;
    if (!Array.isArray(trusted) || trusted.length === 0) return peerText;

    const nets = compileTrusted(trusted);
    const peerAddr = parseNormalized(options.peer);
    if (!peerAddr || !inAny(peerAddr, nets)) return peerText;

    const kind = options.headerKind ?? "forwarded";
    if (kind !== "forwarded" && kind !== "x-forwarded-for") return peerText;
    if (typeof options.header !== "string" || options.header.trim().length === 0) return peerText;

    const hops = kind === "x-forwarded-for" ? parseXForwardedFor(options.header) : parseForwarded(options.header);
    return selectVisitor(hops, nets) ?? peerText;
  } catch {
    return peerText;
  }
}
