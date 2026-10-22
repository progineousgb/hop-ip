import {
  compileTrusted,
  formatAddr,
  inAny,
  parseNormalized,
  stripPort,
  type Addr,
  type Network,
} from "./ip.js";

export type HeaderKind = "forwarded" | "x-forwarded-for";

export interface ClientIpOptions {
  /** Socket peer address (for example req.socket.remoteAddress). */
  peer: string;
  /** Header value. An array (repeated header lines) is joined with ",". */
  header?: string | readonly string[];
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
  const bare = stripPort(token);
  if (bare === null) return { kind: "stop" };
  const addr = parseNormalized(bare);
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

/**
 * Walks the hops from the right. Trusted hops are skipped. The first untrusted
 * address is the visitor. A stop hop (unknown, an obfuscated id such as _hidden,
 * or anything unparsable) ends the walk and the last trusted hop seen is
 * returned, or null so the caller falls back to the peer.
 */
function selectVisitor(hops: readonly Hop[], nets: readonly Network[]): string | null {
  let lastTrusted: Addr | null = null;
  for (let i = hops.length - 1; i >= 0; i -= 1) {
    const hop = hops[i];
    if (hop === undefined || hop.kind === "stop") {
      return lastTrusted ? formatAddr(lastTrusted) : null;
    }
    if (!inAny(hop.addr, nets)) return formatAddr(hop.addr);
    lastTrusted = hop.addr;
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

function headerText(header: unknown): string | null {
  if (typeof header === "string") return header;
  if (Array.isArray(header)) {
    return header.filter((part): part is string => typeof part === "string").join(",");
  }
  return null;
}

/**
 * Returns the visitor address, or null when the peer is not a valid IP.
 * Throws a RangeError when `trusted` holds an IPv6 prefix shorter than /32.
 */
export function clientIp(options: ClientIpOptions): string | null {
  if (options === null || typeof options !== "object") return null;
  const trusted = options.trusted;
  // Configuration errors are thrown, never swallowed.
  const nets = Array.isArray(trusted) ? compileTrusted(trusted) : [];
  let peerText: string | null = null;
  try {
    peerText = peerResult(options.peer);
    if (peerText === null) return null;

    if (nets.length === 0) return peerText;
    const peerAddr = parseNormalized(options.peer);
    if (!peerAddr || !inAny(peerAddr, nets)) return peerText;

    const kind = options.headerKind ?? "forwarded";
    if (kind !== "forwarded" && kind !== "x-forwarded-for") return peerText;
    const header = headerText(options.header);
    if (header === null || header.trim().length === 0) return peerText;

    const hops = kind === "x-forwarded-for" ? parseXForwardedFor(header) : parseForwarded(header);
    return selectVisitor(hops, nets) ?? peerText;
  } catch {
    return peerText;
  }
}
