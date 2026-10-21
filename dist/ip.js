function at(bytes, index) {
    return bytes[index] ?? 0;
}
function stripBrackets(text) {
    if (text.startsWith("[")) {
        if (!text.endsWith("]") || text.length < 2)
            return null;
        return text.slice(1, -1).trim();
    }
    if (text.endsWith("]"))
        return null;
    return text;
}
function parseIpv4(input) {
    const parts = input.split(".");
    if (parts.length !== 4)
        return null;
    const out = new Uint8Array(4);
    for (let i = 0; i < 4; i += 1) {
        const part = parts[i];
        if (part === undefined || !/^[0-9]{1,3}$/.test(part))
            return null;
        if (part.length > 1 && part.startsWith("0"))
            return null;
        const value = Number(part);
        if (!Number.isInteger(value) || value > 255)
            return null;
        out[i] = value;
    }
    return out;
}
function parseIpv6(input) {
    if (input.length === 0 || input.includes("%"))
        return null;
    let text = input;
    if (text.includes(".")) {
        const colon = text.lastIndexOf(":");
        if (colon < 0)
            return null;
        const v4 = parseIpv4(text.slice(colon + 1));
        if (!v4)
            return null;
        const high = ((at(v4, 0) << 8) | at(v4, 1)).toString(16);
        const low = ((at(v4, 2) << 8) | at(v4, 3)).toString(16);
        text = `${text.slice(0, colon + 1)}${high}:${low}`;
    }
    if (text.includes("."))
        return null;
    const first = text.indexOf("::");
    const last = text.lastIndexOf("::");
    if (first !== last)
        return null;
    const left = first >= 0 ? text.slice(0, first) : text;
    const right = first >= 0 ? text.slice(first + 2) : "";
    const leftGroups = left.length === 0 ? [] : left.split(":");
    const rightGroups = right.length === 0 ? [] : right.split(":");
    const explicit = leftGroups.length + rightGroups.length;
    if (first < 0) {
        if (explicit !== 8)
            return null;
    }
    else if (explicit > 7) {
        return null;
    }
    const groups = [];
    for (const group of leftGroups)
        groups.push(group);
    for (let i = 0; i < 8 - explicit; i += 1)
        groups.push("0");
    for (const group of rightGroups)
        groups.push(group);
    if (groups.length !== 8)
        return null;
    const out = new Uint8Array(16);
    for (let i = 0; i < 8; i += 1) {
        const group = groups[i];
        if (group === undefined || !/^[0-9a-fA-F]{1,4}$/.test(group))
            return null;
        const value = Number.parseInt(group, 16);
        if (!Number.isInteger(value) || value < 0 || value > 0xffff)
            return null;
        out[i * 2] = value >> 8;
        out[i * 2 + 1] = value & 0xff;
    }
    return out;
}
export function isV4Mapped(bytes) {
    if (bytes.length !== 16)
        return false;
    for (let i = 0; i < 10; i += 1) {
        if (at(bytes, i) !== 0)
            return false;
    }
    return at(bytes, 10) === 0xff && at(bytes, 11) === 0xff;
}
function parseRaw(input) {
    const stripped = stripBrackets(input.trim());
    if (stripped === null || stripped.length === 0)
        return null;
    if (stripped.includes(":")) {
        const bytes = parseIpv6(stripped);
        if (!bytes)
            return null;
        return { version: 6, bytes };
    }
    const bytes = parseIpv4(stripped);
    if (!bytes)
        return null;
    return { version: 4, bytes };
}
export function parseNormalized(input) {
    const raw = parseRaw(input);
    if (!raw)
        return null;
    if (raw.version === 6 && isV4Mapped(raw.bytes)) {
        return { version: 4, bytes: raw.bytes.slice(12, 16) };
    }
    return raw;
}
function formatIpv6(bytes) {
    const groups = [];
    for (let i = 0; i < 8; i += 1) {
        const value = (at(bytes, i * 2) << 8) | at(bytes, i * 2 + 1);
        groups.push(value.toString(16));
    }
    let bestStart = -1;
    let bestLen = 0;
    let index = 0;
    while (index < groups.length) {
        if (groups[index] !== "0") {
            index += 1;
            continue;
        }
        let end = index;
        while (end < groups.length && groups[end] === "0")
            end += 1;
        if (end - index > bestLen) {
            bestStart = index;
            bestLen = end - index;
        }
        index = end;
    }
    if (bestLen < 2)
        return groups.join(":");
    const left = groups.slice(0, bestStart).join(":");
    const right = groups.slice(bestStart + bestLen).join(":");
    if (left.length === 0 && right.length === 0)
        return "::";
    if (left.length === 0)
        return `::${right}`;
    if (right.length === 0)
        return `${left}::`;
    return `${left}::${right}`;
}
export function formatAddr(addr) {
    if (addr.version === 4) {
        return `${at(addr.bytes, 0)}.${at(addr.bytes, 1)}.${at(addr.bytes, 2)}.${at(addr.bytes, 3)}`;
    }
    return formatIpv6(addr.bytes);
}
export function parseNetwork(entry) {
    const trimmed = entry.trim();
    if (trimmed.length === 0)
        return null;
    const slash = trimmed.lastIndexOf("/");
    let addrText = trimmed;
    let prefix = null;
    if (slash !== -1) {
        addrText = trimmed.slice(0, slash).trim();
        const prefixText = trimmed.slice(slash + 1).trim();
        if (!/^[0-9]{1,3}$/.test(prefixText))
            return null;
        prefix = Number(prefixText);
    }
    const raw = parseRaw(addrText);
    if (!raw)
        return null;
    if (raw.version === 4) {
        const bits = prefix ?? 32;
        if (bits > 32)
            return null;
        return { version: 4, bytes: raw.bytes, prefix: bits };
    }
    const bits = prefix ?? 128;
    if (bits > 128)
        return null;
    // An IPv6 trusted prefix shorter than 32 bits is ignored so it cannot treat every IPv4 address as a proxy.
    if (bits < 32)
        return null;
    if (isV4Mapped(raw.bytes) && bits >= 96) {
        return {
            version: 4,
            bytes: raw.bytes.slice(12, 16),
            prefix: bits - 96,
        };
    }
    return { version: 6, bytes: raw.bytes, prefix: bits };
}
export function compileTrusted(entries) {
    const nets = [];
    for (const entry of entries) {
        if (typeof entry !== "string")
            continue;
        const net = parseNetwork(entry);
        if (net)
            nets.push(net);
    }
    return nets;
}
export function contains(net, addr) {
    if (net.version !== addr.version)
        return false;
    const width = net.version === 4 ? 4 : 16;
    if (net.bytes.length !== width || addr.bytes.length !== width)
        return false;
    let bits = net.prefix;
    for (let i = 0; i < width; i += 1) {
        if (bits <= 0)
            return true;
        if (bits >= 8) {
            if (at(addr.bytes, i) !== at(net.bytes, i))
                return false;
            bits -= 8;
            continue;
        }
        const mask = (0xff << (8 - bits)) & 0xff;
        return (at(addr.bytes, i) & mask) === (at(net.bytes, i) & mask);
    }
    return true;
}
export function inAny(addr, nets) {
    for (const net of nets) {
        if (contains(net, addr))
            return true;
    }
    return false;
}
