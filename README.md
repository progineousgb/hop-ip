# hop-ip

hop-ip tells a server the visitor address when the app sits behind a reverse proxy. It reads one proxy header and ignores addresses the client added.

## What you get

You get a single function, `clientIp`. Pass the socket peer, the header value, and the proxy ranges you trust. The return value is the visitor address, or `null` when the peer is not a valid IP. The package ships both ESM and CommonJS builds with type definitions for each.

## Install

Install from GitHub:

```bash
npm install github:progineousgb/hop-ip
```

The `prepare` script builds the package during a GitHub install, so no build output is stored in the repository.

## Example

```ts
import { clientIp } from "hop-ip";
// CommonJS: const { clientIp } = require("hop-ip");

clientIp({
  peer: "10.0.0.8",
  header: "for=1.1.1.1, for=203.0.113.10",
  trusted: ["10.0.0.0/8"],
});
// "203.0.113.10"
```

## Options

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `peer` | `string` | required | The socket peer address, for example `req.socket.remoteAddress`. |
| `header` | `string \| readonly string[]` | none | The header value. An array (repeated header lines, as Node.js may give you) is joined with `,` before parsing. |
| `trusted` | `readonly string[]` | `[]` | Proxy addresses or CIDR ranges in front of the app. When empty, the peer is returned. |
| `headerKind` | `"forwarded" \| "x-forwarded-for"` | `"forwarded"` | Which header format `header` holds. |

## Trusted

Trusted lists the proxy ranges in front of the app. hop-ip only reads the header when the peer is trusted. It then walks the header from the right and skips addresses inside those ranges until it finds the visitor.

An IPv6 trusted prefix shorter than 32 bits (for example `::/0`) throws a `RangeError` with a clear message. Such a range is almost always a configuration mistake and would trust far too many addresses. Use a prefix of 32 bits or more.

## Ports

Header entries may carry a port. hop-ip removes it before validating the address:

- `[2001:db8::17]:4711` becomes `2001:db8::17`
- `203.0.113.10:4711` (one colon and a dot) becomes `203.0.113.10`

A malformed port makes the entry invalid. A bare IPv6 address without brackets is never treated as having a port.

## Unknown and obfuscated hops

When the walk reaches an entry that is not an address (`unknown`, an obfuscated identifier such as `_hidden`, or anything that does not parse, including IPv6 zone identifiers and leading-zero IPv4 octets), it stops. hop-ip then returns the last trusted hop it saw on the way, because that is the closest address it can still vouch for. If no trusted hop was seen yet, it returns the peer.

```ts
clientIp({
  peer: "10.0.0.8",
  header: "for=203.0.113.10, for=unknown, for=10.0.0.2",
  trusted: ["10.0.0.0/8"],
});
// "10.0.0.2"
```

## Limits

hop-ip reads only the header value you pass (`Forwarded` by default, or `X-Forwarded-For`). It does not ship a cloud provider address list, so you must list your own proxies. It is not a web application firewall.

## Development

Requirements: Node.js 18 or newer and npm.

Linux and macOS:

```bash
git clone https://github.com/progineousgb/hop-ip.git
cd hop-ip
npm ci
npm run build
npm test
npm run lint:pkg
```

Windows (PowerShell or Command Prompt):

```powershell
git clone https://github.com/progineousgb/hop-ip.git
cd hop-ip
npm ci
npm run build
npm test
npm run lint:pkg
```

`npm test` compiles the sources and tests with TypeScript and runs them with `node --test --experimental-test-coverage`, which prints a coverage report. `npm run lint:pkg` checks the published package with `attw` and `publint`.

## License

MIT. See [LICENSE](LICENSE).
