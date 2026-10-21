# hop-ip

hop-ip tells a server the visitor address when the app sits behind a reverse proxy. It reads one proxy header and ignores addresses the client added.

## What you get

You get a single function, `clientIp`. Pass the socket peer, one header string, and the proxy ranges you trust. `headerKind` is `forwarded` unless you set `x-forwarded-for`. The return value is the visitor address, or `null` when the peer is not a valid IP.

## Install

Install from GitHub:

```bash
npm install github:progineousgb/hop-ip
```

## Example

```ts
import { clientIp } from "hop-ip";

clientIp({
  peer: "10.0.0.8",
  header: "for=1.1.1.1, for=203.0.113.10",
  trusted: ["10.0.0.0/8"],
});
// "203.0.113.10"
```

## Trusted

Trusted lists the proxy ranges in front of the app; hop-ip walks the header from the right and skips addresses inside those ranges until it finds the visitor. An IPv6 trusted prefix shorter than 32 bits is ignored so it cannot treat every IPv4 address as a proxy.

## Limits

hop-ip reads only the one header string you pass (`Forwarded` by default, or `X-Forwarded-For`). It does not ship a cloud provider address list, so you must list your own proxies. It is not a web application firewall.
