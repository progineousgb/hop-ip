import { strict as assert } from "node:assert";
import { test } from "node:test";
import { clientIp } from "../src/index.js";

const trusted = ["10.0.0.0/8", "2001:db8:ffff::/48"];

function fwd(header: string | readonly string[]): string | null {
  return clientIp({ peer: "10.0.0.8", header, trusted });
}

function xff(header: string | readonly string[]): string | null {
  return clientIp({ peer: "10.0.0.8", header, trusted, headerKind: "x-forwarded-for" });
}

test("ports: IPv4 with port in Forwarded", () => {
  assert.equal(fwd('for="203.0.113.10:4711"'), "203.0.113.10");
  assert.equal(fwd("for=203.0.113.10:4711, for=10.0.0.2:80"), "203.0.113.10");
});

test("ports: bracketed IPv6 with port in Forwarded", () => {
  assert.equal(fwd('for="[2001:db8::17]:4711"'), "2001:db8::17");
  assert.equal(fwd('for="[2001:db8::17]:4711", for="[2001:db8:ffff::1]:443"'), "2001:db8::17");
});

test("ports: X-Forwarded-For with ports", () => {
  assert.equal(xff("203.0.113.10:1234, 10.0.0.2:80"), "203.0.113.10");
  assert.equal(xff("[2001:db8::17]:8080"), "2001:db8::17");
});

test("ports: malformed ports are a stop hop", () => {
  assert.equal(fwd('for="203.0.113.10:99999"'), "10.0.0.8");
  assert.equal(fwd('for="203.0.113.10:abc"'), "10.0.0.8");
  assert.equal(fwd('for="[2001:db8::17]:"'), "10.0.0.8");
  assert.equal(xff("[2001:db8::17]x"), "10.0.0.8");
});

test("ports: bare IPv6 without brackets is not treated as having a port", () => {
  assert.equal(xff("2001:db8::17"), "2001:db8::17");
});

test("stop hop returns the last trusted hop seen", () => {
  assert.equal(fwd("for=203.0.113.10, for=unknown, for=10.0.0.2"), "10.0.0.2");
  assert.equal(fwd("for=_hidden, for=10.0.0.3, for=10.0.0.2"), "10.0.0.3");
  assert.equal(fwd('for=203.0.113.10, for="_Obf.Id-9", for=10.0.0.2'), "10.0.0.2");
  assert.equal(xff("203.0.113.10, unknown, 10.0.0.2"), "10.0.0.2");
});

test("stop hop with no trusted hop seen falls back to the peer", () => {
  assert.equal(fwd("for=203.0.113.10, for=_hidden"), "10.0.0.8");
  assert.equal(fwd("for=unknown"), "10.0.0.8");
});

test("header array is joined with a comma", () => {
  assert.equal(fwd(["for=1.1.1.1", "for=203.0.113.10, for=10.0.0.2"]), "203.0.113.10");
  assert.equal(xff(["198.51.100.4", "203.0.113.10"]), "203.0.113.10");
  assert.equal(fwd([]), "10.0.0.8");
});

test("IPv6 zone identifiers are rejected", () => {
  assert.equal(fwd('for="[fe80::1%eth0]"'), "10.0.0.8");
  assert.equal(xff("fe80::1%25eth0"), "10.0.0.8");
  assert.equal(clientIp({ peer: "fe80::1%eth0", trusted }), null);
});

test("repeated :: is rejected", () => {
  assert.equal(xff("2001::db8::1"), "10.0.0.8");
  assert.equal(clientIp({ peer: "1::2::3" }), null);
});

test("leading-zero IPv4 octets are rejected", () => {
  assert.equal(xff("203.0.113.010"), "10.0.0.8");
  assert.equal(xff("010.0.0.1"), "10.0.0.8");
  assert.equal(clientIp({ peer: "01.2.3.4" }), null);
});

test("IPv6 prefix of exactly 32 is accepted and a non-array trusted is ignored", () => {
  assert.equal(clientIp({ peer: "2001:db8::8", header: 'for="[2001:db9::5]"', trusted: ["2001:db8::/32"] }), "2001:db9::5");
  const opts = { peer: "10.0.0.8", header: "for=203.0.113.10", trusted: "10.0.0.0/8" };
  assert.equal(clientIp(opts as unknown as Parameters<typeof clientIp>[0]), "10.0.0.8");
});

test("non-object options return null", () => {
  assert.equal(clientIp(null as unknown as Parameters<typeof clientIp>[0]), null);
});
