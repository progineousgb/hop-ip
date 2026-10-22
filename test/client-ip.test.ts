import { strict as assert } from "node:assert";
import { test } from "node:test";
import { clientIp } from "../src/index.js";

test("the documented example returns 203.0.113.10", () => {
  assert.equal(
    clientIp({
      peer: "10.0.0.8",
      header: "for=1.1.1.1, for=203.0.113.10",
      trusted: ["10.0.0.0/8"],
    }),
    "203.0.113.10",
  );
});

test("a forged address on the left is not chosen", () => {
  assert.equal(
    clientIp({
      peer: "10.0.0.8",
      header: "for=198.51.100.4, for=203.0.113.50, for=10.0.0.2",
      trusted: ["10.0.0.0/8"],
    }),
    "203.0.113.50",
  );
});

test("an empty trusted list returns the peer", () => {
  assert.equal(
    clientIp({
      peer: "198.51.100.20",
      header: "for=203.0.113.10",
      trusted: [],
    }),
    "198.51.100.20",
  );
});

test("a missing trusted list returns the peer", () => {
  assert.equal(
    clientIp({
      peer: "198.51.100.20",
      header: "for=203.0.113.10",
    }),
    "198.51.100.20",
  );
});

test("an untrusted peer returns the peer", () => {
  assert.equal(
    clientIp({
      peer: "198.51.100.20",
      header: "for=203.0.113.10",
      trusted: ["10.0.0.0/8"],
    }),
    "198.51.100.20",
  );
});

test("X-Forwarded-For uses comma-separated addresses", () => {
  assert.equal(
    clientIp({
      peer: "10.0.0.8",
      header: "1.1.1.1, 203.0.113.10",
      trusted: ["10.0.0.0/8"],
      headerKind: "x-forwarded-for",
    }),
    "203.0.113.10",
  );
});

test("an unknown token falls back to the peer", () => {
  assert.equal(
    clientIp({
      peer: "10.0.0.8",
      header: "for=203.0.113.10, for=unknown",
      trusted: ["10.0.0.0/8"],
    }),
    "10.0.0.8",
  );
});

test("an obfuscated token falls back to the peer", () => {
  assert.equal(
    clientIp({
      peer: "10.0.0.8",
      header: "for=203.0.113.10, for=_hidden",
      trusted: ["10.0.0.0/8"],
    }),
    "10.0.0.8",
  );
});

test("an empty element falls back to the peer", () => {
  assert.equal(
    clientIp({
      peer: "10.0.0.8",
      header: "for=203.0.113.10, for=",
      trusted: ["10.0.0.0/8"],
    }),
    "10.0.0.8",
  );
});

test("a non-address token falls back to the peer", () => {
  assert.equal(
    clientIp({
      peer: "10.0.0.8",
      header: "for=203.0.113.10, for=gateway",
      trusted: ["10.0.0.0/8"],
    }),
    "10.0.0.8",
  );
});

test("a bracketed IPv6 address is accepted", () => {
  assert.equal(
    clientIp({
      peer: "10.0.0.8",
      header: 'for="[2001:db8::17]"',
      trusted: ["10.0.0.0/8"],
    }),
    "2001:db8::17",
  );
});

test("an IPv6 trusted prefix shorter than 32 throws a clear error", () => {
  for (const trusted of [["::/0"], ["10.0.0.0/8", "2001:db8::/16"], ["::/31"]]) {
    assert.throws(
      () => clientIp({ peer: "10.0.0.8", header: "for=203.0.113.10", trusted }),
      (err: unknown) => err instanceof RangeError && /shorter than \/32/.test(err.message),
    );
  }
});

test("an IPv6 trusted prefix of 32 bits is kept", () => {
  assert.equal(
    clientIp({
      peer: "2001:db8::8",
      header: 'for="[2001:db9::5]"',
      trusted: ["2001:db8::/32"],
    }),
    "2001:db9::5",
  );
});

test("an IPv4-mapped proxy address stays inside the IPv4 trust range", () => {
  assert.equal(
    clientIp({
      peer: "10.0.0.8",
      header: "for=203.0.113.10, for=::ffff:10.0.0.2",
      trusted: ["10.0.0.0/8"],
    }),
    "203.0.113.10",
  );
});

test("an IPv4-mapped visitor is returned as IPv4", () => {
  assert.equal(
    clientIp({
      peer: "10.0.0.8",
      header: 'for="[::ffff:203.0.113.10]"',
      trusted: ["10.0.0.0/8"],
    }),
    "203.0.113.10",
  );
});

test("an IPv4 address matches a trusted IPv4-mapped prefix", () => {
  assert.equal(
    clientIp({
      peer: "10.0.0.8",
      header: "for=203.0.113.10, for=10.0.0.2",
      trusted: ["::ffff:10.0.0.0/104"],
    }),
    "203.0.113.10",
  );
});

test("a mapped peer is trusted when its IPv4 address is in range", () => {
  assert.equal(
    clientIp({
      peer: "::ffff:10.0.0.8",
      header: "for=203.0.113.10",
      trusted: ["10.0.0.0/8"],
    }),
    "203.0.113.10",
  );
});

test("a wider IPv6 prefix does not treat an IPv4 visitor as trusted", () => {
  assert.equal(
    clientIp({
      peer: "10.0.0.8",
      header: "for=198.51.100.7, for=203.0.113.10",
      trusted: ["10.0.0.0/8", "::/64"],
    }),
    "203.0.113.10",
  );
});

test("forwarded parameters other than for are ignored", () => {
  assert.equal(
    clientIp({
      peer: "10.0.0.8",
      header: "for=203.0.113.10;proto=https;by=10.0.0.8",
      trusted: ["10.0.0.0/8"],
    }),
    "203.0.113.10",
  );
});

test("when every header address is trusted the leftmost one is returned", () => {
  assert.equal(
    clientIp({
      peer: "10.0.0.8",
      header: "for=10.0.0.1, for=10.0.0.2",
      trusted: ["10.0.0.0/8"],
    }),
    "10.0.0.1",
  );
});

test("an unrecognized header kind returns the peer", () => {
  const options = {
    peer: "10.0.0.8",
    header: "203.0.113.10",
    trusted: ["10.0.0.0/8"],
    headerKind: "other",
  };
  assert.equal(clientIp(options as Parameters<typeof clientIp>[0]), "10.0.0.8");
});

test("an invalid peer returns null", () => {
  assert.equal(
    clientIp({
      peer: "not-an-ip",
      header: "for=203.0.113.10",
      trusted: ["0.0.0.0/0"],
    }),
    null,
  );
});

test("bad input does not throw", () => {
  assert.doesNotThrow(() => {
    clientIp({
      peer: "10.0.0.8",
      header: ";;;,,,",
      trusted: ["bogus", "10.0.0.0/99"],
    });
    clientIp({
      peer: "",
      header: "",
      trusted: [],
    });
    clientIp({
      peer: "2001:0DB8:0000:0000:0000:0000:0000:0017",
      trusted: [],
    });
  });
  assert.equal(
    clientIp({
      peer: "2001:0DB8:0000:0000:0000:0000:0000:0017",
      header: "for=203.0.113.10",
      trusted: [],
    }),
    "2001:db8::17",
  );
});
