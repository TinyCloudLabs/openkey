import { describe, expect, test } from "bun:test";
import { checkSignableMessage, checkSiweOrigin, isSiweShaped } from "../src/siwe-origin.js";

const ADDRESS = "0x1234567890123456789012345678901234567890";
const INTERNAL = "https://internal.tinycloud.xyz";

function siwe(opts: { domain?: string; uri?: string; header?: string; extra?: string } = {}): string {
  const domain = opts.domain ?? "internal.tinycloud.xyz";
  const uri = opts.uri ?? INTERNAL;
  return [
    opts.header ?? `${domain} wants you to sign in with your Ethereum account:`,
    ADDRESS,
    "",
    "Sign in to Internal",
    "",
    `URI: ${uri}`,
    "Version: 1",
    "Chain ID: 1",
    "Nonce: abcdef12345678",
    "Issued At: 2026-10-19T00:00:00.000Z",
    ...(opts.extra ? [opts.extra] : []),
  ].join("\n");
}

function refusedWith(message: string, origin: string | null | undefined, code: string) {
  const result = checkSiweOrigin(message, origin);
  expect(result).toMatchObject({ siwe: true, ok: false, code });
}

describe("checkSiweOrigin: accepted", () => {
  test("domain and URI equal to the requesting origin sign", () => {
    expect(checkSiweOrigin(siwe(), INTERNAL)).toEqual({ siwe: true, ok: true });
  });

  test("port is part of the match (host:port domain, origin URI)", () => {
    const origin = "http://localhost:5173";
    expect(checkSiweOrigin(siwe({ domain: "localhost:5173", uri: origin }), origin)).toEqual({ siwe: true, ok: true });
  });

  test("a URI path under the same origin is accepted", () => {
    expect(checkSiweOrigin(siwe({ uri: `${INTERNAL}/login?next=/a` }), INTERNAL)).toEqual({ siwe: true, ok: true });
  });

  test("loopback dev origins accept the port-less hostname web-sdk emits; remote hosts do not", () => {
    expect(checkSiweOrigin(siwe({ domain: "localhost", uri: "did:key:z6Mk" }), "http://localhost:5173")).toEqual({ siwe: true, ok: true });
    expect(checkSiweOrigin(siwe({ domain: "127.0.0.1", uri: "did:key:z6Mk" }), "http://127.0.0.1:5173")).toEqual({ siwe: true, ok: true });
    refusedWith(siwe({ domain: "evil.example", uri: "did:key:z6Mk" }), "https://evil.example:8443", "domain-mismatch");
    refusedWith(siwe({ domain: "constructor", uri: "did:key:z6Mk" }), "https://constructor:8443", "domain-mismatch");
    refusedWith(siwe({ domain: "localhost", uri: "did:key:z6Mk" }), "http://localhost.evil.example:5173", "domain-mismatch");
    refusedWith(siwe({ domain: "internal.tinycloud.xyz", uri: "did:key:z6Mk" }), "http://localhost:5173", "domain-mismatch");
  });

  test("case differences in the host normalise away", () => {
    expect(
      checkSiweOrigin(siwe({ domain: "Internal.TinyCloud.XYZ", uri: "HTTPS://Internal.TinyCloud.xyz/" }), INTERNAL),
    ).toEqual({ siwe: true, ok: true });
    expect(checkSiweOrigin(siwe(), "HTTPS://INTERNAL.TINYCLOUD.XYZ")).toEqual({ siwe: true, ok: true });
  });

  test("TinyCloud delegation SIWE (did:key URI) is bound by its domain", () => {
    const delegation = siwe({ uri: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK" });
    expect(checkSiweOrigin(delegation, INTERNAL)).toEqual({ siwe: true, ok: true });
    refusedWith(siwe({ domain: "evil.example", uri: "did:key:z6Mk" }), INTERNAL, "domain-mismatch");
  });
});

describe("checkSiweOrigin: ucan URIs and openkey.so", () => {
  const ACCOUNT = "https://account.tinycloud.xyz";
  const ucan = "ucan:bafyreib2rxk3rybk3aobmv5cjuql3bm2twh4jo5uxgf5kpqcsgzz7nazxe";

  test("owner-revocation SIWE (ucan: URI) is bound by its domain", () => {
    expect(checkSiweOrigin(siwe({ domain: "account.tinycloud.xyz", uri: ucan }), ACCOUNT)).toEqual({ siwe: true, ok: true });
    refusedWith(siwe({ domain: "account.tinycloud.xyz", uri: ucan }), "https://evil.example", "domain-mismatch");
  });

  test("a web origin cannot claim the native issuer openkey.so", () => {
    refusedWith(siwe({ domain: "openkey.so", uri: "did:key:z6Mk" }), "https://attacker.example", "domain-mismatch");
    refusedWith(siwe({ domain: "openkey.so", uri: "https://openkey.so" }), "https://attacker.example", "domain-mismatch");
  });
});

describe("checkSiweOrigin: refused", () => {
  test("mismatched domain is refused", () => {
    refusedWith(siwe({ domain: "internal.tinycloud.xyz", uri: "https://evil.example" }), "https://evil.example", "domain-mismatch");
  });

  test("mismatched URI with a matching domain is refused", () => {
    refusedWith(siwe({ uri: "https://evil.example/login" }), INTERNAL, "uri-mismatch");
  });

  test("a non-web, non-did URI is refused", () => {
    refusedWith(siwe({ uri: "ftp://internal.tinycloud.xyz" }), INTERNAL, "uri-mismatch");
    refusedWith(siwe({ uri: "javascript:alert(1)" }), INTERNAL, "uri-mismatch");
  });

  test.each([undefined, null, "", "*", "null"])("unattributed origin %p is refused", (origin) => {
    refusedWith(siwe(), origin, "unattributed-origin");
  });

  test.each([
    "internal.tinycloud.xyz",
    "https://internal.tinycloud.xyz/",
    "https://internal.tinycloud.xyz/path",
    "https://user@internal.tinycloud.xyz",
    "https://internal.tinycloud.xyz:443",
    " https://internal.tinycloud.xyz",
    "ftp://internal.tinycloud.xyz",
  ])("a non-canonical requesting origin %p is refused", (origin) => {
    refusedWith(siwe(), origin, "invalid-origin");
  });

  test("a different scheme is a different origin", () => {
    refusedWith(siwe({ uri: "http://internal.tinycloud.xyz" }), INTERNAL, "uri-mismatch");
  });

  test("a different port is a different origin", () => {
    refusedWith(siwe({ domain: "internal.tinycloud.xyz:8443", uri: "https://internal.tinycloud.xyz:8443" }), INTERNAL, "domain-mismatch");
  });
});

describe("checkSiweOrigin: bypass attempts", () => {
  test("case games cannot turn another host into the origin", () => {
    refusedWith(siwe({ domain: "EVIL.example", uri: "https://EVIL.example" }), INTERNAL, "domain-mismatch");
    refusedWith(siwe({ uri: "https://INTERNAL.tinycloud.xyz.EVIL.example" }), INTERNAL, "uri-mismatch");
  });

  test("whitespace around or inside the domain is refused", () => {
    refusedWith(siwe({ header: " internal.tinycloud.xyz wants you to sign in with your Ethereum account:" }), INTERNAL, "domain-mismatch");
    refusedWith(siwe({ header: "internal.tinycloud.xyz  wants you to sign in with your Ethereum account:" }), INTERNAL, "domain-mismatch");
    refusedWith(siwe({ header: "evil.example internal.tinycloud.xyz wants you to sign in with your Ethereum account:" }), INTERNAL, "domain-mismatch");
    refusedWith(siwe({ header: "internal.tinycloud.xyz\twants you to sign in with your Ethereum account:" }), INTERNAL, "domain-mismatch");
  });

  test("whitespace in the URI value is refused", () => {
    refusedWith(siwe({ uri: `${INTERNAL} ` }), INTERNAL, "uri-mismatch");
    refusedWith(siwe({ uri: ` ${INTERNAL}` }), INTERNAL, "uri-mismatch");
    refusedWith(siwe({ uri: `${INTERNAL} https://evil.example` }), INTERNAL, "uri-mismatch");
    refusedWith(siwe({ uri: `${INTERNAL}\u00a0` }), INTERNAL, "uri-mismatch");
  });

  test("userinfo in the domain or URI is refused", () => {
    refusedWith(siwe({ domain: "internal.tinycloud.xyz@evil.example", uri: "https://evil.example" }), "https://evil.example", "domain-mismatch");
    refusedWith(siwe({ domain: "evil.example@internal.tinycloud.xyz" }), INTERNAL, "domain-mismatch");
    refusedWith(siwe({ uri: "https://internal.tinycloud.xyz@evil.example" }), INTERNAL, "uri-mismatch");
    refusedWith(siwe({ uri: "https://user:pw@internal.tinycloud.xyz" }), INTERNAL, "uri-mismatch");
    refusedWith(siwe({ uri: "https://internal.tinycloud.xyz\\@evil.example" }), INTERNAL, "uri-mismatch");
  });

  test("a trailing dot is a different host", () => {
    refusedWith(siwe({ domain: "internal.tinycloud.xyz." }), INTERNAL, "domain-mismatch");
    refusedWith(siwe({ uri: "https://internal.tinycloud.xyz./" }), INTERNAL, "uri-mismatch");
    refusedWith(siwe(), "https://internal.tinycloud.xyz.", "domain-mismatch");
  });

  test("punycode and unicode lookalikes are refused", () => {
    refusedWith(siwe({ domain: "xn--nternal-w1a.tinycloud.xyz", uri: "https://xn--nternal-w1a.tinycloud.xyz" }), INTERNAL, "domain-mismatch");
    refusedWith(siwe({ domain: "internal.tinycloud.xyz", uri: "https://internаl.tinycloud.xyz" }), INTERNAL, "uri-mismatch");
    refusedWith(siwe({ domain: "internаl.tinycloud.xyz" }), INTERNAL, "domain-mismatch");
    // Unicode spelling of an IDN origin is not its punycode host.
    refusedWith(siwe({ domain: "bücher.example", uri: "https://xn--bcher-kva.example" }), "https://xn--bcher-kva.example", "domain-mismatch");
    expect(
      checkSiweOrigin(siwe({ domain: "xn--bcher-kva.example", uri: "https://xn--bcher-kva.example" }), "https://xn--bcher-kva.example"),
    ).toEqual({ siwe: true, ok: true });
  });

  test("a SIWE embedded after other text, or with odd line breaks, is still checked", () => {
    refusedWith(`Please sign this\n\n${siwe({ domain: "evil.example", uri: "https://evil.example" })}`, INTERNAL, "domain-mismatch");
    refusedWith(siwe({ domain: "evil.example" }).replace(/\n/g, "\r\n"), INTERNAL, "domain-mismatch");
    refusedWith(siwe({ domain: "evil.example" }).replace(/\n/g, "\u2028"), INTERNAL, "domain-mismatch");
  });

  test("a second, mismatching header or URI cannot hide behind a matching one", () => {
    refusedWith(`${siwe()}\n${siwe({ domain: "evil.example" })}`, INTERNAL, "domain-mismatch");
    refusedWith(siwe({ extra: "URI: https://evil.example" }), INTERNAL, "uri-mismatch");
  });

  test("header phrase casing or spacing variants are still detected", () => {
    refusedWith(siwe({ header: "evil.example WANTS YOU TO SIGN IN WITH YOUR ETHEREUM ACCOUNT:" }), INTERNAL, "domain-mismatch");
    refusedWith(siwe({ header: "evil.example wants  you to sign in with your Ethereum account :" }), INTERNAL, "domain-mismatch");
  });

  test("a header split across lines or missing a URI cannot sneak through unchecked", () => {
    refusedWith(`internal.tinycloud.xyz wants you to sign in\nwith your Ethereum account:\n${ADDRESS}\nNonce: abcdef12`, INTERNAL, "incomplete-siwe");
    refusedWith(`internal.tinycloud.xyz wants you to sign in with your Ethereum account:\n${ADDRESS}`, INTERNAL, "incomplete-siwe");
  });

  test("URI and Nonce lines without a header are SIWE-shaped and refused", () => {
    refusedWith(`URI: ${INTERNAL}\nNonce: abcdef12345`, INTERNAL, "incomplete-siwe");
  });
});

describe("non-SIWE messages are untouched", () => {
  test.each([
    "hello world",
    "",
    "Sign this to prove you own the key",
    "internal.tinycloud.xyz wants you to sign in with your Ethereum account",
    "URI: https://evil.example",
    "Nonce: 12345",
    "0xdeadbeef",
  ])("%p", (message) => {
    expect(isSiweShaped(message)).toBe(false);
    expect(checkSiweOrigin(message, "*")).toEqual({ siwe: false });
    expect(checkSiweOrigin(message, INTERNAL)).toEqual({ siwe: false });
  });
});

describe("checkSignableMessage: hex-encoded text", () => {
  const toHex = (text: string) => `0x${Buffer.from(text, "utf8").toString("hex")}`;

  test("SIWE hidden in hex is checked as the bytes a signer would cover", () => {
    const hostile = toHex(siwe({ domain: "internal.tinycloud.xyz", uri: INTERNAL }));
    expect(checkSignableMessage(hostile, "https://evil.example")).toMatchObject({ siwe: true, ok: false, code: "domain-mismatch" });
    expect(checkSignableMessage(hostile, undefined)).toMatchObject({ siwe: true, ok: false, code: "unattributed-origin" });
    expect(checkSignableMessage(hostile, INTERNAL)).toEqual({ siwe: true, ok: true });
  });

  test("hex that is not text, and plain text, are unchanged", () => {
    expect(checkSignableMessage("0xdeadbeef", "*")).toEqual({ siwe: false });
    expect(checkSignableMessage(toHex("hello"), "*")).toEqual({ siwe: false });
    expect(checkSignableMessage("hello", "*")).toEqual({ siwe: false });
  });
});
