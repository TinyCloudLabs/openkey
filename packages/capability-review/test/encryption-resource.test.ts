// Strict parser for named-key encryption resources (CONTRACT.md v0.2 §2) and
// the containment rule (§3). Vectors follow TEST-VECTORS.md (TC-1777).

import { describe, expect, it } from "bun:test";

import {
  encryptionResourceContains,
  parseEncryptionResource,
} from "../src/index.js";

const OWNER = "did:pkh:eip155:1:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";

function urn(rest: string): string {
  return `urn:tinycloud:encryption:${OWNER}:default/${rest}`;
}

describe("parseEncryptionResource: valid vectors", () => {
  it("parses a bare network", () => {
    expect(
      parseEncryptionResource(`urn:tinycloud:encryption:${OWNER}:default`),
    ).toEqual({ kind: "network", ownerDid: OWNER, network: "default" });
  });

  it("parses an exact key", () => {
    expect(parseEncryptionResource(urn("secrets/software-factory"))).toEqual({
      kind: "key",
      ownerDid: OWNER,
      network: "default",
      keyPath: "secrets/software-factory",
    });
  });

  it("parses a key with a did:key owner", () => {
    const uri =
      "urn:tinycloud:encryption:did:key:z6MkjHi79SMX4doJyo2w7jDTM6Fa7iX6EVZWXNbJ6RzBm3Wi:default/apps/tinychat";
    expect(parseEncryptionResource(uri)).toEqual({
      kind: "key",
      ownerDid: "did:key:z6MkjHi79SMX4doJyo2w7jDTM6Fa7iX6EVZWXNbJ6RzBm3Wi",
      network: "default",
      keyPath: "apps/tinychat",
    });
  });

  it("parses a prefix with exactly one trailing slash", () => {
    expect(parseEncryptionResource(urn("apps/tinychat/"))).toEqual({
      kind: "prefix",
      ownerDid: OWNER,
      network: "default",
      keyPath: "apps/tinychat/",
    });
  });

  it("accepts eight segments at exactly 255 bytes", () => {
    const path = Array.from({ length: 8 }, () => "a".repeat(31)).join("/");
    expect(path.length).toBe(255);
    const parsed = parseEncryptionResource(urn(path));
    expect(parsed?.kind).toBe("key");
    expect(parsed?.kind === "key" && parsed.keyPath.length).toBe(255);
  });

  it("accepts dots, underscores and hyphens inside a segment", () => {
    expect(parseEncryptionResource(urn("apps/v1.2_x-y"))?.kind).toBe("key");
  });

  it("parses a non-default network", () => {
    expect(
      parseEncryptionResource(
        `urn:tinycloud:encryption:${OWNER}:team-2/apps/x`,
      ),
    ).toEqual({
      kind: "key",
      ownerDid: OWNER,
      network: "team-2",
      keyPath: "apps/x",
    });
  });

  it("parses a did:web owner", () => {
    expect(
      parseEncryptionResource("urn:tinycloud:encryption:did:web:example.com:default/apps/x"),
    ).toEqual({
      kind: "key",
      ownerDid: "did:web:example.com",
      network: "default",
      keyPath: "apps/x",
    });
  });

  it("keeps the owner casing exactly as written", () => {
    const uri =
      "urn:tinycloud:encryption:did:pkh:eip155:1:0xABCDEF:default/apps/x";
    expect(parseEncryptionResource(uri)?.ownerDid).toBe(
      "did:pkh:eip155:1:0xABCDEF",
    );
  });
});

describe("parseEncryptionResource: rejects return null", () => {
  const rejects: Array<[string, string]> = [
    ["two trailing slashes", urn("apps/x//")],
    ["empty segment", urn("apps//x")],
    ["leading slash", `urn:tinycloud:encryption:${OWNER}:default//apps`],
    ["uppercase segment", urn("Apps/x")],
    ["dot-dot segment", urn("apps/../x")],
    ["single-dot segment", urn("apps/./x")],
    ["percent escape", urn("apps/a%2Fb")],
    ["colon in path", urn("apps/a:b")],
    ["whitespace", urn("apps/a b")],
    ["non-ASCII", urn("apps/café")],
    ["nine segments", urn("a/a/a/a/a/a/a/a/a")],
    ["segment of 65 bytes", urn("a".repeat(65))],
    [
      "256 bytes total",
      urn(
        [...Array.from({ length: 7 }, () => "a".repeat(31)), "a".repeat(32)].join(
          "/",
        ),
      ),
    ],
    ["segment starting with a dot", urn(".hidden")],
    ["segment starting with a hyphen", urn("-x")],
    ["empty key path", urn("")],
    ["bare network with trailing slash", `urn:tinycloud:encryption:${OWNER}:default/`],
    ["missing urn prefix", `tinycloud:${OWNER}:default/apps/x`],
    ["prefix only", "urn:tinycloud:encryption:"],
  ];

  for (const [name, uri] of rejects) {
    it(`rejects ${name}`, () => {
      expect(parseEncryptionResource(uri)).toBeNull();
    });
  }
});

describe("encryptionResourceContains", () => {
  const key = urn("apps/tinychat/x");
  const prefix = urn("apps/tinychat/");

  it("exact grant covers only the same key", () => {
    expect(encryptionResourceContains(key, urn("apps/tinychat/x"))).toBe(true);
    expect(encryptionResourceContains(key, urn("apps/tinychat/y"))).toBe(false);
  });

  it("prefix covers keys and prefixes under it", () => {
    expect(encryptionResourceContains(prefix, key)).toBe(true);
    expect(encryptionResourceContains(prefix, urn("apps/tinychat/x/"))).toBe(
      true,
    );
    expect(encryptionResourceContains(prefix, prefix)).toBe(true);
  });

  it("prefix does not cover the bare prefix key or a sibling name", () => {
    expect(encryptionResourceContains(prefix, urn("apps/tinychat"))).toBe(false);
    expect(encryptionResourceContains(prefix, urn("apps/tinychatx"))).toBe(
      false,
    );
  });

  it("exact grant never covers a prefix", () => {
    expect(encryptionResourceContains(key, prefix)).toBe(false);
  });

  it("network covers only the same network", () => {
    const network = `urn:tinycloud:encryption:${OWNER}:default`;
    expect(encryptionResourceContains(network, network)).toBe(true);
    expect(encryptionResourceContains(network, key)).toBe(false);
    expect(encryptionResourceContains(key, network)).toBe(false);
  });

  it("owner or network mismatch is never covered", () => {
    const otherOwner = key.replace(OWNER, "did:pkh:eip155:1:0x0000000000000000000000000000000000000001");
    const otherNetwork = key.replace("default", "team-2");
    expect(encryptionResourceContains(prefix, otherOwner)).toBe(false);
    expect(encryptionResourceContains(prefix, otherNetwork)).toBe(false);
  });

  it("invalid input is never covered", () => {
    expect(encryptionResourceContains(prefix, urn("apps//x"))).toBe(false);
    expect(encryptionResourceContains("not-a-urn", key)).toBe(false);
  });
});
