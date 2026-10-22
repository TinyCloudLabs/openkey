// Strict parser for named-key encryption resources (CONTRACT.md v0.2 §2, FB4
// grammar) and the containment rule (§3). Vectors 1-35 follow TEST-VECTORS.md
// (TC-1777, v0.4).
//
// Owner is SHAPE ONLY here. Vectors 23 and 24 need the canonical EIP-55 owner
// byte check, which is enforced at API prepare, not in the consent parser, so
// they are skipped rather than asserting the accepted behaviour as correct.
// Network is narrower than FB4 on purpose (see encryption-resource.ts).

import { describe, expect, it } from "bun:test";

import {
  encryptionResourceContains,
  parseEncryptionResource,
} from "../src/index.js";

const OWNER = "did:pkh:eip155:1:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";
const SEG31 = "a".repeat(31);
const PATH_255 = Array.from({ length: 8 }, () => SEG31).join("/");
const PATH_256 = [...Array.from({ length: 7 }, () => SEG31), "a".repeat(32)].join(
  "/",
);

function urn(rest: string): string {
  return `urn:tinycloud:encryption:${OWNER}:default/${rest}`;
}

describe("parseEncryptionResource: accepts", () => {
  it("1: bare network", () => {
    expect(
      parseEncryptionResource(`urn:tinycloud:encryption:${OWNER}:default`),
    ).toEqual({ kind: "network", ownerDid: OWNER, network: "default" });
  });

  it("2: exact key", () => {
    expect(parseEncryptionResource(urn("secrets/software-factory"))).toEqual({
      kind: "key",
      ownerDid: OWNER,
      network: "default",
      keyPath: "secrets/software-factory",
    });
  });

  it("3: key with a did:key owner", () => {
    const uri =
      "urn:tinycloud:encryption:did:key:z6MkjHi79SMX4doJyo2w7jDTM6Fa7iX6EVZWXNbJ6RzBm3Wi:default/apps/tinychat";
    expect(parseEncryptionResource(uri)).toEqual({
      kind: "key",
      ownerDid: "did:key:z6MkjHi79SMX4doJyo2w7jDTM6Fa7iX6EVZWXNbJ6RzBm3Wi",
      network: "default",
      keyPath: "apps/tinychat",
    });
  });

  it("4: prefix with exactly one trailing slash", () => {
    expect(parseEncryptionResource(urn("apps/tinychat/"))).toEqual({
      kind: "prefix",
      ownerDid: OWNER,
      network: "default",
      keyPath: "apps/tinychat/",
    });
  });

  it("5: eight segments at exactly 255 bytes", () => {
    expect(parseEncryptionResource(urn(PATH_255))?.kind).toBe("key");
  });

  it("6: dots, underscores and hyphens inside a segment", () => {
    expect(parseEncryptionResource(urn("apps/v1.2_x-y"))?.kind).toBe("key");
  });

  it("network named my-net-2 is accepted", () => {
    expect(
      parseEncryptionResource(`urn:tinycloud:encryption:${OWNER}:my-net-2/apps/x`),
    ).toEqual({
      kind: "key",
      ownerDid: OWNER,
      network: "my-net-2",
      keyPath: "apps/x",
    });
  });

  it("did:web owner containing colons", () => {
    expect(
      parseEncryptionResource(
        "urn:tinycloud:encryption:did:web:example.com:user:alice:default/apps/x",
      ),
    ).toEqual({
      kind: "key",
      ownerDid: "did:web:example.com:user:alice",
      network: "default",
      keyPath: "apps/x",
    });
  });

  it("33: prefix whose 255-byte path excludes its trailing slash", () => {
    expect(parseEncryptionResource(urn(`${PATH_255}/`))).toEqual({
      kind: "prefix",
      ownerDid: OWNER,
      network: "default",
      keyPath: `${PATH_255}/`,
    });
  });

  it("35: prefix ending in a slash parses as a prefix", () => {
    expect(parseEncryptionResource(urn("apps/x/"))?.kind).toBe("prefix");
  });

  // Vector 23: owner is not canonical (lowercase) in a key URN -> REJECT.
  // Enforced at API prepare, not by this shape-only parser.
  it.skip("23: lowercase owner in a key URN is rejected (canonical EIP-55 owner enforced at API prepare, not in the consent parser)", () => {
    const lowerOwner =
      "did:pkh:eip155:1:0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed";
    expect(
      parseEncryptionResource(
        `urn:tinycloud:encryption:${lowerOwner}:default/apps/x`,
      ),
    ).toBeNull();
  });

  // Vector 24: bare network with lowercase owner -> normalised to canonical O.
  // Enforced at API prepare, not by this shape-only parser.
  it.skip("24: bare network with lowercase owner normalises to canonical owner (canonical EIP-55 owner enforced at API prepare, not in the consent parser)", () => {
    const lowerOwner =
      "did:pkh:eip155:1:0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed";
    expect(
      parseEncryptionResource(`urn:tinycloud:encryption:${lowerOwner}:default`),
    ).toEqual({ kind: "network", ownerDid: OWNER, network: "default" });
  });
});

describe("parseEncryptionResource: rejects return null", () => {
  const rejects: Array<[string, string]> = [
    ["7: two trailing slashes", urn("apps/x//")],
    ["8: empty segment", urn("apps//x")],
    ["9: leading slash", `urn:tinycloud:encryption:${OWNER}:default//apps`],
    ["10: uppercase segment", urn("Apps/x")],
    ["11: dot-dot segment", urn("apps/../x")],
    ["12: single-dot segment", urn("apps/./x")],
    ["13: percent escape in path", urn("apps/a%2Fb")],
    ["14: colon in path", urn("apps/a:b")],
    ["15: whitespace", urn("apps/a b")],
    ["16: non-ASCII", urn("apps/café")],
    ["17: nine segments", urn("a/a/a/a/a/a/a/a/a")],
    ["18: segment of 65 bytes", urn("a".repeat(65))],
    ["19: 256 bytes total", urn(PATH_256)],
    ["20: segment starting with a dot", urn(".hidden")],
    ["21: segment starting with a hyphen", urn("-x")],
    ["22: empty prefix", urn("")],
    ["34: path over 255 bytes with prefix slash", urn(`${PATH_256}/`)],
    [
      "25: # in owner",
      "urn:tinycloud:encryption:did:key:z6MkjHi79SMX4doJyo2w7jDTM6Fa7iX6EVZWXNbJ6RzBm3Wi#x:default/apps/x",
    ],
    ["26: # in network", `urn:tinycloud:encryption:${OWNER}:default#x/apps/x`],
    ["27: ? in network", `urn:tinycloud:encryption:${OWNER}:default?x/apps/x`],
    [
      "28: % in owner",
      "urn:tinycloud:encryption:did:web:example.com%3A8443:default/apps/x",
    ],
    ["29: uppercase URN scheme", `URN:tinycloud:encryption:${OWNER}:default/apps/x`],
    ["30: mixed-case URN scheme", `urn:TinyCloud:encryption:${OWNER}:default/apps/x`],
    ["# in network, bare", `urn:tinycloud:encryption:${OWNER}:def#ault`],
    ["? in network, bare", `urn:tinycloud:encryption:${OWNER}:def?ault`],
    ["% in network, keyed", `urn:tinycloud:encryption:${OWNER}:def%41ult/apps/x`],
    ["bare network with trailing slash", `urn:tinycloud:encryption:${OWNER}:default/`],
    ["missing urn prefix", `tinycloud:${OWNER}:default/apps/x`],
    ["prefix only", "urn:tinycloud:encryption:"],
    ["32: uppercase network (keyed)", `urn:tinycloud:encryption:${OWNER}:Default/apps/x`],
    ["32: uppercase network (bare)", `urn:tinycloud:encryption:${OWNER}:Default`],
    ["non-ASCII network (keyed)", `urn:tinycloud:encryption:${OWNER}:déf/apps/x`],
    ["non-ASCII network (bare)", `urn:tinycloud:encryption:${OWNER}:déf`],
    ["network with a dot", `urn:tinycloud:encryption:${OWNER}:team.2/apps/x`],
    ["network with an underscore", `urn:tinycloud:encryption:${OWNER}:team_2/apps/x`],
    ["network with a bidi override", `urn:tinycloud:encryption:${OWNER}:def\u202eault/apps/x`],
    ["network starting with a hyphen", `urn:tinycloud:encryption:${OWNER}:-net/apps/x`],
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
    const otherOwner = key.replace(
      OWNER,
      "did:pkh:eip155:1:0x0000000000000000000000000000000000000001",
    );
    const otherNetwork = key.replace("default", "team-2");
    expect(encryptionResourceContains(prefix, otherOwner)).toBe(false);
    expect(encryptionResourceContains(prefix, otherNetwork)).toBe(false);
  });

  it("invalid input is never covered", () => {
    expect(encryptionResourceContains(prefix, urn("apps//x"))).toBe(false);
    expect(encryptionResourceContains("not-a-urn", key)).toBe(false);
  });

  it("prefix covers by whole segments", () => {
    expect(
      encryptionResourceContains(urn("apps/foo/"), urn("apps/foo/a/b")),
    ).toBe(true);
    expect(
      encryptionResourceContains(urn("apps/foo/"), urn("apps/foobar/x")),
    ).toBe(false);
    expect(encryptionResourceContains(urn("apps/foo/"), urn("apps/foo"))).toBe(
      false,
    );
  });
});
