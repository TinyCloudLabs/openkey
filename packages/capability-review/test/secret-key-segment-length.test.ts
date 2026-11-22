// TC-3800, Naomi 13:35:53Z: a secret's name and scope segments are at most 64 bytes, inclusive. 64 is allowed (live
// names are exactly 64) and 65 is refused. The grammar is ASCII only, so a segment with any multi-byte character is
// refused whatever its character count.

import { describe, expect, it } from "bun:test";

import { exactSecretKeyPath, isSecretKeyPath, secretOfKvPath } from "../src/index.js";

const OWNER = "did:pkh:eip155:1:0xA8763f2b67aa9C807d2277a698cb071e3D86204A";
const keyUrn = (keyPath: string) => `urn:tinycloud:encryption:${OWNER}:default/${keyPath}`;
const bytes = (s: string) => Buffer.byteLength(s, "utf8");

const at64 = "a".repeat(64);
const at65 = "a".repeat(65);

describe("secret key segments: 64 bytes allowed, 65 refused", () => {
  it.each([
    ["global name", `secrets/${at64}`],
    ["scope", `secrets/scoped/${at64}/x`],
    ["scoped name", `secrets/scoped/work/${at64}`],
    ["scope and scoped name", `secrets/scoped/${at64}/${at64}`],
  ])("accepts a 64-byte %s", (_label, keyPath) => {
    expect(isSecretKeyPath(keyPath)).toBe(true);
    expect(exactSecretKeyPath(keyUrn(keyPath))).toBe(keyPath);
  });

  it.each([
    ["global name", `secrets/${at65}`],
    ["scope", `secrets/scoped/${at65}/x`],
    ["scoped name", `secrets/scoped/work/${at65}`],
  ])("refuses a 65-byte %s", (_label, keyPath) => {
    expect(isSecretKeyPath(keyPath)).toBe(false);
    expect(exactSecretKeyPath(keyUrn(keyPath))).toBeNull();
  });

  it("maps a 64-character KV name to its key and refuses 65", () => {
    expect(secretOfKvPath(`vault/secrets/${"A".repeat(64)}`)).toEqual({ name: "A".repeat(64), keyPath: `secrets/${at64}` });
    expect(secretOfKvPath(`vault/secrets/scoped/${at64}/${"A".repeat(64)}`)).toEqual({
      name: "A".repeat(64),
      keyPath: `secrets/scoped/${at64}/${at64}`,
    });
    expect(secretOfKvPath(`vault/secrets/${"A".repeat(65)}`)).toBeNull();
    expect(secretOfKvPath(`vault/secrets/scoped/${at65}/A`)).toBeNull();
  });

  it("counts bytes: a 64-character segment with a multi-byte character is refused", () => {
    const accented = `${"a".repeat(63)}é`;
    expect(accented.length).toBe(64);
    expect(bytes(accented)).toBe(65);
    const short = "é".repeat(32); // 32 characters, 64 bytes
    expect(bytes(short)).toBe(64);
    for (const segment of [accented, short]) {
      expect(isSecretKeyPath(`secrets/${segment}`), segment).toBe(false);
      expect(isSecretKeyPath(`secrets/scoped/${segment}/x`), segment).toBe(false);
      expect(exactSecretKeyPath(keyUrn(`secrets/${segment}`)), segment).toBeNull();
    }
    // The Kelvin sign lower-cases to ASCII `k`, but the KV name is checked before lower-casing.
    expect(secretOfKvPath(`vault/secrets/${"A".repeat(63)}\u212A`)).toBeNull();
  });
});
