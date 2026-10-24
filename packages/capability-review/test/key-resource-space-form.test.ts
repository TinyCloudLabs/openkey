// The classifier is one function for both forms of an app-key resource: the key
// URN and the space-path form (`<space>/encryption/<path>`). The API keeps a
// byte-identical copy (key-resource-parity.test.ts); these rows run the
// canonical one.

import { describe, expect, it } from "bun:test";

import { isAppsKeyResource, keyPathOfAnyResource, parseKeyResource } from "../src/index.js";

const OWNER = "did:pkh:eip155:1:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";
const SPACE = "tinycloud:pkh:eip155:1:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed:default";

describe("isAppsKeyResource", () => {
  it.each([
    [`urn:tinycloud:encryption:${OWNER}:default/apps/x/k`, true],
    [`urn:tinycloud:encryption:${OWNER}:default/APPS/x/`, true],
    [`${SPACE}/encryption/apps/x/k`, true],
    [`${SPACE}/encryption/Apps/x/`, true],
    [`${SPACE}/tinycloud.encryption/apps/x/k`, true],
    [`tinycloud:pkh:eip155:1:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed:secrets/ENCRYPTION/apps/x`, true],
    [`${SPACE}/encryption`, false],
    [`${SPACE}/encryption/`, false],
    [`${SPACE}/encryption/appsx/y`, false],
    [`${SPACE}/encryption/apps.x/y`, false],
    [`${SPACE}/encryption/secrets/apps/x`, false],
    [`${SPACE}/kv/apps/x`, false],
    [`${SPACE}/kv/encryption/apps/x`, false],
    [`urn:tinycloud:encryption:${OWNER}:default`, false],
  ])("%s -> %s", (resource, expected) => {
    expect(isAppsKeyResource(resource)).toBe(expected);
  });

  it("the space-path form is never a parseable key resource", () => {
    expect(parseKeyResource(`${SPACE}/encryption/apps/x/k`)).toBeNull();
    expect(parseKeyResource(`urn:tinycloud:encryption:${OWNER}:default/apps/x/k`)).not.toBeNull();
  });
});

describe("keyPathOfAnyResource", () => {
  it("reads the path of either form and nothing else", () => {
    expect(keyPathOfAnyResource(`urn:tinycloud:encryption:${OWNER}:default/secrets/x`)).toBe("secrets/x");
    expect(keyPathOfAnyResource(`${SPACE}/encryption/secrets/x`)).toBe("secrets/x");
    expect(keyPathOfAnyResource(`${SPACE}/encryption/`)).toBe("");
    expect(keyPathOfAnyResource(`${SPACE}/encryption`)).toBeNull();
    expect(keyPathOfAnyResource(`${SPACE}/kv/secrets/x`)).toBeNull();
  });
});
