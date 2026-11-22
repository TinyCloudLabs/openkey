// Hardening: registry record signing. A v1 or v2 registry record payload, as text or as 0x hex of its UTF-8 bytes, is
// recognised by its version and field set; it is signable only for the TinyCloud One / Home origins.

import { describe, expect, it } from "bun:test";

import {
  REGISTRY_RECORD_SIGN_ORIGINS,
  REGISTRY_RECORD_SIGN_REFUSED,
  isRegistryRecordPayload,
  registryRecordSignOriginAllowed,
  registryRecordSignRefusal,
} from "../src/index.js";

const OWNER = "did:pkh:eip155:1:0xA8763f2b67aa9C807d2277a698cb071e3D86204A";
const NODE = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
const V1 = { version: 1, subject: OWNER, multiaddrs: ["/dns4/node.example/tcp/443/https"], updated_at: "2026-11-22T14:00:00.000Z", sequence: 3 };
const V2 = {
  version: 2,
  subject: OWNER,
  nodes: [{ did: NODE, url: "https://node.example" }],
  spaces: [{ space: `tinycloud:pkh:eip155:1:0xA8763f2b67aa9C807d2277a698cb071e3D86204A:default`, nodes: [{ did: NODE, mode: "read-write" }] }],
  encryptionNode: NODE,
  updated_at: "2026-11-22T14:00:00.000Z",
  sequence: 4,
};
const hex = (text: string) => `0x${Buffer.from(text, "utf8").toString("hex")}`;
const without = (record: Record<string, unknown>, field: string) => Object.fromEntries(Object.entries(record).filter(([name]) => name !== field));

describe("isRegistryRecordPayload", () => {
  it.each([
    ["v1 canonical text", JSON.stringify(V1)],
    ["v2 canonical text", JSON.stringify(V2)],
    ["v1 hex", hex(JSON.stringify(V1))],
    ["v2 hex", hex(JSON.stringify(V2))],
    ["v1 hex, capital digits", `0x${hex(JSON.stringify(V1)).slice(2).toUpperCase()}`],
    ["v1 hex, capital X prefix", `0X${hex(JSON.stringify(V1)).slice(2)}`],
    ["v1 reordered", JSON.stringify(Object.fromEntries(Object.entries(V1).reverse()))],
    ["v2 reordered and indented", JSON.stringify(Object.fromEntries(Object.entries(V2).reverse()), null, 2)],
    ["v1 with surrounding whitespace", `\n  ${JSON.stringify(V1)}\t\n`],
    ["v1 with a signature field", JSON.stringify({ ...V1, signature: "0xabc" })],
    ["v2 with an extra field", JSON.stringify({ ...V2, note: "x" })],
    ["v2 with no spaces and a null encryption node", JSON.stringify({ ...V2, spaces: [], encryptionNode: null })],
    ["v1 hex of a reordered, indented record", hex(JSON.stringify(Object.fromEntries(Object.entries(V1).reverse()), null, 4))],
  ])("recognises %s", (_label, message) => {
    expect(isRegistryRecordPayload(message)).toBe(true);
  });

  it.each([
    ["plain text", "Sign in to Example"],
    ["empty", ""],
    ["empty hex", "0x"],
    ["unrelated JSON", JSON.stringify({ hello: "world" })],
    ["a JSON array", JSON.stringify([V1])],
    ["a JSON string", JSON.stringify(JSON.stringify(V1))],
    ["null", "null"],
    ["a record with another version", JSON.stringify({ ...V1, version: 3 })],
    ["a record whose version is a string", JSON.stringify({ ...V1, version: "1" })],
    ["a v1 record without multiaddrs", JSON.stringify(without(V1, "multiaddrs"))],
    ["a v1 record without sequence", JSON.stringify(without(V1, "sequence"))],
    ["a v2 record without spaces", JSON.stringify(without(V2, "spaces"))],
    ["a v2 record without its encryption node field", JSON.stringify(without(V2, "encryptionNode"))],
    ["a v2 record with v1 fields", JSON.stringify({ ...V1, version: 2 })],
    ["invalid JSON", '{"version":1,"subject":'],
    ["odd-length hex", "0xabc"],
    ["hex of non-UTF-8 bytes", "0xff00fe"],
    ["hex of other JSON", hex(JSON.stringify({ a: 1 }))],
    ["a SIWE message", "example.com wants you to sign in with your Ethereum account:\n0x0\n\nSign in\n\nURI: https://example.com\nVersion: 1\nChain ID: 1\nNonce: 12345678\nIssued At: 2026-10-15T00:00:00.000Z"],
  ])("does not recognise %s", (_label, message) => {
    expect(isRegistryRecordPayload(message)).toBe(false);
  });
});

describe("registryRecordSignRefusal", () => {
  const record = JSON.stringify(V1);

  it("allows exactly the TinyCloud One and Home origins", () => {
    expect([...REGISTRY_RECORD_SIGN_ORIGINS]).toEqual([
      "https://home.tinycloud.xyz",
      "https://tinycloud.one",
      "https://app.tinycloud.one",
    ]);
    for (const origin of REGISTRY_RECORD_SIGN_ORIGINS) {
      expect(registryRecordSignOriginAllowed(origin)).toBe(true);
      expect(registryRecordSignRefusal(record, origin)).toBeNull();
    }
  });

  it.each([
    ["a Tauri app", "tauri://localhost"],
    ["a Tauri app on Windows and Android", "http://tauri.localhost"],
    ["the native One app scheme", "tinycloudone://app.tinycloud.one"],
    ["a local dev server", "http://localhost:5173"],
    ["a loopback address", "http://127.0.0.1:3000"],
    ["a subdomain of One", "https://evil.tinycloud.one"],
    ["a subdomain of Home", "https://app.home.tinycloud.xyz"],
    ["a lookalike of One", "https://tinycloud.one.example.com"],
  ])("refuses a record from %s", (_label, origin) => {
    expect(registryRecordSignOriginAllowed(origin)).toBe(false);
    expect(registryRecordSignRefusal(record, origin)?.reason).toBe("registry_record");
  });

  it.each([
    ["another site", "https://example.com"],
    ["an OpenKey page", "https://openkey.so"],
    ["a lookalike host", "https://home.tinycloud.xyz.example.com"],
    ["a host that only ends the same", "https://nothome.tinycloud.xyz"],
    ["plain http for an https origin", "http://home.tinycloud.xyz"],
    ["a trailing slash", "https://home.tinycloud.xyz/"],
    ["capitals", "https://HOME.tinycloud.xyz"],
    ["a port", "https://home.tinycloud.xyz:8443"],
    ["the opaque origin", "null"],
    ["the wildcard", "*"],
    ["an empty origin", ""],
    ["no origin", undefined],
    ["a non-string origin", 7],
  ])("refuses a record from %s", (_label, origin) => {
    expect(registryRecordSignOriginAllowed(origin)).toBe(false);
    expect(registryRecordSignRefusal(record, origin)).toEqual({ reason: "registry_record", message: REGISTRY_RECORD_SIGN_REFUSED.apiMessage });
  });

  it("leaves any other message to the other checks, whatever the origin", () => {
    for (const origin of ["https://example.com", undefined, "https://home.tinycloud.xyz"]) {
      expect(registryRecordSignRefusal("hello", origin)).toBeNull();
      expect(registryRecordSignRefusal(JSON.stringify({ a: 1 }), origin)).toBeNull();
    }
  });

  it("carries Monica's words", () => {
    expect(REGISTRY_RECORD_SIGN_REFUSED.title).toBe("This app's request can't be signed");
    expect(REGISTRY_RECORD_SIGN_REFUSED.popupBody).toBe(
      "It would set which TinyCloud node holds your data. Only TinyCloud One can ask for that, so this app can't. Nothing was signed. You can close this window.",
    );
    expect(REGISTRY_RECORD_SIGN_REFUSED.embedBody).toBe(
      "It would set which TinyCloud node holds your data. Only TinyCloud One can ask for that, so this app can't. Nothing was signed. You can go back to the app.",
    );
    expect(REGISTRY_RECORD_SIGN_REFUSED.apiMessage).toBe(
      "Only TinyCloud One can request a signature that sets the account's node location through OpenKey. Nothing was signed.",
    );
    expect([REGISTRY_RECORD_SIGN_REFUSED.popupButton, REGISTRY_RECORD_SIGN_REFUSED.embedButton]).toEqual(["Close", "Back to the app"]);
  });
});
