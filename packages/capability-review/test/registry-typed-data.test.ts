// Hardening: typed-data signing. The registry's node-location EIP-712 struct is recognised by its primary type, a struct
// it defines, or its domain name, and is signable only for the TinyCloud One / Home origins.

import { describe, expect, it } from "bun:test";

import {
  REGISTRY_RECORD_SIGN_ORIGINS,
  REGISTRY_RECORD_SIGN_REFUSED,
  isRegistryTypedData,
  registryTypedDataSignRefusal,
} from "../src/index.js";

const FIELDS = [{ name: "node", type: "string" }];
const base = { domain: { name: "Example" }, types: { Mail: FIELDS }, primaryType: "Mail", message: { node: "x" } };

describe("isRegistryTypedData", () => {
  it.each([
    ["the registry primary type", { ...base, types: { SetNode: FIELDS }, primaryType: "SetNode" }],
    ["the primary type in capitals", { ...base, types: { SETNODE: FIELDS }, primaryType: "SETNODE" }],
    ["the primary type in lower case", { ...base, types: { setnode: FIELDS }, primaryType: "setnode" }],
    ["the primary type with spaces", { ...base, primaryType: "  SetNode\t\n" }],
    ["the registry domain name", { ...base, domain: { name: "TinyCloudRegistry", version: "1" } }],
    ["the registry domain name in lower case", { ...base, domain: { name: "tinycloudregistry" } }],
    ["the registry domain name with spaces", { ...base, domain: { name: " TinyCloudRegistry\n" } }],
    ["a defined struct of that name", { ...base, types: { Mail: FIELDS, SetNode: FIELDS } }],
    ["a defined struct of that name in capitals", { ...base, types: { Mail: FIELDS, SETNODE: FIELDS } }],
  ])("recognises %s", (_label, typedData) => {
    expect(isRegistryTypedData(typedData)).toBe(true);
  });

  it.each([
    ["an unrelated request", base],
    ["a domain that only contains the name", { ...base, domain: { name: "TinyCloudRegistryMirror" } }],
    ["a struct that only contains the name", { ...base, types: { MySetNode: FIELDS }, primaryType: "MySetNode" }],
    ["a domain with no name", { ...base, domain: { chainId: 1 } }],
    ["a domain name that is not a string", { ...base, domain: { name: 7 } }],
    ["no domain", { ...base, domain: undefined }],
    ["no types", { ...base, types: undefined }],
    ["null", null],
    ["a string", "SetNode"],
    ["an array", [base]],
  ])("does not recognise %s", (_label, typedData) => {
    expect(isRegistryTypedData(typedData)).toBe(false);
  });
});

describe("registryTypedDataSignRefusal", () => {
  const registry = { ...base, types: { SetNode: FIELDS }, primaryType: "SetNode" };

  it("allows the registry struct only for the pinned origins", () => {
    for (const origin of REGISTRY_RECORD_SIGN_ORIGINS) expect(registryTypedDataSignRefusal(registry, origin)).toBeNull();
  });

  it.each([
    ["another site", "https://example.com"],
    ["a Tauri app", "tauri://localhost"],
    ["a subdomain of One", "https://evil.tinycloud.one"],
    ["a trailing slash", "https://tinycloud.one/"],
    ["the opaque origin", "null"],
    ["no origin", undefined],
    ["a non-string origin", 7],
  ])("refuses the registry struct from %s", (_label, origin) => {
    expect(registryTypedDataSignRefusal(registry, origin)).toEqual({
      reason: "registry_record",
      message: REGISTRY_RECORD_SIGN_REFUSED.apiMessage,
    });
  });

  it("leaves other typed data to the other checks, whatever the origin", () => {
    for (const origin of ["https://example.com", undefined, "https://tinycloud.one"]) {
      expect(registryTypedDataSignRefusal(base, origin)).toBeNull();
    }
  });
});
