import { describe, expect, it } from "bun:test";
import {
  TICKET_APP_KEY_MAX_MS,
  matchesTicketAppKeyPreview,
  parseSiweFields,
  serializeSiwe,
  validTicketAppKeyRequest,
  type SiweFields,
} from "../src/index.js";
import { FIXTURE_META, makeRecapResource, siweWithResources } from "./fixtures/index.js";

const appKey = { appId: "xyz.tinycloud.share", key: "contacts/seal-v1" };
const { address, chainId } = FIXTURE_META;
const resource = `urn:tinycloud:encryption:did:pkh:eip155:${chainId}:${address}:default/apps/${appKey.appId}/${appKey.key}`;
const decrypt = "tinycloud.encryption/decrypt";
const create = "tinycloud.encryption/key.create";
const both = { [decrypt]: [{}], [create]: [{}] };
const recap = makeRecapResource({ [resource]: both });
const original = siweWithResources([recap]);
const parsed = parseSiweFields(original);
if (!parsed.ok) throw new Error(parsed.message);
const fields = parsed.fields;
const now = Date.parse(fields.issuedAt);
const acceptedEnd = new Date(now + 3_600_000).toISOString();
const preview = serializeSiwe({ ...fields, expirationTime: acceptedEnd });

describe("before claiming a prepared app key", () => {
  it("accepts exactly the named key, the two canonical abilities and an expiry within seven days", () => {
    expect(validTicketAppKeyRequest(fields, appKey, now)).toBe(true);
  });

  it("requires appKey when the SIWE carries an app key", () => {
    expect(validTicketAppKeyRequest(fields, undefined, now)).toBe(false);
    const legacy = makeRecapResource({ [resource.replace(/\/apps\/.+$/, "/qa/seal-v1")]: both });
    expect(validTicketAppKeyRequest({ ...fields, resources: [legacy] }, undefined, now)).toBe(true);
  });

  const invalid: [string, Partial<SiweFields>][] = [
    ["an additional SIWE resource", { resources: [recap, "https://example.test"] }],
    ["two separate ReCap blocks", { resources: [recap, makeRecapResource({ [resource]: { [decrypt]: [] } })] }],
    ["an extra attenuation entry", { resources: [makeRecapResource({ [resource]: both, [resource + "-other"]: {} })] }],
    ["a short ability name", { resources: [makeRecapResource({ [resource]: { "encryption/decrypt": [{}], [create]: [{}] } })] }],
    ["a non-empty caveat", { resources: [makeRecapResource({ [resource]: { ...both, [decrypt]: [{ example: true }] } })] }],
    ["an absent expiry", { expirationTime: undefined }],
    ["an expired request", { expirationTime: new Date(now).toISOString() }],
    ["an expiry beyond seven days", { expirationTime: new Date(now + TICKET_APP_KEY_MAX_MS + 1000).toISOString() }],
  ];

  it.each(invalid)("refuses %s", (_label, change) => {
    expect(validTicketAppKeyRequest({ ...fields, ...change }, appKey, now)).toBe(false);
  });
});

describe("before showing Approve for a sealed app key preview", () => {
  it("accepts only the end the owner reviewed", () => {
    expect(matchesTicketAppKeyPreview(original, preview, acceptedEnd, now)).toBe(true);
    expect(matchesTicketAppKeyPreview(original, original, acceptedEnd, now)).toBe(false);
  });

  it("rejects a change to the ReCap or another SIWE field", () => {
    expect(matchesTicketAppKeyPreview(original, serializeSiwe({ ...fields, expirationTime: acceptedEnd, resources: [] }), acceptedEnd, now)).toBe(false);
    expect(matchesTicketAppKeyPreview(original, serializeSiwe({ ...fields, expirationTime: acceptedEnd, nonce: "othernonce" }), acceptedEnd, now)).toBe(false);
  });

  it("rejects an end beyond seven days or the original requested end", () => {
    const longEnd = new Date(now + TICKET_APP_KEY_MAX_MS + 1000).toISOString();
    const longMessage = serializeSiwe({ ...fields, expirationTime: longEnd });
    expect(matchesTicketAppKeyPreview(longMessage, longMessage, longEnd, now)).toBe(false);
    const shorterOriginal = serializeSiwe({ ...fields, expirationTime: new Date(now + 1800_000).toISOString() });
    expect(matchesTicketAppKeyPreview(shorterOriginal, preview, acceptedEnd, now)).toBe(false);
  });
});
