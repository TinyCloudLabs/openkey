// TC-3826 N1: a SIWE the node may accept but OpenKey's reader refuses has no
// expiry or fields OpenKey can show, so its review is non-signable (the
// malformed-recap state: no Approve), never a signable review with no expiry.
import { describe, expect, it } from "bun:test";
import { parseCapabilityReview } from "../src/index.js";
import type { ParseContext } from "../src/parse.js";
import { makeRecapResource } from "./fixtures/index.js";

const ADDRESS = "0x71C7656EC7ab88b098defB751B7401B5f6d8976F";
const EXPIRY = "2036-11-22T00:00:00Z";
const RECAP = makeRecapResource({ [`tinycloud:pkh:eip155:1:${ADDRESS}:default/kv`]: { "tinycloud.kv/get": [{}] } });

function message({ nonce = "abcdefgh12345678", expiry = EXPIRY, requestId = "", recap = false } = {}): string {
  return [
    "example.com wants you to sign in with your Ethereum account:",
    ADDRESS,
    "",
    "Sign in to example.com.",
    "",
    "URI: https://example.com",
    "Version: 1",
    "Chain ID: 1",
    `Nonce: ${nonce}`,
    "Issued At: 2026-11-22T00:00:00Z",
    `Expiration Time: ${expiry}`,
    ...(requestId ? [`Request ID: ${requestId}`] : []),
    ...(recap ? ["Resources:", `- ${RECAP}`] : []),
  ].join("\n");
}

function review(text: string) {
  return parseCapabilityReview({
    message: text,
    signer: { address: ADDRESS, chainId: 1 },
    editable: true,
    metadataTrust: { status: "unsigned", reason: "no manifest" },
    reason: { text: "", source: "none" },
    requester: {
      displayName: "example.com",
      verifiedOrigin: "https://example.com",
      appId: null,
      manifestName: null,
      manifestNameProvenance: "none",
    },
  } as ParseContext);
}

const REFUSED = [
  ["a nonce with hyphens", { nonce: "abcd-efgh-1234" }],
  ["a lower-case t and z in the expiry", { expiry: "2036-11-22t00:00:00z" }],
  ["a space between the expiry's date and time", { expiry: "2036-11-22 00:00:00Z" }],
  ["a Request ID with a space", { requestId: "a b" }],
] as const;

describe("parseCapabilityReview refuses a SIWE its reader cannot read", () => {
  for (const recap of [false, true]) {
    it.each(REFUSED)(`${recap ? "ReCap" : "plain"} SIWE with %s is non-signable, with no expiry`, (_name, fields) => {
      const model = review(message({ ...fields, recap }));
      expect(model.protocol).toBe("malformed-recap");
      expect(model.expiry).toBeNull();
      expect(model.immutable).toBeNull();
      expect(model.permissions).toEqual([]);
      expect(model.parseWarnings.map((warning) => warning.code)).toContain("unparseable-siwe");
    });
  }

  it("keeps the same message signable, with its expiry, when every field is in the standard form", () => {
    expect(review(message())).toMatchObject({ protocol: "siwe-plain", expiry: EXPIRY });
    const recap = review(message({ requestId: "request-1", recap: true }));
    expect(recap).toMatchObject({ protocol: "tinycloud-siwe-recap", expiry: EXPIRY });
    expect(recap.permissions).toHaveLength(1);
  });
});
