// TC-3826: the expiry is the `Expiration Time` field after `Issued At`, read
// the way the node reads it; never a look-alike line in the statement.
import { describe, expect, it } from "bun:test";
import { hasForbiddenSiweCharacter, parseCapabilityReview, parseSiweFields, serializeSiwe, siweExpirationTime } from "../src/index.js";
import type { ParseContext } from "../src/parse.js";
import { REAL_RECAP_BOOTSTRAP } from "./fixtures/index.js";

const FAKE = "2026-10-17T17:00:00.000Z";
const REAL = "2036-10-16T17:00:00.000Z";
const SEPARATORS = [["CR", "\r"], ["U+2028", "\u2028"], ["U+2029", "\u2029"]] as const;

function message(statementPrefix: string): string {
  return [
    "example.com wants you to sign in with your Ethereum account:",
    "0x71C7656EC7ab88b098defB751B7401B5f6d8976F",
    "",
    `${statementPrefix}I further authorize the stated URI to perform the following actions on my behalf: (1) 'kv': 'get' for 'tinycloud:pkh:eip155:1:0x71C7656EC7ab88b098defB751B7401B5f6d8976F:default/kv'.`,
    "",
    "URI: https://example.com",
    "Version: 1",
    "Chain ID: 1",
    "Nonce: abcdefgh12345678",
    "Issued At: 2026-10-16T17:00:00.000Z",
    `Expiration Time: ${REAL}`,
  ].join("\n");
}

function review(text: string) {
  const ctx: ParseContext = {
    message: text,
    signer: { address: "0x71C7656EC7ab88b098defB751B7401B5f6d8976F", chainId: 1 },
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
  } as ParseContext;
  return parseCapabilityReview(ctx);
}

describe("siweExpirationTime", () => {
  it.each(SEPARATORS)("refuses a fake statement line behind %s", (_name, separator) => {
    const attack = message(`Expiration Time: ${FAKE}${separator} `);
    expect(hasForbiddenSiweCharacter(attack)).toBe(true);
    expect(parseSiweFields(attack).ok).toBe(false);
    expect(siweExpirationTime(attack)).toBeNull();
  });

  it("reads the field, not statement text that looks like one", () => {
    const normal = message(`Expiration Time: ${FAKE} `);
    expect(siweExpirationTime(normal)).toBe(REAL);
    const parsed = parseSiweFields(normal);
    expect(parsed.ok && serializeSiwe(parsed.fields)).toBe(normal);
  });

  it("refuses every other C0 control and DEL, and accepts a real ReCap message", () => {
    for (const code of [0x00, 0x09, 0x0b, 0x0c, 0x1f, 0x7f]) {
      expect(siweExpirationTime(message(`x${String.fromCharCode(code)} `))).toBeNull();
    }
    expect(parseSiweFields(REAL_RECAP_BOOTSTRAP).ok).toBe(true);
  });

  it("returns null for a non-SIWE with an Expiration Time line", () => {
    for (const text of [
      `Expiration Time: ${FAKE}`,
      `cli.tinycloud.xyz wants you to sign in\n\nExpiration Time: ${FAKE}`,
      "no expiry here",
      "Expiration Time: not-a-date",
    ]) {
      expect(siweExpirationTime(text)).toBeNull();
      expect(review(text).expiry).toBeNull();
    }
  });
});

describe("parseCapabilityReview expiry and immutable fields", () => {
  it.each(SEPARATORS)("shows no expiry and no immutable fields for a fake line behind %s", (_name, separator) => {
    const model = review(message(`Expiration Time: ${FAKE}${separator} `));
    expect(model.expiry).toBeNull();
    expect(model.immutable).toBeNull();
  });

  it("shows the signed field for a normal message", () => {
    const model = review(message(`Expiration Time: ${FAKE} `));
    expect(model.expiry).toBe(REAL);
    expect(model.immutable?.expirationTime).toBe(REAL);
    expect(model.immutable?.issuedAt).toBe("2026-10-16T17:00:00.000Z");
  });
});
