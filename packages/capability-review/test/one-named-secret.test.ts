// A one-tap request to use one named secret: a read of exactly `vault/secrets/NAME` in the signer's own secrets
// space plus decrypt on the signer's own encryption network. Its rows name the secret; any other shape keeps the
// ordinary rows.

import { describe, expect, it } from "bun:test";

import { NAMED_SECRET_DECRYPT_ROW, buildSummaryStatements, oneNamedSecret, parseCapabilityReview } from "../src/index.js";
import type { CapabilityGrant } from "../src/index.js";
import { FIXTURE_META, makeRecapResource, siweWithResources } from "./fixtures/index.js";

const OTHER = "0x2222222222222222222222222222222222222222";
const secrets = (owner: string) => `tinycloud:pkh:eip155:${FIXTURE_META.chainId}:${owner}:secrets`;
const network = (owner: string) => `urn:tinycloud:encryption:did:pkh:eip155:${FIXTURE_META.chainId}:${owner}:default`;
const READ_OPENAI = { [`${secrets(FIXTURE_META.address)}/kv/vault/secrets/OPENAI_API_KEY`]: ["tinycloud.kv/get"] };
const DECRYPT = { [network(FIXTURE_META.address)]: ["tinycloud.encryption/decrypt"] };

function grantsFor(att: Record<string, string[]>): CapabilityGrant[] {
  return parseCapabilityReview({
    message: siweWithResources([
      makeRecapResource(
        Object.fromEntries(Object.entries(att).map(([resource, abilities]) => [resource, Object.fromEntries(abilities.map((a) => [a, [{}]]))])),
      ),
    ]),
    signer: { label: "Key", address: FIXTURE_META.address, chainId: FIXTURE_META.chainId, provenance: "managed" },
    editable: true,
    metadataTrust: { status: "unsigned", reason: "no manifest" },
    reason: { text: "", source: "none" },
    requester: {
      displayName: "TinyCloud CLI",
      verifiedOrigin: null,
      appId: null,
      manifestName: null,
      manifestNameProvenance: "none",
      manifestId: null,
      manifestIdProvenance: "none",
      manifestDigest: null,
      domainWarning: false,
      originWarning: false,
    },
    requesterAddress: null,
  }).permissions;
}

describe("one named secret", () => {
  it("names the secret, then the decrypt row, both Sensitive", () => {
    const grants = grantsFor({ ...READ_OPENAI, ...DECRYPT });
    expect(oneNamedSecret(grants)).toBe("OPENAI_API_KEY");
    expect(buildSummaryStatements(grants).map((row) => [row.key, row.primaryText, row.severity])).toEqual([
      ["read-named-secret", "Read the secret OPENAI_API_KEY", "sensitive"],
      [NAMED_SECRET_DECRYPT_ROW, "Decrypt your data", "sensitive"],
    ]);
  });

  it("keeps the ordinary rows for any other shape", () => {
    const cases: Record<string, Record<string, string[]>> = {
      "read without decrypt": READ_OPENAI,
      "decrypt without read": DECRYPT,
      "a third permission": { ...READ_OPENAI, ...DECRYPT, [`tinycloud:pkh:eip155:1:${FIXTURE_META.address}:default/kv/notes/`]: ["tinycloud.kv/get"] },
      "a write beside the read": { [`${secrets(FIXTURE_META.address)}/kv/vault/secrets/OPENAI_API_KEY`]: ["tinycloud.kv/get", "tinycloud.kv/put"], ...DECRYPT },
      "every secret": { [`${secrets(FIXTURE_META.address)}/kv/vault/secrets/`]: ["tinycloud.kv/get"], ...DECRYPT },
      "an app-scoped secret": { [`${secrets(FIXTURE_META.address)}/kv/vault/secrets/scoped/listen/API_KEY`]: ["tinycloud.kv/get"], ...DECRYPT },
      "another user's secret": { [`${secrets(OTHER)}/kv/vault/secrets/OPENAI_API_KEY`]: ["tinycloud.kv/get"], ...DECRYPT },
      "another user's network": { ...READ_OPENAI, [network(OTHER)]: ["tinycloud.encryption/decrypt"] },
      "one key, not the network": { ...READ_OPENAI, [`${network(FIXTURE_META.address)}/openai`]: ["tinycloud.encryption/decrypt"] },
      "the default space, not secrets": { [`tinycloud:pkh:eip155:1:${FIXTURE_META.address}:default/kv/vault/secrets/OPENAI_API_KEY`]: ["tinycloud.kv/get"], ...DECRYPT },
    };
    for (const [name, att] of Object.entries(cases)) {
      const grants = grantsFor(att);
      const rows = buildSummaryStatements(grants).map((row) => row.primaryText);
      expect({ name, secret: oneNamedSecret(grants), plainDecrypt: rows.includes("Decrypt your data") })
        .toEqual({ name, secret: null, plainDecrypt: false });
    }
  });
});
