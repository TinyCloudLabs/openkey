// A read of one named secret with no key request reads as that secret; a wider decrypt in the same request, a
// scoped path or any other shape keeps the ordinary rows. The two grants that read every secret are named apart
// from every grant that writes or reaches wider.

import { describe, expect, it } from "bun:test";

import { allSecretsReadPart, buildSummaryStatements, isScopedSecretGrant, parseCapabilityReview } from "../src/index.js";
import type { CapabilityGrant } from "../src/index.js";
import { FIXTURE_META, makeRecapResource, siweWithResources } from "./fixtures/index.js";

const OWNER = `did:pkh:eip155:${FIXTURE_META.chainId}:${FIXTURE_META.address}`;
const NETWORK = `urn:tinycloud:encryption:${OWNER}:default`;
const SECRETS_SPACE = `tinycloud:pkh:eip155:${FIXTURE_META.chainId}:${FIXTURE_META.address}:secrets`;
const DECRYPT = "tinycloud.encryption/decrypt";
const KV_GET = "tinycloud.kv/get";

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

const rowsOf = (att: Record<string, string[]>) => buildSummaryStatements(grantsFor(att)).map((row) => row.primaryText);

describe("a read of one named secret with no key request", () => {
  it("reads as that secret, with the secret named on the row", () => {
    const [row] = buildSummaryStatements(grantsFor({ [`${SECRETS_SPACE}/kv/vault/secrets/BOT_HISTORY`]: [KV_GET] }));
    expect(row?.primaryText).toBe("Read the secret BOT_HISTORY");
    expect(row?.secret).toEqual({ name: "BOT_HISTORY", keyPath: "secrets/bot_history", kvPath: "vault/secrets/BOT_HISTORY" });
  });

  it("keeps the ordinary row beside a decrypt on the secrets prefix", () => {
    expect(rowsOf({ [`${SECRETS_SPACE}/kv/vault/secrets/BOT_HISTORY`]: [KV_GET], [`${NETWORK}/secrets/`]: [DECRYPT] })).not.toContain("Read the secret BOT_HISTORY");
  });

  it("keeps the ordinary row beside a decrypt on the whole network", () => {
    expect(rowsOf({ [`${SECRETS_SPACE}/kv/vault/secrets/BOT_HISTORY`]: [KV_GET], [NETWORK]: [DECRYPT] })).not.toContain("Read the secret BOT_HISTORY");
  });

  it("is named beside a decrypt on another secret's own key", () => {
    expect(rowsOf({ [`${SECRETS_SPACE}/kv/vault/secrets/BOT_HISTORY`]: [KV_GET], [`${NETWORK}/secrets/deploy_key`]: [DECRYPT] })).toContain("Read the secret BOT_HISTORY");
  });

  it("is not named for a path that is not a secret name, a trailing slash or a get with a put", () => {
    for (const [path, abilities] of [["NAME-2", [KV_GET]], ["NAME/", [KV_GET]], ["NAME", [KV_GET, "tinycloud.kv/put"]]] as const) {
      expect(rowsOf({ [`${SECRETS_SPACE}/kv/vault/secrets/${path}`]: [...abilities] })).not.toContain("Read the secret NAME");
    }
  });
});

describe("the grants that read every secret", () => {
  const part = (att: Record<string, string[]>) => grantsFor(att).map(allSecretsReadPart);
  it("are a KV get on the secrets directory and a decrypt on the secrets prefix", () => {
    expect(part({ [`${SECRETS_SPACE}/kv/vault/secrets/`]: [KV_GET] })).toEqual(["value"]);
    expect(part({ [`${SECRETS_SPACE}/kv/vault/secrets`]: [KV_GET] })).toEqual(["value"]);
    expect(part({ [`${NETWORK}/secrets/`]: [DECRYPT] })).toEqual(["key"]);
  });

  it("are not a grant with another action, a wider path or the scoped prefix", () => {
    for (const att of [
      { [`${SECRETS_SPACE}/kv/vault/secrets/`]: [KV_GET, "tinycloud.kv/put"] },
      { [`${SECRETS_SPACE}/kv/vault/secrets/`]: ["tinycloud.kv/*"] },
      { [`${SECRETS_SPACE}/kv/vault/`]: [KV_GET] },
      { [`${SECRETS_SPACE}/kv/vault`]: [KV_GET] },
      { [`${SECRETS_SPACE}/kv/secrets/`]: [KV_GET] },
      { [`${NETWORK}/secrets/scoped/`]: [DECRYPT] },
      { [`${NETWORK}/secrets/`]: [DECRYPT, "tinycloud.encryption/key.create"] },
      { [NETWORK]: [DECRYPT] },
    ]) {
      expect(part(att)).toEqual([null]);
    }
  });
});

describe("a scoped secret", () => {
  it("is a KV path or a key under the scoped directory", () => {
    const scoped = (att: Record<string, string[]>) => grantsFor(att).map(isScopedSecretGrant);
    expect(scoped({ [`${SECRETS_SPACE}/kv/vault/secrets/scoped/evil/BOT_HISTORY`]: [KV_GET] })).toEqual([true]);
    expect(scoped({ [`${NETWORK}/secrets/scoped/evil/bot_history`]: [DECRYPT] })).toEqual([true]);
    expect(scoped({ [`${NETWORK}/secrets/scoped/`]: [DECRYPT] })).toEqual([true]);
    expect(scoped({ [`${SECRETS_SPACE}/kv/vault/secrets/BOT_HISTORY`]: [KV_GET] })).toEqual([false]);
    expect(scoped({ [`${NETWORK}/secrets/bot_history`]: [DECRYPT] })).toEqual([false]);
  });
});
