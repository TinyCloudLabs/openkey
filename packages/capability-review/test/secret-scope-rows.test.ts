// A secret's row belongs to its full key path: the same name in two scopes is two rows, each with its secret, so the
// Sensitive count over the rows and the "Read N secrets" count are the number of secrets the request reads.

import { describe, expect, it } from "bun:test";

import {
  buildSummaryStatements,
  parseCapabilityReview,
  secretListLabel,
  secretReadParts,
  sensitiveRowsCallout,
  sensitiveSummaryCount,
} from "../src/index.js";
import type { CapabilityGrant } from "../src/index.js";
import { FIXTURE_META, makeRecapResource, siweWithResources } from "./fixtures/index.js";

const OWNER = `did:pkh:eip155:${FIXTURE_META.chainId}:${FIXTURE_META.address}`;
const NETWORK = `urn:tinycloud:encryption:${OWNER}:default`;
const SPACE_PREFIX = `tinycloud:pkh:eip155:${FIXTURE_META.chainId}:${FIXTURE_META.address}`;
const DECRYPT = "tinycloud.encryption/decrypt";

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

const globalKey = (name: string) => `${NETWORK}/secrets/${name}`;
const scopedKey = (scope: string, name: string) => `${NETWORK}/secrets/scoped/${scope}/${name}`;
const decryptAll = (keys: string[]) => Object.fromEntries(keys.map((key) => [key, [DECRYPT]]));

/** The rows the approval face counts: the secret rows ("Read N secrets") and the Sensitive rows (the banner). */
function counts(att: Record<string, string[]>) {
  const rows = buildSummaryStatements(grantsFor(att));
  return { rows, secrets: rows.filter((row) => row.secret !== undefined).length, sensitive: sensitiveSummaryCount(rows) };
}

describe("same secret name in different scopes", () => {
  it("keeps one row per scope, each marked as a secret, with unique keys", () => {
    const { rows, secrets, sensitive } = counts(decryptAll([scopedKey("alpha", "api_key"), scopedKey("beta", "api_key")]));
    expect(rows.map((row) => row.primaryText)).toEqual([
      "Read the secret api_key in scope alpha",
      "Read the secret api_key in scope beta",
    ]);
    expect(rows.map((row) => row.secret)).toEqual([
      { name: "api_key", keyPath: "secrets/scoped/alpha/api_key", scope: "alpha" },
      { name: "api_key", keyPath: "secrets/scoped/beta/api_key", scope: "beta" },
    ]);
    expect(new Set(rows.map((row) => row.key)).size).toBe(2);
    expect(secrets).toBe(2);
    expect(sensitive).toBe(2);
    expect(sensitiveRowsCallout(sensitive)).toBe("2 permissions are marked Sensitive");
  });

  it("keeps a global secret and a scoped secret of the same name as two rows", () => {
    const { rows, secrets, sensitive } = counts(decryptAll([globalKey("api_key"), scopedKey("alpha", "api_key"), scopedKey("beta", "api_key")]));
    expect(rows.map((row) => row.primaryText)).toEqual([
      "Read the secret api_key",
      "Read the secret api_key in scope alpha",
      "Read the secret api_key in scope beta",
    ]);
    expect(rows.map((row) => row.secret?.scope)).toEqual([undefined, "alpha", "beta"]);
    expect(new Set(rows.map((row) => row.key)).size).toBe(3);
    expect(secrets).toBe(3);
    expect(sensitive).toBe(3);
  });

  it("names a scoped secret by its KV path when the request pairs it with the key", () => {
    const { rows } = counts({
      ...decryptAll([scopedKey("alpha", "api_key"), scopedKey("beta", "api_key")]),
      [`${SPACE_PREFIX}:secrets/kv/vault/secrets/scoped/alpha/API_KEY`]: ["tinycloud.kv/get"],
      [`${SPACE_PREFIX}:secrets/kv/vault/secrets/scoped/beta/API_KEY`]: ["tinycloud.kv/get"],
    });
    expect(rows.map((row) => row.primaryText)).toEqual([
      "Read the secret API_KEY in scope alpha",
      "Read the secret API_KEY in scope beta",
    ]);
    expect(rows.every((row) => row.secret?.kvPath === undefined)).toBe(true);
  });

  it("collapses the same sentence of a row that is not a secret at its strongest severity", () => {
    const grants = grantsFor({ ...decryptAll([scopedKey("alpha", "api_key")]), [`${SPACE_PREFIX}:default/kv/notes/`]: ["tinycloud.kv/get"] });
    const once = buildSummaryStatements(grants);
    expect(buildSummaryStatements([...grants, ...grants]).map((row) => [row.primaryText, row.severity])).toEqual(
      once.map((row) => [row.primaryText, row.severity]),
    );
  });

  it("words the scoped row and lists a secret as SCOPE/NAME, a global one as NAME", () => {
    expect(secretReadParts("api_key", "alpha")).toEqual([
      { text: "Read the secret ", named: false },
      { text: "api_key", named: true },
      { text: " in scope ", named: false },
      { text: "alpha", named: true },
    ]);
    expect(secretReadParts("api_key", null).map((part) => part.text).join("")).toBe("Read the secret api_key");
    expect(secretListLabel({ name: "api_key", keyPath: "secrets/scoped/alpha/api_key", scope: "alpha" } as { name: string; scope: string })).toBe("alpha/api_key");
    expect(secretListLabel({ name: "api_key" })).toBe("api_key");
  });
});

describe("a request shaped like a real one: 140 exact secret keys", () => {
  // 106 names in one place, 17 names in two scopes (34 keys); 123 distinct names.
  const single = Array.from({ length: 106 }, (_, index) => globalKey(`secret_${index}`));
  const doubled = Array.from({ length: 17 }, (_, index) => [scopedKey("alpha", `shared_${index}`), scopedKey("beta", `shared_${index}`)]).flat();

  it("counts every key as a secret row", () => {
    const { secrets, sensitive } = counts(decryptAll([...single, ...doubled]));
    expect(single.length + doubled.length).toBe(140);
    expect(secrets).toBe(140);
    expect(sensitive).toBe(140);
  });

  it("lists 142 Sensitive rows and 140 secrets with a kv row and a network-root row beside the keys", () => {
    const { rows, secrets, sensitive } = counts({
      ...decryptAll([...single, ...doubled]),
      [`${SPACE_PREFIX}:secrets/kv/vault/secrets/`]: ["tinycloud.kv/get"],
      [NETWORK]: [DECRYPT],
    });
    expect(rows.filter((row) => row.secret === undefined).map((row) => [row.primaryText, row.severity])).toEqual([
      ["Decrypt protected data", "sensitive"],
      ["Read secret values", "sensitive"],
    ]);
    expect(secrets).toBe(140);
    expect(sensitive).toBe(142);
    expect(sensitiveRowsCallout(sensitive)).toBe("142 permissions are marked Sensitive");
    expect(new Set(rows.map((row) => row.key)).size).toBe(rows.length);
  });
});
