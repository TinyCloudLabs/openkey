import { describe, expect, it } from "bun:test";
import { buildStatements, buildSummaryStatements, parseCapabilityReview } from "../src/index.js";
import { FIXTURE_META, makeRecapResource, siweWithResources } from "./fixtures/index.js";

const address = FIXTURE_META.address;
const applications = `tinycloud:pkh:eip155:${FIXTURE_META.chainId}:${address}:applications`;
const otherSpace = `tinycloud:pkh:eip155:${FIXTURE_META.chainId}:${address}:default`;

/** Parse one resource carrying `abilities` the way the approval screen does. */
function parseGrant(resource: string, abilities: string[]) {
  const model = parseCapabilityReview({
    message: siweWithResources([
      makeRecapResource({ [resource]: Object.fromEntries(abilities.map((ability) => [ability, [{}]])) }),
    ]),
    signer: { label: "Test signer", address, chainId: FIXTURE_META.chainId, provenance: "managed" },
    editable: true,
    metadataTrust: { status: "unsigned", reason: "no manifest" },
    reason: { text: "", source: "none" },
    requester: {
      displayName: "test.tinycloud.xyz",
      verifiedOrigin: "https://test.tinycloud.xyz",
      appId: null,
      manifestName: null,
      manifestNameProvenance: "none",
      manifestId: null,
      manifestIdProvenance: "none",
      manifestDigest: null,
      domainWarning: false,
      originWarning: false,
    },
  });
  const grant = model.permissions[0];
  if (!grant) throw new Error("resource did not parse to a grant");
  return grant;
}

/** The single grant's severity and the rows it renders. */
function describeGrant(resource: string, abilities: string[]) {
  const grant = parseGrant(resource, abilities);
  return { severity: grant.severity, rows: buildStatements(grant).map((row) => row.primaryText) };
}

const KV_ALL = ["tinycloud.kv/get", "tinycloud.kv/list", "tinycloud.kv/put", "tinycloud.kv/del", "tinycloud.kv/metadata"];

describe("a grant on the whole applications space reaches every app", () => {
  it("marks KV write and delete across all apps as attention, in words that name every app", () => {
    expect(describeGrant(`${applications}/kv/`, KV_ALL)).toEqual({
      severity: "attention",
      rows: ["Read, change and delete data in all your apps"],
    });
  });

  it("marks a KV change-only grant across all apps as attention", () => {
    expect(describeGrant(`${applications}/kv/`, ["tinycloud.kv/put"])).toEqual({
      severity: "attention",
      rows: ["Change data in all your apps"],
    });
  });

  it("marks a KV delete-only grant across all apps as attention", () => {
    expect(describeGrant(`${applications}/kv/`, ["tinycloud.kv/del"])).toEqual({
      severity: "attention",
      rows: ["Delete data in all your apps"],
    });
  });

  it("marks SQL write across all apps as attention, in words that name every app", () => {
    expect(describeGrant(`${applications}/sql/`, ["tinycloud.sql/read", "tinycloud.sql/write"])).toEqual({
      severity: "attention",
      rows: ["Read, change and delete rows in all your apps"],
    });
  });

  it("keeps read-only access across all apps standard, still naming every app", () => {
    expect(describeGrant(`${applications}/kv/`, ["tinycloud.kv/get", "tinycloud.kv/list"])).toEqual({
      severity: "standard",
      rows: ["Read data in all your apps"],
    });
    expect(describeGrant(`${applications}/sql/`, ["tinycloud.sql/read"])).toEqual({
      severity: "standard",
      rows: ["Read data in all your apps"],
    });
  });
});

describe("the summary the owner reads", () => {
  it("carries attention on the all-apps row", () => {
    const rows = buildSummaryStatements([parseGrant(`${applications}/kv/`, KV_ALL)]);
    expect(rows.map((row) => [row.primaryText, row.severity])).toEqual([
      ["Read, change and delete data in all your apps", "attention"],
    ]);
  });
});

describe("a grant on one app is unchanged", () => {
  it("keeps one app's KV folder standard with its own wording", () => {
    expect(
      describeGrant(`${applications}/kv/xyz.tinycloud.sample.recipes/`, [
        "tinycloud.kv/get",
        "tinycloud.kv/put",
        "tinycloud.kv/del",
      ]),
    ).toEqual({
      severity: "standard",
      rows: ["Read and update application data", "Delete data associated with `xyz.tinycloud.sample.recipes`"],
    });
  });

  it("keeps one app's SQL database standard with its own wording", () => {
    expect(
      describeGrant(`${applications}/sql/xyz.tinycloud.sample.healthlog/healthlog`, [
        "tinycloud.sql/read",
        "tinycloud.sql/write",
      ]),
    ).toEqual({
      severity: "standard",
      rows: ["Read, change or delete any row in the xyz.tinycloud.sample.healthlog database"],
    });
  });

  it("does not flag an empty path in another space as all apps", () => {
    expect(describeGrant(`${otherSpace}/kv/`, KV_ALL).severity).toBe("standard");
  });
});
