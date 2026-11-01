// The callout above the approval list counts the rows marked Sensitive that reach secrets or
// decryption. It used to count grants: one share/ grant with a create and a decrypt is two rows,
// both marked Sensitive, but counted once ("2 permissions" above three Sensitive rows).

import { describe, expect, it } from "bun:test";

import {
  buildStatements,
  grantReachesSecretDataOrDecryption,
  parseCapabilityReview,
  sensitiveRowCount,
  type CapabilityGrant,
} from "../src/index.js";
import { FIXTURE_META, makeRecapResource, siweWithResources } from "./fixtures/index.js";

const OWNER = `did:pkh:eip155:${FIXTURE_META.chainId}:${FIXTURE_META.address}`;
const urn = (rest: string) => `urn:tinycloud:encryption:${OWNER}:default${rest}`;
const E = "tinycloud.encryption/";
const SHARE = urn("/share/");
const APP = urn("/apps/xyz.tinycloud.listen/");

function grantsFor(resources: Record<string, string[]>): CapabilityGrant[] {
  return parseCapabilityReview({
    message: siweWithResources([
      makeRecapResource(
        Object.fromEntries(
          Object.entries(resources).map(([resource, abilities]) => [
            resource,
            Object.fromEntries(abilities.map((ability) => [E + ability, [{}]])),
          ]),
        ),
      ),
    ]),
    signer: { label: "Test signer", address: FIXTURE_META.address, chainId: FIXTURE_META.chainId, provenance: "managed" },
    editable: true,
    metadataTrust: { status: "unsigned", reason: "no manifest" },
    reason: { text: "", source: "none" },
    requester: {
      displayName: "listen.tinycloud.xyz",
      verifiedOrigin: "https://listen.tinycloud.xyz",
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

/** The Sensitive rows the approval list shows: one per distinct text, as the list groups them. */
function sensitiveRowTexts(grants: CapabilityGrant[]): string[] {
  const rows = new Map<string, boolean>();
  for (const grant of grants) {
    for (const row of buildStatements(grant)) {
      const sensitive = (row.severity ?? grant.severity) === "sensitive";
      rows.set(row.primaryText, (rows.get(row.primaryText) ?? false) || sensitive);
    }
  }
  return [...rows].filter(([, sensitive]) => sensitive).map(([text]) => text);
}

describe("the callout count matches the Sensitive rows", () => {
  it("counts every Sensitive row of a grant that reaches decryption, not the grant", () => {
    const grants = grantsFor({ [SHARE]: ["key.create", "decrypt"], [APP]: ["key.create", "decrypt"] });
    expect(grants.filter(grantReachesSecretDataOrDecryption)).toHaveLength(2);
    expect(sensitiveRowTexts(grants)).toHaveLength(3);
    expect(sensitiveRowCount(grants)).toBe(3);
  });

  it.each([
    ["one decrypt", { [SHARE]: ["decrypt"] }, 1],
    ["a create and a decrypt on one prefix", { [SHARE]: ["key.create", "decrypt"] }, 2],
    ["an app key decrypt beside its attention-level create", { [APP]: ["key.create", "decrypt"] }, 1],
    ["two decrypts", { [SHARE]: ["decrypt"], [APP]: ["decrypt"] }, 2],
  ])("%s", (_name, resources, expected) => {
    const grants = grantsFor(resources);
    expect(sensitiveRowCount(grants)).toBe(expected);
    expect(sensitiveRowCount(grants)).toBe(sensitiveRowTexts(grants).length);
  });

  it("is zero when nothing reaches decryption", () => {
    expect(sensitiveRowCount(grantsFor({ [SHARE]: ["key.create"] }))).toBe(0);
    expect(sensitiveRowCount([])).toBe(0);
  });

  it("counts a row shown once for two grants once", () => {
    const grants = grantsFor({ [SHARE]: ["decrypt"] });
    expect(sensitiveRowCount([...grants, ...grants])).toBe(1);
  });

  it("does not count a Sensitive row that is not about secrets or decryption", () => {
    const grants = grantsFor({ [SHARE]: ["decrypt"] });
    const space: CapabilityGrant = {
      ...grants[0]!,
      id: "space",
      family: "space-create",
      severity: "sensitive",
      service: "tinycloud.space",
      space: `tinycloud:pkh:eip155:${FIXTURE_META.chainId}:${FIXTURE_META.address}:courier`,
      actions: [{ ...grants[0]!.actions[0]!, id: "space-host", ability: "tinycloud.space/host", verb: "host" }],
    };
    expect(sensitiveRowCount([...grants, space])).toBe(1);
  });
});
