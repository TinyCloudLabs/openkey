// `tinycloud.delegation/revoke` is what an undo request asks for: it lets the requester remove
// access the signer gave. It reads "Remove access you gave" on the signer's own space, stays
// sensitive, and keeps the literal "Unknown action" wording anywhere it cannot be proven to be
// the signer's own space or when it is mixed with another verb.

import { describe, expect, it } from "bun:test";

import {
  buildStatement,
  classifyRecapEntry,
  classifySeverityFromActions,
  parseCapabilityReview,
  type CapabilityGrant,
  type SignerInfo,
} from "../src/index.js";
import type { ParseContext } from "../src/parse.js";
import { FIXTURE_META, makeRecapResource, siweWithResources } from "./fixtures/index.js";

const SIGNER = FIXTURE_META.address;
const OTHER = "0x2222222222222222222222222222222222222222";
const REVOKE = "tinycloud.delegation/revoke";
const LABEL = "Remove access you gave";
const space = (name: string, owner: string = SIGNER) =>
  `tinycloud:pkh:eip155:${FIXTURE_META.chainId}:${owner}:${name}`;

const signer: SignerInfo = {
  label: "Test signer",
  address: SIGNER,
  chainId: FIXTURE_META.chainId,
  provenance: "managed",
};

/** The grant the review builds for one delegation resource, through the real parser. */
function review(resource: string, abilities: string[]): CapabilityGrant {
  const ctx: ParseContext = {
    message: siweWithResources([
      makeRecapResource({
        [resource]: Object.fromEntries(abilities.map((a) => [a, [{}]])),
      }),
    ]),
    signer,
    editable: true,
    metadataTrust: { status: "unsigned", reason: "no manifest" },
    reason: { text: "", source: "none" },
    requester: {
      displayName: "cli.tinycloud.xyz",
      verifiedOrigin: "https://cli.tinycloud.xyz",
      appId: null,
      manifestName: null,
      manifestNameProvenance: "none",
      manifestId: null,
      manifestIdProvenance: "none",
      manifestDigest: null,
      domainWarning: false,
      originWarning: false,
    },
  };
  const model = parseCapabilityReview(ctx);
  expect(model.permissions).toHaveLength(1);
  return model.permissions[0]!;
}

describe("the revoke verb on the signer's own space", () => {
  it.each(["default", "account", "applications", "courier"])(
    "reads 'Remove access you gave', not 'Unknown action', on %s",
    (name) => {
      const grant = review(`${space(name)}/delegation`, [REVOKE]);
      const statement = buildStatement(grant);
      expect(statement.primaryText).toBe(LABEL);
      expect(statement.primaryText).not.toContain("Unknown action");
      expect(statement.literalEscaped).not.toBe(true);
      expect(grant.displayLabel).toBe(LABEL);
      expect(grant.family).toBe("bootstrap-delegation");
    },
  );

  it("stays sensitive", () => {
    const grant = review(`${space("default")}/delegation`, [REVOKE]);
    expect(grant.severity).toBe("sensitive");
    expect(classifySeverityFromActions("bootstrap-delegation", [REVOKE])).toBe("sensitive");
  });

  it("accepts the short service name", () => {
    expect(
      classifyRecapEntry({
        service: "delegation",
        space: space("default"),
        path: "",
        actions: ["delegation/revoke"],
        signerAddress: SIGNER,
      }),
    ).toEqual({ family: "bootstrap-delegation", displayLabel: LABEL });
  });

  it("does not make the delegation reads sensitive", () => {
    expect(classifySeverityFromActions("bootstrap-delegation", ["tinycloud.delegation/list"])).toBe("standard");
    expect(
      classifySeverityFromActions("bootstrap-delegation", ["tinycloud.delegation/list", "tinycloud.delegation/status"]),
    ).toBe("standard");
  });
});

describe("the revoke verb keeps the literal wording where it is not proven to be the signer's own", () => {
  it("on another user's space", () => {
    const grant = review(`${space("default", OTHER)}/delegation`, [REVOKE]);
    expect(buildStatement(grant).primaryText).toBe(`Unknown action: ${REVOKE}`);
    expect(grant.family).toBe("unknown");
  });

  it("when the signer's address is not known", () => {
    expect(
      classifyRecapEntry({ service: "tinycloud.delegation", space: space("default"), path: "", actions: [REVOKE] }),
    ).toEqual({ family: "unknown", displayLabel: "Unrecognized tinycloud.delegation permission" });
  });

  it("when the grant's service does not match its resource", () => {
    expect(
      classifyRecapEntry({
        service: "tinycloud.delegation",
        space: space("default"),
        path: "",
        actions: [REVOKE],
        signerAddress: SIGNER,
        serviceMismatch: true,
      }).family,
    ).toBe("unknown");
  });

  it.each([
    ["list", ["tinycloud.delegation/list", REVOKE]],
    ["an unregistered verb", [REVOKE, "tinycloud.delegation/export"]],
    ["a wildcard", ["tinycloud.delegation/*"]],
    ["create", ["tinycloud.delegation/create"]],
  ])("when mixed with or replaced by %s", (_name, abilities) => {
    const grant = review(`${space("default")}/delegation`, abilities);
    expect(grant.family).toBe("unknown");
    expect(grant.severity).not.toBe("standard");
    expect(buildStatement(grant).primaryText).not.toBe(LABEL);
    expect(buildStatement(grant).primaryText.toLowerCase()).toContain("unknown action");
  });

  it("a grant classed elsewhere never gets the label from its ability alone", () => {
    const grant = review(`${space("default", OTHER)}/delegation`, [REVOKE]);
    expect(buildStatement({ ...grant, family: "bootstrap-delegation", ownedBySelf: null }).primaryText).toBe(
      `Unknown action: ${REVOKE}`,
    );
  });

  it("another user's space is never described as a view when the verb is revoke", () => {
    const grant = review(`${space("account", OTHER)}/delegation`, [REVOKE]);
    expect(buildStatement(grant).primaryText).not.toContain("View");
    expect(buildStatement(grant).primaryText).toBe(`Unknown action: ${REVOKE}`);
  });
});
