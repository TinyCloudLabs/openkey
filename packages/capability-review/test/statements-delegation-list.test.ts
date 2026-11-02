// The consent sentence for a read-only `tinycloud.delegation` grant (`list`, `status`) on the
// signer's own `account` or `applications` space. Other delegation verbs keep their wording.

import { describe, expect, it } from "bun:test";

import {
  buildStatement,
  classifyRecapEntry,
  type CapabilityAction,
  type CapabilityGrant,
} from "../src/index.js";

const SIGNER = "0x1111111111111111111111111111111111111111";
const OTHER = "0x2222222222222222222222222222222222222222";
const space = (name: string, owner = SIGNER) => `tinycloud:pkh:eip155:1:${owner}:${name}`;

const SENTENCE =
  "See who has access to your data";

/** A grant as the review model builds it: classified from its own entry, owned by the signer unless said otherwise. */
function grantFor(spaceUri: string, abilities: string[], options: { owner?: string } = {}): CapabilityGrant {
  const owner = options.owner ?? SIGNER;
  const classification = classifyRecapEntry({
    service: "tinycloud.delegation",
    space: spaceUri,
    path: "",
    actions: abilities,
    signerAddress: SIGNER,
  });
  const actions: CapabilityAction[] = abilities.map((ability) => ({
    id: `tinycloud.delegation\u0000${spaceUri}\u0000\u0000${ability}`,
    ability,
    verb: ability.slice(ability.indexOf("/") + 1),
    required: false,
    selected: true,
    editable: true,
    caveats: [],
  }));
  return {
    id: `tinycloud.delegation\u0000${spaceUri}\u0000`,
    family: classification.family,
    severity: classification.family === "unknown" ? "attention" : "standard",
    service: "tinycloud.delegation",
    space: spaceUri,
    path: "",
    owner,
    ownedBySelf: owner === SIGNER,
    displayLabel: classification.displayLabel,
    metadataLabel: null,
    resourceService: null,
    actions,
  };
}

describe("the sentence for listing the account's delegations", () => {
  it.each([
    ["the account space", "account"],
    ["the own applications space", "applications"],
  ])("is the new sentence for list, status, and both, on %s", (_name, spaceName) => {
    for (const abilities of [
      ["tinycloud.delegation/list"],
      ["tinycloud.delegation/status"],
      ["tinycloud.delegation/list", "tinycloud.delegation/status"],
    ]) {
      expect(buildStatement(grantFor(space(spaceName), abilities)).primaryText).toBe(SENTENCE);
    }
  });

  it("is not a sentence about managing the account: that wording stays for the account's key-value and SQL data", () => {
    expect(buildStatement(grantFor(space("account"), ["tinycloud.delegation/list"])).primaryText)
      .not.toContain("Manage your TinyCloud account");
  });

  it.each([
    ["revoke", ["tinycloud.delegation/revoke"]],
    ["create", ["tinycloud.delegation/create"]],
    ["a wildcard", ["tinycloud.delegation/*"]],
    ["list with revoke", ["tinycloud.delegation/list", "tinycloud.delegation/revoke"]],
  ])("another delegation verb (%s) keeps the literal wording, on both spaces", (_name, abilities) => {
    for (const spaceName of ["account", "applications"]) {
      const primaryText = buildStatement(grantFor(space(spaceName), abilities)).primaryText;
      expect(primaryText).not.toBe(SENTENCE);
      expect(buildStatement(grantFor(space(spaceName), abilities)).literalEscaped).toBe(true);
      for (const ability of abilities.filter((a) => a !== "tinycloud.delegation/list")) {
        expect(primaryText.toLowerCase()).toContain(`unknown action: ${ability}`);
      }
    }
  });

  it("a grant that is classed as a delegation read but carries another verb still gets the literal wording", () => {
    for (const spaceName of ["account", "applications"]) {
      const grant = { ...grantFor(space(spaceName), ["tinycloud.delegation/revoke"]), family: "bootstrap-delegation" as const, severity: "standard" as const };
      expect(buildStatement(grant).primaryText).toBe("Unknown action: tinycloud.delegation/revoke");
    }
  });

  it("another user's account space keeps its own sentence", () => {
    expect(buildStatement(grantFor(space("account", OTHER), ["tinycloud.delegation/list"], { owner: OTHER })).primaryText)
      .toBe("View another user's connected access");
  });

  it("another space keeps the literal wording", () => {
    expect(buildStatement(grantFor(space("default"), ["tinycloud.delegation/list"])).primaryText)
      .toBe("See who can access your data");
  });
});
