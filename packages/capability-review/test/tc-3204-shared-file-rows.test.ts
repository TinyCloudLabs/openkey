// TC-3204: decrypt on several exact shared files is one summary row that counts them, never one repeated row.

import { describe, expect, it } from "bun:test";

import { buildSummaryStatements, sensitiveSummaryCount, type CapabilityGrant } from "../src/index.js";

const NETWORK = "urn:tinycloud:encryption:did:pkh:eip155:1:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed:default";
const DECRYPT = "tinycloud.encryption/decrypt";
const IDS = ["3f9c1a7e5b2d48a09c6e1f7a2b4d8c03", "9b0e4d2c7a1f48e3b5c6d7e8f9a0b1c2", "c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2"];

function grant(resource: string, ability = DECRYPT): CapabilityGrant {
  return {
    id: `tinycloud.encryption\x00${resource}\x00`,
    family: "encryption-decrypt",
    severity: "sensitive",
    service: "tinycloud.encryption",
    space: resource,
    path: "",
    owner: null,
    ownedBySelf: true,
    displayLabel: "",
    metadataLabel: null,
    resourceService: null,
    actions: [{ id: `${resource}\x00${ability}`, ability, verb: ability.slice(ability.indexOf("/") + 1), required: false, selected: true, editable: true, caveats: [] }],
  };
}

const shared = (count: number) => IDS.slice(0, count).map((id) => grant(`${NETWORK}/share/${id}`));

describe("shared-file decrypt summary row", () => {
  it("one shared file reads \"Open this shared file\"", () => {
    expect(buildSummaryStatements(shared(1)).map((row) => [row.primaryText, row.severity])).toEqual([["Open this shared file", "sensitive"]]);
  });

  it("three shared files are one Sensitive row that counts them", () => {
    const rows = buildSummaryStatements(shared(3));
    expect(rows.map((row) => [row.primaryText, row.severity])).toEqual([["Open 3 shared files", "sensitive"]]);
    expect(sensitiveSummaryCount(rows)).toBe(1);
  });

  it("the same shared file twice is still one file", () => {
    expect(buildSummaryStatements([...shared(1), ...shared(1)]).map((row) => row.primaryText)).toEqual(["Open this shared file"]);
  });

  it("other rows beside the shared files keep their own text", () => {
    const rows = buildSummaryStatements([...shared(2), grant(`${NETWORK}/share/`)]).map((row) => row.primaryText);
    expect(rows).toContain("Open 2 shared files");
    expect(rows).toContain("Open all your shared files, including ones you share later.");
  });
});
