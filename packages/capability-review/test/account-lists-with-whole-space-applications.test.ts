// A request that reads the app list and the space list in the account space and also holds a grant on the whole
// applications space shows two rows: the read-only lists row and the whole-space row.

import { describe, expect, it } from "bun:test";

import {
  ACCOUNT_LISTS_READ_ONLY_ROW,
  accountListsReadOnly,
  buildSummaryStatements,
  parseCapabilityReview,
  type CapabilityGrant,
} from "../src/index.js";
import { FIXTURE_META, makeRecapResource, siweWithResources } from "./fixtures/index.js";

const ACCOUNT_SPACE = `tinycloud:pkh:eip155:${FIXTURE_META.chainId}:${FIXTURE_META.address}:account`;
const APPLICATIONS_SPACE = `tinycloud:pkh:eip155:${FIXTURE_META.chainId}:${FIXTURE_META.address}:applications`;
const ACCOUNT_APP_LIST = `${ACCOUNT_SPACE}/kv/applications/`;
const WHOLE_SPACE_KV = `${APPLICATIONS_SPACE}/kv/`;

const LIST_ABILITIES = ["tinycloud.kv/get", "tinycloud.kv/list"];
const WHOLE_SPACE_ABILITIES = [
  "tinycloud.kv/get",
  "tinycloud.kv/put",
  "tinycloud.kv/del",
  "tinycloud.kv/list",
  "tinycloud.kv/metadata",
];

function grantsOf(att: Record<string, string[]>): CapabilityGrant[] {
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
      displayName: "example.com",
      verifiedOrigin: "https://example.com",
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
    requesterVerified: false,
  }).permissions;
}

describe("an account-lists grant beside a whole-space applications grant", () => {
  const both = grantsOf({ [ACCOUNT_APP_LIST]: LIST_ABILITIES, [WHOLE_SPACE_KV]: WHOLE_SPACE_ABILITIES });
  const wholeSpaceAlone = buildSummaryStatements(grantsOf({ [WHOLE_SPACE_KV]: WHOLE_SPACE_ABILITIES }));

  it("parses to the two grants the test combines", () => {
    expect(both).toHaveLength(2);
    expect(accountListsReadOnly(both)).toBe(true);
    expect(wholeSpaceAlone).toHaveLength(1);
  });

  it("gives the lists grant the read-only lists row", () => {
    const rows = buildSummaryStatements(both).map((row) => row.primaryText);
    expect(rows).toContain(ACCOUNT_LISTS_READ_ONLY_ROW);
  });

  it("gives the whole-space grant the row it has alone, not the lists row", () => {
    const [aloneRow] = wholeSpaceAlone;
    expect(aloneRow!.primaryText).not.toBe(ACCOUNT_LISTS_READ_ONLY_ROW);
    const rows = buildSummaryStatements(both).map((row) => row.primaryText);
    expect(rows).toContain(aloneRow!.primaryText);
  });

  it("keeps the two rows separate", () => {
    const rows = buildSummaryStatements(both).map((row) => row.primaryText);
    expect(rows).toHaveLength(2);
    expect(new Set(rows).size).toBe(2);
  });
});
