// A request that only reads the app list and the space list in the account space says so in the main row and in
// Advanced details; any other account access keeps "Manage your TinyCloud account".

import { describe, expect, it } from "bun:test";

import {
  accountListsReadOnlyDetails,
  buildSummaryStatements,
  defaultSelection,
  parseCapabilityReview,
  type CapabilityReviewModel,
} from "../src/index.js";
import { FIXTURE_META, makeRecapResource, siweWithResources } from "./fixtures/index.js";

const ACCOUNT_SPACE = `tinycloud:pkh:eip155:${FIXTURE_META.chainId}:${FIXTURE_META.address}:account`;
const APPS = `${ACCOUNT_SPACE}/kv/applications/`;
const SPACES = `${ACCOUNT_SPACE}/kv/spaces/`;
const SETUP = `${ACCOUNT_SPACE}/kv/system/bootstrap/complete`;
const ACCOUNT_SQL = `${ACCOUNT_SPACE}/sql/account`;
const CAPABILITIES = `${ACCOUNT_SPACE}/capabilities`;

const MANAGE = "Manage your TinyCloud account";
const SEE_LISTS = "See your apps and spaces";
const LISTS_DETAILS =
  "Read-only account lists: Reads the list of apps you've installed and the list of your spaces. Nothing can be changed.";

function modelFor(att: Record<string, string[]>): CapabilityReviewModel {
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
  });
}

function selectedGrants(model: CapabilityReviewModel) {
  const selection = defaultSelection(model);
  return model.permissions.flatMap((grant) => {
    const actions = grant.actions.filter((action) => selection.has(action.id));
    return actions.length > 0 ? [{ ...grant, actions }] : [];
  });
}

function rowsOf(att: Record<string, string[]>): string[] {
  return buildSummaryStatements(selectedGrants(modelFor(att))).map((row) => row.primaryText);
}

function detailsOf(att: Record<string, string[]>): string | null {
  return accountListsReadOnlyDetails(selectedGrants(modelFor(att)));
}

describe("read-only account lists", () => {
  it("reads the app list alone as seeing apps and spaces", () => {
    const att = { [APPS]: ["tinycloud.kv/get", "tinycloud.kv/list"] };
    expect(rowsOf(att)).toEqual([SEE_LISTS]);
    expect(detailsOf(att)).toBe(LISTS_DETAILS);
  });

  it("reads the space list alone as seeing apps and spaces", () => {
    const att = { [SPACES]: ["tinycloud.kv/list"] };
    expect(rowsOf(att)).toEqual([SEE_LISTS]);
    expect(detailsOf(att)).toBe(LISTS_DETAILS);
  });

  it("reads both lists as one row", () => {
    const att = {
      [APPS]: ["tinycloud.kv/get", "tinycloud.kv/list"],
      [SPACES]: ["tinycloud.kv/get", "tinycloud.kv/list"],
    };
    expect(rowsOf(att)).toEqual([SEE_LISTS]);
    expect(detailsOf(att)).toBe(LISTS_DETAILS);
  });

  it("keeps the capabilities read beside the lists row", () => {
    const att = {
      [APPS]: ["tinycloud.kv/list"],
      [CAPABILITIES]: ["tinycloud.capabilities/read"],
    };
    const rows = rowsOf(att);
    expect(rows).toContain(SEE_LISTS);
    expect(rows).not.toContain(MANAGE);
    expect(detailsOf(att)).toBe(LISTS_DETAILS);
  });

  it("states the Advanced details line word for word", () => {
    expect(LISTS_DETAILS).toBe(
      "Read-only account lists: Reads the list of apps you've installed and the list of your spaces. Nothing can be changed.",
    );
    expect(detailsOf({ [APPS]: ["tinycloud.kv/get"] })).toBe(
      "Read-only account lists: Reads the list of apps you've installed and the list of your spaces. Nothing can be changed.",
    );
  });
});

describe("account grants that can change something keep the manage row", () => {
  it("keeps Manage for an app list with a write verb", () => {
    const att = { [APPS]: ["tinycloud.kv/get", "tinycloud.kv/list", "tinycloud.kv/put"] };
    expect(rowsOf(att)).toEqual([MANAGE]);
    expect(detailsOf(att)).toBeNull();
  });

  it("keeps Manage when the app list is read-only but the space list can be written", () => {
    const att = {
      [APPS]: ["tinycloud.kv/get", "tinycloud.kv/list"],
      [SPACES]: ["tinycloud.kv/get", "tinycloud.kv/list", "tinycloud.kv/put"],
    };
    expect(rowsOf(att)).toEqual([MANAGE]);
    expect(detailsOf(att)).toBeNull();
  });

  it("keeps Manage when read-only lists come with account SQL", () => {
    const att = {
      [APPS]: ["tinycloud.kv/get", "tinycloud.kv/list"],
      [SPACES]: ["tinycloud.kv/get", "tinycloud.kv/list"],
      [ACCOUNT_SQL]: ["tinycloud.sql/read"],
    };
    expect(rowsOf(att)).toEqual([MANAGE]);
    expect(detailsOf(att)).toBeNull();
  });

  it("keeps Manage when read-only lists come with the setup status", () => {
    const att = {
      [APPS]: ["tinycloud.kv/get", "tinycloud.kv/list"],
      [SETUP]: ["tinycloud.kv/get", "tinycloud.kv/put"],
    };
    expect(rowsOf(att)).toEqual([MANAGE]);
    expect(detailsOf(att)).toBeNull();
  });

  it("keeps Manage for the setup status alone", () => {
    expect(rowsOf({ [SETUP]: ["tinycloud.kv/get"] })).toEqual([MANAGE]);
    expect(detailsOf({ [SETUP]: ["tinycloud.kv/get"] })).toBeNull();
  });
});
