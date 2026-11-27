// The words of a sign-in review: the heading names the app, one named secret reads by name in the summary,
// and a secret's label separates its kind from its path with a colon.

import { describe, expect, it } from "bun:test";

import {
  PROTOCOL_HEADLINE,
  annotateAppScopedGrants,
  buildSummaryStatements,
  parseCapabilityReview,
  protocolHeadline,
  type CapabilityGrant,
  type CapabilityReviewModel,
  type DeclaredScopedSecret,
} from "../src/index.js";
import { FIXTURE_META, makeRecapResource, siweWithResources } from "./fixtures/index.js";

const SECRETS = `tinycloud:pkh:eip155:${FIXTURE_META.chainId}:${FIXTURE_META.address}:secrets`;

function reviewOf(att: Record<string, string[]>): CapabilityReviewModel {
  return parseCapabilityReview({
    message: siweWithResources([
      makeRecapResource(
        Object.fromEntries(Object.entries(att).map(([resource, abilities]) => [resource, Object.fromEntries(abilities.map((a) => [a, [{}]]))])),
      ),
    ]),
    signer: { label: "Key", address: FIXTURE_META.address, chainId: FIXTURE_META.chainId, provenance: "managed" },
    editable: true,
    metadataTrust: { status: "origin-bound", reason: "matched manifest" },
    reason: { text: "", source: "none" },
    requester: {
      displayName: "Food Tracker",
      verifiedOrigin: "https://food.example",
      appId: null,
      manifestName: "Food Tracker",
      manifestNameProvenance: "origin-bound",
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

const read = (name: string) => `${SECRETS}/kv/vault/secrets/${name}`;
const declared = (...names: string[]): DeclaredScopedSecret[] =>
  names.map((secretName) => ({ secretName, scope: "food", actions: ["read"] }));

/** The summary rows of a request, as the review shows them once the manifest's declared secrets are applied. */
function rowsOf(att: Record<string, string[]>, secrets: DeclaredScopedSecret[]): string[] {
  const model = annotateAppScopedGrants(reviewOf(att), { secrets });
  return buildSummaryStatements(model.permissions).map((row) => row.primaryText);
}

describe("the heading of a sign-in", () => {
  it("names the app", () => {
    expect(protocolHeadline("tinycloud-siwe-recap", "Food Tracker")).toBe("Sign in to Food Tracker");
  });

  it("keeps the protocol heading when there is no app name to give", () => {
    expect(protocolHeadline("tinycloud-siwe-recap", null)).toBe(PROTOCOL_HEADLINE["tinycloud-siwe-recap"]);
    expect(protocolHeadline("tinycloud-siwe-recap", "")).toBe(PROTOCOL_HEADLINE["tinycloud-siwe-recap"]);
  });

  it("leaves the other protocols' headings as they are", () => {
    for (const protocol of ["legacy-message", "siwe-plain", "malformed-recap"] as const) {
      expect(protocolHeadline(protocol, "Food Tracker")).toBe(PROTOCOL_HEADLINE[protocol]);
    }
  });
});

describe("a read of secrets the manifest declares under another path", () => {
  it("names the secret when exactly one is asked for", () => {
    const rows = rowsOf({ [read("ANTHROPIC_API_KEY")]: ["tinycloud.kv/get"] }, declared("ANTHROPIC_API_KEY"));
    expect(rows).toEqual(["Read the secret ANTHROPIC_API_KEY"]);
  });

  it("keeps the plural row for several secrets", () => {
    const rows = rowsOf(
      { [read("ANTHROPIC_API_KEY")]: ["tinycloud.kv/get"], [read("OPENAI_API_KEY")]: ["tinycloud.kv/get"] },
      declared("ANTHROPIC_API_KEY", "OPENAI_API_KEY"),
    );
    expect(rows).toEqual(["Read secrets"]);
  });

  it("keeps the plural row when the read can also write", () => {
    const rows = rowsOf({ [read("ANTHROPIC_API_KEY")]: ["tinycloud.kv/get", "tinycloud.kv/put"] }, declared("ANTHROPIC_API_KEY"));
    expect(rows).not.toContain("Read the secret ANTHROPIC_API_KEY");
  });

  it("marks the named row Sensitive", () => {
    const model = annotateAppScopedGrants(reviewOf({ [read("ANTHROPIC_API_KEY")]: ["tinycloud.kv/get"] }), { secrets: declared("ANTHROPIC_API_KEY") });
    expect(buildSummaryStatements(model.permissions).map((row) => row.severity)).toEqual(["sensitive"]);
  });

  it("keeps the plural row for a read under another app's scope, which names a scope the row would leave out", () => {
    const scoped = `${SECRETS}/kv/vault/secrets/scoped/evil/AAA`;
    expect(rowsOf({ [scoped]: ["tinycloud.kv/get"] }, declared("AAA"))).toEqual(["Read secrets"]);
  });

  it("keeps the plural row when the unscoped and a scoped path name the same secret", () => {
    const rows = rowsOf(
      { [read("AAA")]: ["tinycloud.kv/get"], [`${SECRETS}/kv/vault/secrets/scoped/evil/AAA`]: ["tinycloud.kv/get"] },
      declared("AAA"),
    );
    expect(rows).toEqual(["Read secrets"]);
  });

  it("keeps the plural row when the same name is read in two secrets spaces", () => {
    const rows = rowsOf(
      { [read("AAA")]: ["tinycloud.kv/get"], [`${SECRETS}:x/kv/vault/secrets/AAA`]: ["tinycloud.kv/get"] },
      declared("AAA"),
    );
    expect(rows).toEqual(["Read secrets"]);
  });
});

describe("the label of a secret grant", () => {
  const labelOf = (grants: CapabilityGrant[]) => grants.map((grant) => grant.displayLabel);

  it("separates the kind from the path with a colon", () => {
    expect(labelOf(reviewOf({ [read("ANTHROPIC_API_KEY")]: ["tinycloud.kv/get"] }).permissions)).toEqual([
      "Secret values (read): vault/secrets/ANTHROPIC_API_KEY",
    ]);
    expect(labelOf(reviewOf({ [read("ANTHROPIC_API_KEY")]: ["tinycloud.kv/get", "tinycloud.kv/put"] }).permissions)).toEqual([
      "Secret values (update): vault/secrets/ANTHROPIC_API_KEY",
    ]);
    expect(labelOf(reviewOf({ [read("ANTHROPIC_API_KEY")]: ["tinycloud.kv/metadata"] }).permissions)).toEqual([
      "Secret names and metadata: vault/secrets/ANTHROPIC_API_KEY",
    ]);
  });
});

describe("the other labels that join a kind and a target", () => {
  const labelsOf = (att: Record<string, string[]>) => reviewOf(att).permissions.map((grant) => grant.displayLabel);
  const OTHER = "0x2222222222222222222222222222222222222222";
  const account = (space: string) => `tinycloud:pkh:eip155:${FIXTURE_META.chainId}:${FIXTURE_META.address}:${space}`;

  it("separates all secrets from the kind with a colon", () => {
    expect(labelsOf({ [`${SECRETS}/kv/`]: ["tinycloud.kv/get", "tinycloud.kv/list"] })).toEqual(["Secret data: all secrets"]);
    expect(labelsOf({ [`${SECRETS}/kv/`]: ["tinycloud.kv/list"] })).toEqual(["Secret names and metadata: all secrets"]);
  });

  it("separates the catalog and a named secret from their target with a colon", () => {
    expect(labelsOf({ [`${SECRETS}/sql/catalog`]: ["tinycloud.sql/write"] })).toEqual(["Secret catalog (manage): catalog"]);
    expect(labelsOf({ [`${SECRETS}/sql/catalog`]: ["tinycloud.sql/read"] })).toEqual(["Secret catalog (view): catalog"]);
    expect(labelsOf({ [`${SECRETS}/secrets/vault/secrets/NAME`]: ["tinycloud.secrets/get"] })).toEqual(["Named secret (read): vault/secrets/NAME"]);
  });

  it("separates a permission check from its space with a colon", () => {
    expect(labelsOf({ [`${account("default")}/capabilities`]: ["tinycloud.capabilities/read"] })).toEqual(["Permission check: default"]);
    expect(labelsOf({ [`${account("account")}/capabilities`]: ["tinycloud.capabilities/read"] })).toEqual(["Permission check: account"]);
  });

  it("names another user's database administration with the owner first", () => {
    const other = `tinycloud:pkh:eip155:${FIXTURE_META.chainId}:${OTHER}:default/sql/app`;
    expect(labelsOf({ [other]: ["tinycloud.sql/admin"] })).toEqual(["Another user's SQL database (manage)"]);
    expect(labelsOf({ [other]: ["tinycloud.sql/*"] })).toEqual(["Another user's SQL database (full access)"]);
  });
});
