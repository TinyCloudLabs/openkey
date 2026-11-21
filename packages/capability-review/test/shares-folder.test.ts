// A share-by-email tool asks for the `shares/` folder of the signer's own `default` space with
// `get`, `metadata`, `put` and `del`. The `del` reaches every share in the folder, including
// shares another app made, so the row says that. Any other shape keeps the generic row.

import { describe, expect, it } from "bun:test";

import {
  buildStatement,
  parseCapabilityReview,
  SHARES_FOLDER_STATEMENT,
  type CapabilityGrant,
  type SignerInfo,
} from "../src/index.js";
import type { ParseContext } from "../src/parse.js";
import { FIXTURE_META, makeRecapResource, siweWithResources } from "./fixtures/index.js";

const SIGNER = FIXTURE_META.address;
const OTHER = "0x2222222222222222222222222222222222222222";
const EXACT = ["get", "metadata", "put", "del"];
const space = (name: string, owner: string = SIGNER) =>
  `tinycloud:pkh:eip155:${FIXTURE_META.chainId}:${owner}:${name}`;

const signer: SignerInfo = {
  label: "Test signer",
  address: SIGNER,
  chainId: FIXTURE_META.chainId,
  provenance: "managed",
};

/** The grant the review builds for one KV resource, through the real parser. */
function review(resource: string, verbs: string[]): CapabilityGrant {
  const ctx: ParseContext = {
    message: siweWithResources([
      makeRecapResource({
        [resource]: Object.fromEntries(verbs.map((verb) => [`tinycloud.kv/${verb}`, [{}]])),
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

describe("the shares folder grant", () => {
  it("says it can delete any of the owner's shares, and stays a standard row", () => {
    const grant = review(`${space("default")}/kv/shares/`, EXACT);
    expect(buildStatement(grant).primaryText).toBe("Create shares and delete any of your shares");
    expect(buildStatement(grant).primaryText).toBe(SHARES_FOLDER_STATEMENT);
    expect(grant.severity).toBe("standard");
  });

  it.each([
    ["another user's space", `${space("default", OTHER)}/kv/shares/`, EXACT],
    ["the applications space", `${space("applications")}/kv/shares/`, EXACT],
    ["a folder inside shares/", `${space("default")}/kv/shares/abc/`, EXACT],
    ["a sibling folder", `${space("default")}/kv/shares-old/`, EXACT],
    ["list added", `${space("default")}/kv/shares/`, [...EXACT, "list"]],
    ["no delete", `${space("default")}/kv/shares/`, ["get", "metadata", "put"]],
    ["no read", `${space("default")}/kv/shares/`, ["metadata", "put", "del"]],
  ])("keeps the generic row for %s", (_name, resource, verbs) => {
    expect(buildStatement(review(resource, verbs)).primaryText).not.toBe(SHARES_FOLDER_STATEMENT);
  });
});
