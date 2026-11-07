// TC-2242: the Sensitive callout at the top of a consent must count exactly the rows marked Sensitive below it, and
// the own-key folder rows must not show raw backquotes. The Share sign-in is the case that broke both: two
// encryption grants counted as "2 permissions" while four rows carried the Sensitive pill.

import { describe, expect, it } from "bun:test";

import {
  buildSummaryStatements,
  defaultSelection,
  parseCapabilityReview,
  sensitiveRowsCallout,
  sensitiveSummaryCount,
  splitStatementCode,
  type CapabilityReviewModel,
} from "../src/index.js";
import { FIXTURE_META, makeRecapResource, siweWithResources } from "./fixtures/index.js";

const OWNER = `did:pkh:eip155:${FIXTURE_META.chainId}:${FIXTURE_META.address}`;
const NETWORK = `urn:tinycloud:encryption:${OWNER}:default`;
const SPACE = `tinycloud:pkh:eip155:${FIXTURE_META.chainId}:${FIXTURE_META.address}:default`;

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
      displayName: "share.tinycloud.xyz",
      verifiedOrigin: "https://share.tinycloud.xyz",
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

/** What Share asks at sign-in: the encryption network, its own `share/` key folder, and an unrecognized KV path. */
const SHARE_SIGN_IN = {
  [NETWORK]: ["tinycloud.encryption/decrypt", "tinycloud.encryption/network.create"],
  [`${NETWORK}/share/`]: ["tinycloud.encryption/key.create", "tinycloud.encryption/decrypt"],
  [`${SPACE.replace(/:default$/, ":files")}/kv/files-for-you/v1/`]: ["tinycloud.kv/get", "tinycloud.kv/list", "tinycloud.kv/put"],
  [`${SPACE}/capabilities`]: ["tinycloud.capabilities/read"],
};

function rowsOf(model: CapabilityReviewModel) {
  const selection = defaultSelection(model);
  const selected = model.permissions.flatMap((grant) => {
    const actions = grant.actions.filter((action) => selection.has(action.id));
    return actions.length > 0 ? [{ ...grant, actions }] : [];
  });
  return buildSummaryStatements(selected);
}

describe("the Sensitive header counts the Sensitive rows", () => {
  it("counts three Sensitive rows in the Share sign-in", () => {
    const model = modelFor(SHARE_SIGN_IN);
    const rows = rowsOf(model);
    expect(sensitiveSummaryCount(rows)).toBe(3);
  });

  it("is 0 when nothing selected is marked Sensitive", () => {
    expect(sensitiveSummaryCount(rowsOf(modelFor({ [`${SPACE}/capabilities`]: ["tinycloud.capabilities/read"] })))).toBe(0);
  });

  for (const resource of [`${NETWORK}/share/`, `${NETWORK}/qa/`, `${NETWORK}/share/item`]) {
    it(`keeps create unbadged and decrypt Sensitive on ${resource}`, () => {
      const create = rowsOf(modelFor({ [resource]: ["tinycloud.encryption/key.create"] }));
      const decrypt = rowsOf(modelFor({ [resource]: ["tinycloud.encryption/decrypt"] }));
      const combined = rowsOf(modelFor({ [resource]: ["tinycloud.encryption/key.create", "tinycloud.encryption/decrypt"] }));
      expect(create.map(row => row.severity)).toEqual(["attention"]);
      expect(decrypt.map(row => row.severity)).toEqual(["sensitive"]);
      expect(combined.find(row => row.key === create[0]!.key)?.severity).toBe("attention");
      expect(combined.find(row => row.key === decrypt[0]!.key)?.severity).toBe("sensitive");
    });
  }
});

describe("own-key folder rows show the path in code style, never as raw backquotes", () => {
  it("marks a folder's Create and Decrypt rows so the display splits the path out of the sentence", () => {
    const rows = rowsOf(modelFor({ [`${NETWORK}/qa/`]: ["tinycloud.encryption/key.create", "tinycloud.encryption/decrypt"] }));
    for (const text of ["Create your own encryption keys in `qa/`", "Decrypt data locked with your keys in `qa/`"]) {
      const row = rows.find((candidate) => candidate.primaryText === text);
      expect(row?.codeSpans).toBe(true);
      const parts = splitStatementCode(text);
      expect(parts.some((part) => part.code && part.text === "qa/")).toBe(true);
      expect(parts.filter((part) => !part.code).map((part) => part.text).join("")).not.toContain("`");
    }
  });

  it("the share/ folder has two plain action rows without a code-style path", () => {
    const rows = rowsOf(modelFor({ [`${NETWORK}/share/`]: ["tinycloud.encryption/key.create", "tinycloud.encryption/decrypt"] }));
    expect(rows).toHaveLength(2);
    expect(rows[0]!.primaryText).not.toBe(rows[1]!.primaryText);
    for (const row of rows) {
      expect(row.codeSpans).toBe(false);
      expect(row.primaryText).not.toContain("`");
    }
  });
});

describe("the header agrees in number with what it counts", () => {
  it("is singular for exactly one and plural otherwise, and always leads with the count", () => {
    for (let count = 1; count <= 50; count += 1) {
      const text = sensitiveRowsCallout(count);
      expect(text.startsWith(`${count} `)).toBe(true);
      expect(/\bpermissions\b/.test(text)).toBe(count !== 1);
      expect(/\bpermission\b/.test(text)).toBe(count === 1);
    }
  });
});
