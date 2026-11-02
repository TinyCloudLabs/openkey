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

describe("the Sensitive header matches the Sensitive rows", () => {
  it("counts every row marked Sensitive in the Share sign-in (it said 2 over four marked rows)", () => {
    const rows = rowsOf(modelFor(SHARE_SIGN_IN));
    const marked = rows.filter((row) => row.severity === "sensitive");
    expect(marked.length).toBeGreaterThanOrEqual(4);
    expect(sensitiveSummaryCount(rows)).toBe(marked.length);
  });

  it("is the number of marked rows for any selection, including one row and none", () => {
    const keysOnly = rowsOf(modelFor({ [`${NETWORK}/share/`]: ["tinycloud.encryption/key.create", "tinycloud.encryption/decrypt"] }));
    expect(sensitiveSummaryCount(keysOnly)).toBe(keysOnly.filter((row) => row.severity === "sensitive").length);
    const none = rowsOf(modelFor({ [`${SPACE}/capabilities`]: ["tinycloud.capabilities/read"] }));
    expect(sensitiveSummaryCount(none)).toBe(0);
  });

  it("counts a row once when two grants give it the same sentence", () => {
    const rows = rowsOf(
      modelFor({
        [`${NETWORK}/share/`]: ["tinycloud.encryption/decrypt"],
        [`${NETWORK}/share/x/`]: ["tinycloud.encryption/decrypt"],
      }),
    );
    expect(new Set(rows.map((row) => row.primaryText)).size).toBe(rows.length);
    expect(sensitiveSummaryCount(rows)).toBe(rows.filter((row) => row.severity === "sensitive").length);
  });
});

describe("own-key folder rows show the path in code style, never as raw backquotes", () => {
  it("marks the Create and Decrypt rows so the display splits the path out of the sentence", () => {
    const rows = rowsOf(modelFor(SHARE_SIGN_IN));
    for (const text of ["Create your own encryption keys in `share/`", "Decrypt data locked with your keys in `share/`"]) {
      const row = rows.find((candidate) => candidate.primaryText === text);
      expect(row?.codeSpans).toBe(true);
      const parts = splitStatementCode(text);
      expect(parts.some((part) => part.code && part.text === "share/")).toBe(true);
      expect(parts.filter((part) => !part.code).map((part) => part.text).join("")).not.toContain("`");
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
