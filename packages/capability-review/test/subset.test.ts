// Tests for `assertBaselineSubset` and the shared `canonicalMultisetEqual`
// helper. Sol's MINOR contract item required the JSON.stringify (ordered)
// caveat comparison to be replaced with canonical multiset equality so
// two structurally identical caveat sets do not fail subset validation
// simply because their surface encoding orders keys differently.

import { describe, it, expect } from "bun:test";
import type { CapabilityReviewModel } from "../src/model.js";
import {
  assertBaselineSubset,
  canonicalMultisetEqual,
} from "../src/subset.js";

/**
 * Build a minimal `tinycloud-siwe-recap` model with a single permission
 * carrying one editable action and whatever caveats the caller supplies.
 * We intentionally build the model by hand so the test does not depend on
 * the parser (which is exercised elsewhere).
 */
function modelWithCaveats(caveats: unknown[]): CapabilityReviewModel {
  const space = "tinycloud:pkh:eip155:1:0x1111111111111111111111111111111111111111:default";
  return {
    version: 1,
    protocol: "tinycloud-siwe-recap",
    rawMessage: "raw",
    requester: {
      displayName: "app.example",
      origin: "https://app.example",
      verifiedOrigin: "https://app.example",
    } as any,
    reason: { text: "", provenance: "none" } as any,
    signer: {
      label: "K",
      address: "0x1111111111111111111111111111111111111111",
    } as any,
    expiry: null,
    immutable: null,
    metadataTrust: { status: "unsigned" } as any,
    permissions: [
      {
        id: `tinycloud.kv\0${space}\0`,
        family: "kv-storage" as any,
        severity: "standard" as any,
        service: "tinycloud.kv",
        space,
        path: "",
        owner: "0x1111111111111111111111111111111111111111",
        ownedBySelf: true,
        displayLabel: null,
        metadataLabel: null,
        actions: [
          {
            id: `tinycloud.kv\0${space}\0\0tinycloud.kv/get`,
            ability: "tinycloud.kv/get",
            verb: "get" as any,
            required: false,
            selected: true,
            editable: true,
            caveats,
          },
        ],
      } as any,
    ],
    parseWarnings: [],
  } as CapabilityReviewModel;
}

describe("canonicalMultisetEqual", () => {
  it("treats empty arrays as equal", () => {
    expect(canonicalMultisetEqual([], [])).toBe(true);
  });

  it("treats caveats with different key ordering as equal", () => {
    // The SAME logical caveat serialized with different key ordering must
    // compare equal — this is the exact regression Sol MINOR called out.
    const a = [{ resource: "bucket/abc", scope: "read" }];
    const b = [{ scope: "read", resource: "bucket/abc" }];
    expect(canonicalMultisetEqual(a, b)).toBe(true);
  });

  it("treats caveats in different sequence positions as equal", () => {
    // Two multisets with the same elements in different positions must
    // compare equal.
    const a = [{ scope: "read" }, { scope: "write" }];
    const b = [{ scope: "write" }, { scope: "read" }];
    expect(canonicalMultisetEqual(a, b)).toBe(true);
  });

  it("treats caveats with different duplicate counts as unequal", () => {
    const a = [{ scope: "read" }, { scope: "read" }];
    const b = [{ scope: "read" }];
    expect(canonicalMultisetEqual(a, b)).toBe(false);
  });

  it("treats caveats with entirely different content as unequal", () => {
    const a = [{ scope: "read" }];
    const b = [{ scope: "write" }];
    expect(canonicalMultisetEqual(a, b)).toBe(false);
  });

  it("recurses into nested objects for key-order-insensitive comparison", () => {
    const a = [{ meta: { policy: "p", version: 2 } }];
    const b = [{ meta: { version: 2, policy: "p" } }];
    expect(canonicalMultisetEqual(a, b)).toBe(true);
  });

  it("keeps array element order significant inside a caveat value", () => {
    // The multiset semantic applies to the OUTER caveat collection only.
    // A caveat itself may encode an ordered sequence — that sequence
    // difference is preserved.
    const a = [{ steps: ["a", "b"] }];
    const b = [{ steps: ["b", "a"] }];
    expect(canonicalMultisetEqual(a, b)).toBe(false);
  });
});

describe("assertBaselineSubset caveat semantics (Sol MINOR)", () => {
  it("accepts a candidate whose caveats differ only in key ordering", () => {
    const baseline = modelWithCaveats([
      { resource: "bucket/abc", scope: "read" },
    ]);
    const candidate = modelWithCaveats([
      { scope: "read", resource: "bucket/abc" },
    ]);
    const result = assertBaselineSubset(baseline, candidate);
    expect(result.ok).toBe(true);
    expect(result.violations).toEqual([]);
  });

  it("rejects a candidate that drops a caveat", () => {
    const baseline = modelWithCaveats([{ scope: "read" }]);
    const candidate = modelWithCaveats([]);
    const result = assertBaselineSubset(baseline, candidate);
    expect(result.ok).toBe(false);
    expect(result.violations.some((v) => v.code === "broadened-caveat")).toBe(true);
  });

  it("rejects a candidate that changes a duplicate count", () => {
    const baseline = modelWithCaveats([
      { scope: "read" },
      { scope: "read" },
    ]);
    const candidate = modelWithCaveats([{ scope: "read" }]);
    const result = assertBaselineSubset(baseline, candidate);
    expect(result.ok).toBe(false);
    expect(result.violations.some((v) => v.code === "broadened-caveat")).toBe(true);
  });

  it("rejects a candidate that swaps a caveat for a broader one", () => {
    const baseline = modelWithCaveats([{ scope: "read" }]);
    const candidate = modelWithCaveats([{ scope: "write" }]);
    const result = assertBaselineSubset(baseline, candidate);
    expect(result.ok).toBe(false);
    expect(result.violations.some((v) => v.code === "broadened-caveat")).toBe(true);
  });
});
