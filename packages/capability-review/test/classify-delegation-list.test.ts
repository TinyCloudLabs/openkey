// Reading which apps and links can reach the signer's own data: `tinycloud.delegation` with
// `list` (and `status`) on the signer's own `applications` space is a plain read-only grant.
// The `account` space has the same label. Every other space and verb combination keeps the
// classification it had.

import { describe, expect, it } from "bun:test";

import {
  classifyRecapEntry,
  classifySeverityFromActions,
} from "../src/index.js";

const SIGNER = "0x1111111111111111111111111111111111111111";
const OTHER = "0x2222222222222222222222222222222222222222";
const space = (name: string, owner = SIGNER) => `tinycloud:pkh:eip155:1:${owner}:${name}`;

const LABEL = "Who can access your data";

function classify(options: {
  space: string;
  actions: string[];
  service?: string;
  signerAddress?: string | null;
  serviceMismatch?: boolean;
}) {
  return classifyRecapEntry({
    service: options.service ?? "tinycloud.delegation",
    space: options.space,
    path: "",
    actions: options.actions,
    ...(options.signerAddress === null ? {} : { signerAddress: options.signerAddress ?? SIGNER }),
    ...(options.serviceMismatch ? { serviceMismatch: true } : {}),
  });
}

describe("delegation reads on the signer's own applications space", () => {
  it("labels `list` as a plain read-only grant, with standard severity", () => {
    const result = classify({ space: space("applications"), actions: ["tinycloud.delegation/list"] });
    expect(result).toEqual({ family: "bootstrap-delegation", displayLabel: LABEL });
    expect(classifySeverityFromActions(result.family, ["tinycloud.delegation/list"])).toBe("standard");
  });

  it("labels `list` and `status` the same, and `status` alone too", () => {
    const expected = { family: "bootstrap-delegation", displayLabel: LABEL };
    expect(classify({
      space: space("applications"),
      actions: ["tinycloud.delegation/list", "tinycloud.delegation/status"],
    })).toEqual(expected);
    expect(classify({ space: space("applications"), actions: ["tinycloud.delegation/status"] })).toEqual(expected);
  });

  it("accepts the short service name and a signer address in another letter case", () => {
    const expected = { family: "bootstrap-delegation", displayLabel: LABEL };
    expect(classify({ space: space("applications"), service: "delegation", actions: ["delegation/list"] })).toEqual(expected);
    expect(classify({
      space: space("applications"),
      actions: ["tinycloud.delegation/list"],
      signerAddress: SIGNER.replace("0x", "0X").toUpperCase().replace("0X", "0x"),
    })).toEqual(expected);
  });

  it.each([
    ["revoke", ["tinycloud.delegation/revoke"]],
    ["create", ["tinycloud.delegation/create"]],
    ["delegate", ["tinycloud.delegation/delegate"]],
    ["a wildcard", ["tinycloud.delegation/*"]],
    ["list with revoke", ["tinycloud.delegation/list", "tinycloud.delegation/revoke"]],
    ["status with an unknown verb", ["tinycloud.delegation/status", "tinycloud.delegation/export"]],
  ])("does not take %s: it stays unrecognized", (_name, actions) => {
    const result = classify({ space: space("applications"), actions });
    expect(result).toEqual({ family: "unknown", displayLabel: "Unrecognized tinycloud.delegation permission" });
    expect(classifySeverityFromActions(result.family, actions)).not.toBe("standard");
  });

  it("is not taken by a grant whose service does not match its resource", () => {
    const result = classify({
      space: space("applications"),
      actions: ["tinycloud.delegation/list"],
      serviceMismatch: true,
    });
    expect(result.family).toBe("unknown");
  });
});

describe("delegation reads elsewhere keep their classification", () => {
  it.each(["default", "vault", "courier", "public", "catalog", "secrets"])(
    "`list` on the signer's own %s space is an unrecognized delegation target",
    (name) => {
      expect(classify({ space: space(name), actions: ["tinycloud.delegation/list"] })).toEqual({
        family: "unknown",
        displayLabel: "Unrecognized delegation target",
      });
    },
  );

  it("`list` on another user's applications space is not the new label: it is unrecognized, as before", () => {
    const result = classify({ space: space("applications", OTHER), actions: ["tinycloud.delegation/list"] });
    expect(result).toEqual({ family: "unknown", displayLabel: "Unrecognized delegation target" });
    expect(classifySeverityFromActions(result.family, ["tinycloud.delegation/list"])).toBe("attention");
  });

  it("an owner or signer that cannot be read is not proof of the signer's own space", () => {
    const actions = ["tinycloud.delegation/list"];
    const unrecognized = { family: "unknown", displayLabel: "Unrecognized delegation target" };
    expect(classify({ space: space("applications"), actions, signerAddress: null })).toEqual(unrecognized);
    expect(classify({ space: "applications", actions })).toEqual(unrecognized);
    expect(classify({ space: "tinycloud:pkh:eip155:1:not-an-address:applications", actions })).toEqual(unrecognized);
  });

  it("the account space has the same label, and another user's account space keeps its own", () => {
    for (const actions of [["tinycloud.delegation/list"], ["tinycloud.delegation/list", "tinycloud.delegation/status"]]) {
      expect(classify({ space: space("account"), actions })).toEqual({
        family: "bootstrap-delegation",
        displayLabel: LABEL,
      });
      expect(classify({ space: space("account", OTHER), actions })).toEqual({
        family: "cross-app-data",
        displayLabel: "Another user's connected access",
      });
    }
    expect(classify({ space: space("account"), actions: ["tinycloud.delegation/revoke"] })).toEqual({
      family: "unknown",
      displayLabel: "Unrecognized tinycloud.delegation permission",
    });
  });
});
