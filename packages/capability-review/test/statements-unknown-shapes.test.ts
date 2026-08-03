// Blocker 3: fail-closed classification for unknown action shapes.
//
// The contract requires:
//   - Unknown services or shapes fall back to the literal service,
//     resource, and actions and must NOT receive invented friendly
//     semantics.
//   - classify.ts must not silently downgrade unknown capabilities or
//     secrets grants into a "standard" bucket. Unknown capability verbs
//     escape into the `unknown` family; unknown secret verbs escape
//     into `secret-mutation` (sensitive).
//
// These tests pin the behavior on both surfaces so a future refactor
// cannot re-introduce the friendly-copy-for-anything shortcut.

import { describe, expect, it } from "bun:test";

import {
  buildStatement,
  classifyRecapEntry,
  classifySeverityFromActions,
  type CapabilityAction,
  type CapabilityGrant,
} from "../src/index.js";

const ACCOUNT = "0x1111111111111111111111111111111111111111";
const SPACE = `tinycloud:pkh:eip155:1:${ACCOUNT}:default`;

function makeGrant(input: {
  service: string;
  space?: string;
  path?: string;
  abilities: string[];
  family: CapabilityGrant["family"];
  severity: CapabilityGrant["severity"];
}): CapabilityGrant {
  const space = input.space ?? SPACE;
  const path = input.path ?? "";
  const actions: CapabilityAction[] = input.abilities.map((ability) => ({
    id: `${input.service}\u0000${space}\u0000${path}\u0000${ability}`,
    ability,
    verb: ability.slice(ability.indexOf("/") + 1),
    required: false,
    selected: true,
    editable: true,
    caveats: [],
  }));
  return {
    id: `${input.service}\u0000${space}\u0000${path}`,
    family: input.family,
    severity: input.severity,
    service: input.service,
    space,
    path,
    owner: ACCOUNT,
    ownedBySelf: true,
    displayLabel: path || input.service,
    metadataLabel: null,
    resourceService: null,
    actions,
  };
}

describe("buildStatement — capabilities service unknown verbs", () => {
  it("falls back to literal copy when a capabilities grant carries an unknown verb", () => {
    const grant = makeGrant({
      service: "tinycloud.capabilities",
      abilities: ["tinycloud.capabilities/admin"],
      family: "bootstrap-capabilities",
      severity: "standard",
    });
    const statement = buildStatement(grant);
    expect(statement.primaryText).toBe(
      "Perform tinycloud.capabilities/admin on tinycloud.capabilities",
    );
    expect(statement.service).toBe("tinycloud.capabilities");
  });

  it("falls back when a mixed capabilities grant contains any unknown verb", () => {
    const grant = makeGrant({
      service: "tinycloud.capabilities",
      abilities: [
        "tinycloud.capabilities/read",
        "tinycloud.capabilities/mutate",
      ],
      family: "bootstrap-capabilities",
      severity: "standard",
    });
    const statement = buildStatement(grant);
    expect(statement.primaryText).toContain("Perform");
    expect(statement.primaryText).toContain("tinycloud.capabilities/mutate");
  });

  it("keeps the friendly permissions-check copy for a pure read grant", () => {
    const grant = makeGrant({
      service: "tinycloud.capabilities",
      abilities: ["tinycloud.capabilities/read"],
      family: "bootstrap-capabilities",
      severity: "standard",
    });
    expect(buildStatement(grant).primaryText).toBe(
      "Check your TinyCloud account permissions",
    );
  });
});

describe("buildStatement — secrets service unknown verbs", () => {
  it("falls back to literal copy when a secrets grant carries an unknown verb", () => {
    const grant = makeGrant({
      service: "tinycloud.secrets",
      abilities: ["tinycloud.secrets/rotate"],
      family: "secret-mutation",
      severity: "sensitive",
    });
    const statement = buildStatement(grant);
    expect(statement.primaryText).toBe(
      "Perform tinycloud.secrets/rotate on tinycloud.secrets",
    );
  });

  it("does not invent a vault-read statement when no shape matched", () => {
    // A read-shaped verb that does not fit any of the enumerated
    // secret shapes (capabilities-read, list/metadata, mutation) still
    // qualifies as recognized — the contract carves out the vault-read
    // sentence only for genuine vault reads. `peek` is a recognized
    // read verb but no shape above matches, so the fallback applies.
    const grant = makeGrant({
      service: "tinycloud.secrets",
      abilities: ["tinycloud.secrets/peek"],
      family: "secret-read",
      severity: "attention",
    });
    // With the recognized-verb path, "peek" is a read verb, so the
    // capabilities-shape branch matches and yields the permissions
    // check copy. This test simply pins that we never fall into the
    // previous "View secrets stored in your vault" default for an
    // unrelated read verb.
    const primary = buildStatement(grant).primaryText;
    expect(primary).not.toBe("View secrets stored in your vault");
  });
});

describe("classifyRecapEntry — unknown capabilities verbs", () => {
  it("returns the unknown family for a capabilities grant with an unknown verb", () => {
    const result = classifyRecapEntry({
      service: "tinycloud.capabilities",
      space: SPACE,
      path: "",
      actions: ["tinycloud.capabilities/admin"],
    });
    expect(result.family).toBe("unknown");
  });

  it("classifies unknown capabilities as sensitive when the verb is a mutation", () => {
    const classification = classifyRecapEntry({
      service: "tinycloud.capabilities",
      space: SPACE,
      path: "",
      actions: ["tinycloud.capabilities/grant"],
    });
    const severity = classifySeverityFromActions(
      classification.family,
      ["tinycloud.capabilities/grant"],
    );
    expect(classification.family).toBe("unknown");
    expect(severity).toBe("sensitive");
  });

  it("still classifies a pure read capabilities grant as bootstrap-capabilities", () => {
    const result = classifyRecapEntry({
      service: "tinycloud.capabilities",
      space: SPACE,
      path: "",
      actions: ["tinycloud.capabilities/read"],
    });
    expect(result.family).toBe("bootstrap-capabilities");
  });
});

describe("classifyRecapEntry — unknown secrets verbs", () => {
  it("classifies an unknown secrets verb as secret-mutation (sensitive)", () => {
    const classification = classifyRecapEntry({
      service: "tinycloud.secrets",
      space: SPACE,
      path: "SOME_SECRET",
      actions: ["tinycloud.secrets/rotate"],
    });
    expect(classification.family).toBe("secret-mutation");
    expect(
      classifySeverityFromActions(classification.family, [
        "tinycloud.secrets/rotate",
      ]),
    ).toBe("sensitive");
  });

  it("classifies a pure list/metadata secrets grant as a sensitive namespace listing", () => {
    const classification = classifyRecapEntry({
      service: "tinycloud.secrets",
      space: SPACE,
      path: "",
      actions: ["tinycloud.secrets/list", "tinycloud.secrets/metadata"],
    });
    expect(classification.family).toBe("secret-namespace-list");
    expect(
      classifySeverityFromActions(classification.family, [
        "tinycloud.secrets/list",
        "tinycloud.secrets/metadata",
      ]),
    ).toBe("sensitive");
  });
});
