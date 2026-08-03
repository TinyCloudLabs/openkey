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
  ownedBySelf?: boolean;
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
    ownedBySelf: input.ownedBySelf ?? true,
    displayLabel: path || input.service,
    metadataLabel: null,
    resourceService: null,
    actions,
  };
}

describe("buildStatement — unknown structural shapes", () => {
  it("keeps an unknown cross-user KV target literal", () => {
    const statement = buildStatement(
      makeGrant({
        service: "tinycloud.kv",
        space: `tinycloud:pkh:eip155:1:${ACCOUNT}:custom`,
        path: "locations/",
        abilities: ["tinycloud.kv/get"],
        family: "unknown",
        severity: "attention",
        ownedBySelf: false,
      }),
    );
    expect(statement.primaryText).toBe(
      "Perform tinycloud.kv/get on tinycloud.kv",
    );
  });

  it("keeps an unknown delegation target literal", () => {
    const statement = buildStatement(
      makeGrant({
        service: "tinycloud.delegation",
        space: `tinycloud:pkh:eip155:1:${ACCOUNT}:custom`,
        abilities: ["tinycloud.delegation/list"],
        family: "unknown",
        severity: "attention",
      }),
    );
    expect(statement.primaryText).toBe(
      "Perform tinycloud.delegation/list on tinycloud.delegation",
    );
  });

  it("does not infer secret semantics from a variables-looking path", () => {
    const statement = buildStatement(
      makeGrant({
        service: "tinycloud.kv",
        space: `tinycloud:pkh:eip155:1:${ACCOUNT}:custom`,
        path: "variables/",
        abilities: ["tinycloud.kv/get"],
        family: "unknown",
        severity: "attention",
      }),
    );
    expect(statement.primaryText).toBe(
      "Perform tinycloud.kv/get on tinycloud.kv",
    );
  });
});

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
      "Check your TinyCloud permissions",
    );
  });
});

describe("buildStatement — secrets service unknown verbs", () => {
  it("keeps the legacy named-secrets read service literal", () => {
    const grant = makeGrant({
      service: "tinycloud.secrets",
      abilities: ["tinycloud.secrets/read"],
      family: "secret-read",
      severity: "sensitive",
    });
    expect(buildStatement(grant).primaryText).toBe(
      "Perform tinycloud.secrets/read on tinycloud.secrets",
    );
  });

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
    // `peek` is not a manifest-defined secrets action, so it stays literal
    // and must never inherit reassuring vault-read copy.
    const grant = makeGrant({
      service: "tinycloud.secrets",
      abilities: ["tinycloud.secrets/peek"],
      family: "secret-read",
      severity: "sensitive",
    });
    const primary = buildStatement(grant).primaryText;
    expect(primary).toBe(
      "Perform tinycloud.secrets/peek on tinycloud.secrets",
    );
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
    const severity = classifySeverityFromActions(classification.family, [
      "tinycloud.capabilities/grant",
    ]);
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

  it("elevates a capabilities read on another user's space", () => {
    const result = classifyRecapEntry({
      service: "tinycloud.capabilities",
      space: SPACE,
      path: "",
      actions: ["tinycloud.capabilities/read"],
      signerAddress: "0x2222222222222222222222222222222222222222",
    });
    expect(result.family).toBe("cross-app-data");
    expect(
      classifySeverityFromActions(result.family, [
        "tinycloud.capabilities/read",
      ]),
    ).toBe("attention");
  });

  it("maps the stable permissions-check meaning on a custom space", () => {
    const result = classifyRecapEntry({
      service: "tinycloud.capabilities",
      space: `tinycloud:pkh:eip155:1:${ACCOUNT}:custom`,
      path: "",
      actions: ["tinycloud.capabilities/read"],
      signerAddress: ACCOUNT,
    });
    expect(result.family).toBe("bootstrap-capabilities");
  });
});

describe("classifyRecapEntry — unknown data targets", () => {
  for (const [service, action] of [
    ["tinycloud.kv", "tinycloud.kv/get"],
    ["tinycloud.sql", "tinycloud.sql/read"],
  ] as const) {
    it(`fails closed for ${service} on an unrecognized space`, () => {
      const result = classifyRecapEntry({
        service,
        space: `tinycloud:pkh:eip155:1:${ACCOUNT}:custom`,
        path: "",
        actions: [action],
        signerAddress: ACCOUNT,
      });
      expect(result.family).toBe("unknown");
      expect(classifySeverityFromActions(result.family, [action])).toBe(
        "attention",
      );
    });
  }

  it("fails closed for a scoped path in an unrecognized custom space", () => {
    const result = classifyRecapEntry({
      service: "tinycloud.kv",
      space: `tinycloud:pkh:eip155:1:${ACCOUNT}:health-records`,
      path: "locations/",
      actions: ["tinycloud.kv/get"],
      signerAddress: ACCOUNT,
    });
    expect(result.family).toBe("unknown");
  });

  it("does not make a custom target friendly just because it belongs to another user", () => {
    const result = classifyRecapEntry({
      service: "tinycloud.kv",
      space:
        "tinycloud:pkh:eip155:1:0x2222222222222222222222222222222222222222:health-records",
      path: "locations/",
      actions: ["tinycloud.kv/get"],
      signerAddress: ACCOUNT,
    });
    expect(result.family).toBe("unknown");
    expect(
      classifySeverityFromActions(result.family, ["tinycloud.kv/get"]),
    ).toBe("attention");
  });

  it("validates account actions before overlaying another-user ownership", () => {
    const action = "tinycloud.kv/del";
    const result = classifyRecapEntry({
      service: "tinycloud.kv",
      space:
        "tinycloud:pkh:eip155:1:0x2222222222222222222222222222222222222222:account",
      path: "applications/",
      actions: [action],
      signerAddress: ACCOUNT,
    });
    expect(result.family).toBe("unknown");
    expect(classifySeverityFromActions(result.family, [action])).toBe(
      "sensitive",
    );
  });

  it("keeps a canonical account read recognizable for another user", () => {
    const result = classifyRecapEntry({
      service: "tinycloud.kv",
      space:
        "tinycloud:pkh:eip155:1:0x2222222222222222222222222222222222222222:account",
      path: "applications/",
      actions: ["tinycloud.kv/get"],
      signerAddress: ACCOUNT,
    });
    expect(result.family).toBe("cross-app-data");
  });

  it("rejects schema authority on a whole application SQL space", () => {
    const action = "tinycloud.sql/schema";
    const result = classifyRecapEntry({
      service: "tinycloud.sql",
      space: `tinycloud:pkh:eip155:1:${ACCOUNT}:applications`,
      path: "",
      actions: [action],
      signerAddress: ACCOUNT,
    });
    expect(result.family).toBe("unknown");
    expect(classifySeverityFromActions(result.family, [action])).toBe(
      "attention",
    );
  });

  it("allows schema authority on a named application database", () => {
    const result = classifyRecapEntry({
      service: "tinycloud.sql",
      space: `tinycloud:pkh:eip155:1:${ACCOUNT}:applications`,
      path: "default",
      actions: ["tinycloud.sql/read", "tinycloud.sql/schema"],
      signerAddress: ACCOUNT,
    });
    expect(result.family).toBe("own-app-data");
  });

  for (const entry of [
    {
      service: "tinycloud.kv",
      space: `tinycloud:pkh:eip155:1:${ACCOUNT}:account`,
      path: "applications/",
      action: "tinycloud.kv/del",
      target: "account app registry",
    },
    {
      service: "tinycloud.sql",
      space: `tinycloud:pkh:eip155:1:${ACCOUNT}:account`,
      path: "account",
      action: "tinycloud.sql/admin",
      target: "account index",
    },
    {
      service: "tinycloud.sql",
      space: `tinycloud:pkh:eip155:1:${ACCOUNT}:applications`,
      path: "",
      action: "tinycloud.sql/admin",
      target: "application data",
    },
  ] as const) {
    it(`rejects excess authority on ${entry.target}: ${entry.action}`, () => {
      const result = classifyRecapEntry({
        service: entry.service,
        space: entry.space,
        path: entry.path,
        actions: [entry.action],
        signerAddress: ACCOUNT,
      });
      expect(result.family).toBe("unknown");
      expect(
        classifySeverityFromActions(result.family, [entry.action]),
      ).toBe("sensitive");
    });
  }
});

describe("classifyRecapEntry — malformed wire tuples", () => {
  for (const [service, action] of [
    ["tinycloud.capabilities", "tinycloud.capabilities/read"],
    ["tinycloud.delegation", "tinycloud.delegation/list"],
  ] as const) {
    it(`elevates a service-mismatched ${service} grant`, () => {
      const result = classifyRecapEntry({
        service,
        space: SPACE,
        path: "",
        actions: [action],
        signerAddress: ACCOUNT,
        serviceMismatch: true,
      });
      expect(result.family).toBe("unknown");
      expect(classifySeverityFromActions(result.family, [action])).toBe(
        "attention",
      );
    });
  }
});

describe("classifyRecapEntry — encryption severity", () => {
  it("keeps unknown encryption authority sensitive", () => {
    const actions = ["tinycloud.encryption/export-key"];
    const result = classifyRecapEntry({
      service: "tinycloud.encryption",
      space: SPACE,
      path: "",
      actions,
      signerAddress: ACCOUNT,
    });
    expect(result.displayLabel).toBe("Unrecognized encryption permission");
    expect(classifySeverityFromActions(result.family, actions)).toBe(
      "sensitive",
    );
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
    expect(classification.family).toBe("secret-read");
    expect(
      classifySeverityFromActions(classification.family, [
        "tinycloud.secrets/list",
        "tinycloud.secrets/metadata",
      ]),
    ).toBe("sensitive");
    expect(classification.displayLabel).toContain("Secret names and metadata");
  });
});
