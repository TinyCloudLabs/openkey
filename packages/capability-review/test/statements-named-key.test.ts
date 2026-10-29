// Named-key encryption resources (urn:tinycloud:encryption:<owner>:<network>/<path>)
// get one consent sentence per verb and per exact/prefix shape. Malformed paths
// fall back to the literal resource. Delete is never approvable.

import { describe, expect, it } from "bun:test";

import { renderLiteral } from "../src/copy.js";
import {
  buildStatement,
  buildStatements,
  type CapabilityGrant,
} from "../src/index.js";

const OWNER = "did:pkh:eip155:1:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";
const NETWORK = `urn:tinycloud:encryption:${OWNER}:default`;
const KEY = `${NETWORK}/qa/x`;
const PREFIX = `${NETWORK}/qa/`;

const ABILITY = {
  create: "tinycloud.encryption/key.create",
  block: "tinycloud.encryption/key.block",
  unblock: "tinycloud.encryption/key.unblock",
  delete: "tinycloud.encryption/key.delete",
  decrypt: "tinycloud.encryption/decrypt",
} as const;

function namedGrant(space: string, abilities: string[]): CapabilityGrant {
  return {
    id: `tinycloud.encryption\x00${space}\x00`,
    family: "encryption-decrypt",
    severity: "sensitive",
    service: "tinycloud.encryption",
    space,
    path: "",
    owner: null,
    ownedBySelf: true,
    displayLabel: "",
    metadataLabel: null,
    resourceService: null,
    actions: abilities.map((ability) => ({
      id: `tinycloud.encryption\x00${space}\x00\x00${ability}`,
      ability,
      verb: ability.slice(ability.indexOf("/") + 1),
      required: false,
      selected: true,
      editable: true,
      caveats: [{}],
    })),
  };
}

const KEY_SENTENCE = {
  create: "Create your encryption key default/qa/x",
  block: "Block your key default/qa/x from decrypting",
  unblock: "Let your key default/qa/x decrypt again",
  decrypt: "Decrypt data with your key default/qa/x",
  delete: "Refused: only you can delete the key qa/x",
} as const;

const PREFIX_SENTENCE = {
  create: "Create your own encryption keys in `qa/`",
  block: "Block keys in default/qa/ from decrypting",
  unblock: "Let all keys in default/qa/ decrypt again",
  decrypt: "Decrypt data locked with your keys in `qa/`",
  delete: "Refused: only you can delete the key qa/",
} as const;

describe("named-key exact resources: one sentence per verb", () => {
  for (const verb of ["create", "block", "unblock", "decrypt", "delete"] as const) {
    it(`renders ${verb} on an exact key`, () => {
      const grant = namedGrant(KEY, [ABILITY[verb]]);
      expect(buildStatement(grant).primaryText).toBe(KEY_SENTENCE[verb]);
    });
  }
});

describe("named-key prefix resources: one sentence per verb", () => {
  for (const verb of ["create", "block", "unblock", "decrypt", "delete"] as const) {
    it(`renders ${verb} on a prefix`, () => {
      const grant = namedGrant(PREFIX, [ABILITY[verb]]);
      expect(buildStatement(grant).primaryText).toBe(PREFIX_SENTENCE[verb]);
    });
  }
});

describe("named-key delete is never approvable", () => {
  it("marks exact-key delete rows as never approvable", () => {
    expect(buildStatement(namedGrant(KEY, [ABILITY.delete])).neverApprovable).toBe(
      true,
    );
  });

  it("marks prefix delete rows as never approvable", () => {
    expect(
      buildStatement(namedGrant(PREFIX, [ABILITY.delete])).neverApprovable,
    ).toBe(true);
  });

  it("leaves other named-key verbs approvable", () => {
    for (const verb of ["create", "block", "unblock", "decrypt"] as const) {
      expect(buildStatement(namedGrant(KEY, [ABILITY[verb]])).neverApprovable).not.toBe(
        true,
      );
      expect(
        buildStatement(namedGrant(PREFIX, [ABILITY[verb]])).neverApprovable,
      ).not.toBe(true);
    }
  });
});

describe("named-key mixed verbs split into one row per action", () => {
  it("renders each action as its own sentence in grant order", () => {
    const grant = namedGrant(KEY, [ABILITY.create, ABILITY.decrypt, ABILITY.block]);
    expect(buildStatements(grant).map((row) => row.primaryText)).toEqual([
      KEY_SENTENCE.create,
      KEY_SENTENCE.decrypt,
      KEY_SENTENCE.block,
    ]);
  });

  it("keeps a prefix distinct from the same name as an exact key", () => {
    const exact = namedGrant(`${NETWORK}/qa`, [ABILITY.decrypt]);
    const prefix = namedGrant(`${NETWORK}/qa/`, [ABILITY.decrypt]);
    expect(buildStatement(exact).primaryText).not.toBe(
      buildStatement(prefix).primaryText,
    );
    expect(buildStatement(prefix).primaryText).toBe(PREFIX_SENTENCE.decrypt);
  });
});

describe("malformed named-key resources fall back to generic rows", () => {
  const malformed = [
    `${NETWORK}/apps//x`,
    `${NETWORK}/Apps/x`,
    `${NETWORK}/apps/../x`,
    `${NETWORK}/apps/a b`,
    `${NETWORK}/apps/x//`,
  ];

  for (const space of malformed) {
    it(`uses the generic fallback for ${space}`, () => {
      const grant = namedGrant(space, [ABILITY.decrypt, ABILITY.delete]);
      const rows = buildStatements(grant);
      expect(rows.map((row) => row.primaryText)).toEqual([
        "Unknown action: tinycloud.encryption/decrypt",
        `Refused: only you can delete the key ${space}`,
      ]);
      expect(rows[0]?.neverApprovable).not.toBe(true);
      expect(rows[1]?.neverApprovable).toBe(true);
    });
  }
});

function shapeGrant(
  shape: "A" | "B",
  resource: string,
  abilities: string[],
): CapabilityGrant {
  // Shape A: the URN is the whole `space`. Shape B: `space` is the raw
  // "encryption" service name and the URN sits in `path`.
  return shape === "A"
    ? namedGrant(resource, abilities)
    : { ...namedGrant("encryption", abilities), path: resource };
}

describe("named-key routing: shape A and shape B resolve identically", () => {
  for (const shape of ["A", "B"] as const) {
    it(`shape ${shape} exact key routes to the key sentence and keeps the URN`, () => {
      const row = buildStatement(shapeGrant(shape, KEY, [ABILITY.decrypt]));
      expect(row.primaryText).toBe(KEY_SENTENCE.decrypt);
      expect(row.resource).toBe(KEY);
    });

    it(`shape ${shape} prefix routes to the prefix sentence and keeps the URN`, () => {
      const row = buildStatement(shapeGrant(shape, PREFIX, [ABILITY.decrypt]));
      expect(row.primaryText).toBe(PREFIX_SENTENCE.decrypt);
      expect(row.resource).toBe(PREFIX);
    });

    it(`shape ${shape} bare network keeps the plain decrypt copy`, () => {
      expect(
        buildStatement(shapeGrant(shape, NETWORK, [ABILITY.decrypt])).primaryText,
      ).toBe("Decrypt protected data");
    });

    it(`shape ${shape} malformed URN renders the literal fallback, not friendly copy`, () => {
      expect(
        buildStatement(shapeGrant(shape, `${NETWORK}/apps//x`, [ABILITY.decrypt]))
          .primaryText,
      ).toBe("Unknown action: tinycloud.encryption/decrypt");
    });
  }
});

describe("key.delete fails closed on every encryption resource shape", () => {
  const cases = [
    ["exact key", KEY],
    ["prefix", PREFIX],
    ["malformed", `${NETWORK}/apps//x`],
  ] as const;
  for (const shape of ["A", "B"] as const) {
    for (const [label, resource] of cases) {
      it(`shape ${shape} ${label} delete is never approvable and refused`, () => {
        const row = buildStatement(shapeGrant(shape, resource, [ABILITY.delete]));
        expect(row.neverApprovable).toBe(true);
        expect(row.primaryText).toContain("Refused: ");
      });
    }
  }

  it("a delete on a non-URN resource is still never approvable and refused", () => {
    const row = buildStatement(namedGrant("default", [ABILITY.delete]));
    expect(row.neverApprovable).toBe(true);
    expect(row.primaryText).toContain("Refused: ");
  });

  for (const shape of ["A", "B"] as const) {
    it(`shape ${shape} mixed decrypt and delete: only the delete row is never approvable`, () => {
      const rows = buildStatements(
        shapeGrant(shape, KEY, [ABILITY.decrypt, ABILITY.delete]),
      );
      expect(rows.map((row) => row.primaryText)).toEqual([
        KEY_SENTENCE.decrypt,
        KEY_SENTENCE.delete,
      ]);
      expect(rows[0]?.neverApprovable).not.toBe(true);
      expect(rows[1]?.neverApprovable).toBe(true);
    });
  }
});

describe("literal resource text in refusals is escaped and capped", () => {
  it("escapes a bidi override in a malformed key.delete refusal", () => {
    const resource = `${NETWORK}/apps/\u202ex`;
    const row = buildStatement(namedGrant(resource, [ABILITY.delete]));
    expect(row.primaryText).toBe(
      `Refused: only you can delete the key ${NETWORK}/apps/\\u202ex`,
    );
    expect(row.primaryText).not.toContain("\u202e");
    expect(row.resource).toBe(`${NETWORK}/apps/\\u202ex`);
    expect(row.neverApprovable).toBe(true);
  });

  it("escapes a bidi override inside the network of a delete refusal", () => {
    const row = buildStatement(
      namedGrant(`urn:tinycloud:encryption:${OWNER}:def\u202eault/apps/x`, [
        ABILITY.delete,
      ]),
    );
    expect(row.primaryText).toContain("def\\u202eault/apps/x");
    expect(row.primaryText).not.toContain("\u202e");
  });

  it("escapes a zero-width character in a malformed key.delete refusal", () => {
    const row = buildStatement(
      namedGrant(`${NETWORK}/apps/a\u200bx//`, [ABILITY.delete]),
    );
    expect(row.primaryText).toContain("apps/a\\u200bx//");
    expect(row.primaryText).not.toContain("\u200b");
  });

  it("escapes a newline in a malformed key.delete refusal", () => {
    const row = buildStatement(
      namedGrant(`${NETWORK}/apps/a\nx//`, [ABILITY.delete]),
    );
    expect(row.primaryText).toContain("apps/a\\u000ax//");
    expect(row.primaryText).not.toContain("\n");
  });

  it("truncates a 300-character malformed resource to 120 characters and an ellipsis", () => {
    const resource = `${NETWORK}/${"x".repeat(300)}//`;
    const row = buildStatement(namedGrant(resource, [ABILITY.delete]));
    expect(row.primaryText).toBe(
      `Refused: only you can delete the key ${resource.slice(0, 120)}…`,
    );
    expect(row.resource).toBe(`${resource.slice(0, 120)}…`);
  });

  it("leaves a valid key.delete sentence byte-for-byte unchanged", () => {
    expect(buildStatement(namedGrant(KEY, [ABILITY.delete])).primaryText).toBe(
      KEY_SENTENCE.delete,
    );
  });

  it("escapes a literal backslash so escape-looking text stays visible", () => {
    const row = buildStatement(
      namedGrant(`${NETWORK}/apps/\\u202ex//`, [ABILITY.delete]),
    );
    expect(row.primaryText).toContain("apps/\\u005Cu202ex//");
    expect(row.primaryText).not.toContain("\\u202e");
  });
});

it("escapes markup and controls while capping raw consent text", () => {
  const text = `<script>${"\u202e"}\n${"x".repeat(300)}`;
  const abbreviated = renderLiteral(text, 120);
  expect(abbreviated).toStartWith("\\u003cscript\\u003e\\u202e\\u000a");
  expect(abbreviated.length).toBe(121);
  expect(abbreviated.endsWith("…")).toBe(true);
  expect(abbreviated).not.toContain("<script>");
  expect(renderLiteral(text)).toContain(`${"x".repeat(300)}`);
});

describe("failing encryption URNs: every displayed string is printable ASCII", () => {
  const SEG31 = "a".repeat(31);
  const PATH_256 = [...Array.from({ length: 7 }, () => SEG31), "a".repeat(32)].join(
    "/",
  );
  const keyUrn = (rest: string): string =>
    `urn:tinycloud:encryption:${OWNER}:default/${rest}`;
  // TEST-VECTORS.md v0.4 REJECT vectors 7-21: each must fail the strict parse.
  const rejects: Array<[string, string]> = [
    ["7", keyUrn("apps/x//")],
    ["8", keyUrn("apps//x")],
    ["9", `urn:tinycloud:encryption:${OWNER}:default//apps`],
    ["10", keyUrn("Apps/x")],
    ["11", keyUrn("apps/../x")],
    ["12", keyUrn("apps/./x")],
    ["13", keyUrn("apps/a%2Fb")],
    ["14", keyUrn("apps/a:b")],
    ["15", keyUrn("apps/a b")],
    ["16", keyUrn("apps/caf\u00e9")],
    ["17", keyUrn("a/a/a/a/a/a/a/a/a")],
    ["18", keyUrn("a".repeat(65))],
    ["19", keyUrn(PATH_256)],
    ["20", keyUrn(".hidden")],
    ["21", keyUrn("-x")],
  ];
  // The only non-printable-ASCII character a displayed string may hold is the
  // fixed truncation mark `…`, at most one per capped piece in that string.
  function expectDisplayable(text: string, maxMarks: number): void {
    expect(text.split("…").length - 1).toBeLessThanOrEqual(maxMarks);
    expect(text.replace(/…/g, "")).toMatch(/^[\x20-\x7e]*$/);
  }
  const abilities = [
    ABILITY.decrypt,
    ABILITY.create,
    ABILITY.delete,
    "tinycloud.encryption/unknown",
  ];
  for (const [vector, uri] of rejects) {
    for (const shape of ["A", "B"] as const) {
      for (const ability of abilities) {
        it(`vector ${vector}, shape ${shape}, ${ability}: no displayed string holds raw text`, () => {
          const rows = buildStatements(shapeGrant(shape, uri, [ability]));
          expect(rows.length).toBeGreaterThan(0);
          for (const row of rows) {
            expectDisplayable(row.primaryText, 3);
            expectDisplayable(row.service, 3);
            expectDisplayable(row.resource, 3);
          }
        });
      }
    }
  }

  it("caps a 300-character unknown ability once, with one ellipsis", () => {
    const ability = `tinycloud.encryption/${"u".repeat(300)}`;
    const rows = buildStatements(
      shapeGrant("A", keyUrn("apps/x//"), [ability]),
    );
    expect(rows.length).toBeGreaterThan(0);
    for (const row of rows) {
      expectDisplayable(row.primaryText, 1);
    }
    expect(rows[0].primaryText.startsWith(`Unknown action: ${ability.slice(0, 120)}…`)).toBe(
      true,
    );
    expect(rows[0].primaryText).not.toContain("u".repeat(121));
  });

  it("caps a 300-character service once, with one ellipsis, on fallback and key.delete rows", () => {
    for (const ability of [ABILITY.decrypt, ABILITY.delete]) {
      const grant = { ...shapeGrant("A", keyUrn("apps/x//"), [ability]), service: "x".repeat(300) };
      const rows = buildStatements(grant);
      expect(rows.length).toBeGreaterThan(0);
      for (const row of rows) {
        expectDisplayable(row.primaryText, 1);
        expectDisplayable(row.service, 1);
        expect(row.service).toBe(`${"x".repeat(120)}…`);
      }
    }
  });

  // Combined case: a 300-char unknown ability and a 300-char service in one
  // failing-URN row. Bound = fixed text (baseline row with short pieces) plus
  // one 120-char cap and one `…` per capped piece.
  for (const shape of ["A", "B"] as const) {
    it(`shape ${shape}: 300-char unknown ability and service stay bounded`, () => {
      const longAbility = `tinycloud.encryption/${"u".repeat(300)}`;
      const shortAbility = "tinycloud.encryption/a";
      const grant = {
        ...shapeGrant(shape, keyUrn("apps/x//"), [longAbility]),
        service: "x".repeat(300),
      };
      const base = {
        ...shapeGrant(shape, keyUrn("apps/x//"), [shortAbility]),
        service: "s",
      };
      const rows = buildStatements(grant);
      const baseRows = buildStatements(base);
      expect(rows.length).toBeGreaterThan(0);
      expect(rows.length).toBe(baseRows.length);
      rows.forEach((row, i) => {
        expectDisplayable(row.primaryText, 2);
        const fixed =
          baseRows[i].primaryText.length - shortAbility.length - "s".length;
        expect(row.primaryText.length).toBeLessThanOrEqual(
          fixed + 2 * (120 + 1),
        );
      });
    });

    it(`shape ${shape}: key.delete with 300-char service stays bounded`, () => {
      const grant = {
        ...shapeGrant(shape, keyUrn("apps/x//"), [ABILITY.delete]),
        service: "x".repeat(300),
      };
      const base = {
        ...shapeGrant(shape, keyUrn("apps/x//"), [ABILITY.delete]),
        service: "s",
      };
      const rows = buildStatements(grant);
      const baseRows = buildStatements(base);
      expect(rows.length).toBeGreaterThan(0);
      expect(rows.length).toBe(baseRows.length);
      rows.forEach((row, i) => {
        expectDisplayable(row.primaryText, 2);
        expectDisplayable(row.service, 1);
        const fixed = baseRows[i].primaryText.length - "s".length;
        expect(row.primaryText.length).toBeLessThanOrEqual(
          fixed + 2 * (120 + 1),
        );
      });
    });
  }
});
