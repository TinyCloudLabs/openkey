// Named-key encryption resources (urn:tinycloud:encryption:<owner>:<network>/<path>)
// get one consent sentence per verb and per exact/prefix shape. Malformed paths
// fall back to the literal resource. Delete is never approvable.

import { describe, expect, it } from "bun:test";

import { DECRYPT_DEFAULT_KEY_STATEMENT } from "../src/copy.js";
import {
  buildStatement,
  buildStatements,
  type CapabilityGrant,
} from "../src/index.js";

const OWNER = "did:pkh:eip155:1:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";
const NETWORK = `urn:tinycloud:encryption:${OWNER}:default`;
const KEY = `${NETWORK}/apps/tinychat/x`;
const PREFIX = `${NETWORK}/apps/tinychat/`;

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
  create: "Create the encryption key apps/tinychat/x in your account's default network.",
  block:
    "Block the key apps/tinychat/x in your account's default network, so it can no longer decrypt. You can unblock it later.",
  unblock:
    "Unblock the key apps/tinychat/x in your account's default network, so it can decrypt again.",
  decrypt:
    "Decrypt anything encrypted with your key apps/tinychat/x in your account's default network, whenever this app gets hold of the encrypted copy, until this access expires.",
  delete:
    "Delete the key apps/tinychat/x: only you can do this, with your wallet, as a separate step. This request is refused.",
} as const;

const PREFIX_SENTENCE = {
  create:
    "Create encryption keys under apps/tinychat/ in your account's default network.",
  block:
    "Block every key under apps/tinychat/ in your account's default network, so none of them can decrypt. You can unblock them later.",
  unblock:
    "Unblock every key under apps/tinychat/ in your account's default network, so they can decrypt again.",
  decrypt:
    "Decrypt anything encrypted with any of your keys under apps/tinychat/ in your account's default network, whenever this app gets hold of the encrypted copy, until this access expires.",
  delete:
    "Delete the key apps/tinychat/: only you can do this, with your wallet, as a separate step. This request is refused.",
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
    const exact = namedGrant(`${NETWORK}/apps/tinychat`, [ABILITY.decrypt]);
    const prefix = namedGrant(`${NETWORK}/apps/tinychat/`, [ABILITY.decrypt]);
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
        "Perform tinycloud.encryption/decrypt on tinycloud.encryption",
        `Delete the key ${space}: only you can do this, with your wallet, as a separate step. This request is refused.`,
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

    it(`shape ${shape} bare network keeps the default-key decrypt copy`, () => {
      expect(
        buildStatement(shapeGrant(shape, NETWORK, [ABILITY.decrypt])).primaryText,
      ).toBe(DECRYPT_DEFAULT_KEY_STATEMENT);
    });

    it(`shape ${shape} malformed URN renders the literal fallback, not friendly copy`, () => {
      expect(
        buildStatement(shapeGrant(shape, `${NETWORK}/apps//x`, [ABILITY.decrypt]))
          .primaryText,
      ).toBe("Perform tinycloud.encryption/decrypt on tinycloud.encryption");
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
        expect(row.primaryText).toContain("This request is refused.");
      });
    }
  }

  it("a delete on a non-URN resource is still never approvable and refused", () => {
    const row = buildStatement(namedGrant("default", [ABILITY.delete]));
    expect(row.neverApprovable).toBe(true);
    expect(row.primaryText).toContain("This request is refused.");
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
      `Delete the key ${NETWORK}/apps/\\u202ex: only you can do this, with your wallet, as a separate step. This request is refused.`,
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
      `Delete the key ${resource.slice(0, 120)}…: only you can do this, with your wallet, as a separate step. This request is refused.`,
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
  // The only non-ASCII character a displayed string may hold is the single
  // truncation mark `…`, where a literal was capped.
  function expectPrintableAscii(text: string): void {
    expect(text.split("…").length - 1).toBeLessThanOrEqual(1);
    expect(text.replace("…", "")).toMatch(/^[\x20-\x7e]*$/);
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
            expectPrintableAscii(row.primaryText);
            expectPrintableAscii(row.service);
            expectPrintableAscii(row.resource);
          }
        });
      }
    }
  }
});
