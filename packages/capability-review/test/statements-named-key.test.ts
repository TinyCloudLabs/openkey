// Named-key encryption resources (urn:tinycloud:encryption:<owner>:<network>/<path>)
// get one consent sentence per verb and per exact/prefix shape. Malformed paths
// fall back to the literal resource. Delete is never approvable.

import { describe, expect, it } from "bun:test";

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
      const texts = buildStatements(grant).map((row) => row.primaryText);
      expect(texts).toEqual([
        "Perform tinycloud.encryption/decrypt on tinycloud.encryption",
        "Perform tinycloud.encryption/key.delete on tinycloud.encryption",
      ]);
    });
  }
});
