// Raw `tinycloud.encryption/decrypt` on the account's `:default` network is
// the only encryption shape that gets the default-key consent statement.
// Named networks and sub-paths keep the neutral "Decrypt protected data".

import { describe, expect, it } from "bun:test";

import { DECRYPT_DEFAULT_KEY_STATEMENT } from "../src/copy.js";
import { buildStatement, buildStatements } from "../src/index.js";
import type { CapabilityGrant } from "../src/index.js";
import { FIXTURE_META } from "./fixtures/index.js";

const ADDRESS = FIXTURE_META.address;
const DEFAULT_NETWORK = `urn:tinycloud:encryption:did:pkh:eip155:${FIXTURE_META.chainId}:${ADDRESS}:default`;
const TEAM_NETWORK = `urn:tinycloud:encryption:did:pkh:eip155:${FIXTURE_META.chainId}:${ADDRESS}:team-2`;
const APP_SPACE = `tinycloud:pkh:eip155:${FIXTURE_META.chainId}:${ADDRESS}:default`;

function encryptionGrant(space: string, path: string): CapabilityGrant {
  const ability = "tinycloud.encryption/decrypt";
  return {
    id: `tinycloud.encryption\x00${space}\x00${path}`,
    family: "encryption-decrypt",
    severity: "sensitive",
    service: "tinycloud.encryption",
    space,
    path,
    owner: null,
    ownedBySelf: true,
    displayLabel: "",
    metadataLabel: null,
    resourceService: null,
    actions: [
      {
        id: `tinycloud.encryption\x00${space}\x00${path}\x00${ability}`,
        ability,
        verb: "decrypt",
        required: false,
        selected: true,
        editable: true,
        caveats: [{}],
      },
    ],
  };
}

function appDataGrant(abilities: string[]): CapabilityGrant {
  return {
    id: `tinycloud.sql\x00${APP_SPACE}\x00`,
    family: "own-app-data",
    severity: "attention",
    service: "tinycloud.sql",
    space: APP_SPACE,
    path: "",
    owner: null,
    ownedBySelf: true,
    displayLabel: "",
    metadataLabel: null,
    resourceService: null,
    actions: abilities.map((ability) => ({
      id: `tinycloud.sql\x00${APP_SPACE}\x00\x00${ability}`,
      ability,
      verb: ability.slice(ability.indexOf("/") + 1),
      required: false,
      selected: true,
      editable: true,
      caveats: [{}],
    })),
  };
}

describe("buildStatement — raw decrypt on the account default network", () => {
  it("selects the default-key statement for the :default URN network", () => {
    expect(buildStatement(encryptionGrant(DEFAULT_NETWORK, "")).primaryText).toBe(
      DECRYPT_DEFAULT_KEY_STATEMENT,
    );
  });

  it("keeps 'Decrypt protected data' for a named URN network", () => {
    expect(buildStatement(encryptionGrant(TEAM_NETWORK, "")).primaryText).toBe(
      "Decrypt protected data",
    );
  });

  it("keeps 'Decrypt protected data' when the default network carries a sub-path", () => {
    expect(
      buildStatement(encryptionGrant(DEFAULT_NETWORK, "shares/abc")).primaryText,
    ).toBe("Decrypt protected data");
  });
});

describe("buildStatements — default-key decrypt alongside SQL schema access", () => {
  it("renders the SQL rows and the default-key row as separate rows", () => {
    const rows = [
      ...buildStatements(
        appDataGrant([
          "tinycloud.sql/read",
          "tinycloud.sql/write",
          "tinycloud.sql/schema",
        ]),
      ),
      ...buildStatements(encryptionGrant(DEFAULT_NETWORK, "")),
    ].map((row) => row.primaryText);
    expect(rows).toEqual([
      "Read and update application data",
      "Create, change and delete tables in application data",
      DECRYPT_DEFAULT_KEY_STATEMENT,
    ]);
  });
});
