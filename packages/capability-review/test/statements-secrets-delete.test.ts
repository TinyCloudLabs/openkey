// A secrets-space KV grant names a delete: a delete never reads as an update, and an update never hides a delete.

import { describe, expect, it } from "bun:test";
import {
  buildStatements,
  type CapabilityAction,
  type CapabilityGrant,
} from "../src/index.js";

const ACCOUNT = "0x1111111111111111111111111111111111111111";
const SECRETS_SPACE = `tinycloud:pkh:eip155:1:${ACCOUNT}:secrets`;

function secretsKvGrant(abilities: string[], ownedBySelf: boolean | null = true): CapabilityGrant {
  const actions: CapabilityAction[] = abilities.map((ability) => ({
    id: `kv-${ability}`,
    ability,
    verb: ability.slice(ability.indexOf("/") + 1),
    required: false,
    selected: true,
    editable: true,
    caveats: [],
  }));
  return {
    id: `kv-${SECRETS_SPACE}-vault/secrets`,
    family: "secret-mutation",
    severity: "attention",
    service: "tinycloud.kv",
    space: SECRETS_SPACE,
    path: "vault/secrets",
    owner: ACCOUNT,
    ownedBySelf,
    displayLabel: "vault/secrets",
    metadataLabel: null,
    resourceService: null,
    actions,
  };
}

function texts(abilities: string[], ownedBySelf: boolean | null = true): string[] {
  return buildStatements(secretsKvGrant(abilities, ownedBySelf)).map((s) => s.primaryText);
}

describe("secrets KV statements with a delete", () => {
  it.each([
    ["delete only", ["tinycloud.kv/del"], "Delete secret values"],
    ["read and delete", ["tinycloud.kv/get", "tinycloud.kv/del"], "Read and delete secret values"],
    ["update and delete", ["tinycloud.kv/put", "tinycloud.kv/del"], "Update and delete secret values"],
    [
      "read, update and delete",
      ["tinycloud.kv/get", "tinycloud.kv/put", "tinycloud.kv/del", "tinycloud.kv/list"],
      "Read, update and delete secret values",
    ],
  ])("%s", (_label, abilities, expected) => {
    expect(texts(abilities)).toEqual([expected]);
  });

  it("keeps another user's secret values in each delete sentence", () => {
    expect(texts(["tinycloud.kv/del"], false)).toEqual(["Delete another user's secret values"]);
    expect(texts(["tinycloud.kv/get", "tinycloud.kv/del"], false)).toEqual([
      "Read and delete another user's secret values",
    ]);
    expect(texts(["tinycloud.kv/put", "tinycloud.kv/del"], false)).toEqual([
      "Update and delete another user's secret values",
    ]);
    expect(texts(["tinycloud.kv/get", "tinycloud.kv/put", "tinycloud.kv/del"], false)).toEqual([
      "Read, update and delete another user's secret values",
    ]);
  });

  it("does not claim the space is the person's own when the owner is unknown", () => {
    expect(texts(["tinycloud.kv/del"], null)).toEqual(["Delete secret values"]);
  });

  it("leaves a grant with no delete on its update sentences", () => {
    expect(texts(["tinycloud.kv/put"])).toEqual(["Update secret values"]);
    expect(texts(["tinycloud.kv/get", "tinycloud.kv/put"])).toEqual(["Read and update secret values"]);
  });

  it("names a wildcard or an unrecognised ability beside a delete instead of a delete sentence", () => {
    expect(texts(["tinycloud.kv/*"]).join(" ")).toContain("nknown action: tinycloud.kv/*");
    for (const other of ["tinycloud.kv/admin", "tinycloud.kv/grant", "tinycloud.kv/revoke"]) {
      expect(texts(["tinycloud.kv/del", other]).join(" ")).toContain(`nknown action: ${other}`);
    }
  });
});
