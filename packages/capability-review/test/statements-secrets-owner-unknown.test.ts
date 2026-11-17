// A secrets-space request whose owner is not yet known (`ownedBySelf: null`,
// e.g. the pre-sign-in device page) must never claim the space is "your"s.
// `true` and `false` keep their existing wording.

import { describe, expect, it } from "bun:test";
import {
  buildStatements,
  type CapabilityAction,
  type CapabilityGrant,
} from "../src/index.js";

const ACCOUNT = "0x1111111111111111111111111111111111111111";
const SECRETS_SPACE = `tinycloud:pkh:eip155:1:${ACCOUNT}:secrets`;

function makeGrant(
  service: string,
  path: string,
  abilities: string[],
  ownedBySelf: boolean | null,
): CapabilityGrant {
  const actions: CapabilityAction[] = abilities.map((ability) => ({
    id: `${service}-${path}-${ability}`,
    ability,
    verb: ability.slice(ability.indexOf("/") + 1),
    required: false,
    selected: true,
    editable: true,
    caveats: [],
  }));
  return {
    id: `${service}-${SECRETS_SPACE}-${path}`,
    family: "secret-mutation",
    severity: "attention",
    service,
    space: SECRETS_SPACE,
    path,
    owner: ACCOUNT,
    ownedBySelf,
    displayLabel: path || service,
    metadataLabel: null,
    resourceService: null,
    actions,
  };
}

function texts(grant: CapabilityGrant): string[] {
  return buildStatements(grant).map((s) => s.primaryText);
}

const SQL_ALL = ["tinycloud.sql/read", "tinycloud.sql/write", "tinycloud.sql/schema"];
const SHAPES: Array<[string, string, string[]]> = [
  ["sql scoped read+manage", "default", SQL_ALL],
  ["sql scoped read", "default", ["tinycloud.sql/read"]],
  ["sql scoped manage", "default", ["tinycloud.sql/write"]],
  ["sql schema only", "default", ["tinycloud.sql/schema"]],
  ["sql root read+manage", "", SQL_ALL],
  ["sql root read", "", ["tinycloud.sql/read"]],
];

describe("secrets space with unknown owner", () => {
  for (const [name, path, abilities] of SHAPES) {
    it(`${name} never reads "your"`, () => {
      const out = texts(makeGrant("tinycloud.sql", path, abilities, null));
      for (const text of out) expect(text.toLowerCase()).not.toContain("your");
    });
  }

  for (const [name, path, abilities] of [
    ["kv get", "", ["tinycloud.kv/get"]],
    ["kv get+put", "", ["tinycloud.kv/get", "tinycloud.kv/put"]],
    ["kv metadata", "", ["tinycloud.kv/metadata"]],
    ["kv list", "", ["tinycloud.kv/list"]],
  ] as Array<[string, string, string[]]>) {
    it(`${name} never reads "your"`, () => {
      const out = texts(makeGrant("tinycloud.kv", path, abilities, null));
      for (const text of out) expect(text.toLowerCase()).not.toContain("your");
    });
  }

  it("names the catalog neutrally", () => {
    expect(texts(makeGrant("tinycloud.sql", "default", ["tinycloud.sql/read"], null))).toEqual([
      "View the secret catalog",
    ]);
  });

  it("manage and view-and-manage read without an owner", () => {
    expect(texts(makeGrant("tinycloud.sql", "default", ["tinycloud.sql/write"], null))).toEqual([
      "Manage the secret catalog",
    ]);
    expect(
      texts(makeGrant("tinycloud.sql", "default", ["tinycloud.sql/read", "tinycloud.sql/write"], null)),
    ).toEqual(["View and manage the secret catalog"]);
  });

  it("owner true still says your", () => {
    expect(texts(makeGrant("tinycloud.sql", "default", SQL_ALL, true))).toEqual([
      "View and manage your secret catalog",
      "Edit and delete your secret tables",
    ]);
  });

  it("owner false still says another user's", () => {
    expect(texts(makeGrant("tinycloud.sql", "default", SQL_ALL, false))).toEqual([
      "View and manage another user's secret catalog",
      "Edit and delete another user's secret tables",
    ]);
  });
});
