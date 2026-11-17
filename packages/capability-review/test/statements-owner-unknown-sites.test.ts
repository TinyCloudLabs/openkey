// Non-secret statements that name an owner ("your ...") must not claim it when
// the owner is not yet known (`ownedBySelf: null`). `true` keeps its wording
// exactly. Every case runs null and true; the old wording is pinned for true.

import { describe, expect, it } from "bun:test";
import {
  buildStatements,
  type CapabilityAction,
  type CapabilityGrant,
} from "../src/index.js";

const ACCOUNT = "0x1111111111111111111111111111111111111111";
const space = (name: string) => `tinycloud:pkh:eip155:1:${ACCOUNT}:${name}`;

function makeGrant(
  family: CapabilityGrant["family"],
  service: string,
  spaceName: string,
  path: string,
  verbs: string[],
  ownedBySelf: boolean | null,
): CapabilityGrant {
  const actions: CapabilityAction[] = verbs.map((verb) => ({
    id: `${service}-${spaceName}-${path}-${verb}`,
    ability: `${service}/${verb}`,
    verb,
    required: false,
    selected: true,
    editable: true,
    caveats: [],
  }));
  return {
    id: `${service}-${spaceName}-${path}`,
    family,
    severity: "attention",
    service,
    space: space(spaceName),
    path,
    owner: ACCOUNT,
    ownedBySelf,
    displayLabel: path || service,
    metadataLabel: null,
    resourceService: null,
    actions,
  };
}

// [name, family, service, space, path, verbs, text when true, text when null]
const SITES: Array<[string, CapabilityGrant["family"], string, string, string, string[], string[], string[]]> = [
  ["account bootstrap", "bootstrap-kv", "tinycloud.kv", "account", "", ["get", "put"],
    ["Manage your TinyCloud account"], ["Manage the requested TinyCloud account"]],
  ["account bootstrap sql schema", "bootstrap-sql", "tinycloud.sql", "account", "", ["read", "schema"],
    ["Manage your TinyCloud account", "Edit and delete tables in your TinyCloud account"],
    ["Manage the requested TinyCloud account", "Edit and delete tables in the requested account"]],
  ["public read and publish", "public-data", "tinycloud.kv", "public", "", ["get", "put"],
    ["Read and publish your public data"], ["Read and publish the requested public data"]],
  ["public publish", "public-data", "tinycloud.kv", "public", "", ["put"],
    ["Publish and update your public data"], ["Publish and update the requested public data"]],
  ["public read", "public-data", "tinycloud.kv", "public", "", ["get"],
    ["Read your public data"], ["Read the requested public data"]],
  ["default read and update", "bootstrap-kv", "tinycloud.kv", "default", "notes/", ["get", "put"],
    ["Read and update your TinyCloud data"], ["Read and update data in the requested account"]],
  ["default update", "bootstrap-kv", "tinycloud.kv", "default", "notes/", ["put"],
    ["Update your TinyCloud data"], ["Update data in the requested account"]],
  ["default read", "bootstrap-kv", "tinycloud.kv", "default", "notes/", ["get"],
    ["Read your TinyCloud data"], ["Read data in the requested account"]],
  ["delegation list", "bootstrap-capabilities", "tinycloud.delegation", "notes", "apps/x/", ["list"],
    ["See who has access to your data"], ["See who has access to the requested data"]],
];

describe("an unknown owner never reads as \"your\"", () => {
  for (const [name, family, service, spaceName, path, verbs, whenTrue, whenNull] of SITES) {
    it(`${name}: null is neutral`, () => {
      const out = buildStatements(makeGrant(family, service, spaceName, path, verbs, null)).map((s) => s.primaryText);
      expect(out).toEqual(whenNull);
      for (const text of out) expect(text.toLowerCase()).not.toMatch(/\byour\b/);
    });
    it(`${name}: true keeps its wording`, () => {
      expect(buildStatements(makeGrant(family, service, spaceName, path, verbs, true)).map((s) => s.primaryText)).toEqual(whenTrue);
    });
  }

  it("another user's account, public and default data keep their wording", () => {
    const read = (family: CapabilityGrant["family"], spaceName: string, verbs: string[]) =>
      buildStatements(makeGrant(family, "tinycloud.kv", spaceName, "", verbs, false)).map((s) => s.primaryText);
    expect(read("bootstrap-kv", "account", ["get", "put"])).toEqual(["Read and update another user's account data"]);
    expect(read("public-data", "public", ["get"])).toEqual(["Read another user's public data"]);
    expect(read("bootstrap-kv", "default", ["put"])).toEqual(["Update another user's TinyCloud data"]);
  });
});
