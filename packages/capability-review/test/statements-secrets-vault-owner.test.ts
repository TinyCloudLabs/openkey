// Secret catalog and vault sentences: an unknown owner (`ownedBySelf: null`)
// and another user (`false`) never read "your"; `true` keeps its wording.
// None of the unknown-owner sentences says "requested".

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

type Row = [string, CapabilityGrant["family"], string, string, string, string[], string, string, string];
// [name, family, service, space, path, verbs, null text, true text, false text]
// For another user's vault path an earlier branch already gives the generic
// "another user's account data" sentence, so the vault branch's own
// "another user's vault" text is not reached; it never says "your" either way.
const ROWS: Row[] = [
  ["secret names and details", "secret-namespace-list", "tinycloud.kv", "secrets", "", ["metadata"],
    "View secret names and details", "View your secret names and details", "View another user's secret names and details"],
  ["entire secret catalog (view)", "secret-namespace-list", "tinycloud.sql", "secrets", "", ["read"],
    "View the entire secret catalog", "View your entire secret catalog", "View another user's entire secret catalog"],
  ["all secret values", "secret-namespace-list", "tinycloud.kv", "secrets", "", ["get"],
    "Read all secret values in the vault", "Read all secret values in your vault", "Read all secret values in another user's vault"],
  ["manage all secrets", "secret-mutation", "tinycloud.kv", "secrets", "", ["get", "put"],
    "Manage all secrets in the vault", "Manage all secrets stored in your vault", "Manage all secrets stored in another user's vault"],
  ["entire secret catalog (manage)", "secret-mutation", "tinycloud.sql", "secrets", "", ["read", "write"],
    "Manage the entire secret catalog", "Manage your entire secret catalog", "Manage another user's entire secret catalog"],
  ["vault manage", "secret-mutation", "tinycloud.kv", "account", "vault/secrets", ["get", "put"],
    "Manage secrets in the vault", "Manage secrets stored in your vault", "Read and update another user's account data"],
  ["vault view", "secret-read", "tinycloud.kv", "account", "vault/secrets", ["get"],
    "View secrets in the vault", "View secrets stored in your vault", "Read another user's account data"],
];

const texts = (grant: CapabilityGrant) => buildStatements(grant).map((s) => s.primaryText);

describe("secret catalog and vault sentences by owner", () => {
  for (const [name, family, service, spaceName, path, verbs, whenNull, whenTrue, whenFalse] of ROWS) {
    it(`${name}: unknown owner has no possessive and no "requested"`, () => {
      const out = texts(makeGrant(family, service, spaceName, path, verbs, null));
      expect(out).toEqual([whenNull]);
      expect(out[0]!.toLowerCase()).not.toMatch(/\b(your|requested)\b/);
    });
    it(`${name}: owner true keeps its wording`, () => {
      expect(texts(makeGrant(family, service, spaceName, path, verbs, true))).toEqual([whenTrue]);
    });
    it(`${name}: another user's wording never says "your"`, () => {
      const out = texts(makeGrant(family, service, spaceName, path, verbs, false));
      expect(out).toEqual([whenFalse]);
      expect(out[0]!.toLowerCase()).not.toMatch(/\byour\b/);
    });
  }
});
