// A KV grant on a secrets vault path (`vault/secrets/...`) outside the secrets
// space is described by buildStatement's "3b. Vault secret reads" branch. Its
// sentence names whose vault it is only when the owner is known: "your" for the
// signer's own vault, and "the requested" when the owner is not known. It used
// to say "your vault" when the owner was not known.

import { describe, expect, it } from "bun:test";

import {
  buildStatement,
  type CapabilityAction,
  type CapabilityGrant,
} from "../src/index.js";

const ACCOUNT = "0x1111111111111111111111111111111111111111";
const ACCOUNT_SPACE = `tinycloud:pkh:eip155:1:${ACCOUNT}:account`;

function vaultGrant(
  abilities: string[],
  ownedBySelf: boolean | null,
): CapabilityGrant {
  const path = "vault/secrets/api-token";
  const actions: CapabilityAction[] = abilities.map((ability) => ({
    id: `tinycloud.kv-${path}-${ability}`,
    ability,
    verb: ability.slice(ability.indexOf("/") + 1),
    required: false,
    selected: true,
    editable: true,
    caveats: [],
  }));
  return {
    id: `tinycloud.kv-${ACCOUNT_SPACE}-${path}`,
    family: "secret-read",
    severity: "sensitive",
    service: "tinycloud.kv",
    space: ACCOUNT_SPACE,
    path,
    owner: ACCOUNT,
    ownedBySelf,
    displayLabel: path,
    metadataLabel: null,
    resourceService: null,
    actions,
  };
}

const READ = ["tinycloud.kv/get", "tinycloud.kv/list", "tinycloud.kv/metadata"];
const WRITE = ["tinycloud.kv/get", "tinycloud.kv/put", "tinycloud.kv/del"];

describe("vault secret statements name the owner only when it is known", () => {
  const cases: Array<[boolean | null, string, string]> = [
    [true, "View secrets stored in your vault", "Manage secrets stored in your vault"],
    [
      null,
      "View secrets stored in the requested vault",
      "Manage secrets stored in the requested vault",
    ],
  ];
  for (const [owner, read, write] of cases) {
    it(`owner ${String(owner)}: read says "${read}"`, () => {
      expect(buildStatement(vaultGrant(READ, owner)).primaryText).toBe(read);
    });
    it(`owner ${String(owner)}: write says "${write}"`, () => {
      expect(buildStatement(vaultGrant(WRITE, owner)).primaryText).toBe(write);
    });
  }

  // Another user's vault is described by an earlier branch (it never reaches the
  // vault sentence); it must not claim "your".
  it("another user's vault never says \"your vault\"", () => {
    for (const abilities of [READ, WRITE]) {
      expect(buildStatement(vaultGrant(abilities, false)).primaryText).not.toContain("your");
    }
  });
});
