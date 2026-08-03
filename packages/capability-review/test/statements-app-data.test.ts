import { describe, expect, it } from "bun:test";
import {
  buildStatement,
  type CapabilityAction,
  type CapabilityGrant,
} from "../src/index.js";

function grant(
  family: CapabilityGrant["family"],
  abilities: string[],
  appScopedSecret?: CapabilityGrant["appScopedSecret"],
): CapabilityGrant {
  const actions: CapabilityAction[] = abilities.map((ability) => ({
    id: ability,
    ability,
    verb: ability.slice(ability.indexOf("/") + 1),
    required: false,
    selected: true,
    editable: true,
    caveats: [],
  }));
  return {
    id: `${family}-grant`,
    family,
    severity: appScopedSecret ? "standard" : "attention",
    service: "tinycloud.kv",
    space:
      "tinycloud:pkh:eip155:1:0x1111111111111111111111111111111111111111:applications",
    path: "cycle/",
    owner: "0x1111111111111111111111111111111111111111",
    ownedBySelf: family === "own-app-data",
    displayLabel: "App data — cycle/",
    metadataLabel: null,
    ...(appScopedSecret ? { appScopedSecret } : {}),
    actions,
  };
}

describe("buildStatement — generic app data", () => {
  it("describes read-only app data without inferring path semantics", () => {
    expect(
      buildStatement(grant("own-app-data", ["tinycloud.kv/get"])).primaryText,
    ).toBe("Read this app's data");
  });

  it("describes read/write data outside the app without a product name", () => {
    expect(
      buildStatement(
        grant("cross-app-data", ["tinycloud.kv/get", "tinycloud.kv/put"]),
      ).primaryText,
    ).toBe("Read and update data outside this app");
  });

  it("uses the exactly proven app-scoped secret name", () => {
    // buildStatement defense-in-depth requires exact service/space/path tuple.
    const scopedGrant: CapabilityGrant = {
      ...grant("secret-read", ["tinycloud.kv/get"], {
        secretName: "GOOGLE_MEET_TOKENS",
        scope: "listen",
      }),
      service: "tinycloud.kv",
      space: "tinycloud:pkh:eip155:1:0x1111111111111111111111111111111111111111:secrets",
      path: "vault/secrets/scoped/listen/GOOGLE_MEET_TOKENS",
    };
    expect(buildStatement(scopedGrant).primaryText).toBe(
      "Read the app secret GOOGLE_MEET_TOKENS",
    );
  });

  it("falls back for an unknown app-data verb", () => {
    expect(
      buildStatement(grant("own-app-data", ["tinycloud.kv/archive"]))
        .primaryText,
    ).toBe("Perform tinycloud.kv/archive on tinycloud.kv");
  });
});
