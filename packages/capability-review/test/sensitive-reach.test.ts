import { describe, expect, it } from "bun:test";

import {
  grantReachesSecretDataOrDecryption,
  type CapabilityGrant,
} from "../src/index.js";

const ACCOUNT = "0x1111111111111111111111111111111111111111";

function grant(input: {
  service: string;
  space: string;
  path: string;
  ability: string;
  family: CapabilityGrant["family"];
  severity: CapabilityGrant["severity"];
  appScopedSecret?: CapabilityGrant["appScopedSecret"];
}): CapabilityGrant {
  return {
    id: `${input.service}\u0000${input.space}\u0000${input.path}`,
    family: input.family,
    severity: input.severity,
    service: input.service,
    space: input.space,
    path: input.path,
    owner: ACCOUNT,
    ownedBySelf: null,
    displayLabel: input.path,
    metadataLabel: null,
    ...(input.appScopedSecret
      ? { appScopedSecret: input.appScopedSecret }
      : {}),
    actions: [
      {
        id: `${input.service}\u0000${input.space}\u0000${input.path}\u0000${input.ability}`,
        ability: input.ability,
        verb: input.ability.slice(input.ability.indexOf("/") + 1),
        required: false,
        selected: true,
        editable: true,
        caveats: [],
      },
    ],
  };
}

describe("grantReachesSecretDataOrDecryption", () => {
  it("includes TinyCloud Secrets SQL even when ownership classification is cross-app", () => {
    expect(
      grantReachesSecretDataOrDecryption(
        grant({
          service: "tinycloud.sql",
          space: `tinycloud:pkh:eip155:1:${ACCOUNT}:secrets`,
          path: "default",
          ability: "tinycloud.sql/read",
          family: "cross-app-data",
          severity: "attention",
        }),
      ),
    ).toBe(true);
  });

  it("does not count an unrelated unknown mutation solely because it is sensitive", () => {
    expect(
      grantReachesSecretDataOrDecryption(
        grant({
          service: "example.unknown",
          space: "applications",
          path: "items",
          ability: "example.unknown/write",
          family: "unknown",
          severity: "sensitive",
        }),
      ),
    ).toBe(false);
  });

  it("counts an exactly proven app-scoped secret in the secret-reach total", () => {
    // App-scoped secrets remain in the callout count regardless of the
    // presentation severity `annotateAppScopedGrants` assigns. The user
    // is still authorizing access to secret data; the standard-severity
    // presentation only affects how the grant is displayed, not whether
    // it belongs in the "N exact grants reach secret data or decryption"
    // total.
    expect(
      grantReachesSecretDataOrDecryption(
        grant({
          service: "tinycloud.kv",
          space: `tinycloud:pkh:eip155:1:${ACCOUNT}:secrets`,
          path: "vault/secrets/scoped/listen/GOOGLE_MEET_TOKENS",
          ability: "tinycloud.kv/get",
          family: "secret-read",
          severity: "standard",
          appScopedSecret: {
            secretName: "GOOGLE_MEET_TOKENS",
            scope: "listen",
          },
        }),
      ),
    ).toBe(true);
  });
});
