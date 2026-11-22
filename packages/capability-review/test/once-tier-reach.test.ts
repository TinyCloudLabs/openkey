import { describe, expect, it } from "bun:test";

import { grantIsBroadOnce, type CapabilityGrant } from "../src/index.js";

// The one-hour tier holds only access to all secrets or all encrypted data;
// every narrower secret or decryption grant follows the app's length.

const ACCOUNT = "0x1111111111111111111111111111111111111111";
const OWNER = `did:pkh:eip155:1:${ACCOUNT}`;
const SECRETS_SPACE = `tinycloud:pkh:eip155:1:${ACCOUNT}:secrets`;
const OWN_SPACE = `tinycloud:pkh:eip155:1:${ACCOUNT}:courier`;

function grant(input: {
  service: string;
  space: string;
  path: string;
  ability: string;
  family: CapabilityGrant["family"];
  serviceMismatch?: boolean;
}): CapabilityGrant {
  return {
    id: `${input.service}\u0000${input.space}\u0000${input.path}`,
    family: input.family,
    severity: "sensitive",
    service: input.service,
    space: input.space,
    path: input.path,
    owner: ACCOUNT,
    ownedBySelf: null,
    displayLabel: input.path,
    metadataLabel: null,
    resourceService: null,
    ...(input.serviceMismatch ? { serviceMismatch: true } : {}),
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

const decrypt = (urnTail: string) =>
  grant({
    service: "tinycloud.encryption",
    space: `urn:tinycloud:encryption:${OWNER}:default${urnTail}`,
    path: "",
    ability: "tinycloud.encryption/decrypt",
    family: "encryption-decrypt",
  });

const kv = (path: string, ability = "tinycloud.kv/get") =>
  grant({
    service: "tinycloud.kv",
    space: SECRETS_SPACE,
    path,
    ability,
    family: ability.endsWith("/get") ? "secret-read" : "secret-mutation",
  });

describe("encryption prefixes: one segment is everything, apps/<appId>/ is one app", () => {
  it.each([["/apps/"], ["/shared/"], ["/keys/"]])(
    "a one-segment prefix %s starts at one hour",
    (tail) => {
      expect(grantIsBroadOnce(decrypt(tail))).toBe(true);
    },
  );

  it.each([["/shared/team/"], ["/keys/primary/"], ["/shared/team/deep/"]])(
    "a deeper prefix %s outside apps/ starts at one hour",
    (tail) => {
      expect(grantIsBroadOnce(decrypt(tail))).toBe(true);
    },
  );

  it.each([
    ["/apps/xyz.tinycloud.courier/"],
    ["/apps/xyz.tinycloud.courier/keys/"],
    ["/apps/xyz.tinycloud.courier/keys/nested/"],
  ])("a prefix inside one app %s keeps the app's length", (tail) => {
    expect(grantIsBroadOnce(decrypt(tail))).toBe(false);
  });

  it.each([["/apps/xyz.tinycloud.courier/primary"], ["/shared"], ["/shared/team/key"]])(
    "an exact key %s keeps the app's length",
    (tail) => {
      expect(grantIsBroadOnce(decrypt(tail))).toBe(false);
    },
  );

  it("the whole network starts at one hour", () => {
    expect(grantIsBroadOnce(decrypt(""))).toBe(true);
  });

  it("a URN that does not parse starts at one hour", () => {
    expect(grantIsBroadOnce(decrypt("/"))).toBe(true);
    expect(grantIsBroadOnce(decrypt("/Apps/UPPER/"))).toBe(true);
  });
});

describe("secrets: the whole vault is everything, anything narrower keeps the app's length", () => {
  it.each([[""], ["vault"], ["vault/"], ["vault/secrets"], ["vault/secrets/"], ["secrets"], ["secrets/"]])(
    "KV write at %p starts at one hour",
    (path) => {
      expect(grantIsBroadOnce(kv(path, "tinycloud.kv/put"))).toBe(true);
    },
  );

  it("reading every secret value starts at one hour", () => {
    expect(grantIsBroadOnce(kv("vault/secrets/"))).toBe(true);
  });

  it.each([
    ["vault/secrets/DEPLOY_KEY"],
    ["secrets/DEPLOY_KEY"],
    ["vault/secrets/scoped/dev/"],
    ["vault/secrets/scoped/dev/DEPLOY_KEY"],
    ["vault/secrets/1password"],
    ["variables/REGION"],
  ])("KV at %p keeps the app's length", (path) => {
    expect(grantIsBroadOnce(kv(path))).toBe(false);
    expect(grantIsBroadOnce(kv(path, "tinycloud.kv/put"))).toBe(false);
  });

  it("one named secret outside the secrets space keeps the app's length", () => {
    expect(
      grantIsBroadOnce(
        grant({
          service: "tinycloud.kv",
          space: OWN_SPACE,
          path: "vault/secrets/DEPLOY_KEY",
          ability: "tinycloud.kv/get",
          family: "secret-read",
        }),
      ),
    ).toBe(false);
  });

  it("SQL on the secret catalog keeps the app's length, whole catalog included", () => {
    for (const path of ["", "default"]) {
      for (const ability of ["tinycloud.sql/read", "tinycloud.sql/write"]) {
        expect(
          grantIsBroadOnce(
            grant({
              service: "tinycloud.sql",
              space: SECRETS_SPACE,
              path,
              ability,
              family: ability.endsWith("/read") ? "secret-read" : "secret-mutation",
            }),
          ),
        ).toBe(false);
      }
    }
  });

  it("the secrets service on one name keeps the app's length, on the whole space starts at one hour", () => {
    const secrets = (path: string) =>
      grant({
        service: "tinycloud.secrets",
        space: SECRETS_SPACE,
        path,
        ability: "tinycloud.secrets/put",
        family: "secret-mutation",
      });
    expect(grantIsBroadOnce(secrets("DEPLOY_KEY"))).toBe(false);
    expect(grantIsBroadOnce(secrets(""))).toBe(true);
  });
});

describe("shapes that cannot be placed start at one hour", () => {
  it("an unknown service on the secrets space", () => {
    expect(
      grantIsBroadOnce(
        grant({
          service: "tinycloud.blob",
          space: SECRETS_SPACE,
          path: "vault/secrets/DEPLOY_KEY",
          ability: "tinycloud.blob/get",
          family: "unknown",
        }),
      ),
    ).toBe(true);
  });

  it("a mismatched service on a named secret", () => {
    expect(
      grantIsBroadOnce(
        grant({
          service: "tinycloud.kv",
          space: SECRETS_SPACE,
          path: "vault/secrets/DEPLOY_KEY",
          ability: "tinycloud.sql/read",
          family: "unknown",
          serviceMismatch: true,
        }),
      ),
    ).toBe(true);
  });

  it.each([
    ["tinycloud.secrets", "DEPLOY_KEY", "tinycloud.secrets/rotate"],
    ["tinycloud.kv", "vault/secrets/DEPLOY_KEY", "tinycloud.kv/rotate"],
    ["tinycloud.sql", "default", "tinycloud.sql/export"],
  ])("an unknown ability on %s, even on one name (%s)", (service, path, ability) => {
    expect(
      grantIsBroadOnce(
        grant({ service, space: SECRETS_SPACE, path, ability, family: "secret-mutation" }),
      ),
    ).toBe(true);
  });
});

describe("access that reaches no secret or decryption is outside the tier", () => {
  it("ordinary KV on the app's own space", () => {
    expect(
      grantIsBroadOnce(
        grant({
          service: "tinycloud.kv",
          space: OWN_SPACE,
          path: "",
          ability: "tinycloud.kv/put",
          family: "own-app-data",
        }),
      ),
    ).toBe(false);
  });

  it("creating a key on the whole network", () => {
    expect(
      grantIsBroadOnce(
        grant({
          service: "tinycloud.encryption",
          space: `urn:tinycloud:encryption:${OWNER}:default`,
          path: "",
          ability: "tinycloud.encryption/key.create",
          family: "encryption-key",
        }),
      ),
    ).toBe(false);
  });
});
