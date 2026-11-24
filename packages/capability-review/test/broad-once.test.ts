import { describe, expect, it } from "bun:test";

import {
  grantIsBroadOnce,
  type CapabilityGrant,
} from "../src/index.js";

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
  severity?: CapabilityGrant["severity"];
  resourceService?: string | null;
}): CapabilityGrant {
  return {
    id: `${input.service}\u0000${input.space}\u0000${input.path}`,
    family: input.family,
    severity: input.severity ?? "sensitive",
    service: input.service,
    space: input.space,
    path: input.path,
    owner: ACCOUNT,
    ownedBySelf: null,
    displayLabel: input.path,
    metadataLabel: null,
    resourceService: input.resourceService ?? null,
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

describe("grantIsBroadOnce: non-Sensitive grants are not broad-once", () => {
  it("plain KV write on the app's own space is not broad-once", () => {
    expect(
      grantIsBroadOnce(
        grant({
          service: "tinycloud.kv",
          space: OWN_SPACE,
          path: "courier/outbox",
          ability: "tinycloud.kv/put",
          family: "own-app-data",
          severity: "standard",
        }),
      ),
    ).toBe(false);
  });
});

describe("grantIsBroadOnce: broad shapes stay at the one-hour start", () => {
  it("whole-network encryption decrypt (bare network URN) is broad-once", () => {
    expect(
      grantIsBroadOnce(
        grant({
          service: "tinycloud.encryption",
          space: `urn:tinycloud:encryption:${OWNER}:default`,
          path: "",
          ability: "tinycloud.encryption/decrypt",
          family: "encryption-decrypt",
        }),
      ),
    ).toBe(true);
  });

  it("an encryption prefix other than apps/<id>/ is broad-once (empty prefix)", () => {
    expect(
      grantIsBroadOnce(
        grant({
          service: "tinycloud.encryption",
          space: `urn:tinycloud:encryption:${OWNER}:default/`,
          path: "",
          ability: "tinycloud.encryption/decrypt",
          family: "encryption-decrypt",
        }),
      ),
    ).toBe(true);
  });

  it("an encryption prefix nested deeper than apps/<id>/ keeps the app's length (inside one app)", () => {
    expect(
      grantIsBroadOnce(
        grant({
          service: "tinycloud.encryption",
          space: `urn:tinycloud:encryption:${OWNER}:default/apps/x/nested/`,
          path: "",
          ability: "tinycloud.encryption/decrypt",
          family: "encryption-decrypt",
        }),
      ),
    ).toBe(false);
  });

  it("an invalid encryption URN stays broad-once (fail closed)", () => {
    expect(
      grantIsBroadOnce(
        grant({
          service: "tinycloud.encryption",
          space: "urn:tinycloud:encryption:garbage-not-a-valid-urn",
          path: "",
          ability: "tinycloud.encryption/decrypt",
          family: "encryption-decrypt",
        }),
      ),
    ).toBe(true);
  });

  it("a secret-namespace-list that reads values is broad-once", () => {
    expect(
      grantIsBroadOnce(
        grant({
          service: "tinycloud.kv",
          space: SECRETS_SPACE,
          path: "",
          ability: "tinycloud.kv/get",
          family: "secret-namespace-list",
        }),
      ),
    ).toBe(true);
  });

  it("a secret-mutation with an empty path in the secrets space is broad-once", () => {
    expect(
      grantIsBroadOnce(
        grant({
          service: "tinycloud.kv",
          space: SECRETS_SPACE,
          path: "",
          ability: "tinycloud.kv/put",
          family: "secret-mutation",
        }),
      ),
    ).toBe(true);
  });

  it("a secret-mutation at `vault/` is broad-once (not a named path)", () => {
    expect(
      grantIsBroadOnce(
        grant({
          service: "tinycloud.kv",
          space: OWN_SPACE,
          path: "vault/",
          ability: "tinycloud.kv/put",
          family: "secret-mutation",
        }),
      ),
    ).toBe(true);
  });

  it("a secret-mutation at `vault/secrets` (no slash) is broad-once", () => {
    expect(
      grantIsBroadOnce(
        grant({
          service: "tinycloud.kv",
          space: OWN_SPACE,
          path: "vault/secrets",
          ability: "tinycloud.kv/put",
          family: "secret-mutation",
        }),
      ),
    ).toBe(true);
  });

  it("a secret-mutation at `vault/secrets/` with an empty tail is broad-once", () => {
    expect(
      grantIsBroadOnce(
        grant({
          service: "tinycloud.kv",
          space: OWN_SPACE,
          path: "vault/secrets/",
          ability: "tinycloud.kv/put",
          family: "secret-mutation",
        }),
      ),
    ).toBe(true);
  });

  it("a `secret-mutation` on the SQL secrets catalog keeps the app's length", () => {
    expect(
      grantIsBroadOnce(
        grant({
          service: "tinycloud.sql",
          space: SECRETS_SPACE,
          path: "default",
          ability: "tinycloud.sql/write",
          family: "secret-mutation",
        }),
      ),
    ).toBe(false);
  });

  it("a `secret-read` on the SQL secrets catalog keeps the app's length", () => {
    expect(
      grantIsBroadOnce(
        grant({
          service: "tinycloud.sql",
          space: SECRETS_SPACE,
          path: "default",
          ability: "tinycloud.sql/read",
          family: "secret-read",
        }),
      ),
    ).toBe(false);
  });

  it("an unknown mutation on `tinycloud.secrets` with a non-empty path is broad-once (unlisted service)", () => {
    expect(
      grantIsBroadOnce(
        grant({
          service: "tinycloud.secrets",
          space: SECRETS_SPACE,
          path: "DEPLOY_KEY",
          ability: "tinycloud.secrets/rotate",
          family: "secret-mutation",
        }),
      ),
    ).toBe(true);
  });

  it("a KV path under a lowercase scope directory `vault/secrets/scoped` keeps the app's length (a sub-prefix)", () => {
    expect(
      grantIsBroadOnce(
        grant({
          service: "tinycloud.kv",
          space: OWN_SPACE,
          path: "vault/secrets/scoped",
          ability: "tinycloud.kv/get",
          family: "secret-read",
        }),
      ),
    ).toBe(false);
  });

  it("a KV path under a lowercase scope directory `secrets/scoped` keeps the app's length (a sub-prefix)", () => {
    expect(
      grantIsBroadOnce(
        grant({
          service: "tinycloud.kv",
          space: OWN_SPACE,
          path: "secrets/scoped",
          ability: "tinycloud.kv/get",
          family: "secret-read",
        }),
      ),
    ).toBe(false);
  });

  it("a KV named-secret path whose name begins with a digit keeps the app's length", () => {
    expect(
      grantIsBroadOnce(
        grant({
          service: "tinycloud.kv",
          space: OWN_SPACE,
          path: "vault/secrets/1KEY",
          ability: "tinycloud.kv/get",
          family: "secret-read",
        }),
      ),
    ).toBe(false);
  });

  it("a KV named-secret path with a dot in the name keeps the app's length", () => {
    expect(
      grantIsBroadOnce(
        grant({
          service: "tinycloud.kv",
          space: OWN_SPACE,
          path: "vault/secrets/DEPLOY.KEY",
          ability: "tinycloud.kv/get",
          family: "secret-read",
        }),
      ),
    ).toBe(false);
  });
});

describe("grantIsBroadOnce: exact-named shapes follow the app's ask", () => {
  it("a KV `secret-read` on `vault/secrets/<name>` is not broad-once", () => {
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

  it("a KV `secret-mutation` on `secrets/<name>` is not broad-once", () => {
    expect(
      grantIsBroadOnce(
        grant({
          service: "tinycloud.kv",
          space: OWN_SPACE,
          path: "secrets/DEPLOY_KEY",
          ability: "tinycloud.kv/put",
          family: "secret-mutation",
        }),
      ),
    ).toBe(false);
  });

  it("a KV named-secret path with an inner `/` keeps the app's length (a sub-prefix)", () => {
    expect(
      grantIsBroadOnce(
        grant({
          service: "tinycloud.kv",
          space: OWN_SPACE,
          path: "vault/secrets/scoped/dev/DEPLOY_KEY",
          ability: "tinycloud.kv/get",
          family: "secret-read",
        }),
      ),
    ).toBe(false);
  });

  it("an encryption `kind: \"key\"` grant is not broad-once", () => {
    expect(
      grantIsBroadOnce(
        grant({
          service: "tinycloud.encryption",
          space: `urn:tinycloud:encryption:${OWNER}:default/apps/xyz.tinycloud.courier/keys/primary`,
          path: "",
          ability: "tinycloud.encryption/decrypt",
          family: "encryption-decrypt",
        }),
      ),
    ).toBe(false);
  });

  it("an encryption prefix of exactly `apps/<appId>/` is not broad-once", () => {
    expect(
      grantIsBroadOnce(
        grant({
          service: "tinycloud.encryption",
          space: `urn:tinycloud:encryption:${OWNER}:default/apps/xyz.tinycloud.courier/`,
          path: "",
          ability: "tinycloud.encryption/decrypt",
          family: "encryption-decrypt",
        }),
      ),
    ).toBe(false);
  });

  it("an encryption prefix with an `apps/<appId>/<extra>/` deeper path keeps the app's length", () => {
    expect(
      grantIsBroadOnce(
        grant({
          service: "tinycloud.encryption",
          space: `urn:tinycloud:encryption:${OWNER}:default/apps/xyz.tinycloud.courier/keys/`,
          path: "",
          ability: "tinycloud.encryption/decrypt",
          family: "encryption-decrypt",
        }),
      ),
    ).toBe(false);
  });
});
