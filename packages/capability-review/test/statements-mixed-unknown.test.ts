// Mixed unknown-action regression tests.
//
// Prior to this fix, `buildStatement` derived its friendly copy from
// broad `classifyVerbs` flag sets (`hasRead`, `hasWrite`, `hasDecrypt`,
// ...). Those flags fire whenever ANY action's short verb sits inside
// the corresponding synonym set (`READ_VERBS`, `MUTATION_VERBS`, ...),
// so a grant like `[tinycloud.kv/get, tinycloud.kv/exfiltrate]` inherited
// the friendly "Read this app's data" copy: `get` set `hasRead`, and the
// unknown `exfiltrate` was silently ignored by every gate. The operator
// saw a reassuring summary for a request that actually carried an
// unknown mutation-like verb.
//
// The fix places a fail-closed gate BETWEEN the appScopedSecret branch
// and the own-app-data/cross-app-data family branch that requires EVERY
// action in the grant to be a byte-exact ability shape the KV / SQL /
// encryption branches are prepared to speak friendly copy for. Any
// unknown ability forces the whole grant into `fallbackStatement`.
//
// The failure tests below pin the fail-closed behavior. The happy-path
// tests re-pin the friendly copy the existing catalog is expected to
// preserve verbatim.

import { describe, expect, it } from "bun:test";
import {
  buildStatement,
  type CapabilityAction,
  type CapabilityGrant,
} from "../src/index.js";

const ACCOUNT = "0x1111111111111111111111111111111111111111";
const APPS_SPACE = `tinycloud:pkh:eip155:1:${ACCOUNT}:applications`;
const ACCOUNT_SPACE = `tinycloud:pkh:eip155:1:${ACCOUNT}:account`;
const DEFAULT_SPACE = `tinycloud:pkh:eip155:1:${ACCOUNT}:default`;
const SECRETS_SPACE = `tinycloud:pkh:eip155:1:${ACCOUNT}:secrets`;

interface GrantInput {
  family: CapabilityGrant["family"];
  service: string;
  space?: string;
  path?: string;
  abilities: string[];
  severity?: CapabilityGrant["severity"];
  ownedBySelf?: boolean;
  appScopedSecret?: CapabilityGrant["appScopedSecret"];
}

function makeGrant(input: GrantInput): CapabilityGrant {
  const space = input.space ?? DEFAULT_SPACE;
  const path = input.path ?? "";
  const actions: CapabilityAction[] = input.abilities.map((ability) => ({
    id: `${input.service}-${space}-${path}-${ability}`,
    ability,
    verb: ability.includes("/")
      ? ability.slice(ability.indexOf("/") + 1)
      : ability,
    required: false,
    selected: true,
    editable: true,
    caveats: [],
  }));
  return {
    id: `${input.service}-${space}-${path}`,
    family: input.family,
    severity: input.severity ?? "attention",
    service: input.service,
    space,
    path,
    owner: ACCOUNT,
    ownedBySelf: input.ownedBySelf ?? input.family !== "cross-app-data",
    displayLabel: path || input.service,
    metadataLabel: null,
    resourceService: null,
    ...(input.appScopedSecret
      ? { appScopedSecret: input.appScopedSecret }
      : {}),
    actions,
  };
}

describe("buildStatement — fail-closed on mixed known+unknown actions", () => {
  it("own-app-data with [get, exfiltrate] falls back to literal", () => {
    const grant = makeGrant({
      family: "own-app-data",
      service: "tinycloud.kv",
      path: "cycle/",
      abilities: ["tinycloud.kv/get", "tinycloud.kv/exfiltrate"],
    });
    const stmt = buildStatement(grant);
    expect(stmt.primaryText).toBe(
      "Perform tinycloud.kv/get, tinycloud.kv/exfiltrate on tinycloud.kv",
    );
    // Must NOT inherit the friendly own-app-data copy.
    expect(stmt.primaryText).not.toBe("Read this app's data");
    expect(stmt.primaryText).not.toBe("Read and update this app's data");
  });

  it("cross-app-data with [get, put, archive] falls back to literal", () => {
    const grant = makeGrant({
      family: "cross-app-data",
      service: "tinycloud.kv",
      path: "shared/",
      abilities: [
        "tinycloud.kv/get",
        "tinycloud.kv/put",
        "tinycloud.kv/archive",
      ],
      ownedBySelf: false,
    });
    const stmt = buildStatement(grant);
    expect(stmt.primaryText).toBe(
      "Perform tinycloud.kv/get, tinycloud.kv/put, tinycloud.kv/archive on tinycloud.kv",
    );
    expect(stmt.primaryText).not.toBe("Read and update data outside this app");
    expect(stmt.primaryText).not.toBe("Update data outside this app");
  });

  it("encryption grant with [decrypt, export-key] falls back to literal", () => {
    const grant = makeGrant({
      family: "encryption-decrypt",
      service: "tinycloud.encryption",
      path: "health-data",
      abilities: [
        "tinycloud.encryption/decrypt",
        "tinycloud.encryption/export-key",
      ],
      severity: "sensitive",
    });
    const stmt = buildStatement(grant);
    expect(stmt.primaryText).toBe(
      "Perform tinycloud.encryption/decrypt, tinycloud.encryption/export-key on tinycloud.encryption",
    );
    // Must NOT inherit the friendly "Decrypt protected data" copy just
    // because `decrypt` is a known verb.
    expect(stmt.primaryText).not.toBe("Decrypt protected data");
    expect(stmt.primaryText).not.toBe(
      "Create a decryption network and decrypt protected data",
    );
  });

  it("encryption grant with only unknown verb (no decrypt) falls back", () => {
    const grant = makeGrant({
      family: "encryption-decrypt",
      service: "tinycloud.encryption",
      path: "health-data",
      abilities: ["tinycloud.encryption/export-key"],
      severity: "sensitive",
    });
    const stmt = buildStatement(grant);
    expect(stmt.primaryText).toBe(
      "Perform tinycloud.encryption/export-key on tinycloud.encryption",
    );
    expect(stmt.primaryText).not.toBe("Decrypt protected data");
  });

  it("KV variables path with unknown-only [rotate] falls back to literal", () => {
    const grant = makeGrant({
      family: "secret-mutation",
      service: "tinycloud.kv",
      space: SECRETS_SPACE,
      path: "variables/API_KEY",
      abilities: ["tinycloud.kv/rotate"],
      severity: "sensitive",
    });
    const stmt = buildStatement(grant);
    expect(stmt.primaryText).toBe(
      "Perform tinycloud.kv/rotate on tinycloud.kv",
    );
    // Must NOT get the friendly "Manage secret variables" copy just
    // because the path shape is secrets-variables — the ability is
    // still unknown.
    expect(stmt.primaryText).not.toBe("Manage secret variables");
    expect(stmt.primaryText).not.toBe("View secret variable names and details");
  });

  it("KV apps path with [get, archive] falls back to literal", () => {
    const grant = makeGrant({
      family: "bootstrap-kv",
      service: "tinycloud.kv",
      path: "applications",
      abilities: ["tinycloud.kv/get", "tinycloud.kv/archive"],
      severity: "standard",
    });
    const stmt = buildStatement(grant);
    expect(stmt.primaryText).toBe(
      "Perform tinycloud.kv/get, tinycloud.kv/archive on tinycloud.kv",
    );
    expect(stmt.primaryText).not.toBe("View your connected apps");
    expect(stmt.primaryText).not.toBe("View and update your connected apps");
  });

  it("SQL grant with [read, vacuum] falls back to literal", () => {
    const grant = makeGrant({
      family: "bootstrap-sql",
      service: "tinycloud.sql",
      path: "",
      abilities: ["tinycloud.sql/read", "tinycloud.sql/vacuum"],
      severity: "standard",
    });
    const stmt = buildStatement(grant);
    expect(stmt.primaryText).toBe(
      "Perform tinycloud.sql/read, tinycloud.sql/vacuum on tinycloud.sql",
    );
    // Must NOT get the friendly "Read your TinyCloud account" copy just
    // because `read` is a known verb.
    expect(stmt.primaryText).not.toBe("Read your TinyCloud account");
    expect(stmt.primaryText).not.toBe("Read and update your TinyCloud account");
  });

  it("SQL grant on secrets space with mixed unknown falls back to literal", () => {
    const grant = makeGrant({
      family: "bootstrap-sql",
      service: "tinycloud.sql",
      space: SECRETS_SPACE,
      path: "",
      abilities: ["tinycloud.sql/read", "tinycloud.sql/dump"],
      severity: "sensitive",
    });
    const stmt = buildStatement(grant);
    expect(stmt.primaryText).toBe(
      "Perform tinycloud.sql/read, tinycloud.sql/dump on tinycloud.sql",
    );
    expect(stmt.primaryText).not.toBe("Read TinyCloud Secrets data");
    expect(stmt.primaryText).not.toBe("Read and update TinyCloud Secrets data");
  });
});

describe("buildStatement — happy-path friendly copy preserved", () => {
  it("own-app-data with [get] yields neutral application-data copy", () => {
    const grant = makeGrant({
      family: "own-app-data",
      service: "tinycloud.kv",
      path: "cycle/",
      abilities: ["tinycloud.kv/get"],
    });
    expect(buildStatement(grant).primaryText).toBe("Read application data");
  });

  it("own-app-data with [get, put] yields the combined copy", () => {
    const grant = makeGrant({
      family: "own-app-data",
      service: "tinycloud.kv",
      path: "cycle/",
      abilities: ["tinycloud.kv/get", "tinycloud.kv/put"],
    });
    expect(buildStatement(grant).primaryText).toBe(
      "Read and update application data",
    );
  });

  it("cross-app-data with [get, put] identifies another user's data", () => {
    const grant = makeGrant({
      family: "cross-app-data",
      service: "tinycloud.kv",
      path: "shared/",
      abilities: ["tinycloud.kv/get", "tinycloud.kv/put"],
      ownedBySelf: false,
    });
    expect(buildStatement(grant).primaryText).toBe(
      "Read and update another user's TinyCloud data",
    );
  });

  it('encryption with [decrypt] alone yields "Decrypt protected data"', () => {
    const grant = makeGrant({
      family: "encryption-decrypt",
      service: "tinycloud.encryption",
      path: "health-data",
      abilities: ["tinycloud.encryption/decrypt"],
      severity: "sensitive",
    });
    expect(buildStatement(grant).primaryText).toBe("Decrypt protected data");
  });

  it("encryption with [network.create, decrypt] yields the combined copy", () => {
    const grant = makeGrant({
      family: "encryption-decrypt",
      service: "tinycloud.encryption",
      path: "health-data",
      abilities: [
        "tinycloud.encryption/network.create",
        "tinycloud.encryption/decrypt",
      ],
      severity: "sensitive",
    });
    expect(buildStatement(grant).primaryText).toBe(
      "Set up encrypted data access and decrypt protected data",
    );
  });

  it("encryption with [create, decrypt] (unregistered short create verb) falls back to literal", () => {
    // Sol rejection re-fix: `tinycloud.encryption/create` is NOT in the
    // canonical js-sdk registry (only `decrypt`, `network.create`, and
    // `network.revoke` are registered). Mixing it with a registered
    // `decrypt` must NOT let the whole grant inherit the friendly
    // combined copy — that would give an unregistered wire shape
    // reassuring "Create a decryption network and decrypt protected
    // data" phrasing at sensitive severity. The fail-closed gate in
    // ENCRYPTION_RECOGNIZED_ABILITIES forces the entire grant into the
    // literal fallback so the operator sees the raw actions.
    const grant = makeGrant({
      family: "encryption-decrypt",
      service: "tinycloud.encryption",
      path: "health-data",
      abilities: [
        "tinycloud.encryption/create",
        "tinycloud.encryption/decrypt",
      ],
      severity: "sensitive",
    });
    const stmt = buildStatement(grant);
    expect(stmt.primaryText).toBe(
      "Perform tinycloud.encryption/create, tinycloud.encryption/decrypt on tinycloud.encryption",
    );
    expect(stmt.primaryText).not.toBe(
      "Create a decryption network and decrypt protected data",
    );
    expect(stmt.primaryText).not.toBe("Decrypt protected data");
    expect(stmt.primaryText).not.toBe("Create a decryption network");
  });

  it("encryption with [create] alone (unregistered short create verb) falls back to literal", () => {
    // Sol rejection re-fix: an unknown-only grant carrying
    // `tinycloud.encryption/create` must not render the friendly
    // "Create a decryption network" copy — the wire shape is not in the
    // canonical js-sdk registry.
    const grant = makeGrant({
      family: "encryption-decrypt",
      service: "tinycloud.encryption",
      path: "health-data",
      abilities: ["tinycloud.encryption/create"],
      severity: "attention",
    });
    const stmt = buildStatement(grant);
    expect(stmt.primaryText).toBe(
      "Perform tinycloud.encryption/create on tinycloud.encryption",
    );
    expect(stmt.primaryText).not.toBe("Create a decryption network");
  });

  it("canonical account app registry folds into account management", () => {
    const grant = makeGrant({
      family: "bootstrap-kv",
      service: "tinycloud.kv",
      space: ACCOUNT_SPACE,
      path: "applications/",
      abilities: ["tinycloud.kv/get"],
      severity: "standard",
    });
    expect(buildStatement(grant).primaryText).toBe(
      "Manage your TinyCloud account",
    );
  });

  it("canonical account SQL read folds into account management", () => {
    const grant = makeGrant({
      family: "bootstrap-sql",
      service: "tinycloud.sql",
      space: ACCOUNT_SPACE,
      path: "account",
      abilities: ["tinycloud.sql/read"],
      severity: "standard",
    });
    expect(buildStatement(grant).primaryText).toBe(
      "Manage your TinyCloud account",
    );
  });

  it("SQL account with [read, write] yields the combined copy", () => {
    const grant = makeGrant({
      family: "bootstrap-sql",
      service: "tinycloud.sql",
      space: ACCOUNT_SPACE,
      path: "account",
      abilities: ["tinycloud.sql/read", "tinycloud.sql/write"],
      severity: "attention",
    });
    expect(buildStatement(grant).primaryText).toBe(
      "Manage your TinyCloud account",
    );
  });

  it("SQL account with [read, schema] yields the combined copy", () => {
    const grant = makeGrant({
      family: "bootstrap-sql",
      service: "tinycloud.sql",
      space: ACCOUNT_SPACE,
      path: "account",
      abilities: ["tinycloud.sql/read", "tinycloud.sql/schema"],
      severity: "attention",
    });
    expect(buildStatement(grant).primaryText).toBe(
      "Manage your TinyCloud account",
    );
  });
});
