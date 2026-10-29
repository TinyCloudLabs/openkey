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
  buildStatements,
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
      "Read your data; unknown action: tinycloud.kv/exfiltrate",
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
      "Read and change another user's data; unknown action: tinycloud.kv/archive",
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
      "Decrypt your data; unknown action: tinycloud.encryption/export-key",
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
      "Unknown action: tinycloud.encryption/export-key",
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
      "Unknown action: tinycloud.kv/rotate",
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
      "Read your data; unknown action: tinycloud.kv/archive",
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
      "Read your data; unknown action: tinycloud.sql/vacuum",
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
      "Read your secrets; unknown action: tinycloud.sql/dump",
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
      "Set up encryption and decrypt protected data",
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
      "Decrypt your data; unknown action: tinycloud.encryption/create",
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
      "Unknown action: tinycloud.encryption/create",
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

  it("SQL account with [read, schema] splits schema into its own row", () => {
    const grant = makeGrant({
      family: "bootstrap-sql",
      service: "tinycloud.sql",
      space: ACCOUNT_SPACE,
      path: "account",
      abilities: ["tinycloud.sql/read", "tinycloud.sql/schema"],
      severity: "attention",
    });
    expect(buildStatements(grant).map((s) => s.primaryText)).toEqual([
      "Manage your TinyCloud account",
      "Edit and delete tables in your TinyCloud account",
    ]);
  });
});

describe("secret catalog SQL schema gets its own row", () => {
  // Secret Manager's manifest requests tinycloud.sql on `secrets`/`default`
  // with [read, write, schema]. The catalog row must keep its existing copy,
  // and schema must be stated, not hidden inside "manage".
  it("Secret Manager grant keeps 'View and manage' and adds a schema row", () => {
    const grant = makeGrant({
      family: "secret-mutation",
      service: "tinycloud.sql",
      space: SECRETS_SPACE,
      path: "default",
      abilities: [
        "tinycloud.sql/read",
        "tinycloud.sql/write",
        "tinycloud.sql/schema",
      ],
    });
    expect(buildStatements(grant).map((s) => s.primaryText)).toEqual([
      "View and manage your secret catalog",
      "Edit and delete your secret tables",
    ]);
  });

  it("another user's secret catalog schema row names the other user", () => {
    const grant = makeGrant({
      family: "secret-mutation",
      service: "tinycloud.sql",
      space: SECRETS_SPACE,
      path: "default",
      abilities: [
        "tinycloud.sql/read",
        "tinycloud.sql/write",
        "tinycloud.sql/schema",
      ],
      ownedBySelf: false,
    });
    expect(buildStatements(grant).map((s) => s.primaryText)).toEqual([
      "View and manage another user's secret catalog",
      "Edit and delete another user's secret tables",
    ]);
  });

  it("schema-only secret catalog grant states table rights", () => {
    const grant = makeGrant({
      family: "secret-mutation",
      service: "tinycloud.sql",
      space: SECRETS_SPACE,
      path: "default",
      abilities: ["tinycloud.sql/schema"],
    });
    expect(buildStatements(grant).map((s) => s.primaryText)).toEqual([
      "Edit and delete your secret tables",
    ]);
  });

  it("root-scope secret catalog schema row says entire catalog", () => {
    const grant = makeGrant({
      family: "secret-mutation",
      service: "tinycloud.sql",
      space: SECRETS_SPACE,
      path: "",
      abilities: ["tinycloud.sql/read", "tinycloud.sql/schema"],
    });
    expect(buildStatements(grant).map((s) => s.primaryText)).toEqual([
      "Manage your entire secret catalog",
      "Edit and delete all your secret tables",
    ]);
  });
});

describe("unknown cross-user schema grants stay literal", () => {
  // schemaOnlyStatementText must not reach friendly copy for a shape the
  // classifier does not recognise, even when the owner is another user.
  it("another user's account root with [schema] renders the literal fallback", () => {
    const grant = makeGrant({
      family: "unknown",
      service: "tinycloud.sql",
      space: ACCOUNT_SPACE,
      path: "",
      abilities: ["tinycloud.sql/schema"],
      ownedBySelf: false,
    });
    expect(buildStatement(grant).literalEscaped).toBe(true);
    expect(buildStatements(grant).map((s) => s.primaryText)).toEqual([
      buildStatement(grant).primaryText,
    ]);
  });

  it("another user's public space with [schema] renders the literal fallback", () => {
    const grant = makeGrant({
      family: "unknown",
      service: "tinycloud.sql",
      space: `tinycloud:pkh:eip155:1:${ACCOUNT}:public`,
      path: "*",
      abilities: ["tinycloud.sql/schema"],
      ownedBySelf: false,
    });
    expect(buildStatement(grant).literalEscaped).toBe(true);
  });
});

describe("schema-only copy pins the owner and the space", () => {
  // Account index: classifyRecapEntry returns bootstrap-sql for path "account".
  it("account index schema-only grant names the TinyCloud account", () => {
    const grant = makeGrant({
      family: "bootstrap-sql",
      service: "tinycloud.sql",
      space: ACCOUNT_SPACE,
      path: "account",
      abilities: ["tinycloud.sql/schema"],
    });
    expect(buildStatement(grant).primaryText).toBe(
      "Edit and delete tables in your TinyCloud account",
    );
  });

  it("another user's default data schema-only grant names their TinyCloud data", () => {
    const grant = makeGrant({
      family: "cross-app-data",
      service: "tinycloud.sql",
      space: DEFAULT_SPACE,
      path: "*",
      abilities: ["tinycloud.sql/schema"],
      ownedBySelf: false,
    });
    expect(buildStatement(grant).primaryText).toBe(
      "Edit and delete another user's TinyCloud tables",
    );
  });

  it("another user's application data schema-only grant names their application data", () => {
    const grant = makeGrant({
      family: "cross-app-data",
      service: "tinycloud.sql",
      space: APPS_SPACE,
      path: "*",
      abilities: ["tinycloud.sql/schema"],
      ownedBySelf: false,
    });
    expect(buildStatement(grant).primaryText).toBe(
      "Edit and delete another user's application tables",
    );
  });
});

describe("unrecognized schema spellings stay literal", () => {
  // verbOf("tinycloud.kv/schema") is "schema", but the ability is not in
  // SQL_RECOGNIZED_ABILITIES. Without the set check, friendly copy would leak.
  it("another user's default schema under a kv-prefixed ability stays literal", () => {
    const grant = makeGrant({
      family: "cross-app-data",
      service: "tinycloud.sql",
      space: DEFAULT_SPACE,
      path: "*",
      abilities: ["tinycloud.kv/schema"],
      ownedBySelf: false,
    });
    expect(buildStatement(grant).primaryText).toBe(
      "Unknown action: tinycloud.kv/schema",
    );
  });
});
