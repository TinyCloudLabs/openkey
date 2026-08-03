// Registry-parity regression tests for buildStatement's friendly-copy gate.
//
// The KV / SQL / encryption friendly-copy catalogs previously admitted
// verbs that are NOT in the canonical js-sdk capability registry
// (`js-sdk/packages/bootstrap/src/generated/capabilities.ts`). Sol
// rejected that shape of the fix: treating synonyms like
// `tinycloud.kv/peek`, `tinycloud.kv/read`, `tinycloud.kv/update`,
// `tinycloud.encryption/unwrap`, or `tinycloud.sql/schema.apply` as
// recognized let novel unknown-verb requests inherit friendly copy at
// standard severity even though no js-sdk producer emits them.
//
// Friendly copy now covers only the exact abilities current manifests emit.
// Registered compatibility aliases and broader authority remain literal
// because they are outside the predictable consent happy path. Anything else — including the
// unregistered `tinycloud.encryption/create` short-form previously
// admitted as a compatibility path — falls back to the literal
// `Perform <actions> on <service>` copy. See
// `statements-mixed-unknown.test.ts` for the encryption-side
// fail-closed regressions.
//
// Also pins the empty-action-list handling for the capabilities,
// secrets, and appScopedSecret branches — `every` on `[]` returns
// `true`, so without an explicit length check a zero-action grant would
// inherit friendly copy despite carrying no authority.

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

// ─── KV: unregistered abilities must NOT earn friendly copy ─────────────────
describe("buildStatement — KV catalog is registry-scoped", () => {
  // Sol rejected the prior catalog for admitting `peek`, `read`,
  // `update`, `write`, `post`, `admin`, `grant`, `revoke` — none of
  // which appear in the js-sdk capability registry.

  it("KV [tinycloud.kv/peek] alone → literal fallback (peek is not registered)", () => {
    const grant = makeGrant({
      family: "own-app-data",
      service: "tinycloud.kv",
      path: "cycle/",
      abilities: ["tinycloud.kv/peek"],
    });
    const stmt = buildStatement(grant);
    expect(stmt.primaryText).toBe("Perform tinycloud.kv/peek on tinycloud.kv");
    expect(stmt.primaryText).not.toBe("Read this app's data");
  });

  it("KV [tinycloud.kv/read] alone → literal fallback (long-form not registered)", () => {
    // js-sdk emits `tinycloud.kv/get` on the wire, never `tinycloud.kv/read`.
    const grant = makeGrant({
      family: "own-app-data",
      service: "tinycloud.kv",
      path: "cycle/",
      abilities: ["tinycloud.kv/read"],
    });
    const stmt = buildStatement(grant);
    expect(stmt.primaryText).toBe("Perform tinycloud.kv/read on tinycloud.kv");
    expect(stmt.primaryText).not.toBe("Read this app's data");
  });

  it("KV [tinycloud.kv/update] → literal fallback (update is not registered)", () => {
    const grant = makeGrant({
      family: "own-app-data",
      service: "tinycloud.kv",
      path: "cycle/",
      abilities: ["tinycloud.kv/update"],
    });
    const stmt = buildStatement(grant);
    expect(stmt.primaryText).toBe(
      "Perform tinycloud.kv/update on tinycloud.kv",
    );
    expect(stmt.primaryText).not.toBe("Update this app's data");
    expect(stmt.primaryText).not.toBe("Read and update this app's data");
  });

  it("KV [tinycloud.kv/write] → literal fallback (write is not registered)", () => {
    const grant = makeGrant({
      family: "own-app-data",
      service: "tinycloud.kv",
      path: "cycle/",
      abilities: ["tinycloud.kv/write"],
    });
    const stmt = buildStatement(grant);
    expect(stmt.primaryText).toBe("Perform tinycloud.kv/write on tinycloud.kv");
    expect(stmt.primaryText).not.toBe("Update this app's data");
  });

  it("KV [tinycloud.kv/admin] → literal fallback (KV admin is not registered)", () => {
    const grant = makeGrant({
      family: "own-app-data",
      service: "tinycloud.kv",
      path: "cycle/",
      abilities: ["tinycloud.kv/admin"],
    });
    const stmt = buildStatement(grant);
    expect(stmt.primaryText).toBe("Perform tinycloud.kv/admin on tinycloud.kv");
  });

  it("KV [tinycloud.kv/grant, tinycloud.kv/revoke] → literal fallback", () => {
    const grant = makeGrant({
      family: "own-app-data",
      service: "tinycloud.kv",
      path: "cycle/",
      abilities: ["tinycloud.kv/grant", "tinycloud.kv/revoke"],
    });
    const stmt = buildStatement(grant);
    expect(stmt.primaryText).toBe(
      "Perform tinycloud.kv/grant, tinycloud.kv/revoke on tinycloud.kv",
    );
  });

  it("KV mixed [get, peek] → literal fallback (peek is unrecognized)", () => {
    // `get` is registered but `peek` is not — the whole grant must fall
    // back rather than inherit friendly read copy from the recognized get.
    const grant = makeGrant({
      family: "own-app-data",
      service: "tinycloud.kv",
      path: "cycle/",
      abilities: ["tinycloud.kv/get", "tinycloud.kv/peek"],
    });
    const stmt = buildStatement(grant);
    expect(stmt.primaryText).toBe(
      "Perform tinycloud.kv/get, tinycloud.kv/peek on tinycloud.kv",
    );
    expect(stmt.primaryText).not.toBe("Read this app's data");
  });

  it("KV apps path with [peek] → literal fallback (unrecognized on account paths)", () => {
    const grant = makeGrant({
      family: "bootstrap-kv",
      service: "tinycloud.kv",
      space: APPS_SPACE,
      path: "applications",
      abilities: ["tinycloud.kv/peek"],
      severity: "standard",
    });
    const stmt = buildStatement(grant);
    expect(stmt.primaryText).toBe("Perform tinycloud.kv/peek on tinycloud.kv");
    expect(stmt.primaryText).not.toBe("View your connected apps");
  });
});

describe("buildStatement — TinyCloud Secrets value boundary", () => {
  it("describes list/metadata without claiming secret-value access", () => {
    const grant = makeGrant({
      family: "secret-read",
      service: "tinycloud.kv",
      space: SECRETS_SPACE,
      abilities: ["tinycloud.kv/list", "tinycloud.kv/metadata"],
      severity: "standard",
    });
    expect(buildStatement(grant).primaryText).toBe(
      "View secret names and details",
    );
  });

  it("describes get as reading secret values", () => {
    const grant = makeGrant({
      family: "secret-read",
      service: "tinycloud.kv",
      space: SECRETS_SPACE,
      path: "vault/secrets",
      abilities: [
        "tinycloud.kv/get",
        "tinycloud.kv/list",
        "tinycloud.kv/metadata",
      ],
      severity: "sensitive",
    });
    expect(buildStatement(grant).primaryText).toBe("Read secret values");
  });

  it("describes mixed reads and mutations without hiding either", () => {
    const grant = makeGrant({
      family: "secret-mutation",
      service: "tinycloud.kv",
      space: SECRETS_SPACE,
      path: "variables",
      abilities: ["tinycloud.kv/get", "tinycloud.kv/put"],
      severity: "sensitive",
    });
    expect(buildStatement(grant).primaryText).toBe(
      "Read and update secret values",
    );
  });

  it("keeps the secret-value meaning when the resource belongs to another user", () => {
    const grant = makeGrant({
      family: "secret-read",
      service: "tinycloud.kv",
      space: SECRETS_SPACE,
      path: "vault/secrets",
      abilities: ["tinycloud.kv/get"],
      severity: "sensitive",
      ownedBySelf: false,
    });
    expect(buildStatement(grant).primaryText).toBe(
      "Read another user's secret values",
    );
  });
});

// ─── KV: registered abilities still earn friendly copy ──────────────────────
describe("buildStatement — KV catalog: registered abilities preserved", () => {
  it("KV [get, put, del] all still yield combined friendly copy", () => {
    const grant = makeGrant({
      family: "own-app-data",
      service: "tinycloud.kv",
      path: "cycle/",
      abilities: ["tinycloud.kv/get", "tinycloud.kv/put", "tinycloud.kv/del"],
    });
    expect(buildStatement(grant).primaryText).toBe(
      "Read and update application data",
    );
  });

  it("KV [delete] (deprecated alias) stays literal", () => {
    const grant = makeGrant({
      family: "own-app-data",
      service: "tinycloud.kv",
      path: "cycle/",
      abilities: ["tinycloud.kv/delete"],
    });
    expect(buildStatement(grant).primaryText).toBe(
      "Perform tinycloud.kv/delete on tinycloud.kv",
    );
  });

  it("KV [list, metadata] still classified as read-only", () => {
    const grant = makeGrant({
      family: "bootstrap-kv",
      service: "tinycloud.kv",
      space: ACCOUNT_SPACE,
      path: "applications/",
      abilities: ["tinycloud.kv/list", "tinycloud.kv/metadata"],
      severity: "standard",
    });
    // Account bootstrap details fold into one consequence-first summary.
    expect(buildStatement(grant).primaryText).toBe(
      "Manage your TinyCloud account",
    );
  });
});

// ─── SQL: unregistered abilities must NOT earn friendly copy ────────────────
describe("buildStatement — SQL catalog is registry-scoped", () => {
  it("SQL [tinycloud.sql/get] → literal fallback (get is not registered)", () => {
    // Current manifests emit `tinycloud.sql/read`, never `tinycloud.sql/get`.
    const grant = makeGrant({
      family: "own-app-data",
      service: "tinycloud.sql",
      abilities: ["tinycloud.sql/get"],
      severity: "standard",
    });
    const stmt = buildStatement(grant);
    expect(stmt.primaryText).toBe("Perform tinycloud.sql/get on tinycloud.sql");
    expect(stmt.primaryText).not.toBe("Read your TinyCloud account");
  });

  it("SQL [tinycloud.sql/put] → literal fallback", () => {
    const grant = makeGrant({
      family: "bootstrap-sql",
      service: "tinycloud.sql",
      abilities: ["tinycloud.sql/put"],
      severity: "attention",
    });
    const stmt = buildStatement(grant);
    expect(stmt.primaryText).toBe("Perform tinycloud.sql/put on tinycloud.sql");
    expect(stmt.primaryText).not.toBe("Update your TinyCloud account");
  });

  it("SQL [tinycloud.sql/delete] → literal fallback", () => {
    const grant = makeGrant({
      family: "bootstrap-sql",
      service: "tinycloud.sql",
      abilities: ["tinycloud.sql/delete"],
      severity: "attention",
    });
    const stmt = buildStatement(grant);
    expect(stmt.primaryText).toBe(
      "Perform tinycloud.sql/delete on tinycloud.sql",
    );
  });

  it("SQL [tinycloud.sql/schema.apply] → literal fallback (compound not registered)", () => {
    const grant = makeGrant({
      family: "bootstrap-sql",
      service: "tinycloud.sql",
      abilities: ["tinycloud.sql/schema.apply"],
      severity: "attention",
    });
    const stmt = buildStatement(grant);
    expect(stmt.primaryText).toBe(
      "Perform tinycloud.sql/schema.apply on tinycloud.sql",
    );
    expect(stmt.primaryText).not.toBe("Update your TinyCloud account");
  });

  it("SQL [tinycloud.sql/update] → literal fallback", () => {
    const grant = makeGrant({
      family: "bootstrap-sql",
      service: "tinycloud.sql",
      abilities: ["tinycloud.sql/update"],
      severity: "attention",
    });
    const stmt = buildStatement(grant);
    expect(stmt.primaryText).toBe(
      "Perform tinycloud.sql/update on tinycloud.sql",
    );
  });
});

// ─── SQL: broader/compatibility operations stay literal ────────────────────
describe("buildStatement — SQL catalog: manifest abilities only", () => {
  it("application SQL [admin] stays literal", () => {
    const grant = makeGrant({
      family: "own-app-data",
      service: "tinycloud.sql",
      space: APPS_SPACE,
      path: "app/records",
      abilities: ["tinycloud.sql/admin"],
      severity: "attention",
    });
    expect(buildStatement(grant).primaryText).toBe(
      "Perform tinycloud.sql/admin on tinycloud.sql",
    );
  });

  it("application SQL [read, admin] stays literal as a whole", () => {
    const grant = makeGrant({
      family: "own-app-data",
      service: "tinycloud.sql",
      space: APPS_SPACE,
      path: "app/records",
      abilities: ["tinycloud.sql/read", "tinycloud.sql/admin"],
      severity: "attention",
    });
    expect(buildStatement(grant).primaryText).toBe(
      "Perform tinycloud.sql/read, tinycloud.sql/admin on tinycloud.sql",
    );
  });

  it("SQL [select] (deprecated alias) stays literal", () => {
    const grant = makeGrant({
      family: "bootstrap-sql",
      service: "tinycloud.sql",
      abilities: ["tinycloud.sql/select"],
      severity: "standard",
    });
    const stmt = buildStatement(grant);
    expect(stmt.primaryText).toBe(
      "Perform tinycloud.sql/select on tinycloud.sql",
    );
  });
});

// ─── Encryption: unregistered abilities must NOT earn friendly copy ─────────
describe("buildStatement — encryption catalog is registry-scoped", () => {
  it("encryption [tinycloud.encryption/unwrap] → literal fallback (unwrap not registered)", () => {
    // Sol rejection note: `tinycloud.encryption/unwrap` is not in the
    // canonical registry and no positive test exercises it.
    const grant = makeGrant({
      family: "encryption-decrypt",
      service: "tinycloud.encryption",
      path: "health-data",
      abilities: ["tinycloud.encryption/unwrap"],
      severity: "sensitive",
    });
    const stmt = buildStatement(grant);
    expect(stmt.primaryText).toBe(
      "Perform tinycloud.encryption/unwrap on tinycloud.encryption",
    );
    expect(stmt.primaryText).not.toBe("Decrypt protected data");
  });

  it("encryption [decrypt, unwrap] → literal fallback", () => {
    const grant = makeGrant({
      family: "encryption-decrypt",
      service: "tinycloud.encryption",
      path: "health-data",
      abilities: [
        "tinycloud.encryption/decrypt",
        "tinycloud.encryption/unwrap",
      ],
      severity: "sensitive",
    });
    const stmt = buildStatement(grant);
    expect(stmt.primaryText).toBe(
      "Perform tinycloud.encryption/decrypt, tinycloud.encryption/unwrap on tinycloud.encryption",
    );
    expect(stmt.primaryText).not.toBe("Decrypt protected data");
  });
});

// ─── Empty action lists: capabilities / secrets / appScopedSecret ──────────
describe("buildStatement — empty action lists fall back", () => {
  it("capabilities service with EMPTY actions → literal fallback", () => {
    // `every` on `[]` returns `true`; without the explicit length
    // guard the friendly "Check your TinyCloud account permissions"
    // copy would fire for a grant carrying no authority.
    const grant = makeGrant({
      family: "bootstrap-capabilities",
      service: "tinycloud.capabilities",
      abilities: [],
      severity: "standard",
    });
    const stmt = buildStatement(grant);
    expect(stmt.primaryText).toBe("Access tinycloud.capabilities");
    expect(stmt.primaryText).not.toContain("permissions");
  });

  it("secrets service with EMPTY actions → literal fallback", () => {
    const grant = makeGrant({
      family: "secret-read",
      service: "tinycloud.secrets",
      abilities: [],
      severity: "attention",
    });
    const stmt = buildStatement(grant);
    expect(stmt.primaryText).toBe("Access tinycloud.secrets");
  });

  it("appScopedSecret grant with EMPTY actions → literal fallback", () => {
    // Defense-in-depth: even if the annotator somehow stamped
    // appScopedSecret on a zero-action grant, buildStatement must not
    // render "Read the app secret X" for a grant carrying no verb.
    const grant: CapabilityGrant = {
      ...makeGrant({
        family: "secret-read",
        service: "tinycloud.kv",
        space: SECRETS_SPACE,
        path: "vault/secrets/scoped/listen/API_KEY",
        abilities: [],
        severity: "standard",
      }),
      appScopedSecret: { secretName: "API_KEY", scope: "listen" },
    };
    const stmt = buildStatement(grant);
    expect(stmt.primaryText).not.toContain("app secret");
    expect(stmt.primaryText).toBe("Access tinycloud.kv");
  });
});

// ─── appScopedSecret defense-in-depth: byte-exact ability membership ────────
describe("buildStatement — appScopedSecret uses byte-exact ability check", () => {
  // Sol rejection note: replace normalized action.verb membership with
  // byte-exact action.ability membership in CANONICAL_APP_SCOPE_SECRET_ABILITIES.
  //
  // The canonical URN allowlist is `tinycloud.kv/get | put | del`. Any
  // other spelling — even a synonym `read`/`write`/`delete` or the
  // short-form `kv/get` — must fall back to literal copy at this branch.

  it("stamped appScopedSecret with tinycloud.kv/read → literal fallback", () => {
    // The annotator's own gate now byte-exact-checks against the same
    // canonical allowlist, but the defense-in-depth check here MUST
    // enforce the same rule to protect against a compromised annotator.
    const grant: CapabilityGrant = {
      ...makeGrant({
        family: "secret-read",
        service: "tinycloud.kv",
        space: SECRETS_SPACE,
        path: "vault/secrets/scoped/listen/API_KEY",
        abilities: ["tinycloud.kv/read"],
        severity: "standard",
      }),
      appScopedSecret: { secretName: "API_KEY", scope: "listen" },
    };
    const stmt = buildStatement(grant);
    expect(stmt.primaryText).not.toContain("app secret");
    expect(stmt.primaryText).toBe("Perform tinycloud.kv/read on tinycloud.kv");
  });

  it("stamped appScopedSecret with kv/get short-form → literal fallback", () => {
    // The bare `kv/get` short-form is not in the canonical allowlist
    // (which requires the fully-qualified `tinycloud.kv/get`). This
    // matches the annotator's proof-side check.
    const grant: CapabilityGrant = {
      ...makeGrant({
        family: "secret-read",
        service: "tinycloud.kv",
        space: SECRETS_SPACE,
        path: "vault/secrets/scoped/listen/API_KEY",
        abilities: ["kv/get"],
        severity: "standard",
      }),
      appScopedSecret: { secretName: "API_KEY", scope: "listen" },
    };
    const stmt = buildStatement(grant);
    expect(stmt.primaryText).not.toContain("app secret");
  });

  it("stamped appScopedSecret with tinycloud.kv/GET (uppercase) → literal fallback", () => {
    const grant: CapabilityGrant = {
      ...makeGrant({
        family: "secret-read",
        service: "tinycloud.kv",
        space: SECRETS_SPACE,
        path: "vault/secrets/scoped/listen/API_KEY",
        abilities: ["tinycloud.kv/GET"],
        severity: "standard",
      }),
      appScopedSecret: { secretName: "API_KEY", scope: "listen" },
    };
    const stmt = buildStatement(grant);
    expect(stmt.primaryText).not.toContain("app secret");
  });

  it("stamped appScopedSecret with canonical tinycloud.kv/get → friendly copy (regression)", () => {
    // Happy path: the canonical wire ability must still render the
    // friendly copy so we haven't over-blocked legitimate annotations.
    const grant: CapabilityGrant = {
      ...makeGrant({
        family: "secret-read",
        service: "tinycloud.kv",
        space: SECRETS_SPACE,
        path: "vault/secrets/scoped/listen/API_KEY",
        abilities: ["tinycloud.kv/get"],
        severity: "standard",
      }),
      appScopedSecret: { secretName: "API_KEY", scope: "listen" },
    };
    expect(buildStatement(grant).primaryText).toBe(
      "Read the app secret API_KEY",
    );
  });

  it("stamped appScopedSecret with mixed [get, peek] → literal fallback", () => {
    const grant: CapabilityGrant = {
      ...makeGrant({
        family: "secret-read",
        service: "tinycloud.kv",
        space: SECRETS_SPACE,
        path: "vault/secrets/scoped/listen/API_KEY",
        abilities: ["tinycloud.kv/get", "tinycloud.kv/peek"],
        severity: "standard",
      }),
      appScopedSecret: { secretName: "API_KEY", scope: "listen" },
    };
    const stmt = buildStatement(grant);
    expect(stmt.primaryText).not.toContain("app secret");
  });
});

// ─── Encryption: registered abilities still earn friendly copy ──────────────
describe("buildStatement — encryption catalog: registered abilities preserved", () => {
  it("encryption [network.revoke] explains the known consequence", () => {
    const grant = makeGrant({
      family: "encryption-key",
      service: "tinycloud.encryption",
      path: "health-data",
      abilities: ["tinycloud.encryption/network.revoke"],
      severity: "sensitive",
    });
    const stmt = buildStatement(grant);
    expect(stmt.primaryText).toBe("Disable the decryption network");
  });

  it("encryption [network.create, decrypt] → combined friendly copy", () => {
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

  it("encryption [decrypt] alone → 'Decrypt protected data'", () => {
    const grant = makeGrant({
      family: "encryption-decrypt",
      service: "tinycloud.encryption",
      path: "health-data",
      abilities: ["tinycloud.encryption/decrypt"],
      severity: "sensitive",
    });
    expect(buildStatement(grant).primaryText).toBe("Decrypt protected data");
  });
});
