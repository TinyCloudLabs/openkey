// Sol post-rejection follow-up: fail-closed regression tests for the two
// friendly-statement gaps identified in the iteration-2 review.
//
// Behavior 1 (encryption/network.revoke) — a revoke-only grant has a
// deterministic product consequence and earns the friendly statement
// "Disable the decryption network". A grant that mixes revoke with any
// other encryption action still fails closed to the literal rendering so
// no authority is hidden by a partial summary.
//
// Behavior 2 (unknown-service app-data) — `buildStatement`'s app-data
// family branch previously fired friendly "Read this app's data" /
// "Update data outside this app" copy for any grant whose family was
// `own-app-data` / `cross-app-data`, without checking the service. The
// classifier only stamps that family on KV / SQL grants today, but
// `buildStatement` must uphold that invariant so a future classifier
// change (or a fixture built by a caller) cannot smuggle an
// unknown-service grant into friendly copy. Fail closed for any service
// outside the KV / SQL recognized set — the grant renders the literal
// service/resource/actions instead.

import { describe, expect, it } from "bun:test";
import {
  buildStatement,
  type CapabilityAction,
  type CapabilityGrant,
} from "../src/index.js";

const ACCOUNT = "0x1111111111111111111111111111111111111111";
const DEFAULT_SPACE = `tinycloud:pkh:eip155:1:${ACCOUNT}:default`;

interface GrantInput {
  family: CapabilityGrant["family"];
  service: string;
  space?: string;
  path?: string;
  abilities: string[];
  severity?: CapabilityGrant["severity"];
  ownedBySelf?: boolean;
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
    actions,
  };
}

// ─── Behavior 1: network.revoke has an exact, fail-closed mapping ──────

describe("buildStatement — encryption network.revoke", () => {
  it("[network.revoke] alone explains the consequence", () => {
    const grant = makeGrant({
      family: "encryption-key",
      service: "tinycloud.encryption",
      path: "health-data",
      abilities: ["tinycloud.encryption/network.revoke"],
      severity: "sensitive",
    });
    const stmt = buildStatement(grant);
    expect(stmt.primaryText).toBe("Disable the decryption network");
    expect(stmt.primaryText).not.toBe("Decrypt protected data");
    expect(stmt.service).toBe("tinycloud.encryption");
    // The resource must be preserved verbatim as well.
    expect(stmt.resource).toBe(`${DEFAULT_SPACE}/health-data`);
  });

  it("[decrypt, network.revoke] renders the literal fallback (revoke not swallowed)", () => {
    // The prior behavior rendered this as "Decrypt protected data",
    // silently dropping the revoke authority. Fail closed so the
    // operator sees BOTH abilities.
    const grant = makeGrant({
      family: "encryption-decrypt",
      service: "tinycloud.encryption",
      path: "health-data",
      abilities: [
        "tinycloud.encryption/decrypt",
        "tinycloud.encryption/network.revoke",
      ],
      severity: "sensitive",
    });
    const stmt = buildStatement(grant);
    expect(stmt.primaryText).toBe(
      "Perform tinycloud.encryption/decrypt, tinycloud.encryption/network.revoke on tinycloud.encryption",
    );
    expect(stmt.primaryText).not.toBe("Decrypt protected data");
    expect(stmt.primaryText).not.toBe(
      "Create a decryption network and decrypt protected data",
    );
    // Every raw ability must appear.
    expect(stmt.primaryText).toContain("tinycloud.encryption/decrypt");
    expect(stmt.primaryText).toContain("tinycloud.encryption/network.revoke");
  });

  it("[network.create, network.revoke] renders the literal fallback (revoke not swallowed)", () => {
    // The prior behavior rendered this as "Create a decryption network"
    // via verbs.onlyCreate — silently dropping the revoke authority.
    const grant = makeGrant({
      family: "encryption-decrypt",
      service: "tinycloud.encryption",
      path: "health-data",
      abilities: [
        "tinycloud.encryption/network.create",
        "tinycloud.encryption/network.revoke",
      ],
      severity: "sensitive",
    });
    const stmt = buildStatement(grant);
    expect(stmt.primaryText).toBe(
      "Perform tinycloud.encryption/network.create, tinycloud.encryption/network.revoke on tinycloud.encryption",
    );
    expect(stmt.primaryText).not.toBe("Create a decryption network");
    expect(stmt.primaryText).not.toBe(
      "Create a decryption network and decrypt protected data",
    );
    expect(stmt.primaryText).toContain("tinycloud.encryption/network.create");
    expect(stmt.primaryText).toContain("tinycloud.encryption/network.revoke");
  });

  it("[decrypt, network.create, network.revoke] renders the literal fallback", () => {
    // The prior behavior rendered this as the combined create+decrypt
    // copy — silently dropping the revoke authority even in the
    // presence of BOTH other registered abilities.
    const grant = makeGrant({
      family: "encryption-decrypt",
      service: "tinycloud.encryption",
      path: "health-data",
      abilities: [
        "tinycloud.encryption/decrypt",
        "tinycloud.encryption/network.create",
        "tinycloud.encryption/network.revoke",
      ],
      severity: "sensitive",
    });
    const stmt = buildStatement(grant);
    expect(stmt.primaryText).toBe(
      "Perform tinycloud.encryption/decrypt, tinycloud.encryption/network.create, tinycloud.encryption/network.revoke on tinycloud.encryption",
    );
    expect(stmt.primaryText).not.toBe(
      "Create a decryption network and decrypt protected data",
    );
    expect(stmt.primaryText).not.toBe("Decrypt protected data");
    expect(stmt.primaryText).not.toBe("Create a decryption network");
    // Every raw ability must appear.
    expect(stmt.primaryText).toContain("tinycloud.encryption/decrypt");
    expect(stmt.primaryText).toContain("tinycloud.encryption/network.create");
    expect(stmt.primaryText).toContain("tinycloud.encryption/network.revoke");
  });

  it("also explains the short-form `encryption/network.revoke` alias", () => {
    const grant = makeGrant({
      family: "encryption-key",
      service: "encryption",
      path: "health-data",
      abilities: ["encryption/network.revoke"],
      severity: "sensitive",
    });
    const stmt = buildStatement(grant);
    expect(stmt.primaryText).toBe("Disable the decryption network");
  });
});

// ─── Behavior 2: unknown-service app-data grants render literal ─────────────

describe("buildStatement — unknown-service app-data fails closed", () => {
  it("own-app-data on an uncatalogued service renders the literal fallback", () => {
    // The friendly "Read this app's data" copy is only truthful for
    // services whose wire abilities we recognize (KV / SQL). An
    // uncatalogued service must fall through to the literal fallback
    // so the operator sees the raw service and abilities.
    const grant = makeGrant({
      family: "own-app-data",
      service: "tinycloud.foo",
      path: "widgets/",
      abilities: ["tinycloud.foo/get"],
    });
    const stmt = buildStatement(grant);
    expect(stmt.primaryText).toBe("Perform tinycloud.foo/get on tinycloud.foo");
    expect(stmt.primaryText).not.toBe("Read this app's data");
    expect(stmt.primaryText).not.toBe("Update this app's data");
    expect(stmt.primaryText).not.toBe("Read and update this app's data");
    expect(stmt.service).toBe("tinycloud.foo");
    expect(stmt.resource).toBe(`${DEFAULT_SPACE}/widgets/`);
  });

  it("cross-app-data on an uncatalogued service renders the literal fallback", () => {
    const grant = makeGrant({
      family: "cross-app-data",
      service: "tinycloud.foo",
      path: "shared/",
      abilities: ["tinycloud.foo/get", "tinycloud.foo/put"],
      ownedBySelf: false,
    });
    const stmt = buildStatement(grant);
    expect(stmt.primaryText).toBe(
      "Perform tinycloud.foo/get, tinycloud.foo/put on tinycloud.foo",
    );
    expect(stmt.primaryText).not.toBe("Read data outside this app");
    expect(stmt.primaryText).not.toBe("Update data outside this app");
    expect(stmt.primaryText).not.toBe("Read and update data outside this app");
    // Every raw ability must appear.
    expect(stmt.primaryText).toContain("tinycloud.foo/get");
    expect(stmt.primaryText).toContain("tinycloud.foo/put");
  });

  it("own-app-data on an uncatalogued service does not leak friendly copy even for a known verb", () => {
    // Extra guard: even when the short verb (`get`) matches a recognized
    // read verb, the whole-grant / app-data gate must still fail because
    // the service is uncatalogued. The friendly own-app-data copy must
    // not fire.
    const grant = makeGrant({
      family: "own-app-data",
      service: "tinycloud.notes",
      path: "notes/",
      abilities: ["tinycloud.notes/get"],
    });
    const stmt = buildStatement(grant);
    expect(stmt.primaryText).toBe(
      "Perform tinycloud.notes/get on tinycloud.notes",
    );
    expect(stmt.primaryText).not.toBe("Read this app's data");
  });
});

// ─── Behavior 3 (preserve): known KV / SQL / encryption copy unchanged ──────

describe("buildStatement — preserved known copy", () => {
  it('own-app-data on tinycloud.kv yields "Read application data"', () => {
    const grant = makeGrant({
      family: "own-app-data",
      service: "tinycloud.kv",
      path: "cycle/",
      abilities: ["tinycloud.kv/get"],
    });
    expect(buildStatement(grant).primaryText).toBe("Read application data");
  });

  it("another user's tinycloud.sql data is identified as such", () => {
    const grant = makeGrant({
      family: "cross-app-data",
      service: "tinycloud.sql",
      path: "",
      abilities: ["tinycloud.sql/read", "tinycloud.sql/write"],
      ownedBySelf: false,
    });
    expect(buildStatement(grant).primaryText).toBe(
      "Read and update another user's TinyCloud data",
    );
  });

  it('encryption [decrypt] alone still yields "Decrypt protected data"', () => {
    const grant = makeGrant({
      family: "encryption-decrypt",
      service: "tinycloud.encryption",
      path: "health-data",
      abilities: ["tinycloud.encryption/decrypt"],
      severity: "sensitive",
    });
    expect(buildStatement(grant).primaryText).toBe("Decrypt protected data");
  });

  it('encryption [network.create] yields "Set up encrypted data access"', () => {
    const grant = makeGrant({
      family: "encryption-decrypt",
      service: "tinycloud.encryption",
      path: "health-data",
      abilities: ["tinycloud.encryption/network.create"],
      severity: "sensitive",
    });
    expect(buildStatement(grant).primaryText).toBe(
      "Set up encrypted data access",
    );
  });

  it("encryption [network.create, decrypt] still yields the combined copy", () => {
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
});
