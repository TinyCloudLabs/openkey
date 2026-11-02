import { describe, expect, it } from "bun:test";
import {
  buildStatement,
  buildStatements,
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
    ownedBySelf: family !== "cross-app-data",
    displayLabel: "App data — cycle/",
    metadataLabel: null,
    // Test grants default to null: no wire-shape mismatch signal on
    // manually-constructed fixtures. See CapabilityGrant.resourceService.
    resourceService: null,
    ...(appScopedSecret ? { appScopedSecret } : {}),
    actions,
  };
}

describe("buildStatement — generic app data", () => {
  it("describes read-only app data without inferring path semantics", () => {
    expect(
      buildStatement(grant("own-app-data", ["tinycloud.kv/get"])).primaryText,
    ).toBe("Read application data");
  });

  it("describes another user's read/write data without a product name", () => {
    expect(
      buildStatement(
        grant("cross-app-data", ["tinycloud.kv/get", "tinycloud.kv/put"]),
      ).primaryText,
    ).toBe("Read and update another user's application data");
  });

  it("uses the exactly proven app-scoped secret name", () => {
    // buildStatement defense-in-depth requires exact service/space/path tuple.
    const scopedGrant: CapabilityGrant = {
      ...grant("secret-read", ["tinycloud.kv/get"], {
        secretName: "GOOGLE_MEET_TOKENS",
        scope: "listen",
      }),
      service: "tinycloud.kv",
      space:
        "tinycloud:pkh:eip155:1:0x1111111111111111111111111111111111111111:secrets",
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
    ).toBe("Unknown action: tinycloud.kv/archive");
  });
});

function sqlGrant(abilities: string[]): CapabilityGrant {
  return { ...grant("own-app-data", abilities), service: "tinycloud.sql" };
}

describe("buildStatements — schema gets its own row", () => {
  it("splits read/write/schema into the read-update row and a schema row", () => {
    const rows = buildStatements(
      sqlGrant(["tinycloud.sql/read", "tinycloud.sql/write", "tinycloud.sql/schema"]),
    );
    expect(rows.map((row) => row.primaryText)).toEqual([
      "Read and update application data",
      "Edit and delete this app's tables",
    ]);
  });

  it("schema-only renders the schema row, not the update copy", () => {
    const rows = buildStatements(sqlGrant(["tinycloud.sql/schema"]));
    expect(rows.map((row) => row.primaryText)).toEqual([
      "Edit and delete this app's tables",
    ]);
  });

  it("an unknown ability keeps the whole grant as one literal row", () => {
    const rows = buildStatements(
      sqlGrant(["tinycloud.sql/read", "tinycloud.sql/exfiltrate", "tinycloud.sql/schema"]),
    );
    expect(rows).toHaveLength(1);
    expect(rows[0]!.literalEscaped).toBe(true);
    expect(rows[0]!.primaryText).toBe(
      "Read, change and delete your data; unknown action: tinycloud.sql/exfiltrate",
    );
  });

  it("buildStatement fails closed on a mixed schema grant instead of dropping schema", () => {
    const stmt = buildStatement(
      sqlGrant(["tinycloud.sql/read", "tinycloud.sql/schema"]),
    );
    expect(stmt.primaryText).toBe(
      "Read, change and delete your data",
    );
  });
});
