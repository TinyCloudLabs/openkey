// TC-3126: the grants of a feed connect step read as sentences derived from
// the exact service, space, path and verb set. Anything else keeps the
// generic rows.

import { describe, expect, it } from "bun:test";

import { buildSummaryStatements, parseCapabilityReview } from "../src/index.js";
import { FIXTURE_META, makeRecapResource, siweWithResources } from "./fixtures/index.js";

const OWNER = FIXTURE_META.address;
const OTHER = "0x2222222222222222222222222222222222222222";
const space = (owner: string, name = "applications") => `tinycloud:pkh:eip155:${FIXTURE_META.chainId}:${owner}:${name}`;

const SQL_ALL = ["tinycloud.sql/read", "tinycloud.sql/write", "tinycloud.sql/schema"];
const HOME_FEED = "xyz.tinycloud.tinychat/home_feed";
const FEED = "xyz.tinycloud.tinychat/feed/";

function rows(resources: Record<string, string[]>): string[] {
  const att = Object.fromEntries(
    Object.entries(resources).map(([resource, abilities]) => [
      resource,
      Object.fromEntries(abilities.map((ability) => [ability, [{}]])),
    ]),
  );
  const model = parseCapabilityReview({
    message: siweWithResources([makeRecapResource(att)]),
    signer: { label: "Signer", address: OWNER, chainId: FIXTURE_META.chainId, provenance: "managed" },
    editable: true,
    metadataTrust: { status: "unsigned", reason: "no manifest" },
    reason: { text: "", source: "none" },
    requester: {
      displayName: "cli.tinycloud.xyz",
      verifiedOrigin: "https://cli.tinycloud.xyz",
      appId: null,
      manifestName: null,
      manifestNameProvenance: "none",
      manifestId: null,
      manifestIdProvenance: "none",
      manifestDigest: null,
      domainWarning: false,
      originWarning: false,
    },
  });
  return buildSummaryStatements(model.permissions).map((row) => row.primaryText);
}

const FEED_ROWS = [
  "Set up and use your TinyCloud One agent list",
  "Set up and use cards and answers in TinyCloud One",
  "Get notified of changes to your TinyCloud One feed",
];

const feedConnect = (owner = OWNER): Record<string, string[]> => ({
  [`${space(owner)}/sql/${HOME_FEED}`]: SQL_ALL,
  [`${space(owner)}/sql/${FEED}`]: SQL_ALL,
  [`${space(owner)}/hooks/sql/${FEED}`]: ["tinycloud.hooks/subscribe"],
});

describe("feed connect grants", () => {
  it("read as one sentence per grant, naming TinyCloud One and saying the tables are set up", () => {
    expect(rows(feedConnect()).sort()).toEqual([...FEED_ROWS].sort());
  });

  it("do not show the generic database rows or the product's wire app id", () => {
    const text = rows(feedConnect()).join("\n");
    expect(text).not.toContain("xyz.tinycloud.tinychat");
    expect(text).not.toContain("Edit and delete this app's tables");
  });

  it("each row stands alone: one grant alone gives only its own sentence", () => {
    expect(rows({ [`${space(OWNER)}/sql/${HOME_FEED}`]: SQL_ALL })).toEqual([FEED_ROWS[0]!]);
    expect(rows({ [`${space(OWNER)}/sql/${FEED}`]: SQL_ALL })).toEqual([FEED_ROWS[1]!]);
    expect(rows({ [`${space(OWNER)}/hooks/sql/${FEED}`]: ["tinycloud.hooks/subscribe"] })).toEqual([FEED_ROWS[2]!]);
  });
});

describe("near misses keep the generic rows", () => {
  const generic = (resources: Record<string, string[]>) => {
    const found = rows(resources);
    for (const sentence of FEED_ROWS) expect(found).not.toContain(sentence);
    return found;
  };

  it("another path: no trailing slash, a sub-path, another app id", () => {
    for (const path of ["xyz.tinycloud.tinychat/feed", "xyz.tinycloud.tinychat/feed/agent", "xyz.tinycloud.other/feed/", "xyz.tinycloud.tinychat/home_feed2"]) {
      expect(generic({ [`${space(OWNER)}/sql/${path}`]: SQL_ALL }).length).toBeGreaterThan(0);
    }
  });

  it("a verb set that is not exactly read, write and schema (no schema, or one extra)", () => {
    generic({ [`${space(OWNER)}/sql/${FEED}`]: ["tinycloud.sql/read", "tinycloud.sql/write"] });
    generic({ [`${space(OWNER)}/sql/${FEED}`]: [...SQL_ALL, "tinycloud.sql/admin"] });
    generic({ [`${space(OWNER)}/hooks/sql/${FEED}`]: ["tinycloud.hooks/subscribe", "tinycloud.hooks/register"] });
  });

  it("another user's space, or a space that is not applications", () => {
    generic(feedConnect(OTHER));
    generic({ [`${space(OWNER, "default")}/sql/${FEED}`]: SQL_ALL });
  });

  it("the same path on another service", () => {
    generic({ [`${space(OWNER)}/kv/${FEED}`]: ["tinycloud.kv/get", "tinycloud.kv/put"] });
    generic({ [`${space(OWNER)}/hooks/${FEED}`]: ["tinycloud.hooks/subscribe"] });
    generic({ [`${space(OWNER)}/sql/sql/xyz.tinycloud.tinychat/feed/`]: SQL_ALL });
  });

  it("the whole applications space keeps the all-databases wording", () => {
    expect(rows({ [`${space(OWNER)}/sql/`]: SQL_ALL }).join("\n")).not.toContain("TinyCloud One");
  });

  it("a feed grant beside an unrelated grant leaves the other row untouched", () => {
    const found = rows({ ...feedConnect(), [`${space(OWNER)}/kv/notes/`]: ["tinycloud.kv/get"] });
    expect(found).toHaveLength(FEED_ROWS.length + 1);
    for (const sentence of FEED_ROWS) expect(found).toContain(sentence);
  });
});
