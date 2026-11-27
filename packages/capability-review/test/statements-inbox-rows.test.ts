import { describe, expect, it } from "bun:test";

import {
  buildStatements,
  buildSummaryStatements,
  classifyRecapEntry,
  defaultSelection,
  parseCapabilityReview,
} from "../src/index.js";
import { FIXTURE_META, makeRecapResource, siweWithResources } from "./fixtures/index.js";

const { address, chainId } = FIXTURE_META;
const SPACE_PREFIX = `tinycloud:pkh:eip155:${chainId}:${address}`;
const MESSAGES = `${SPACE_PREFIX}:messages`;
const APPLICATIONS = `${SPACE_PREFIX}:applications`;
const OTHER_MESSAGES = `tinycloud:pkh:eip155:${chainId}:0x2222222222222222222222222222222222222222:messages`;
const OTHER_CHAIN_MESSAGES = `tinycloud:pkh:eip155:${chainId + 1}:${address}:messages`;
const ORIGIN = "https://inbox.tinycloud.xyz";
const MEDIA = "xyz.tinycloud.inbox/media/";
const DB = "xyz.tinycloud.inbox/db/";
const TRIAGE = "xyz.tinycloud.inbox/triage";
const GET = "tinycloud.kv/get";
const READ = "tinycloud.sql/read";
const KV_FALLBACK = "Unrecognized key-value data";
const SQL_FALLBACK = "Unrecognized SQL data";

const inboxGrants = [
  { target: `kv/${MEDIA}`, abilities: [GET], text: "Read your Inbox attachments and message text" },
  { target: `sql/${DB}`, abilities: [READ], text: "Read your Inbox mail and messages" },
  { target: `sql/${TRIAGE}`, abilities: [READ], text: "Read how Inbox sorted your messages" },
];

function review(grants: Record<string, string[]>, caveats: unknown[] = [{}]) {
  const att = Object.fromEntries(
    Object.entries(grants).map(([resource, abilities]) => [
      resource,
      Object.fromEntries(abilities.map((ability) => [ability, caveats])),
    ]),
  );
  return parseCapabilityReview({
    message: siweWithResources([makeRecapResource(att)], {
      domain: "inbox.tinycloud.xyz",
      issuedAt: "2026-11-23T12:00:00.000Z",
      expirationTime: "2026-11-23T13:00:00.000Z",
    }),
    signer: { label: "Key", address, chainId, provenance: "managed" },
    editable: true,
    metadataTrust: { status: "unsigned", reason: "no manifest" },
    reason: { text: "", source: "none" },
    requester: {
      displayName: "inbox.tinycloud.xyz",
      verifiedOrigin: ORIGIN,
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
}

describe("Inbox approval rows", () => {
  it.each(inboxGrants)("names the exact $target grant at Attention", ({ target, abilities, text }) => {
    const { permissions: [grant] } = review({ [`${MESSAGES}/${target}`]: abilities });
    expect(grant).toMatchObject({
      family: "unknown",
      displayLabel: text,
      severity: "attention",
      ownedBySelf: true,
    });
    const rows = buildStatements(grant!);
    expect(rows.map(({ primaryText }) => primaryText)).toEqual([text]);
    expect(rows[0]!.literalEscaped).toBeUndefined();
  });

  it.each([
    ["a KV metadata grant", MESSAGES, `kv/${MEDIA}`, ["tinycloud.kv/metadata"], KV_FALLBACK, "attention"],
    ["KV get plus metadata", MESSAGES, `kv/${MEDIA}`, [GET, "tinycloud.kv/metadata"], KV_FALLBACK, "attention"],
    ["KV get plus put", MESSAGES, `kv/${MEDIA}`, [GET, "tinycloud.kv/put"], KV_FALLBACK, "sensitive"],
    ["KV get plus del", MESSAGES, `kv/${MEDIA}`, [GET, "tinycloud.kv/del"], KV_FALLBACK, "sensitive"],
    ["media without a trailing slash", MESSAGES, `kv/${MEDIA.slice(0, -1)}`, [GET], KV_FALLBACK, "attention"],
    ["a child of media", MESSAGES, `kv/${MEDIA}images/`, [GET], KV_FALLBACK, "attention"],
    ["the whole KV space", MESSAGES, "kv", [GET], KV_FALLBACK, "attention"],
    ["another user's media", OTHER_MESSAGES, `kv/${MEDIA}`, [GET], KV_FALLBACK, "attention"],
    ["media on another chain", OTHER_CHAIN_MESSAGES, `kv/${MEDIA}`, [GET], KV_FALLBACK, "attention"],
    ["a different space name", `${SPACE_PREFIX}:Messages`, `kv/${MEDIA}`, [GET], KV_FALLBACK, "attention"],
    ["a missing KV resource service", MESSAGES, `/${MEDIA}`, [GET], KV_FALLBACK, "attention"],
    ["SQL read plus write", MESSAGES, `sql/${DB}`, [READ, "tinycloud.sql/write"], SQL_FALLBACK, "sensitive"],
    ["SQL write only", MESSAGES, `sql/${TRIAGE}`, ["tinycloud.sql/write"], SQL_FALLBACK, "sensitive"],
    ["SQL select", MESSAGES, `sql/${DB}`, ["tinycloud.sql/select"], SQL_FALLBACK, "attention"],
    ["db without a trailing slash", MESSAGES, `sql/${DB.slice(0, -1)}`, [READ], SQL_FALLBACK, "attention"],
    ["triage with a trailing slash", MESSAGES, `sql/${TRIAGE}/`, [READ], SQL_FALLBACK, "attention"],
    ["another SQL path", MESSAGES, "sql/xyz.tinycloud.inbox/other/", [READ], SQL_FALLBACK, "attention"],
    ["another user's db", OTHER_MESSAGES, `sql/${DB}`, [READ], SQL_FALLBACK, "attention"],
    ["another user's triage", OTHER_MESSAGES, `sql/${TRIAGE}`, [READ], SQL_FALLBACK, "attention"],
    ["db on another chain", OTHER_CHAIN_MESSAGES, `sql/${DB}`, [READ], SQL_FALLBACK, "attention"],
    ["triage on another chain", OTHER_CHAIN_MESSAGES, `sql/${TRIAGE}`, [READ], SQL_FALLBACK, "attention"],
  ] as const)("keeps %s unrecognized", (_name, space, target, abilities, fallback, severity) => {
    const { permissions: [grant] } = review({ [`${space}/${target}`]: [...abilities] });
    expect(grant).toMatchObject({ family: "unknown", displayLabel: fallback, severity });
    expect(buildStatements(grant!).map(({ literalEscaped }) => literalEscaped)).toEqual([true]);
  });

  it.each(inboxGrants)("keeps caveated $target unrecognized", ({ target, abilities }) => {
    const displayLabel = target.startsWith("kv/") ? KV_FALLBACK : SQL_FALLBACK;
    for (const caveats of [[{ limit: 1 }], [{ ownerFullAccess: true }]]) {
      const { permissions: [grant] } = review({ [`${MESSAGES}/${target}`]: abilities }, caveats);
      expect(grant).toMatchObject({ family: "unknown", displayLabel, severity: "attention" });
      expect(buildStatements(grant!).map(({ literalEscaped }) => literalEscaped)).toEqual([true]);
    }
  });

  it.each(inboxGrants)("accepts an empty caveat list for $target", ({ target, abilities, text }) => {
    const { permissions: [grant] } = review({ [`${MESSAGES}/${target}`]: abilities }, []);
    expect(grant?.displayLabel).toBe(text);
    expect(buildStatements(grant!).map(({ primaryText }) => primaryText)).toEqual([text]);
  });

  it.each(inboxGrants)("requires proof of ownership for $target", ({ target, abilities }) => {
    const slash = target.indexOf("/");
    const service = `tinycloud.${target.slice(0, slash)}`;
    const path = target.slice(slash + 1);
    const displayLabel = service === "tinycloud.kv" ? KV_FALLBACK : SQL_FALLBACK;
    const entry = { service, path, actions: abilities, caveatsByAbility: { [abilities[0]!]: [{}] } };
    expect(classifyRecapEntry({ ...entry, space: MESSAGES, signerChainId: chainId })).toEqual({
      family: "unknown",
      displayLabel,
    });
    expect(classifyRecapEntry({ ...entry, space: MESSAGES, signerAddress: address })).toEqual({
      family: "unknown",
      displayLabel,
    });
    expect(classifyRecapEntry({ ...entry, space: "messages", signerAddress: address, signerChainId: chainId })).toEqual({
      family: "unknown",
      displayLabel,
    });
  });

  it("shows three distinct Attention rows alongside the standard app data and permission check", () => {
    const appPath = "xyz.tinycloud.tinyapps.inbox/";
    const model = review({
      ...Object.fromEntries(inboxGrants.map(({ target, abilities }) => [`${MESSAGES}/${target}`, abilities])),
      [MESSAGES]: ["tinycloud.capabilities/read"],
      [`${APPLICATIONS}/kv/${appPath}`]: ["get", "put", "list", "del", "metadata"].map((verb) => `tinycloud.kv/${verb}`),
      [`${APPLICATIONS}/sql/${appPath}`]: [READ, "tinycloud.sql/write"],
    });
    expect(model.protocol).toBe("tinycloud-siwe-recap");
    expect(model.parseWarnings).toEqual([]);

    const selection = defaultSelection(model);
    const summary = buildSummaryStatements(model.permissions.map((grant) => ({
      ...grant,
      actions: grant.actions.filter((action) => selection.has(action.id)),
    })));
    expect(summary.filter(({ severity }) => severity === "attention").map(({ primaryText, unmapped }) => ({
      primaryText,
      unmapped,
    }))).toEqual(inboxGrants.map(({ text }) => ({ primaryText: text, unmapped: false })));
    expect(summary.every(({ severity, unmapped }) => severity !== "sensitive" && !unmapped)).toBe(true);
    expect(model.permissions.filter(({ space }) => space === APPLICATIONS)).toMatchObject([
      { family: "own-app-data", displayLabel: "Application data", severity: "standard" },
      { family: "own-app-data", displayLabel: "Application data", severity: "standard" },
    ]);
    expect(model.permissions.find(({ service }) => service === "tinycloud.capabilities")).toMatchObject({
      family: "bootstrap-capabilities",
      displayLabel: "Permission check: messages",
      severity: "standard",
    });
  });
});
