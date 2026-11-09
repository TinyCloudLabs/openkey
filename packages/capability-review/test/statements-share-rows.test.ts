// Share-style approval rows. Three grants get dedicated rows on exact wire
// tuples only: the sender's sharing-history KV prefix, the recipient's
// files-for-you mailbox, and the capabilities read. A KV `del` inside one
// app folder gets its own row naming the folder. Every test asserts
// classification and row structure (family, severity, which shapes match and
// which fall through), never pinned sentences.

import { describe, expect, it } from "bun:test";

import {
  CAPABILITIES_READ_STATEMENT,
  FILES_FOR_YOU_STATEMENT,
  SENDER_HISTORY_STATEMENT,
  appFolderDeleteStatement,
  buildStatements,
  buildSummaryStatements,
  defaultSelection,
  parseCapabilityReview,
  type CapabilityGrant,
  type CapabilityReviewModel,
} from "../src/index.js";
import {
  FIXTURE_META,
  makeRecapResource,
  siweWithResources,
} from "./fixtures/index.js";

const SIGNER = FIXTURE_META.address;
const CHAIN = FIXTURE_META.chainId;
const OTHER = "0x2222222222222222222222222222222222222222";
const ownSpace = (name: string) =>
  `tinycloud:pkh:eip155:${CHAIN}:${SIGNER}:${name}`;
const otherSpace = (name: string) =>
  `tinycloud:pkh:eip155:${CHAIN}:${OTHER}:${name}`;
const APPLICATIONS = ownSpace("applications");
const FILES_FOR_YOU = ownSpace("files-for-you");
const SENDER_HISTORY = `${APPLICATIONS}/kv/vault/sender-history/v2/records/`;
const MAILBOX = `${FILES_FOR_YOU}/kv/v1/`;
const MAILBOX_CAPS = `${FILES_FOR_YOU}/capabilities`;
const kv = (verb: string) => `tinycloud.kv/${verb}`;

function modelFor(att: Record<string, string[]>): CapabilityReviewModel {
  return parseCapabilityReview({
    message: siweWithResources([
      makeRecapResource(
        Object.fromEntries(
          Object.entries(att).map(([resource, abilities]) => [
            resource,
            Object.fromEntries(abilities.map((ability) => [ability, [{}]])),
          ]),
        ),
      ),
    ]),
    signer: {
      label: "Key",
      address: SIGNER,
      chainId: CHAIN,
      provenance: "managed",
    },
    editable: true,
    metadataTrust: { status: "unsigned", reason: "no manifest" },
    reason: { text: "", source: "none" },
    requester: {
      displayName: "share.tinycloud.xyz",
      verifiedOrigin: "https://share.tinycloud.xyz",
      appId: null,
      manifestName: null,
      manifestNameProvenance: "none",
      manifestId: null,
      manifestIdProvenance: "none",
      manifestDigest: null,
      domainWarning: false,
      originWarning: false,
    },
    requesterAddress: null,
    requesterVerified: false,
  });
}

function grantFor(att: Record<string, string[]>): CapabilityGrant {
  const grants = modelFor(att).permissions;
  if (grants.length !== 1) throw new Error("expected exactly one grant");
  return grants[0]!;
}

function summaryRows(model: CapabilityReviewModel) {
  const selection = defaultSelection(model);
  const selected = model.permissions.flatMap((grant) => {
    const actions = grant.actions.filter((action) => selection.has(action.id));
    return actions.length > 0 ? [{ ...grant, actions }] : [];
  });
  return buildSummaryStatements(selected);
}

describe("sender-history grant", () => {
  const verbs = [kv("get"), kv("list"), kv("put"), kv("del")];

  it("labels the exact v2 records prefix at standard severity", () => {
    const grant = grantFor({ [SENDER_HISTORY]: verbs });
    expect(grant.family).toBe("own-app-data");
    expect(grant.displayLabel).toBe(SENDER_HISTORY_STATEMENT);
    expect(grant.severity).toBe("standard");
    const rows = buildStatements(grant);
    expect(rows).toHaveLength(1);
    expect(rows[0]!.primaryText).toBe(SENDER_HISTORY_STATEMENT);
    expect(rows[0]!.literalEscaped).toBeUndefined();
  });

  it.each([
    ["a subset", [kv("get"), kv("list"), kv("put")]],
    ["an extra verb", [...verbs, kv("metadata")]],
    ["the deprecated delete alias", [kv("get"), kv("list"), kv("put"), kv("delete")]],
  ])("does not label %s of the verb set", (_name, abilities) => {
    const grant = grantFor({ [SENDER_HISTORY]: abilities });
    expect(grant.displayLabel).not.toBe(SENDER_HISTORY_STATEMENT);
    expect(buildStatements(grant).some((row) => row.primaryText === SENDER_HISTORY_STATEMENT)).toBe(false);
  });

  it.each([
    ["the broader vault/ prefix", `${APPLICATIONS}/kv/vault/`],
    ["the v1 records prefix", `${APPLICATIONS}/kv/vault/sender-history/v1/records/`],
    ["a sibling v2 path", `${APPLICATIONS}/kv/vault/sender-history/v2/other/`],
    ["the prefix itself", `${APPLICATIONS}/kv/vault/sender-history/v2/records`],
  ])("does not label %s", (_name, resource) => {
    const grant = grantFor({ [resource]: verbs });
    expect(grant.displayLabel).not.toBe(SENDER_HISTORY_STATEMENT);
    expect(buildStatements(grant).some((row) => row.primaryText === SENDER_HISTORY_STATEMENT)).toBe(false);
  });

  it("does not label the grant on another user's applications space", () => {
    const grant = grantFor({ [`${otherSpace("applications")}/kv/vault/sender-history/v2/records/`]: verbs });
    expect(grant.family).toBe("cross-app-data");
    expect(grant.displayLabel).not.toBe(SENDER_HISTORY_STATEMENT);
  });
});

describe("files-for-you grant", () => {
  const verbs = [kv("get"), kv("list"), kv("put")];

  it("labels the exact v1/ shape and keeps the Sensitive severity it had", () => {
    const grant = grantFor({ [MAILBOX]: verbs });
    expect(grant.family).toBe("unknown");
    expect(grant.displayLabel).toBe(FILES_FOR_YOU_STATEMENT);
    expect(grant.severity).toBe("sensitive");
    const rows = buildStatements(grant);
    expect(rows).toHaveLength(1);
    expect(rows[0]!.primaryText).toBe(FILES_FOR_YOU_STATEMENT);
    expect(rows[0]!.literalEscaped).toBeUndefined();
  });

  it.each([
    ["a missing verb", [kv("get"), kv("list")]],
    ["an extra verb", [...verbs, kv("del")]],
    ["path v1 without the slash", `${FILES_FOR_YOU}/kv/v1`],
    ["another path", `${FILES_FOR_YOU}/kv/v2/`],
    ["the whole space", `${FILES_FOR_YOU}/kv/`],
  ])("stays an unrecognized literal row for %s", (_name, resourceOrVerbs) => {
    const att = Array.isArray(resourceOrVerbs)
      ? { [MAILBOX]: resourceOrVerbs }
      : { [resourceOrVerbs as string]: verbs };
    const grant = grantFor(att);
    expect(grant.displayLabel).not.toBe(FILES_FOR_YOU_STATEMENT);
    expect(buildStatements(grant).every((row) => row.literalEscaped === true)).toBe(true);
  });

  it("keeps another user's files-for-you space unrecognized and sensitive", () => {
    const grant = grantFor({ [`${otherSpace("files-for-you")}/kv/v1/`]: verbs });
    expect(grant.family).toBe("unknown");
    expect(grant.displayLabel).not.toBe(FILES_FOR_YOU_STATEMENT);
    expect(grant.severity).toBe("sensitive");
    expect(buildStatements(grant).every((row) => row.literalEscaped === true)).toBe(true);
  });
});

describe("capabilities read grant", () => {
  it("renders the granted-permissions sentence at standard severity on the share space", () => {
    const grant = grantFor({ [MAILBOX_CAPS]: ["tinycloud.capabilities/read"] });
    expect(grant.family).toBe("bootstrap-capabilities");
    expect(grant.severity).toBe("standard");
    const rows = buildStatements(grant);
    expect(rows).toHaveLength(1);
    expect(rows[0]!.primaryText).toBe(CAPABILITIES_READ_STATEMENT);
  });

  it("renders the same sentence wherever a pure capabilities read lands", () => {
    const grant = grantFor({ [`${ownSpace("default")}/capabilities`]: ["tinycloud.capabilities/read"] });
    expect(buildStatements(grant).map((row) => row.primaryText)).toEqual([CAPABILITIES_READ_STATEMENT]);
  });
});

describe("KV delete inside one app folder", () => {
  const FOLDER = "xyz.tinycloud.share";
  const FOLDER_RESOURCE = `${APPLICATIONS}/kv/${FOLDER}/`;

  it("gives a del-only grant one row naming the folder in code style", () => {
    const grant = grantFor({ [FOLDER_RESOURCE]: [kv("del")] });
    expect(grant.family).toBe("own-app-data");
    expect(grant.severity).toBe("standard");
    const rows = buildStatements(grant);
    expect(rows).toHaveLength(1);
    expect(rows[0]!.primaryText).toBe(appFolderDeleteStatement(FOLDER));
    expect(rows[0]!.codeSpans).toBe(true);
    expect(rows[0]!.literalEscaped).toBeUndefined();
  });

  it("splits a mixed grant into the app-data row plus one delete row", () => {
    const grant = grantFor({ [FOLDER_RESOURCE]: [kv("get"), kv("put"), kv("del")] });
    const rows = buildStatements(grant);
    expect(rows).toHaveLength(2);
    expect(rows[0]!.primaryText).not.toBe(appFolderDeleteStatement(FOLDER));
    expect(rows[1]!.primaryText).toBe(appFolderDeleteStatement(FOLDER));
    expect(rows[1]!.codeSpans).toBe(true);
  });

  it("keeps one row when the grant cannot delete", () => {
    const grant = grantFor({ [FOLDER_RESOURCE]: [kv("get"), kv("put")] });
    const rows = buildStatements(grant);
    expect(rows).toHaveLength(1);
    expect(rows[0]!.primaryText).not.toContain(FOLDER);
    expect(rows[0]!.codeSpans).toBeUndefined();
  });

  it("names a different folder in its own row (one row per folder grant)", () => {
    const model = modelFor({
      [FOLDER_RESOURCE]: [kv("del")],
      [`${APPLICATIONS}/kv/xyz.qa.p17.grant/`]: [kv("del")],
    });
    const rows = model.permissions.flatMap((grant) => buildStatements(grant));
    expect(rows).toHaveLength(2);
    const texts = rows.map((row) => row.primaryText);
    expect(texts).toContain(appFolderDeleteStatement(FOLDER));
    expect(texts).toContain(appFolderDeleteStatement("xyz.qa.p17.grant"));
  });

  it.each([
    ["a dotless folder", `${APPLICATIONS}/kv/chat/`],
    ["a whole-space grant", `${APPLICATIONS}/kv/`],
    ["the sender-history prefix", SENDER_HISTORY],
  ])("does not name a folder for %s", (_name, resource) => {
    const grant = grantFor({ [resource]: [kv("get"), kv("del")] });
    const rows = buildStatements(grant);
    expect(rows).toHaveLength(1);
    expect(rows.every((row) => !row.primaryText.includes("associated with"))).toBe(true);
  });

  it("does not name a folder on another user's applications space", () => {
    const grant = grantFor({ [`${otherSpace("applications")}/kv/${FOLDER}/`]: [kv("del")] });
    const rows = buildStatements(grant);
    expect(rows).toHaveLength(1);
    expect(rows[0]!.primaryText).not.toContain("associated with");
    expect(rows[0]!.primaryText).not.toContain(`\`${FOLDER}\``);
  });

  it("leaves SQL delete wording on app folders alone", () => {
    const grant = grantFor({
      [`${APPLICATIONS}/sql/${FOLDER}`]: ["tinycloud.sql/read", "tinycloud.sql/write"],
    });
    const rows = buildStatements(grant);
    expect(rows).toHaveLength(1);
    expect(rows[0]!.primaryText).not.toContain("associated with");
    expect(rows[0]!.primaryText).toContain(FOLDER);
  });
});

describe("the Share request as a whole", () => {
  it("shows the three dedicated rows with their severities", () => {
    const model = modelFor({
      [SENDER_HISTORY]: [kv("get"), kv("list"), kv("put"), kv("del")],
      [MAILBOX_CAPS]: ["tinycloud.capabilities/read"],
      [MAILBOX]: [kv("get"), kv("list"), kv("put")],
      [`${APPLICATIONS}/kv/xyz.tinycloud.share/`]: [kv("get"), kv("put"), kv("del")],
    });
    const rows = summaryRows(model);
    const byText = new Map(rows.map((row) => [row.primaryText, row.severity]));
    expect(byText.get(SENDER_HISTORY_STATEMENT)).toBe("standard");
    expect(byText.get(CAPABILITIES_READ_STATEMENT)).toBe("standard");
    expect(byText.get(FILES_FOR_YOU_STATEMENT)).toBe("sensitive");
    expect(byText.get(appFolderDeleteStatement("xyz.tinycloud.share"))).toBe("standard");
  });
});
