// KV and SQL grants on the signer's own plainly named space (Inbox's
// `messages`) read in plain words that name it (TC-2232). A
// `urn:tinycloud:recipients:` line is not something OpenKey interprets: a
// request carrying one is reviewed exactly as without it, apart from the
// unrecognized-resource warning OpenKey already gives any such line.

import { describe, expect, it } from "bun:test";

import { buildStatements, parseCapabilityReview, type CapabilityReviewModel } from "../src/index.js";
import { INBOX_OWNER, M, inboxAtt, inboxRecipients, inboxSignIn, recipientsResource } from "./fixtures/inbox.js";

function review(message: string, signer: string = INBOX_OWNER): CapabilityReviewModel {
  return parseCapabilityReview({
    message,
    signer: { label: "Managed key", address: signer, chainId: 1, provenance: "managed" },
    editable: true,
    metadataTrust: { status: "unsigned", reason: "no manifest" },
    reason: { text: "", source: "none" },
    requester: {
      displayName: "inbox.tinycloud.xyz",
      verifiedOrigin: "https://inbox.tinycloud.xyz",
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

const rows = (model: CapabilityReviewModel) =>
  model.permissions.flatMap((grant) => buildStatements(grant).map((statement) => ({ grant, statement })));
const messagesRows = (model: CapabilityReviewModel) =>
  rows(model).filter(({ grant }) => grant.space === M && (grant.service === "tinycloud.kv" || grant.service === "tinycloud.sql"));

describe("the Inbox sign-in rows", () => {
  it("render with no fallback row, first setup included, and name the messages space", () => {
    for (const firstSetup of [false, true]) {
      const model = review(inboxSignIn({ att: inboxAtt({ firstSetup }) }));
      expect(rows(model).filter(({ statement }) => statement.literalEscaped === true).map(({ statement }) => statement.primaryText)).toEqual([]);
      const messages = messagesRows(model);
      expect([...new Set(messages.map(({ statement }) => statement.primaryText))].sort()).toEqual([
        "Edit and delete your messages tables",
        "Read and change your messages data",
        "Read, change and delete your messages data",
      ]);
      expect(messages.every(({ grant }) => grant.family === "own-app-data" && grant.severity === "standard")).toBe(true);
    }
    const hosting = rows(review(inboxSignIn({ att: inboxAtt({ firstSetup: true }) }))).filter(({ grant }) => grant.service === "tinycloud.space");
    expect(hosting.map(({ statement }) => statement.primaryText)).toEqual(["Create a new TinyCloud space", "Create a new TinyCloud space"]);
  });

  it("render the same grants on another user's messages space as another user's data, unnamed and unrecognized", () => {
    const messages = messagesRows(review(inboxSignIn(), "0x2222222222222222222222222222222222222222"));
    expect(messages.length).toBeGreaterThan(0);
    expect(messages.every(({ grant }) => grant.family === "unknown" && grant.ownedBySelf === false)).toBe(true);
    expect([...new Set(messages.map(({ statement }) => statement.primaryText))]).toEqual(["Read, change and delete another user's data"]);
  });
});

describe("a urn:tinycloud:recipients: line", () => {
  // The Inbox plan's declaration, and one that is not even base64url.
  const lines = [recipientsResource({ v: 1, recipients: inboxRecipients() }), "urn:tinycloud:recipients:%%%"];

  it("changes nothing in the review but the warning any unrecognized resource gets", () => {
    const without = review(inboxSignIn());
    for (const line of lines) {
      const withLine = review(inboxSignIn({ declarations: [line] }));
      // Same model shape: nothing new is parsed, checked or shown.
      expect(Object.keys(withLine).sort()).toEqual(Object.keys(without).sort());
      expect(withLine.protocol).toBe("tinycloud-siwe-recap");
      expect(withLine.permissions).toEqual(without.permissions);
      expect(withLine.permissions.map((grant) => buildStatements(grant))).toEqual(without.permissions.map((grant) => buildStatements(grant)));
      // Still narrowable: the same actions stay editable.
      expect(withLine.permissions.flatMap((grant) => grant.actions).filter((action) => action.editable).length).toBeGreaterThan(0);
      // The only difference is OpenKey's existing warning for a resource it cannot read as a grant.
      expect(without.parseWarnings).toEqual([]);
      expect(withLine.parseWarnings.map((warning) => warning.code)).toEqual(["malformed-space"]);
      expect(withLine.parseWarnings[0]!.message).toContain("urn:tinycloud:recipients:");
    }
  });
});
