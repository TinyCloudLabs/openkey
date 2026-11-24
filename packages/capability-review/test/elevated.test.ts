import { describe, expect, test } from "bun:test";
import {
  allSecretsCard,
  elevatedActionsOf,
  elevatedCard,
  elevatedDecidedAnnouncement,
  elevatedKindOf,
  elevatedNotApprovedRow,
  elevatedRejectNote,
  elevatedTitle,
  elevatedWhere,
  elevatedWhereText,
  elevatedWholeNote,
  isExactShareKeyGrant,
} from "../src/index";

const OWNER = "did:pkh:eip155:1:0x1111111111111111111111111111111111111111";
const urn = (rest: string) => `urn:tinycloud:encryption:${OWNER}:default${rest}`;
const E = "tinycloud.encryption/";

// The parser's form (space "encryption", path the URN) and the reported one (space the URN, no path) must agree.
const parserForm = (resource: string) => ({ service: "encryption", space: "encryption", path: resource });
const reportedForm = (resource: string) => ({ service: "tinycloud.encryption", space: resource, path: "" });

describe("elevatedKindOf", () => {
  test.each([
    ["decrypt on the whole network", urn(""), `${E}decrypt`, "encryption-network"],
    ["key.create on the whole network", urn(""), `${E}key.create`, "encryption-network"],
    ["decrypt on the share/ prefix", urn("/share/"), `${E}decrypt`, "encryption-keys"],
    ["key.create on a folder", urn("/qa/"), `${E}key.create`, "encryption-keys"],
    ["decrypt on an exact key outside apps/", urn("/secrets/k"), `${E}decrypt`, "encryption-keys"],
    ["the short service and ability names", urn("/qa/"), "encryption/decrypt", "encryption-keys"],
    ["an upper-case verb", urn("/qa/"), `${E}Decrypt`, "encryption-keys"],
    ["key.block on the whole network", urn(""), `${E}key.block`, "encryption-network"],
    ["key.unblock on a folder", urn("/qa/"), `${E}key.unblock`, "encryption-keys"],
    ["key.block on an exact key outside apps/", urn("/share/abc"), `${E}key.block`, "encryption-keys"],
  ])("%s", (_name, resource, ability, kind) => {
    expect(elevatedKindOf(parserForm(resource), ability)).toBe(kind as never);
    expect(elevatedKindOf(reportedForm(resource), ability)).toBe(kind as never);
  });

  test.each([
    ["network.create alone", urn(""), `${E}network.create`],
    ["network.revoke", urn(""), `${E}network.revoke`],
    ["key.delete (refused elsewhere)", urn("/qa/"), `${E}key.delete`],
    ["an app's own keys", urn("/apps/xyz.tinycloud.listen/"), `${E}decrypt`],
    ["an app's own key", urn("/apps/xyz.tinycloud.listen/k"), `${E}key.create`],
    ["an app's own key being blocked", urn("/apps/xyz.tinycloud.listen/k"), `${E}key.block`],
    ["an app's own keys in any case", urn("/Apps/xyz.tinycloud.listen/"), `${E}decrypt`],
  ])("%s needs no extra warning", (_name, resource, ability) => {
    expect(elevatedKindOf(parserForm(resource), ability)).toBeNull();
  });

  test("a non-encryption service or resource is never elevated", () => {
    expect(elevatedKindOf({ service: "kv", space: "tinycloud:pkh:eip155:1:0x1:default", path: "x" }, "tinycloud.kv/get")).toBeNull();
    expect(elevatedKindOf({ service: "kv", space: "encryption", path: urn("") }, `${E}decrypt`)).toBeNull();
    expect(elevatedKindOf({ service: "encryption", space: "tinycloud:pkh:eip155:1:0x1:secrets", path: "x" }, `${E}decrypt`)).toBeNull();
  });
});

describe("elevatedActionsOf", () => {
  test("lists only the extra actions, in order, with the caller's ids", () => {
    const entries = [
      { ...parserForm(urn("")), actions: [`${E}decrypt`, `${E}network.create`] },
      { ...parserForm(urn("/qa/")), actions: [`${E}key.create`, `${E}decrypt`] },
      { ...parserForm(urn("/apps/a.b/")), actions: [`${E}decrypt`] },
      { service: "kv", space: "s", path: "p", actions: ["tinycloud.kv/get"] },
    ];
    const found = elevatedActionsOf(entries, (entry, action) => `${entry.path}|${action}`);
    expect(found.map((item) => item.actionId)).toEqual([
      `${urn("")}|${E}decrypt`,
      `${urn("/qa/")}|${E}key.create`,
      `${urn("/qa/")}|${E}decrypt`,
    ]);
    expect(found.map((item) => item.kind)).toEqual(["encryption-network", "encryption-keys", "encryption-keys"]);
  });
});

describe("elevatedWhere", () => {
  test("is the last folder or key name, never a whole network", () => {
    expect(elevatedWhere(parserForm(urn("/share/")))).toBe("share");
    expect(elevatedWhere(parserForm(urn("/a/b/c")))).toBe("c");
    expect(elevatedWhere(parserForm(urn("")))).toBeNull();
    expect(elevatedWhere({ service: "kv", space: "s", path: "p" })).toBeNull();
  });
});

describe("isExactShareKeyGrant", () => {
  test("an exact share key with decrypt or key.create", () => {
    expect(isExactShareKeyGrant(parserForm(urn("/share/abc")), `${E}decrypt`)).toBe(true);
    expect(isExactShareKeyGrant(parserForm(urn("/share/abc")), `${E}key.create`)).toBe(true);
  });
  test("not the prefix, a longer path, another folder, the network, or another ability", () => {
    expect(isExactShareKeyGrant(parserForm(urn("/share/")), `${E}decrypt`)).toBe(false);
    expect(isExactShareKeyGrant(parserForm(urn("/share/a/b")), `${E}decrypt`)).toBe(false);
    expect(isExactShareKeyGrant(parserForm(urn("/shares/abc")), `${E}decrypt`)).toBe(false);
    expect(isExactShareKeyGrant(parserForm(urn("")), `${E}decrypt`)).toBe(false);
    expect(isExactShareKeyGrant(parserForm(urn("/share/abc")), `${E}key.block`)).toBe(false);
  });
});

// The wording is Monica's; these pin who is named and the parts an owner decides on, not every sentence.
describe("the warning copy", () => {
  test("names the verified site, or 'This request' where nothing is verified", () => {
    expect(elevatedTitle("gk.gbafa.com")).toBe("gk.gbafa.com is asking for more access");
    expect(elevatedTitle(null)).toBe("This request is asking for more access");
    expect(elevatedRejectNote("gk.gbafa.com")).toContain("gk.gbafa.com may not work fully");
    expect(elevatedRejectNote(null)).toContain("This request may not work fully");
    expect(elevatedWholeNote("gk.gbafa.com")).toBe("gk.gbafa.com sent this as one request, so you can approve all of it or none of it.");
  });

  test("Card A: decrypt on the whole network asks to use the master key", () => {
    const card = elevatedCard("encryption-network", { decrypt: true, create: false }, "gk.gbafa.com", elevatedWhereText(null));
    expect(card.heading).toBe("Use your master key to decrypt?");
    expect(card.body).toBe(
      "gk.gbafa.com is asking to use your master key, which can open all your encrypted data. Some apps do this because they don't have app-specific keys.",
    );
  });

  test("whole-network key creation alone says keys are created in your account, and the folder 'both' card joins the two", () => {
    const create = elevatedCard("encryption-network", { decrypt: false, create: true }, "gk.gbafa.com", elevatedWhereText(null));
    expect(create.heading).toBe("Create encryption keys anywhere in your account");
    expect(create.body).toBe("gk.gbafa.com could create new encryption keys anywhere in your account, for as long as this approval lasts.");
    const both = elevatedCard("encryption-keys", { decrypt: true, create: true }, "gk.gbafa.com", elevatedWhereText("share"));
    expect(both.body).toBe(
      "gk.gbafa.com could unlock the encrypted items in a folder named share and create new encryption keys there, for as long as this approval lasts.",
    );
  });

  test("Card B: by action, with the folder named in plain words", () => {
    const where = elevatedWhereText("share");
    expect(where).toBe("a folder named share");
    expect(elevatedCard("encryption-keys", { decrypt: true, create: false }, "x.test", where).heading).toBe("Unlock encrypted items in a folder named share");
    expect(elevatedCard("encryption-keys", { decrypt: false, create: true }, "x.test", where).heading).toBe("Create encryption keys in a folder named share");
    expect(elevatedCard("encryption-keys", { decrypt: true, create: true }, "x.test", where).heading).toBe("Unlock and create encrypted items in a folder named share");
  });

  test("the control card: Sam's example, word for word", () => {
    const card = elevatedCard("encryption-keys", { decrypt: false, create: false, block: true }, "example.com", elevatedWhereText("Shared"));
    expect(card.heading).toBe("Control access to encryption keys in a folder named Shared");
    expect(card.body).toBe(
      "example.com could block encryption keys in a folder named Shared, for as long as this approval lasts. Until the key is unblocked, requests to unlock the items it protects are refused, including your own.",
    );
  });

  test("the control card: the whole account heading, every action the grant carries in order, and the refusal sentence only when blocking is included", () => {
    const network = elevatedCard("encryption-network", { decrypt: true, create: false, block: true, unblock: true }, "example.com", elevatedWhereText(null));
    expect(network.heading).toBe("Control access to encryption keys anywhere in your account");
    expect(network.body.startsWith("example.com could unlock encrypted items and block and unblock encryption keys anywhere in your account, for as long as this approval lasts.")).toBe(true);
    expect(network.body.endsWith("including your own.")).toBe(true);
    const unblock = elevatedCard("encryption-keys", { decrypt: false, create: false, unblock: true }, null, elevatedWhereText("Shared"));
    expect(unblock.body).toBe("This request could unblock encryption keys in a folder named Shared, for as long as this approval lasts.");
    const pair = elevatedCard("encryption-keys", { decrypt: false, create: true, unblock: true }, "x.test", elevatedWhereText("Shared"));
    expect(pair.body).toBe("x.test could create and unblock encryption keys in a folder named Shared, for as long as this approval lasts.");
    const all = elevatedCard("encryption-network", { decrypt: true, create: true, block: true, unblock: true }, null, elevatedWhereText(null));
    expect(all.body.startsWith("This request could unlock encrypted items and create, block and unblock encryption keys anywhere in your account, for as long as this approval lasts.")).toBe(true);
    const both = elevatedCard("encryption-network", { decrypt: false, create: false, block: true, unblock: true }, "example.com", elevatedWhereText(null));
    expect(both.body.startsWith("example.com could block and unblock encryption keys anywhere in your account, for as long as this approval lasts.")).toBe(true);
  });

  test("no card ever says 'until {date}' (the approval can renew)", () => {
    for (const kind of ["encryption-network", "encryption-keys"] as const) {
      for (const abilities of [{ decrypt: true, create: false }, { decrypt: false, create: true }, { decrypt: true, create: true }]) {
        const { body } = elevatedCard(kind, abilities, "x.test", elevatedWhereText("qa"));
        if (!(kind === "encryption-network" && abilities.decrypt)) expect(body).toContain("for as long as this approval lasts");
        expect(body).not.toMatch(/\buntil\b/);
      }
    }
  });

  test("whole-network decrypt: the master-key question, the site in the body, and the cue only for an unverified site", () => {
    const body = "is asking to use your master key, which can open all your encrypted data. Some apps do this because they don't have app-specific keys.";
    const verified = elevatedCard("encryption-network", { decrypt: true, create: false }, "gk.gbafa.com", elevatedWhereText(null));
    expect(verified).toEqual({ heading: "Use your master key to decrypt?", body: `gk.gbafa.com ${body}` });
    const unverified = elevatedCard("encryption-network", { decrypt: true, create: false }, null, elevatedWhereText(null));
    expect(unverified).toEqual({ heading: "Use your master key to decrypt?", body: `This app ${body} OpenKey can't confirm the site.` });
  });

  test("whole-network decrypt with key creation adds one line, and the all-secrets card says the same words", () => {
    const body = "is asking to use your master key, which can open all your encrypted data. Some apps do this because they don't have app-specific keys.";
    const combo = elevatedCard("encryption-network", { decrypt: true, create: true }, "gk.gbafa.com", elevatedWhereText(null));
    expect(combo).toEqual({ heading: "Use your master key to decrypt?", body: `gk.gbafa.com ${body} It can also create encryption keys.` });
    const card = allSecretsCard({ kind: "whole-account", alsoWholeAccount: false }, "gk.gbafa.com");
    expect(card).toEqual({ heading: "Use your master key to decrypt?", body: `gk.gbafa.com ${body}`, cue: null });
    const unverified = allSecretsCard({ kind: "whole-account", alsoWholeAccount: false }, null);
    expect(unverified).toEqual({ heading: "Use your master key to decrypt?", body: `This app ${body}`, cue: "OpenKey can't confirm the site." });
  });

  test("announcements and the review row", () => {
    expect(elevatedDecidedAnnouncement("Use your master key to decrypt?", false, 1)).toBe("Rejected: Use your master key to decrypt. 1 left to decide.");
    expect(elevatedDecidedAnnouncement("Use your master key to decrypt?", true, 0)).toBe("Allowed: Use your master key to decrypt. All decided.");
    expect(elevatedNotApprovedRow("Use your master key to decrypt?")).toBe("Not approved: Use your master key to decrypt");
  });
});
