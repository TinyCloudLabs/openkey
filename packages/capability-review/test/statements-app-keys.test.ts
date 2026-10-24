// Consent copy for encryption keys under `apps/`: one row per ability, the
// approved wording, the key path in monospace, `key.delete` listed but never
// selectable, and the same literal fallback as before for everything else.

import { describe, expect, it } from "bun:test";

import {
  APP_KEY_ACCESS_WITHOUT_EXPIRY,
  FAMILY_LABEL,
  appKeyAccessStatement,
  appKeyNotGrantableStatements,
  buildStatement,
  buildStatements,
  grantIsAppKeyDecrypt,
  grantReachesSecretDataOrDecryption,
  parseCapabilityReview,
  splitStatementCode,
} from "../src/index.js";
import type { CapabilityGrant, SignerInfo } from "../src/index.js";
import type { ParseContext } from "../src/parse.js";
import {
  FIXTURE_META,
  makeRecapResource,
  siweWithResources,
} from "./fixtures/index.js";

const OWNER = `did:pkh:eip155:${FIXTURE_META.chainId}:${FIXTURE_META.address}`;
const urn = (rest: string) => `urn:tinycloud:encryption:${OWNER}:default${rest}`;
const KEY = "/apps/xyz.tinycloud.listen/k";
const PREFIX = "/apps/xyz.tinycloud.listen/";
const E = "tinycloud.encryption/";

const signer: SignerInfo = {
  label: "Test signer",
  address: FIXTURE_META.address,
  chainId: FIXTURE_META.chainId,
  provenance: "managed",
};

function ctx(message: string, selectedActionIds?: string[]): ParseContext {
  return {
    message,
    signer,
    editable: true,
    ...(selectedActionIds ? { selectedActionIds } : {}),
    metadataTrust: { status: "unsigned", reason: "no manifest" },
    reason: { text: "", source: "none" },
    requester: {
      displayName: "listen.tinycloud.xyz",
      verifiedOrigin: "https://listen.tinycloud.xyz",
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
  };
}

function model(resource: string, abilities: string[]) {
  const att = { [resource]: Object.fromEntries(abilities.map((ability) => [ability, [{}]])) };
  return parseCapabilityReview(ctx(siweWithResources([makeRecapResource(att)])));
}

function grantFor(resource: string, abilities: string[]): CapabilityGrant {
  const grant = model(resource, abilities).permissions[0];
  if (!grant) throw new Error("no grant");
  return grant;
}

function rows(resource: string, abilities: string[]): string[] {
  return buildStatements(grantFor(resource, abilities)).map((row) => row.primaryText);
}

describe("one row per ability, exact key", () => {
  it.each([
    ["key.create", "Create the encryption key `apps/xyz.tinycloud.listen/k`."],
    ["decrypt", "Decrypt data locked with the key `apps/xyz.tinycloud.listen/k`."],
    ["key.block", "Block the key `apps/xyz.tinycloud.listen/k` so it can't be used to decrypt."],
    ["key.unblock", "Unblock the key `apps/xyz.tinycloud.listen/k` so it can be used again."],
    ["key.delete", "Delete the key `apps/xyz.tinycloud.listen/k`. Apps can't be given this permission."],
  ])("%s", (ability, text) => {
    expect(rows(urn(KEY), [`${E}${ability}`])).toEqual([text]);
  });
});

describe("one row per ability, prefix", () => {
  it.each([
    ["key.create", "Create new encryption keys under `apps/xyz.tinycloud.listen/`."],
    ["decrypt", "Decrypt data locked with any key under `apps/xyz.tinycloud.listen/`."],
    ["key.block", "Block any key under `apps/xyz.tinycloud.listen/` so it can't be used to decrypt."],
    ["key.unblock", "Unblock any key under `apps/xyz.tinycloud.listen/` so it can be used again."],
  ])("%s", (ability, text) => {
    expect(rows(urn(PREFIX), [`${E}${ability}`])).toEqual([text]);
  });

  it("the prefix keeps its trailing slash", () => {
    expect(rows(urn(PREFIX), [`${E}decrypt`])[0]).toContain("`apps/xyz.tinycloud.listen/`");
  });
});

describe("several abilities on one resource", () => {
  it("are listed separately, in a fixed order, never merged", () => {
    expect(rows(urn(KEY), [`${E}key.unblock`, `${E}decrypt`, `${E}key.create`, `${E}key.block`])).toEqual([
      "Create the encryption key `apps/xyz.tinycloud.listen/k`.",
      "Decrypt data locked with the key `apps/xyz.tinycloud.listen/k`.",
      "Block the key `apps/xyz.tinycloud.listen/k` so it can't be used to decrypt.",
      "Unblock the key `apps/xyz.tinycloud.listen/k` so it can be used again.",
    ]);
  });

  it("the short namespace gets the same rows", () => {
    expect(rows(urn(KEY), ["encryption/key.create", "encryption/decrypt"])).toEqual([
      "Create the encryption key `apps/xyz.tinycloud.listen/k`.",
      "Decrypt data locked with the key `apps/xyz.tinycloud.listen/k`.",
    ]);
  });

  it("an ability that is not one of the five keeps the literal fallback beside the others", () => {
    const result = rows(urn(KEY), [`${E}decrypt`, `${E}key.rotate`]);
    expect(result).toHaveLength(2);
    expect(result[0]).toBe("Decrypt data locked with the key `apps/xyz.tinycloud.listen/k`.");
    expect(result[1]).toStartWith("Perform ");
    expect(result[1]).toContain("key.rotate");
  });

  it("only exact ability names get a sentence", () => {
    const [row] = rows(urn(KEY), [`${E}KEY.CREATE`]);
    expect(row).toStartWith("Perform ");
  });

  it("every row carries codeSpans", () => {
    const entries = buildStatements(grantFor(urn(KEY), [`${E}key.create`, `${E}decrypt`]));
    expect(entries.every((entry) => entry.codeSpans === true)).toBe(true);
  });
});

describe("resources under apps/ that are not valid keys keep the literal fallback", () => {
  it.each([
    ["a capital in the first segment", urn("/Apps/x/y")],
    ["an empty segment", urn("/apps//y")],
    ["two segments", urn("/apps/x")],
    ["apps/ alone", urn("/apps/")],
    ["an upper-case path", urn("/apps/X/y")],
    ["an upper-case URN scheme", `URN:TINYCLOUD:ENCRYPTION:${OWNER}:default/apps/x/y`],
    ["a path of nine segments", urn("/apps/a/b/c/d/e/f/g/h")],
  ])("%s", (_name, resource) => {
    const result = rows(resource, [`${E}decrypt`]);
    expect(result).toHaveLength(1);
    expect(result[0]).toStartWith("Perform ");
  });
});

describe("resources that are not under apps/ are unchanged", () => {
  it("decrypt on another key keeps the neutral sentence", () => {
    expect(rows(urn("/shares/abc"), [`${E}decrypt`])).toEqual(["Decrypt protected data"]);
  });

  it("key.create on another key keeps the literal fallback", () => {
    expect(rows(urn("/secrets/x"), [`${E}key.create`])[0]).toStartWith("Perform ");
  });

  it.each(["/appsx/y/z", "/apps.x/y/z"])("%s is an ordinary key", (rest) => {
    expect(rows(urn(rest), [`${E}decrypt`])).toEqual(["Decrypt protected data"]);
  });

  it("the default network decrypt keeps the default-key statement", () => {
    expect(rows(urn(""), [`${E}decrypt`])[0]).toStartWith("Decrypt anything encrypted with your account's default key");
  });
});

describe("family, label and severity", () => {
  it("is the app-keys family with the approved label", () => {
    const [grant] = model(urn(KEY), [`${E}decrypt`]).permissions;
    expect(grant!.family).toBe("app-keys");
    expect(grant!.displayLabel).toBe("App keys");
    expect(FAMILY_LABEL["app-keys"]).toBe("App keys");
  });

  it.each([
    [[`${E}key.create`], "attention"],
    [[`${E}key.block`, `${E}key.unblock`], "attention"],
    [[`${E}decrypt`], "sensitive"],
    [[`${E}key.create`, `${E}decrypt`], "sensitive"],
    [[`${E}key.delete`], "sensitive"],
    [[`${E}key.rotate`], "sensitive"],
  ])("%j is %s", (abilities, severity) => {
    expect(model(urn(KEY), abilities).permissions[0]!.severity).toBe(severity as string);
  });

  it("other encryption keys keep their family", () => {
    expect(model(urn("/shares/abc"), [`${E}decrypt`]).permissions[0]!.family).toBe("encryption-decrypt");
  });

  it("decrypt on an app key counts toward the sensitive callout, create alone does not", () => {
    expect(grantReachesSecretDataOrDecryption(grantFor(urn(KEY), [`${E}decrypt`]))).toBe(true);
    expect(grantReachesSecretDataOrDecryption(grantFor(urn(KEY), [`${E}key.create`]))).toBe(false);
  });

  it("grantIsAppKeyDecrypt is true only for app keys with decrypt", () => {
    expect(grantIsAppKeyDecrypt(grantFor(urn(KEY), [`${E}decrypt`]))).toBe(true);
    expect(grantIsAppKeyDecrypt(grantFor(urn(PREFIX), [`${E}key.create`, `${E}decrypt`]))).toBe(true);
    expect(grantIsAppKeyDecrypt(grantFor(urn(KEY), [`${E}key.create`]))).toBe(false);
    expect(grantIsAppKeyDecrypt(grantFor(urn("/shares/abc"), [`${E}decrypt`]))).toBe(false);
  });
});

describe("key.delete is listed and cannot be selected", () => {
  const abilities = [`${E}key.create`, `${E}key.delete`];

  it("the action is not selected and not editable; the others are", () => {
    const [grant] = model(urn(KEY), abilities).permissions;
    const byAbility = Object.fromEntries(grant!.actions.map((action) => [action.ability, action]));
    expect(byAbility[`${E}key.delete`]).toMatchObject({ selected: false, editable: false });
    expect(byAbility[`${E}key.create`]).toMatchObject({ selected: true, editable: true });
  });

  it("it stays unselected when the caller lists every action as selected", () => {
    const att = { [urn(KEY)]: Object.fromEntries(abilities.map((ability) => [ability, [{}]])) };
    const message = siweWithResources([makeRecapResource(att)]);
    const every = parseCapabilityReview(ctx(message)).permissions.flatMap((grant) =>
      grant.actions.map((action) => action.id),
    );
    expect(every).toHaveLength(2);
    const again = parseCapabilityReview(ctx(message, every));
    const byAbility = Object.fromEntries(again.permissions[0]!.actions.map((action) => [action.ability, action]));
    expect(byAbility[`${E}key.delete`]).toMatchObject({ selected: false, editable: false });
    expect(byAbility[`${E}key.create`]).toMatchObject({ selected: true });
  });

  it("key.delete on a resource outside apps/ is not selectable either", () => {
    const [grant] = model(urn("/secrets/x"), [`${E}key.delete`]).permissions;
    expect(grant!.actions[0]).toMatchObject({ selected: false, editable: false });
  });

  it("the not-grantable rows come from the unselected action", () => {
    const [grant] = model(urn(KEY), abilities).permissions;
    expect(appKeyNotGrantableStatements(grant!).map((row) => row.primaryText)).toEqual([
      "Delete the key `apps/xyz.tinycloud.listen/k`. Apps can't be given this permission.",
    ]);
    expect(appKeyNotGrantableStatements(grantFor(urn(KEY), [`${E}decrypt`]))).toEqual([]);
  });

  it("the delete row is first in buildStatement only when it is the only action", () => {
    const [grant] = model(urn(KEY), abilities).permissions;
    expect(buildStatement(grant!).primaryText).toBe("Create the encryption key `apps/xyz.tinycloud.listen/k`.");
  });
});

describe("standing access line", () => {
  it("states the signed expiry", () => {
    const expiry = model(urn(KEY), [`${E}decrypt`]).expiry;
    expect(expiry).toBe(FIXTURE_META.expirationTime);
    expect(appKeyAccessStatement(expiry)).toBe(`This access lasts until ${FIXTURE_META.expirationTime}.`);
  });

  it("uses the formatter it is given", () => {
    expect(appKeyAccessStatement("2026-11-23T10:00:00.000Z", () => "Nov 23, 2026, 10:00 AM")).toBe(
      "This access lasts until Nov 23, 2026, 10:00 AM.",
    );
  });

  it.each([[null], [""], ["not a date"], ["Expiration Time"]])("without a usable expiry (%p)", (expiry) => {
    expect(appKeyAccessStatement(expiry)).toBe("This access lasts until it expires.");
    expect(APP_KEY_ACCESS_WITHOUT_EXPIRY).toBe("This access lasts until it expires.");
  });
});

describe("splitStatementCode", () => {
  it("returns the text between backticks as code", () => {
    expect(splitStatementCode("Create the encryption key `apps/x/k`.")).toEqual([
      { text: "Create the encryption key ", code: false },
      { text: "apps/x/k", code: true },
      { text: ".", code: false },
    ]);
  });

  it("returns plain text unchanged", () => {
    expect(splitStatementCode("Read application data")).toEqual([{ text: "Read application data", code: false }]);
  });
});
