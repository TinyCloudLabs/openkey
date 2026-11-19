// The app a request with app keys comes from: which names are shown, and which
// id is shown under them.

import { describe, expect, it } from "bun:test";

import { APP_NAME_MAX_LENGTH, appDisplayName, appKeyIdentity, appRequestingLine, parseCapabilityReview } from "../src/index.js";
import type { RequesterIdentity } from "../src/index.js";
import { FIXTURE_META, makeRecapResource, siweWithResources } from "./fixtures/index.js";

describe("appDisplayName", () => {
  it("shows an ordinary name as it is", () => {
    expect(appDisplayName("Listen")).toBe("Listen");
    expect(appDisplayName("Listen — voice notes")).toBe("Listen — voice notes");
  });

  it("collapses runs of whitespace and trims", () => {
    expect(appDisplayName("  Listen    notes  ")).toBe("Listen notes");
    expect(appDisplayName("Listen\u2028notes\u00A0here")).toBe("Listen notes here");
  });

  it("shows names in one non-Latin script", () => {
    expect(appDisplayName("Слушать")).toBe("Слушать");
    expect(appDisplayName("اسمع")).toBe("اسمع");
    expect(appDisplayName("聞く")).toBe("聞く");
  });

  it.each([
    ["a right-to-left override", "Listen\u202Egnp.exe"],
    ["a left-to-right isolate", "\u2066Listen"],
    ["a right-to-left mark", "Listen\u200F"],
    ["a zero-width space", "Lis\u200Bten"],
    ["a zero-width joiner", "Lis\u200Dten"],
    ["a byte order mark", "\uFEFFListen"],
    ["a tag character", "Listen\u{E0041}"],
    ["a control character", "Lis\u001Bten"],
    ["a line break", "Listen\nnotes"],
    ["a tab", "Listen\tnotes"],
    ["a null", "Lis\u0000ten"],
    ["a private-use character", "Lis\uE000ten"],
    ["a lone surrogate", "Lis\uD800ten"],
  ])("leaves out a name with %s", (_label, name) => {
    expect(appDisplayName(name)).toBeNull();
  });

  it.each([
    ["Cyrillic", "Lіsten"],
    ["Greek", "Lιsten"],
  ])("leaves out Latin mixed with %s", (_label, name) => {
    expect(appDisplayName(name)).toBeNull();
  });

  it("leaves out what is not text or has nothing to show", () => {
    for (const value of [undefined, null, 42, {}, "", "   ", "\u00A0\u2003"]) expect(appDisplayName(value)).toBeNull();
  });

  it("cuts a long name to the limit with an ellipsis, counting characters not code units", () => {
    expect(appDisplayName("A".repeat(APP_NAME_MAX_LENGTH))).toBe("A".repeat(APP_NAME_MAX_LENGTH));
    const cut = appDisplayName("A".repeat(APP_NAME_MAX_LENGTH + 1))!;
    expect([...cut]).toHaveLength(APP_NAME_MAX_LENGTH);
    expect(cut.endsWith("…")).toBe(true);
    const wide = appDisplayName("😀".repeat(60))!;
    expect([...wide]).toHaveLength(APP_NAME_MAX_LENGTH);
    expect(wide.endsWith("…")).toBe(true);
  });

  it("does not leave a space before the ellipsis", () => {
    expect(appDisplayName(`${"A".repeat(46)} ${"B".repeat(10)}`)).toBe(`${"A".repeat(46)}…`);
  });
});

const OWNER = `did:pkh:eip155:${FIXTURE_META.chainId}:${FIXTURE_META.address}`;
const urn = (rest: string) => `urn:tinycloud:encryption:${OWNER}:default${rest}`;
const APP = "xyz.tinycloud.listen";

function modelFor(resources: Record<string, string[]>, who: Partial<RequesterIdentity> = {}) {
  const att = Object.fromEntries(
    Object.entries(resources).map(([resource, abilities]) => [resource, Object.fromEntries(abilities.map((a) => [a, [{}]]))]),
  );
  return parseCapabilityReview({
    message: siweWithResources([makeRecapResource(att)]),
    signer: { label: "Key", address: FIXTURE_META.address, chainId: FIXTURE_META.chainId, provenance: "managed" },
    editable: true,
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
      ...who,
    },
    requesterAddress: null,
    requesterVerified: false,
  });
}

const KEYS = { [urn(`/apps/${APP}/`)]: ["tinycloud.encryption/key.create", "tinycloud.encryption/decrypt"] };

describe("appKeyIdentity", () => {
  it("has a name only from a verified or origin-bound manifest, and the verified id", () => {
    for (const provenance of ["verified", "origin-bound"] as const) {
      expect(appKeyIdentity(modelFor(KEYS, { manifestName: "Listen", manifestNameProvenance: provenance, appId: APP }))).toEqual({
        name: "Listen",
        appId: APP,
        origin: "https://listen.tinycloud.xyz",
      });
    }
  });

  it("never takes the name from the caller", () => {
    expect(appKeyIdentity(modelFor(KEYS, { manifestName: "Listen", manifestNameProvenance: "caller", appId: null }))).toEqual({
      name: null,
      appId: APP,
      origin: "https://listen.tinycloud.xyz",
    });
  });

  it("takes the id from the key resources until the manifest is verified", () => {
    expect(appKeyIdentity(modelFor(KEYS))?.appId).toBe(APP);
    expect(appKeyIdentity(modelFor({ [urn(`/apps/${APP}/api-token`)]: ["tinycloud.encryption/decrypt"] }))?.appId).toBe(APP);
  });

  it("leaves the name out when the verified id and the resources disagree, and shows the resources' id", () => {
    const identity = appKeyIdentity(modelFor(KEYS, { manifestName: "Other", manifestNameProvenance: "origin-bound", appId: "xyz.tinycloud.other" }));
    expect(identity?.name).toBeNull();
    expect(identity?.appId).toBe(APP);
  });

  it("leaves out a name that is not displayable", () => {
    expect(appKeyIdentity(modelFor(KEYS, { manifestName: "Lis\u202Eten", manifestNameProvenance: "origin-bound", appId: APP }))?.name).toBeNull();
  });

  it("is null for a request without app keys", () => {
    expect(appKeyIdentity(modelFor({ [urn("")]: ["tinycloud.encryption/decrypt"] }, { manifestName: "Listen", manifestNameProvenance: "origin-bound", appId: APP }))).toBeNull();
  });

  it("is null when two apps' keys are requested and no id is verified", () => {
    expect(
      appKeyIdentity(modelFor({ [urn("/apps/a.one/")]: ["tinycloud.encryption/decrypt"], [urn("/apps/b.two/")]: ["tinycloud.encryption/decrypt"] })),
    ).toBeNull();
  });
});

describe("appRequestingLine", () => {
  it("names the app, or says this app", () => {
    expect(appRequestingLine("Listen")).toBe("Listen is requesting:");
    expect(appRequestingLine(null)).toBe("This app is requesting:");
  });
});
