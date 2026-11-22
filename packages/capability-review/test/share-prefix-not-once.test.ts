import { describe, expect, it } from "bun:test";

import { grantIsBroadOnce, grantIsOwnShareFolder, parseCapabilityReview, type CapabilityGrant } from "../src/index.js";
import { FIXTURE_META, makeRecapResource, siweWithResources } from "./fixtures/index";

// The owner's own `default/share/` folder holds shared-file keys only: a decrypt or key.create on it, or on a prefix
// under it, follows the app's length. Every other prefix keeps the one-hour start.

const ACCOUNT = "0x1111111111111111111111111111111111111111";
const OWNER = `did:pkh:eip155:1:${ACCOUNT}`;

function decrypt(resource: string, ownedBySelf: boolean | null = true, ability = "tinycloud.encryption/decrypt"): CapabilityGrant {
  return {
    id: `tinycloud.encryption\u0000${resource}\u0000`,
    family: "encryption-decrypt",
    severity: "sensitive",
    service: "tinycloud.encryption",
    space: resource,
    path: "",
    owner: null,
    ownedBySelf,
    displayLabel: resource,
    metadataLabel: null,
    resourceService: null,
    actions: [
      {
        id: `tinycloud.encryption\u0000${resource}\u0000\u0000${ability}`,
        ability,
        verb: ability.slice(ability.indexOf("/") + 1),
        required: false,
        selected: true,
        editable: true,
        caveats: [],
      },
    ],
  };
}

const urn = (tail: string, network = "default") => `urn:tinycloud:encryption:${OWNER}:${network}${tail}`;

describe("the owner's default/share/ folder keeps the app's length", () => {
  it.each([["/share/"], ["/share/abc123/"], ["/share/abc123/inner/"]])("a decrypt on the prefix %s", (tail) => {
    expect(grantIsBroadOnce(decrypt(urn(tail)))).toBe(false);
  });

  it("a key.create on the share/ prefix", () => {
    expect(grantIsBroadOnce(decrypt(urn("/share/"), true, "tinycloud.encryption/key.create"))).toBe(false);
  });

  it("an exact share key stays one key", () => {
    expect(grantIsBroadOnce(decrypt(urn("/share/abc123")))).toBe(false);
  });
});

describe("everything near share/ keeps the one-hour start", () => {
  it.each([
    ["a prefix of another owner's keys (not the signer's)", urn("/share/"), false],
    ["a prefix whose owner is not known", urn("/share/"), null],
  ] as const)("%s", (_label, resource, ownedBySelf) => {
    expect(grantIsBroadOnce(decrypt(resource, ownedBySelf))).toBe(true);
  });

  it.each([
    ["a different network (other/share/)", urn("/share/", "other")],
    ["a look-alike network (default-x/share/)", urn("/share/", "default-x")],
    ["a sibling prefix (shared/)", urn("/shared/")],
    ["a sibling prefix (sharex/)", urn("/sharex/")],
    ["a sibling prefix (share-x/)", urn("/share-x/")],
    ["a share folder in another case (Share/), which does not parse", urn("/Share/")],
    ["a different folder (apps/)", urn("/apps/")],
    ["a different folder (keys/)", urn("/keys/")],
    ["the secrets folder (secrets/)", urn("/secrets/")],
    ["the whole network", urn("")],
  ])("%s", (_label, resource) => {
    expect(grantIsBroadOnce(decrypt(resource))).toBe(true);
  });

  it("share/ beside a whole-network decrypt is the one-hour tier", () => {
    const grants = [decrypt(urn("/share/")), decrypt(urn(""))];
    expect(grants.some(grantIsBroadOnce)).toBe(true);
  });
});

describe("a signed request is read the same way", () => {
  const share = (att: Record<string, Record<string, unknown[]>>) =>
    parseCapabilityReview({
      message: siweWithResources([makeRecapResource(att)]),
      editable: true,
      metadataTrust: { status: "unsigned", reason: "no manifest" },
      reason: { text: "", source: "none" },
      requester: {
        displayName: "share.example", verifiedOrigin: "https://share.example", appId: null,
        manifestName: null, manifestNameProvenance: "none", manifestId: null, manifestIdProvenance: "none",
        manifestDigest: null, domainWarning: false, originWarning: false,
      },
      signer: { label: "Key", address: FIXTURE_META.address, chainId: FIXTURE_META.chainId, provenance: "managed" },
    }).permissions;
  const network = `urn:tinycloud:encryption:did:pkh:eip155:${FIXTURE_META.chainId}:${FIXTURE_META.address}:default`;

  it("the signer's share/ decrypt and key.create start at the asked length", () => {
    const grants = share({ [`${network}/share/`]: { "tinycloud.encryption/key.create": [{}], "tinycloud.encryption/decrypt": [{}] } });
    expect(grants.some((grant) => grant.ownedBySelf === true)).toBe(true);
    expect(grants.some(grantIsBroadOnce)).toBe(false);
  });

  it("another owner's share/ decrypt keeps the one-hour start", () => {
    const other = `urn:tinycloud:encryption:did:pkh:eip155:${FIXTURE_META.chainId}:0x2222222222222222222222222222222222222222:default`;
    expect(share({ [`${other}/share/`]: { "tinycloud.encryption/decrypt": [{}] } }).some(grantIsBroadOnce)).toBe(true);
  });
});

describe("grantIsOwnShareFolder names the signer's own share/ folder and nothing else", () => {
  it.each([["/share/"], ["/share/abc123/"], ["/share/abc123/inner/"]])("the prefix %s", (tail) => {
    expect(grantIsOwnShareFolder(decrypt(urn(tail)))).toBe(true);
  });

  it("a key.create on the share/ prefix", () => {
    expect(grantIsOwnShareFolder(decrypt(urn("/share/"), true, "tinycloud.encryption/key.create"))).toBe(true);
  });

  it.each([
    ["an exact share key", urn("/share/abc123"), true],
    ["another owner", urn("/share/"), false],
    ["an unknown owner", urn("/share/"), null],
    ["another network", urn("/share/", "other"), true],
    ["a look-alike folder", urn("/shared/"), true],
    ["the apps folder", urn("/apps/x/"), true],
    ["the secrets folder", urn("/secrets/"), true],
    ["the whole network", urn(""), true],
  ] as const)("not %s", (_label, resource, ownedBySelf) => {
    expect(grantIsOwnShareFolder(decrypt(resource, ownedBySelf))).toBe(false);
  });
});
