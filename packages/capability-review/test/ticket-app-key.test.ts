// The owner screen for a command-line tool that asks for one exact app key: the host an app id names, the
// strict reading of the request's `appKey`, and the agreement between that claim and the signed message.

import { describe, expect, it } from "bun:test";

import {
  TICKET_APP_KEY_COPY,
  appHostForAppId,
  parseCapabilityReview,
  readTicketAppKey,
  reviewTicketAppKey,
  ticketAppKeyRefusal,
  ticketAppKeyRefusalText,
  ticketAppKeyText,
} from "../src/index.js";
import type { ParseContext } from "../src/parse.js";
import { FIXTURE_META, makeRecapResource, siweWithResources } from "./fixtures/index.js";

const OWNER = `did:pkh:eip155:${FIXTURE_META.chainId}:${FIXTURE_META.address}`;
const APP_ID = "xyz.tinycloud.share";
const KEY = "xyz.tinycloud.tinyapps.contacts/seal-v1";
const E = "tinycloud.encryption/";

function ctx(resources: Record<string, string[]>): ParseContext {
  const att = Object.fromEntries(
    Object.entries(resources).map(([resource, abilities]) => [resource, Object.fromEntries(abilities.map((a) => [a, [{}]]))]),
  );
  return {
    message: siweWithResources([makeRecapResource(att)]),
    signer: { label: "Test signer", address: FIXTURE_META.address, chainId: FIXTURE_META.chainId, provenance: "managed" },
    editable: true,
    metadataTrust: { status: "unsigned", reason: "no manifest" },
    reason: { text: "", source: "none" },
    requester: {
      displayName: "cli",
      verifiedOrigin: null,
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
const urn = (path: string, network = "default") => `urn:tinycloud:encryption:${OWNER}:${network}/${path}`;
const BOTH = [`${E}decrypt`, `${E}key.create`];
const claim = { appId: APP_ID, key: KEY };

describe("the host of an app id", () => {
  it("is the id reversed label by label", () => {
    expect(appHostForAppId(APP_ID)).toBe("share.tinycloud.xyz");
  });
  it.each(["share", "localhost.app", "1.2.3.4", "xyz.-bad.share", "XYZ.tinycloud.share", "xyz..share"])("%s names no host", (id) => {
    expect(appHostForAppId(id)).toBeNull();
  });
});

describe("the appKey of a request", () => {
  it("is two text fields naming a valid key", () => {
    expect(readTicketAppKey(claim)).toEqual(claim);
  });
  it.each([
    [{ appId: APP_ID }],
    [{ ...claim, extra: 1 }],
    [{ appId: APP_ID, key: `/${KEY}` }],
    [{ appId: APP_ID, key: "k/" }],
    [{ appId: "share", key: "a/b" }],
    [{ appId: APP_ID, key: 7 }],
    [null],
    [[claim]],
  ])("refuses %j", (value) => {
    expect(readTicketAppKey(value)).toBeNull();
  });
});

describe("the signed message against the claim", () => {
  const path = `apps/${APP_ID}/${KEY}`;
  it("agrees only for one exact key with decrypt and key.create", () => {
    const review = reviewTicketAppKey(parseCapabilityReview(ctx({ [urn(path)]: BOTH })), claim);
    expect(review).toEqual({ appId: APP_ID, host: "share.tinycloud.xyz", keyPath: path, keyName: "seal-v1" });
  });
  it.each([
    ["another key", { [urn(`apps/${APP_ID}/other/seal-v1`)]: BOTH }],
    ["a prefix", { [urn(`apps/${APP_ID}/${KEY.split("/")[0]}/`)]: BOTH }],
    ["another network", { [urn(path, "other")]: BOTH }],
    ["a missing ability", { [urn(path)]: [`${E}decrypt`] }],
    ["an extra ability", { [urn(path)]: [...BOTH, `${E}key.block`] }],
    ["a second resource", { [urn(path)]: BOTH, [urn(`apps/${APP_ID}/second/k`)]: BOTH }],
  ])("refuses %s", (_name, resources) => {
    expect(reviewTicketAppKey(parseCapabilityReview(ctx(resources)), claim)).toBeNull();
  });
});

describe("the words", () => {
  const review = { appId: APP_ID, host: "share.tinycloud.xyz", keyPath: `apps/${APP_ID}/${KEY}`, keyName: "seal-v1" };
  it("fill the host, the key name and the key path", () => {
    expect(ticketAppKeyText(TICKET_APP_KEY_COPY.decryptLine, review)).toBe("Decrypt data locked with share.tinycloud.xyz's key `seal-v1`");
    expect(ticketAppKeyText(TICKET_APP_KEY_COPY.keyLine, review)).toBe(`Key: \`apps/${APP_ID}/${KEY}\``);
  });
  it("name each refusal the API gives and no other code", () => {
    expect(ticketAppKeyRefusal("app_key_not_listed")).toBe("notListed");
    expect(ticketAppKeyRefusal("app_keys_file_unavailable")).toBe("unavailable");
    expect(ticketAppKeyRefusal("toString")).toBeNull();
    expect(ticketAppKeyRefusalText("missing", review)).toEndWith("Nothing was approved.");
  });
});
