// The host card and the node check read every tinycloud.space/host grant of the request, whoever owns the space:
// the signature hosts that space on the named node, so a grant on another chain or for another account is reviewed too.

import { describe, expect, it } from "bun:test";

import { parseCapabilityReview, readSpaceHostFacts } from "../src/index.js";
import { FIXTURE_META, makeRecapResource, siweWithResources } from "./fixtures/index.js";

const PEER = "did:key:z6Mkj8ZndSavdU1RqiTepC1hj4jcKHC5qELaBUxBKrPteD25";
const OTHER_ACCOUNT = "0x2222222222222222222222222222222222222222";

function factsFor(space: string) {
  const message = siweWithResources([makeRecapResource({ [`${space}/space`]: { "tinycloud.space/host": [{}] } })], { uri: PEER });
  const model = parseCapabilityReview({
    message,
    signer: { label: "Key", address: FIXTURE_META.address, chainId: FIXTURE_META.chainId, provenance: "managed" },
    editable: false,
    metadataTrust: { status: "unsigned", reason: "no manifest" },
    reason: { text: "", source: "none" },
    requester: {
      displayName: "TinyCloud CLI",
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
  });
  return readSpaceHostFacts(model);
}

describe("a request to host a space has host facts for every host grant", () => {
  it.each([
    ["the signer's own space", `tinycloud:pkh:eip155:${FIXTURE_META.chainId}:${FIXTURE_META.address}:default`],
    ["the signer's address on chain 137", `tinycloud:pkh:eip155:137:${FIXTURE_META.address}:default`],
    ["another account's space", `tinycloud:pkh:eip155:${FIXTURE_META.chainId}:${OTHER_ACCOUNT}:default`],
  ])("%s", (_name: string, space: string) => {
    const facts = factsFor(space);
    expect(facts?.spaces.map((hosted) => hosted.spaceId)).toEqual([space]);
    expect(facts?.peerDid).toBe(PEER);
  });
});
