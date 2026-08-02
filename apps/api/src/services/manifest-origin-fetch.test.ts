import { describe, expect, it } from "bun:test";

import {
  annotateAppScopedGrants,
  type CapabilityGrant,
  type CapabilityReviewModel,
} from "@openkey/capability-review";
import {
  bindWellKnownManifestBytes,
  canonicalManifestSha256Hex,
  canonicalizeManifestJson,
} from "./manifest-origin-fetch";

const manifest = {
  manifest_version: 1,
  app_id: "xyz.tinycloud.listen",
  name: "Listen",
  secrets: {
    GOOGLE_MEET_TOKENS: {
      scope: "listen",
      actions: ["read", "write", "delete"],
    },
    READ_ONLY_TOKEN: {
      scope: "listen",
    },
  },
};

const prettyReorderedManifest = `{
  "secrets": {
    "READ_ONLY_TOKEN": { "scope": "listen" },
    "GOOGLE_MEET_TOKENS": {
      "actions": ["read", "write", "delete"],
      "scope": "listen"
    }
  },
  "name": "Listen",
  "app_id": "xyz.tinycloud.listen",
  "manifest_version": 1
}`;

function scopedSecretGrant(): CapabilityGrant {
  const space =
    "tinycloud:pkh:eip155:1:0x1111111111111111111111111111111111111111:secrets";
  const path = "vault/secrets/scoped/listen/GOOGLE_MEET_TOKENS";
  return {
    id: `tinycloud.kv\u0000${space}\u0000${path}`,
    family: "secret-mutation",
    severity: "sensitive",
    service: "tinycloud.kv",
    space,
    path,
    owner: null,
    ownedBySelf: null,
    displayLabel: "Named secret",
    metadataLabel: null,
    actions: ["get", "put", "del"].map((verb) => ({
      id: `tinycloud.kv\u0000${space}\u0000${path}\u0000tinycloud.kv/${verb}`,
      ability: `tinycloud.kv/${verb}`,
      verb,
      required: false,
      selected: true,
      editable: true,
      caveats: [],
    })),
  };
}

function reviewModel(grant: CapabilityGrant): CapabilityReviewModel {
  return {
    version: 1,
    protocol: "tinycloud-siwe-recap",
    rawMessage: "",
    requester: {
      displayName: "Listen",
      verifiedOrigin: "https://listen.tinycloud.xyz",
      appId: "xyz.tinycloud.listen",
      manifestName: "Listen",
      manifestNameProvenance: "origin-bound",
      manifestId: null,
      manifestIdProvenance: "none",
      manifestDigest: canonicalManifestSha256Hex(manifest),
      domainWarning: false,
      originWarning: false,
    },
    reason: { text: "", source: "none" },
    signer: {
      label: "OpenKey account",
      address: "0x1111111111111111111111111111111111111111",
      chainId: 1,
      provenance: "managed",
    },
    expiry: null,
    immutable: null,
    metadataTrust: {
      status: "origin-bound",
      reason: "well-known manifest digest matched",
    },
    permissions: [grant],
    parseWarnings: [],
  };
}

describe("canonical well-known manifest binding", () => {
  it("binds structurally identical JSON regardless of whitespace and key order", () => {
    const digest = canonicalManifestSha256Hex(manifest);
    expect(digest).toBe(
      "9811eb387770f1c0a26f36755a6604741be995692dc97561e2de924bb2ac9c3a",
    );
    expect(canonicalizeManifestJson(JSON.parse(prettyReorderedManifest))).toBe(
      canonicalizeManifestJson(manifest),
    );

    const result = bindWellKnownManifestBytes(
      new TextEncoder().encode(prettyReorderedManifest),
      digest,
    );

    expect(result.ok).toBe(true);
    expect(result.fetchedDigest).toBe(digest);
    expect(result.manifest?.appId).toBe("xyz.tinycloud.listen");
    expect(result.manifest?.declaredSecrets).toEqual([
      { secretName: "READ_ONLY_TOKEN", scope: "listen", actions: ["read"] },
      {
        secretName: "GOOGLE_MEET_TOKENS",
        scope: "listen",
        actions: ["read", "write", "delete"],
      },
    ]);
  });

  it("fails closed on a digest mismatch or invalid JSON", () => {
    expect(
      bindWellKnownManifestBytes(
        new TextEncoder().encode(prettyReorderedManifest),
        "0".repeat(64),
      ).ok,
    ).toBe(false);
    expect(
      bindWellKnownManifestBytes(
        new TextEncoder().encode("not json"),
        "0".repeat(64),
      ).ok,
    ).toBe(false);
  });

  it("drives the exact app-scoped-secret proof gate without caller metadata", () => {
    const bound = bindWellKnownManifestBytes(
      new TextEncoder().encode(prettyReorderedManifest),
      canonicalManifestSha256Hex(manifest),
    );
    expect(bound.ok).toBe(true);

    const annotated = annotateAppScopedGrants(reviewModel(scopedSecretGrant()), {
      prefix: bound.manifest?.prefix,
      defaultSpace: bound.manifest?.defaultSpace,
      secrets: bound.manifest?.declaredSecrets,
      permissions: bound.manifest?.declaredPermissions,
    });

    expect(annotated.permissions[0]?.severity).toBe("standard");
    expect(annotated.permissions[0]?.metadataLabel).toBe(
      "Secret: GOOGLE_MEET_TOKENS · Scope: listen",
    );
  });
});
