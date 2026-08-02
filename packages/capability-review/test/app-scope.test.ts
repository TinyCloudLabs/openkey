// Sol MAJOR-1: unit tests for the app-scoped-secret gate.
//
// The js-sdk emits real production KV/vault paths in the shape
// `secrets/scoped/<scope>/<name>` (and `vault/secrets/scoped/<scope>/<name>`).
// Manifests declare secrets with the longer synonyms `read/write/delete`,
// while grants on the wire carry the short verbs `get/put/del`.
//
// Before this change, `parseSecretPath` did not recognize the js-sdk
// shape and the verb comparison compared raw strings — so real production
// scoped-secret grants never matched a declaration and the gate never
// fired. These tests lock in the fix.

import { describe, expect, it } from "bun:test";

import {
  annotateAppScopedGrants,
  findMatchingDeclaredSecret,
  normalizeSecretVerb,
  type DeclaredScopedSecret,
} from "../src/app-scope.js";
import type {
  CapabilityGrant,
  CapabilityReviewModel,
} from "../src/model.js";

const SPACE = "tinycloud:pkh:eip155:1:0x1111111111111111111111111111111111111111:default";

function kvGrant(path: string, verbs: string[]): CapabilityGrant {
  return {
    id: `tinycloud.kv\x00${SPACE}\x00${path}`,
    family: "secret-read",
    severity: "sensitive",
    service: "tinycloud.kv",
    space: SPACE,
    path,
    owner: null,
    ownedBySelf: true,
    displayLabel: "",
    metadataLabel: null,
    actions: verbs.map((verb) => ({
      id: `tinycloud.kv\x00${SPACE}\x00${path}\x00tinycloud.kv/${verb}`,
      ability: `tinycloud.kv/${verb}`,
      verb,
      required: false,
      selected: true,
      editable: true,
      caveats: [{}],
    })),
  };
}

function model(perms: CapabilityGrant[]): CapabilityReviewModel {
  return {
    version: 1,
    protocol: "tinycloud-siwe-recap",
    rawMessage: "",
    requester: {
      displayName: "",
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
    reason: { text: "", source: "none" },
    signer: {
      label: "",
      address: "0x1111111111111111111111111111111111111111",
      chainId: 1,
      provenance: "managed",
    },
    expiry: null,
    immutable: null,
    metadataTrust: {
      status: "origin-bound",
      reason: "test",
    },
    permissions: perms,
    parseWarnings: [],
  };
}

describe("normalizeSecretVerb", () => {
  it("maps read -> get, write -> put, delete -> del", () => {
    expect(normalizeSecretVerb("read")).toBe("get");
    expect(normalizeSecretVerb("write")).toBe("put");
    expect(normalizeSecretVerb("delete")).toBe("del");
  });

  it("keeps grant-side short verbs stable", () => {
    expect(normalizeSecretVerb("get")).toBe("get");
    expect(normalizeSecretVerb("put")).toBe("put");
    expect(normalizeSecretVerb("del")).toBe("del");
  });

  it("passes unknown verbs through", () => {
    expect(normalizeSecretVerb("list")).toBe("list");
    expect(normalizeSecretVerb("admin")).toBe("admin");
  });
});

describe("findMatchingDeclaredSecret — js-sdk production shapes", () => {
  it("matches secrets/scoped/<scope>/<name> against a scoped declaration", () => {
    const grant = kvGrant("secrets/scoped/listen/ANTHROPIC_KEY", ["get"]);
    const declared: DeclaredScopedSecret[] = [
      { secretName: "ANTHROPIC_KEY", scope: "listen", actions: ["read"] },
    ];
    const match = findMatchingDeclaredSecret(grant, declared);
    expect(match).not.toBeNull();
    expect(match?.secretName).toBe("ANTHROPIC_KEY");
    expect(match?.scope).toBe("listen");
  });

  it("matches vault/secrets/scoped/<scope>/<name>", () => {
    const grant = kvGrant("vault/secrets/scoped/listen/ANTHROPIC_KEY", ["get"]);
    const declared: DeclaredScopedSecret[] = [
      { secretName: "ANTHROPIC_KEY", scope: "listen", actions: ["read"] },
    ];
    expect(findMatchingDeclaredSecret(grant, declared)).not.toBeNull();
  });

  it("matches multiple normalized verbs (read/write -> get/put)", () => {
    const grant = kvGrant("secrets/scoped/listen/API_KEY", ["get", "put"]);
    const declared: DeclaredScopedSecret[] = [
      { secretName: "API_KEY", scope: "listen", actions: ["read", "write"] },
    ];
    expect(findMatchingDeclaredSecret(grant, declared)).not.toBeNull();
  });

  it("rejects a grant asking for an undeclared verb", () => {
    const grant = kvGrant("secrets/scoped/listen/API_KEY", ["get", "del"]);
    const declared: DeclaredScopedSecret[] = [
      { secretName: "API_KEY", scope: "listen", actions: ["read", "write"] },
    ];
    expect(findMatchingDeclaredSecret(grant, declared)).toBeNull();
  });

  it("rejects a scoped grant against an unscoped declaration", () => {
    const grant = kvGrant("secrets/scoped/listen/API_KEY", ["get"]);
    const declared: DeclaredScopedSecret[] = [
      { secretName: "API_KEY", actions: ["read"] },
    ];
    expect(findMatchingDeclaredSecret(grant, declared)).toBeNull();
  });

  it("rejects a scoped-name mismatch even at the same scope", () => {
    const grant = kvGrant("secrets/scoped/listen/API_KEY", ["get"]);
    const declared: DeclaredScopedSecret[] = [
      { secretName: "OTHER_KEY", scope: "listen", actions: ["read"] },
    ];
    expect(findMatchingDeclaredSecret(grant, declared)).toBeNull();
  });

  it("still matches legacy scope-first `<scope>/secrets/<name>` shape", () => {
    const grant = kvGrant("listen/secrets/API_KEY", ["get"]);
    const declared: DeclaredScopedSecret[] = [
      { secretName: "API_KEY", scope: "listen", actions: ["read"] },
    ];
    expect(findMatchingDeclaredSecret(grant, declared)).not.toBeNull();
  });

  it("matches unscoped secrets/<name>", () => {
    const grant = kvGrant("secrets/API_KEY", ["get"]);
    const declared: DeclaredScopedSecret[] = [
      { secretName: "API_KEY", actions: ["read"] },
    ];
    expect(findMatchingDeclaredSecret(grant, declared)).not.toBeNull();
  });

  it("returns null for a path that isn't secret-shaped", () => {
    const grant = kvGrant("chat/messages/1", ["get"]);
    const declared: DeclaredScopedSecret[] = [
      { secretName: "chat", actions: ["read"] },
    ];
    expect(findMatchingDeclaredSecret(grant, declared)).toBeNull();
  });
});

describe("annotateAppScopedGrants", () => {
  it("labels a matching grant under origin-bound trust", () => {
    const grant = kvGrant("secrets/scoped/listen/API_KEY", ["get"]);
    const m = model([grant]);
    const declared: DeclaredScopedSecret[] = [
      { secretName: "API_KEY", scope: "listen", actions: ["read"] },
    ];
    const out = annotateAppScopedGrants(m, { secrets: declared });
    expect(out.permissions[0]?.metadataLabel).toBe(
      "Secret: API_KEY · Scope: listen",
    );
    expect(out.permissions[0]?.appScopedSecret).toEqual({
      secretName: "API_KEY",
      scope: "listen",
    });
  });

  it("never labels under unsigned trust — metadata cannot expand authority", () => {
    const grant = kvGrant("secrets/scoped/listen/API_KEY", ["get"]);
    const m: CapabilityReviewModel = {
      ...model([grant]),
      metadataTrust: { status: "unsigned", reason: "no manifest" },
    };
    const declared: DeclaredScopedSecret[] = [
      { secretName: "API_KEY", scope: "listen", actions: ["read"] },
    ];
    const out = annotateAppScopedGrants(m, { secrets: declared });
    expect(out.permissions[0]?.metadataLabel).toBeNull();
  });

  it("keeps a global app-declared secret sensitive", () => {
    const grant = kvGrant("secrets/API_KEY", ["get"]);
    const out = annotateAppScopedGrants(model([grant]), {
      secrets: [{ secretName: "API_KEY", actions: ["read"] }],
    });
    expect(out.permissions[0]?.severity).toBe("sensitive");
    expect(out.permissions[0]?.appScopedSecret).toBeUndefined();
  });

  it("presents an exactly proven app-scoped secret as standard", () => {
    const grant = kvGrant("secrets/scoped/listen/API_KEY", ["get"]);
    const m = model([grant]);
    const declared: DeclaredScopedSecret[] = [
      { secretName: "API_KEY", scope: "listen", actions: ["read"] },
    ];
    const out = annotateAppScopedGrants(m, { secrets: declared });
    expect(out.permissions[0]?.severity).toBe("standard");
  });
});
