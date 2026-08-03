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
  RECOGNIZED_APP_SCOPE_SECRET_VERBS,
  type DeclaredScopedSecret,
} from "../src/app-scope.js";
import type {
  CapabilityGrant,
  CapabilityReviewModel,
} from "../src/model.js";
import { buildStatement } from "../src/statements.js";

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

function secretsServiceGrant(
  path: string,
  verbs: string[],
  family: CapabilityGrant["family"] = "secret-mutation",
  severity: CapabilityGrant["severity"] = "sensitive",
): CapabilityGrant {
  return {
    id: `tinycloud.secrets\x00${SPACE}\x00${path}`,
    family,
    severity,
    service: "tinycloud.secrets",
    space: SPACE,
    path,
    owner: null,
    ownedBySelf: true,
    displayLabel: "",
    metadataLabel: null,
    actions: verbs.map((verb) => ({
      id: `tinycloud.secrets\x00${SPACE}\x00${path}\x00tinycloud.secrets/${verb}`,
      ability: `tinycloud.secrets/${verb}`,
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

describe("annotateAppScopedGrants — recognized-verb allowlist (Sol MAJOR)", () => {
  // Sol MAJOR (this iteration): the merge-readiness contract says an
  // origin-bound manifest may NOT expand the recognized named-secret
  // action vocabulary. Only the canonical read/write/delete verbs
  // (get/put/del and their synonyms) can carry the sensitive->standard
  // presentation transition. Unknown verbs (peek, admin, rotate, and
  // any future/novel action) MUST leave the grant untouched: severity
  // stays sensitive, `appScopedSecret` is NOT stamped, and
  // `buildStatement` renders the literal fallback copy — never the
  // friendly "Read the app secret API_KEY" copy that implies a
  // read/write/delete authority the wire verb may not carry.

  it("exposes the canonical recognized-verb set", () => {
    expect(RECOGNIZED_APP_SCOPE_SECRET_VERBS.has("get")).toBe(true);
    expect(RECOGNIZED_APP_SCOPE_SECRET_VERBS.has("put")).toBe(true);
    expect(RECOGNIZED_APP_SCOPE_SECRET_VERBS.has("del")).toBe(true);
    // Unknown verbs are NOT in the set. These are the exact tokens that
    // must fail the app-scope gate.
    expect(RECOGNIZED_APP_SCOPE_SECRET_VERBS.has("peek")).toBe(false);
    expect(RECOGNIZED_APP_SCOPE_SECRET_VERBS.has("admin")).toBe(false);
    expect(RECOGNIZED_APP_SCOPE_SECRET_VERBS.has("list")).toBe(false);
    expect(RECOGNIZED_APP_SCOPE_SECRET_VERBS.has("metadata")).toBe(false);
    expect(RECOGNIZED_APP_SCOPE_SECRET_VERBS.has("rotate")).toBe(false);
  });

  it("does NOT annotate a KV secret grant with an unknown verb (peek)", () => {
    // A grant asking `tinycloud.kv/peek` on a scoped secret path with a
    // manifest declaring `peek` on the same secret must NOT flip to
    // standard severity. `peek` is not in the recognized set, so the
    // grant retains its `sensitive` classification and never carries
    // `appScopedSecret`.
    const grant = kvGrant("secrets/scoped/listen/API_KEY", ["peek"]);
    const declared: DeclaredScopedSecret[] = [
      { secretName: "API_KEY", scope: "listen", actions: ["peek"] },
    ];
    const out = annotateAppScopedGrants(model([grant]), { secrets: declared });
    const out0 = out.permissions[0];
    expect(out0?.severity).toBe("sensitive");
    expect(out0?.appScopedSecret).toBeUndefined();
    expect(out0?.metadataLabel).toBeNull();
  });

  it("does NOT annotate a named-secrets service grant with an unknown verb", () => {
    // The direct `tinycloud.secrets/peek` shape Sol demonstrated must
    // fail the gate too — otherwise `buildStatement` renders "Read the
    // app secret API_KEY" for a `peek` grant. Path `secrets/scoped/...`
    // is the shape `parseSecretPath` recognizes for scoped secrets on
    // this service.
    const grant = secretsServiceGrant(
      "secrets/scoped/listen/API_KEY",
      ["peek"],
    );
    const declared: DeclaredScopedSecret[] = [
      { secretName: "API_KEY", scope: "listen", actions: ["peek"] },
    ];
    const out = annotateAppScopedGrants(model([grant]), { secrets: declared });
    const out0 = out.permissions[0];
    expect(out0?.severity).toBe("sensitive");
    expect(out0?.appScopedSecret).toBeUndefined();
  });

  it("does NOT annotate when ANY grant verb is unrecognized (mixed set)", () => {
    // Mixed recognized + unrecognized verbs must still fail closed. A
    // caller cannot smuggle `admin` in alongside `get` to inherit the
    // read-friendly copy for the whole grant.
    const grant = kvGrant("secrets/scoped/listen/API_KEY", ["get", "admin"]);
    const declared: DeclaredScopedSecret[] = [
      { secretName: "API_KEY", scope: "listen", actions: ["read", "admin"] },
    ];
    const out = annotateAppScopedGrants(model([grant]), { secrets: declared });
    const out0 = out.permissions[0];
    expect(out0?.severity).toBe("sensitive");
    expect(out0?.appScopedSecret).toBeUndefined();
  });

  it("does NOT annotate when the DECLARED manifest verb is unrecognized", () => {
    // Even if the grant asks for a recognized verb, a manifest that
    // declares an unknown verb (`peek`) alongside must fail closed.
    // Otherwise a compromised manifest could widen future authority by
    // stapling an unknown declared verb next to a recognized one.
    const grant = kvGrant("secrets/scoped/listen/API_KEY", ["get"]);
    const declared: DeclaredScopedSecret[] = [
      { secretName: "API_KEY", scope: "listen", actions: ["read", "peek"] },
    ];
    const out = annotateAppScopedGrants(model([grant]), { secrets: declared });
    const out0 = out.permissions[0];
    expect(out0?.severity).toBe("sensitive");
    expect(out0?.appScopedSecret).toBeUndefined();
  });

  it("still annotates a recognized-verb grant with a recognized declaration", () => {
    // Regression guard: the allowlist gate must not break the happy
    // path — read/write/delete (get/put/del) all remain eligible.
    const grant = kvGrant("secrets/scoped/listen/API_KEY", ["get", "put"]);
    const declared: DeclaredScopedSecret[] = [
      { secretName: "API_KEY", scope: "listen", actions: ["read", "write"] },
    ];
    const out = annotateAppScopedGrants(model([grant]), { secrets: declared });
    const out0 = out.permissions[0];
    expect(out0?.severity).toBe("standard");
    expect(out0?.appScopedSecret).toEqual({
      secretName: "API_KEY",
      scope: "listen",
    });
  });
});

describe("buildStatement — appScopedSecret branch verb gate (defense-in-depth)", () => {
  // Sol MAJOR (this iteration): even if a grant somehow reached
  // `buildStatement` carrying `appScopedSecret` with an unrecognized
  // verb (compromised or future-buggy annotation code), the friendly
  // "Read/Update the app secret X" copy MUST NOT fire. The exact
  // literal fallback ("Perform tinycloud.secrets/peek on ...") is what
  // the operator sees, so the wire verb is never dressed up in
  // read/write/delete copy it does not carry.

  it("falls back to literal copy when the annotated verb is unknown (peek)", () => {
    const grant = secretsServiceGrant(
      "secrets/scoped/listen/API_KEY",
      ["peek"],
      "secret-read",
      "standard",
    );
    // Simulate a hypothetical broken annotator that stamped
    // `appScopedSecret` on a peek-only grant.
    const stamped: CapabilityGrant = {
      ...grant,
      appScopedSecret: { secretName: "API_KEY", scope: "listen" },
      metadataLabel: "Secret: API_KEY · Scope: listen",
    };
    const statement = buildStatement(stamped);
    expect(statement.primaryText).not.toBe("Read the app secret API_KEY");
    expect(statement.primaryText).not.toContain("app secret");
    // Falls through to the literal fallback: "Perform <ability> on <service>".
    expect(statement.primaryText).toBe(
      "Perform tinycloud.secrets/peek on tinycloud.secrets",
    );
  });

  it("still renders friendly copy for a legitimately-stamped recognized grant", () => {
    // Regression guard: the defense-in-depth gate must not break the
    // happy path. A grant with recognized `get` verbs and a valid
    // `appScopedSecret` continues to render the friendly copy.
    const grant = kvGrant("secrets/scoped/listen/API_KEY", ["get"]);
    const stamped: CapabilityGrant = {
      ...grant,
      appScopedSecret: { secretName: "API_KEY", scope: "listen" },
      severity: "standard",
    };
    const statement = buildStatement(stamped);
    expect(statement.primaryText).toBe("Read the app secret API_KEY");
  });

  it("end-to-end: unknown-verb peek grant on tinycloud.secrets never renders friendly copy", () => {
    // Full production-path repro of the Sol probe: origin-bound
    // manifest declares `peek`, grant asks `tinycloud.secrets/peek`.
    // After `annotateAppScopedGrants`, the grant MUST retain
    // sensitive severity and `buildStatement` MUST render the literal
    // fallback — not "Read the app secret API_KEY".
    const grant = secretsServiceGrant(
      "secrets/scoped/listen/API_KEY",
      ["peek"],
    );
    const m = model([grant]);
    const declared: DeclaredScopedSecret[] = [
      { secretName: "API_KEY", scope: "listen", actions: ["peek"] },
    ];
    const out = annotateAppScopedGrants(m, { secrets: declared });
    const annotated = out.permissions[0]!;
    expect(annotated.severity).toBe("sensitive");
    expect(annotated.appScopedSecret).toBeUndefined();
    const statement = buildStatement(annotated);
    expect(statement.primaryText).not.toBe("Read the app secret API_KEY");
  });
});
