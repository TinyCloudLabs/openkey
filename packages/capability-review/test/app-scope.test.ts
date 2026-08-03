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
  expectedSignerSecretsSpace,
  findMatchingDeclaredSecret,
  isSignerOwnedSecretsSpace,
  normalizeSecretVerb,
  RECOGNIZED_APP_SCOPE_SECRET_VERBS,
  type DeclaredScopedSecret,
} from "../src/app-scope.js";
import type {
  CapabilityGrant,
  CapabilityReviewModel,
} from "../src/model.js";
import { buildStatement } from "../src/statements.js";

const ACCOUNT = "0x1111111111111111111111111111111111111111";
// Non-secrets space — used in negative tests to prove space-check fails closed.
const SPACE = `tinycloud:pkh:eip155:1:${ACCOUNT}:default`;
// Structurally-named secrets space — required for app-scoped annotation.
const SECRETS_SPACE = `tinycloud:pkh:eip155:1:${ACCOUNT}:secrets`;

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

// A KV grant on the structurally-named secrets space with the canonical
// vault/secrets/scoped/<scope>/<name> path. This is the only shape that
// can receive app-scoped annotation after the Blocker-4 fix.
function kvSecretsGrant(scope: string, name: string, verbs: string[]): CapabilityGrant {
  const path = `vault/secrets/scoped/${scope}/${name}`;
  return {
    id: `tinycloud.kv\x00${SECRETS_SPACE}\x00${path}`,
    family: "secret-read",
    severity: "sensitive",
    service: "tinycloud.kv",
    space: SECRETS_SPACE,
    path,
    owner: null,
    ownedBySelf: true,
    displayLabel: "",
    metadataLabel: null,
    actions: verbs.map((verb) => ({
      id: `tinycloud.kv\x00${SECRETS_SPACE}\x00${path}\x00tinycloud.kv/${verb}`,
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
  it("matches vault/secrets/scoped/<scope>/<name> (canonical js-sdk shape)", () => {
    const grant = kvGrant("vault/secrets/scoped/listen/ANTHROPIC_KEY", ["get"]);
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
    const grant = kvGrant("vault/secrets/scoped/listen/API_KEY", ["get", "put"]);
    const declared: DeclaredScopedSecret[] = [
      { secretName: "API_KEY", scope: "listen", actions: ["read", "write"] },
    ];
    expect(findMatchingDeclaredSecret(grant, declared)).not.toBeNull();
  });

  it("rejects a grant asking for an undeclared verb", () => {
    const grant = kvGrant("vault/secrets/scoped/listen/API_KEY", ["get", "del"]);
    const declared: DeclaredScopedSecret[] = [
      { secretName: "API_KEY", scope: "listen", actions: ["read", "write"] },
    ];
    expect(findMatchingDeclaredSecret(grant, declared)).toBeNull();
  });

  it("rejects a scoped grant against an unscoped declaration (no scope in declaration)", () => {
    const grant = kvGrant("vault/secrets/scoped/listen/API_KEY", ["get"]);
    const declared: DeclaredScopedSecret[] = [
      { secretName: "API_KEY", actions: ["read"] },
    ];
    // Unscoped declarations lack a scope field; they cannot match the
    // vault/secrets/scoped/<scope>/<name> pattern.
    expect(findMatchingDeclaredSecret(grant, declared)).toBeNull();
  });

  it("rejects when the exact path doesn't match the declared name", () => {
    const grant = kvGrant("vault/secrets/scoped/listen/API_KEY", ["get"]);
    const declared: DeclaredScopedSecret[] = [
      { secretName: "OTHER_KEY", scope: "listen", actions: ["read"] },
    ];
    // vault/secrets/scoped/listen/API_KEY ≠ vault/secrets/scoped/listen/OTHER_KEY
    expect(findMatchingDeclaredSecret(grant, declared)).toBeNull();
  });

  it("does NOT match legacy scope-first `<scope>/secrets/<name>` shape (fail-closed)", () => {
    // js-sdk never emits this shape; annotation loss is demote-only.
    const grant = kvGrant("listen/secrets/API_KEY", ["get"]);
    const declared: DeclaredScopedSecret[] = [
      { secretName: "API_KEY", scope: "listen", actions: ["read"] },
    ];
    expect(findMatchingDeclaredSecret(grant, declared)).toBeNull();
  });

  it("does NOT match `secrets/scoped/<scope>/<name>` without vault/ prefix (fail-closed)", () => {
    // js-sdk emits vault/secrets/scoped/... — the non-vault shape is not canonical.
    const grant = kvGrant("secrets/scoped/listen/API_KEY", ["get"]);
    const declared: DeclaredScopedSecret[] = [
      { secretName: "API_KEY", scope: "listen", actions: ["read"] },
    ];
    expect(findMatchingDeclaredSecret(grant, declared)).toBeNull();
  });

  it("does NOT match unscoped secrets/<name> (no vault path, no scope)", () => {
    // Unscoped paths don't match vault/secrets/scoped/... and unscoped
    // declarations have no scope to build an expected path from.
    const grant = kvGrant("secrets/API_KEY", ["get"]);
    const declared: DeclaredScopedSecret[] = [
      { secretName: "API_KEY", actions: ["read"] },
    ];
    expect(findMatchingDeclaredSecret(grant, declared)).toBeNull();
  });

  it("rejects a secretName that fails SECRET_NAME_RE (lowercase)", () => {
    const grant = kvGrant("vault/secrets/scoped/listen/api_key", ["get"]);
    const declared: DeclaredScopedSecret[] = [
      { secretName: "api_key", scope: "listen", actions: ["read"] },
    ];
    expect(findMatchingDeclaredSecret(grant, declared)).toBeNull();
  });

  it("rejects a reserved scope (default)", () => {
    const grant = kvGrant("vault/secrets/scoped/default/API_KEY", ["get"]);
    const declared: DeclaredScopedSecret[] = [
      { secretName: "API_KEY", scope: "default", actions: ["read"] },
    ];
    expect(findMatchingDeclaredSecret(grant, declared)).toBeNull();
  });

  it("rejects a reserved scope (global)", () => {
    const grant = kvGrant("vault/secrets/scoped/global/API_KEY", ["get"]);
    const declared: DeclaredScopedSecret[] = [
      { secretName: "API_KEY", scope: "global", actions: ["read"] },
    ];
    expect(findMatchingDeclaredSecret(grant, declared)).toBeNull();
  });

  it("rejects a non-canonical scope (uppercase)", () => {
    const grant = kvGrant("vault/secrets/scoped/Listen/API_KEY", ["get"]);
    const declared: DeclaredScopedSecret[] = [
      { secretName: "API_KEY", scope: "Listen", actions: ["read"] },
    ];
    expect(findMatchingDeclaredSecret(grant, declared)).toBeNull();
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
    const grant = kvSecretsGrant("listen", "API_KEY", ["get"]);
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
    const grant = kvSecretsGrant("listen", "API_KEY", ["get"]);
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

  it("keeps a global app-declared secret sensitive (no scope)", () => {
    // Unscoped declarations have no scope and cannot form a vault path.
    const grant = kvSecretsGrant("listen", "API_KEY", ["get"]);
    const out = annotateAppScopedGrants(model([grant]), {
      secrets: [{ secretName: "API_KEY", actions: ["read"] }],
    });
    expect(out.permissions[0]?.severity).toBe("sensitive");
    expect(out.permissions[0]?.appScopedSecret).toBeUndefined();
  });

  it("presents an exactly proven app-scoped secret as standard", () => {
    const grant = kvSecretsGrant("listen", "API_KEY", ["get"]);
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
    const grant = kvSecretsGrant("listen", "API_KEY", ["peek"]);
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
    const grant = kvSecretsGrant("listen", "API_KEY", ["get", "admin"]);
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
    const grant = kvSecretsGrant("listen", "API_KEY", ["get"]);
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
    const grant = kvSecretsGrant("listen", "API_KEY", ["get", "put"]);
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
    // happy path. A grant with recognized `get` verbs, KV service,
    // secrets space, and canonical vault path renders the friendly copy.
    const grant = kvSecretsGrant("listen", "API_KEY", ["get"]);
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

// ─── Blocker 4 regression suite ───────────────────────────────────────────────
// Proves the exact-resource proof gate: service, space, and path must all match
// the manifest-derived canonical tuple for any sensitive → standard transition.

describe("annotateAppScopedGrants — Blocker 4: exact-resource proof gate", () => {
  const DECLARED: DeclaredScopedSecret[] = [
    { secretName: "API_KEY", scope: "listen", actions: ["read"] },
  ];

  it("Sol probe repro (must fail closed): tinycloud.secrets service on unrelated space and wrong path", () => {
    // Exact repro of the pre-fix exploit: origin-bound declaration
    // {API_KEY/listen/read} must NOT annotate a tinycloud.secrets/get
    // grant on an unrelated space at path secrets/scoped/listen/API_KEY.
    const grant = secretsServiceGrant(
      "secrets/scoped/listen/API_KEY",
      ["get"],
      "secret-mutation",
      "sensitive",
    );
    const out = annotateAppScopedGrants(model([grant]), { secrets: DECLARED });
    const g = out.permissions[0]!;
    expect(g.severity).toBe("sensitive");
    expect(g.appScopedSecret).toBeUndefined();
    expect(g.metadataLabel).toBeNull();
    // The literal fallback must name the actual service/actions.
    const stmt = buildStatement(g);
    expect(stmt.primaryText).not.toContain("app secret");
  });

  it("wrong space: KV grant on vault path but non-secrets space is not annotated", () => {
    // tinycloud.kv + vault/secrets/scoped/... + :default space = fail closed.
    const grant = kvGrant("vault/secrets/scoped/listen/API_KEY", ["get"]);
    // grant.space is the :default SPACE constant — not a secrets space.
    const out = annotateAppScopedGrants(model([grant]), { secrets: DECLARED });
    const g = out.permissions[0]!;
    expect(g.severity).toBe("sensitive");
    expect(g.appScopedSecret).toBeUndefined();
  });

  it("wrong path: tinycloud.kv on secrets space but path missing vault/ prefix", () => {
    // secrets/scoped/listen/API_KEY without vault/ prefix is not canonical.
    const grant: CapabilityGrant = {
      ...kvSecretsGrant("listen", "API_KEY", ["get"]),
      path: "secrets/scoped/listen/API_KEY",
    };
    const out = annotateAppScopedGrants(model([grant]), { secrets: DECLARED });
    const g = out.permissions[0]!;
    expect(g.severity).toBe("sensitive");
    expect(g.appScopedSecret).toBeUndefined();
  });

  it("wrong path: legacy scope-first shape on secrets space is not annotated", () => {
    const grant: CapabilityGrant = {
      ...kvSecretsGrant("listen", "API_KEY", ["get"]),
      path: "listen/vault/secrets/API_KEY",
    };
    const out = annotateAppScopedGrants(model([grant]), { secrets: DECLARED });
    expect(out.permissions[0]?.appScopedSecret).toBeUndefined();
  });

  it("wrong service: tinycloud.secrets/get on secrets space at vault path is not annotated", () => {
    // The named-secrets service is NOT in KV_SECRET_SERVICES.
    const grant: CapabilityGrant = {
      ...secretsServiceGrant(
        "vault/secrets/scoped/listen/API_KEY",
        ["get"],
        "secret-mutation",
        "sensitive",
      ),
      space: SECRETS_SPACE,
    };
    const out = annotateAppScopedGrants(model([grant]), { secrets: DECLARED });
    const g = out.permissions[0]!;
    expect(g.severity).toBe("sensitive");
    expect(g.appScopedSecret).toBeUndefined();
  });

  it("fail-closed: literal 'secrets' space is NOT the signer's canonical secrets space", () => {
    // Blocker 4 (Defect 1) tightening: the pre-fix `isSecretsSpace` shape
    // check accepted the literal string `"secrets"` even though the
    // js-sdk secrets resolver always targets the signer-owned canonical
    // form `tinycloud:pkh:eip155:<chainId>:<address>:secrets`. Accepting
    // a bare `"secrets"` string would let a caller demote a grant on a
    // space nobody demonstrably owns. After the fix the annotation gate
    // requires the exact signer-owned space, and this grant fails closed:
    // near-miss stamp + literal fallback + sensitive severity.
    const grant: CapabilityGrant = {
      ...kvSecretsGrant("listen", "API_KEY", ["get"]),
      space: "secrets",
    };
    const out = annotateAppScopedGrants(model([grant]), { secrets: DECLARED });
    const g = out.permissions[0]!;
    expect(g.severity).toBe("sensitive");
    expect(g.appScopedSecret).toBeUndefined();
    expect(g.metadataLabel).toBeNull();
    expect(g.appScopeNearMiss).toBe(true);
    // Literal fallback: the operator must see the raw ability + service.
    const stmt = buildStatement(g);
    expect(stmt.primaryText).not.toContain("app secret");
    expect(stmt.primaryText).not.toContain("vault");
  });

  it("happy path: tinycloud.kv on DID-style :secrets space annotates correctly", () => {
    // Regression guard: tinycloud:pkh:eip155:1:0x...:secrets must annotate.
    const out = annotateAppScopedGrants(
      model([kvSecretsGrant("listen", "API_KEY", ["get"])]),
      { secrets: DECLARED },
    );
    const g = out.permissions[0]!;
    expect(g.severity).toBe("standard");
    expect(g.metadataLabel).toBe("Secret: API_KEY · Scope: listen");
  });

  it("happy path: scoped secret remains in the top-level secret-reach count (Blocker 2 invariant)", () => {
    // Even after demotion to standard severity, the grant must still count
    // as reaching secret data (grantReachesSecretDataOrDecryption = true).
    // This is verified via the sensitive-reach suite; here we confirm
    // appScopedSecret is set so the UI can still include it in the count.
    const out = annotateAppScopedGrants(
      model([kvSecretsGrant("listen", "API_KEY", ["get"])]),
      { secrets: DECLARED },
    );
    const g = out.permissions[0]!;
    expect(g.severity).toBe("standard");
    expect(g.appScopedSecret).toBeDefined();
    // family remains secret-read, so grantReachesSecretDataOrDecryption
    // returns true regardless of severity.
    expect(g.family).toBe("secret-read");
  });
});

describe("buildStatement — Blocker 4: defense-in-depth exact-resource checks", () => {
  it("falls back when appScopedSecret is stamped but service is tinycloud.secrets", () => {
    const grant: CapabilityGrant = {
      ...secretsServiceGrant(
        "vault/secrets/scoped/listen/API_KEY",
        ["get"],
        "secret-read",
        "standard",
      ),
      space: SECRETS_SPACE,
      appScopedSecret: { secretName: "API_KEY", scope: "listen" },
      metadataLabel: "Secret: API_KEY · Scope: listen",
    };
    const stmt = buildStatement(grant);
    expect(stmt.primaryText).not.toContain("app secret");
  });

  it("falls back when appScopedSecret is stamped but space is not a secrets space", () => {
    const grant: CapabilityGrant = {
      ...kvSecretsGrant("listen", "API_KEY", ["get"]),
      space: SPACE, // :default — not a secrets space
      appScopedSecret: { secretName: "API_KEY", scope: "listen" },
      severity: "standard",
    };
    const stmt = buildStatement(grant);
    expect(stmt.primaryText).not.toContain("app secret");
  });

  it("falls back when appScopedSecret is stamped but path is non-canonical", () => {
    const grant: CapabilityGrant = {
      ...kvSecretsGrant("listen", "API_KEY", ["get"]),
      path: "secrets/scoped/listen/API_KEY", // missing vault/
      appScopedSecret: { secretName: "API_KEY", scope: "listen" },
      severity: "standard",
    };
    const stmt = buildStatement(grant);
    expect(stmt.primaryText).not.toContain("app secret");
  });
});

// ─── Blocker 4 (Defect 1 + Defect 2): Sol follow-up regression suite ────────
// Locks in the two specific defects Sol identified after the first pass:
//
//   Defect 1: `isSecretsSpace` accepted any string containing `:secrets`, so
//     a probe signed by 0x1111…1111 targeting 0x2222…2222:secrets was
//     incorrectly demoted to standard. The gate must instead prove that
//     `grant.space` is the SIGNER's own canonical secrets space
//     (`tinycloud:pkh:eip155:<chainId>:<address>:secrets`).
//
//   Defect 2: When a KV secret-family grant on a secrets-shaped space failed
//     the exact proof (wrong owner, wrong path, wrong verb, no matching
//     declared entry, …), the grant was left "structurally classified" and
//     `buildStatement` emitted friendly KV secrets copy ("View secrets
//     stored in your vault"). The grant must instead be forced to sensitive
//     severity + literal-fallback copy so the operator sees the raw ability
//     and resource string.

describe("isSignerOwnedSecretsSpace + expectedSignerSecretsSpace", () => {
  it("computes the canonical PKH-derived secrets space with lowercase hex", () => {
    expect(
      expectedSignerSecretsSpace({ address: ACCOUNT, chainId: 1 }),
    ).toBe(`tinycloud:pkh:eip155:1:${ACCOUNT}:secrets`);
  });

  it("normalizes EIP-55 mixed-case addresses to a canonical match", () => {
    // The signer identity may arrive EIP-55 checksummed; the wire space
    // may be lowercased. Both must resolve to the same canonical space
    // so a caller cannot smuggle a mismatched case as a distinct space.
    const eip55 = "0xAaBbCcDdEeFf00112233445566778899aAbBcCdD";
    const signer = { address: eip55, chainId: 1 };
    const canonical = `tinycloud:pkh:eip155:1:${eip55.toLowerCase()}:secrets`;
    expect(expectedSignerSecretsSpace(signer)).toBe(canonical);
    expect(isSignerOwnedSecretsSpace(canonical, signer)).toBe(true);
    // The mixed-case form of the same space also matches:
    expect(
      isSignerOwnedSecretsSpace(
        `tinycloud:pkh:eip155:1:${eip55}:secrets`,
        signer,
      ),
    ).toBe(true);
  });

  it("rejects a cross-signer secrets space (the Defect 1 exploit)", () => {
    const attacker = "0x2222222222222222222222222222222222222222";
    const signer = { address: ACCOUNT, chainId: 1 };
    const attackerSpace = `tinycloud:pkh:eip155:1:${attacker}:secrets`;
    expect(isSignerOwnedSecretsSpace(attackerSpace, signer)).toBe(false);
  });

  it("rejects a bare `secrets` string as a canonical space", () => {
    // js-sdk never emits a bare "secrets" space; only the PKH form.
    expect(
      isSignerOwnedSecretsSpace("secrets", { address: ACCOUNT, chainId: 1 }),
    ).toBe(false);
  });

  it("rejects a same-address secrets space on a different chain", () => {
    expect(
      isSignerOwnedSecretsSpace(
        `tinycloud:pkh:eip155:137:${ACCOUNT}:secrets`,
        { address: ACCOUNT, chainId: 1 },
      ),
    ).toBe(false);
  });
});

describe("annotateAppScopedGrants — Defect 1: cross-signer space attack", () => {
  // Exact repro of the pre-fix cross-signer exploit: a manifest declares
  // {API_KEY/listen/read} for its OWN app. A caller signed by 0x1111…1111
  // presents a grant on 0x2222…2222:secrets at the canonical vault path
  // with matching verbs. Pre-fix: annotated as standard + labelled.
  // Post-fix: nothing about the caller demonstrates ownership of the
  // attacker's space, so the grant must be forced to sensitive + literal
  // fallback + near-miss stamp.

  const DECLARED: DeclaredScopedSecret[] = [
    { secretName: "API_KEY", scope: "listen", actions: ["read"] },
  ];

  it("does NOT annotate a grant on a space owned by a DIFFERENT signer", () => {
    const attackerAccount = "0x2222222222222222222222222222222222222222";
    const attackerSecretsSpace = `tinycloud:pkh:eip155:1:${attackerAccount}:secrets`;
    const path = "vault/secrets/scoped/listen/API_KEY";
    const grant: CapabilityGrant = {
      id: `tinycloud.kv\x00${attackerSecretsSpace}\x00${path}`,
      family: "secret-read",
      severity: "sensitive",
      service: "tinycloud.kv",
      space: attackerSecretsSpace,
      path,
      owner: null,
      ownedBySelf: true,
      displayLabel: "",
      metadataLabel: null,
      actions: [
        {
          id: `tinycloud.kv\x00${attackerSecretsSpace}\x00${path}\x00tinycloud.kv/get`,
          ability: "tinycloud.kv/get",
          verb: "get",
          required: false,
          selected: true,
          editable: true,
          caveats: [{}],
        },
      ],
    };
    // The model.signer stays as 0x1111…1111 — the caller cannot claim
    // ownership of 0x2222…2222:secrets just because they signed a grant
    // that references it.
    const out = annotateAppScopedGrants(model([grant]), { secrets: DECLARED });
    const g = out.permissions[0]!;
    expect(g.severity).toBe("sensitive");
    expect(g.appScopedSecret).toBeUndefined();
    expect(g.metadataLabel).toBeNull();
    expect(g.appScopeNearMiss).toBe(true);
    // Literal fallback — no friendly KV secrets copy.
    const stmt = buildStatement(g);
    expect(stmt.primaryText).not.toContain("app secret");
    expect(stmt.primaryText).not.toContain("vault");
    expect(stmt.primaryText).toBe(
      `Perform tinycloud.kv/get on tinycloud.kv`,
    );
  });

  it("does NOT annotate the same grant on a same-address different-chain space", () => {
    // A same-address secrets space on a different chain is still not
    // owned by the current signer identity.
    const wrongChainSpace = `tinycloud:pkh:eip155:137:${ACCOUNT}:secrets`;
    const path = "vault/secrets/scoped/listen/API_KEY";
    const grant: CapabilityGrant = {
      ...kvSecretsGrant("listen", "API_KEY", ["get"]),
      space: wrongChainSpace,
      path,
    };
    const out = annotateAppScopedGrants(model([grant]), { secrets: DECLARED });
    const g = out.permissions[0]!;
    expect(g.severity).toBe("sensitive");
    expect(g.appScopedSecret).toBeUndefined();
    expect(g.appScopeNearMiss).toBe(true);
  });
});

describe("annotateAppScopedGrants — Defect 2: near-miss literal fallback", () => {
  // Near-miss cases: the grant STRUCTURALLY looks like an app-scoped
  // secret attempt (KV service, secret-family classification), but the
  // exact-resource proof rejects it. The near-miss stamp must force
  // buildStatement into the literal fallback so the operator never sees
  // the friendly "View secrets stored in your vault" wording without
  // an origin-bound proof to justify it.

  const DECLARED: DeclaredScopedSecret[] = [
    { secretName: "API_KEY", scope: "listen", actions: ["read"] },
  ];

  it("near-miss path on the signer's own secrets space → literal fallback + sensitive", () => {
    // Path is a non-canonical near-miss: vault/secrets/alternate/... is
    // not vault/secrets/scoped/... The declared secret does exist but
    // the path shape does not match the canonical scoped form.
    const grant: CapabilityGrant = {
      ...kvSecretsGrant("listen", "API_KEY", ["get"]),
      path: "vault/secrets/alternate/listen/API_KEY",
    };
    const out = annotateAppScopedGrants(model([grant]), { secrets: DECLARED });
    const g = out.permissions[0]!;
    expect(g.severity).toBe("sensitive");
    expect(g.appScopedSecret).toBeUndefined();
    expect(g.metadataLabel).toBeNull();
    expect(g.appScopeNearMiss).toBe(true);
    // Literal fallback: no "View secrets stored in your vault" copy.
    const stmt = buildStatement(g);
    expect(stmt.primaryText).not.toContain("app secret");
    expect(stmt.primaryText).not.toContain("View secrets stored in your vault");
    expect(stmt.primaryText).not.toContain("Manage secrets stored in your vault");
    expect(stmt.primaryText).toBe(
      "Perform tinycloud.kv/get on tinycloud.kv",
    );
  });

  it("near-miss: declared name mismatch → literal fallback + sensitive", () => {
    // Path is the canonical form for OTHER_KEY but the manifest only
    // declares API_KEY. The grant does not match any declaration.
    const grant: CapabilityGrant = {
      ...kvSecretsGrant("listen", "OTHER_KEY", ["get"]),
    };
    const out = annotateAppScopedGrants(model([grant]), { secrets: DECLARED });
    const g = out.permissions[0]!;
    expect(g.severity).toBe("sensitive");
    expect(g.appScopedSecret).toBeUndefined();
    expect(g.appScopeNearMiss).toBe(true);
    const stmt = buildStatement(g);
    expect(stmt.primaryText).not.toContain("app secret");
    expect(stmt.primaryText).not.toContain("vault");
  });

  it("near-miss: wrong service (tinycloud.secrets) is NOT KV → not stamped", () => {
    // The tinycloud.secrets service has its own copy path in
    // buildStatement (recognized-actions allowlist), so we do NOT
    // near-miss stamp it here. Verify the grant retains sensitive
    // severity (unchanged from the fixture) and no appScopedSecret.
    const grant = secretsServiceGrant(
      "vault/secrets/scoped/listen/API_KEY",
      ["get"],
      "secret-mutation",
      "sensitive",
    );
    const out = annotateAppScopedGrants(model([grant]), { secrets: DECLARED });
    const g = out.permissions[0]!;
    expect(g.severity).toBe("sensitive");
    expect(g.appScopedSecret).toBeUndefined();
    // No stamp — the SECRETS_SERVICES branch of buildStatement handles this.
    expect(g.appScopeNearMiss).toBeUndefined();
  });

  it("near-miss: legacy path shape (missing vault/ prefix) → literal fallback", () => {
    // Path secrets/scoped/... without the vault/ prefix is the legacy
    // shape the js-sdk never emits. It must not annotate AND must not
    // render friendly copy.
    const grant: CapabilityGrant = {
      ...kvSecretsGrant("listen", "API_KEY", ["get"]),
      path: "secrets/scoped/listen/API_KEY",
    };
    const out = annotateAppScopedGrants(model([grant]), { secrets: DECLARED });
    const g = out.permissions[0]!;
    expect(g.severity).toBe("sensitive");
    expect(g.appScopedSecret).toBeUndefined();
    expect(g.appScopeNearMiss).toBe(true);
    const stmt = buildStatement(g);
    expect(stmt.primaryText).not.toContain("app secret");
  });

  it("near-miss: unknown verb (peek) → literal fallback + sensitive", () => {
    // A KV secret-family grant asking for an unknown verb on the
    // signer's own secrets space at the canonical vault path. The verb
    // fails the recognized allowlist so the grant becomes a near-miss.
    const grant = kvSecretsGrant("listen", "API_KEY", ["peek"]);
    const out = annotateAppScopedGrants(model([grant]), { secrets: DECLARED });
    const g = out.permissions[0]!;
    expect(g.severity).toBe("sensitive");
    expect(g.appScopedSecret).toBeUndefined();
    expect(g.appScopeNearMiss).toBe(true);
    // The literal fallback must name the raw ability.
    const stmt = buildStatement(g);
    expect(stmt.primaryText).toBe(
      "Perform tinycloud.kv/peek on tinycloud.kv",
    );
  });

  it("regression: happy path still renders friendly app-secret copy", () => {
    // The near-miss stamping must not affect the exact-match happy path:
    // KV service + signer-owned space + canonical path + declared name+
    // scope + subset of declared recognized verbs → standard severity +
    // "Read the app secret API_KEY" copy.
    const grant = kvSecretsGrant("listen", "API_KEY", ["get"]);
    const out = annotateAppScopedGrants(model([grant]), { secrets: DECLARED });
    const g = out.permissions[0]!;
    expect(g.severity).toBe("standard");
    expect(g.appScopedSecret).toEqual({
      secretName: "API_KEY",
      scope: "listen",
    });
    expect(g.appScopeNearMiss).toBeUndefined();
    const stmt = buildStatement(g);
    expect(stmt.primaryText).toBe("Read the app secret API_KEY");
  });
});

describe("buildStatement — appScopeNearMiss short-circuit", () => {
  // A grant carrying appScopeNearMiss MUST render the literal fallback
  // regardless of any other structural facts. This is the primary
  // enforcement point for Defect 2 and should never be affected by
  // service/space/path branches.

  it("returns the literal fallback for any near-miss stamped grant", () => {
    const grant: CapabilityGrant = {
      ...kvSecretsGrant("listen", "API_KEY", ["get"]),
      appScopeNearMiss: true,
    };
    const stmt = buildStatement(grant);
    expect(stmt.primaryText).toBe(
      "Perform tinycloud.kv/get on tinycloud.kv",
    );
  });

  it("near-miss overrides even a stamped appScopedSecret (defense-in-depth)", () => {
    // If a grant somehow arrived at buildStatement carrying both an
    // appScopedSecret (from a buggy annotator) and a near-miss stamp,
    // the near-miss short-circuit must win — the operator sees the
    // literal fallback, never the friendly "app secret" copy.
    const grant: CapabilityGrant = {
      ...kvSecretsGrant("listen", "API_KEY", ["get"]),
      appScopedSecret: { secretName: "API_KEY", scope: "listen" },
      appScopeNearMiss: true,
    };
    const stmt = buildStatement(grant);
    expect(stmt.primaryText).not.toContain("app secret");
    expect(stmt.primaryText).toBe(
      "Perform tinycloud.kv/get on tinycloud.kv",
    );
  });
});
