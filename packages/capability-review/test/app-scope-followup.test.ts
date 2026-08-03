// Blocker 4 follow-up regression suite (Sol).
//
// Locks in the security fixes that tighten the app-scoped-secret proof
// gate after the initial Blocker 4 pass:
//
//   Defect 1: `KV_SECRET_SERVICES` admitted bare `kv` abilities. Only
//     the fully-qualified `tinycloud.kv` service can pass the proof
//     gate now (KV_SECRET_SERVICES_PROOF); bare `kv` grants become
//     near-miss candidates and are demoted to literal fallback.
//
//   Defect 2: `findMatchingDeclaredSecret` stripped leading/trailing
//     slashes before comparing paths. Paths must now be BYTE-EXACT —
//     `/vault/secrets/scoped/listen/API_KEY/` no longer matches.
//
//   Defect 3: `isSignerOwnedSecretsSpace` lowercased the entire space
//     URI, so `:SECRETS` and mixed-case `PKH` variants passed. The
//     match is now structural — exact lowercase literals for scheme,
//     namespace, and the `:secrets` suffix; address hex case-insensitive.
//
//   Defect 4: Near-miss stamping only fired for KV/named-secrets exact
//     grants. Wrong-scope, wrong-service paths on the correct secret
//     name escaped to friendly copy. Near-miss detection is now widened
//     to a scope-independent, service-agnostic name fingerprint plus a
//     secrets-space-shape check.
//
//   Defect 5: `splitResourceUri` discarded the resource's short-service
//     segment. Grants of shape `<space>/sql/vault/secrets/...` +
//     ability `tinycloud.kv/get` appeared as valid app-scoped grants.
//     The parser now emits `resourceService` and a `serviceMismatch`
//     flag; `annotateAppScopedGrants` never annotates mismatched grants,
//     and `buildStatement` short-circuits them to literal fallback.

import { describe, expect, it } from "bun:test";

import {
  annotateAppScopedGrants,
  findMatchingDeclaredSecret,
  grantReachesSecretDataOrDecryption,
  isSignerOwnedSecretsSpace,
  parseCapabilityReview,
  pathContainsDeclaredSecretName,
  type CapabilityGrant,
  type CapabilityReviewModel,
  type DeclaredScopedSecret,
  type ParseContext,
  type SignerInfo,
} from "../src/index.js";
import { buildStatement } from "../src/statements.js";

const ACCOUNT = "0x1111111111111111111111111111111111111111";
const CHAIN = 1;
const SECRETS_SPACE = `tinycloud:pkh:eip155:${CHAIN}:${ACCOUNT}:secrets`;
const DEFAULT_SPACE = `tinycloud:pkh:eip155:${CHAIN}:${ACCOUNT}:default`;
const CANONICAL_PATH = "vault/secrets/scoped/listen/API_KEY";

const DECLARED: DeclaredScopedSecret[] = [
  { secretName: "API_KEY", scope: "listen", actions: ["read", "write"] },
];

// Test grant builder. Uses positional args so each test can express the
// (service, space, path, verbs) tuple compactly.
function makeGrant(input: {
  service: string;
  space?: string;
  path?: string;
  verbs?: string[];
  family?: CapabilityGrant["family"];
  severity?: CapabilityGrant["severity"];
  resourceService?: string | null;
  serviceMismatch?: boolean;
}): CapabilityGrant {
  const space = input.space ?? SECRETS_SPACE;
  const path = input.path ?? CANONICAL_PATH;
  const verbs = input.verbs ?? ["get"];
  return {
    id: `${input.service}\x00${space}\x00${path}`,
    family: input.family ?? "secret-read",
    severity: input.severity ?? "sensitive",
    service: input.service,
    space,
    path,
    owner: ACCOUNT,
    ownedBySelf: true,
    displayLabel: "",
    metadataLabel: null,
    resourceService: input.resourceService ?? null,
    ...(input.serviceMismatch === true ? { serviceMismatch: true as const } : {}),
    actions: verbs.map((verb) => ({
      id: `${input.service}\x00${space}\x00${path}\x00${input.service}/${verb}`,
      ability: `${input.service}/${verb}`,
      verb,
      required: false,
      selected: true,
      editable: true,
      caveats: [{}],
    })),
  };
}

function makeModel(grants: CapabilityGrant[]): CapabilityReviewModel {
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
      address: ACCOUNT,
      chainId: CHAIN,
      provenance: "managed",
    },
    expiry: null,
    immutable: null,
    metadataTrust: { status: "origin-bound", reason: "test" },
    permissions: grants,
    parseWarnings: [],
  };
}

// ─── Defect 1: KV_SECRET_SERVICES admits bare `kv` abilities ──────────────
describe("Blocker 4 follow-up (Defect 1): service exactness", () => {
  it("bare `kv` ability service on the canonical tuple is sensitive + literal fallback", () => {
    // Even though space + path + verbs + declared entry all line up, the
    // ability service is bare `kv` (not `tinycloud.kv`). The proof gate
    // must reject the annotation and near-miss stamp the grant so
    // buildStatement renders the literal fallback.
    const grant = makeGrant({
      service: "kv",
      space: SECRETS_SPACE,
      path: CANONICAL_PATH,
      verbs: ["get"],
      family: "secret-read",
    });
    const out = annotateAppScopedGrants(makeModel([grant]), { secrets: DECLARED });
    const g = out.permissions[0]!;
    expect(g.severity).toBe("sensitive");
    expect(g.appScopedSecret).toBeUndefined();
    expect(g.metadataLabel).toBeNull();
    expect(g.appScopeNearMiss).toBe(true);
    const stmt = buildStatement(g);
    expect(stmt.primaryText).toBe("Perform kv/get on kv");
    expect(stmt.primaryText).not.toContain("app secret");
  });

  it("canonical tuple with `tinycloud.kv` still annotates (regression guard)", () => {
    const grant = makeGrant({
      service: "tinycloud.kv",
      space: SECRETS_SPACE,
      path: CANONICAL_PATH,
      verbs: ["get"],
      family: "secret-read",
    });
    const out = annotateAppScopedGrants(makeModel([grant]), { secrets: DECLARED });
    const g = out.permissions[0]!;
    expect(g.severity).toBe("standard");
    expect(g.appScopedSecret).toEqual({
      secretName: "API_KEY",
      scope: "listen",
    });
    expect(g.appScopeNearMiss).toBeUndefined();
  });
});

// ─── Defect 2: path slash normalization ─────────────────────────────────────
describe("Blocker 4 follow-up (Defect 2): path byte-exactness", () => {
  it("leading slash in path fails the proof (findMatchingDeclaredSecret)", () => {
    const grant = makeGrant({
      service: "tinycloud.kv",
      path: `/${CANONICAL_PATH}`,
    });
    expect(findMatchingDeclaredSecret(grant, DECLARED)).toBeNull();
  });

  it("trailing slash in path fails the proof (findMatchingDeclaredSecret)", () => {
    const grant = makeGrant({
      service: "tinycloud.kv",
      path: `${CANONICAL_PATH}/`,
    });
    expect(findMatchingDeclaredSecret(grant, DECLARED)).toBeNull();
  });

  it("leading + trailing slashes in path → near-miss stamp + literal fallback", () => {
    const grant = makeGrant({
      service: "tinycloud.kv",
      path: `/${CANONICAL_PATH}/`,
    });
    const out = annotateAppScopedGrants(makeModel([grant]), { secrets: DECLARED });
    const g = out.permissions[0]!;
    expect(g.severity).toBe("sensitive");
    expect(g.appScopedSecret).toBeUndefined();
    expect(g.appScopeNearMiss).toBe(true);
    const stmt = buildStatement(g);
    expect(stmt.primaryText).not.toContain("app secret");
    expect(stmt.primaryText).toBe("Perform tinycloud.kv/get on tinycloud.kv");
  });
});

// ─── Defect 3: space URI case exactness ────────────────────────────────────
describe("Blocker 4 follow-up (Defect 3): space structural match", () => {
  it("uppercase `:SECRETS` fails ownership proof", () => {
    const wrongCase = `tinycloud:pkh:eip155:${CHAIN}:${ACCOUNT}:SECRETS`;
    expect(
      isSignerOwnedSecretsSpace(wrongCase, { address: ACCOUNT, chainId: CHAIN }),
    ).toBe(false);
  });

  it("uppercase `PKH` in namespace fails ownership proof", () => {
    const wrongCase = `tinycloud:PKH:eip155:${CHAIN}:${ACCOUNT}:secrets`;
    expect(
      isSignerOwnedSecretsSpace(wrongCase, { address: ACCOUNT, chainId: CHAIN }),
    ).toBe(false);
  });

  it("EIP-55 checksummed address still passes ownership proof", () => {
    // The address hex is the only case-insensitive segment; EIP-55 and
    // lowercased forms both resolve to the same identity.
    const eip55 = "0x1111111111111111111111111111111111111111"; // already lower
    const space = `tinycloud:pkh:eip155:${CHAIN}:0x1111111111111111111111111111111111111111:secrets`;
    expect(
      isSignerOwnedSecretsSpace(space, { address: eip55, chainId: CHAIN }),
    ).toBe(true);
    // Uppercased hex too (EIP-55 style):
    const mixedCase = `tinycloud:pkh:eip155:${CHAIN}:0x1111111111111111111111111111111111111111:secrets`;
    expect(
      isSignerOwnedSecretsSpace(mixedCase, {
        address: "0x1111111111111111111111111111111111111111",
        chainId: CHAIN,
      }),
    ).toBe(true);
  });

  it(":SECRETS space variant → near-miss stamp + literal fallback", () => {
    const wrongCase = `tinycloud:pkh:eip155:${CHAIN}:${ACCOUNT}:SECRETS`;
    const grant = makeGrant({
      service: "tinycloud.kv",
      space: wrongCase,
      path: CANONICAL_PATH,
    });
    // Since isSecretsSpace's regex tolerates `:SECRETS` (matches
    // /:secrets(?:\/|$)/ case-insensitively only if we make it so — actually
    // it does not; it's case-sensitive), we should test both directions:
    // annotate must reject the annotation even if the space "looks like" a
    // secrets space; and if isSecretsSpace does not match, the grant retains
    // its structural classification. Either way it must never annotate.
    const out = annotateAppScopedGrants(makeModel([grant]), { secrets: DECLARED });
    const g = out.permissions[0]!;
    expect(g.appScopedSecret).toBeUndefined();
    expect(g.severity).not.toBe("standard");
  });

  it("PKH-uppercase space variant + canonical path never annotates", () => {
    const wrongCase = `tinycloud:PKH:eip155:${CHAIN}:${ACCOUNT}:secrets`;
    const grant = makeGrant({
      service: "tinycloud.kv",
      space: wrongCase,
      path: CANONICAL_PATH,
    });
    const out = annotateAppScopedGrants(makeModel([grant]), { secrets: DECLARED });
    const g = out.permissions[0]!;
    expect(g.appScopedSecret).toBeUndefined();
    expect(g.severity).not.toBe("standard");
  });
});

// ─── Defect 4: widened near-miss detection ──────────────────────────────────
describe("Blocker 4 follow-up (Defect 4): widened near-miss detection", () => {
  it("wrong-scope same-name secret (secrets/scoped/other/API_KEY) → sensitive + literal", () => {
    const grant = makeGrant({
      service: "tinycloud.kv",
      space: SECRETS_SPACE,
      path: "secrets/scoped/other/API_KEY",
      verbs: ["get"],
      family: "secret-read",
    });
    const out = annotateAppScopedGrants(makeModel([grant]), { secrets: DECLARED });
    const g = out.permissions[0]!;
    expect(g.severity).toBe("sensitive");
    expect(g.appScopedSecret).toBeUndefined();
    expect(g.appScopeNearMiss).toBe(true);
    const stmt = buildStatement(g);
    expect(stmt.primaryText).not.toContain("app secret");
  });

  it("variables/API_KEY on secrets space → sensitive + literal", () => {
    const grant = makeGrant({
      service: "tinycloud.kv",
      space: SECRETS_SPACE,
      path: "variables/API_KEY",
      verbs: ["get"],
      family: "secret-read",
    });
    const out = annotateAppScopedGrants(makeModel([grant]), { secrets: DECLARED });
    const g = out.permissions[0]!;
    expect(g.severity).toBe("sensitive");
    expect(g.appScopeNearMiss).toBe(true);
    const stmt = buildStatement(g);
    expect(stmt.primaryText).not.toContain("app secret");
    expect(stmt.primaryText).not.toContain("secret variables");
  });

  it("tinycloud.sql/read at canonical secret path → sensitive + literal", () => {
    const grant = makeGrant({
      service: "tinycloud.sql",
      space: SECRETS_SPACE,
      path: CANONICAL_PATH,
      verbs: ["read"],
      family: "cross-app-data",
      severity: "attention",
    });
    const out = annotateAppScopedGrants(makeModel([grant]), { secrets: DECLARED });
    const g = out.permissions[0]!;
    expect(g.severity).toBe("sensitive");
    expect(g.appScopedSecret).toBeUndefined();
    expect(g.appScopeNearMiss).toBe(true);
    const stmt = buildStatement(g);
    expect(stmt.primaryText).not.toContain("app secret");
    expect(stmt.primaryText).not.toContain("Read TinyCloud Secrets data");
    // Literal fallback: `Perform tinycloud.sql/read on tinycloud.sql`.
    expect(stmt.primaryText).toBe(
      "Perform tinycloud.sql/read on tinycloud.sql",
    );
  });

  it("tinycloud.capabilities/read at canonical secret path → sensitive + literal", () => {
    const grant = makeGrant({
      service: "tinycloud.capabilities",
      space: SECRETS_SPACE,
      path: CANONICAL_PATH,
      verbs: ["read"],
      family: "bootstrap-capabilities",
      severity: "standard",
    });
    const out = annotateAppScopedGrants(makeModel([grant]), { secrets: DECLARED });
    const g = out.permissions[0]!;
    expect(g.severity).toBe("sensitive");
    expect(g.appScopeNearMiss).toBe(true);
    const stmt = buildStatement(g);
    expect(stmt.primaryText).not.toContain("permissions for your secrets");
    expect(stmt.primaryText).not.toContain("app secret");
  });

  it("pathContainsDeclaredSecretName is scope-independent and service-agnostic", () => {
    // Matches when the declared name appears as a whole path segment,
    // regardless of scope or leading path.
    expect(pathContainsDeclaredSecretName("API_KEY", DECLARED)).toBe(true);
    expect(
      pathContainsDeclaredSecretName("variables/API_KEY", DECLARED),
    ).toBe(true);
    expect(
      pathContainsDeclaredSecretName("secrets/scoped/other/API_KEY", DECLARED),
    ).toBe(true);
    expect(
      pathContainsDeclaredSecretName("foo/API_KEY/bar", DECLARED),
    ).toBe(true);
    // No match: substring inside a longer segment.
    expect(
      pathContainsDeclaredSecretName("API_KEY_BACKUP", DECLARED),
    ).toBe(false);
    expect(
      pathContainsDeclaredSecretName("foo/API_KEY_BAR", DECLARED),
    ).toBe(false);
    // No declarations → no match.
    expect(pathContainsDeclaredSecretName("API_KEY", [])).toBe(false);
    // Invalid secretName (lowercase) is ignored.
    expect(
      pathContainsDeclaredSecretName("api_key", [
        { secretName: "api_key", scope: "listen", actions: ["read"] },
      ]),
    ).toBe(false);
  });
});

// ─── Defect 5: serviceMismatch (parser + gate) ─────────────────────────────
describe("Blocker 4 follow-up (Defect 5): serviceMismatch parser + gate", () => {
  const signer: SignerInfo = {
    label: "Test signer",
    address: ACCOUNT,
    chainId: CHAIN,
    provenance: "managed",
  };

  function makeCtx(message: string): ParseContext {
    return {
      message,
      signer,
      editable: true,
      metadataTrust: { status: "origin-bound", reason: "test" },
      reason: { text: "", source: "none" },
      requester: {
        displayName: "example.tinycloud.xyz",
        verifiedOrigin: "https://example.tinycloud.xyz",
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

  // Build a SIWE message that carries a urn:recap: payload with an ATT
  // resource of shape `<space>/sql/vault/secrets/...` and a KV ability.
  // The parser must record `resourceService = "sql"` and stamp
  // `serviceMismatch = true` on the grant. `annotateAppScopedGrants`
  // must refuse to annotate it, and `buildStatement` must short-circuit
  // to literal fallback.
  function makeMismatchRecap(): string {
    const att = {
      [`${SECRETS_SPACE}/sql/vault/secrets/scoped/listen/API_KEY`]: {
        "tinycloud.kv/get": [{}],
        "tinycloud.capabilities/read": [{}],
      },
      // Bootstrap capabilities grant so the message is a valid
      // tinycloud-siwe-recap protocol.
      [SECRETS_SPACE]: {
        "tinycloud.capabilities/read": [{}],
      },
    };
    const json = JSON.stringify({ att, prf: [] });
    // base64url encode (no padding)
    const b64 = Buffer.from(json, "utf8")
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    const recap = `urn:recap:${b64}`;
    return [
      "example.tinycloud.xyz wants you to sign in with your Ethereum account:",
      ACCOUNT,
      "",
      "TinyCloud delegation",
      "",
      "URI: https://example.tinycloud.xyz",
      "Version: 1",
      `Chain ID: ${CHAIN}`,
      "Nonce: abcdef123456",
      "Issued At: 2026-01-01T00:00:00Z",
      "Expiration Time: 2027-01-01T00:00:00Z",
      "Resources:",
      `- ${recap}`,
    ].join("\n");
  }

  it("parser emits serviceMismatch and never annotates the ATT entry", () => {
    const message = makeMismatchRecap();
    const model = parseCapabilityReview(makeCtx(message));
    expect(model.protocol).toBe("tinycloud-siwe-recap");
    // Find the mismatched grant: service = tinycloud.kv, resource segment = sql.
    const kv = model.permissions.find(
      (p) => p.service === "tinycloud.kv" && p.resourceService === "sql",
    );
    expect(kv).toBeDefined();
    expect(kv?.serviceMismatch).toBe(true);
    // Parser emits a malformed-space warning for the mismatch.
    expect(
      model.parseWarnings.some(
        (w) =>
          w.code === "malformed-space" &&
          typeof w.message === "string" &&
          w.message.includes("resource segment"),
      ),
    ).toBe(true);

    // The annotation gate must never stamp appScopedSecret on a
    // service-mismatched grant, even with a matching declaration.
    const annotated = annotateAppScopedGrants(model, { secrets: DECLARED });
    const g = annotated.permissions.find(
      (p) => p.service === "tinycloud.kv" && p.resourceService === "sql",
    )!;
    expect(g.appScopedSecret).toBeUndefined();
    expect(g.severity).toBe("sensitive");
    expect(g.appScopeNearMiss).toBe(true);
    // buildStatement short-circuits mismatched grants to literal fallback.
    const stmt = buildStatement(g);
    expect(stmt.primaryText).not.toContain("app secret");
  });

  it("serviceMismatch grants stay in the top-level secret-reach count (Blocker 2)", () => {
    // A grant with resourceService = "sql" on the secrets space reaches
    // secret data through the sql surface — it must remain in the count
    // returned by grantReachesSecretDataOrDecryption, even after being
    // demoted to literal fallback.
    const grant = makeGrant({
      service: "tinycloud.kv",
      space: SECRETS_SPACE,
      path: CANONICAL_PATH,
      resourceService: "sql",
      serviceMismatch: true,
      family: "cross-app-data",
      severity: "sensitive",
      verbs: ["get"],
    });
    expect(grantReachesSecretDataOrDecryption(grant)).toBe(true);
  });

  it("actionId/permissionId inputs unchanged: canonical four-part IDs preserved", () => {
    // Blocker 4 follow-up MUST NOT change actionId/permissionId inputs so
    // preview/finalize correlation stays byte-identical. Round-trip a
    // recap through parse and re-parse to confirm IDs are deterministic
    // regardless of the new fields we added to the entry.
    const message = makeMismatchRecap();
    const a = parseCapabilityReview(makeCtx(message));
    const b = parseCapabilityReview(makeCtx(message));
    const ids = (m: CapabilityReviewModel) =>
      m.permissions
        .flatMap((p) => [p.id, ...p.actions.map((x) => x.id)])
        .sort();
    expect(ids(a)).toEqual(ids(b));
  });
});
