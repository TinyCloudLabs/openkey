// Sol final-continuation Blockers A, B, C regression suite.
//
// Locks in the three defects Sol identified after the MAJOR-1..3 approval:
//
//   Blocker A: Widgets constructed the review signer with a hard-coded
//     chainId=1 instead of parsing it from the actual SIWE. A SIWE
//     signed on chain 8453 with a resource space
//     `tinycloud:pkh:eip155:8453:<signer>:secrets` was compared against
//     the chain-1 identity in `expectedSignerSecretsSpace`, so the
//     ownership proof passed for the wrong chain and the grant received a
//     trusted app-scoped label. Fix: `parseSiweChainId` in @openkey/capability-review
//     lets the widgets derive the chain ID from the signed bytes.
//
//   Blocker B: The app-scope proof gate lowered grant-side abilities and
//     synonym-normalized them (`normalizeSecretVerb(a.verb.toLowerCase())`),
//     so `tinycloud.kv/GET` and `tinycloud.kv/read` earned trusted app-scoped
//     copy even though no js-sdk producer emits either shape.
//     Fix: grant-side abilities are compared BYTE-EXACTLY against a
//     canonical URN allowlist (`tinycloud.kv/get`|`put`|`del`).
//
//   Blocker C: Near-miss fingerprinting only accepted manifests whose
//     RAW scope matched `/^[a-z0-9-]+$/`. js-sdk canonicalizes raw
//     scopes like `Listen App`, ` listen app `, or `listen--app` all to
//     `listen-app` before emitting the signed vault path, so a grant on
//     `vault/secrets/scoped/listen-app/API_KEY` with a manifest
//     declaring `scope: "Listen App"` produced no fingerprint and
//     escaped to friendly copy. Fix: fingerprint helpers canonicalize
//     the declared scope via `canonicalizeSecretScopeForFingerprint`
//     before comparing.

import { describe, expect, it } from "bun:test";

import {
  annotateAppScopedGrants,
  canonicalizeSecretScopeForFingerprint,
  CANONICAL_APP_SCOPE_SECRET_ABILITIES,
  findMatchingDeclaredSecret,
  parseSiweChainId,
  pathContainsDeclaredSecretFragment,
  pathContainsDeclaredSecretName,
  type CapabilityGrant,
  type CapabilityReviewModel,
  type DeclaredScopedSecret,
} from "../src/index.js";
import { buildStatement } from "../src/statements.js";

const ACCOUNT = "0x1111111111111111111111111111111111111111";

function secretsSpaceFor(chainId: number, address: string = ACCOUNT): string {
  return `tinycloud:pkh:eip155:${chainId}:${address}:secrets`;
}

function makeGrant(input: {
  ability: string;
  space: string;
  path: string;
  service?: string;
  family?: CapabilityGrant["family"];
  severity?: CapabilityGrant["severity"];
}): CapabilityGrant {
  const service = input.service ?? input.ability.slice(0, input.ability.indexOf("/"));
  const verb = input.ability.slice(input.ability.indexOf("/") + 1);
  return {
    id: `${service}\x00${input.space}\x00${input.path}`,
    family: input.family ?? "secret-read",
    severity: input.severity ?? "sensitive",
    service,
    space: input.space,
    path: input.path,
    owner: ACCOUNT,
    ownedBySelf: true,
    displayLabel: "",
    metadataLabel: null,
    resourceService: null,
    actions: [
      {
        id: `${service}\x00${input.space}\x00${input.path}\x00${input.ability}`,
        ability: input.ability,
        verb,
        required: false,
        selected: true,
        editable: true,
        caveats: [{}],
      },
    ],
  };
}

function makeModel(
  grants: CapabilityGrant[],
  chainId: number = 1,
): CapabilityReviewModel {
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
      chainId,
      provenance: "managed",
    },
    expiry: null,
    immutable: null,
    metadataTrust: { status: "origin-bound", reason: "test" },
    permissions: grants,
    parseWarnings: [],
  };
}

// ─── Blocker A: SIWE chain-ID parser ────────────────────────────────────────
describe("Sol Blocker A: parseSiweChainId", () => {
  function siweWithChain(chainId: number): string {
    return [
      "example.tinycloud.xyz wants you to sign in with your Ethereum account:",
      ACCOUNT,
      "",
      "TinyCloud delegation",
      "",
      "URI: https://example.tinycloud.xyz",
      "Version: 1",
      `Chain ID: ${chainId}`,
      "Nonce: abcdef123456",
      "Issued At: 2026-01-01T00:00:00Z",
      "Expiration Time: 2027-01-01T00:00:00Z",
    ].join("\n");
  }

  it("parses mainnet Chain ID 1", () => {
    expect(parseSiweChainId(siweWithChain(1))).toBe(1);
  });

  it("parses Base Chain ID 8453 (the Sol probe chain)", () => {
    expect(parseSiweChainId(siweWithChain(8453))).toBe(8453);
  });

  it("parses Polygon Chain ID 137", () => {
    expect(parseSiweChainId(siweWithChain(137))).toBe(137);
  });

  it("returns null when no SIWE Chain ID line is present", () => {
    expect(parseSiweChainId("plain text with no siwe")).toBeNull();
  });

  it("returns null when Chain ID value is non-integer text", () => {
    const message = siweWithChain(1).replace("Chain ID: 1", "Chain ID: abc");
    expect(parseSiweChainId(message)).toBeNull();
  });
});

describe("Sol Blocker A: wrong-chain ownership proof fails closed", () => {
  const DECLARED: DeclaredScopedSecret[] = [
    { secretName: "API_KEY", scope: "listen", actions: ["read"] },
  ];

  it("SIWE signed on chain 8453 does NOT annotate a chain-1 signer identity", () => {
    // Sol's Blocker A probe repro: SIWE with `Chain ID: 8453` and
    // resource space `tinycloud:pkh:eip155:8453:<signer>:secrets`.
    // The widget MUST NOT construct the signer with chainId=1 and let
    // the ownership check pass a mismatched-chain resource URI.
    const chain8453Space = secretsSpaceFor(8453);
    const grant = makeGrant({
      ability: "tinycloud.kv/get",
      space: chain8453Space,
      path: "vault/secrets/scoped/listen/API_KEY",
    });
    // Model built with the WRONG (hard-coded) chain-1 signer identity.
    // The ownership proof must reject the mismatched space so the grant
    // never receives trusted app-scoped annotation.
    const out = annotateAppScopedGrants(makeModel([grant], 1), {
      secrets: DECLARED,
    });
    const g = out.permissions[0]!;
    expect(g.severity).toBe("sensitive");
    expect(g.appScopedSecret).toBeUndefined();
    expect(g.appScopeNearMiss).toBe(true);
  });

  it("SIWE signed on chain 8453 annotates the chain-8453 signer identity", () => {
    // Regression guard: when the widget correctly parses chainId=8453
    // from the SIWE and constructs the signer with it, the same
    // resource URI passes the ownership proof and gets annotated.
    const chain8453Space = secretsSpaceFor(8453);
    const grant = makeGrant({
      ability: "tinycloud.kv/get",
      space: chain8453Space,
      path: "vault/secrets/scoped/listen/API_KEY",
    });
    const out = annotateAppScopedGrants(makeModel([grant], 8453), {
      secrets: DECLARED,
    });
    const g = out.permissions[0]!;
    expect(g.severity).toBe("sensitive");
    expect(g.appScopedSecret).toEqual({
      secretName: "API_KEY",
      scope: "listen",
    });
  });
});

// ─── Blocker B: exact-byte canonical ability allowlist ─────────────────────
describe("Sol Blocker B: canonical grant-side ability allowlist", () => {
  const DECLARED: DeclaredScopedSecret[] = [
    { secretName: "API_KEY", scope: "listen", actions: ["read", "write"] },
  ];

  it("exposes the canonical wire ability allowlist", () => {
    expect(CANONICAL_APP_SCOPE_SECRET_ABILITIES.has("tinycloud.kv/get")).toBe(
      true,
    );
    expect(CANONICAL_APP_SCOPE_SECRET_ABILITIES.has("tinycloud.kv/put")).toBe(
      true,
    );
    expect(CANONICAL_APP_SCOPE_SECRET_ABILITIES.has("tinycloud.kv/del")).toBe(
      true,
    );
    // Anything outside must be rejected — no case-fold, no synonym.
    expect(CANONICAL_APP_SCOPE_SECRET_ABILITIES.has("tinycloud.kv/GET")).toBe(
      false,
    );
    expect(CANONICAL_APP_SCOPE_SECRET_ABILITIES.has("tinycloud.kv/read")).toBe(
      false,
    );
    expect(CANONICAL_APP_SCOPE_SECRET_ABILITIES.has("kv/get")).toBe(false);
  });

  it("tinycloud.kv/read (long-form synonym) does NOT annotate (Sol Blocker B probe)", () => {
    // The Sol probe: a grant with ability `tinycloud.kv/read` and a
    // matching declared entry received trusted app-scoped copy because the
    // prior gate folded `read` -> `get`. No js-sdk producer emits
    // `tinycloud.kv/read` on the wire; the exact-byte gate must reject.
    const grant = makeGrant({
      ability: "tinycloud.kv/read",
      space: secretsSpaceFor(1),
      path: "vault/secrets/scoped/listen/API_KEY",
    });
    const out = annotateAppScopedGrants(makeModel([grant]), {
      secrets: DECLARED,
    });
    const g = out.permissions[0]!;
    expect(g.severity).toBe("sensitive");
    expect(g.appScopedSecret).toBeUndefined();
    expect(g.appScopeNearMiss).toBe(true);
    // Literal fallback renders the raw ability so the operator sees the
    // non-canonical wire form verbatim.
    const stmt = buildStatement(g);
    expect(stmt.primaryText).toBe(
      "Perform tinycloud.kv/read on tinycloud.kv",
    );
    expect(stmt.primaryText).not.toContain("app secret");
  });

  it("tinycloud.kv/GET (uppercase verb) does NOT annotate (Sol Blocker B probe)", () => {
    // Case-folded probe: prior gate did `verb.toLowerCase()` so `GET`
    // matched `get`. Exact-byte match must reject.
    const grant = makeGrant({
      ability: "tinycloud.kv/GET",
      space: secretsSpaceFor(1),
      path: "vault/secrets/scoped/listen/API_KEY",
    });
    const out = annotateAppScopedGrants(makeModel([grant]), {
      secrets: DECLARED,
    });
    const g = out.permissions[0]!;
    expect(g.severity).toBe("sensitive");
    expect(g.appScopedSecret).toBeUndefined();
    expect(g.appScopeNearMiss).toBe(true);
  });

  it("findMatchingDeclaredSecret rejects tinycloud.kv/read", () => {
    // The proof-side helper must also apply exact-byte matching. Prior
    // implementation folded grant verbs before comparing so `read`
    // matched declared `read`.
    const grant = makeGrant({
      ability: "tinycloud.kv/read",
      space: secretsSpaceFor(1),
      path: "vault/secrets/scoped/listen/API_KEY",
    });
    expect(findMatchingDeclaredSecret(grant, DECLARED)).toBeNull();
  });

  it("findMatchingDeclaredSecret rejects tinycloud.kv/GET", () => {
    const grant = makeGrant({
      ability: "tinycloud.kv/GET",
      space: secretsSpaceFor(1),
      path: "vault/secrets/scoped/listen/API_KEY",
    });
    expect(findMatchingDeclaredSecret(grant, DECLARED)).toBeNull();
  });

  it("canonical tinycloud.kv/get still annotates (regression guard)", () => {
    const grant = makeGrant({
      ability: "tinycloud.kv/get",
      space: secretsSpaceFor(1),
      path: "vault/secrets/scoped/listen/API_KEY",
    });
    const out = annotateAppScopedGrants(makeModel([grant]), {
      secrets: DECLARED,
    });
    const g = out.permissions[0]!;
    expect(g.severity).toBe("sensitive");
    expect(g.appScopedSecret).toEqual({
      secretName: "API_KEY",
      scope: "listen",
    });
  });
});

// ─── Blocker C: near-miss fingerprint uses canonical scope ─────────────────
describe("Sol Blocker C: canonicalized-scope near-miss fingerprint", () => {
  it("canonicalizeSecretScopeForFingerprint mirrors js-sdk canonicalization", () => {
    expect(canonicalizeSecretScopeForFingerprint("Listen App")).toBe(
      "listen-app",
    );
    expect(canonicalizeSecretScopeForFingerprint(" listen app ")).toBe(
      "listen-app",
    );
    expect(canonicalizeSecretScopeForFingerprint("listen--app")).toBe(
      "listen-app",
    );
    expect(canonicalizeSecretScopeForFingerprint("listen-app")).toBe(
      "listen-app",
    );
    // Reserved scopes return null.
    expect(canonicalizeSecretScopeForFingerprint("default")).toBeNull();
    expect(canonicalizeSecretScopeForFingerprint("global")).toBeNull();
    // Empty / only-separator input returns null.
    expect(canonicalizeSecretScopeForFingerprint("")).toBeNull();
    expect(canonicalizeSecretScopeForFingerprint("   ")).toBeNull();
    expect(canonicalizeSecretScopeForFingerprint("---")).toBeNull();
  });

  it("pathContainsDeclaredSecretName fires for uppercase-scope declarations", () => {
    // Sol Blocker C probe: manifest declares `scope: "Listen App"` (which
    // js-sdk canonicalizes to `listen-app`). The signed grant path
    // therefore carries `vault/secrets/scoped/listen-app/API_KEY`. The
    // fingerprint MUST match so near-miss stamping fires.
    const declared: DeclaredScopedSecret[] = [
      { secretName: "API_KEY", scope: "Listen App", actions: ["read"] },
    ];
    expect(
      pathContainsDeclaredSecretName(
        "vault/secrets/scoped/listen-app/API_KEY",
        declared,
      ),
    ).toBe(true);
  });

  it("pathContainsDeclaredSecretFragment fires for uppercase-scope declarations", () => {
    const declared: DeclaredScopedSecret[] = [
      { secretName: "API_KEY", scope: "Listen App", actions: ["read"] },
    ];
    // Fragment match uses the CANONICALIZED scope: `listen-app/API_KEY`.
    expect(
      pathContainsDeclaredSecretFragment(
        "vault/secrets/scoped/listen-app/API_KEY",
        declared,
      ),
    ).toBe(true);
  });

  it("wrong-service grant with non-canonical raw scope declaration → sensitive + literal", () => {
    // Sol Blocker C end-to-end: manifest declares `scope: "Listen App"`
    // plus a `tinycloud.capabilities/read` grant at the canonical
    // secret path. Prior code skipped the declaration in near-miss
    // fingerprinting because `"Listen App"` failed SECRET_SCOPE_RE,
    // so the wrong-service grant retained misleading friendly copy. Post-fix:
    // the fingerprint fires and near-miss stamping forces literal
    // fallback + sensitive severity.
    const declared: DeclaredScopedSecret[] = [
      { secretName: "API_KEY", scope: "Listen App", actions: ["read"] },
    ];
    const grant = makeGrant({
      ability: "tinycloud.capabilities/read",
      service: "tinycloud.capabilities",
      space: secretsSpaceFor(1),
      path: "vault/secrets/scoped/listen-app/API_KEY",
      family: "bootstrap-capabilities",
      severity: "standard",
    });
    const out = annotateAppScopedGrants(makeModel([grant]), {
      secrets: declared,
    });
    const g = out.permissions[0]!;
    expect(g.severity).toBe("sensitive");
    expect(g.appScopedSecret).toBeUndefined();
    expect(g.appScopeNearMiss).toBe(true);
    const stmt = buildStatement(g);
    expect(stmt.primaryText).not.toContain("permissions for your secrets");
    expect(stmt.primaryText).not.toContain("app secret");
  });

  it("KV wrong-scope grant with `listen--app` declaration → sensitive + literal", () => {
    // The declaration is `listen--app` (double dash); js-sdk emits the
    // signed vault path with `listen-app` (single dash). The name
    // fingerprint MUST fire so the grant on the canonical path never
    // escapes to friendly KV secrets copy.
    const declared: DeclaredScopedSecret[] = [
      { secretName: "API_KEY", scope: "listen--app", actions: ["read"] },
    ];
    const grant = makeGrant({
      ability: "tinycloud.kv/get",
      space: secretsSpaceFor(1),
      path: "vault/secrets/scoped/listen-app/API_KEY",
      family: "secret-read",
    });
    const out = annotateAppScopedGrants(makeModel([grant]), {
      secrets: declared,
    });
    const g = out.permissions[0]!;
    // findMatchingDeclaredSecret still rejects the non-canonical
    // declaration (Sol MAJOR-1 fix retained), so the grant fails the
    // proof gate. Post-Blocker-C fix, the fingerprint fires with the
    // canonicalized scope and stamps near-miss + sensitive.
    expect(g.severity).toBe("sensitive");
    expect(g.appScopedSecret).toBeUndefined();
    expect(g.appScopeNearMiss).toBe(true);
  });

  it("reserved-scope declaration still fingerprints on the secret name (regression)", () => {
    // A declaration with a reserved scope is invalid, but the name
    // fingerprint still fires on any grant whose path contains the
    // declared secret name. This matches the prior scope-independent
    // name fingerprint behaviour.
    const declared: DeclaredScopedSecret[] = [
      { secretName: "API_KEY", scope: "default", actions: ["read"] },
    ];
    expect(pathContainsDeclaredSecretName("variables/API_KEY", declared)).toBe(
      false,
    );
    // A valid declaration on a real scope, however, does fingerprint:
    const validDeclared: DeclaredScopedSecret[] = [
      { secretName: "API_KEY", scope: "listen", actions: ["read"] },
    ];
    expect(
      pathContainsDeclaredSecretName("variables/API_KEY", validDeclared),
    ).toBe(true);
  });
});
