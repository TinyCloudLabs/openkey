// App-scoped-secret trust rule (Sol MAJOR-2 / Blocker 4).
//
// The merge-readiness contract says:
//
//   A scoped secret can be presented as normal/app-scoped only when a
//   trusted or independently origin-bound manifest declares that exact
//   secret, scope, and requested actions and the signed resource carries
//   the same scope. Otherwise it remains sensitive. No metadata may
//   expand authority.
//
// This helper takes a parsed `CapabilityReviewModel` plus the
// origin-bound declared-app-scope block the server extracted from the
// well-known manifest, and:
//
//   1. For every capability grant, decides whether the grant matches an
//      app-declared secret entry via an EXACT resource tuple:
//        - service must be a KV service (tinycloud.kv or kv), never tinycloud.secrets
//        - space must be the structurally-named secrets space
//        - path must equal exactly vault/secrets/scoped/<scope>/<name>
//          (the canonical js-sdk shape from packages/sdk-services/src/secrets/paths.ts)
//        - secretName must match /^[A-Z][A-Z0-9_]*$/
//        - scope must match /^[a-z0-9-]+$/ and not be 'default' or 'global'
//        - grant verbs must be a subset of declared verbs within the
//          recognized get/put/del allowlist
//   2. When ALL conditions hold AND the metadata trust is at least origin-bound,
//      records the proven app-scoped-secret identity, renders a compact label,
//      and presents the grant at standard severity.
//   3. Under ANY other condition leaves the grant untouched (fail closed).
//
// The severity change is intentionally confined to this proof gate. Generic
// metadata helpers still cannot lower severity (see metadata.ts), and this
// helper never changes the authority-bearing actions or resource.

import type {
  CapabilityGrant,
  CapabilityReviewModel,
  SignerInfo,
} from "./model.js";
import { isVerified } from "./metadata.js";

/**
 * Blocker 4 follow-up (Defect 1): PROOF-SIDE exact service allowlist.
 *
 * The sole ability-derived service that can pass the exact-resource proof
 * (and receive the sensitive → standard demotion) is the fully-qualified
 * `tinycloud.kv`. Bare short-form abilities (`kv/get`, `kv/put`, `kv/del`)
 * were previously admitted, but no js-sdk producer emits them — treating
 * them as acceptable expands the proof surface without a matching wire
 * shape. `annotateAppScopedGrants` and `buildStatement`'s defense-in-depth
 * branch use this set to reject anything but the canonical service.
 *
 * A grant flagged with `serviceMismatch: true` (ability-derived service
 * disagrees with the resource-derived short-service segment) is ALSO
 * rejected by the proof gate even if its `service` is `tinycloud.kv`.
 */
export const KV_SECRET_SERVICES_PROOF: ReadonlySet<string> = new Set([
  "tinycloud.kv",
]);

/**
 * NEAR-MISS candidacy set (loose): services whose grants participate in the
 * declared-shape fingerprint check. Wider than the proof set so a bare
 * short-form `kv/get` grant that references a declared secret name still
 * gets stamped `appScopeNearMiss` (literal fallback + sensitive) instead
 * of escaping to friendly copy. Presence in this set never grants
 * annotation on its own; the proof gate is the authoritative demotion path.
 */
export const KV_SECRET_SERVICES_LOOSE: ReadonlySet<string> = new Set([
  "tinycloud.kv",
  "kv",
]);

/**
 * Backwards-compatible alias for external consumers (statements.ts,
 * downstream tests). Points at the loose set so structural counting
 * predicates that ask "is this a KV secret service?" continue to include
 * both the fully-qualified and short forms. The proof gate uses
 * `KV_SECRET_SERVICES_PROOF` internally for exact matching.
 */
export const KV_SECRET_SERVICES: ReadonlySet<string> = KV_SECRET_SERVICES_LOOSE;

/**
 * Named-secrets services. `tinycloud.secrets/*` grants are a DIFFERENT surface
 * from the KV vault path used by app-scoped secrets and CAN NEVER earn the
 * sensitive -> standard demotion. This set is used only for near-miss
 * detection: a `tinycloud.secrets/*` grant whose path fingerprint references
 * a declared secret name/scope MUST be forced to sensitive severity + literal
 * fallback (Blocker 4, Sol follow-up probe A) — the friendly SECRETS_SERVICES
 * branch of `buildStatement` (e.g. "Check permissions for your secrets") is
 * never allowed when the operator is being invited to trust an app-scope
 * declaration that this grant does not, in fact, satisfy.
 */
export const NAMED_SECRETS_SERVICES: ReadonlySet<string> = new Set([
  "tinycloud.secrets",
  "secrets",
]);

/**
 * Loose structural predicate: true when `space` looks like ANY secrets space.
 *
 * Kept as the shared "structural counting" predicate imported by statements.ts
 * so `grantReachesSecretDataOrDecryption` and other structural surfaces treat
 * every secrets-shaped space as reaching secret data. This predicate is NOT
 * sufficient by itself for the app-scoped-secret proof gate — a caller cannot
 * be trusted just because they target a secrets-shaped space they may not
 * even own. Use `isSignerOwnedSecretsSpace` for the exact ownership proof.
 */
export function isSecretsSpace(space: string): boolean {
  return (
    space === "secrets" ||
    /:secrets(?:\/|$)/.test(space) ||
    /:secrets:/.test(space)
  );
}

/**
 * Blocker 4 (Defect 1): exact manifest-derived secrets-space proof.
 *
 * The real js-sdk secrets resolver
 * (`packages/sdk-services/src/secrets/paths.ts`) always targets a KV path
 * inside the SIGNER's own secrets space:
 *
 *   tinycloud:pkh:eip155:<chainId>:<signerAddress>:secrets
 *
 * The pre-fix `isSecretsSpace` was purely a shape check — it accepted the
 * literal string `"secrets"` OR any space whose path contained `:secrets`.
 * That would happily accept a probe signed by 0x1111…1111 targeting a
 * space owned by 0x2222…2222, since the string still contains `:secrets`.
 * `annotateAppScopedGrants` would then demote the cross-signer grant to
 * standard severity, breaking the app-scope trust rule which requires the
 * signed grant's space to be the same one the manifest declaration
 * describes.
 *
 * `expectedSignerSecretsSpace` returns the canonical space string derived
 * from a signer identity. It always emits an EIP-55-independent form: the
 * address hex is lowercased, matching the canonical PKH form the js-sdk
 * spaceId helper produces. Space matching is likewise done
 * case-insensitively on the hex so both `0xABCD…` and `0xabcd…` variants
 * resolve to the same identity.
 */
export function expectedSignerSecretsSpace(signer: {
  address: string;
  chainId: number;
}): string {
  return `tinycloud:pkh:eip155:${signer.chainId}:${signer.address.toLowerCase()}:secrets`;
}

/**
 * Blocker 4 (Defect 1) — follow-up: true only when `space` is the EXACT
 * signer-owned canonical secrets space derived from `signer.address` +
 * `signer.chainId`, with STRUCTURAL matching rather than a whole-URI
 * lowercase compare.
 *
 * The prior implementation `space.toLowerCase() === expectedSignerSecretsSpace(...)`
 * accepted spellings that carried an uppercased scheme (`PKH`) or an
 * uppercased trailing space name (`:SECRETS`), because they collapsed to
 * the same string once lowercased. The signed wire form uses the exact
 * lowercase literals `tinycloud:pkh:eip155:` and `:secrets` — anything
 * else is either a caller mangling the space or a fingerprint of a
 * different backend surface. Only the address hex is compared case-
 * insensitively so EIP-55 vs lowercased addresses both pass.
 */
export function isSignerOwnedSecretsSpace(
  space: string,
  signer: { address: string; chainId: number },
): boolean {
  const expectedPrefix = `tinycloud:pkh:eip155:${signer.chainId}:`;
  const expectedSuffix = ":secrets";
  if (!space.startsWith(expectedPrefix)) return false;
  if (!space.endsWith(expectedSuffix)) return false;
  const addr = space.slice(
    expectedPrefix.length,
    space.length - expectedSuffix.length,
  );
  if (!/^0x[0-9a-fA-F]{40}$/.test(addr)) return false;
  return addr.toLowerCase() === signer.address.toLowerCase();
}

// Secret-name and scope validation mirrors js-sdk
// packages/sdk-services/src/secrets/paths.ts so the OpenKey gate and the
// js-sdk resolver share the same canonical forms.
const SECRET_NAME_RE = /^[A-Z][A-Z0-9_]*$/;
const SECRET_SCOPE_RE = /^[a-z0-9-]+$/;
const RESERVED_SCOPES = new Set(["default", "global"]);

/**
 * Near-miss fingerprint (Blocker 4, Sol follow-up).
 *
 * Returns true when the grant path contains a `<scope>/<secretName>` fragment
 * matching ANY validly-declared secret entry. Used only to widen the near-miss
 * enforcement above so that a grant on a KV or named-secrets service which
 * references a declared secret name gets stamped near-miss even if it does
 * not sit at the canonical `vault/secrets/scoped/<scope>/<name>` shape or on
 * the signer's own secrets space. The check is a fingerprint, NOT an
 * authorization signal — matching only forces literal-fallback rendering; it
 * never grants annotation. Only declared entries that pass the SECRET_NAME_RE
 * / SECRET_SCOPE_RE / reserved-scope validation participate, so a manifest
 * cannot smuggle arbitrary strings into the fingerprint.
 */
export function pathContainsDeclaredSecretFragment(
  path: string,
  secrets: readonly DeclaredScopedSecret[],
): boolean {
  if (!path || secrets.length === 0) return false;
  const normalizedPath = path.replace(/^\/+/, "").replace(/\/+$/, "");
  for (const declared of secrets) {
    if (!declared.scope) continue;
    if (!SECRET_NAME_RE.test(declared.secretName)) continue;
    if (!SECRET_SCOPE_RE.test(declared.scope)) continue;
    if (RESERVED_SCOPES.has(declared.scope)) continue;
    const fragment = `${declared.scope}/${declared.secretName}`;
    // Match as a whole-segment substring: either at end of path, or
    // followed by another slash. This avoids accidental matches inside
    // longer identifier segments.
    if (
      normalizedPath === fragment ||
      normalizedPath.endsWith(`/${fragment}`) ||
      normalizedPath.includes(`/${fragment}/`) ||
      normalizedPath.startsWith(`${fragment}/`)
    ) {
      return true;
    }
  }
  return false;
}

/**
 * Blocker 4 follow-up (Defect 4): scope-independent, service-agnostic
 * near-miss fingerprint.
 *
 * Returns true when the grant path contains ANY declared `secretName`
 * (that passes `SECRET_NAME_RE`) as a WHOLE PATH SEGMENT. Unlike
 * `pathContainsDeclaredSecretFragment`, this variant does NOT require the
 * scope segment to appear next to the name — it catches grants of the
 * shape `<anything>/API_KEY`, `secrets/scoped/other/API_KEY`,
 * `variables/API_KEY`, or `API_KEY` alone, where the declared secret
 * name is present and could plausibly reach the underlying secret bytes.
 *
 * This is the primary fingerprint used to force literal-fallback rendering
 * on wrong-scope / wrong-service paths that share only the declared name
 * with the trusted declaration. It is a fingerprint, NOT an authorization
 * signal — matching only demotes to sensitive + literal fallback, never
 * annotates. Only declared entries that pass SECRET_NAME_RE participate
 * so a manifest cannot smuggle arbitrary substrings into the fingerprint.
 */
export function pathContainsDeclaredSecretName(
  path: string,
  secrets: readonly DeclaredScopedSecret[],
): boolean {
  if (!path || secrets.length === 0) return false;
  const normalizedPath = path.replace(/^\/+/, "").replace(/\/+$/, "");
  for (const declared of secrets) {
    if (!SECRET_NAME_RE.test(declared.secretName)) continue;
    // Skip declarations whose scope is PRESENT-but-invalid or reserved.
    // A manifest that names a reserved scope has produced no valid
    // declaration; the entry is entirely untrusted (both proof-side and
    // fingerprint-side) and must not force literal-fallback stamping.
    // Scope-independent name fingerprinting is intentional — grants of
    // the shape `<any>/API_KEY` still deserve near-miss stamping when a
    // valid declaration names API_KEY under a real scope — but the
    // declaration itself must be valid.
    if (declared.scope !== undefined) {
      if (!SECRET_SCOPE_RE.test(declared.scope)) continue;
      if (RESERVED_SCOPES.has(declared.scope)) continue;
    }
    const name = declared.secretName;
    // Match as a whole path segment: bare, at end, at start, or between slashes.
    if (
      normalizedPath === name ||
      normalizedPath.endsWith(`/${name}`) ||
      normalizedPath.startsWith(`${name}/`) ||
      normalizedPath.includes(`/${name}/`)
    ) {
      return true;
    }
  }
  return false;
}

export interface DeclaredScopedSecret {
  secretName: string;
  scope?: string;
  actions: string[];
}

export interface DeclaredPermission {
  service: string;
  space?: string;
  path: string;
  actions: string[];
}

export interface DeclaredAppScope {
  prefix?: string;
  defaultSpace?: string;
  secrets?: DeclaredScopedSecret[];
  permissions?: DeclaredPermission[];
}

/**
 * Sol MAJOR-2: annotate grants that match an app-declared scoped-secret
 * entry with a compact label and standard app-scoped presentation. Everything
 * else is left untouched and therefore remains structurally sensitive.
 *
 * Trust gate:
 *   - `model.metadataTrust.status` must be `verified` or `origin-bound`.
 *     A verified signed manifest OR a digest-matched well-known fetch
 *     is required before ANY app-scope label is applied.
 *   - The `declaredAppScope` argument must have been derived by the
 *     server from that same manifest. Callers MUST NOT synthesize this
 *     block from caller-echoed envelope data.
 *
 * Matching rule (all conjuncts must hold):
 *   1. The grant's `path` ends with `secrets/<secretName>` or
 *      `vault/secrets/<secretName>`.
 *   2. The grant's actions (short verbs) are a subset of the declared
 *      entry's actions. Missing declared actions on the grant are fine
 *      (narrowing); ANY grant action not declared makes it not a match.
 *   3. When the declared entry carries a `scope`, the ReCap resource
 *      path must include the scope segment (`<scope>/...`) so a caller
 *      cannot claim app-scope on a global-secret grant.
 *   4. When the declared entry has NO `scope`, the grant path must NOT
 *      contain a scope-shaped segment either — otherwise the caller is
 *      asking for a scoped secret the manifest never declared.
 */
export function annotateAppScopedGrants(
  model: CapabilityReviewModel,
  declaredAppScope: DeclaredAppScope | undefined,
): CapabilityReviewModel {
  if (!declaredAppScope) return model;
  const trust = model.metadataTrust.status;
  // Only origin-bound and verified trust may unlock the app-scope label.
  // Anything below (unsigned/stale/etc.) leaves the grant labelled by
  // structural fallback.
  if (trust !== "origin-bound" && !isVerified(model.metadataTrust)) {
    return model;
  }
  const secrets = declaredAppScope.secrets ?? [];
  const signer = model.signer;
  const permissions = model.permissions.map((grant): CapabilityGrant => {
    // App-scope near-miss enforcement (Blocker 4, Sol follow-up).
    //
    // A grant is a "declared-shape candidate" (subject to near-miss
    // stamping if it fails the strict exact-resource proof) when ANY of
    // the following holds:
    //
    //   (a) KV secret-family grants (family = secret-read/secret-mutation
    //       on a KV service). The classifier reaches these via a `secrets/`
    //       or `vault/secrets/` path on tinycloud.kv.
    //
    //   (b) A grant whose path contains a `<scope>/<secretName>`
    //       fragment matching a validly-declared entry. This closes the
    //       original Sol probes on tinycloud.secrets/* + wrong-space and
    //       tinycloud.kv/* + unrelated-path.
    //
    //   (c) Blocker 4 follow-up (Defect 4): a grant whose path contains
    //       ANY declared `secretName` as a whole path segment. This is
    //       intentionally scope-independent and service-agnostic so
    //       wrong-scope same-name probes (e.g. `secrets/scoped/other/API_KEY`
    //       or `variables/API_KEY`) still fail closed to literal fallback.
    //
    //   (d) Blocker 4 follow-up (Defect 4): any grant on a secrets-shaped
    //       space (isSecretsSpace) whose path matches the declared name
    //       fingerprint — closes SQL/capabilities reads that reach a
    //       secret path on the secrets space (e.g. tinycloud.sql/read at
    //       vault/secrets/scoped/listen/API_KEY, or tinycloud.capabilities/read
    //       at the same path).
    //
    // Failed proofs get `appScopeNearMiss` + `severity = "sensitive"` +
    // `metadataLabel = null` so `buildStatement` renders the literal
    // fallback. Metadata cannot expand authority and it cannot dress up
    // an unsatisfied proof in reassuring copy.
    const isKvSecretFamily =
      KV_SECRET_SERVICES_LOOSE.has(grant.service) &&
      (grant.family === "secret-read" || grant.family === "secret-mutation");
    const nameFingerprintMatches = pathContainsDeclaredSecretName(
      grant.path,
      secrets,
    );
    const fragmentFingerprintMatches = pathContainsDeclaredSecretFragment(
      grant.path,
      secrets,
    );
    const spaceIsSecretsShaped = isSecretsSpace(grant.space);
    const isDeclaredShapeCandidate =
      // Legacy (original) predicate: KV/named-secrets service +
      // <scope>/<name> fragment. Preserved so the existing follow-up
      // probes stay covered.
      ((KV_SECRET_SERVICES_LOOSE.has(grant.service) ||
        NAMED_SECRETS_SERVICES.has(grant.service)) &&
        fragmentFingerprintMatches) ||
      // Widened (Defect 4): scope-independent, service-agnostic name
      // fingerprint. ANY grant whose path references a declared secret
      // name is a candidate, and ANY grant on a secrets-shaped space
      // that references the name is a candidate. Reaches SQL and
      // capabilities services on the secrets space, plus wrong-scope
      // probes on any service.
      nameFingerprintMatches ||
      (spaceIsSecretsShaped && nameFingerprintMatches);
    if (!isKvSecretFamily && !isDeclaredShapeCandidate) {
      return grant;
    }

    // Near-miss stamp: sensitive severity, cleared metadata label, and the
    // `appScopeNearMiss` flag which `buildStatement` short-circuits into
    // the literal fallback. Applies to all families identified above so
    // wrong-service and wrong-path near misses lose their friendly copy.
    const nearMissMark = (target: CapabilityGrant): CapabilityGrant => {
      return {
        ...target,
        severity: "sensitive",
        metadataLabel: null,
        appScopeNearMiss: true,
      };
    };

    // Blocker 4 follow-up (Defect 5): a `serviceMismatch` grant (ability-
    // derived service disagrees with the resource-derived short-service
    // segment) can NEVER annotate. Force literal fallback + sensitive so
    // the operator sees the raw wire tuple.
    if (grant.serviceMismatch === true) return nearMissMark(grant);

    // Sol MAJOR (previous iteration): before doing ANY app-scope match, fail
    // closed on unknown action verbs. `annotateAppScopedGrants` transitions
    // a grant from sensitive -> standard AND stamps `appScopedSecret` on
    // it, which lets `buildStatement` render friendly copy such as
    // "Read the app secret API_KEY". If we accept an arbitrary verb from
    // the manifest / grant (e.g. `peek`, `admin`, some novel action), we
    // would grant that friendly presentation to an action whose actual
    // authority is not part of the read/write/delete vocabulary the copy
    // implies. An origin-bound manifest MUST NOT be able to widen the
    // recognized secret-action vocabulary.
    //
    // The canonical recognized verbs are exactly those `normalizeSecretVerb`
    // maps to (`get` / `put` / `del`). Any grant verb whose normalized form
    // is NOT one of these fails the proof (fail closed: near-miss stamp so
    // `buildStatement` renders the literal fallback).
    const allVerbsRecognized = grant.actions.every((a) =>
      RECOGNIZED_APP_SCOPE_SECRET_VERBS.has(
        normalizeSecretVerb(a.verb.toLowerCase()),
      ),
    );
    if (!allVerbsRecognized) return nearMissMark(grant);
    // Blocker 4 (Defect 1) — follow-up: exact-resource proof. Only
    // grants whose ability-derived service is EXACTLY `tinycloud.kv`
    // (no bare `kv` alias) AND whose resource-derived short-service
    // segment (when present on the wire) is exactly `kv` on the SIGNER's
    // own canonical secrets space (`tinycloud:pkh:eip155:<chainId>:<address>:secrets`)
    // can demote.
    //   - `tinycloud.secrets` service grants (a different surface) fail here.
    //   - Bare `kv` service grants fail here (no js-sdk producer emits them).
    //   - Grants whose resource-side short-service segment is anything
    //     other than `kv` (e.g. a service-mismatched `<space>/sql/...`
    //     with a `tinycloud.kv/get` ability) fail here.
    //   - Cross-signer secrets spaces fail here.
    //   - Non-secrets spaces fail here.
    //
    // Only the check below is authoritative for ownership; the loose
    // `isSecretsSpace` predicate is used only for near-miss stamping.
    if (!KV_SECRET_SERVICES_PROOF.has(grant.service)) return nearMissMark(grant);
    if (grant.resourceService !== null && grant.resourceService !== "kv") {
      return nearMissMark(grant);
    }
    if (!isSignerOwnedSecretsSpace(grant.space, signer)) {
      return nearMissMark(grant);
    }
    // Only a genuinely scoped secret can receive app-scoped/normal
    // presentation. Global app-declared secrets remain sensitive.
    if (secrets.length === 0) return nearMissMark(grant);
    const match = findMatchingDeclaredSecret(grant, secrets);
    if (!match?.scope) return nearMissMark(grant);
    // Also fail closed if the DECLARED entry carries any verb outside the
    // recognized set. A manifest that declares `peek` for a secret cannot
    // be used to promote a matching grant from sensitive to standard, even
    // if the grant itself only asks for recognized verbs.
    const allDeclaredVerbsRecognized = match.actions.every((a) =>
      RECOGNIZED_APP_SCOPE_SECRET_VERBS.has(
        normalizeSecretVerb(a.toLowerCase()),
      ),
    );
    if (!allDeclaredVerbsRecognized) return nearMissMark(grant);
    // This is the one allowed sensitive -> standard presentation transition:
    // the server independently origin-bound the manifest and this pure gate
    // matched its exact secret/scope/action declaration to the signed grant
    // that also sits inside the signer's own canonical secrets space.
    // No authority is added or changed.
    const label = `Secret: ${match.secretName} · Scope: ${match.scope}`;
    return {
      ...grant,
      severity: "standard",
      metadataLabel: label,
      appScopedSecret: {
        secretName: match.secretName,
        scope: match.scope,
      },
    };
  });
  return { ...model, permissions };
}

/**
 * Recognized action verbs for named-secret app-scope annotation.
 *
 * `annotateAppScopedGrants` is the ONE place presentation severity can move
 * sensitive -> standard, and `buildStatement` then renders friendly copy for
 * anything carrying `appScopedSecret`. To keep that friendly copy honest we
 * only annotate grants whose verbs are inside this fixed, canonical set:
 *
 *   - `get` (aliases: `read`)
 *   - `put` (aliases: `write`)
 *   - `del` (aliases: `delete`)
 *
 * Both grant-side verbs and declared-manifest verbs are compared through
 * `normalizeSecretVerb`, which folds the synonyms above into these three
 * canonical entries. Anything outside (e.g. `peek`, `admin`, `list`,
 * `metadata`, or any future/unknown verb) fails the gate; the grant keeps
 * its structural secret-mutation/sensitive classification and
 * `buildStatement` falls back to the literal service/resource/actions copy.
 */
export const RECOGNIZED_APP_SCOPE_SECRET_VERBS: ReadonlySet<string> = new Set([
  "get",
  "put",
  "del",
]);

/**
 * Test-visible helper: return the matched declared entry, or null.
 *
 * Matching rule (Blocker 4 fix — all conjuncts must hold):
 *   1. declared.secretName matches /^[A-Z][A-Z0-9_]*$/ (js-sdk SECRET_NAME_RE)
 *   2. declared.scope is present, matches /^[a-z0-9-]+$/, and is not
 *      'default' or 'global' (mirrors js-sdk scope validation)
 *   3. grant.path (normalized) equals exactly
 *      `vault/secrets/scoped/${scope}/${secretName}` — the sole canonical
 *      shape js-sdk packages/sdk-services/src/secrets/paths.ts ever emits.
 *      Legacy shapes (secrets/scoped/..., <scope>/secrets/...) do NOT
 *      annotate; losing annotation is demote-only (fail-closed direction).
 *   4. Every grant verb (normalized) is declared. Narrowing is allowed;
 *      any undeclared grant verb falsifies the match.
 */
export function findMatchingDeclaredSecret(
  grant: CapabilityGrant,
  secrets: readonly DeclaredScopedSecret[],
): DeclaredScopedSecret | null {
  // Blocker 4 follow-up (Defect 2): BYTE-EXACT path comparison. The prior
  // implementation stripped leading/trailing slashes before comparing —
  // that let a caller send `/vault/secrets/scoped/listen/API_KEY/` (with
  // decorative slashes) and still hit the proof gate, even though the
  // js-sdk secrets resolver never emits such a path. Slash variants MUST
  // now fail the proof and be caught downstream by near-miss stamping.
  const grantPath = grant.path;
  const grantVerbs = grant.actions.map((a) =>
    normalizeSecretVerb(a.verb.toLowerCase()),
  );
  for (const declared of secrets) {
    // Validate secret name against js-sdk SECRET_NAME_RE.
    if (!SECRET_NAME_RE.test(declared.secretName)) continue;
    // Scope must be present, canonical, and not reserved.
    if (!declared.scope) continue;
    if (!SECRET_SCOPE_RE.test(declared.scope)) continue;
    if (RESERVED_SCOPES.has(declared.scope)) continue;
    // Exact manifest-derived path. This is the only shape js-sdk emits.
    const expectedPath = `vault/secrets/scoped/${declared.scope}/${declared.secretName}`;
    if (grantPath !== expectedPath) continue;
    // Verb subset check: every grant verb must appear in the declared set.
    const declaredVerbs = new Set(
      declared.actions.map((a) => normalizeSecretVerb(a.toLowerCase())),
    );
    let ok = true;
    for (const v of grantVerbs) {
      if (!declaredVerbs.has(v)) {
        ok = false;
        break;
      }
    }
    if (!ok) continue;
    return declared;
  }
  return null;
}

/**
 * Sol MAJOR-1: canonical verb table. Grants and manifests both target
 * the same three operations on a secret — READ, WRITE, DELETE — but
 * they spell them differently:
 *   - grants (from ability tails): `get` / `put` / `del`
 *   - manifests (from `ManifestSecretActions`): `read` / `write` / `delete`
 *
 * We normalize BOTH sides to the short verb the wire actually carries
 * (`get`/`put`/`del`) so a declaration like `{ MY_KEY: ["read", "write"] }`
 * matches a grant asking for `tinycloud.kv/get + tinycloud.kv/put`.
 *
 * Unknown verbs pass through untouched — the exact-string match still
 * applies (e.g., `list`, `admin`), and the gate stays fail-closed for
 * anything the caller didn't declare.
 */
export function normalizeSecretVerb(verb: string): string {
  switch (verb) {
    case "read":
    case "get":
      return "get";
    case "write":
    case "put":
      return "put";
    case "delete":
    case "del":
      return "del";
    default:
      return verb;
  }
}
