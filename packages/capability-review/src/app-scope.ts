// App-scoped-secret trust rule (Sol MAJOR-2).
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
//      app-declared secret / permission entry (exact secret name, scope,
//      actions, and same-scope ReCap resource path).
//   2. When a match holds AND the metadata trust is at least origin-bound
//      (never below), records the proven app-scoped-secret identity, renders
//      a compact label, and presents the grant at standard severity.
//   3. Under ANY other condition — no manifest, trust unsigned, no
//      declared entry, actions mismatched, scope missing on the ReCap —
//      leaves `metadataLabel` unchanged.
//
// The severity change is intentionally confined to this proof gate. Generic
// metadata helpers still cannot lower severity (see metadata.ts), and this
// helper never changes the authority-bearing actions or resource.

import type { CapabilityGrant, CapabilityReviewModel } from "./model.js";
import { isVerified } from "./metadata.js";

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
  if (secrets.length === 0) return model;
  const permissions = model.permissions.map((grant): CapabilityGrant => {
    // Only KV/secret-shaped grants can be app-scoped secrets.
    if (grant.family !== "secret-read" && grant.family !== "secret-mutation") {
      return grant;
    }
    // Sol MAJOR (this iteration): before doing ANY app-scope match, fail
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
    // is NOT one of these leaves the grant untouched (fail closed: retains
    // its structural secret-mutation/sensitive classification and
    // `buildStatement` renders the literal fallback).
    const allVerbsRecognized = grant.actions.every((a) =>
      RECOGNIZED_APP_SCOPE_SECRET_VERBS.has(
        normalizeSecretVerb(a.verb.toLowerCase()),
      ),
    );
    if (!allVerbsRecognized) return grant;
    const match = findMatchingDeclaredSecret(grant, secrets);
    // Only a genuinely scoped secret can receive app-scoped/normal
    // presentation. Global app-declared secrets remain sensitive.
    if (!match?.scope) return grant;
    // Also fail closed if the DECLARED entry carries any verb outside the
    // recognized set. A manifest that declares `peek` for a secret cannot
    // be used to promote a matching grant from sensitive to standard, even
    // if the grant itself only asks for recognized verbs.
    const allDeclaredVerbsRecognized = match.actions.every((a) =>
      RECOGNIZED_APP_SCOPE_SECRET_VERBS.has(
        normalizeSecretVerb(a.toLowerCase()),
      ),
    );
    if (!allDeclaredVerbsRecognized) return grant;
    // This is the one allowed sensitive -> standard presentation transition:
    // the server independently origin-bound the manifest and this pure gate
    // matched its exact secret/scope/action declaration to the signed grant.
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
 */
export function findMatchingDeclaredSecret(
  grant: CapabilityGrant,
  secrets: readonly DeclaredScopedSecret[],
): DeclaredScopedSecret | null {
  // Extract the trailing secret name from the ReCap path. Real requests
  // use one of the following shapes:
  //   `secrets/<name>`, `vault/secrets/<name>`,
  //   `secrets/scoped/<scope>/<name>`, `vault/secrets/scoped/<scope>/<name>`,
  //   `<scope>/secrets/<name>`, `<scope>/vault/secrets/<name>`
  const parsed = parseSecretPath(grant.path);
  if (!parsed) return null;
  // Sol MAJOR-1 (this iteration): normalize BOTH sides to a canonical
  // verb space before comparison. Grants ship short verbs sourced from
  // the ability tail (`tinycloud.kv/get`, `tinycloud.kv/put`,
  // `tinycloud.kv/del`), while manifests conventionally use the
  // longer `read/write/delete` synonyms. Comparing them raw always
  // failed the app-scope gate on real production capabilities.
  const grantVerbs = grant.actions.map((a) =>
    normalizeSecretVerb(a.verb.toLowerCase()),
  );
  for (const declared of secrets) {
    if (declared.secretName !== parsed.secretName) continue;
    // Scope agreement: an entry without scope MUST match an unscoped
    // path; an entry WITH scope must match a path prefixed by that
    // exact scope segment.
    if ((declared.scope ?? null) !== (parsed.scope ?? null)) continue;
    // Actions: every requested verb must be declared. A missing
    // declared verb on the grant is legal narrowing; ANY grant verb
    // NOT declared falsifies the match. Both sides are canonicalized
    // through the same verb-normalization table.
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

/**
 * Parse the trailing secret-name segment (and optional scope) from a
 * ReCap `path`. Returns null when the shape does not describe a secret.
 *
 * Accepted shapes:
 *   1. `secrets/<name>`                              — global, no vault prefix
 *   2. `vault/secrets/<name>`                        — global, vault prefix
 *   3. `secrets/scoped/<scope>/<name>`               — js-sdk production shape (scoped)
 *   4. `vault/secrets/scoped/<scope>/<name>`         — js-sdk production shape (scoped, vault)
 *   5. `<scope>/secrets/<name>`                      — alternate scope-first shape
 *   6. `<scope>/vault/secrets/<name>`                — alternate scope-first (vault)
 *
 * The js-sdk `resolveSecretPath` helper emits shapes 1-4 (see
 * `packages/sdk-services/src/secrets/paths.ts`); shapes 5-6 exist for
 * backward compatibility with older callers that prefixed the scope.
 */
function parseSecretPath(path: string): { scope?: string; secretName: string } | null {
  if (!path) return null;
  // Normalize any leading slash + trailing slash.
  const normalized = path.replace(/^\/+/, "").replace(/\/+$/, "");
  if (normalized.length === 0) return null;
  const segments = normalized.split("/");
  // Locate the `secrets` (or `vault/secrets`) segment.
  let anchor = -1;
  for (let i = 0; i < segments.length; i += 1) {
    if (segments[i] === "secrets") {
      anchor = i;
      break;
    }
  }
  if (anchor < 0) return null;
  // Sol MAJOR-1: recognize the js-sdk production shape
  // `secrets/scoped/<scope>/<name>`. When the segment immediately after
  // `secrets` is the literal `scoped`, the following segment is the
  // scope and the segment after that is the secret name. Anything
  // beyond the secret name is not a legal single-secret grant.
  if (segments[anchor + 1] === "scoped") {
    const scopeSegment = segments[anchor + 2];
    const scopedName = segments[anchor + 3];
    if (!scopeSegment || scopeSegment.length === 0) return null;
    if (!scopedName || scopedName.length === 0) return null;
    if (anchor + 4 !== segments.length) return null;
    // A scope-first prefix in front of `secrets/scoped/...` is not a
    // legal shape — the js-sdk never emits it and mixing both scope
    // conventions in one path is ambiguous.
    for (let i = 0; i < anchor; i += 1) {
      const seg = segments[i]!;
      if (seg !== "vault") return null;
    }
    return { scope: scopeSegment, secretName: scopedName };
  }
  // Legacy shape: `secrets/<name>` (unscoped) or `<scope>/secrets/<name>`
  // (scope-first). The `vault` segment may sit immediately before
  // `secrets` — treat it as part of the anchor prefix (no scope
  // contribution).
  const secretName = segments[anchor + 1];
  if (!secretName || secretName.length === 0) return null;
  // Anything remaining after the secret name is not a legal single-secret
  // grant.
  if (anchor + 2 !== segments.length) return null;
  // Scope is any segment that precedes the anchor and is NOT `vault`.
  const scopeSegments: string[] = [];
  for (let i = 0; i < anchor; i += 1) {
    const seg = segments[i]!;
    if (seg === "vault") continue;
    scopeSegments.push(seg);
  }
  const scope = scopeSegments.length > 0 ? scopeSegments.join("/") : undefined;
  return { scope, secretName };
}
