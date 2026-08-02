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
//      (never below), sets `metadataLabel` to a compact "app-scoped"
//      string so the widget can render an honest hint.
//   3. Under ANY other condition — no manifest, trust unsigned, no
//      declared entry, actions mismatched, scope missing on the ReCap —
//      leaves `metadataLabel` unchanged.
//
// This helper NEVER touches `severity`, `family`, `actions`, or any
// other structural field. Metadata may not lower severity, per the
// metadata-monotonicity rule in metadata.ts.

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
 * entry with a compact "app-scoped" `metadataLabel`. Everything else is
 * left untouched — including severity, so a secret that was classified
 * `sensitive` STAYS `sensitive` even if the label changes.
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
    const match = findMatchingDeclaredSecret(grant, secrets);
    if (!match) return grant;
    // Keep the structural severity untouched; only add a metadata label.
    // The label is a compact, non-marketing string derived from the
    // manifest's declared secret name plus (when present) its scope.
    const label = match.scope
      ? `App-scoped secret (${match.scope}): ${match.secretName}`
      : `App-declared secret: ${match.secretName}`;
    return { ...grant, metadataLabel: label };
  });
  return { ...model, permissions };
}

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
  //   `<scope>/secrets/<name>`, `<scope>/vault/secrets/<name>`
  const parsed = parseSecretPath(grant.path);
  if (!parsed) return null;
  const grantVerbs = grant.actions.map((a) => a.verb.toLowerCase());
  for (const declared of secrets) {
    if (declared.secretName !== parsed.secretName) continue;
    // Scope agreement: an entry without scope MUST match an unscoped
    // path; an entry WITH scope must match a path prefixed by that
    // exact scope segment.
    if ((declared.scope ?? null) !== (parsed.scope ?? null)) continue;
    // Actions: every requested verb must be declared. A missing
    // declared verb on the grant is legal narrowing; ANY grant verb
    // NOT declared falsifies the match.
    const declaredVerbs = new Set(declared.actions.map((a) => a.toLowerCase()));
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
 * Parse the trailing secret-name segment (and optional scope) from a
 * ReCap `path`. Returns null when the shape does not describe a secret.
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
  // The `vault` segment may sit immediately before `secrets` — treat it
  // as part of the anchor prefix (no scope contribution).
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
