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

import type { CapabilityGrant, CapabilityReviewModel } from "./model.js";
import { isVerified } from "./metadata.js";

/**
 * KV services that may hold app-scoped secrets. tinycloud.secrets is the
 * named-secrets service (a different surface) and must never trigger the
 * app-scoped annotation; only KV grants on the secrets space carry vault paths.
 */
export const KV_SECRET_SERVICES: ReadonlySet<string> = new Set([
  "tinycloud.kv",
  "kv",
]);

/**
 * True when `space` identifies the structurally-named secrets space.
 * Mirrors the private isSecretsSqlSpace predicate in statements.ts so that
 * the annotation gate and the structural counting predicate use one shared
 * definition (imported by statements.ts).
 */
export function isSecretsSpace(space: string): boolean {
  return (
    space === "secrets" ||
    /:secrets(?:\/|$)/.test(space) ||
    /:secrets:/.test(space)
  );
}

// Secret-name and scope validation mirrors js-sdk
// packages/sdk-services/src/secrets/paths.ts so the OpenKey gate and the
// js-sdk resolver share the same canonical forms.
const SECRET_NAME_RE = /^[A-Z][A-Z0-9_]*$/;
const SECRET_SCOPE_RE = /^[a-z0-9-]+$/;
const RESERVED_SCOPES = new Set(["default", "global"]);

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
    // Blocker 4: exact-resource proof. Only KV service grants on the secrets
    // space can demote. tinycloud.secrets service grants, non-secrets spaces,
    // and non-canonical paths all fail closed here, before any path matching.
    if (!KV_SECRET_SERVICES.has(grant.service) || !isSecretsSpace(grant.space)) {
      return grant;
    }
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
  const normalizedPath = grant.path.replace(/^\/+/, "").replace(/\/+$/, "");
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
    if (normalizedPath !== expectedPath) continue;
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

