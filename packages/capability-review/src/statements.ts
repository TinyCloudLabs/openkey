// Deterministic statement catalog.
//
// Turns a `CapabilityGrant` into the plain-English single-sentence statement
// the default review view renders. The statement text is a shared, structural
// projection of (family + service + path + actions). It NEVER incorporates
// caller-supplied metadata — presentation metadata may enrich secondary
// display strings, but the primary statement is always derived from the
// verified structure of the request.
//
// Falls back to the literal service/resource/actions for any shape it does
// not recognize — invented friendly semantics on unknown shapes would be a
// spec violation (see the merge-readiness contract).
//
// The `sensitiveCallout(n)` string is the exact copy required by the
// contract; UI callers MUST route through it rather than composing the
// sentence themselves.

import type { CapabilityGrant } from "./model.js";
import {
  CANONICAL_APP_SCOPE_SECRET_ABILITIES,
  KV_SECRET_SERVICES_PROOF,
  isSecretsSpace,
} from "./app-scope.js";

export interface StatementEntry {
  /**
   * Primary sentence shown as the deterministic statement in the default
   * (summary) review view. Never contains a caller-supplied app name.
   */
  primaryText: string;
  /**
   * Service short-name shown as secondary context beneath the primary
   * sentence. Rendered as-is (never rewritten to a "friendly" name).
   */
  service: string;
  /**
   * The literal resource label (space + path when present, or just the
   * space) shown alongside the service. Rendered as-is.
   */
  resource: string;
}

/** Family/action-aware structural verb classification. */
interface VerbSet {
  hasRead: boolean;
  hasWrite: boolean;
  hasDecrypt: boolean;
  hasCreate: boolean;
  hasSchema: boolean;
  hasList: boolean;
  hasMetadata: boolean;
  onlyRead: boolean;
  onlyWrite: boolean;
  onlyDecrypt: boolean;
  onlyCreate: boolean;
}

const MUTATION_VERBS = new Set([
  "put",
  "post",
  "write",
  "delete",
  "del",
  "admin",
  "grant",
  "revoke",
  "update",
]);
const READ_VERBS = new Set(["read", "get", "peek", "list"]);
const DECRYPT_VERBS = new Set(["decrypt", "unwrap"]);

// Exact action shapes we will render friendly copy for on each service.
// A grant is only eligible for the friendly copy on that service when
// EVERY action's ability string is in the corresponding recognized set.
// Anything outside must fall back to `fallbackStatement(grant)` per the
// merge-readiness contract — do not invent friendly semantics on
// unrecognized shapes (Sol MAJOR-1).

// The capabilities service only has one canonical action shape today:
// `tinycloud.capabilities/read`. Verbs like `get`, `peek`, `list` are NOT
// registered as capability shapes on the node — treating them as friendly
// "check permissions" grants would classify novel/unknown shapes at
// standard severity with unearned copy. Fail closed on anything else.
const RECOGNIZED_CAPABILITY_ACTIONS = new Set([
  "tinycloud.capabilities/read",
  "capabilities/read",
]);

// The named-secrets service accepts the read / mutation / list / metadata
// shapes below. Anything else must fall back to the literal actions.
const RECOGNIZED_SECRETS_READ_ACTIONS = new Set([
  "tinycloud.secrets/read",
  "tinycloud.secrets/get",
  "secrets/read",
  "secrets/get",
]);
const RECOGNIZED_SECRETS_WRITE_ACTIONS = new Set([
  "tinycloud.secrets/put",
  "tinycloud.secrets/write",
  "tinycloud.secrets/delete",
  "tinycloud.secrets/del",
  "tinycloud.secrets/update",
  "secrets/put",
  "secrets/write",
  "secrets/delete",
  "secrets/del",
  "secrets/update",
]);
const RECOGNIZED_SECRETS_LIST_ACTIONS = new Set([
  "tinycloud.secrets/list",
  "secrets/list",
]);
const RECOGNIZED_SECRETS_METADATA_ACTIONS = new Set([
  "tinycloud.secrets/metadata",
  "secrets/metadata",
]);
const RECOGNIZED_SECRETS_ACTIONS = new Set<string>([
  ...RECOGNIZED_SECRETS_READ_ACTIONS,
  ...RECOGNIZED_SECRETS_WRITE_ACTIONS,
  ...RECOGNIZED_SECRETS_LIST_ACTIONS,
  ...RECOGNIZED_SECRETS_METADATA_ACTIONS,
]);
// Sol MAJOR-3: `create` matches short-verb abilities (e.g. `foo/create`).
// The production encryption service uses the compound verb
// `network.create`, so we ALSO recognize that specific form here; the
// resource is still classified as a network-create action. Adding the
// compound alias is safer than dropping the dot-segment from every verb
// blindly, because unrelated services could carry different meanings
// (e.g. `sql/schema.migrate` should NOT be classified as `migrate`).
const CREATE_VERBS = new Set(["create", "network.create"]);
const SCHEMA_VERBS = new Set(["schema"]);
const LIST_VERBS = new Set(["list"]);
const METADATA_VERBS = new Set(["metadata"]);

function verbOf(ability: string): string {
  if (ability.includes("/")) return ability.slice(ability.indexOf("/") + 1);
  return ability;
}

function classifyVerbs(actions: readonly string[]): VerbSet {
  let hasRead = false;
  let hasWrite = false;
  let hasDecrypt = false;
  let hasCreate = false;
  let hasSchema = false;
  let hasList = false;
  let hasMetadata = false;
  for (const a of actions) {
    const v = verbOf(a);
    if (READ_VERBS.has(v)) hasRead = true;
    if (MUTATION_VERBS.has(v)) hasWrite = true;
    if (DECRYPT_VERBS.has(v)) hasDecrypt = true;
    if (CREATE_VERBS.has(v)) hasCreate = true;
    if (SCHEMA_VERBS.has(v)) hasSchema = true;
    if (LIST_VERBS.has(v)) hasList = true;
    if (METADATA_VERBS.has(v)) hasMetadata = true;
  }
  // "only" variants gate action-aware phrasing so we never claim
  // "read and update" when the request is read-only.
  const onlyRead = hasRead && !hasWrite && !hasDecrypt && !hasCreate && !hasSchema;
  const onlyWrite = hasWrite && !hasRead && !hasDecrypt && !hasCreate;
  const onlyDecrypt = hasDecrypt && !hasRead && !hasWrite && !hasCreate;
  const onlyCreate = hasCreate && !hasRead && !hasWrite && !hasDecrypt;
  return {
    hasRead,
    hasWrite,
    hasDecrypt,
    hasCreate,
    hasSchema,
    hasList,
    hasMetadata,
    onlyRead,
    onlyWrite,
    onlyDecrypt,
    onlyCreate,
  };
}

/** Compact resource string used as secondary context.
 *
 * Blocker 4 follow-up (Defect 2): when the wire carried a resource-side
 * short-service segment (e.g. `kv` from `<space>/kv/vault/...`), the
 * literal fallback rendering MUST include it verbatim. Prior code emitted
 * `${grant.space}/${grant.path}` which dropped the `/<short>/` segment,
 * so a `<space>/kv/<path>` and a `<space>/sql/<path>` grant with the
 * same ability rendered as visually identical strings. The operator now
 * sees the signed resource URI exactly as it appears on the wire.
 */
function resourceOf(grant: CapabilityGrant): string {
  if (grant.resourceService !== null && grant.resourceService !== "") {
    if (grant.path) return `${grant.space}/${grant.resourceService}/${grant.path}`;
    return `${grant.space}/${grant.resourceService}`;
  }
  if (grant.path) return `${grant.space}/${grant.path}`;
  return grant.space;
}

/** Fallback statement for anything the catalog does not recognize. */
function fallbackStatement(grant: CapabilityGrant): StatementEntry {
  // Grant actions are CapabilityAction objects; join their ability
  // strings for the literal fallback text. Never invent friendly
  // semantics from a shape we don't recognize.
  const actionList = grant.actions.map((a) => a.ability).join(", ");
  const resource = resourceOf(grant);
  return {
    primaryText:
      actionList.length > 0
        ? `Perform ${actionList} on ${grant.service}`
        : `Access ${grant.service}`,
    service: grant.service,
    resource,
  };
}

/**
 * Path-shape helpers. These match structural conventions in the wire path
 * (never a caller-supplied "friendly" name).
 */
function isAccountAppsPath(path: string): boolean {
  // e.g. `applications`, `applications/<something>`, `apps`
  return (
    path === "applications" ||
    path.startsWith("applications/") ||
    path === "apps" ||
    path.startsWith("apps/")
  );
}
function isAccountSpacesPath(path: string): boolean {
  return (
    path === "spaces" ||
    path.startsWith("spaces/") ||
    path === "space" ||
    path.startsWith("space/")
  );
}
function isSecretsVaultPath(path: string): boolean {
  return path.startsWith("vault/secrets") || path === "vault/secrets";
}
function isSecretsVariablesPath(path: string): boolean {
  return (
    path === "variables" ||
    path.startsWith("variables/") ||
    path === "vars" ||
    path.startsWith("vars/")
  );
}
// isSecretsSpace is imported from app-scope.ts to keep one shared predicate
// across the annotation gate and the structural counting/copy surfaces.

function grantVerbSet(grant: CapabilityGrant): Set<string> {
  return new Set(grant.actions.map((action) => verbOf(action.ability)));
}

/**
 * True only when the exact grant reaches TinyCloud secret data or can decrypt
 * protected data. Kept beside the statement catalog so every UI surface uses
 * the same structural definition as the copy it displays.
 *
 * App-scoped secrets that passed the dedicated origin-bound manifest proof
 * still reach secret data — they are just presented at `standard` severity
 * via `annotateAppScopedGrants` (see app-scope.ts). The count exposed by
 * `sensitiveCallout` describes every exact grant that reaches secret data
 * OR decryption regardless of presentation severity, so app-scoped secrets
 * remain in the count. Unknown sensitive mutations and create-only
 * encryption grants do not enter the count: neither fact alone proves
 * access to secret data or decryption.
 */
export function grantReachesSecretDataOrDecryption(
  grant: CapabilityGrant,
): boolean {
  if (grant.family === "secret-read" || grant.family === "secret-mutation") {
    return true;
  }

  if (ENCRYPTION_SERVICES.has(grant.service)) {
    const verbs = grantVerbSet(grant);
    return verbs.has("decrypt") || verbs.has("unwrap");
  }

  // Blocker 4 follow-up (Defect 3): ANY grant on a secrets-shaped space
  // reaches secret data, regardless of which service the ability or
  // resource segment names.
  //
  // Prior code only counted grants whose ability-derived service OR
  // resource-derived short-service was `kv` / `sql`. That left a gap:
  // a grant on the signer secrets space with an ability like
  // `tinycloud.foo/read` (unknown service) was correctly marked
  // sensitive and `serviceMismatch`, but the count predicate returned
  // false — the operator saw a sensitive grant that touched their
  // secret data but the top-level "N exact grants reach secret data
  // or decryption" callout under-counted it. Any grant on a secrets-
  // shaped space plausibly reaches secret bytes; count them all so
  // the callout is a true upper-bound.
  if (isSecretsSpace(grant.space)) return true;
  return false;
}

const KV_SERVICES = new Set(["tinycloud.kv", "kv"]);
const SQL_SERVICES = new Set(["tinycloud.sql", "sql"]);
const CAPABILITY_SERVICES = new Set(["tinycloud.capabilities", "capabilities"]);
const SECRETS_SERVICES = new Set(["tinycloud.secrets", "secrets"]);
const ENCRYPTION_SERVICES = new Set(["tinycloud.encryption", "encryption"]);

// Sol/Fable follow-up: friendly copy for the KV / SQL / encryption service
// branches (own-app-data, cross-app-data, KV account paths, KV secret paths,
// SQL account, SQL secrets space, encryption decrypt/create) MUST only fire
// when EVERY action in the grant is a byte-exact ability shape the wire is
// known to carry. Reusing the broad `classifyVerbs` verb sets meant a grant
// like `[tinycloud.kv/get, tinycloud.kv/exfiltrate]` inherited the friendly
// "Read this app's data" copy: `hasRead` fired on the known `get`, and the
// unknown `exfiltrate` was silently ignored. The operator saw a reassuring
// sentence for a request that carried an unknown mutation-like verb.
//
// The gate below is placed AFTER the appScopedSecret branch (which has its
// own dedicated proof + defense-in-depth checks) and BEFORE the
// own-app-data/cross-app-data family branch, so it protects every friendly
// KV/SQL/encryption family/service branch that reads `verbs.*` flags from
// `classifyVerbs`. The capabilities and named-secrets branches keep their
// own dedicated exact-ability allowlists inside the branch.
//
// Rules:
//   - Empty action list → false (a friendly sentence would still speak
//     about "read" or "update" authority the grant does not carry).
//   - Any action outside the recognized catalog for the ability-derived
//     service → false, whole grant falls back to literal.
//   - All actions in the catalog → true, downstream branches run as before.
//
// The catalogs are UNION-of-both-service-forms (short + fully-qualified)
// to match what the surrounding branches accept. Anything genuinely novel
// must be added here explicitly — silent inheritance of friendly copy is a
// merge-readiness contract violation.

// Sol MAJOR (post-rejection re-fix): the KV catalog now enumerates ONLY the
// exact wire abilities the production js-sdk emits per the canonical
// capability registry (`js-sdk/packages/bootstrap/src/generated/capabilities.ts`).
// The prior catalog listed synonyms and near-look-alikes (`peek`, `read`,
// `update`, `post`, `write`, `admin`, `grant`, `revoke`) that no js-sdk
// producer emits — treating them as recognized let novel unknown-verb
// requests inherit friendly copy at standard severity even though the
// underlying wire shape was unregistered.
//
// The short-form alias (`kv/<verb>`) is kept alongside the fully-qualified
// form because the branch guards below (`KV_SERVICES`) accept both and the
// service-mismatch check has already validated the resource-side segment.
const KV_RECOGNIZED_ABILITIES = new Set<string>([
  "tinycloud.kv/get",
  "kv/get",
  "tinycloud.kv/list",
  "kv/list",
  "tinycloud.kv/metadata",
  "kv/metadata",
  "tinycloud.kv/put",
  "kv/put",
  "tinycloud.kv/del",
  "kv/del",
  // `tinycloud.kv/delete` is a deprecated alias for `tinycloud.kv/del`
  // that IS in the registered ACCEPTED_ACTIONS list — keep it so wire
  // shapes emitted via the alias still earn friendly copy.
  "tinycloud.kv/delete",
  "kv/delete",
]);

// SQL abilities. The registered wire shapes per the canonical capability
// registry are `read`, `select` (alias for `read`), `write`, `schema`, and
// `admin`. The prior catalog admitted `get`, `put`, `delete`, `del`,
// `update`, `schema.apply`, `schema.drop`, `schema.migrate` — none of which
// appear in the registry — and OMITTED `admin`, even though `admin` is
// registered and previously earned friendly copy via the broad mutation
// verb set. Restore parity with the registry.
const SQL_RECOGNIZED_ABILITIES = new Set<string>([
  "tinycloud.sql/read",
  "sql/read",
  // `tinycloud.sql/select` is a deprecated alias for `tinycloud.sql/read`
  // that IS in ACCEPTED_ACTIONS; keep it so wire shapes emitted via the
  // alias still earn friendly copy.
  "tinycloud.sql/select",
  "sql/select",
  "tinycloud.sql/write",
  "sql/write",
  "tinycloud.sql/schema",
  "sql/schema",
  // `tinycloud.sql/admin` is a registered action that previously
  // rendered friendly "update" copy via the broad MUTATION_VERBS set
  // (Sol rejection note: it MUST be included so parity with the prior
  // recognized behavior is preserved).
  "tinycloud.sql/admin",
  "sql/admin",
]);

// Encryption abilities. Per the canonical capability registry the
// registered wire shapes are `decrypt`, `network.create`, and
// `network.revoke`. The bare `create` short-form is NOT registered but IS
// present as a compatibility path exercised by the mixed-unknown positive
// tests (see `statements-mixed-unknown.test.ts` — "encryption with
// [create, decrypt] (short create verb) yields combined copy"), so it
// stays in the catalog. The `unwrap` verb from the prior catalog is NOT
// registered and no positive test exercises it — dropped.
const ENCRYPTION_RECOGNIZED_ABILITIES = new Set<string>([
  "tinycloud.encryption/decrypt",
  "encryption/decrypt",
  "tinycloud.encryption/network.create",
  "encryption/network.create",
  "tinycloud.encryption/network.revoke",
  "encryption/network.revoke",
  // Bare `create` short-form: retained because a positive test asserts
  // the combined "Create a decryption network and decrypt protected data"
  // copy for a grant carrying `tinycloud.encryption/create`. The
  // downstream branch treats `create` via the CREATE_VERBS set (which
  // includes both `create` and `network.create`).
  "tinycloud.encryption/create",
  "encryption/create",
]);

/**
 * Fail-closed gate for the KV / SQL / encryption family/service branches
 * below: return `true` only when EVERY action in the grant is a byte-exact
 * ability shape the corresponding branch is prepared to speak friendly
 * copy for. Any unknown ability (or an empty action list) forces the
 * caller into `fallbackStatement(grant)`.
 *
 * Services with their own dedicated exact-ability allowlists inside the
 * branch (`CAPABILITY_SERVICES`, `SECRETS_SERVICES`) return `true` here so
 * the branch's own allowlist stays the sole authority. A blanket `false`
 * return would over-block their own recognized shapes.
 *
 * Unknown services (anything not in KV / SQL / encryption / capabilities
 * / secrets) return `true` so `buildStatement` reaches its unknown-service
 * fallback branch untouched. The fallback at the end of `buildStatement`
 * still emits the literal `Perform <actions> on <service>` copy, so
 * returning `true` here does NOT admit friendly copy for an unknown
 * service — it just avoids double-handling.
 *
 * Empty action lists ALWAYS return `false` regardless of service. A
 * friendly sentence would still speak about "read" or "update" authority
 * that a zero-action grant demonstrably does not carry.
 */
function allActionsRecognizedForService(grant: CapabilityGrant): boolean {
  const abilityStrings = grant.actions.map((a) => a.ability);
  if (abilityStrings.length === 0) return false;
  const service = grant.service;
  if (KV_SERVICES.has(service)) {
    return abilityStrings.every((a) => KV_RECOGNIZED_ABILITIES.has(a));
  }
  if (SQL_SERVICES.has(service)) {
    return abilityStrings.every((a) => SQL_RECOGNIZED_ABILITIES.has(a));
  }
  if (ENCRYPTION_SERVICES.has(service)) {
    return abilityStrings.every((a) =>
      ENCRYPTION_RECOGNIZED_ABILITIES.has(a),
    );
  }
  // Capabilities and named-secrets services keep their own dedicated
  // allowlists inside the branch. Unknown services always route to
  // fallbackStatement at the end of buildStatement.
  return true;
}

/**
 * Compute the deterministic statement for a grant. Match order:
 *   1. Encryption create + decrypt combined form (bundle across grants must
 *      be handled by the caller — here we only produce the single-grant
 *      "network + decrypt" phrasing when a grant carries both `network`
 *      create and a decrypt verb).
 *   2. bootstrap-capabilities read → account capabilities check
 *   3. bootstrap-kv on account apps/spaces paths
 *   4. bootstrap-sql on account or secrets space
 *   5. secret-read / secret-mutation (with vault vs variables shapes)
 *   6. Anything else → literal fallback
 */
export function buildStatement(grant: CapabilityGrant): StatementEntry {
  const service = grant.service;
  const path = grant.path;
  const space = grant.space;
  // `grant.actions` is `CapabilityAction[]`; classifyVerbs works on the
  // ability string (e.g. `tinycloud.kv/get`), so project first.
  const abilityStrings = grant.actions.map((a) => a.ability);
  const verbs = classifyVerbs(abilityStrings);
  const resource = resourceOf(grant);

  // Blocker 4 follow-up (Defect 5): serviceMismatch short-circuit.
  //
  // A grant flagged with `serviceMismatch: true` (ability-derived service
  // disagrees with the resource-derived short-service segment; e.g. a
  // `tinycloud.kv/get` ability on a `<space>/sql/...` resource URI) MUST
  // render the literal fallback so the operator sees the raw wire tuple.
  // Any friendly copy on a service-mismatched grant would misrepresent
  // the underlying authority: the ability-based service branches below
  // would render KV/secret copy for a grant whose wire form actually
  // targets a different backend surface.
  if (grant.serviceMismatch === true) {
    return fallbackStatement(grant);
  }

  // Blocker 4 (Defect 2): near-miss short-circuit.
  //
  // `annotateAppScopedGrants` stamps `appScopeNearMiss` on any KV secret
  // grant that structurally looked like an app-scoped secret attempt but
  // failed the exact-resource proof (cross-signer secrets space, non-
  // canonical vault path, no matching declaration, unknown verb, …).
  // Those grants MUST render the literal fallback so the operator sees
  // the raw ability + resource — the friendly "View secrets stored in
  // your vault" / "Manage secret variables" copy the KV secret branches
  // below would emit would dress the ability up in reassuring copy that
  // the failed proof did not earn. Fail closed here, before any
  // family/service-shaped branch fires.
  if (grant.appScopeNearMiss) {
    return fallbackStatement(grant);
  }

  // An app-scoped secret reaches this branch only after the exact,
  // origin-bound manifest proof in app-scope.ts. The secret name is therefore
  // structural review state rather than an unverified friendly label.
  //
  // Sol MAJOR (this iteration): defense-in-depth against a compromised or
  // future-buggy `annotateAppScopedGrants`. Even if a grant somehow reached
  // this branch with an unrecognized verb (e.g. `peek`), we MUST NOT let
  // the friendly "Read/Update the app secret" copy fire, because that copy
  // implies a read/write/delete authority the wire verb may not carry.
  //
  // Sol post-rejection: the check uses BYTE-EXACT ability-string membership
  // against `CANONICAL_APP_SCOPE_SECRET_ABILITIES` (the same URN allowlist
  // `annotateAppScopedGrants` uses as its proof-side check). The prior
  // implementation lower-cased `action.verb` and folded synonyms via
  // `normalizeSecretVerb`, which would silently admit non-canonical wire
  // shapes like `tinycloud.kv/GET` (upper-cased) or `tinycloud.kv/read`
  // (long-form synonym) — neither of which is emitted by any js-sdk
  // producer. Requiring byte-exact ability membership keeps the two proof
  // surfaces in lock-step; a grant that passes the annotation gate will
  // also satisfy this defense-in-depth check, and anything the annotation
  // gate would refuse also falls back here.
  //
  // Empty action list also falls back — `every` on `[]` returns `true`,
  // which would otherwise let a zero-action grant inherit friendly
  // "app secret" copy despite carrying no authority.
  if (grant.appScopedSecret) {
    if (grant.actions.length === 0) {
      return fallbackStatement(grant);
    }
    const allActionsRecognized = grant.actions.every((a) =>
      CANONICAL_APP_SCOPE_SECRET_ABILITIES.has(a.ability),
    );
    if (!allActionsRecognized) {
      return fallbackStatement(grant);
    }
    // Defense-in-depth (Blocker 4 follow-up): re-verify the exact
    // resource tuple even if this grant somehow bypassed
    // annotateAppScopedGrants. The proof requires:
    //   - Ability-derived service is EXACTLY `tinycloud.kv` (no bare
    //     `kv` alias; the annotation gate uses KV_SECRET_SERVICES_PROOF).
    //   - When the wire carried a resource-side short-service segment,
    //     it must be exactly `kv`.
    //   - Space is a secrets-shaped space (loose structural check is
    //     fine here — annotate already required signer-owned exactness).
    //   - Path is BYTE-EXACTLY
    //     `vault/secrets/scoped/<scope>/<secretName>` (no leading/
    //     trailing slash normalization).
    // A wrong service (tinycloud.secrets, bare `kv`), a service-
    // mismatched wire tuple, a non-secrets space, or a non-canonical
    // path must never produce friendly copy.
    if (!KV_SECRET_SERVICES_PROOF.has(service)) {
      return fallbackStatement(grant);
    }
    if (
      grant.resourceService !== null &&
      grant.resourceService !== "kv"
    ) {
      return fallbackStatement(grant);
    }
    if (!isSecretsSpace(space)) {
      return fallbackStatement(grant);
    }
    if (grant.appScopedSecret.scope) {
      const expectedPath = `vault/secrets/scoped/${grant.appScopedSecret.scope}/${grant.appScopedSecret.secretName}`;
      // BYTE-EXACT: no slash normalization. Slash-decorated paths never
      // earned annotation in the first place (see findMatchingDeclaredSecret)
      // and the defense-in-depth check must match that criterion exactly.
      if (path !== expectedPath) {
        return fallbackStatement(grant);
      }
    }
    let primaryText: string;
    if (verbs.hasRead && verbs.hasWrite) {
      primaryText = `Read and update the app secret ${grant.appScopedSecret.secretName}`;
    } else if (verbs.onlyWrite) {
      primaryText = `Update the app secret ${grant.appScopedSecret.secretName}`;
    } else if (verbs.onlyRead) {
      primaryText = `Read the app secret ${grant.appScopedSecret.secretName}`;
    } else {
      return fallbackStatement(grant);
    }
    return { primaryText, service, resource };
  }

  // Sol/Fable follow-up gate: for the KV / SQL / encryption family and
  // service branches below, refuse friendly copy whenever ANY action in
  // the grant is outside the byte-exact ability catalog for that service.
  // Without this gate, a grant like
  // `[tinycloud.kv/get, tinycloud.kv/exfiltrate]` would fall through the
  // `verbs.hasRead && verbs.hasWrite` cases (because `get` is a known
  // read verb and `exfiltrate` silently fails every classification check)
  // and inherit friendly copy — implying read/update authority the
  // operator has not seen the unknown verb attached to.
  //
  // Placed AFTER the appScopedSecret branch (whose defense-in-depth
  // already re-checks its own canonical verb allowlist) and BEFORE the
  // own-app-data / cross-app-data family branch, so it protects every
  // friendly KV/SQL/encryption sentence downstream. The named-secrets
  // and capabilities branches keep their own dedicated exact-ability
  // allowlists inside the branch; this gate is a no-op for those
  // services (see `allActionsRecognizedForService`).
  if (!allActionsRecognizedForService(grant)) {
    return fallbackStatement(grant);
  }

  // App-data ownership is already a structural classification. Keep the
  // summary understandable without guessing what a path such as `cycle/` or
  // `inbox/` contains. The literal service and resource remain immediately
  // below this sentence.
  if (grant.family === "own-app-data" || grant.family === "cross-app-data") {
    const noun =
      grant.family === "own-app-data"
        ? "this app's data"
        : "data outside this app";
    let primaryText: string;
    if (verbs.hasRead && verbs.hasWrite) {
      primaryText = `Read and update ${noun}`;
    } else if (verbs.onlyWrite) {
      primaryText = `Update ${noun}`;
    } else if (verbs.onlyRead) {
      primaryText = `Read ${noun}`;
    } else {
      return fallbackStatement(grant);
    }
    return { primaryText, service, resource };
  }

  // 1. Encryption: create + decrypt in the same grant.
  if (ENCRYPTION_SERVICES.has(service)) {
    if (verbs.hasCreate && verbs.hasDecrypt) {
      return {
        primaryText: "Create a decryption network and decrypt protected data",
        service,
        resource,
      };
    }
    if (verbs.onlyDecrypt || (verbs.hasDecrypt && !verbs.hasCreate)) {
      return {
        primaryText: "Decrypt protected data",
        service,
        resource,
      };
    }
    if (verbs.onlyCreate) {
      return {
        primaryText: "Create a decryption network",
        service,
        resource,
      };
    }
    // Mixed / unknown encryption verb combination — fall through to
    // fallback rather than invent semantics.
    return fallbackStatement(grant);
  }

  // 2. Capabilities read (account permissions or secrets permissions).
  if (CAPABILITY_SERVICES.has(service)) {
    // Fail-closed (Sol MAJOR-1 re-fix): the capabilities service has
    // exactly ONE registered structural shape — `capabilities/read` —
    // so we only render the friendly permissions-check copy when every
    // action in the grant is that exact ability. Verbs like `get`,
    // `peek`, or `list` are NOT registered capability shapes and MUST
    // fall back to literal service/resource/actions rendering. Reusing
    // the broad `READ_VERBS` verb set here would let novel action names
    // inherit friendly copy at standard severity.
    //
    // An empty action list must ALSO fall back — `every` on `[]` returns
    // `true` which would otherwise let a zero-action grant inherit the
    // friendly "Check permissions" copy despite carrying no authority.
    if (abilityStrings.length === 0) {
      return fallbackStatement(grant);
    }
    const allActionsRecognized = abilityStrings.every((a) =>
      RECOGNIZED_CAPABILITY_ACTIONS.has(a),
    );
    if (!allActionsRecognized) {
      return fallbackStatement(grant);
    }
    // A capabilities grant on the secrets service is "check permissions
    // for your secrets"; on any other space it is the generic account
    // permissions check. Structurally, the secrets-permission variant
    // sits inside a capabilities grant whose space names the secrets
    // service — but per the contract the family is bootstrap-capabilities
    // for both. We split on the space, which is a structural fact.
    if (isSecretsSpace(space) || grant.family === "secret-read") {
      return {
        primaryText: "Check permissions for your secrets",
        service,
        resource,
      };
    }
    return {
      primaryText: "Check your TinyCloud account permissions",
      service,
      resource,
    };
  }

  // 3. KV shapes on account paths and secret shapes.
  if (KV_SERVICES.has(service)) {
    // 3a. Named secret variables (list / metadata / mutation)
    if (isSecretsVariablesPath(path)) {
      if (verbs.hasWrite) {
        return {
          primaryText: "Manage secret variables",
          service,
          resource,
        };
      }
      // List / metadata only — the read-only variant per contract.
      return {
        primaryText: "View secret variable names and details",
        service,
        resource,
      };
    }
    // 3b. Vault secret reads
    if (isSecretsVaultPath(path)) {
      if (verbs.hasWrite) {
        // The contract only lists vault reads. A vault write is still a
        // "manage secret variables"-adjacent shape; keep the phrasing
        // truthful about mutation.
        return {
          primaryText: "Manage secrets stored in your vault",
          service,
          resource,
        };
      }
      return {
        primaryText: "View secrets stored in your vault",
        service,
        resource,
      };
    }
    // 3c. Account apps / spaces — action-aware phrasing. Never claim
    //     "view and update" unless both read and write actions are
    //     present. Read-only maps to "View"; write-only to "Update".
    if (isAccountAppsPath(path)) {
      let primaryText: string;
      if (verbs.hasRead && verbs.hasWrite) {
        primaryText = "View and update your connected apps";
      } else if (verbs.onlyWrite) {
        primaryText = "Update your connected apps";
      } else if (verbs.onlyRead) {
        primaryText = "View your connected apps";
      } else {
        // Unknown/mixed verb combination — do not invent semantics.
        return fallbackStatement(grant);
      }
      return { primaryText, service, resource };
    }
    if (isAccountSpacesPath(path)) {
      let primaryText: string;
      if (verbs.hasRead && verbs.hasWrite) {
        primaryText = "View and update your storage spaces";
      } else if (verbs.onlyWrite) {
        primaryText = "Update your storage spaces";
      } else if (verbs.onlyRead) {
        primaryText = "View your storage spaces";
      } else {
        return fallbackStatement(grant);
      }
      return { primaryText, service, resource };
    }
    // 3d. Unknown KV path → fallback.
    return fallbackStatement(grant);
  }

  // 4. SQL — account vs secrets.
  if (SQL_SERVICES.has(service)) {
    // 4a. Named secret variables via SQL (list / metadata / mutation) —
    //     structurally these are variables on the secrets space with a
    //     variables path. Match before the generic secrets-SQL rule.
    if (isSecretsVariablesPath(path)) {
      if (verbs.hasWrite) {
        return {
          primaryText: "Manage secret variables",
          service,
          resource,
        };
      }
      return {
        primaryText: "View secret variable names and details",
        service,
        resource,
      };
    }
    // Action-aware SQL phrasing. "Read and update" is only truthful when
    // read AND write (or schema-mutation) actions are both present.
    // Read-only maps to "Read"; write/schema-only maps to "Update".
    const hasSqlMutation = verbs.hasWrite || verbs.hasSchema;
    const sqlReadOnly = verbs.hasRead && !hasSqlMutation;
    const sqlWriteOnly = hasSqlMutation && !verbs.hasRead;
    if (isSecretsSpace(space)) {
      let primaryText: string;
      if (verbs.hasRead && hasSqlMutation) {
        primaryText = "Read and update TinyCloud Secrets data";
      } else if (sqlReadOnly) {
        primaryText = "Read TinyCloud Secrets data";
      } else if (sqlWriteOnly) {
        primaryText = "Update TinyCloud Secrets data";
      } else {
        return fallbackStatement(grant);
      }
      return { primaryText, service, resource };
    }
    let primaryText: string;
    if (verbs.hasRead && hasSqlMutation) {
      primaryText = "Read and update your TinyCloud account";
    } else if (sqlReadOnly) {
      primaryText = "Read your TinyCloud account";
    } else if (sqlWriteOnly) {
      primaryText = "Update your TinyCloud account";
    } else {
      return fallbackStatement(grant);
    }
    return { primaryText, service, resource };
  }

  // 5. Named secrets service (not KV): read vs mutation family.
  if (SECRETS_SERVICES.has(service)) {
    // Fail-closed (Sol MAJOR-1 re-fix): only render friendly copy when
    // every action's ability is an EXACT registered secrets shape.
    // Reusing broad verb sets (READ_VERBS/MUTATION_VERBS/…) would map
    // novel verbs like `secrets/peek` to friendly "permissions" copy at
    // standard severity even though `peek` is not a registered secrets
    // action. Fall back to literal actions instead.
    //
    // Empty action lists must ALSO fall back — `every` on `[]` returns
    // `true` which would let a zero-action grant inherit friendly copy
    // despite carrying no authority.
    if (abilityStrings.length === 0) {
      return fallbackStatement(grant);
    }
    const allActionsRecognized = abilityStrings.every((a) =>
      RECOGNIZED_SECRETS_ACTIONS.has(a),
    );
    if (!allActionsRecognized) {
      return fallbackStatement(grant);
    }
    const hasRecognizedWrite = abilityStrings.some((a) =>
      RECOGNIZED_SECRETS_WRITE_ACTIONS.has(a),
    );
    const hasRecognizedRead = abilityStrings.some((a) =>
      RECOGNIZED_SECRETS_READ_ACTIONS.has(a),
    );
    const hasRecognizedList = abilityStrings.some((a) =>
      RECOGNIZED_SECRETS_LIST_ACTIONS.has(a),
    );
    const hasRecognizedMetadata = abilityStrings.some((a) =>
      RECOGNIZED_SECRETS_METADATA_ACTIONS.has(a),
    );
    if (grant.family === "secret-mutation" || hasRecognizedWrite) {
      return {
        primaryText: "Manage secret variables",
        service,
        resource,
      };
    }
    // capabilities-shape secret reads: "secrets/read" or "secrets/get"
    if (hasRecognizedRead && !hasRecognizedList && !hasRecognizedMetadata) {
      return {
        primaryText: "Check permissions for your secrets",
        service,
        resource,
      };
    }
    // list/metadata → variable-shape read
    if (hasRecognizedList || hasRecognizedMetadata) {
      return {
        primaryText: "View secret variable names and details",
        service,
        resource,
      };
    }
    // Recognized actions but none of the shapes above matched — fall
    // back to the literal actions rather than invent a statement.
    return fallbackStatement(grant);
  }

  // 6. Unknown service — never invent friendly semantics.
  return fallbackStatement(grant);
}

/**
 * Exact copy required by the merge-readiness contract for the sensitive-
 * grant callout pinned at the top of the review. The number must be an
 * integer; callers pass the count produced with
 * `grantReachesSecretDataOrDecryption`.
 */
export function sensitiveCallout(count: number): string {
  return `${count} exact grants reach secret data or decryption. You can review them below.`;
}
