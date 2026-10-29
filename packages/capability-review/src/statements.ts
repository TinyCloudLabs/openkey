// Deterministic statement catalog.
//
// Turns a `CapabilityGrant` into the plain-English single-sentence statement
// the default review view renders. The statement text is a shared, structural
// projection of (family + service + path + actions). It NEVER incorporates
// caller-supplied metadata — presentation metadata may enrich secondary
// display strings, but the primary statement is always derived from the
// verified structure of the request.
//
// Falls back to plain words for the known actions, and the raw ability for
// any other, on any shape it does not recognize — invented friendly semantics
// on unknown shapes would be a spec violation (see the merge-readiness
// contract).
//
// The `sensitiveCallout(n)` string is the exact copy required by the
// contract; UI callers MUST route through it rather than composing the
// sentence themselves.

import type { CapabilityAction, CapabilityGrant, CapabilityReviewModel, PermissionSeverity } from "./model.js";
import { appDisplayName } from "./app-identity.js";
import {
  APP_KEY_ABILITIES,
  DELETE_REFUSED_TEMPLATE,
  DELEGATION_LIST_STATEMENT,
  LITERAL_TRUNCATE_CHARS,
  NAMED_KEY_STATEMENTS,
  OWN_KEY_PREFIX_STATEMENTS,
  appKeyStatementText,
  renderLiteral,
  renderNamedKeySentence,
  type AppKeyAbility,
  type NamedKeyVerb,
} from "./copy.js";
import type { EncryptionResource } from "./encryption-resource.js";
import { ENCRYPTION_URN_PREFIX, parseEncryptionResource } from "./encryption-resource.js";
import { isAppsKeyResource, parseKeyResource } from "./key-resource.js";
import { isMetadataOnlyAccess } from "./action-semantics.js";
import {
  CANONICAL_APP_SCOPE_SECRET_ABILITIES,
  KV_SECRET_SERVICES_PROOF,
  isSecretsSpace,
} from "./app-scope.js";
import {
  KV_FEED_DESCRIPTIONS,
  SQL_ADMIN_OPERATIONS,
  coreOperations,
  isCoreOperationService,
} from "./core-operations.js";
import { plainSentence, plainWords } from "./plain-words.js";

export interface StatementEntry {
  /** The severity of this row when it differs from the grant's: each app key ability is its own row. */
  severity?: PermissionSeverity;
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
  /** Set only on key.delete rows; the review does not offer these to approve. */
  neverApprovable?: boolean;
  /** True when text between backticks in `primaryText` is shown in monospace. */
  codeSpans?: true;
  /** Set on every fallback row (a shape the catalog does not recognize); its raw parts are already escaped and capped. */
  literalEscaped?: true;
  /**
   * Set on a fallback row that shows an action or service raw (unknown,
   * service-mismatched or failing). A safety display: it lists every raw
   * action, so it is exempt from the one-line rule and may wrap.
   */
  showsRawText?: true;
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
  hasRevoke: boolean;
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

// Whole-namespace KV/SQL access has a distinct, known consequence. The
// legacy named-secrets service is intentionally excluded because it is not a
// current manifest service; those grants remain literal.
const RECOGNIZED_KV_NAMESPACE_ACTIONS = new Set<string>([
  "tinycloud.kv/get",
  "kv/get",
  "tinycloud.kv/list",
  "tinycloud.kv/metadata",
  "kv/list",
  "kv/metadata",
]);
const RECOGNIZED_SQL_NAMESPACE_ACTIONS = new Set<string>([
  "tinycloud.sql/read",
  "sql/read",
]);
// Sol MAJOR-3: `create` matches short-verb abilities (e.g. `foo/create`).
// The production encryption service uses the compound verb
// `network.create`, so we ALSO recognize that specific form here; the
// resource is still classified as a network-create action. Adding the
// compound alias is safer than dropping the dot-segment from every verb
// blindly, because unrelated services could carry different meanings
// (e.g. `sql/schema.migrate` should NOT be classified as `migrate`).
//
// The bare `create` short verb is retained in this set so any future
// service that DOES register a `create` action can be classified
// correctly by `classifyVerbs`. Whether friendly encryption copy fires
// is gated separately by `ENCRYPTION_RECOGNIZED_ABILITIES`, which does
// NOT admit `tinycloud.encryption/create` — that string is not in the
// canonical js-sdk registry, so it falls back to literal even though
// its short verb is a known "create" verb.
const CREATE_VERBS = new Set(["create", "network.create"]);
const SCHEMA_VERBS = new Set(["schema"]);
const LIST_VERBS = new Set(["list"]);
const METADATA_VERBS = new Set(["metadata"]);
const REVOKE_VERBS = new Set(["network.revoke"]);

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
  let hasRevoke = false;
  for (const a of actions) {
    const v = verbOf(a);
    if (READ_VERBS.has(v)) hasRead = true;
    if (MUTATION_VERBS.has(v)) hasWrite = true;
    if (DECRYPT_VERBS.has(v)) hasDecrypt = true;
    if (CREATE_VERBS.has(v)) hasCreate = true;
    if (SCHEMA_VERBS.has(v)) hasSchema = true;
    if (LIST_VERBS.has(v)) hasList = true;
    if (METADATA_VERBS.has(v)) hasMetadata = true;
    if (REVOKE_VERBS.has(v)) hasRevoke = true;
  }
  // "only" variants gate action-aware phrasing so we never claim
  // "read and update" when the request is read-only.
  const onlyRead =
    hasRead &&
    !hasWrite &&
    !hasDecrypt &&
    !hasCreate &&
    !hasSchema &&
    !hasRevoke;
  const onlyWrite =
    hasWrite && !hasRead && !hasDecrypt && !hasCreate && !hasRevoke;
  const onlyDecrypt =
    hasDecrypt && !hasRead && !hasWrite && !hasCreate && !hasRevoke;
  const onlyCreate =
    hasCreate && !hasRead && !hasWrite && !hasDecrypt && !hasRevoke;
  return {
    hasRead,
    hasWrite,
    hasDecrypt,
    hasCreate,
    hasSchema,
    hasList,
    hasMetadata,
    hasRevoke,
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
    if (grant.path)
      return `${grant.space}/${grant.resourceService}/${grant.path}`;
    return `${grant.space}/${grant.resourceService}`;
  }
  if (grant.path) return `${grant.space}/${grant.path}`;
  return grant.space;
}

/**
 * True when `space`, `path` or `resourceService` carries an encryption URN
 * that fails the strict parse. Such a grant's literal text is untrusted, so
 * every displayed value is escaped and the resource is capped.
 */
function hasFailingEncryptionUrn(grant: CapabilityGrant): boolean {
  return [grant.space, grant.path, grant.resourceService ?? ""].some(
    (value) =>
      value.startsWith(ENCRYPTION_URN_PREFIX) &&
      parseEncryptionResource(value) === null,
  );
}

/**
 * Fallback row for anything the catalog does not recognize: the known
 * actions in plain words (see plainWords), then every other action by its
 * raw ability ("unknown action: tinycloud.kv/archive"). A service-mismatched
 * wire tuple or a failing encryption URN shows every action raw. Every raw
 * action stays visible. The row is marked `literalEscaped`, and
 * `showsRawText` when any part is raw.
 */
function fallbackStatement(grant: CapabilityGrant): StatementEntry {
  const failing = hasFailingEncryptionUrn(grant);
  const service = failing
    ? renderLiteral(grant.service, LITERAL_TRUNCATE_CHARS)
    : grant.service;
  const resource = failing
    ? renderLiteral(resourceOf(grant), LITERAL_TRUNCATE_CHARS)
    : resourceOf(grant);
  // A near-miss failed the app-scope proof, so it never claims "your".
  const owner =
    grant.ownedBySelf === false
      ? "another user's "
      : grant.ownedBySelf === true && grant.appScopeNearMiss !== true
        ? "your "
        : "";
  const { parts, raw } = plainWords(
    grant.actions.map((action) => action.ability),
    grant.space,
    owner,
    failing || grant.serviceMismatch === true,
  );
  if (raw.length > 0) {
    parts.push(`unknown action${raw.length > 1 ? "s" : ""}: ${raw.join(", ")}`);
  }
  const text =
    parts.length > 0
      ? parts.join("; ")
      : `unknown access: ${renderLiteral(grant.service, LITERAL_TRUNCATE_CHARS)}`;
  return {
    primaryText: text.charAt(0).toUpperCase() + text.slice(1),
    service,
    resource,
    literalEscaped: true,
    ...(raw.length > 0 || parts.length === 0 ? { showsRawText: true as const } : {}),
  };
}

/**
 * Path-shape helpers. These match structural conventions in the wire path
 * (never a caller-supplied "friendly" name).
 */
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
 * still reach secret data and remain Sensitive; the proof only enriches their
 * label. The count exposed by `sensitiveCallout` describes every exact grant
 * that reaches secret data or decryption. Unknown sensitive mutations and create-only
 * encryption grants do not enter the count: neither fact alone proves
 * access to secret data or decryption.
 */
export function grantReachesSecretDataOrDecryption(
  grant: CapabilityGrant,
): boolean {
  if (grant.family === "secret-mutation") return true;
  if (grant.family === "secret-read") {
    return !isMetadataOnlyAccess(grant.actions.map((action) => action.ability));
  }
  if (grant.family === "secret-namespace-list") {
    return !isMetadataOnlyAccess(grant.actions.map((action) => action.ability));
  }

  if (ENCRYPTION_SERVICES.has(grant.service)) {
    const verbs = grantVerbSet(grant);
    return verbs.has("decrypt") || verbs.has("unwrap");
  }

  // Unknown or mismatched grants on a secrets-shaped space still fail closed.
  // Known permission checks and list/metadata-only operations are excluded:
  // they can inspect authority or names, but cannot read secret values.
  //
  // Preserve the earlier fail-closed behavior for unknown services: an
  // unrecognized ability on the secrets space plausibly reaches secret bytes.
  // Only byte-exact, understood permission and metadata shapes earn exclusion.
  if (isSecretsSpace(grant.space)) {
    if (grant.serviceMismatch === true) return true;
    if (
      CAPABILITY_SERVICES.has(grant.service) &&
      grant.actions.length > 0 &&
      grant.actions.every((action) =>
        RECOGNIZED_CAPABILITY_ACTIONS.has(action.ability),
      )
    ) {
      return false;
    }
    if (
      (KV_SERVICES.has(grant.service) || SECRETS_SERVICES.has(grant.service)) &&
      isMetadataOnlyAccess(grant.actions.map((action) => action.ability))
    ) {
      return false;
    }
    return true;
  }
  return false;
}

const KV_SERVICES = new Set(["tinycloud.kv", "kv"]);
const SQL_SERVICES = new Set(["tinycloud.sql", "sql"]);
const CAPABILITY_SERVICES = new Set(["tinycloud.capabilities", "capabilities"]);
const DELEGATION_SERVICES = new Set(["tinycloud.delegation", "delegation"]);
const SECRETS_SERVICES = new Set(["tinycloud.secrets", "secrets"]);
const ENCRYPTION_SERVICES = new Set(["tinycloud.encryption", "encryption"]);
const RECOGNIZED_DELEGATION_ACTIONS = new Set([
  "tinycloud.delegation/list",
  "delegation/list",
  "tinycloud.delegation/status",
  "delegation/status",
]);

function spaceNameOf(space: string): string | null {
  if (/^[a-z][a-z0-9-]*$/i.test(space)) return space.toLowerCase();
  const match = space.match(
    /^tinycloud:pkh:eip155:\d+:0x[a-fA-F0-9]{40}:([^/:]+)$/,
  );
  return match?.[1]?.toLowerCase() ?? null;
}

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

// The KV catalog enumerates only the exact abilities emitted by current
// manifests. Registered compatibility aliases do not earn friendly copy:
// they remain visible literally because they are outside the predictable
// happy path the user is consenting to.
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
]);

// SQL manifests emit read, write, and schema. Broader registered operations
// such as admin and compatibility aliases such as select are intentionally
// literal: they carry authority beyond the deterministic manifest mapping.
const SQL_RECOGNIZED_ABILITIES = new Set<string>([
  "tinycloud.sql/read",
  "sql/read",
  "tinycloud.sql/write",
  "sql/write",
  "tinycloud.sql/schema",
  "sql/schema",
]);

// Encryption abilities. Per the canonical js-sdk capability registry
// (`js-sdk/packages/bootstrap/src/generated/capabilities.ts`) the
// registered wire shapes are `decrypt`, `network.create`, and
// `network.revoke`. The bare `create` short-form is not registered and
// therefore falls back literally rather than receiving friendly copy.
//
// The `unwrap` verb from earlier catalogs is likewise NOT registered
// and no positive test exercises it — dropped.
//
// A revoke-only grant has an exact user-facing consequence. Revoke mixed
// with other encryption actions falls back literally so no authority is
// swallowed by a partial sentence.
const ENCRYPTION_RECOGNIZED_ABILITIES = new Set<string>([
  "tinycloud.encryption/decrypt",
  "encryption/decrypt",
  "tinycloud.encryption/network.create",
  "encryption/network.create",
  "tinycloud.encryption/network.revoke",
  "encryption/network.revoke",
  "tinycloud.encryption/key.create",
  "encryption/key.create",
  "tinycloud.encryption/key.block",
  "encryption/key.block",
  "tinycloud.encryption/key.unblock",
  "encryption/key.unblock",
  "tinycloud.encryption/key.delete",
  "encryption/key.delete",
]);

/**
 * Named-key abilities and the consent verb each one renders. `key.delete` is
 * absent on purpose: it never reaches this table (see buildKeyDeleteStatement).
 */
const NAMED_KEY_VERB_BY_ABILITY: Record<string, NamedKeyVerb> = {
  "tinycloud.encryption/decrypt": "decrypt",
  "encryption/decrypt": "decrypt",
  "tinycloud.encryption/key.create": "create",
  "encryption/key.create": "create",
  "tinycloud.encryption/key.block": "block",
  "encryption/key.block": "block",
  "tinycloud.encryption/key.unblock": "unblock",
  "encryption/key.unblock": "unblock",
};

const KEY_DELETE_ABILITIES = new Set<string>([
  "tinycloud.encryption/key.delete",
  "encryption/key.delete",
]);

function isKeyDeleteAction(action: { ability: string }): boolean {
  return KEY_DELETE_ABILITIES.has(action.ability);
}

/**
 * Encryption URN view of a grant. The URN is read from `space` (canonical:
 * splitResourceUri leaves it whole with `path` "") or from `path` when `space`
 * is the raw "encryption" service name. Any other placement, or a URN that
 * fails the strict parse, is `invalid` and renders the literal fallback.
 * `grant` is the canonical form, with the URN alone in `space`.
 */
type EncryptionUrnView =
  | { kind: "none" }
  | { kind: "invalid"; resource: string }
  | {
      kind: "urn";
      resource: string;
      parsed: EncryptionResource;
      grant: CapabilityGrant;
    };

function canonicalEncryptionUrn(grant: CapabilityGrant): EncryptionUrnView {
  if (!ENCRYPTION_SERVICES.has(grant.service)) return { kind: "none" };
  const resourceService = grant.resourceService ?? "";
  const inSpace = grant.space.startsWith(ENCRYPTION_URN_PREFIX);
  const inPath = grant.path.startsWith(ENCRYPTION_URN_PREFIX);
  const inService = resourceService.startsWith(ENCRYPTION_URN_PREFIX);
  if (!inSpace && !inPath && !inService) return { kind: "none" };
  const resource = inSpace
    ? grant.space
    : inPath
      ? grant.path
      : resourceService;
  const shapeOk =
    (inSpace && !inPath && !inService && resourceService === "") ||
    (inPath &&
      !inSpace &&
      !inService &&
      grant.space === "encryption" &&
      resourceService === "");
  const parsed = shapeOk ? parseEncryptionResource(resource) : null;
  if (parsed === null) return { kind: "invalid", resource };
  // Key and prefix URNs carry their whole path, so a stray `path` beside one
  // is an unexpected placement. A network URN keeps `path` for the legacy
  // network routing.
  if (inSpace && grant.path !== "" && parsed.kind !== "network") {
    return { kind: "invalid", resource };
  }
  return {
    kind: "urn",
    resource,
    parsed,
    grant: {
      ...grant,
      space: resource,
      path: inSpace ? grant.path : "",
      resourceService: null,
    },
  };
}

/**
 * Fail-closed delete row. Every key.delete renders the refusal line and is
 * never approvable. A parsed key or prefix names its own path and network;
 * anything else names the raw resource string.
 */
function buildKeyDeleteStatement(
  grant: CapabilityGrant,
  view: EncryptionUrnView,
): StatementEntry {
  const resource = view.kind === "none" ? resourceOf(grant) : view.resource;
  const parsed = view.kind === "urn" ? view.parsed : null;
  const primaryText =
    parsed !== null && parsed.kind !== "network"
      ? renderNamedKeySentence(
          DELETE_REFUSED_TEMPLATE,
          parsed.keyPath,
          parsed.network,
        )
      : renderNamedKeySentence(
          DELETE_REFUSED_TEMPLATE,
          resource,
          "",
          LITERAL_TRUNCATE_CHARS,
        );
  const failing = hasFailingEncryptionUrn(grant);
  return {
    primaryText,
    service: failing
      ? renderLiteral(grant.service, LITERAL_TRUNCATE_CHARS)
      : grant.service,
    resource: failing ? renderLiteral(resource, LITERAL_TRUNCATE_CHARS) : resource,
    neverApprovable: true,
  };
}

/**
 * Consent row for one key-shaped encryption grant. Anything the ability table
 * or the copy table does not cover renders the literal fallback, so no
 * sentence is shown for an unrecognized shape.
 */
function buildNamedKeyStatement(
  grant: CapabilityGrant,
  parsed: EncryptionResource,
  resource: string,
): StatementEntry {
  const action = grant.actions.length === 1 ? grant.actions[0] : undefined;
  const verb =
    action !== undefined &&
    Object.hasOwn(NAMED_KEY_VERB_BY_ABILITY, action.ability)
      ? NAMED_KEY_VERB_BY_ABILITY[action.ability]
      : undefined;
  if (parsed.kind === "network" || verb === undefined) {
    return fallbackStatement(grant);
  }
  if (grant.ownedBySelf !== true) return fallbackStatement(grant);
  if (parsed.kind === "key" && parsed.network === "default" &&
    /^share\/[^/]+$/.test(parsed.keyPath) && verb === "decrypt") {
    return { primaryText: "Open this shared file", service: grant.service, resource };
  }
  const template = parsed.kind === "prefix" && parsed.network === "default" &&
    (verb === "create" || verb === "decrypt")
    ? OWN_KEY_PREFIX_STATEMENTS[verb]
    : NAMED_KEY_STATEMENTS[verb][parsed.kind];
  if (template === null) return fallbackStatement(grant);
  return {
    primaryText: renderNamedKeySentence(
      template,
      parsed.keyPath,
      parsed.network,
    ),
    service: grant.service,
    resource,
  };
}

/**
 * Fail-closed gate for the KV / SQL / encryption family/service branches
 * below: return `true` only when EVERY action in the grant is a byte-exact
 * ability shape the corresponding branch is prepared to speak friendly
 * copy for. Any unknown ability (or an empty action list) forces the
 * caller into `fallbackStatement(grant)`.
 *
 * Capabilities uses its own dedicated exact-ability allowlist inside the
 * branch. The legacy named-secrets service always falls back literally.
 *
 * Unknown services (anything not in KV / SQL / encryption / capabilities
 * / secrets) return `true` so `buildStatement` reaches its unknown-service
 * fallback branch untouched. The fallback names only the actions it knows
 * and shows any other one raw, so returning `true` here does NOT admit
 * friendly copy for an unknown service — it just avoids double-handling.
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
    return abilityStrings.every((a) => ENCRYPTION_RECOGNIZED_ABILITIES.has(a));
  }
  // Capabilities keeps its own dedicated allowlist inside the branch.
  // Unknown and legacy named-secrets services route to fallbackStatement.
  return true;
}

// Subject phrase for another user's data in `spaceName`.
function otherUserSubject(spaceName: string | null): string {
  const knownSubject: Record<string, string> = {
    account: "account data",
    applications: "application data",
    default: "TinyCloud data",
    public: "public data",
  };
  return spaceName
    ? `another user's ${knownSubject[spaceName] ?? `${spaceName} data`}`
    : "another user's TinyCloud data";
}

// Returns the statement text when a grant is schema-only and sits on a branch
// that would otherwise fold schema into update copy. Null for anything else.
function schemaOnlyStatementText(
  grant: CapabilityGrant,
  spaceName: string | null,
): string | null {
  if (!SQL_SERVICES.has(grant.service)) return null;
  // Unknown families must reach the literal fallback in buildStatement, which
  // gates on classification before any friendly copy. Ownership never
  // upgrades an unknown shape into schema wording.
  if (grant.family === "unknown") return null;
  if (grant.actions.length === 0) return null;
  if (
    !grant.actions.every(
      (a) =>
        SQL_RECOGNIZED_ABILITIES.has(a.ability) && verbOf(a.ability) === "schema",
    )
  ) {
    return null;
  }
  if (isSecretsSpace(grant.space)) {
    // Secret catalog SQL: schema gets its own row. The catalog's "manage"
    // copy does not name tables, so create/change/delete is stated here.
    if (grant.ownedBySelf !== true && grant.ownedBySelf !== false) return null;
    const owner = grant.ownedBySelf === false ? "another user's" : "your";
    const scope = grant.path === "" ? (grant.ownedBySelf === false ? "all of " : "all ") : "";
    return `Edit and delete ${scope}${owner} secret tables`;
  }
  if (grant.ownedBySelf === false && !isSecretsSpace(grant.space)) {
    // "another user's application data" → "another user's application tables".
    return `Edit and delete ${otherUserSubject(spaceName).replace(/ data$/, " tables")}`;
  }
  if (spaceName === "applications" && grant.family === "own-app-data") {
    return "Edit and delete this app's tables";
  }
  if (spaceName === "account" && grant.family === "bootstrap-sql") {
    return "Edit and delete tables in your TinyCloud account";
  }
  if (grant.family === "own-app-data" || grant.family === "cross-app-data") {
    return "Edit and delete tables in application data";
  }
  return null;
}

/** The app key ability a wire ability names, byte-exact in either namespace. */
function appKeyAbilityOf(ability: string): AppKeyAbility | null {
  for (const name of APP_KEY_ABILITIES) {
    if (ability === `tinycloud.encryption/${name}` || ability === `encryption/${name}`) return name;
  }
  return null;
}

/**
 * Rows for an encryption grant on a key or prefix under `apps/`, one row per
 * ability in a fixed order, each on its own. An ability that is not one of the
 * five, and a resource under `apps/` that does not parse, keep the literal
 * fallback. `null` for every other grant.
 */
function appKeyStatements(grant: CapabilityGrant): StatementEntry[] | null {
  if (!ENCRYPTION_SERVICES.has(grant.service) || grant.serviceMismatch === true) return null;
  const resource = resourceOf(grant);
  if (!isAppsKeyResource(resource)) return null;
  const parsed = parseKeyResource(resource);
  if (!parsed) {
    const view = canonicalEncryptionUrn(grant);
    return grant.actions.map((action) => {
      const single = { ...grant, actions: [action] };
      return isKeyDeleteAction(action)
        ? buildKeyDeleteStatement(single, view)
        : fallbackStatement(single);
    });
  }
  const target = {
    path: parsed.isPrefix ? `${parsed.keyPath}/` : parsed.keyPath,
    isPrefix: parsed.isPrefix,
  };
  const present = new Set<AppKeyAbility>();
  const unrecognised: CapabilityAction[] = [];
  for (const action of grant.actions) {
    const name = appKeyAbilityOf(action.ability);
    if (name) present.add(name);
    else unrecognised.push(action);
  }
  const rows: StatementEntry[] = APP_KEY_ABILITIES.filter((name) => present.has(name)).map(
    (name) => ({
      primaryText: appKeyStatementText(name, target),
      service: grant.service,
      resource,
      codeSpans: true,
      neverApprovable: name === "key.delete",
      severity: name === "decrypt" ? "sensitive" : "attention",
    }),
  );
  if (rows.length === 0 || unrecognised.length > 0) {
    rows.push(fallbackStatement({ ...grant, actions: unrecognised.length > 0 ? unrecognised : grant.actions }));
  }
  return rows;
}

/**
 * The `key.delete` rows of an app key grant, whether or not the action is
 * selected. The action is shown and cannot be approved.
 */
export function appKeyNotGrantableStatements(grant: CapabilityGrant): StatementEntry[] {
  const actions = grant.actions.filter((action) => appKeyAbilityOf(action.ability) === "key.delete");
  return actions.length === 0 ? [] : (appKeyStatements({ ...grant, actions }) ?? []);
}

/** Does this grant let an app decrypt with keys under `apps/`? */
export function grantIsAppKeyDecrypt(grant: CapabilityGrant): boolean {
  return grant.family === "app-keys" && grant.actions.some((action) => appKeyAbilityOf(action.ability) === "decrypt");
}

/** The app a request with app keys comes from; see `app-identity.ts`. */
export interface AppKeyIdentity {
  /** The verified manifest's name after `appDisplayName`, or `null`. */
  name: string | null;
  appId: string;
  /** The verified origin, when there is one. */
  origin: string | null;
}

/**
 * The identity shown at the top of a request with app keys, `null` for any
 * other request. The name needs a manifest that is verified or origin-bound;
 * the id is the verified `app_id`, or the id the key resources name until the
 * manifest is verified. Where the two disagree the name is left out and the id
 * of the resources is shown.
 */
export function appKeyIdentity(model: CapabilityReviewModel): AppKeyIdentity | null {
  const grants = model.permissions.filter((grant) => grant.family === "app-keys");
  if (grants.length === 0) return null;
  const named = new Set<string>();
  for (const grant of grants) {
    const parsed = parseKeyResource(resourceOf(grant));
    const segments = parsed?.keyPath.split("/");
    if (segments && segments[0] === "apps" && segments[1]) named.add(segments[1]);
  }
  const requester = model.requester;
  const verifiedId = requester.appId;
  const resourceId = named.size === 1 ? [...named][0]! : null;
  const appId = verifiedId ?? resourceId;
  if (!appId) return null;
  const trusted =
    requester.manifestNameProvenance === "verified" || requester.manifestNameProvenance === "origin-bound";
  const consistent = resourceId === null || resourceId === appId;
  return {
    name: trusted && verifiedId !== null && consistent ? appDisplayName(requester.manifestName) : null,
    appId: consistent ? appId : resourceId!,
    origin: requester.verifiedOrigin,
  };
}

/** A statement split at its backticks; the odd parts are the monospace text. */
export function splitStatementCode(text: string): Array<{ text: string; code: boolean }> {
  return text
    .split("`")
    .map((part, index) => ({ text: part, code: index % 2 === 1 }))
    .filter((part) => part.text !== "");
}

/**
 * Statement rows for a grant. A KV/SQL grant that mixes `schema` with other
 * recognized abilities yields two rows: the read/update row for the other
 * abilities, and a separate row for schema. Schema is never merged into an
 * update row. Callers must render every returned row; `buildStatement` alone
 * renders only the non-schema part of a mixed grant.
 */
export function buildStatements(input: CapabilityGrant): StatementEntry[] {
  const appKeyRows = appKeyStatements(input);
  if (appKeyRows) return appKeyRows;
  // key.delete is its own never-approvable row beside any other abilities.
  const deletes = input.actions.filter(isKeyDeleteAction);
  if (deletes.length > 0) {
    const others = input.actions.filter((a) => !isKeyDeleteAction(a));
    return [
      ...(others.length > 0 ? buildStatements({ ...input, actions: others }) : []),
      ...deletes.map((action) => buildStatement({ ...input, actions: [action] })),
    ];
  }
  const view = canonicalEncryptionUrn(input);
  if (view.kind === "invalid") return [buildStatement(input)];
  const grant = view.kind === "urn" ? view.grant : input;
  if (view.kind === "urn" && view.parsed.kind !== "network" && grant.actions.length > 1) {
    return grant.actions.map((action) => buildStatement({ ...grant, actions: [action] }));
  }
  // Key actions and decryption actions on one encryption resource get a row
  // each, so neither is folded into the other's words.
  const keyActions = grant.actions.filter((a) => /^(tinycloud\.)?encryption\/key\./.test(a.ability));
  if (
    ENCRYPTION_SERVICES.has(grant.service) &&
    grant.serviceMismatch !== true &&
    keyActions.length > 0 &&
    keyActions.length < grant.actions.length &&
    grant.actions.every((a) => ENCRYPTION_RECOGNIZED_ABILITIES.has(a.ability))
  ) {
    return [
      buildStatement({ ...grant, actions: grant.actions.filter((a) => !keyActions.includes(a)) }),
      buildStatement({ ...grant, actions: keyActions }),
    ];
  }
  const schemaActions = grant.actions.filter(
    (a) => verbOf(a.ability) === "schema",
  );
  const otherActions = grant.actions.filter(
    (a) => verbOf(a.ability) !== "schema",
  );
  const splittable =
    schemaActions.length > 0 &&
    otherActions.length > 0 &&
    SQL_SERVICES.has(grant.service) &&
    grant.serviceMismatch !== true &&
    grant.appScopeNearMiss !== true &&
    !grant.appScopedSecret &&
    grant.actions.every((a) => SQL_RECOGNIZED_ABILITIES.has(a.ability)) &&
    schemaOnlyStatementText(
      { ...grant, actions: schemaActions },
      spaceNameOf(grant.space),
    ) !== null;
  if (!splittable) return [buildStatement(grant)];
  return [
    buildStatement({ ...grant, actions: otherActions }),
    buildStatement({ ...grant, actions: schemaActions }),
  ];
}

/**
 * Compute the deterministic statement for a grant. Match order:
 *   1. Encryption create + decrypt combined form (bundle across grants must
 *      be handled by the caller — here we only produce the single-grant
 *      "network + decrypt" phrasing when a grant carries both `network`
 *      create and a decrypt verb).
 *   2. Canonical TinyCloud account/application/public/default resources
 *   3. Secret reads and mutations
 *   4. Anything else → literal fallback
 */
export function buildStatement(input: CapabilityGrant): StatementEntry {
  const appKeyRows = appKeyStatements(input);
  if (appKeyRows) return appKeyRows[0]!;
  // key.delete fails closed: every delete row is never approvable and renders
  // the refusal line, whatever its resource parses to.
  const view = canonicalEncryptionUrn(input);
  if (input.actions.some(isKeyDeleteAction)) {
    return input.actions.length === 1
      ? buildKeyDeleteStatement(input, view)
      : { ...fallbackStatement(input), neverApprovable: true };
  }
  // A URN that fails the strict parse, or sits in an unexpected field, renders
  // the literal fallback.
  if (view.kind === "invalid") return fallbackStatement(input);
  const grant = view.kind === "urn" ? view.grant : input;
  const service = grant.service;
  const path = grant.path;
  const space = grant.space;
  // `grant.actions` is `CapabilityAction[]`; classifyVerbs works on the
  // ability string (e.g. `tinycloud.kv/get`), so project first.
  const abilityStrings = grant.actions.map((a) => a.ability);
  const verbs = classifyVerbs(abilityStrings);
  const resource = resourceOf(grant);
  const spaceName = spaceNameOf(space);

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
  // Key-shaped encryption grants render per-verb copy. A network URN falls
  // through to the network branches below.
  if (view.kind === "urn" && view.parsed.kind !== "network") {
    return buildNamedKeyStatement(input, view.parsed, view.resource);
  }

  // Schema is never folded into another row. A mixed schema grant falls back
  // to the literal wire tuple here; buildStatements() renders the split rows.
  if (
    grant.actions.some((a) => verbOf(a.ability) === "schema") &&
    grant.actions.some((a) => verbOf(a.ability) !== "schema")
  ) {
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

  // Schema-only SQL grants get their own row; see schemaOnlyStatementText.
  const schemaText = schemaOnlyStatementText(grant, spaceName);
  if (schemaText !== null) {
    return { primaryText: schemaText, service, resource };
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
    if (grant.resourceService !== null && grant.resourceService !== "kv") {
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

  if (grant.family === "secret-namespace-list") {
    const recognizedActions = KV_SERVICES.has(service)
      ? RECOGNIZED_KV_NAMESPACE_ACTIONS
      : SQL_SERVICES.has(service)
        ? RECOGNIZED_SQL_NAMESPACE_ACTIONS
        : null;
    if (
      grant.actions.length === 0 ||
      recognizedActions === null ||
      !grant.actions.every((action) =>
        recognizedActions.has(action.ability),
      )
    ) {
      return fallbackStatement(grant);
    }
    const hasValueRead = grant.actions.some((action) =>
      ["get", "read", "select"].includes(verbOf(action.ability)),
    );
    if (!hasValueRead) {
      return {
        primaryText:
          grant.ownedBySelf === false
            ? "View another user's secret names and details"
            : grant.ownedBySelf === true
              ? "View your secret names and details"
              : "View the requested secret names and details",
        service,
        resource,
      };
    }
    return {
      primaryText: SQL_SERVICES.has(service)
        ? grant.ownedBySelf === false
          ? "View another user's entire secret catalog"
          : grant.ownedBySelf === true
            ? "View your entire secret catalog"
            : "View the entire requested secret catalog"
        : grant.ownedBySelf === false
          ? "Read all secret values in another user's vault"
          : grant.ownedBySelf === true
            ? "Read all secret values in your vault"
            : "Read all secret values in the requested vault",
      service,
      resource,
    };
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
  const coreStatement = coreOperationStatement(grant);
  if (coreStatement) return coreStatement;

  if (!allActionsRecognizedForService(grant)) {
    return fallbackStatement(grant);
  }

  // Classification is the authority for whether a structural shape is
  // understood. Ownership or a familiar-looking path must never upgrade an
  // unknown grant into reassuring copy.
  if (grant.family === "unknown") {
    return fallbackStatement(grant);
  }

  // Root access covers the whole secrets store. Preserve that scope in the
  // plain-language consequence instead of making it sound like one value.
  if (
    grant.family === "secret-mutation" &&
    isSecretsSpace(space) &&
    path === ""
  ) {
    if (KV_SERVICES.has(service)) {
      return {
        primaryText:
          grant.ownedBySelf === false
            ? "Manage all secrets stored in another user's vault"
            : grant.ownedBySelf === true
              ? "Manage all secrets stored in your vault"
              : "Manage all secrets stored in the requested vault",
        service,
        resource,
      };
    }
    if (SQL_SERVICES.has(service)) {
      return {
        primaryText:
          grant.ownedBySelf === false
            ? "Manage another user's entire secret catalog"
            : grant.ownedBySelf === true
              ? "Manage your entire secret catalog"
              : "Manage the entire requested secret catalog",
        service,
        resource,
      };
    }
  }

  // Resource ownership is a different fact from application identity. Only
  // an owner that differs from the signer earns another-user wording.
  if (grant.ownedBySelf === false && CAPABILITY_SERVICES.has(service)) {
    return {
      primaryText: "Check another user's TinyCloud permissions",
      service,
      resource,
    };
  }
  if (grant.ownedBySelf === false && DELEGATION_SERVICES.has(service)) {
    return {
      primaryText: "View another user's connected access",
      service,
      resource,
    };
  }
  // The KV data sentences below say "update", which hides a delete. A grant
  // that can delete reads in plain words that name it ("Read and delete your
  // data"). Secrets and the account space keep their own sentences.
  if (
    KV_SERVICES.has(service) &&
    !isSecretsSpace(space) &&
    spaceName !== "account" &&
    grant.actions.some((a) => verbOf(a.ability) === "del" || verbOf(a.ability) === "delete")
  ) {
    const owner = grant.ownedBySelf === true ? "your " : grant.ownedBySelf === false ? "another user's " : "";
    return { primaryText: plainSentence(abilityStrings, space, owner), service, resource };
  }
  if (
    grant.ownedBySelf === false &&
    (KV_SERVICES.has(service) || SQL_SERVICES.has(service)) &&
    !isSecretsSpace(space)
  ) {
    const subject = otherUserSubject(spaceName);
    if (verbs.hasRead && verbs.hasWrite) {
      return { primaryText: `Read and update ${subject}`, service, resource };
    }
    if (verbs.hasWrite) {
      return { primaryText: `Update ${subject}`, service, resource };
    }
    if (verbs.hasRead || verbs.hasList || verbs.hasMetadata) {
      return { primaryText: `Read ${subject}`, service, resource };
    }
    return fallbackStatement(grant);
  }

  // Secret-space list/metadata operations expose names and metadata, not
  // secret values. Value reads and mutations retain explicit, sensitive
  // copy. This mapping is structural and applies consistently to KV and SQL
  // without relying on app-specific labels.
  if (
    isSecretsSpace(space) &&
    (KV_SERVICES.has(service) || SQL_SERVICES.has(service))
  ) {
    const secretOwner = grant.ownedBySelf === false ? "another user's" : "your";
    // TinyCloud's secrets SQL database stores the secret catalog (scope,
    // name, provider, notes, and test metadata). Secret values live in KV.
    if (SQL_SERVICES.has(service)) {
      const hasCatalogMutation = verbs.hasWrite || verbs.hasSchema;
      if (verbs.hasRead && hasCatalogMutation) {
        return {
          primaryText: `View and manage ${secretOwner} secret catalog`,
          service,
          resource,
        };
      }
      if (hasCatalogMutation) {
        return {
          primaryText: `Manage ${secretOwner} secret catalog`,
          service,
          resource,
        };
      }
      if (verbs.hasRead) {
        return {
          primaryText: `View ${secretOwner} secret catalog`,
          service,
          resource,
        };
      }
      return fallbackStatement(grant);
    }
    if (isMetadataOnlyAccess(abilityStrings)) {
      return {
        primaryText:
          grant.ownedBySelf === false
            ? "View another user's secret names and details"
            : "View secret names and details",
        service,
        resource,
      };
    }
    const hasValueRead = abilityStrings.some((ability) => {
      const verb = verbOf(ability);
      return verb === "get" || verb === "read" || verb === "select";
    });
    const hasValueMutation = verbs.hasWrite || verbs.hasSchema;
    if (hasValueRead && hasValueMutation) {
      return {
        primaryText:
          grant.ownedBySelf === false
            ? "Read and update another user's secret values"
            : "Read and update secret values",
        service,
        resource,
      };
    }
    if (hasValueMutation) {
      return {
        primaryText:
          grant.ownedBySelf === false
            ? "Update another user's secret values"
            : "Update secret values",
        service,
        resource,
      };
    }
    if (hasValueRead) {
      return {
        primaryText:
          grant.ownedBySelf === false
            ? "Read another user's secret values"
            : "Read secret values",
        service,
        resource,
      };
    }
    return fallbackStatement(grant);
  }

  // Canonical bootstrap resources have stable product meaning. These labels
  // are derived from the signed resource structure, not caller-supplied copy.
  if (
    spaceName === "account" &&
    (grant.family === "bootstrap-kv" || grant.family === "bootstrap-sql")
  ) {
    return {
      primaryText: "Manage your TinyCloud account",
      service,
      resource,
    };
  }

  if (
    spaceName === "applications" &&
    grant.family === "own-app-data" &&
    (KV_SERVICES.has(service) || SQL_SERVICES.has(service))
  ) {
    if (verbs.hasRead && verbs.hasWrite) {
      return {
        primaryText: "Read and update application data",
        service,
        resource,
      };
    }
    if (verbs.hasWrite) {
      return { primaryText: "Update application data", service, resource };
    }
    if (verbs.hasRead || verbs.hasList || verbs.hasMetadata) {
      return { primaryText: "Read application data", service, resource };
    }
    return fallbackStatement(grant);
  }

  if (grant.family === "public-data" && KV_SERVICES.has(service)) {
    if (verbs.hasWrite) {
      return {
        primaryText: verbs.hasRead
          ? "Read and publish your public data"
          : "Publish and update your public data",
        service,
        resource,
      };
    }
    if (verbs.hasRead || verbs.hasList || verbs.hasMetadata) {
      return { primaryText: "Read your public data", service, resource };
    }
    return fallbackStatement(grant);
  }

  if (
    spaceName === "default" &&
    (grant.family === "bootstrap-kv" || grant.family === "bootstrap-sql") &&
    (KV_SERVICES.has(service) || SQL_SERVICES.has(service))
  ) {
    if (verbs.hasRead && verbs.hasWrite) {
      return {
        primaryText: "Read and update your TinyCloud data",
        service,
        resource,
      };
    }
    if (verbs.hasWrite) {
      return { primaryText: "Update your TinyCloud data", service, resource };
    }
    if (verbs.hasRead || verbs.hasList || verbs.hasMetadata) {
      return { primaryText: "Read your TinyCloud data", service, resource };
    }
    return fallbackStatement(grant);
  }

  // App-data ownership is already a structural classification. Keep the
  // summary understandable without guessing what a path such as `cycle/` or
  // `inbox/` contains. The literal service and resource remain immediately
  // below this sentence.
  //
  // Sol post-rejection (Behavior 2): the friendly app-data copy is only
  // truthful for services whose wire abilities we recognize. The current
  // classifier only stamps `own-app-data` / `cross-app-data` on
  // KV / SQL grants, but `buildStatement` itself must uphold that
  // invariant so a future classifier change (or a fixture built by a
  // caller) cannot smuggle an unknown-service grant into the friendly
  // neutral application-data copy. Fail
  // closed for any service outside the KV / SQL recognized set — the
  // grant renders the literal service/resource/actions instead.
  //
  // Capabilities, named-secrets, encryption, and their own-app-scoped
  // secret siblings never carry the app-data family, so they are not
  // affected by this gate — the earlier appScopedSecret branch and the
  // downstream family/service branches keep their exact gates.
  if (grant.family === "own-app-data" || grant.family === "cross-app-data") {
    if (!KV_SERVICES.has(service) && !SQL_SERVICES.has(service)) {
      return fallbackStatement(grant);
    }
    const noun = "application data";
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
    // The words below name neither another user nor key actions, so those
    // grants read in plain words instead.
    if (
      grant.ownedBySelf === false ||
      !abilityStrings.every((a) => /^(tinycloud\.)?encryption\/(decrypt|network\.create|network\.revoke)$/.test(a))
    ) {
      return fallbackStatement(grant);
    }
    if (verbs.hasRevoke) {
      if (
        abilityStrings.length === 1 &&
        (abilityStrings[0] === "tinycloud.encryption/network.revoke" ||
          abilityStrings[0] === "encryption/network.revoke")
      ) {
        return {
          primaryText: "Disable the decryption network",
          service,
          resource,
        };
      }
      return fallbackStatement(grant);
    }
    if (verbs.hasCreate && verbs.hasDecrypt) {
      return {
        primaryText: "Set up encryption and decrypt protected data",
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
        primaryText: "Set up encryption",
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
    return {
      primaryText: "Check your TinyCloud permissions",
      service,
      resource,
    };
  }

  if (DELEGATION_SERVICES.has(service)) {
    const allActionsRecognized =
      abilityStrings.length > 0 &&
      abilityStrings.every((ability) =>
        RECOGNIZED_DELEGATION_ACTIONS.has(ability),
      );
    if (!allActionsRecognized) return fallbackStatement(grant);
    return {
      primaryText: DELEGATION_LIST_STATEMENT,
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
    // 3c. Unknown KV path → fallback.
    return fallbackStatement(grant);
  }

  // 4. Other SQL shapes are not part of the canonical bootstrap mapping.
  if (SQL_SERVICES.has(service)) {
    return fallbackStatement(grant);
  }

  // 5. Current manifests represent secrets through KV vault resources.
  // The named-secrets service has no authoritative current wire contract,
  // so keep every action literal while its secret family retains Sensitive.
  if (SECRETS_SERVICES.has(service)) {
    return fallbackStatement(grant);
  }

  // 6. Unknown service — never invent friendly semantics.
  return fallbackStatement(grant);
}

/**
 * Friendly copy for TinyCloud core operations named by exact ability
 * (core-operations.ts), plus SQL admin on a named database and the KV
 * change feed. Returns null when the grant is not one of these shapes; the
 * caller then applies its usual gates. Every action must be in the catalog,
 * the family must be the one classify.ts assigns, and another user's
 * resource always renders literally.
 */
function coreOperationStatement(grant: CapabilityGrant): StatementEntry | null {
  const service = grant.service;
  const abilities = grant.actions.map((action) => action.ability);
  const resource = resourceOf(grant);
  const literal = () => fallbackStatement(grant);
  // One operation keeps its own sentence; several read as plain kinds, on one line.
  const oneLine = (descriptions: string[]): string =>
    new Set(descriptions).size === 1
      ? descriptions[0]!
      : plainSentence(abilities, grant.space, grant.ownedBySelf === true ? "your " : "");

  if (isCoreOperationService(service)) {
    const operations = coreOperations(service, abilities);
    if (
      !operations ||
      grant.ownedBySelf === false ||
      !operations.some((operation) => operation.family === grant.family)
    ) {
      return literal();
    }
    return {
      primaryText: oneLine(operations.map((operation) => operation.description)),
      service,
      resource,
    };
  }

  const exactVerbs = (
    services: ReadonlySet<string>,
    catalog: Readonly<Record<string, unknown>>,
  ): string[] | null => {
    if (abilities.length === 0) return null;
    const verbs: string[] = [];
    for (const ability of abilities) {
      if (!ability.includes("/")) return null;
      const head = ability.slice(0, ability.indexOf("/"));
      const verb = verbOf(ability);
      if (!services.has(head) || !Object.hasOwn(catalog, verb)) return null;
      verbs.push(verb);
    }
    return verbs;
  };

  if (grant.family === "database-admin" && SQL_SERVICES.has(service)) {
    const verbs = exactVerbs(SQL_SERVICES, SQL_ADMIN_OPERATIONS);
    if (!verbs || grant.ownedBySelf === false) return literal();
    return {
      primaryText: oneLine(verbs.map((verb) => SQL_ADMIN_OPERATIONS[verb]!.description)),
      service,
      resource,
    };
  }

  if (
    KV_SERVICES.has(service) &&
    (grant.family === "own-app-data" || grant.family === "bootstrap-kv") &&
    grant.ownedBySelf !== false &&
    !isSecretsSpace(grant.space)
  ) {
    const verbs = exactVerbs(KV_SERVICES, KV_FEED_DESCRIPTIONS);
    if (!verbs) return null;
    return {
      primaryText: oneLine(verbs.map((verb) => KV_FEED_DESCRIPTIONS[verb]!)),
      service,
      resource,
    };
  }
  return null;
}

/**
 * Exact copy required by the merge-readiness contract for the sensitive-
 * grant callout pinned at the top of the review. The number must be an
 * integer; callers pass the count produced with
 * `grantReachesSecretDataOrDecryption`.
 */
export function sensitiveCallout(count: number): string {
  return count === 1
    ? "1 permission reaches secrets or decryption"
    : `${count} permissions reach secrets or decryption`;
}
