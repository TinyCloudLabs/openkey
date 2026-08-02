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

/** Compact resource string used as secondary context. */
function resourceOf(grant: CapabilityGrant): string {
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
function isSecretsSqlSpace(space: string): boolean {
  // A SQL grant on the "secrets" space or a `tinycloud:...:secrets` space.
  return (
    space === "secrets" ||
    /:secrets(?:\/|$)/.test(space) ||
    /:secrets:/.test(space)
  );
}

function grantVerbSet(grant: CapabilityGrant): Set<string> {
  return new Set(grant.actions.map((action) => verbOf(action.ability)));
}

/**
 * True only when the exact grant reaches TinyCloud secret data or can decrypt
 * protected data. Kept beside the statement catalog so every UI surface uses
 * the same structural definition as the copy it displays.
 *
 * App-scoped secrets that passed the dedicated origin-bound manifest proof
 * are deliberately normal and do not enter the warning count. Unknown
 * sensitive mutations and create-only encryption grants also do not enter the
 * count: neither fact alone proves access to secret data or decryption.
 */
export function grantReachesSecretDataOrDecryption(
  grant: CapabilityGrant,
): boolean {
  if (grant.appScopedSecret) return false;

  if (grant.family === "secret-read" || grant.family === "secret-mutation") {
    return true;
  }

  if (ENCRYPTION_SERVICES.has(grant.service)) {
    const verbs = grantVerbSet(grant);
    return verbs.has("decrypt") || verbs.has("unwrap");
  }

  // KV and SQL entries in the structurally named secrets space can be
  // classified as cross-app data before their domain-specific statement is
  // projected. They still reach TinyCloud Secrets data and belong here.
  return (
    (KV_SERVICES.has(grant.service) || SQL_SERVICES.has(grant.service)) &&
    isSecretsSqlSpace(grant.space)
  );
}

const KV_SERVICES = new Set(["tinycloud.kv", "kv"]);
const SQL_SERVICES = new Set(["tinycloud.sql", "sql"]);
const CAPABILITY_SERVICES = new Set(["tinycloud.capabilities", "capabilities"]);
const SECRETS_SERVICES = new Set(["tinycloud.secrets", "secrets"]);
const ENCRYPTION_SERVICES = new Set(["tinycloud.encryption", "encryption"]);

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

  // An app-scoped secret reaches this branch only after the exact,
  // origin-bound manifest proof in app-scope.ts. The secret name is therefore
  // structural review state rather than an unverified friendly label.
  if (grant.appScopedSecret) {
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
    // A capabilities grant on the secrets service is "check permissions
    // for your secrets"; on any other space it is the generic account
    // permissions check. Structurally, the secrets-permission variant
    // sits inside a capabilities grant whose space names the secrets
    // service — but per the contract the family is bootstrap-capabilities
    // for both. We split on the space, which is a structural fact.
    if (isSecretsSqlSpace(space) || grant.family === "secret-read") {
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
    if (isSecretsSqlSpace(space)) {
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
    if (grant.family === "secret-mutation" || verbs.hasWrite) {
      return {
        primaryText: "Manage secret variables",
        service,
        resource,
      };
    }
    // capabilities-shape secret reads: "capabilities/read"
    if (verbs.hasRead && !verbs.hasList && !verbs.hasMetadata) {
      return {
        primaryText: "Check permissions for your secrets",
        service,
        resource,
      };
    }
    // list/metadata → variable-shape read
    if (verbs.hasList || verbs.hasMetadata) {
      return {
        primaryText: "View secret variable names and details",
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
