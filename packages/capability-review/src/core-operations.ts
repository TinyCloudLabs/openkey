// TinyCloud core operations that capability review names by exact ability.
//
// The TinyCloud node registry (`tinycloud-node/capabilities.json`, vendored in
// `@tinycloud/bootstrap`) lists every grantable core ability. KV, SQL,
// capabilities, delegation and encryption keep their dedicated branches in
// classify.ts and statements.ts. The services below have no product-specific
// target rules, so each registered ability carries one fixed label and one
// fixed consent sentence.
//
// This catalog only changes how a grant is described. It never decides what
// is permitted, signed or delegated. Any verb outside the catalog on these
// services still classifies as `unknown` and is shown literally.

import type { CapabilityFamily } from "./model.js";

export interface CoreOperation {
  /** Family the ability classifies into on its own. */
  family: CapabilityFamily;
  /** Short display label (grant title). */
  label: string;
  /** Consent-screen sentence. */
  description: string;
}

export const SPACE_SERVICES = new Set(["tinycloud.space", "space"]);
export const HOOKS_SERVICES = new Set(["tinycloud.hooks", "hooks"]);
export const DUCKDB_SERVICES = new Set(["tinycloud.duckdb", "duckdb"]);
export const VFS_SERVICES = new Set(["tinycloud.vfs", "vfs"]);

/** Keyed by service family, then by verb. */
const CATALOG: ReadonlyArray<{
  services: ReadonlySet<string>;
  verbs: Readonly<Record<string, CoreOperation>>;
}> = [
  {
    services: SPACE_SERVICES,
    verbs: {
      // `space/host` is what actually creates the space on the node.
      host: {
        family: "space-create",
        label: "Create a space",
        description: "Create a new TinyCloud space",
      },
      create: {
        family: "space-create",
        label: "Create a space",
        description: "Create a new TinyCloud space",
      },
      list: {
        family: "space-read",
        label: "List your spaces",
        description: "See which TinyCloud spaces you own",
      },
      info: {
        family: "space-read",
        label: "Space storage usage",
        description: "See this space's storage usage and plan",
      },
    },
  },
  {
    services: HOOKS_SERVICES,
    verbs: {
      subscribe: {
        family: "hooks",
        label: "Change notifications (subscribe)",
        description: "Get notified when data in this space changes",
      },
      register: {
        family: "hooks",
        label: "Webhooks (register)",
        description: "Send this space's change alerts to a webhook",
      },
      list: {
        family: "hooks",
        label: "Webhooks (view)",
        description: "See the webhooks registered for this space",
      },
      unregister: {
        family: "hooks",
        label: "Webhooks (remove)",
        description: "Remove webhooks registered for this space",
      },
    },
  },
  {
    services: DUCKDB_SERVICES,
    verbs: {
      read: {
        family: "duckdb-data",
        label: "DuckDB database (read)",
        description: "Read a DuckDB database",
      },
      // Deprecated alias of `duckdb/read`.
      select: {
        family: "duckdb-data",
        label: "DuckDB database (read)",
        description: "Read a DuckDB database",
      },
      write: {
        family: "duckdb-data",
        label: "DuckDB database (update)",
        description: "Update a DuckDB database",
      },
      export: {
        family: "duckdb-data",
        label: "DuckDB database (export)",
        description: "Download a copy of a DuckDB database",
      },
      admin: {
        family: "database-admin",
        label: "DuckDB database (manage)",
        description: "Change a DuckDB database's structure and settings",
      },
      import: {
        family: "database-admin",
        label: "DuckDB database (replace)",
        description: "Replace a DuckDB database with an uploaded file",
      },
      "*": {
        family: "database-admin",
        label: "DuckDB database (full access)",
        description: "Read, update, replace and manage a DuckDB database",
      },
    },
  },
  {
    // Reserved in the registry: the node does not serve these yet.
    services: VFS_SERVICES,
    verbs: {
      get: {
        family: "file-data",
        label: "Files (read)",
        description: "Read files",
      },
      list: {
        family: "file-data",
        label: "Files (list)",
        description: "See file names",
      },
      metadata: {
        family: "file-data",
        label: "Files (details)",
        description: "See file names and details",
      },
      put: {
        family: "file-data",
        label: "Files (update)",
        description: "Add and change files",
      },
      delete: {
        family: "file-data",
        label: "Files (delete)",
        description: "Delete files",
      },
    },
  },
];

/** SQL operations beyond the manifest read/write/schema mapping. */
export const SQL_ADMIN_OPERATIONS: Readonly<Record<string, CoreOperation>> = {
  admin: {
    family: "database-admin",
    label: "SQL database (manage)",
    description: "Change an app database's structure and settings",
  },
  "*": {
    family: "database-admin",
    label: "SQL database (full access)",
    description: "Read, change, delete and manage an app database",
  },
};

/**
 * Consent sentences for the KV change-feed abilities. Their family and label
 * come from the KV target rules in classify.ts.
 */
export const KV_FEED_DESCRIPTIONS: Readonly<Record<string, string>> = {
  sync: "See which data changes, but not the values",
  retain: "Keep synced data available offline",
};

export function isCoreOperationService(service: string): boolean {
  return CATALOG.some((entry) => entry.services.has(service));
}

function verbOf(ability: string): string {
  return ability.includes("/") ? ability.slice(ability.indexOf("/") + 1) : ability;
}

/** The catalog entry for one ability, or null when it is not registered. */
export function coreOperation(
  service: string,
  ability: string,
): CoreOperation | null {
  const entry = CATALOG.find((candidate) => candidate.services.has(service));
  if (!entry) return null;
  if (ability.includes("/")) {
    const head = ability.slice(0, ability.indexOf("/"));
    if (!entry.services.has(head)) return null;
  }
  return Object.hasOwn(entry.verbs, verbOf(ability))
    ? entry.verbs[verbOf(ability)]!
    : null;
}

/**
 * Operations for every action, or null when any action is outside the
 * catalog (including an empty action list).
 */
export function coreOperations(
  service: string,
  actions: readonly string[],
): CoreOperation[] | null {
  if (actions.length === 0) return null;
  const operations: CoreOperation[] = [];
  for (const action of actions) {
    const operation = coreOperation(service, action);
    if (!operation) return null;
    operations.push(operation);
  }
  return operations;
}
