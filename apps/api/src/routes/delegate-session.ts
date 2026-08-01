// Pure delegation-session preparation helpers.
//
// Extracted from `delegate.ts` so tests can exercise the SIWE/ReCap logic
// (including the CLI-explicit permission narrowing rule) without pulling in
// better-auth, Prisma, or the TEE client — all of which delegate.ts loads at
// module import time. Keeping this file free of side-effect imports also
// prevents `mock.module(...)` calls in one test suite from leaking into
// unrelated integration suites.

import {
  prepareSession,
  makeSpaceId,
  parseRecapFromSiwe,
} from '@tinycloud/node-sdk-wasm';
import { CAPABILITIES, KV, SQL } from '@tinycloud/bootstrap';
import {
  DelegateRequestError,
  shortServiceName,
} from './delegate-validation';

export type DelegationJwk = { kty: string; crv: string; x: string };
export type AbilitiesMap = Record<string, Record<string, string[]>>;

export interface RecapEntry {
  service: string;
  space: string;
  path: string;
  actions: string[];
}

export interface PermissionActionOption {
  key: string;
  action: string;
  ability: string;
  required: boolean;
}

export interface PermissionOption {
  key: string;
  service: string;
  path: string;
  label: string;
  resourcePath: string;
  actions: PermissionActionOption[];
}

/**
 * The CLI baseline permission shape. Duplicated locally rather than imported
 * from delegate-validation so this module can accept the more permissive raw
 * encryption entries (which delegate-validation.validatePermissions rejects).
 */
export interface DelegationPermissionEntry {
  service: string;
  space?: string;
  path: string;
  actions: string[];
}

// SIWE domain identifies the requestor (the CLI). Duplicated (rather than
// re-exported from delegate.ts) to keep this module standalone.
export const SIWE_DOMAIN = 'cli.tinycloud.xyz';

// Capability URNs come from the TC-112 registry constants published by
// @tinycloud/bootstrap. Note: tinycloud.sql/export is deliberately absent —
// it was never a node-dispatched ability (SQL export ops are authorized as
// sql/read) and js-sdk 2.6.0's exportDb mints sql/read, so granting it was
// a dead no-op (TC-114).
export const DEFAULT_ABILITIES: AbilitiesMap = {
  kv: {
    '': [KV.PUT, KV.GET, KV.DEL, KV.LIST, KV.METADATA],
  },
  sql: {
    '': [SQL.READ, SQL.WRITE, SQL.ADMIN],
  },
  capabilities: {
    '': [CAPABILITIES.READ],
  },
};

const SERVICE_LABELS: Record<string, string> = {
  kv: 'Key-Value Storage',
  sql: 'SQL Database',
  capabilities: 'Capabilities',
};

/**
 * Canonicalize a WASM/short service name (e.g. `kv`) to its fully-qualified
 * TinyCloud namespace (`tinycloud.kv`). The WASM `parseRecapFromSiwe`
 * emits short names in RecapEntry.service, but the canonical OpenKey
 * action ID and the js-sdk NodeUserAuthorization consumer both expect
 * the four-part `service\0space\0path\0ability` form where `service`
 * is `tinycloud.<short>` — matching how ReCap actions are prefixed
 * (`tinycloud.kv/get`, etc.).
 *
 * Passing `tinycloud.kv` (already-qualified) returns it unchanged.
 */
export function canonicalizeServiceName(service: string): string {
  if (!service) return service;
  if (service.startsWith('tinycloud.')) return service;
  return `tinycloud.${service}`;
}

export function permissionKey(entry: RecapEntry): string {
  return `${canonicalizeServiceName(entry.service)}\0${entry.space}\0${entry.path}`;
}

export function actionKey(entry: RecapEntry, action: string): string {
  return `${permissionKey(entry)}\0${action}`;
}

export function isRequiredAction(entry: RecapEntry, action: string): boolean {
  return entry.service === 'capabilities' && action === CAPABILITIES.READ;
}

export function permissionOption(entry: RecapEntry): PermissionOption {
  const resourcePath = entry.path ? `${entry.service}/${entry.path}` : entry.service;
  return {
    key: permissionKey(entry),
    service: entry.service,
    path: entry.path,
    label: SERVICE_LABELS[entry.service] || entry.service,
    resourcePath,
    actions: entry.actions.map((action) => ({
      key: actionKey(entry, action),
      action: action.slice(action.indexOf('/') + 1),
      ability: action,
      required: isRequiredAction(entry, action),
    })),
  };
}

export function entriesToAbilities(entries: RecapEntry[]): AbilitiesMap {
  const abilities: AbilitiesMap = {};

  for (const entry of entries) {
    abilities[entry.service] ??= {};
    const serviceAbilities = abilities[entry.service];
    if (!serviceAbilities) continue;
    serviceAbilities[entry.path] = entry.actions;
  }

  return abilities;
}

export function assertBaselineSubset(entries: RecapEntry[], baseline: AbilitiesMap) {
  if (entries.length === 0) {
    throw new Error('Only SIWE ReCap messages can be edited');
  }

  for (const entry of entries) {
    const serviceAbilities = baseline[entry.service];
    const allowedActions = serviceAbilities?.[entry.path];

    if (!allowedActions) {
      throw new Error('Edited permissions must be a subset of the original delegation request');
    }

    for (const action of entry.actions) {
      if (!allowedActions.includes(action)) {
        throw new Error('Edited permissions must be a subset of the original delegation request');
      }
    }
  }
}

export function assertDefaultSubset(entries: RecapEntry[]) {
  assertBaselineSubset(entries, DEFAULT_ABILITIES);
}

export function assertRequiredActions(entries: RecapEntry[]) {
  const hasRequiredCapabilitiesRead = entries.some(
    (entry) =>
      entry.service === 'capabilities' &&
      entry.actions.includes(CAPABILITIES.READ),
  );

  if (!hasRequiredCapabilitiesRead) {
    throw new Error('capabilities/read is required for this delegation');
  }
}

export function parsePreparedRecap(siwe: string): RecapEntry[] {
  return parseRecapFromSiwe(siwe) as RecapEntry[];
}

export function normalizeStringArray(value: unknown, name: string): string[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value)) {
    throw new Error(`${name} must be an array`);
  }
  if (!value.every((key): key is string => typeof key === 'string')) {
    throw new Error(`${name} must only contain strings`);
  }
  return [...new Set(value)];
}

export function entriesForSelectedActions(
  entries: RecapEntry[],
  selectedActionKeys: Set<string>,
): RecapEntry[] {
  const selectedEntries: RecapEntry[] = [];

  for (const entry of entries) {
    const actions = entry.actions.filter((action) =>
      selectedActionKeys.has(actionKey(entry, action)),
    );
    if (actions.length > 0) {
      selectedEntries.push({ ...entry, actions });
    }
  }

  return selectedEntries;
}

function isRawEncryptionPermission(
  entry: Pick<DelegationPermissionEntry, 'service' | 'path'>,
): boolean {
  return (
    entry.service === 'tinycloud.encryption' &&
    entry.path.startsWith('urn:tinycloud:encryption:')
  );
}

/**
 * Translate a list of permission entries into the `abilities` map shape that
 * `prepareSession()` expects. Keys are short service names (`kv`, `sql`,
 * `hooks`, …), values are `path → actions[]`. Actions are kept fully-qualified
 * (`tinycloud.sql/read`) because the SIWE recap stores them that way.
 */
export function abilitiesFromPermissions(
  permissions: DelegationPermissionEntry[],
): AbilitiesMap {
  const abilities: AbilitiesMap = {};
  for (const entry of permissions) {
    const short = shortServiceName(entry.service);
    if (!short) continue;
    const byPath = abilities[short] ?? (abilities[short] = {});
    const list = byPath[entry.path] ?? (byPath[entry.path] = []);
    for (const action of entry.actions) {
      if (!list.includes(action)) list.push(action);
    }
  }
  return abilities;
}

/**
 * Pull the space short-name out of the requested permissions. The CLI groups
 * its requests by space before calling /delegate, so a single delegation only
 * ever covers one space. We refuse mixed-space requests rather than silently
 * dropping caps.
 */
export function spacePrefixFromPermissions(
  permissions: DelegationPermissionEntry[],
): string {
  const spaces = new Set<string>();
  for (const permission of permissions) {
    if (isRawEncryptionPermission(permission)) continue;
    if (!permission.space) {
      throw new Error('non-raw permissions must include a space');
    }
    spaces.add(permission.space);
  }
  if (spaces.size !== 1) {
    throw new DelegateRequestError(
      'invalid_permissions',
      'permissions must belong to a single space',
      permissions.map((_permission, index) => ({
        path: `permissions[${index}].space`,
        message: 'All permissions must use the same space',
      })),
    );
  }
  const space = [...spaces][0]!;
  if (!space.startsWith('tinycloud:')) return space;
  return space.slice(space.lastIndexOf(':') + 1);
}

export interface PrepareDelegationSessionInput {
  address: string;
  chainId: number;
  prefix: string;
  jwk: DelegationJwk;
  actionKeys?: string[];
  permissionKeys?: string[];
  /**
   * CLI-driven explicit capability request. When set, the prefix is derived
   * from the entries' space URI and abilities are built directly from the
   * entries rather than the DEFAULT_ABILITIES baseline. The CLI-supplied
   * permissions become the *baseline* for the same actionKeys/permissionKeys
   * narrowing the standard consent UI uses, so users can still trim a CLI
   * request before signing.
   */
  permissions?: DelegationPermissionEntry[];
  /** Pre-validated, clamped delegation lifetime in milliseconds. */
  expiryMs: number;
}

export interface PrepareDelegationSessionResult {
  prepared: ReturnType<typeof prepareSession>;
  permissions: PermissionOption[];
  selectedActionKeys: string[];
  edited: boolean;
  spaceId: string;
}

export function prepareDelegationSession({
  address,
  chainId,
  prefix,
  jwk,
  actionKeys,
  permissionKeys,
  permissions,
  expiryMs,
}: PrepareDelegationSessionInput): PrepareDelegationSessionResult {
  const isCliBaseline = permissions !== undefined;
  const effectivePrefix = isCliBaseline
    ? spacePrefixFromPermissions(permissions!)
    : prefix;
  const spaceId = makeSpaceId(address, chainId, effectivePrefix);

  const now = new Date();
  const expirationTime = new Date(now.getTime() + expiryMs);
  const baseConfig = {
    address,
    chainId,
    domain: SIWE_DOMAIN,
    issuedAt: now.toISOString(),
    expirationTime: expirationTime.toISOString(),
    spaceId,
    jwk,
  };

  const baselineAbilities = isCliBaseline
    ? abilitiesFromPermissions(permissions!)
    : DEFAULT_ABILITIES;

  const baselinePrepared = prepareSession({
    ...baseConfig,
    abilities: baselineAbilities,
  });
  const baselineEntries = parsePreparedRecap(baselinePrepared.siwe);

  if (baselineEntries.length === 0) {
    throw new Error('Only SIWE ReCap messages can be edited');
  }

  const permissionOptions = baselineEntries.map(permissionOption);
  const baselineActionKeys = new Set(
    baselineEntries.flatMap((entry) =>
      entry.actions.map((action) => actionKey(entry, action)),
    ),
  );
  const requiredActionKeys = baselineEntries.flatMap((entry) =>
    entry.actions
      .filter((action) => isRequiredAction(entry, action))
      .map((action) => actionKey(entry, action)),
  );
  const selectedKeys = actionKeys ?? (
    permissionKeys
      ? baselineEntries
          .filter((entry) => permissionKeys.includes(permissionKey(entry)))
          .flatMap((entry) => entry.actions.map((action) => actionKey(entry, action)))
      : [...baselineActionKeys]
  );
  const selectedActionKeys = new Set(selectedKeys);

  for (const key of selectedActionKeys) {
    if (!baselineActionKeys.has(key)) {
      throw new Error('Requested permissions are not available for this delegation');
    }
  }

  for (const key of requiredActionKeys) {
    selectedActionKeys.add(key);
  }

  if (selectedActionKeys.size === 0) {
    throw new Error('At least one permission is required');
  }

  const selectedEntries = entriesForSelectedActions(baselineEntries, selectedActionKeys);
  const selectedActionCount = selectedEntries.reduce(
    (count, entry) => count + entry.actions.length,
    0,
  );
  const edited = selectedActionCount < baselineActionKeys.size;
  const prepared = edited
    ? prepareSession({
        ...baseConfig,
        abilities: entriesToAbilities(selectedEntries),
      })
    : baselinePrepared;

  return {
    prepared,
    permissions: permissionOptions,
    selectedActionKeys: selectedEntries.flatMap((entry) =>
      entry.actions.map((action) => actionKey(entry, action)),
    ),
    edited,
    spaceId,
  };
}
