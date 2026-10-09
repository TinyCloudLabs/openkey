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
import { CAPABILITIES, ENCRYPTION, KV, SQL } from '@tinycloud/bootstrap';
import {
  DelegateRequestError,
  shortServiceName,
} from './delegate-validation';

export type DelegationJwk = { kty: string; crv: string; x: string };
export type AbilitiesMap = Record<string, Record<string, string[]>>;
/** Top-level ReCap resources (not under the session space): `resource → actions[]`. */
export type RawAbilitiesMap = Record<string, string[]>;

/**
 * The two ability maps `prepareSession` signs: `abilities` nests under the
 * session space, `rawAbilities` are top-level ReCap resources (raw
 * encryption networks, `urn:tinycloud:encryption:<ownerDid>:<name>`).
 */
export interface SessionAbilities {
  abilities: AbilitiesMap;
  rawAbilities: RawAbilitiesMap;
}

// `parseRecapFromSiwe` reports a top-level encryption resource with this
// space and the full network URN as its path.
export const RAW_ENCRYPTION_SPACE = 'encryption';
const RAW_ENCRYPTION_SERVICE = 'tinycloud.encryption';
const RAW_ENCRYPTION_PREFIX = 'urn:tinycloud:encryption:';

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

export const DEFAULT_SESSION_ABILITIES: SessionAbilities = {
  abilities: DEFAULT_ABILITIES,
  rawAbilities: Object.create(null),
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
    label: (Object.hasOwn(SERVICE_LABELS, entry.service) ? SERVICE_LABELS[entry.service] : undefined) || entry.service,
    resourcePath,
    actions: entry.actions.map((action) => ({
      key: actionKey(entry, action),
      action: action.slice(action.indexOf('/') + 1),
      ability: action,
      required: isRequiredAction(entry, action),
    })),
  };
}

// Ability maps are keyed by request-supplied services and paths (`constructor`,
// `__proto__`, ...), so they never inherit from Object.prototype.
function addActions(byResource: Record<string, string[]>, resource: string, actions: string[]) {
  if (!Object.hasOwn(byResource, resource)) byResource[resource] = [];
  const list = byResource[resource]!;
  for (const action of actions) {
    if (!list.includes(action)) list.push(action);
  }
}

/** A parsed ReCap entry for a top-level raw encryption resource. */
export function isRawRecapEntry(entry: RecapEntry): boolean {
  return (
    entry.space === RAW_ENCRYPTION_SPACE &&
    canonicalizeServiceName(entry.service) === RAW_ENCRYPTION_SERVICE &&
    entry.path.startsWith(RAW_ENCRYPTION_PREFIX)
  );
}

export function entriesToSessionAbilities(entries: RecapEntry[]): SessionAbilities {
  const abilities: AbilitiesMap = Object.create(null);
  const rawAbilities: RawAbilitiesMap = Object.create(null);

  for (const entry of entries) {
    if (isRawRecapEntry(entry)) {
      rawAbilities[entry.path] = entry.actions;
      continue;
    }
    if (!Object.hasOwn(abilities, entry.service)) abilities[entry.service] = Object.create(null);
    abilities[entry.service]![entry.path] = entry.actions;
  }

  return { abilities, rawAbilities };
}

/** `prepareSession` config fields; `rawAbilities` only when there are any. */
export function sessionAbilitiesConfig({ abilities, rawAbilities }: SessionAbilities): {
  abilities: AbilitiesMap;
  rawAbilities?: RawAbilitiesMap;
} {
  return Object.keys(rawAbilities).length > 0 ? { abilities, rawAbilities } : { abilities };
}

/**
 * Refuse any parsed ReCap entry the baseline does not grant. A raw entry is
 * matched only against the baseline's raw resources, so a request for a raw
 * network never admits the same URN nested under the session space (or the
 * reverse).
 */
export function assertBaselineSubset(entries: RecapEntry[], baseline: SessionAbilities) {
  if (entries.length === 0) {
    throw new Error('Only SIWE ReCap messages can be edited');
  }

  for (const entry of entries) {
    let allowedActions: string[] | undefined;
    if (isRawRecapEntry(entry)) {
      allowedActions = Object.hasOwn(baseline.rawAbilities, entry.path) ? baseline.rawAbilities[entry.path] : undefined;
    } else {
      const serviceAbilities = Object.hasOwn(baseline.abilities, entry.service) ? baseline.abilities[entry.service] : undefined;
      allowedActions = serviceAbilities && Object.hasOwn(serviceAbilities, entry.path) ? serviceAbilities[entry.path] : undefined;
    }

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
  assertBaselineSubset(entries, DEFAULT_SESSION_ABILITIES);
}

/**
 * capabilities/read is required only when the request baseline grants it:
 * the user may not uncheck it from the default consent set or from a CLI
 * request that asked for it. A CLI request that did not ask for it (for
 * example `tc secrets list`, TC-658) must not need it; the CLI refuses any
 * grant it did not request, and the node does not need it to activate a
 * session.
 */
export function assertRequiredActions(entries: RecapEntry[], baseline: SessionAbilities) {
  const baselineCapabilities = Object.hasOwn(baseline.abilities, 'capabilities')
    ? baseline.abilities.capabilities!
    : undefined;
  const baselineGrantsCapabilitiesRead = baselineCapabilities !== undefined &&
    Object.values(baselineCapabilities).some((actions) => actions.includes(CAPABILITIES.READ));
  if (!baselineGrantsCapabilitiesRead) return;

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

/**
 * A CLI permission for a top-level encryption network. The short service
 * name `encryption` is the same service, so it gets the same validation
 * rather than being nested under the session space.
 */
export function isRawEncryptionPermission(
  entry: { service?: unknown; path?: unknown },
): boolean {
  return (
    typeof entry.service === 'string' &&
    canonicalizeServiceName(entry.service) === RAW_ENCRYPTION_SERVICE &&
    typeof entry.path === 'string' &&
    entry.path.startsWith(RAW_ENCRYPTION_PREFIX)
  );
}

const RAW_ENCRYPTION_NETWORK = /^urn:tinycloud:encryption:did:pkh:eip155:(\d+):(0x[0-9a-fA-F]{40}):([^:]*)$/;
// The network-name rule of the TinyCloud SDK (`sdk-services` NETWORK_NAME_RE).
const ENCRYPTION_NETWORK_NAME = /^[a-z0-9][a-z0-9-]*$/;

/**
 * A raw encryption entry carries no space (`space` absent or `encryption`),
 * grants only `tinycloud.encryption/decrypt`, and names a network the signer
 * owns: the URN's owner DID must be the signer's
 * `did:pkh:eip155:<chainId>:<address>` (address case-insensitive) and the
 * network name must follow the SDK's naming rule.
 */
function assertRawEncryptionPermission(
  entry: DelegationPermissionEntry,
  index: number,
  signer: { address: string; chainId: number },
) {
  if (entry.space !== undefined && entry.space !== RAW_ENCRYPTION_SPACE) {
    throw new DelegateRequestError(
      'invalid_permissions',
      `permissions[${index}].space must be "${RAW_ENCRYPTION_SPACE}" or absent for a raw encryption network`,
      [{
        path: `permissions[${index}].space`,
        message: 'Raw encryption networks are not inside a space',
        value: entry.space,
        expected: RAW_ENCRYPTION_SPACE,
      }],
    );
  }
  if (entry.actions.length === 0) {
    throw new DelegateRequestError(
      'invalid_permissions',
      `permissions[${index}].actions must be ["${ENCRYPTION.DECRYPT}"] for a raw encryption network`,
      [{ path: `permissions[${index}].actions`, message: 'Expected the decrypt action', expected: ENCRYPTION.DECRYPT }],
    );
  }
  entry.actions.forEach((action, actionIndex) => {
    if (action !== ENCRYPTION.DECRYPT) {
      throw new DelegateRequestError(
        'invalid_permissions',
        `permissions[${index}].actions[${actionIndex}] is not available on a raw encryption network; only ${ENCRYPTION.DECRYPT} is`,
        [{
          path: `permissions[${index}].actions[${actionIndex}]`,
          message: 'Raw encryption networks grant decrypt only',
          value: action,
          expected: ENCRYPTION.DECRYPT,
        }],
      );
    }
  });
  const network = RAW_ENCRYPTION_NETWORK.exec(entry.path);
  if (
    !network ||
    network[1] !== String(signer.chainId) ||
    network[2]!.toLowerCase() !== signer.address.toLowerCase()
  ) {
    const signerDid = `did:pkh:eip155:${signer.chainId}:${signer.address}`;
    throw new DelegateRequestError(
      'invalid_permissions',
      `permissions[${index}].path must be an encryption network owned by the signer ${signerDid}`,
      [{
        path: `permissions[${index}].path`,
        message: 'The encryption network owner must be the signing account',
        value: entry.path,
        expectedPrefix: `${RAW_ENCRYPTION_PREFIX}${signerDid}:`,
      }],
    );
  }
  if (!ENCRYPTION_NETWORK_NAME.test(network[3]!)) {
    throw new DelegateRequestError(
      'invalid_permissions',
      `permissions[${index}].path names an invalid encryption network; the name must match ${ENCRYPTION_NETWORK_NAME.source}`,
      [{
        path: `permissions[${index}].path`,
        message: `The network name must match ${ENCRYPTION_NETWORK_NAME.source}`,
        value: entry.path,
      }],
    );
  }
}

/**
 * Translate CLI permission entries into the ability maps `prepareSession()`
 * signs. Space abilities are keyed by short service name (`kv`, `sql`, …),
 * then `path → actions[]`; raw encryption entries become top-level
 * `rawAbilities` keyed by network URN, after checking the signer owns the
 * network. Actions stay fully-qualified (`tinycloud.sql/read`) because the
 * SIWE recap stores them that way.
 */
export function sessionAbilitiesFromPermissions(
  permissions: DelegationPermissionEntry[],
  signer: { address: string; chainId: number },
): SessionAbilities {
  const abilities: AbilitiesMap = Object.create(null);
  const rawAbilities: RawAbilitiesMap = Object.create(null);
  permissions.forEach((entry, index) => {
    if (isRawEncryptionPermission(entry)) {
      assertRawEncryptionPermission(entry, index, signer);
      addActions(rawAbilities, entry.path, entry.actions);
      return;
    }
    const short = shortServiceName(entry.service);
    if (!short) return;
    if (!Object.hasOwn(abilities, short)) abilities[short] = Object.create(null);
    addActions(abilities[short]!, entry.path, entry.actions);
  });
  return { abilities, rawAbilities };
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
  // Ethereum addresses in `tinycloud:pkh` URIs are case-insensitive; chain
  // and space name stay exact (same rule as device authorization).
  const spaces = new Set<string>();
  for (const permission of permissions) {
    if (isRawEncryptionPermission(permission)) continue;
    if (!permission.space) {
      throw new Error('non-raw permissions must include a space');
    }
    const pkh = /^tinycloud:pkh:eip155:([^:]+):(0x[0-9a-fA-F]{40}):(.+)$/.exec(permission.space);
    spaces.add(pkh ? `tinycloud:pkh:eip155:${pkh[1]}:${pkh[2]!.toLowerCase()}:${pkh[3]}` : permission.space);
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
   * entries rather than the DEFAULT_ABILITIES baseline; raw encryption
   * entries are signed as top-level ReCap resources. The CLI-supplied
   * permissions become the *baseline* for the same actionKeys/permissionKeys
   * narrowing the standard consent UI uses, so users can still trim a CLI
   * request before signing.
   */
  permissions?: DelegationPermissionEntry[];
  /** Pre-validated, clamped delegation lifetime in milliseconds. */
  expiryMs: number;
  domain?: string;
  nonce?: string;
  issuedAt?: Date;
}

export interface PrepareDelegationSessionResult {
  prepared: ReturnType<typeof prepareSession>;
  permissions: PermissionOption[];
  selectedActionKeys: string[];
  edited: boolean;
  /** The request baseline the session was prepared from (before narrowing). */
  baselineAbilities: SessionAbilities;
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
  domain,
  nonce,
  issuedAt,
}: PrepareDelegationSessionInput): PrepareDelegationSessionResult {
  const isCliBaseline = permissions !== undefined;
  const effectivePrefix = isCliBaseline
    ? spacePrefixFromPermissions(permissions!)
    : prefix;
  const spaceId = makeSpaceId(address, chainId, effectivePrefix);

  const now = issuedAt ?? new Date();
  const expirationTime = new Date(now.getTime() + expiryMs);
  const baseConfig = {
    address,
    chainId,
    domain: domain ?? SIWE_DOMAIN,
    ...(nonce ? { nonce } : {}),
    issuedAt: now.toISOString(),
    expirationTime: expirationTime.toISOString(),
    spaceId,
    jwk,
  };

  const baselineAbilities = isCliBaseline
    ? sessionAbilitiesFromPermissions(permissions!, { address, chainId })
    : DEFAULT_SESSION_ABILITIES;

  const baselinePrepared = prepareSession({
    ...baseConfig,
    ...sessionAbilitiesConfig(baselineAbilities),
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
        ...sessionAbilitiesConfig(entriesToSessionAbilities(selectedEntries)),
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
    baselineAbilities,
  };
}
