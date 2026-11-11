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
import { getAddress } from 'viem';
import { parseEncryptionResource } from '@openkey/capability-review';
import {
  DelegateRequestError,
  shortServiceName,
} from './delegate-validation';
import { logPermissionEntryUnknownFields } from '../log';
import { narrowSiwePreservingImmutable } from '../services/siwe-narrow';

export type DelegationJwk = { kty: string; crv: string; x: string };
export type AbilitiesMap = Record<string, Record<string, string[]>>;
export type SpaceAbilitiesMap = Record<string, AbilitiesMap>;
/** Top-level ReCap resources (not under the session space): `resource → actions[]`. */
export type RawAbilitiesMap = Record<string, string[]>;

/**
 * Space-scoped ReCap resources and top-level raw encryption resources.
 * The primary routing space is not an authority boundary.
 */
export interface SessionAbilities {
  spaceAbilities: SpaceAbilitiesMap;
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

export interface RequestedDelegationSpace {
  space: string;
  spaceId: string;
}

/** Enumerate the full request baseline, including spaces the owner later deselects. */
export function delegationSpaces(entries: RecapEntry[], baseline?: SessionAbilities): RequestedDelegationSpace[] {
  const signedSpaces = new Set(entries.filter(entry => !isRawRecapEntry(entry)).map(entry => entry.space));
  const ordered = baseline ? Object.keys(baseline.spaceAbilities) : [...signedSpaces];
  return ordered.map(spaceId => ({ space: spaceId.slice(spaceId.lastIndexOf(':') + 1), spaceId }));
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

export function defaultSessionAbilities(spaceId: string): SessionAbilities {
  return { spaceAbilities: { [spaceId]: DEFAULT_ABILITIES }, rawAbilities: Object.create(null) };
}

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

const RAW_ENCRYPTION_RESOURCE_PREFIX = 'urn:tinycloud:encryption:';

/**
 * How a signing response reports a ReCap entry to the consumer of the signed
 * session. The WASM ReCap parser splits a raw encryption resource
 * (`urn:tinycloud:encryption:…`) into `space: "encryption"`, `path: <urn>`.
 * The consumer (sdk-core `parseCanonicalRecapResource`) reads a resource that
 * does not start with `tinycloud:` as the `space` itself with no `path`, and
 * checks both `selectedActionKeys` and `permissions` in that form. Every other
 * entry is returned unchanged. Only the final /authorize-sign response uses
 * this: the preview and the action ids the window sends keep the parser's form.
 */
export function reportedEntry(entry: RecapEntry): RecapEntry {
  if (entry.space !== 'encryption' || !entry.path.startsWith(RAW_ENCRYPTION_RESOURCE_PREFIX)) return entry;
  return { ...entry, space: entry.path, path: '' };
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
  const spaceAbilities: SpaceAbilitiesMap = Object.create(null);
  const rawAbilities: RawAbilitiesMap = Object.create(null);

  for (const entry of entries) {
    if (isRawRecapEntry(entry)) {
      addActions(rawAbilities, entry.path, entry.actions);
      continue;
    }
    if (!Object.hasOwn(spaceAbilities, entry.space)) spaceAbilities[entry.space] = Object.create(null);
    const abilities = spaceAbilities[entry.space]!;
    const service = shortServiceName(entry.service);
    if (!Object.hasOwn(abilities, service)) abilities[service] = Object.create(null);
    addActions(abilities[service]!, entry.path, entry.actions);
  }

  return { spaceAbilities, rawAbilities };
}

/** The WASM per-space builder, including raw resources when present. */
export function sessionAbilitiesConfig({ spaceAbilities, rawAbilities }: SessionAbilities) {
  return { abilities: {}, spaceAbilities, ...(Object.keys(rawAbilities).length > 0 ? { rawAbilities } : {}) };
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
      const abilities = Object.hasOwn(baseline.spaceAbilities, entry.space) ? baseline.spaceAbilities[entry.space] : undefined;
      const service = shortServiceName(entry.service);
      const serviceAbilities = abilities && Object.hasOwn(abilities, service) ? abilities[service] : undefined;
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


/**
 * capabilities/read is required only when the request baseline grants it:
 * the user may not uncheck it from the default consent set or from a CLI
 * request that asked for it. A CLI request that did not ask for it (for
 * example `tc secrets list`, TC-658) must not need it; the CLI refuses any
 * grant it did not request, and the node does not need it to activate a
 * session.
 */
export function assertRequiredActions(entries: RecapEntry[], baseline: SessionAbilities) {
  for (const [space, abilities] of Object.entries(baseline.spaceAbilities)) {
    const capabilities = Object.hasOwn(abilities, 'capabilities') ? abilities.capabilities : undefined;
    for (const [path, actions] of Object.entries(capabilities ?? {})) {
      if (!actions.includes(CAPABILITIES.READ)) continue;
      const retained = entries.some(entry =>
        entry.space === space &&
        shortServiceName(entry.service) === 'capabilities' &&
        entry.path === path &&
        entry.actions.includes(CAPABILITIES.READ),
      );
      if (!retained) throw new Error('capabilities/read is required for this delegation');
    }
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

/** Entry fields this validator reads. Any other defined field is dropped and reported by name. */
const PERMISSION_ENTRY_FIELDS: Record<string, true> = {
  service: true, space: true, path: true, actions: true, caveats: true, expiry: true, expiryMs: true,
};

/**
 * Refusal messages for narrowing fields this approval cannot carry. Each names the field and the
 * entry index only, never a value.
 */
const PERMISSION_ENTRY_REFUSAL = {
  caveats: (index: number) =>
    `permissions[${index}] includes a limit (caveats) that this approval can't carry, so a request that needs the limit can't be made this way. Nothing was approved.`,
  expiry: (index: number) =>
    `permissions[${index}] sets its own expiry (expiry). Set one expiry for the whole request instead. Nothing was approved.`,
  expiryMs: (index: number) =>
    `permissions[${index}] sets its own expiry (expiryMs). Set one expiry for the whole request instead. Nothing was approved.`,
};

/**
 * Validates the CLI `permissions[]` array. Narrowing fields this approval cannot carry (`caveats`
 * with restrictions, per-entry `expiry` / `expiryMs`) are refused with an error. Other unknown
 * entry fields are dropped; their names are logged, capped per request (see
 * `logPermissionEntryUnknownFields`). Nothing is logged for a refused request.
 */
export function validatePermissions(permissions: unknown): DelegationPermissionEntry[] {
  if (!Array.isArray(permissions) || permissions.length === 0) {
    throw new Error('permissions must be a non-empty array');
  }
  const unknownFields = new Map<string, number>();
  const entries = permissions.map((entry, index) => {
    if (!entry || typeof entry !== 'object') {
      throw new Error(`permissions[${index}] is not an object`);
    }
    const e = entry as Record<string, unknown>;
    if (typeof e.service !== 'string' || !e.service) {
      throw new Error(`permissions[${index}].service is required`);
    }
    const isRawEncryption = isRawEncryptionPermission(e);
    if (!isRawEncryption && (typeof e.space !== 'string' || !e.space)) {
      throw new Error(`permissions[${index}].space is required`);
    }
    if (e.space !== undefined && typeof e.space !== 'string') {
      throw new Error(`permissions[${index}].space must be a string`);
    }
    if (typeof e.path !== 'string') {
      throw new Error(`permissions[${index}].path must be a string`);
    }
    if (!Array.isArray(e.actions) || e.actions.some((a) => typeof a !== 'string')) {
      throw new Error(`permissions[${index}].actions must be a string[]`);
    }
    const caveatsRestrictNothing =
      e.caveats === undefined ||
      (Array.isArray(e.caveats) &&
        e.caveats.every((c) => c !== null && typeof c === 'object' && !Array.isArray(c) && Object.keys(c).length === 0));
    if (!caveatsRestrictNothing) {
      throw new Error(PERMISSION_ENTRY_REFUSAL.caveats(index));
    }
    if (e.expiry !== undefined) {
      throw new Error(PERMISSION_ENTRY_REFUSAL.expiry(index));
    }
    if (e.expiryMs !== undefined) {
      throw new Error(PERMISSION_ENTRY_REFUSAL.expiryMs(index));
    }
    for (const key of Object.keys(e)) {
      if (e[key] !== undefined && !Object.hasOwn(PERMISSION_ENTRY_FIELDS, key)) {
        unknownFields.set(key, (unknownFields.get(key) ?? 0) + 1);
      }
    }
    return {
      service: e.service,
      ...(typeof e.space === 'string' ? { space: e.space } : {}),
      path: e.path,
      actions: e.actions as string[],
    };
  });
  logPermissionEntryUnknownFields(unknownFields);
  return entries;
}

const RAW_ENCRYPTION_NETWORK = /^urn:tinycloud:encryption:did:pkh:eip155:(\d+):(0x[0-9a-fA-F]{40}):([^:]*)$/;
// The network-name rule of the TinyCloud SDK (`sdk-services` NETWORK_NAME_RE).
const ENCRYPTION_NETWORK_NAME = /^[a-z0-9][a-z0-9-]*$/;
// The one key folder a raw entry may name besides a bare network: the `share/` folder of the signer's own
// network (the CLI's `builtin:share-publishing` manifest, TC-2349). Exactly this suffix, nothing after it.
const SHARE_KEY_FOLDER_SUFFIX = '/share/';

/**
 * A raw encryption entry carries no space (`space` absent or `encryption`),
 * grants only `tinycloud.encryption/decrypt`, and names a network the signer
 * owns, that network's `share/` folder, or one exact `default/share/<id>` key.
 * Bare networks retain their case-insensitive owner check. Named resources
 * require canonical owner bytes and a network name of at most 64 characters.
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
  const tail = network[3]!;
  const isShareFolder = tail.endsWith(SHARE_KEY_FOLDER_SUFFIX);
  const networkName = isShareFolder ? tail.slice(0, -SHARE_KEY_FOLDER_SUFFIX.length) : tail;
  const key = !isShareFolder && tail.includes('/') ? parseEncryptionResource(entry.path) : null;
  const isShareLeaf = key !== null && key.kind === 'key' && key.network === 'default' &&
    /^share\/[^/]+$/.test(key.keyPath) &&
    entry.path === `${RAW_ENCRYPTION_PREFIX}${key.ownerDid}:default/${key.keyPath}`;
  if (isShareFolder || isShareLeaf) {
    if (network[2] !== getAddress(signer.address)) {
      throw new DelegateRequestError(
        'invalid_permissions',
        `permissions[${index}].path must use the canonical owner DID for a named encryption resource`,
        [{ path: `permissions[${index}].path`, message: 'Expected the canonical signing account DID', value: entry.path }],
      );
    }
    const namedNetwork = isShareLeaf ? key!.network : networkName;
    if (namedNetwork.length > 64) {
      throw new DelegateRequestError(
        'invalid_permissions',
        `permissions[${index}].path names an encryption network longer than 64 characters`,
        [{ path: `permissions[${index}].path`, message: 'Named encryption networks have at most 64 characters', value: entry.path }],
      );
    }
  }
  if (!ENCRYPTION_NETWORK_NAME.test(networkName) && !isShareLeaf) {
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

// Share invitation key entries OpenKey built itself (TC-2234). A requester's own entries are never in this set, so
// a request that names a `default/share/<id>` key is held to the decrypt-only rule above.
const issuedShareInvitationEntries = new WeakSet<DelegationPermissionEntry>();
const SHARE_INVITATION_KEY_ACTIONS = ['tinycloud.encryption/key.create', ENCRYPTION.DECRYPT];

/**
 * The one permission of a share invitation approval: `key.create` and `decrypt` on the share key `path`, which
 * OpenKey generated. Only entries made here may carry `key.create` on a raw encryption resource.
 */
export function issuedShareInvitationPermission(path: string): DelegationPermissionEntry {
  const entry = { service: RAW_ENCRYPTION_SERVICE, path, actions: [...SHARE_INVITATION_KEY_ACTIONS] };
  issuedShareInvitationEntries.add(entry);
  return entry;
}

/** The issued entry is the request's only permission and names the signer's own `default/share/<32 hex>` key. */
function assertShareInvitationPermission(
  entry: DelegationPermissionEntry,
  count: number,
  signer: { address: string; chainId: number },
) {
  const owner = `did:pkh:eip155:${signer.chainId}:${getAddress(signer.address)}`;
  if (
    count !== 1 ||
    entry.space !== undefined ||
    !new RegExp(`^${RAW_ENCRYPTION_PREFIX}${owner}:default/share/[0-9a-f]{32}$`).test(entry.path) ||
    entry.actions.length !== SHARE_INVITATION_KEY_ACTIONS.length ||
    entry.actions.some((action, index) => action !== SHARE_INVITATION_KEY_ACTIONS[index])
  ) {
    throw new DelegateRequestError('invalid_permissions', 'A share invitation approval grants one new share key only');
  }
}

/** Service name of the device authorization encryption entry, exact on the wire. */
const DEVICE_ENCRYPTION_SERVICE = 'tinycloud.encryption';
/** Space name of the approving account's own default encryption network. */
const DEVICE_ENCRYPTION_SPACE = 'default';

/**
 * URN of the signer's own `default` encryption network. Single producer for the
 * device entry; owner DID uses the signer's chain and EIP-55 address.
 */
export function defaultEncryptionNetworkUrn(signer: { address: string; chainId: number }): string {
  return `${RAW_ENCRYPTION_PREFIX}did:pkh:eip155:${signer.chainId}:${getAddress(signer.address)}:default`;
}

/**
 * The exact device authorization encryption entry: service `tinycloud.encryption`,
 * space `default`, path `""`, and only the decrypt action. Any other entry keeps
 * its existing handling.
 */
export function isDeviceDefaultEncryptionEntry(entry: DelegationPermissionEntry): boolean {
  return (
    entry.service === DEVICE_ENCRYPTION_SERVICE &&
    entry.space === DEVICE_ENCRYPTION_SPACE &&
    entry.path === '' &&
    entry.actions.length === 1 &&
    entry.actions[0] === ENCRYPTION.DECRYPT
  );
}

/**
 * Translate CLI permission entries into the ability maps `prepareSession()`
 * signs. Space abilities are keyed by short service name (`kv`, `sql`, …),
 * then `path → actions[]`; raw encryption entries become top-level
 * `rawAbilities` keyed by network URN, after checking the signer owns the
 * network. Actions stay fully-qualified (`tinycloud.sql/read`) because the
 * SIWE recap stores them that way.
 *
 * With `deviceTransaction`, the exact default encryption entry (see
 * `isDeviceDefaultEncryptionEntry`) resolves to the signer's own default
 * network. Every other entry is handled as before.
 */
export function sessionAbilitiesFromPermissions(
  permissions: DelegationPermissionEntry[],
  signer: { address: string; chainId: number },
  options: { deviceTransaction?: boolean } = {},
): SessionAbilities {
  const entries: RecapEntry[] = [];
  const rawAbilities: RawAbilitiesMap = Object.create(null);
  let deviceDefaultSeen = false;
  permissions.forEach((entry, index) => {
    if (options.deviceTransaction && isDeviceDefaultEncryptionEntry(entry)) {
      if (deviceDefaultSeen) {
        throw new DelegateRequestError(
          'invalid_permissions',
          `permissions[${index}] repeats the default encryption entry; a device request carries one`,
          [{ path: `permissions[${index}]`, message: 'Only one default encryption entry is allowed' }],
        );
      }
      deviceDefaultSeen = true;
      addActions(rawAbilities, defaultEncryptionNetworkUrn(signer), [ENCRYPTION.DECRYPT]);
      return;
    }
    if (issuedShareInvitationEntries.has(entry)) {
      assertShareInvitationPermission(entry, permissions.length, signer);
      addActions(rawAbilities, entry.path, entry.actions);
      return;
    }
    if (isRawEncryptionPermission(entry)) {
      assertRawEncryptionPermission(entry, index, signer);
      addActions(rawAbilities, entry.path, entry.actions);
      return;
    }
    const short = shortServiceName(entry.service);
    if (!short) return;
    entries.push({ service: short, space: resolvePermissionSpace(entry.space!, signer), path: entry.path, actions: entry.actions });
  });
  const scoped = entriesToSessionAbilities(entries);
  return { spaceAbilities: scoped.spaceAbilities, rawAbilities };
}

/** Logical names resolve only to the selected signing account; qualified names must already name it. */
export function resolvePermissionSpace(space: string, signer: { address: string; chainId: number }): string {
  if (!space) throw new Error('non-raw permissions must include a space');
  if (!space.startsWith('tinycloud:')) return makeSpaceId(signer.address, signer.chainId, space);
  const pkh = /^tinycloud:pkh:eip155:([1-9][0-9]*):(0x[0-9a-fA-F]{40}):([^:/]+)$/.exec(space);
  if (!pkh || pkh[1] !== String(signer.chainId) || pkh[2]!.toLowerCase() !== signer.address.toLowerCase()) {
    throw new DelegateRequestError('invalid_permissions', 'Requested spaces must belong to the signing account');
  }
  return makeSpaceId(signer.address, signer.chainId, pkh[3]!);
}

/** Prefer applications for routing; otherwise preserve the request's first resolved space. */
export function primaryRoutingSpace(spaceIds: string[], fallback: string): string {
  return spaceIds.find(space => space.endsWith(':applications')) ?? spaceIds[0] ?? fallback;
}

export interface PrepareDelegationSessionInput {
  address: string;
  chainId: number;
  prefix: string;
  jwk: DelegationJwk;
  actionKeys?: string[];
  permissionKeys?: string[];
  /**
   * CLI-driven explicit capability request. Every logical space resolves to
   * the signing account and becomes a separate per-space ability baseline.
   * Raw encryption entries remain top-level ReCap resources. Users can trim
   * the baseline through the same actionKeys/permissionKeys consent controls.
   */
  permissions?: DelegationPermissionEntry[];
  /**
   * Device authorization context. Only then does the exact default encryption
   * entry resolve to the signer's own network.
   */
  deviceTransaction?: boolean;
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
  requestedSpaces: RequestedDelegationSpace[];
}

export function prepareDelegationSession({
  address,
  chainId,
  prefix,
  jwk,
  actionKeys,
  permissionKeys,
  permissions,
  deviceTransaction,
  expiryMs,
  domain,
  nonce,
  issuedAt,
}: PrepareDelegationSessionInput): PrepareDelegationSessionResult {
  const isCliBaseline = permissions !== undefined;
  const fallbackSpaceId = makeSpaceId(address, chainId, prefix);
  const baselineAbilities = isCliBaseline
    ? sessionAbilitiesFromPermissions(permissions!, { address, chainId }, { deviceTransaction })
    : defaultSessionAbilities(fallbackSpaceId);
  const spaceId = primaryRoutingSpace(Object.keys(baselineAbilities.spaceAbilities), fallbackSpaceId);

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
  let prepared = baselinePrepared;
  if (edited) {
    const narrowed = narrowSiwePreservingImmutable({
      originalSiwe: baselinePrepared.siwe,
      narrowedEntries: selectedEntries,
      ...baseConfig,
    });
    if (!narrowed.ok) throw new Error(narrowed.message);
    prepared = { ...baselinePrepared, siwe: narrowed.siwe };
  }

  return {
    prepared,
    permissions: permissionOptions,
    selectedActionKeys: selectedEntries.flatMap((entry) =>
      entry.actions.map((action) => actionKey(entry, action)),
    ),
    edited,
    spaceId,
    baselineAbilities,
    requestedSpaces: delegationSpaces(selectedEntries, baselineAbilities),
  };
}
