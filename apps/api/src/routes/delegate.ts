// Delegate route - creates TinyCloud delegation for CLI auth flow
import { Hono } from 'hono';
import { createPrismaClient } from '@openkey/db';
import { createTeeClient, unseal } from '@openkey/tee';
import { requireSession, type SessionContext } from '../middleware/session';
import type { Hex } from 'viem';
import {
  prepareSession,
  completeSessionSetup,
  ensureEip55,
  makeSpaceId,
  parseRecapFromSiwe,
} from '@tinycloud/node-sdk-wasm';
import { activateSessionWithHost } from '@tinycloud/sdk-core';

const prisma = createPrismaClient();
const tee = createTeeClient();

export const delegateRouter = new Hono<SessionContext>();

// The SIWE domain identifies the requestor (the CLI), not the storage node
const SIWE_DOMAIN = 'cli.tinycloud.xyz';

// Require authentication
delegateRouter.use('*', requireSession);

// Default abilities (same as NodeUserAuthorization)
type DelegationJwk = { kty: string; crv: string; x: string };
type AbilitiesMap = Record<string, Record<string, string[]>>;

interface RecapEntry {
  service: string;
  space: string;
  path: string;
  actions: string[];
}

interface PermissionActionOption {
  key: string;
  action: string;
  ability: string;
  required: boolean;
}

interface PermissionOption {
  key: string;
  service: string;
  path: string;
  label: string;
  resourcePath: string;
  actions: PermissionActionOption[];
}

const DEFAULT_ABILITIES: AbilitiesMap = {
  kv: {
    '': [
      'tinycloud.kv/put',
      'tinycloud.kv/get',
      'tinycloud.kv/del',
      'tinycloud.kv/list',
      'tinycloud.kv/metadata',
    ],
  },
  sql: {
    '': [
      'tinycloud.sql/read',
      'tinycloud.sql/write',
      'tinycloud.sql/admin',
      'tinycloud.sql/export',
    ],
  },
  capabilities: {
    '': ['tinycloud.capabilities/read'],
  },
};

const SERVICE_LABELS: Record<string, string> = {
  kv: 'Key-Value Storage',
  sql: 'SQL Database',
  capabilities: 'Capabilities',
};

function permissionKey(entry: RecapEntry): string {
  return `${entry.service}\0${entry.space}\0${entry.path}`;
}

function actionKey(entry: RecapEntry, action: string): string {
  return `${permissionKey(entry)}\0${action}`;
}

function isRequiredAction(entry: RecapEntry, action: string): boolean {
  return entry.service === 'capabilities' && action === 'tinycloud.capabilities/read';
}

function permissionOption(entry: RecapEntry): PermissionOption {
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

function entriesToAbilities(entries: RecapEntry[]): AbilitiesMap {
  const abilities: AbilitiesMap = {};

  for (const entry of entries) {
    abilities[entry.service] ??= {};
    const serviceAbilities = abilities[entry.service];
    if (!serviceAbilities) continue;
    serviceAbilities[entry.path] = entry.actions;
  }

  return abilities;
}

function assertDefaultSubset(entries: RecapEntry[]) {
  if (entries.length === 0) {
    throw new Error('Only SIWE ReCap messages can be edited');
  }

  for (const entry of entries) {
    const serviceAbilities = DEFAULT_ABILITIES[entry.service];
    const allowedActions = serviceAbilities?.[entry.path];

    if (!allowedActions) {
      throw new Error('Edited permissions must be a subset of the default delegation');
    }

    for (const action of entry.actions) {
      if (!allowedActions.includes(action)) {
        throw new Error('Edited permissions must be a subset of the default delegation');
      }
    }
  }
}

function assertRequiredActions(entries: RecapEntry[]) {
  const hasRequiredCapabilitiesRead = entries.some(
    (entry) =>
      entry.service === 'capabilities' &&
      entry.actions.includes('tinycloud.capabilities/read')
  );

  if (!hasRequiredCapabilitiesRead) {
    throw new Error('capabilities/read is required for this delegation');
  }
}

function parsePreparedRecap(siwe: string): RecapEntry[] {
  const entries = parseRecapFromSiwe(siwe) as RecapEntry[];
  return entries;
}

function normalizeStringArray(value: unknown, name: string): string[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value)) {
    throw new Error(`${name} must be an array`);
  }
  if (!value.every((key): key is string => typeof key === 'string')) {
    throw new Error(`${name} must only contain strings`);
  }
  return [...new Set(value)];
}

function entriesForSelectedActions(entries: RecapEntry[], selectedActionKeys: Set<string>): RecapEntry[] {
  const selectedEntries: RecapEntry[] = [];

  for (const entry of entries) {
    const actions = entry.actions.filter((action) => selectedActionKeys.has(actionKey(entry, action)));
    if (actions.length > 0) {
      selectedEntries.push({ ...entry, actions });
    }
  }

  return selectedEntries;
}

function prepareDelegationSession({
  address,
  chainId,
  prefix,
  jwk,
  actionKeys,
  permissionKeys,
  permissions,
  expiryMs,
}: {
  address: string;
  chainId: number;
  prefix: string;
  jwk: DelegationJwk;
  actionKeys?: string[];
  permissionKeys?: string[];
  /**
   * CLI-driven explicit capability request. When set, the prefix is
   * derived from the entries' space URI, abilities are built directly
   * from the entries, and the baseline-trim path is bypassed entirely.
   * Mutually exclusive with `actionKeys`/`permissionKeys` editing.
   */
  permissions?: PermissionEntry[];
  /** Pre-validated, clamped delegation lifetime in milliseconds. */
  expiryMs: number;
}) {
  // CLI-driven path: build abilities + prefix from the explicit request,
  // skip the baseline (DEFAULT_ABILITIES → trim) flow that the
  // user-editable consent UI relies on.
  if (permissions !== undefined) {
    const cliPrefix = spacePrefixFromPermissions(permissions);
    const cliSpaceId = makeSpaceId(address, chainId, cliPrefix);
    const now = new Date();
    const expirationTime = new Date(now.getTime() + expiryMs);
    const prepared = prepareSession({
      address,
      chainId,
      domain: SIWE_DOMAIN,
      issuedAt: now.toISOString(),
      expirationTime: expirationTime.toISOString(),
      spaceId: cliSpaceId,
      jwk,
      abilities: abilitiesFromPermissions(permissions),
    });
    const entries = parsePreparedRecap(prepared.siwe);
    return {
      prepared,
      permissions: entries.map(permissionOption),
      selectedActionKeys: entries.flatMap((entry) =>
        entry.actions.map((action) => actionKey(entry, action)),
      ),
      edited: false,
      spaceId: cliSpaceId,
    };
  }

  const spaceId = makeSpaceId(address, chainId, prefix);

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

  const baselinePrepared = prepareSession({
    ...baseConfig,
    abilities: DEFAULT_ABILITIES,
  });
  const baselineEntries = parsePreparedRecap(baselinePrepared.siwe);

  if (baselineEntries.length === 0) {
    throw new Error('Only SIWE ReCap messages can be edited');
  }

  const permissionOptions = baselineEntries.map(permissionOption);
  const baselineActionKeys = new Set(
    baselineEntries.flatMap((entry) => entry.actions.map((action) => actionKey(entry, action)))
  );
  const requiredActionKeys = baselineEntries.flatMap((entry) =>
    entry.actions
      .filter((action) => isRequiredAction(entry, action))
      .map((action) => actionKey(entry, action))
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
  const selectedActionCount = selectedEntries.reduce((count, entry) => count + entry.actions.length, 0);
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
      entry.actions.map((action) => actionKey(entry, action))
    ),
    edited,
    spaceId,
  };
}

/**
 * A capability the CLI is asking us to grant. Mirrors `PermissionEntry`
 * from `@tinycloud/sdk-core` — duplicated here so this route doesn't pull
 * the WASM-heavy node-sdk surface just for a type.
 */
interface PermissionEntry {
  service: string;
  space?: string;
  path: string;
  actions: string[];
}

type AbilitiesMap = Record<string, Record<string, string[]>>;

/**
 * Translate a list of {@link PermissionEntry}s into the `abilities` map shape
 * that `prepareSession()` expects. Keys are short service names (`kv`, `sql`,
 * `hooks`, …), values are `path → actions[]`. Actions are kept fully-qualified
 * (`tinycloud.sql/read`) because the SIWE recap stores them that way.
 */
function abilitiesFromPermissions(permissions: PermissionEntry[]): AbilitiesMap {
  const abilities: AbilitiesMap = {};
  for (const entry of permissions) {
    const short = entry.service.startsWith('tinycloud.')
      ? entry.service.slice('tinycloud.'.length)
      : entry.service;
    if (!short) continue;
    const byPath = abilities[short] ?? (abilities[short] = {});
    const list = byPath[entry.path] ?? (byPath[entry.path] = []);
    for (const action of entry.actions) {
      if (!list.includes(action)) list.push(action);
    }
  }
  return abilities;
}

function isRawEncryptionPermission(entry: Pick<PermissionEntry, 'service' | 'path'>): boolean {
  return entry.service === 'tinycloud.encryption' &&
    entry.path.startsWith('urn:tinycloud:encryption:');
}

/**
 * Pull the space short-name out of the requested permissions. The CLI groups
 * its requests by space before calling /delegate, so a single delegation only
 * ever covers one space. We refuse mixed-space requests rather than silently
 * dropping caps.
 */
function spacePrefixFromPermissions(permissions: PermissionEntry[]): string {
  const spaces = new Set<string>();
  for (const permission of permissions) {
    if (isRawEncryptionPermission(permission)) continue;
    if (!permission.space) {
      throw new Error('non-raw permissions must include a space');
    }
    spaces.add(permission.space);
  }
  if (spaces.size !== 1) {
    throw new Error(
      `permissions must belong to a single space; got ${JSON.stringify([...spaces])}`,
    );
  }
  const [space] = [...spaces];
  if (!space.startsWith('tinycloud:')) return space;
  return space.slice(space.lastIndexOf(':') + 1);
}

/**
 * Default lifetime when callers don't specify one. Tuned to match the
 * client-side default in `@tinycloud/cli` so an agent can run unattended
 * for the same window whether it's signing locally or coming through
 * OpenKey.
 */
const DEFAULT_DELEGATION_EXPIRY_MS = 7 * 24 * 60 * 60 * 1000;
/**
 * Upper bound on caller-supplied expiry. Ten years is effectively "forever"
 * — calls that ask for more get clamped here. The constant exists primarily
 * to guard against integer overflow / silly inputs, not as a security policy
 * lever. Long-lived agents and API-token-style delegations are first-class
 * use cases; revocation, not expiry, is the right control for them.
 */
const MAX_DELEGATION_EXPIRY_MS = 10 * 365 * 24 * 60 * 60 * 1000;
const MIN_DELEGATION_EXPIRY_MS = 60 * 1000; // 1 minute

const MS_UNIT_FACTORS: Record<string, number> = {
  ms: 1,
  s: 1000,
  m: 60 * 1000,
  h: 60 * 60 * 1000,
  d: 24 * 60 * 60 * 1000,
  w: 7 * 24 * 60 * 60 * 1000,
};

/**
 * Parse a caller-provided expiry into a clamped ms count.
 *  - missing → default (7d)
 *  - number → treated as raw milliseconds
 *  - "604800000" → numeric milliseconds
 *  - "7d", "30m", "12h", "1w" → ms-format string (small subset of
 *    the popular `ms` package, inlined to avoid a new dep)
 *
 * Result is clamped to [MIN, MAX]. Bad input throws a 400-friendly Error.
 */
function resolveDelegationExpiryMs(input: unknown): number {
  if (input === undefined || input === null || input === '') {
    return DEFAULT_DELEGATION_EXPIRY_MS;
  }
  let raw: number;
  if (typeof input === 'number') {
    raw = input;
  } else if (typeof input === 'string') {
    const trimmed = input.trim();
    if (/^\d+$/.test(trimmed)) {
      raw = Number(trimmed);
    } else {
      const match = trimmed.match(/^(\d+(?:\.\d+)?)\s*(ms|s|m|h|d|w)$/i);
      if (!match) {
        throw new Error(`Invalid expiry "${input}" — use ms-format ("7d", "30m") or a millisecond integer.`);
      }
      const value = Number(match[1]);
      const factor = MS_UNIT_FACTORS[match[2].toLowerCase()];
      raw = value * factor;
    }
  } else {
    throw new Error(`expiry must be a string or number, got ${typeof input}`);
  }
  if (!Number.isFinite(raw) || raw <= 0) {
    throw new Error(`expiry must be a positive number, got ${input}`);
  }
  return Math.min(MAX_DELEGATION_EXPIRY_MS, Math.max(MIN_DELEGATION_EXPIRY_MS, raw));
}

function validatePermissions(permissions: unknown): PermissionEntry[] {
  if (!Array.isArray(permissions) || permissions.length === 0) {
    throw new Error('permissions must be a non-empty array');
  }
  return permissions.map((entry, index) => {
    if (!entry || typeof entry !== 'object') {
      throw new Error(`permissions[${index}] is not an object`);
    }
    const e = entry as Record<string, unknown>;
    if (typeof e.service !== 'string' || !e.service) {
      throw new Error(`permissions[${index}].service is required`);
    }
    const isRawEncryption = e.service === 'tinycloud.encryption' &&
      typeof e.path === 'string' &&
      e.path.startsWith('urn:tinycloud:encryption:');
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
    return {
      service: e.service,
      ...(typeof e.space === 'string' ? { space: e.space } : {}),
      path: e.path,
      actions: e.actions as string[],
    };
  });
}

/**
 * POST /api/delegate
 *
 * Creates a TinyCloud delegation for the CLI using a MANAGED key.
 * The server unseals the private key via TEE and signs the SIWE message.
 */
delegateRouter.post('/', async (c) => {
  const user = c.get('user');
  const body = await c.req.json<{
    keyId: string;
    jwk: DelegationJwk;
    host: string;
    prefix?: string;
    actionKeys?: unknown;
    permissionKeys?: unknown;
    permissions?: unknown;
    expiry?: unknown;
  }>();

  if (!body.keyId || !body.jwk || !body.host) {
    return c.json({ error: 'keyId, jwk, and host are required' }, 400);
  }

  const key = await prisma.ethereumKey.findFirst({
    where: { id: body.keyId, userId: user.id },
  });

  if (!key) {
    return c.json({ error: 'Key not found' }, 404);
  }

  if (key.keyType !== 'MANAGED') {
    return c.json({ error: 'Only managed keys can be used with this endpoint. Use /api/delegate/prepare + /api/delegate/complete for external keys.' }, 400);
  }

  if (!key.sealedBlob) {
    return c.json({ error: 'Key has no sealed data' }, 400);
  }

  // Unseal the private key
  const sealingKey = await tee.deriveKey(`openkey/user/${user.id}/keys`);
  const privateKey = await unseal(key.sealedBlob, sealingKey) as Hex;

  // Import viem account for signing
  const { createWalletFromPrivateKey } = await import('@openkey/tee');
  const account = createWalletFromPrivateKey(privateKey);

  const address = ensureEip55(key.address);
  const chainId = 1;
  const prefix = body.prefix || 'default';
  const host = body.host;
  let permissions: PermissionEntry[] | undefined;
  if (body.permissions !== undefined) {
    try {
      permissions = validatePermissions(body.permissions);
    } catch (err) {
      return c.json({ error: (err as Error).message }, 400);
    }
  }
  let expiryMs: number;
  try {
    expiryMs = resolveDelegationExpiryMs(body.expiry);
  } catch (err) {
    return c.json({ error: (err as Error).message }, 400);
  }
  let preparedResult: ReturnType<typeof prepareDelegationSession>;
  try {
    preparedResult = prepareDelegationSession({
      address,
      chainId,
      prefix,
      jwk: body.jwk,
      actionKeys: normalizeStringArray(body.actionKeys, 'actionKeys'),
      permissionKeys: normalizeStringArray(body.permissionKeys, 'permissionKeys'),
      permissions,
      expiryMs,
    });
  } catch (e) {
    return c.json({ error: e instanceof Error ? e.message : 'Failed to prepare delegation' }, 400);
  }

  const signature = await account.signMessage({
    message: preparedResult.prepared.siwe,
  });

  const session = completeSessionSetup({
    ...preparedResult.prepared,
    signature,
  });

  let hostActivated = false;
  try {
    const activationResult = await activateSessionWithHost(host, session.delegationHeader);
    hostActivated = activationResult.success;
    if (!hostActivated) {
      console.warn(`[Delegate] Session activation warning: ${activationResult.error}`);
    }
  } catch (e) {
    console.warn(`[Delegate] Session activation failed (host unreachable):`, e);
  }

  const ownerDid = `did:pkh:eip155:${chainId}:${address}`;

  return c.json({
    delegationHeader: session.delegationHeader,
    delegationCid: session.delegationCid,
    spaceId: preparedResult.spaceId,
    ownerDid,
    verificationMethod: session.verificationMethod,
    jwk: body.jwk,
    address,
    chainId,
    hostActivated,
    edited: preparedResult.edited,
    // Include the SIWE message so callers (CLI, web SDK) can persist it
    // alongside the delegation. The SDK extracts `expirationTime` from
    // this string at session-restore time; without it, restored sessions
    // are treated as expired-at-epoch-zero.
    siwe: preparedResult.prepared.siwe,
  });
});

/**
 * POST /api/delegate/prepare
 *
 * Prepares a SIWE delegation message for an external key to sign.
 * Returns the SIWE message and prepared session data. The client
 * signs the SIWE message with their browser wallet, then calls
 * POST /api/delegate/complete with the signature.
 */
delegateRouter.post('/prepare', async (c) => {
  const user = c.get('user');
  const body = await c.req.json<{
    keyId: string;
    jwk: DelegationJwk;
    host: string;
    prefix?: string;
    actionKeys?: unknown;
    permissionKeys?: unknown;
    permissions?: unknown;
    expiry?: unknown;
  }>();

  if (!body.keyId || !body.jwk || !body.host) {
    return c.json({ error: 'keyId, jwk, and host are required' }, 400);
  }

  const key = await prisma.ethereumKey.findFirst({
    where: { id: body.keyId, userId: user.id },
  });

  if (!key) {
    return c.json({ error: 'Key not found' }, 404);
  }

  const address = ensureEip55(key.address);
  const chainId = 1;
  const prefix = body.prefix || 'default';
  const host = body.host;
  let permissions: PermissionEntry[] | undefined;
  if (body.permissions !== undefined) {
    try {
      permissions = validatePermissions(body.permissions);
    } catch (err) {
      return c.json({ error: (err as Error).message }, 400);
    }
  }
  let expiryMs: number;
  try {
    expiryMs = resolveDelegationExpiryMs(body.expiry);
  } catch (err) {
    return c.json({ error: (err as Error).message }, 400);
  }
  let preparedResult: ReturnType<typeof prepareDelegationSession>;
  try {
    preparedResult = prepareDelegationSession({
      address,
      chainId,
      prefix,
      jwk: body.jwk,
      actionKeys: normalizeStringArray(body.actionKeys, 'actionKeys'),
      permissionKeys: normalizeStringArray(body.permissionKeys, 'permissionKeys'),
      permissions,
      expiryMs,
    });
  } catch (e) {
    return c.json({ error: e instanceof Error ? e.message : 'Failed to prepare delegation' }, 400);
  }

  const ownerDid = `did:pkh:eip155:${chainId}:${address}`;

  // Ensure JWK is preserved as a plain object through JSON round-trip.
  // The WASM prepareSession may return JWK as a special object that
  // doesn't serialize correctly, so we merge the original JWK back in.
  const preparedData = {
    ...preparedResult.prepared,
    jwk: body.jwk,
  };

  return c.json({
    prepared: preparedData,
    spaceId: preparedResult.spaceId,
    ownerDid,
    address,
    chainId,
    host,
    jwk: body.jwk,
    permissions: preparedResult.permissions,
    selectedActionKeys: preparedResult.selectedActionKeys,
    edited: preparedResult.edited,
  });
});

/**
 * POST /api/delegate/complete
 *
 * Completes a delegation using a wallet-signed SIWE message.
 * Takes the prepared session data from /prepare plus the signature,
 * calls completeSessionSetup, activates the session, and returns
 * the delegation data.
 */
delegateRouter.post('/complete', async (c) => {
  const user = c.get('user');
  const body = await c.req.json<{
    prepared: any;
    signature: string;
    host: string;
    jwk: DelegationJwk;
    edited?: boolean;
  }>();

  if (!body.prepared || !body.signature || !body.host || !body.jwk) {
    return c.json({ error: 'prepared, signature, host, and jwk are required' }, 400);
  }

  if (body.edited) {
    try {
      const entries = parsePreparedRecap(body.prepared.siwe || '');
      assertDefaultSubset(entries);
      assertRequiredActions(entries);
    } catch (e) {
      return c.json({ error: e instanceof Error ? e.message : 'Invalid edited permissions' }, 400);
    }
  }

  // Ensure JWK is a proper object with kty for WASM deserialization
  const session = completeSessionSetup({
    ...body.prepared,
    jwk: body.jwk,
    signature: body.signature,
  });

  let hostActivated = false;
  try {
    const activationResult = await activateSessionWithHost(body.host, session.delegationHeader);
    hostActivated = activationResult.success;
    if (!hostActivated) {
      console.warn(`[Delegate] Session activation warning: ${activationResult.error}`);
    }
  } catch (e) {
    console.warn(`[Delegate] Session activation failed (host unreachable):`, e);
  }

  // Extract address/chainId from the prepared data
  const address = body.prepared.address || '';
  const chainId = body.prepared.chainId || 1;
  const spaceId = body.prepared.spaceId || '';
  const ownerDid = `did:pkh:eip155:${chainId}:${address}`;

  return c.json({
    delegationHeader: session.delegationHeader,
    delegationCid: session.delegationCid,
    spaceId,
    ownerDid,
    verificationMethod: session.verificationMethod,
    jwk: body.jwk,
    address,
    chainId,
    hostActivated,
    edited: Boolean(body.edited),
    // Echo the SIWE the caller asked us to sign — the SDK extracts
    // `expirationTime` from this when restoring the session, and
    // without it a restored session is treated as expired-at-epoch-zero.
    siwe: body.prepared.siwe,
  });
});
