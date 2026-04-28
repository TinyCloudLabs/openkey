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

interface PermissionOption {
  key: string;
  service: string;
  path: string;
  label: string;
  resourcePath: string;
  actions: string[];
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

function permissionOption(entry: RecapEntry): PermissionOption {
  const resourcePath = entry.path ? `${entry.service}/${entry.path}` : entry.service;
  return {
    key: permissionKey(entry),
    service: entry.service,
    path: entry.path,
    label: SERVICE_LABELS[entry.service] || entry.service,
    resourcePath,
    actions: entry.actions.map((action) => action.slice(action.indexOf('/') + 1)),
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

function parsePreparedRecap(siwe: string): RecapEntry[] {
  const entries = parseRecapFromSiwe(siwe) as RecapEntry[];
  return entries;
}

function normalizePermissionKeys(permissionKeys: unknown): string[] | undefined {
  if (permissionKeys === undefined) return undefined;
  if (!Array.isArray(permissionKeys)) {
    throw new Error('permissionKeys must be an array');
  }
  if (!permissionKeys.every((key): key is string => typeof key === 'string')) {
    throw new Error('permissionKeys must only contain strings');
  }
  return [...new Set(permissionKeys)];
}

function prepareDelegationSession({
  address,
  chainId,
  prefix,
  jwk,
  permissionKeys,
}: {
  address: string;
  chainId: number;
  prefix: string;
  jwk: DelegationJwk;
  permissionKeys?: string[];
}) {
  const spaceId = makeSpaceId(address, chainId, prefix);

  const now = new Date();
  const expirationTime = new Date(now.getTime() + 60 * 60 * 1000); // 1 hour
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
  const baselineKeys = new Set(permissionOptions.map((permission) => permission.key));
  const selectedKeys = permissionKeys ?? permissionOptions.map((permission) => permission.key);
  const selectedKeySet = new Set(selectedKeys);

  for (const key of selectedKeySet) {
    if (!baselineKeys.has(key)) {
      throw new Error('Requested permissions are not available for this delegation');
    }
  }

  if (selectedKeySet.size === 0) {
    throw new Error('At least one permission is required');
  }

  const selectedEntries = baselineEntries.filter((entry) => selectedKeySet.has(permissionKey(entry)));
  const edited = selectedEntries.length < baselineEntries.length;
  const prepared = edited
    ? prepareSession({
        ...baseConfig,
        abilities: entriesToAbilities(selectedEntries),
      })
    : baselinePrepared;

  return {
    prepared,
    permissions: permissionOptions,
    selectedPermissionKeys: selectedEntries.map(permissionKey),
    edited,
    spaceId,
  };
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
    permissionKeys?: unknown;
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
  let preparedResult: ReturnType<typeof prepareDelegationSession>;
  try {
    preparedResult = prepareDelegationSession({
      address,
      chainId,
      prefix,
      jwk: body.jwk,
      permissionKeys: normalizePermissionKeys(body.permissionKeys),
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

  const primaryDid = `did:pkh:eip155:${chainId}:${address}`;

  return c.json({
    delegationHeader: session.delegationHeader,
    delegationCid: session.delegationCid,
    spaceId: preparedResult.spaceId,
    primaryDid,
    verificationMethod: session.verificationMethod,
    jwk: body.jwk,
    address,
    chainId,
    hostActivated,
    edited: preparedResult.edited,
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
    permissionKeys?: unknown;
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
  let preparedResult: ReturnType<typeof prepareDelegationSession>;
  try {
    preparedResult = prepareDelegationSession({
      address,
      chainId,
      prefix,
      jwk: body.jwk,
      permissionKeys: normalizePermissionKeys(body.permissionKeys),
    });
  } catch (e) {
    return c.json({ error: e instanceof Error ? e.message : 'Failed to prepare delegation' }, 400);
  }

  const primaryDid = `did:pkh:eip155:${chainId}:${address}`;

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
    primaryDid,
    address,
    chainId,
    host,
    jwk: body.jwk,
    permissions: preparedResult.permissions,
    selectedPermissionKeys: preparedResult.selectedPermissionKeys,
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
      assertDefaultSubset(parsePreparedRecap(body.prepared.siwe || ''));
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
  const primaryDid = `did:pkh:eip155:${chainId}:${address}`;

  return c.json({
    delegationHeader: session.delegationHeader,
    delegationCid: session.delegationCid,
    spaceId,
    primaryDid,
    verificationMethod: session.verificationMethod,
    jwk: body.jwk,
    address,
    chainId,
    hostActivated,
    edited: Boolean(body.edited),
  });
});
