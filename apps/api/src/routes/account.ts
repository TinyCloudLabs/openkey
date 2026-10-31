// Account management routes
import { Hono } from 'hono';
import { createPrismaClient } from '@openkey/db';
import { requireSession, type SessionContext } from '../middleware/session';
import { parseAutoSignPreferencePatch } from './account-preferences';
import { TINYCLOUD_DELEGATION_SCOPE, TINYCLOUD_MANAGE_KEY_SCOPE, TINYCLOUD_MCP_SCOPE } from '../oauth-config';
import {
  changeTinyCloudManageKeyGrant,
  changeTinyCloudManageKeyMode,
  controlMutationError,
} from '../services/tinycloud-manage-key-control';
import { requireOpenKeyOriginForBearer } from '../middleware/bearer-origin';
import { requireFreshPasskey } from '../services/passkey-freshness';
import { rejectNonBrowserControlRequest } from '../middleware/browser-control';
import { nativeDelegationLockResponse } from '../services/native-delegation/errors';
import { personalKeyWhere } from '../services/primary-key';

const prisma = createPrismaClient();

export const accountRouter = new Hono<SessionContext>();

// All routes require authentication. A bearer session token is accepted only
// from an OpenKey web origin (TC-688).
accountRouter.use('*', requireOpenKeyOriginForBearer);
accountRouter.use('*', requireSession);

// Account deletion needs a passkey verification on this session within the
// last five minutes (TC-689).
const ACCOUNT_DELETE_PASSKEY_MAX_AGE_MS = 5 * 60 * 1000;

// Get account info
accountRouter.get('/', async (c) => {
  const user = c.get('user');

  const userData = await prisma.user.findUnique({
    where: { id: user.id },
    select: {
      id: true,
      email: true,
      name: true,
      emailVerified: true,
      autoSignEnabled: true,
      tinyCloudManageKeyEnabled: true,
      createdAt: true,
      _count: {
        select: {
          ethereumKeys: { where: { archivedAt: null } },
          passkeys: true,
        },
      },
    },
  });

  return c.json({ user: userData });
});

// Global stop control for OAuth tinycloud:manage-key signing. This is kept
// separate from Auto-Sign, which controls the fixed bootstrap allowlist.
accountRouter.get('/tinycloud-manage-key', async (c) => {
  const user = c.get('user');
  const preference = await prisma.user.findUnique({
    where: { id: user.id },
    select: { tinyCloudManageKeyEnabled: true, tinyCloudManageKeyMode: true, tinyCloudManageKeyPolicyEpoch: true },
  });
  if (!preference) return c.json({ error: 'User not found' }, 404);
  return c.json({
    tinyCloudManageKeyEnabled: preference.tinyCloudManageKeyEnabled,
    mode: preference.tinyCloudManageKeyMode,
    policyEpoch: Number(preference.tinyCloudManageKeyPolicyEpoch),
  });
});

accountRouter.patch('/tinycloud-manage-key', async (c) => {
  const user = c.get('user');
  const rejected = rejectNonBrowserControlRequest(c);
  if (rejected) return rejected;
  let body: unknown;
  try {
    body = await c.req.json();
  } catch (error) {
    return c.json({ error: error instanceof Error ? error.message : 'Invalid request body' }, 400);
  }
  const error = controlMutationError(body);
  if (error) return c.json({ error }, 400);
  const patch = body as { mode: string; expectedEpoch: number };
  const result = await changeTinyCloudManageKeyMode(prisma, user.id, {
    mode: patch.mode as any, expectedEpoch: patch.expectedEpoch, request: body,
  });
  if (result.kind === 'not_found') return c.json({ error: 'User not found' }, 404);
  if (result.kind === 'stale') return c.json({ error: 'TinyCloud signing policy changed in another session', policyEpoch: result.epoch }, 409);
  if (result.kind === 'invalid_transition') return c.json({ error: 'TinyCloud signing cannot return to app-managed after you take control', policyEpoch: result.epoch }, 409);
  return c.json({ mode: result.mode, policyEpoch: result.epoch, tinyCloudManageKeyEnabled: result.mode !== 'USER_CONTROLLED_EXCLUSIVE' });
});

// Get Auto-Sign preference
accountRouter.get('/auto-sign', async (c) => {
  const user = c.get('user');

  const preference = await prisma.user.findUnique({
    where: { id: user.id },
    select: { autoSignEnabled: true },
  });

  if (!preference) {
    return c.json({ error: 'User not found' }, 404);
  }

  return c.json({ autoSignEnabled: preference.autoSignEnabled });
});

// Update Auto-Sign preference
accountRouter.patch('/auto-sign', async (c) => {
  const user = c.get('user');
  const rejected = rejectNonBrowserControlRequest(c);
  if (rejected) return rejected;
  let patch;

  try {
    patch = parseAutoSignPreferencePatch(await c.req.json());
  } catch (err) {
    return c.json({
      error: err instanceof Error ? err.message : 'Invalid request body',
    }, 400);
  }

  const preference = await prisma.user.update({
    where: { id: user.id },
    data: { autoSignEnabled: patch.autoSignEnabled },
    select: { autoSignEnabled: true },
  });

  return c.json({ autoSignEnabled: preference.autoSignEnabled });
});

// List apps with a TinyCloud signing or native delegation consent and the
// user's per-app stop control. The client is resolved from a consent, grant,
// preference or decision; callers cannot create preferences without consent.
accountRouter.get('/tinycloud-apps', async (c) => {
  const user = c.get('user');
  const [consents, preferences, decisions, userPreference, nativeGrants, mcpConsents] = await Promise.all([
    prisma.oauthConsent.findMany({
      where: { userId: user.id, OR: [{ scopes: { has: TINYCLOUD_MANAGE_KEY_SCOPE } }, { scopes: { has: TINYCLOUD_DELEGATION_SCOPE } }] },
      select: { clientId: true, scopes: true },
    }),
    prisma.tinyCloudManageKeyAppPreference.findMany({
      where: { userId: user.id },
      select: { clientId: true, enabled: true, status: true, clientNameSnapshot: true, clientUriSnapshot: true, consentWithdrawnAt: true },
    }),
    prisma.tinyCloudManageKeySigningDecision.findMany({
      where: { userId: user.id }, orderBy: { createdAt: 'desc' }, take: 20,
      select: { clientId: true, allowed: true, reason: true, policyEpoch: true, createdAt: true },
    }),
    prisma.user.findUnique({
      where: { id: user.id }, select: { tinyCloudManageKeyMode: true, tinyCloudManageKeyPolicyEpoch: true },
    }),
    prisma.tinyCloudNativeGrant.groupBy({ by: ['clientId'], where: { userId: user.id, status: 'ACTIVE' }, _count: { id: true } }),
    // MCP consents are listed separately; they never add entries to `apps`.
    prisma.oauthConsent.findMany({
      where: { userId: user.id, scopes: { has: TINYCLOUD_MCP_SCOPE } },
      orderBy: { createdAt: 'desc' },
      select: { id: true, clientId: true, scopes: true, createdAt: true },
    }),
  ]);
  const clientIds = [...new Set([
    ...consents.map((consent) => consent.clientId),
    ...preferences.map((preference) => preference.clientId),
    ...decisions.map((decision) => decision.clientId),
    ...nativeGrants.map((grant) => grant.clientId),
  ])];
  const clientLookupIds = [...new Set([...clientIds, ...mcpConsents.map((consent) => consent.clientId)])];
  const clients = clientLookupIds.length === 0 ? [] : await prisma.oauthClient.findMany({
    where: { clientId: { in: clientLookupIds } },
    select: { clientId: true, name: true, uri: true, icon: true, disabled: true },
  });
  const clientById = new Map(clients.map((client) => [client.clientId, client]));
  const consentIds = new Set(consents.map((consent) => consent.clientId));
  return c.json({
    apps: clientIds.map((clientId) => {
      const preference = preferences.find((candidate) => candidate.clientId === clientId);
      const client = clientById.get(clientId);
      const nativeDelegation = consents.some((consent) => consent.clientId === clientId && consent.scopes.includes(TINYCLOUD_DELEGATION_SCOPE));
      const blocked = preference?.enabled === false || preference?.status === 'DISABLED';
      return {
        kind: 'tinycloud' as const,
        clientId,
        name: client?.name || preference?.clientNameSnapshot || clientId,
        uri: client?.uri || preference?.clientUriSnapshot || null,
        icon: client?.icon || null,
        disabled: client?.disabled ?? true,
        nativeDelegation,
        activeNativeGrants: nativeGrants.find((grant) => grant.clientId === clientId)?._count.id ?? 0,
        enabled: nativeDelegation
          ? userPreference?.tinyCloudManageKeyMode !== 'USER_CONTROLLED_EXCLUSIVE' && consentIds.has(clientId) && !blocked
          : userPreference?.tinyCloudManageKeyMode === 'APP_MANAGED'
          ? consentIds.has(clientId) && !(preference?.enabled === false || preference?.status === 'DISABLED')
          : preference?.enabled === true && preference.status === 'ENABLED' && consentIds.has(clientId),
        status: consentIds.has(clientId) ? (preference?.status ?? (nativeDelegation ? 'ENABLED' : 'PENDING_USER_APPROVAL')) : 'CONSENT_WITHDRAWN',
      };
    }),
    mcpApps: mcpConsents.map((consent) => {
      const client = clientById.get(consent.clientId);
      return {
        kind: 'mcp' as const,
        consentId: consent.id,
        clientId: consent.clientId,
        name: client?.name || consent.clientId,
        uri: client?.uri || null,
        host: hostnameOf(client?.uri),
        icon: client?.icon || null,
        connectedAt: consent.createdAt.toISOString(),
        scopes: consent.scopes,
      };
    }),
    activity: decisions.map((decision) => {
      const client = clientById.get(decision.clientId);
      const preference = preferences.find((candidate) => candidate.clientId === decision.clientId);
      return {
        ...decision,
        clientName: client?.name || preference?.clientNameSnapshot || decision.clientId,
        policyEpoch: Number(decision.policyEpoch),
      };
    }),
    mode: userPreference?.tinyCloudManageKeyMode ?? 'APP_MANAGED',
    policyEpoch: Number(userPreference?.tinyCloudManageKeyPolicyEpoch ?? BigInt(0)),
  });
});

accountRouter.patch('/tinycloud-apps/:clientId', async (c) => {
  const user = c.get('user');
  const rejected = rejectNonBrowserControlRequest(c);
  if (rejected) return rejected;
  let body: unknown;
  try {
    body = await c.req.json();
  } catch (error) {
    return c.json({ error: error instanceof Error ? error.message : 'Invalid request body' }, 400);
  }
  if (!body || typeof body !== 'object' || Array.isArray(body)) return c.json({ error: 'Request body must be an object' }, 400);
  const patch = body as { enabled?: unknown; expectedEpoch?: unknown; confirmation?: unknown };
  if (typeof patch.enabled !== 'boolean' || !Number.isSafeInteger(patch.expectedEpoch) || (patch.expectedEpoch as number) < 0 || patch.confirmation !== 'TAKE CONTROL') {
    return c.json({ error: 'enabled, expectedEpoch, and typed confirmation "TAKE CONTROL" are required' }, 400);
  }
  const clientId = c.req.param('clientId');
  const result = await changeTinyCloudManageKeyGrant(prisma, user.id, clientId, {
    enabled: patch.enabled, expectedEpoch: patch.expectedEpoch as number, request: body,
  });
  if (result.kind === 'not_found') return c.json({ error: 'User not found' }, 404);
  if (result.kind === 'missing_consent') return c.json({ error: 'TinyCloud signing consent not found' }, 404);
  if (result.kind === 'stale') return c.json({ error: 'TinyCloud signing policy changed in another session', policyEpoch: result.epoch }, 409);
  return c.json({ clientId, enabled: result.grant.enabled, status: result.grant.status, policyEpoch: result.epoch });
});

// Disconnect withdraws the OAuth consent. The database withdrawal trigger
// increments its generation, revokes every native grant for this app, and
// deletes their tokens in the same transaction.
accountRouter.delete('/tinycloud-apps/:clientId', async (c) => {
  const rejected = rejectNonBrowserControlRequest(c);
  if (rejected) return rejected;
  const body = await c.req.json().catch(() => null) as { confirmation?: unknown } | null;
  if (body?.confirmation !== 'DISCONNECT') return c.json({ error: 'Type DISCONNECT to confirm' }, 400);
  const userId = c.get('user').id;
  const clientId = c.req.param('clientId');
  const removed = await prisma.oauthConsent.deleteMany({ where: {
    userId, clientId, scopes: { has: TINYCLOUD_DELEGATION_SCOPE },
  } });
  if (removed.count === 0) return c.json({ error: 'TinyCloud app consent not found' }, 404);
  return c.json({ clientId, disconnected: true });
});

// Disconnect an MCP app. The consent row is withdrawn exactly as in the delete
// above (the database trigger bumps the consent generation and revokes native
// grants and their tokens). The provider's refresh grant never re-checks
// consent, so this branch also deletes the user's access and refresh token rows
// for the client in the same transaction; the consent is unique per user and
// client. The consent is addressed by id, must belong to the signed-in user, and
// must carry the MCP scope.
accountRouter.delete('/tinycloud-apps/mcp/:consentId', async (c) => {
  const rejected = rejectNonBrowserControlRequest(c);
  if (rejected) return rejected;
  const body = await c.req.json().catch(() => null) as { confirmation?: unknown } | null;
  if (body?.confirmation !== 'DISCONNECT') return c.json({ error: 'Type DISCONNECT to confirm' }, 400);
  const userId = c.get('user').id;
  const consentId = c.req.param('consentId');
  const mine = { id: consentId, userId, scopes: { has: TINYCLOUD_MCP_SCOPE } };
  const disconnected = await prisma.$transaction(async (tx) => {
    const consent = await tx.oauthConsent.findFirst({ where: mine, select: { clientId: true } });
    if (!consent) return false;
    // Consent first, matching the trigger's lock order (consent, then tokens).
    const removed = await tx.oauthConsent.deleteMany({ where: mine });
    if (removed.count !== 1) return false;
    await tx.oauthAccessToken.deleteMany({ where: { userId, clientId: consent.clientId } });
    await tx.oauthRefreshToken.deleteMany({ where: { userId, clientId: consent.clientId } });
    return true;
  });
  if (!disconnected) return c.json({ error: 'Connected MCP app not found' }, 404);
  return c.json({ consentId, disconnected: true });
});

function hostnameOf(uri: string | null | undefined): string | null {
  if (!uri) return null;
  try { return new URL(uri).hostname || null; } catch { return null; }
}

// Delete account permanently
// Requires: cookie session from an OpenKey origin, a passkey verification on
// this session within the last five minutes, and typed confirmation.
accountRouter.post('/delete', async (c) => {
  const user = c.get('user');
  const rejected = rejectNonBrowserControlRequest(c);
  if (rejected) return rejected;
  const stale = await requireFreshPasskey(c, ACCOUNT_DELETE_PASSKEY_MAX_AGE_MS, prisma);
  if (stale) return stale;
  const body = await c.req.json<{
    confirmation: string; // Must be "DELETE MY ACCOUNT"
  }>();

  // Verify typed confirmation
  if (body.confirmation !== 'DELETE MY ACCOUNT') {
    return c.json({
      error: 'Invalid confirmation',
      message: 'Please type "DELETE MY ACCOUNT" exactly to confirm',
    }, 400);
  }


  // Delete all user data in transaction. The OWNER check runs under the user
  // row lock. Only personal keys are deleted; ORG-custodied keys have no userId
  // and are not touched (TC-1518 D1).
  let result: { kind: 'deleted'; keysDeleted: number } | { kind: 'owner_grant' };
  try { result = await prisma.$transaction(async (tx) => {
    await tx.$queryRaw`SELECT id FROM "user" WHERE id = ${user.id} FOR UPDATE`;
    const activeOwnerGrants = await tx.keyGrant.count({
      where: { granteeUserId: user.id, role: 'OWNER', revokedAt: null },
    });
    if (activeOwnerGrants > 0) return { kind: 'owner_grant' as const };

    // Active ADMIN grants do not block deletion: revoke them and detach the grantee.
    // key_grants.granteeUserId is ON DELETE RESTRICT, so the user row cannot be
    // deleted while any grant still points at it.
    await tx.keyGrant.updateMany({
      where: { granteeUserId: user.id, role: 'ADMIN', revokedAt: null },
      data: { revokedAt: new Date(), revokedByUserId: user.id, granteeUserId: null },
    });
    // Grants revoked earlier still point at the user. Detach them too; revokedAt and
    // revokedByUserId stay, so the revocation record is kept without the grantee link.
    await tx.keyGrant.updateMany({
      where: { granteeUserId: user.id, revokedAt: { not: null } },
      data: { granteeUserId: null },
    });

    // Delete all ethereum keys (sealed blobs will be unrecoverable)
    const { count: keysDeleted } = await tx.ethereumKey.deleteMany({ where: personalKeyWhere(user.id) });

    // Delete all passkeys
    await tx.passkey.deleteMany({ where: { userId: user.id } });

    // Delete all sessions
    await tx.session.deleteMany({ where: { userId: user.id } });

    // Delete all accounts (OAuth)
    await tx.account.deleteMany({ where: { userId: user.id } });

    // Delete all verifications
    await tx.verification.deleteMany({ where: { userId: user.id } });

    // Finally delete the user
    await tx.user.delete({ where: { id: user.id } });
    return { kind: 'deleted' as const, keysDeleted };
  }); } catch (error) {
    const unavailable = nativeDelegationLockResponse(error);
    if (unavailable) return unavailable;
    throw error;
  }
  if (result.kind === 'owner_grant') {
    return c.json({
      error: 'Account owns an organization key',
      message: 'Accounts holding an active organization key grant cannot be deleted',
    }, 409);
  }

  return c.json({
    success: true,
    message: 'Account permanently deleted',
    keysDeleted: result.keysDeleted,
  });
});

// Email-confirmed account deletion is not implemented. Say so rather than
// claiming an email was sent (TC-689).
accountRouter.post('/delete/request', (c) => {
  return c.json({ error: 'Email-confirmed account deletion is not implemented' }, 501);
});
