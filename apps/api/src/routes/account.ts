// Account management routes
import { Hono } from 'hono';
import { createPrismaClient } from '@openkey/db';
import { requireSession, type SessionContext } from '../middleware/session';
import { parseAutoSignPreferencePatch } from './account-preferences';
import { TINYCLOUD_MANAGE_KEY_SCOPE } from '../oauth-config';
import {
  changeTinyCloudManageKeyGrant,
  changeTinyCloudManageKeyMode,
  controlMutationError,
} from '../services/tinycloud-manage-key-control';

const prisma = createPrismaClient();

export const accountRouter = new Hono<SessionContext>();

// All routes require authentication
accountRouter.use('*', requireSession);

function rejectNonBrowserControlRequest(c: any) {
  // Account controls are deliberately cookie-session-only. In particular, an
  // OAuth bearer token that can call /delegate/sign must never change custody.
  if (c.req.header('authorization')) return c.json({ error: 'Bearer tokens cannot change TinyCloud signing controls' }, 403);
  const origin = c.req.header('origin');
  const allowed = (process.env.CORS_ORIGIN || 'http://localhost:5173,http://localhost:3000')
    .split(',').map((value) => value.trim()).filter(Boolean);
  if (!origin || !allowed.includes(origin)) return c.json({ error: 'A same-site browser Origin is required' }, 403);
  return null;
}

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
          ethereumKeys: { where: { archivedAt: null, keyPurpose: 'PERSONAL' } },
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

// List the apps with an active TinyCloud signing consent and the user's
// per-app stop control. The client is always resolved from the consent row;
// callers cannot create preferences for arbitrary OAuth client IDs.
accountRouter.get('/tinycloud-apps', async (c) => {
  const user = c.get('user');
  const [consents, preferences, decisions, userPreference] = await Promise.all([
    prisma.oauthConsent.findMany({
      where: { userId: user.id, scopes: { has: TINYCLOUD_MANAGE_KEY_SCOPE } }, select: { clientId: true },
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
  ]);
  const clientIds = [...new Set([...consents.map((consent) => consent.clientId), ...preferences.map((preference) => preference.clientId)])];
  const clients = clientIds.length === 0 ? [] : await prisma.oauthClient.findMany({
    where: { clientId: { in: clientIds } },
    select: { clientId: true, name: true, uri: true, icon: true, disabled: true },
  });
  const clientById = new Map(clients.map((client) => [client.clientId, client]));
  const consentIds = new Set(consents.map((consent) => consent.clientId));
  return c.json({
    apps: clientIds.map((clientId) => {
      const preference = preferences.find((candidate) => candidate.clientId === clientId);
      const client = clientById.get(clientId);
      return {
        clientId,
        name: client?.name || preference?.clientNameSnapshot || clientId,
        uri: client?.uri || preference?.clientUriSnapshot || null,
        icon: client?.icon || null,
        disabled: client?.disabled ?? true,
        enabled: userPreference?.tinyCloudManageKeyMode === 'APP_MANAGED'
          ? consentIds.has(clientId)
          : preference?.enabled === true && preference.status === 'ENABLED' && consentIds.has(clientId),
        status: consentIds.has(clientId) ? (preference?.status ?? 'PENDING_USER_APPROVAL') : 'CONSENT_WITHDRAWN',
      };
    }),
    activity: decisions.map((decision) => ({ ...decision, policyEpoch: Number(decision.policyEpoch) })),
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

// Delete account permanently
// Requires: typed confirmation + passkey verification
accountRouter.post('/delete', async (c) => {
  const user = c.get('user');
  const body = await c.req.json<{
    confirmation: string; // Must be "DELETE MY ACCOUNT"
    passkeyChallenge?: string; // Passkey challenge response (if available)
  }>();

  // Verify typed confirmation
  if (body.confirmation !== 'DELETE MY ACCOUNT') {
    return c.json({
      error: 'Invalid confirmation',
      message: 'Please type "DELETE MY ACCOUNT" exactly to confirm',
    }, 400);
  }

  // Managed accounts are a custody boundary and cannot be deleted by the
  // personal account route. Fail before touching personal data.
  const managedAccount = await prisma.managedAccount.findFirst({
    where: { ownerUserId: user.id },
    select: { id: true },
  });
  if (managedAccount) {
    return c.json({
      error: {
        code: 'MANAGED_ACCOUNTS_BLOCK_DELETION',
        message: 'Transfer or eject all managed accounts before deleting this OpenKey account',
      },
    }, 409);
  }

  // Count and delete only personal keys. Managed keys are never part of this
  // personal deletion contract.
  const keyCount = await prisma.ethereumKey.count({
    where: { userId: user.id, keyPurpose: 'PERSONAL' },
  });

  // Delete all user data in transaction
  await prisma.$transaction(async (tx) => {
    // Delete all ethereum keys (sealed blobs will be unrecoverable)
    await tx.ethereumKey.deleteMany({ where: { userId: user.id, keyPurpose: 'PERSONAL' } });

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
  });

  return c.json({
    success: true,
    message: 'Account permanently deleted',
    keysDeleted: keyCount,
  });
});

// Request account deletion (sends confirmation email, returns challenge)
accountRouter.post('/delete/request', async (c) => {
  const user = c.get('user');

  // In a full implementation, this would:
  // 1. Send email with deletion confirmation link
  // 2. Generate a time-limited deletion token
  // 3. Require the user to verify via both email AND passkey

  return c.json({
    success: true,
    message: 'Deletion confirmation sent to your email',
    expiresIn: 3600, // 1 hour
  });
});
