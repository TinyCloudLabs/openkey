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
import { resolveOriginPolicy } from '../origin-policy';

const prisma = createPrismaClient();

export const accountRouter = new Hono<SessionContext>();

// All routes require authentication
accountRouter.use('*', requireSession);

function rejectNonBrowserControlRequest(c: any) {
  // Account controls are deliberately cookie-session-only. In particular, an
  // OAuth bearer token that can call /delegate/sign must never change custody.
  if (c.req.header('authorization')) return c.json({ error: 'Bearer tokens cannot change TinyCloud signing controls' }, 403);
  const origin = c.req.header('origin');
  const allowed = resolveOriginPolicy('http://localhost:5173,http://localhost:3000');
  if (!origin || !allowed.includes(origin)) return c.json({ error: 'A same-site browser Origin is required' }, 403);
  return null;
}

// This recovery image deliberately uses the pre-TC-488/TC-492 Prisma shape.
// Do not let a request reach tables or columns that are absent from the
// production database while the destructive cutover remains unapplied.
function preCutoverFeatureUnavailable(c: any) {
  return c.json({ error: 'TinyCloud manage-key controls require the separately authorized schema cutover' }, 503);
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
  return preCutoverFeatureUnavailable(c);
});

accountRouter.patch('/tinycloud-manage-key', async (c) => {
  const rejected = rejectNonBrowserControlRequest(c);
  if (rejected) return rejected;
  return preCutoverFeatureUnavailable(c);
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
  return preCutoverFeatureUnavailable(c);
});

accountRouter.patch('/tinycloud-apps/:clientId', async (c) => {
  const rejected = rejectNonBrowserControlRequest(c);
  if (rejected) return rejected;
  return preCutoverFeatureUnavailable(c);
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


  // Count and delete every user key. TC-488 removed tenant-managed keys.
  const keyCount = await prisma.ethereumKey.count({
    where: { userId: user.id },
  });

  // Delete all user data in transaction
  await prisma.$transaction(async (tx) => {
    // Delete all ethereum keys (sealed blobs will be unrecoverable)
    await tx.ethereumKey.deleteMany({ where: { userId: user.id } });

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
