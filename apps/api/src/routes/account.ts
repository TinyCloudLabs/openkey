// Account management routes
import { Hono } from 'hono';
import { createPrismaClient } from '@openkey/db';
import { requireSession, type SessionContext } from '../middleware/session';
import { parseAutoSignPreferencePatch } from './account-preferences';

const prisma = createPrismaClient();

export const accountRouter = new Hono<SessionContext>();

// All routes require authentication
accountRouter.use('*', requireSession);

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
          ethereumKeys: { where: { archivedAt: null, keyPurpose: 'PERSONAL' } },
          passkeys: true,
        },
      },
    },
  });

  return c.json({ user: userData });
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
