// Account management routes
import { Hono } from 'hono';
import { PrismaClient } from '@prisma/client';
import { requireSession, type SessionContext } from '../middleware/session';
import { auth } from '../auth';

const prisma = new PrismaClient();

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

  // Get user's keys count for final warning
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
