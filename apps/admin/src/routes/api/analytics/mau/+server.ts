// GET /api/analytics/mau - Return current month MAU count and limit
import { json } from '@sveltejs/kit';
import { db } from '$lib/server/db';
import type { RequestHandler } from './$types';

export const GET: RequestHandler = async ({ locals }) => {
  const user = locals.user;
  if (!user) {
    return json({ error: 'Unauthorized' }, { status: 401 });
  }

  // Get all clientIds owned by this user
  const clients = await db.oauthClient.findMany({
    where: { userId: user.id },
    select: { clientId: true },
  });

  const clientIds = clients.map((c) => c.clientId);

  // Calculate current month boundaries
  const now = new Date();
  const monthStart = new Date(now.getFullYear(), now.getMonth(), 1);
  const monthEnd = new Date(now.getFullYear(), now.getMonth() + 1, 1);

  let mau = 0;

  if (clientIds.length > 0) {
    // COUNT DISTINCT userId from OauthAccessToken where clientId IN user's apps AND createdAt in current month
    const uniqueUsers = await db.oauthAccessToken.groupBy({
      by: ['userId'],
      where: {
        clientId: { in: clientIds },
        createdAt: {
          gte: monthStart,
          lt: monthEnd,
        },
      },
    });

    mau = uniqueUsers.length;
  }

  // Get the developer account for MAU limit
  const developerAccount = await db.developerAccount.findUnique({
    where: { userId: user.id },
    select: { mauLimit: true },
  });

  const limit = developerAccount?.mauLimit ?? 1000;

  return json({ mau, limit });
};
