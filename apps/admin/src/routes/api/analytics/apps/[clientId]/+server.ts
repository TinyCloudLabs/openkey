// GET /api/analytics/apps/[clientId] - Return per-app daily stats for current month
import { json } from '@sveltejs/kit';
import { db } from '$lib/server/db';
import type { RequestHandler } from './$types';

export const GET: RequestHandler = async ({ params, locals }) => {
  const user = locals.user;
  if (!user) {
    return json({ error: 'Unauthorized' }, { status: 401 });
  }

  const { clientId } = params;

  // Verify app ownership: OauthClient.userId must match current user
  const client = await db.oauthClient.findUnique({
    where: { clientId },
    select: { userId: true },
  });

  if (!client || client.userId !== user.id) {
    return json({ error: 'Not found' }, { status: 404 });
  }

  // Calculate current month boundaries
  const now = new Date();
  const monthStart = new Date(now.getFullYear(), now.getMonth(), 1);
  const monthEnd = new Date(now.getFullYear(), now.getMonth() + 1, 1);

  // Query OauthDailyStats for this clientId in the current month
  const stats = await db.oauthDailyStats.findMany({
    where: {
      clientId,
      date: {
        gte: monthStart,
        lt: monthEnd,
      },
    },
    select: {
      date: true,
      uniqueUsers: true,
      totalAuthorizations: true,
      totalTokenExchanges: true,
    },
    orderBy: { date: 'asc' },
  });

  return json(
    stats.map((s) => ({
      date: s.date.toISOString().split('T')[0],
      uniqueUsers: s.uniqueUsers,
      totalAuthorizations: s.totalAuthorizations,
      totalTokenExchanges: s.totalTokenExchanges,
    }))
  );
};
