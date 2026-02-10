import type { PageServerLoad } from './$types';
import { db } from '$lib/server/db';

export const load: PageServerLoad = async ({ locals }) => {
  const user = locals.user;
  const developerAccount = locals.developerAccount;

  if (!user) {
    return {
      apps: [],
      developerAccount: null,
      currentMau: 0,
    };
  }

  // Load the developer's OAuth clients
  const apps = await db.oauthClient.findMany({
    where: { userId: user.id },
    select: {
      id: true,
      clientId: true,
      name: true,
      type: true,
      createdAt: true,
    },
    orderBy: { createdAt: 'desc' },
  });

  // Placeholder for current MAU - will be loaded from analytics API later
  const currentMau = 0;

  return {
    apps: apps.map((app) => ({
      id: app.id,
      clientId: app.clientId,
      name: app.name,
      type: app.type,
      createdAt: app.createdAt.toISOString(),
    })),
    developerAccount,
    currentMau,
  };
};
