import type { PageServerLoad } from './$types';
import { db } from '$lib/server/db';

export const load: PageServerLoad = async ({ locals }) => {
  const user = locals.user;
  const developerAccount = locals.developerAccount;

  if (!user) {
    return {
      user: null,
      developerAccount: null,
    };
  }

  // Load full user record for display
  const fullUser = await db.user.findUnique({
    where: { id: user.id },
    select: {
      id: true,
      email: true,
      name: true,
      createdAt: true,
    },
  });

  return {
    user: fullUser
      ? {
          id: fullUser.id,
          email: fullUser.email,
          name: fullUser.name,
          createdAt: fullUser.createdAt.toISOString(),
        }
      : null,
    developerAccount,
  };
};
