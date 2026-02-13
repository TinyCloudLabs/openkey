import type { Handle } from '@sveltejs/kit';
import { redirect } from '@sveltejs/kit';
import { validateToken } from '$lib/server/auth';
import { db } from '$lib/server/db';

export const handle: Handle = async ({ event, resolve }) => {
  // Initialize locals
  event.locals.user = null;
  event.locals.session = null;
  event.locals.developerAccount = null;

  // Skip auth for login page, auth callback, static assets, and Stripe webhook
  const { pathname } = event.url;
  if (
    pathname === '/login' ||
    pathname.startsWith('/auth/') ||
    pathname.startsWith('/_app/') ||
    pathname.startsWith('/favicon') ||
    pathname === '/api/stripe/webhook'
  ) {
    return resolve(event);
  }

  // Validate session using OAuth access token from cookie
  const accessToken = event.cookies.get('admin_session');
  const authResult = await validateToken(accessToken);

  if (!authResult) {
    // Not authenticated - redirect to login
    throw redirect(302, '/login');
  }

  // Store user in locals
  event.locals.user = authResult.user;
  event.locals.session = { accessToken: accessToken! };

  // Ensure DeveloperAccount exists (upsert on first authenticated request)
  try {
    const developerAccount = await db.developerAccount.upsert({
      where: { userId: authResult.user.id },
      create: {
        userId: authResult.user.id,
      },
      update: {},
    });

    event.locals.developerAccount = {
      id: developerAccount.id,
      plan: developerAccount.plan,
      billingState: developerAccount.billingState,
      mauLimit: developerAccount.mauLimit,
      appLimit: developerAccount.appLimit,
      stripeCustomerId: developerAccount.stripeCustomerId,
      stripeSubscriptionId: developerAccount.stripeSubscriptionId,
    };
  } catch (error) {
    console.error('[hooks] Failed to upsert DeveloperAccount:', error);
  }

  return resolve(event);
};
