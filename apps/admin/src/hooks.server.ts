import type { Handle } from '@sveltejs/kit';
import { redirect } from '@sveltejs/kit';
import { validateSession } from '$lib/server/auth';
import { db } from '$lib/server/db';

export const handle: Handle = async ({ event, resolve }) => {
  // Initialize locals
  event.locals.user = null;
  event.locals.session = null;
  event.locals.developerAccount = null;

  // Skip auth for login page, static assets, and Stripe webhook (called by Stripe directly)
  const { pathname } = event.url;
  if (pathname === '/login' || pathname.startsWith('/_app/') || pathname.startsWith('/favicon') || pathname === '/api/stripe/webhook') {
    return resolve(event);
  }

  // Validate session by forwarding cookies to the main API
  const cookieHeader = event.request.headers.get('cookie');
  const authResult = await validateSession(cookieHeader);

  if (!authResult) {
    // Not authenticated - redirect to login
    throw redirect(302, '/login');
  }

  // Store user and session in locals
  event.locals.user = authResult.user;
  event.locals.session = authResult.session;

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
