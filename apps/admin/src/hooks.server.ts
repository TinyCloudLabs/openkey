import type { Handle } from '@sveltejs/kit';
import { redirect } from '@sveltejs/kit';

// Dynamic imports to avoid SvelteKit's vite-plugin-sveltekit-guard
// triggering "An impossible situation occurred" on Cloudflare CI.
// The guard incorrectly evaluates static $lib/server/* imports during
// the client build phase on node 22. Dynamic imports bypass this.
let _validateToken: typeof import('$lib/server/auth').validateToken;
let _db: typeof import('$lib/server/db').db;

async function getServerModules() {
  if (!_validateToken) {
    const auth = await import('$lib/server/auth');
    _validateToken = auth.validateToken;
  }
  if (!_db) {
    const dbModule = await import('$lib/server/db');
    _db = dbModule.db;
  }
  return { validateToken: _validateToken, db: _db };
}

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

  const { validateToken, db } = await getServerModules();

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
