import { json } from '@sveltejs/kit';
import type { RequestHandler } from './$types';
import { stripe } from '$lib/server/stripe';

export const POST: RequestHandler = async ({ locals, url }) => {
  const user = locals.user;
  if (!user) return new Response('Unauthorized', { status: 401 });

  const developerAccount = locals.developerAccount;
  if (!developerAccount?.stripeCustomerId) {
    return json({ error: 'No billing account found' }, { status: 404 });
  }

  const session = await stripe.billingPortal.sessions.create({
    customer: developerAccount.stripeCustomerId,
    return_url: `${url.origin}/billing`,
  });

  return json({ url: session.url });
};
