import { json } from '@sveltejs/kit';
import type { RequestHandler } from './$types';
import { stripe, PLANS, type PlanKey } from '$lib/server/stripe';
import { db } from '$lib/server/db';

export const POST: RequestHandler = async ({ request, locals, url }) => {
  const user = locals.user;
  if (!user) return new Response('Unauthorized', { status: 401 });

  const body = await request.json();
  const planKey = body.plan as PlanKey;

  if (!planKey || !PLANS[planKey]) {
    return json({ error: 'Invalid plan' }, { status: 400 });
  }

  const plan = PLANS[planKey];
  if (!plan.priceId) {
    return json({ error: 'Cannot checkout for free plan' }, { status: 400 });
  }

  let developerAccount = locals.developerAccount;
  if (!developerAccount) {
    return json({ error: 'Developer account not found' }, { status: 404 });
  }

  // Create Stripe customer if needed
  let stripeCustomerId = developerAccount.stripeCustomerId;
  if (!stripeCustomerId) {
    const customer = await stripe.customers.create({
      email: user.email,
      metadata: {
        userId: user.id,
        developerAccountId: developerAccount.id,
      },
    });

    stripeCustomerId = customer.id;

    await db.developerAccount.update({
      where: { id: developerAccount.id },
      data: { stripeCustomerId },
    });
  }

  // Create checkout session
  const session = await stripe.checkout.sessions.create({
    customer: stripeCustomerId,
    mode: 'subscription',
    line_items: [
      {
        price: plan.priceId,
        quantity: 1,
      },
    ],
    success_url: `${url.origin}/billing?success=true`,
    cancel_url: `${url.origin}/billing?canceled=true`,
    metadata: {
      userId: user.id,
      developerAccountId: developerAccount.id,
      plan: planKey,
    },
  });

  return json({ url: session.url });
};
